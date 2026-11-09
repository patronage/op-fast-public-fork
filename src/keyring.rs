//! Thin wrapper over the OS keyring.
//!
//! Every value op-fast keeps (cached secrets and service-account tokens)
//! goes through here, so tests can redirect storage without touching the
//! operator's real Keychain:
//!
//! - `OP_FAST_KEYRING_SERVICE` renames the base keyring service (default
//!   `op-fast`). Service-account tokens live under `<base>-service-account`.
//! - Debug builds only: `OP_FAST_TEST_KEYRING_DIR` swaps the OS keyring for a
//!   plaintext directory. Release builds ignore it, so a shipped binary can
//!   never be pointed at plaintext storage.

use anyhow::{Context, Result};

const DEFAULT_SERVICE: &str = "op-fast";

/// Keyring service holding cached secret values.
pub fn cache_service() -> String {
    std::env::var("OP_FAST_KEYRING_SERVICE")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| DEFAULT_SERVICE.to_string())
}

/// Keyring service holding service-account tokens.
pub fn account_service() -> String {
    format!("{}-service-account", cache_service())
}

pub fn get(service: &str, account: &str) -> Result<Option<String>> {
    #[cfg(debug_assertions)]
    if let Some(dir) = test_dir() {
        return test_backend::get(&dir, service, account);
    }

    let entry =
        keyring_core::Entry::new(service, account).context("Failed to open keyring entry")?;
    match entry.get_password() {
        Ok(value) => Ok(Some(value)),
        Err(keyring_core::Error::NoEntry) => Ok(None),
        Err(e) => Err(anyhow::anyhow!("Keyring error: {}", e)),
    }
}

pub fn set(service: &str, account: &str, value: &str) -> Result<()> {
    #[cfg(debug_assertions)]
    if let Some(dir) = test_dir() {
        return test_backend::set(&dir, service, account, value);
    }

    let entry =
        keyring_core::Entry::new(service, account).context("Failed to open keyring entry")?;
    entry
        .set_password(value)
        .context("Failed to store value in keyring")
}

pub fn delete(service: &str, account: &str) -> Result<bool> {
    #[cfg(debug_assertions)]
    if let Some(dir) = test_dir() {
        return test_backend::delete(&dir, service, account);
    }

    let entry =
        keyring_core::Entry::new(service, account).context("Failed to open keyring entry")?;
    match entry.delete_credential() {
        Ok(()) => Ok(true),
        Err(keyring_core::Error::NoEntry) => Ok(false),
        Err(e) => Err(anyhow::anyhow!("Keyring error: {}", e)),
    }
}

/// Human-readable backend name, for `doctor`.
pub fn backend_name() -> &'static str {
    #[cfg(debug_assertions)]
    if test_dir().is_some() {
        return "test-directory (debug build)";
    }
    if cfg!(target_os = "macos") {
        "macOS Keychain"
    } else if cfg!(target_os = "linux") {
        "Linux keyutils"
    } else {
        "Secret Service"
    }
}

#[cfg(debug_assertions)]
fn test_dir() -> Option<std::path::PathBuf> {
    std::env::var_os("OP_FAST_TEST_KEYRING_DIR")
        .filter(|s| !s.is_empty())
        .map(std::path::PathBuf::from)
}

#[cfg(debug_assertions)]
mod test_backend {
    use std::os::unix::fs::OpenOptionsExt;
    use std::path::{Path, PathBuf};

    use anyhow::Result;

    fn hex(s: &str) -> String {
        s.bytes().map(|b| format!("{:02x}", b)).collect()
    }

    fn path(dir: &Path, service: &str, account: &str) -> PathBuf {
        dir.join(hex(service)).join(hex(account))
    }

    pub fn get(dir: &Path, service: &str, account: &str) -> Result<Option<String>> {
        match std::fs::read_to_string(path(dir, service, account)) {
            Ok(v) => Ok(Some(v)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    pub fn set(dir: &Path, service: &str, account: &str, value: &str) -> Result<()> {
        use std::io::Write;
        let p = path(dir, service, account);
        std::fs::create_dir_all(p.parent().unwrap())?;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&p)?;
        f.write_all(value.as_bytes())?;
        Ok(())
    }

    pub fn delete(dir: &Path, service: &str, account: &str) -> Result<bool> {
        match std::fs::remove_file(path(dir, service, account)) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e.into()),
        }
    }
}
