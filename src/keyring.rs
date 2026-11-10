//! Thin wrapper over the OS keyring.
//!
//! Two disjoint namespaces, each with its own typed entry points:
//!
//! - Cached secrets: service `op-fast`, account = a secret reference that
//!   must start with `op://` (`cache_*`).
//! - Service-account tokens: service `op-fast-service-account`, account = a
//!   validated account name, which can never start with `op://`
//!   (`token_*`).
//!
//! Both service names are compile-time constants in release builds. Debug
//! builds (tests) may rename them with `OP_FAST_KEYRING_SERVICE` and may
//! swap the OS keyring for a plaintext directory with
//! `OP_FAST_TEST_KEYRING_DIR`; neither exists in a release binary.

use anyhow::{Context, Result, bail};

const CACHE_SERVICE: &str = "op-fast";
const TOKEN_SERVICE: &str = "op-fast-service-account";
const TOKEN_SUFFIX: &str = "-service-account";

/// Keyring service holding cached secret values.
pub fn cache_service() -> String {
    #[cfg(debug_assertions)]
    if let Some(base) = std::env::var("OP_FAST_KEYRING_SERVICE")
        .ok()
        .filter(|s| !s.is_empty())
    {
        return base;
    }
    CACHE_SERVICE.to_string()
}

/// Keyring service holding service-account tokens.
pub fn token_service() -> String {
    #[cfg(debug_assertions)]
    if let Some(base) = std::env::var("OP_FAST_KEYRING_SERVICE")
        .ok()
        .filter(|s| !s.is_empty())
    {
        return format!("{}{}", base, TOKEN_SUFFIX);
    }
    TOKEN_SERVICE.to_string()
}

fn checked_cache_service(reference: &str) -> Result<String> {
    crate::template::validate_reference(reference)?;
    cache_service_for_key(reference)
}

/// For deletion only: any key that starts with `op://`, including legacy
/// keys with control characters, so they can always be cleaned up.
fn cache_service_for_key(reference: &str) -> Result<String> {
    if !reference.starts_with("op://") {
        bail!("not a secret reference (must start with op://)");
    }
    let service = cache_service();
    if service.ends_with(TOKEN_SUFFIX) {
        bail!("refusing to use a token keyring service for cached secrets");
    }
    Ok(service)
}

fn checked_token_service(name: &str) -> Result<String> {
    crate::config::validate_account_name(name)?;
    Ok(token_service())
}

pub fn cache_get(reference: &str) -> Result<Option<String>> {
    get(&checked_cache_service(reference)?, reference)
}

pub fn cache_set(reference: &str, value: &str) -> Result<()> {
    set(&checked_cache_service(reference)?, reference, value)
}

/// Deletion accepts any `op://` key, including legacy keys that reads and
/// writes refuse (control characters), so they can be removed.
pub fn cache_delete(reference: &str) -> Result<bool> {
    delete(&cache_service_for_key(reference)?, reference)
}

pub fn token_get(name: &str) -> Result<Option<String>> {
    get(&checked_token_service(name)?, name)
}

pub fn token_set(name: &str, token: &str) -> Result<()> {
    set(&checked_token_service(name)?, name, token)
}

pub fn token_delete(name: &str) -> Result<bool> {
    delete(&checked_token_service(name)?, name)
}

pub fn token_exists(name: &str) -> Option<bool> {
    exists(&checked_token_service(name).ok()?, name)
}

fn get(service: &str, account: &str) -> Result<Option<String>> {
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

fn set(service: &str, account: &str, value: &str) -> Result<()> {
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

fn delete(service: &str, account: &str) -> Result<bool> {
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

/// Whether an entry exists, without reading its value (so no Keychain
/// access dialog). `None` when the backend has no attribute-only lookup.
fn exists(service: &str, account: &str) -> Option<bool> {
    #[cfg(debug_assertions)]
    if let Some(dir) = test_dir() {
        return Some(test_backend::exists(&dir, service, account));
    }

    #[cfg(target_os = "macos")]
    {
        // Without -g/-w, `security` returns attributes only, never the
        // secret, so it cannot raise an access dialog.
        let status = std::process::Command::new("/usr/bin/security")
            .args(["find-generic-password", "-s", service, "-a", account])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .ok()?;
        match status.code() {
            Some(0) => Some(true),
            Some(44) => Some(false),
            _ => None,
        }
    }

    #[cfg(not(target_os = "macos"))]
    {
        let _ = (service, account);
        None
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

    pub fn exists(dir: &Path, service: &str, account: &str) -> bool {
        path(dir, service, account).is_file()
    }

    pub fn delete(dir: &Path, service: &str, account: &str) -> Result<bool> {
        match std::fs::remove_file(path(dir, service, account)) {
            Ok(()) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e.into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn release_service_names_are_disjoint_constants() {
        assert_eq!(CACHE_SERVICE, "op-fast");
        assert_eq!(TOKEN_SERVICE, "op-fast-service-account");
        assert_ne!(CACHE_SERVICE, TOKEN_SERVICE);
    }

    #[test]
    fn cache_entry_points_refuse_non_references() {
        // Rejected before any keyring access.
        for bad in ["agents", "ops_FAKE", "op:/x", "op://V/i\n/f", ""] {
            assert!(checked_cache_service(bad).is_err(), "{:?}", bad);
        }
        assert!(checked_cache_service("op://V/i/f").is_ok());
        // Deletion still works for a legacy key with a control character,
        // but never for a non-reference.
        assert!(cache_service_for_key("op://V/i\n/f").is_ok());
        assert!(cache_service_for_key("agents").is_err());
    }

    #[test]
    fn token_entry_points_refuse_references() {
        assert!(checked_token_service("op://V/i/f").is_err());
        assert!(checked_token_service("agents").is_ok());
    }
}
