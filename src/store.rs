mod db;

pub use db::{Db, Meta};

use std::collections::HashMap;
use std::time::Duration;

pub fn init() -> anyhow::Result<()> {
    let config = HashMap::new();

    #[cfg(target_os = "linux")]
    {
        let store = linux_keyutils_keyring_store::Store::new_with_configuration(&config)
            .map_err(|e| anyhow::anyhow!("Failed to initialize Linux keyutils store: {}", e))?;
        keyring_core::set_default_store(store);
        Ok(())
    }

    #[cfg(target_os = "macos")]
    {
        let store = apple_native_keyring_store::keychain::Store::new_with_configuration(&config)
            .map_err(|e| anyhow::anyhow!("Failed to initialize macOS keychain store: {}", e))?;
        keyring_core::set_default_store(store);
        Ok(())
    }

    #[cfg(any(target_os = "freebsd", target_os = "openbsd"))]
    {
        let store = dbus_secret_service_keyring_store::Store::new_with_configuration(&config)
            .map_err(|e| anyhow::anyhow!("Failed to initialize Secret Service store: {}", e))?;
        keyring_core::set_default_store(store);
        Ok(())
    }

    #[cfg(not(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "freebsd",
        target_os = "openbsd",
    )))]
    {
        anyhow::bail!("No supported keyring backend is configured for this platform");
    }
}

/// Debug builds only: `OP_FAST_TEST_FORCE_GC=1` makes GC deterministic for
/// tests. Release builds compile this to `false`.
fn gc_forced_for_tests() -> bool {
    #[cfg(debug_assertions)]
    {
        if std::env::var_os("OP_FAST_TEST_FORCE_GC").is_some_and(|v| v == "1") {
            return true;
        }
    }
    false
}

pub struct Store {
    db: Db,
}

impl Store {
    /// Open the store. `stale_grace` bounds how long expired entries are
    /// kept for stale-on-auth-failure before background GC removes them.
    pub fn open(stale_grace: Duration) -> anyhow::Result<Self> {
        let db = Db::open()?;
        let store = Self { db };

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        if (now.is_multiple_of(10) || gc_forced_for_tests())
            && let Err(e) = store.db.gc(stale_grace)
        {
            log::warn!("Background GC failed: {}", e);
        }

        Ok(store)
    }

    /// Open without background GC (GC may delete keyring items, which can
    /// raise a Keychain prompt). For read-only reporting commands.
    pub fn open_read_only() -> anyhow::Result<Self> {
        Ok(Self { db: Db::open()? })
    }

    pub fn get_with_meta(&self, reference: &str) -> anyhow::Result<Option<(String, Meta)>> {
        match self.db.get(reference)? {
            Some(entry) => {
                log::debug!("Store hit for: {}", reference);
                Ok(Some(entry))
            }
            None => {
                log::debug!("Store miss for: {}", reference);
                Ok(None)
            }
        }
    }

    /// Entry regardless of expiry.
    pub fn get_any(&self, reference: &str) -> anyhow::Result<Option<(String, Meta)>> {
        self.db.get_any(reference)
    }

    /// Metadata only; never touches the keyring.
    pub fn meta(&self, reference: &str) -> anyhow::Result<Option<Meta>> {
        self.db.meta(reference)
    }

    pub fn path() -> anyhow::Result<std::path::PathBuf> {
        Db::db_path()
    }

    pub fn put(&self, reference: &str, value: &str, ttl: Duration) -> anyhow::Result<()> {
        self.db.put(reference, value, ttl)?;
        log::debug!("Stored {} with TTL {:?}", reference, ttl);
        Ok(())
    }

    pub fn delete(&self, reference: &str) -> anyhow::Result<bool> {
        self.db.delete(reference)
    }

    pub fn list(&self) -> anyhow::Result<Vec<(String, Meta)>> {
        self.db.list()
    }

    pub fn clear(&self) -> anyhow::Result<()> {
        self.db.clear()
    }
}
