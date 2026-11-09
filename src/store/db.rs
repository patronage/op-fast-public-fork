use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use heed::{Database, Env, EnvOpenOptions};
use serde::{Deserialize, Serialize};

const DIR_NAME: &str = "op-fast";
const DB_NAME: &str = "store.mdb";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Meta {
    pub stored_at: u64,
    pub ttl_seconds: u64,
}

impl Meta {
    pub fn new(ttl: Duration) -> Self {
        let stored_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        Self {
            stored_at,
            ttl_seconds: ttl.as_secs(),
        }
    }

    pub fn is_expired(&self) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        now > self.stored_at + self.ttl_seconds
    }

    pub fn expires_at(&self) -> u64 {
        self.stored_at.saturating_add(self.ttl_seconds)
    }

    /// Seconds since this entry expired, or `None` while it is still valid.
    pub fn expired_for_secs(&self) -> Option<u64> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        if now > self.expires_at() {
            Some(now - self.expires_at())
        } else {
            None
        }
    }

    /// Expired, but by no more than `grace`.
    pub fn is_in_grace(&self, grace: Duration) -> bool {
        matches!(self.expired_for_secs(), Some(age) if age <= grace.as_secs())
    }

    pub fn remaining_secs(&self) -> u64 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        (self.stored_at + self.ttl_seconds).saturating_sub(now)
    }
}

pub struct Db {
    env: Env,
    db: Database<heed::types::Str, heed::types::SerdeBincode<Meta>>,
}

impl Db {
    pub fn open() -> Result<Self> {
        let path = Self::db_path()?;
        std::fs::create_dir_all(&path).context("Failed to create store directory")?;

        let env = unsafe {
            EnvOpenOptions::new()
                .max_dbs(1)
                .map_size(10 * 1024 * 1024)
                .open(&path)?
        };

        let mut wtxn = env.write_txn()?;
        let db = env.create_database(&mut wtxn, None)?;
        wtxn.commit()?;

        Ok(Self { env, db })
    }

    pub fn get(&self, reference: &str) -> Result<Option<(String, Meta)>> {
        match self.get_any(reference)? {
            Some((_, meta)) if meta.is_expired() => Ok(None),
            other => Ok(other),
        }
    }

    pub fn meta(&self, reference: &str) -> Result<Option<Meta>> {
        crate::template::validate_reference(reference)?;
        let rtxn = self.env.read_txn()?;
        Ok(self.db.get(&rtxn, reference)?)
    }

    /// Entry regardless of expiry (used for stale-on-auth-failure).
    pub fn get_any(&self, reference: &str) -> Result<Option<(String, Meta)>> {
        crate::template::validate_reference(reference)?;
        let meta = {
            let rtxn = self.env.read_txn()?;
            let Some(meta) = self.db.get(&rtxn, reference)? else {
                return Ok(None);
            };
            meta
        };

        match Self::keyring_get(reference)? {
            Some(value) => Ok(Some((value, meta))),
            None => {
                log::warn!(
                    "Store metadata exists but keyring value missing for: {}",
                    reference
                );
                Ok(None)
            }
        }
    }

    pub fn put(&self, reference: &str, value: &str, ttl: Duration) -> Result<()> {
        crate::template::validate_reference(reference)?;
        let meta = Meta::new(ttl);

        Self::keyring_put(reference, value)?;

        let mut wtxn = self.env.write_txn()?;
        if let Err(e) = self.db.put(&mut wtxn, reference, &meta) {
            let _ = Self::keyring_delete(reference);
            return Err(e.into());
        }
        wtxn.commit()?;

        Ok(())
    }

    pub fn delete(&self, reference: &str) -> Result<bool> {
        crate::template::validate_reference(reference)?;
        let deleted_keyring = Self::keyring_delete(reference)?;

        let mut wtxn = self.env.write_txn()?;
        let deleted_meta = self.db.delete(&mut wtxn, reference)?;
        wtxn.commit()?;

        Ok(deleted_keyring || deleted_meta)
    }

    pub fn list(&self) -> Result<Vec<(String, Meta)>> {
        let rtxn = self.env.read_txn()?;
        let iter = self.db.iter(&rtxn)?;
        let entries: Vec<_> = iter
            .filter_map(|r| r.ok())
            .map(|(k, v)| (k.to_string(), v))
            .collect();
        Ok(entries)
    }

    pub fn clear(&self) -> Result<()> {
        let rtxn = self.env.read_txn()?;
        let iter = self.db.iter(&rtxn)?;
        for (reference, _) in iter.flatten() {
            if crate::template::validate_reference(reference).is_ok() {
                let _ = Self::keyring_delete(reference);
            }
        }
        drop(rtxn);

        let mut wtxn = self.env.write_txn()?;
        self.db.clear(&mut wtxn)?;
        wtxn.commit()?;

        Ok(())
    }

    /// Delete entries that expired more than `grace` ago. Entries inside the
    /// grace window are kept so they can be served stale when 1Password
    /// approval is unavailable.
    pub fn gc(&self, grace: Duration) -> Result<usize> {
        let entries = self.list()?;
        let mut deleted = 0;

        for (reference, meta) in &entries {
            if crate::template::validate_reference(reference).is_err() {
                // A key that is not a secret reference never touches the
                // keyring; drop its metadata only.
                let mut wtxn = self.env.write_txn()?;
                self.db.delete(&mut wtxn, reference)?;
                wtxn.commit()?;
                deleted += 1;
            } else if meta.is_expired() && !meta.is_in_grace(grace) {
                self.delete(reference)?;
                deleted += 1;
            }
        }

        if deleted > 0 {
            log::info!("GC removed {} expired entries", deleted);
        }

        Ok(deleted)
    }

    pub fn db_path() -> Result<PathBuf> {
        if let Ok(path) = std::env::var("OP_FAST_STORE_DIR") {
            return Ok(PathBuf::from(path));
        }

        let data_dir = std::env::var_os("XDG_DATA_HOME")
            .map(PathBuf::from)
            .or_else(|| dirs_sys::home_dir().map(|h| h.join(".local/share")))
            .context("Could not determine data directory")?;

        Ok(data_dir.join(DIR_NAME).join(DB_NAME))
    }

    fn keyring_get(reference: &str) -> Result<Option<String>> {
        crate::keyring::cache_get(reference)
    }

    fn keyring_put(reference: &str, value: &str) -> Result<()> {
        crate::keyring::cache_set(reference, value)
    }

    fn keyring_delete(reference: &str) -> Result<bool> {
        crate::keyring::cache_delete(reference)
    }
}
