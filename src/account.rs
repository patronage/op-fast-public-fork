//! Service-account selection and token storage.
//!
//! Tokens live only in the OS keyring (service `<base>-service-account`,
//! account = the configured name). They are handed to exactly one delegate
//! child through `OP_SERVICE_ACCOUNT_TOKEN` and never appear on argv, in
//! config, in the audit log, or in error text.

use anyhow::{Result, bail};

use crate::config::{Config, ServiceAccount};

pub const TOKEN_ENV: &str = "OP_SERVICE_ACCOUNT_TOKEN";
pub const FORCE_ENV: &str = "OP_FAST_ACCOUNT";

/// How one delegate call authenticates.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Auth {
    /// The caller already exported `OP_SERVICE_ACCOUNT_TOKEN`; leave it be.
    Ambient,
    /// 1Password desktop-app integration (may raise an approval prompt).
    Desktop,
    /// A configured `[[service_account]]`.
    Account(String),
}

impl Auth {
    /// Name recorded in the audit log.
    pub fn label(&self) -> &str {
        match self {
            Auth::Ambient => "env-token",
            Auth::Desktop => "desktop",
            Auth::Account(name) => name,
        }
    }

    /// Whether a call with this auth may wait on a desktop approval.
    pub fn may_prompt(&self) -> bool {
        matches!(self, Auth::Desktop)
    }
}

#[derive(Clone, Debug, PartialEq)]
enum Forced {
    Desktop,
    Account(String),
}

pub struct Selector<'a> {
    config: &'a Config,
    forced: Option<Forced>,
    ambient: bool,
}

impl<'a> Selector<'a> {
    /// `cli_sa` is the global `--sa` flag; it wins over `OP_FAST_ACCOUNT`.
    pub fn new(config: &'a Config, cli_sa: Option<&str>) -> Result<Self> {
        let env_sa = std::env::var(FORCE_ENV).ok();
        let raw = cli_sa
            .map(str::to_string)
            .or(env_sa)
            .filter(|s| !s.is_empty());
        let forced = match raw.as_deref() {
            None => None,
            Some(name) if name.eq_ignore_ascii_case("none") => Some(Forced::Desktop),
            Some(name) => {
                if config.account(name).is_none() {
                    bail!(
                        "unknown service account {:?} (configured: {})",
                        name,
                        configured_names(config)
                    );
                }
                Some(Forced::Account(name.to_string()))
            }
        };
        let ambient = std::env::var_os(TOKEN_ENV).is_some_and(|v| !v.is_empty());
        Ok(Self {
            config,
            forced,
            ambient,
        })
    }

    /// Account for a secret reference: ambient token, then forced account,
    /// then the first account whose vaults contain the reference's vault,
    /// then desktop auth.
    pub fn for_reference(&self, reference: &str) -> Auth {
        self.select(vault_of(reference))
    }

    /// Account for a passthrough command, given its `--vault` (if any).
    pub fn for_vault(&self, vault: Option<&str>) -> Auth {
        self.select(vault)
    }

    fn select(&self, vault: Option<&str>) -> Auth {
        if self.ambient {
            return Auth::Ambient;
        }
        match &self.forced {
            Some(Forced::Desktop) => return Auth::Desktop,
            Some(Forced::Account(name)) => return Auth::Account(name.clone()),
            None => {}
        }
        if let Some(vault) = vault
            && let Some(account) = self
                .config
                .service_accounts
                .iter()
                .find(|a| a.covers_vault(vault))
        {
            return Auth::Account(account.name.clone());
        }
        Auth::Desktop
    }

    pub fn service_account(&self, auth: &Auth) -> Option<&ServiceAccount> {
        match auth {
            Auth::Account(name) => self.config.account(name),
            _ => None,
        }
    }
}

fn configured_names(config: &Config) -> String {
    if config.service_accounts.is_empty() {
        return "none".to_string();
    }
    config
        .service_accounts
        .iter()
        .map(|a| a.name.as_str())
        .collect::<Vec<_>>()
        .join(", ")
}

/// Vault segment of `op://<vault>/<item>/...`.
pub fn vault_of(reference: &str) -> Option<&str> {
    let rest = reference.strip_prefix("op://")?;
    let vault = rest.split('/').next()?;
    (!vault.is_empty()).then_some(vault)
}

/// Token for `auth`, if it needs one. Errors when a selected account has no
/// stored token (never falls back to desktop auth silently).
pub fn token_for(auth: &Auth) -> Result<Option<String>> {
    match auth {
        Auth::Account(name) => match load_token(name)? {
            Some(token) => Ok(Some(token)),
            None => bail!(
                "no token stored for service account {:?}; run `op-fast sa add {}`",
                name,
                name
            ),
        },
        _ => Ok(None),
    }
}

pub fn load_token(name: &str) -> Result<Option<String>> {
    crate::keyring::get(&crate::keyring::account_service(), name)
}

pub fn has_token(name: &str) -> bool {
    matches!(load_token(name), Ok(Some(t)) if !t.is_empty())
}

pub fn store_token(name: &str, token: &str) -> Result<()> {
    crate::keyring::set(&crate::keyring::account_service(), name, token)
}

pub fn remove_token(name: &str) -> Result<bool> {
    crate::keyring::delete(&crate::keyring::account_service(), name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    fn config() -> Config {
        let mut c = Config::load_from_str("").unwrap();
        c.service_accounts = vec![
            ServiceAccount {
                name: "agents".into(),
                vaults: vec!["Agents".into(), "Shared".into()],
                ttl: Some(Duration::from_secs(900)),
            },
            ServiceAccount {
                name: "ci".into(),
                vaults: vec!["CI".into(), "Shared".into()],
                ttl: None,
            },
        ];
        c
    }

    fn selector(config: &Config, forced: Option<Forced>, ambient: bool) -> Selector<'_> {
        Selector {
            config,
            forced,
            ambient,
        }
    }

    #[test]
    fn vault_segment_extraction() {
        assert_eq!(vault_of("op://Agents/item/field"), Some("Agents"));
        assert_eq!(vault_of("op://Agents"), Some("Agents"));
        assert_eq!(vault_of("op:///x"), None);
        assert_eq!(vault_of("not-a-ref"), None);
    }

    #[test]
    fn first_matching_account_wins_and_unmatched_is_desktop() {
        let c = config();
        let s = selector(&c, None, false);
        assert_eq!(
            s.for_reference("op://agents/i/f"),
            Auth::Account("agents".into())
        );
        assert_eq!(s.for_reference("op://CI/i/f"), Auth::Account("ci".into()));
        // "Shared" is in both; declaration order decides.
        assert_eq!(
            s.for_reference("op://Shared/i/f"),
            Auth::Account("agents".into())
        );
        assert_eq!(s.for_reference("op://Private/i/f"), Auth::Desktop);
        assert_eq!(s.for_vault(None), Auth::Desktop);
    }

    #[test]
    fn forced_and_ambient_precedence() {
        let c = config();
        let none = selector(&c, Some(Forced::Desktop), false);
        assert_eq!(none.for_reference("op://Agents/i/f"), Auth::Desktop);
        let ci = selector(&c, Some(Forced::Account("ci".into())), false);
        assert_eq!(
            ci.for_reference("op://Agents/i/f"),
            Auth::Account("ci".into())
        );
        let ambient = selector(&c, Some(Forced::Account("ci".into())), true);
        assert_eq!(ambient.for_reference("op://Agents/i/f"), Auth::Ambient);
    }

    #[test]
    fn no_accounts_configured_is_always_desktop() {
        let c = Config::load_from_str("").unwrap();
        let s = selector(&c, None, false);
        assert_eq!(s.for_reference("op://Agents/i/f"), Auth::Desktop);
    }
}
