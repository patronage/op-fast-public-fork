use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use globset::Glob;
use serde::Deserialize;

const DEFAULT_TTL: Duration = Duration::from_secs(86400);
const DEFAULT_PROMPT_TIMEOUT: Duration = Duration::from_secs(15);
const DEFAULT_STALE_GRACE: Duration = Duration::from_secs(30 * 86400);

#[derive(Debug, Clone)]
pub struct Config {
    pub default_ttl: Duration,
    pub ttl_rules: Vec<TtlRule>,
    /// Deadline for delegate calls that may wait on a desktop approval when
    /// stderr is not a TTY.
    pub prompt_timeout: Duration,
    /// How long expired entries stay available for stale-on-auth-failure.
    pub stale_grace: Duration,
    /// Path to the real `op` (`OP_FAST_COMMAND` still wins).
    pub op_command: Option<PathBuf>,
    pub service_accounts: Vec<ServiceAccount>,
    pub path: PathBuf,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ServiceAccount {
    /// Account name; also the keyring account holding the token.
    pub name: String,
    /// Vault names or IDs this account covers.
    pub vaults: Vec<String>,
    /// Optional TTL for references this account serves.
    pub ttl: Option<Duration>,
}

impl ServiceAccount {
    pub fn covers_vault(&self, vault: &str) -> bool {
        self.vaults.iter().any(|v| v.eq_ignore_ascii_case(vault))
    }
}

/// Account names double as keyring account names and CLI arguments, so keep
/// them to a boring character set.
pub fn validate_account_name(name: &str) -> Result<()> {
    anyhow::ensure!(
        !name.is_empty()
            && name.len() <= 64
            && name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.'),
        "invalid service account name {:?}: use 1-64 characters from [A-Za-z0-9._-]",
        name
    );
    anyhow::ensure!(
        !name.eq_ignore_ascii_case("none") && !name.eq_ignore_ascii_case("desktop"),
        "service account name {:?} is reserved",
        name
    );
    Ok(())
}

#[derive(Debug, Clone)]
pub struct TtlRule {
    glob: Glob,
    ttl: Duration,
}

impl TtlRule {
    pub fn new(pattern: &str, ttl: Duration) -> Result<Self> {
        let glob = Glob::new(pattern)?;
        Ok(Self { glob, ttl })
    }

    pub fn matches(&self, reference: &str) -> bool {
        self.glob.compile_matcher().is_match(reference)
    }
}

impl Config {
    pub fn load() -> Result<Self> {
        let config_path = Self::config_path()?;

        let raw = if config_path.exists() {
            let content = fs::read_to_string(&config_path).context("Failed to read config file")?;
            toml::from_str(&content)?
        } else {
            RawConfig::default()
        };

        let mut config = Self::from_raw(raw)
            .with_context(|| format!("Invalid config file {}", config_path.display()))?;
        config.path = config_path;

        if let Ok(env_ttl) = env::var("OP_FAST_DEFAULT_TTL") {
            config.default_ttl =
                humantime::parse_duration(&env_ttl).context("Invalid OP_FAST_DEFAULT_TTL")?;
        }

        if let Ok(v) = env::var("OP_FAST_PROMPT_TIMEOUT") {
            config.prompt_timeout =
                humantime::parse_duration(&v).context("Invalid OP_FAST_PROMPT_TIMEOUT")?;
        }

        Ok(config)
    }

    /// Config for paths that must work even with a broken config file
    /// (bypass, doctor).
    pub fn load_or_default() -> Self {
        Self::load().unwrap_or_else(|e| {
            log::warn!("config unavailable, using defaults: {:#}", e);
            Self::from_raw(RawConfig::default()).expect("default config is valid")
        })
    }

    #[cfg(test)]
    pub fn load_from_str(src: &str) -> Result<Self> {
        Self::from_raw(toml::from_str(src)?)
    }

    /// TTL for a reference fetched through `account` (or desktop auth).
    pub fn resolve_ttl_for(&self, reference: &str, account: Option<&ServiceAccount>) -> Duration {
        account
            .and_then(|a| a.ttl)
            .unwrap_or_else(|| self.resolve_ttl(reference))
    }

    pub fn account(&self, name: &str) -> Option<&ServiceAccount> {
        self.service_accounts.iter().find(|a| a.name == name)
    }

    pub fn resolve_ttl(&self, reference: &str) -> Duration {
        for rule in &self.ttl_rules {
            if rule.matches(reference) {
                return rule.ttl;
            }
        }
        self.default_ttl
    }

    fn from_raw(raw: RawConfig) -> Result<Self> {
        let default_ttl = raw
            .default_ttl
            .map(|s| humantime::parse_duration(&s))
            .transpose()
            .context("Invalid default_ttl")?
            .unwrap_or(DEFAULT_TTL);

        let mut ttl_rules = Vec::new();
        for (pattern, ttl_str) in &raw.ttl {
            let ttl = humantime::parse_duration(ttl_str)
                .with_context(|| format!("Invalid TTL for pattern: {}", pattern))?;
            ttl_rules.push(TtlRule::new(pattern, ttl)?);
        }

        let parse = |v: Option<String>, what: &str, default: Duration| -> Result<Duration> {
            v.map(|s| humantime::parse_duration(&s))
                .transpose()
                .with_context(|| format!("Invalid {}", what))
                .map(|d| d.unwrap_or(default))
        };
        let prompt_timeout = parse(raw.prompt_timeout, "prompt_timeout", DEFAULT_PROMPT_TIMEOUT)?;
        let stale_grace = parse(raw.stale_grace, "stale_grace", DEFAULT_STALE_GRACE)?;

        let mut service_accounts: Vec<ServiceAccount> = Vec::new();
        for sa in raw.service_account {
            validate_account_name(&sa.name)?;
            anyhow::ensure!(
                !service_accounts.iter().any(|a| a.name == sa.name),
                "duplicate [[service_account]] name {:?}",
                sa.name
            );
            let ttl = sa
                .ttl
                .map(|s| humantime::parse_duration(&s))
                .transpose()
                .with_context(|| format!("Invalid ttl for service account {:?}", sa.name))?;
            service_accounts.push(ServiceAccount {
                name: sa.name,
                vaults: sa.vaults,
                ttl,
            });
        }

        Ok(Self {
            default_ttl,
            ttl_rules,
            prompt_timeout,
            stale_grace,
            op_command: raw.op_command.map(PathBuf::from),
            service_accounts,
            path: PathBuf::new(),
        })
    }

    fn config_path() -> Result<PathBuf> {
        if let Ok(path) = env::var("OP_FAST_CONFIG") {
            return Ok(PathBuf::from(path));
        }

        let config_dir = env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(|| dirs_sys::home_dir().map(|h| h.join(".config")))
            .context("Could not determine config directory")?;

        Ok(config_dir.join("op-fast").join("config.toml"))
    }
}

#[derive(Debug, Default, Deserialize)]
struct RawConfig {
    #[serde(default)]
    default_ttl: Option<String>,

    #[serde(default)]
    ttl: HashMap<String, String>,

    #[serde(default)]
    prompt_timeout: Option<String>,

    #[serde(default)]
    stale_grace: Option<String>,

    #[serde(default)]
    op_command: Option<String>,

    #[serde(default)]
    service_account: Vec<RawServiceAccount>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawServiceAccount {
    name: String,
    #[serde(default)]
    vaults: Vec<String>,
    #[serde(default)]
    ttl: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(toml_src: &str) -> Result<Config> {
        Config::from_raw(toml::from_str(toml_src)?)
    }

    #[test]
    fn defaults_when_keys_absent() {
        let c = parse("").unwrap();
        assert_eq!(c.default_ttl, DEFAULT_TTL);
        assert_eq!(c.prompt_timeout, Duration::from_secs(15));
        assert_eq!(c.stale_grace, Duration::from_secs(30 * 86400));
        assert!(c.service_accounts.is_empty());
        assert!(c.op_command.is_none());
    }

    #[test]
    fn parses_service_accounts_and_ttl_precedence() {
        let c = parse(
            r#"
default_ttl = "14days"
op_command = "/opt/op"
[[service_account]]
name = "agents"
vaults = ["Agents", "Shared"]
ttl = "15m"
[[service_account]]
name = "ci"
vaults = ["CI"]
"#,
        )
        .unwrap();
        assert_eq!(c.service_accounts.len(), 2);
        let agents = c.account("agents").unwrap();
        assert!(agents.covers_vault("shared"));
        assert_eq!(
            c.resolve_ttl_for("op://Agents/x/y", Some(agents)),
            Duration::from_secs(900)
        );
        // No account TTL: fall back to normal resolution (desktop TTL unchanged).
        assert_eq!(
            c.resolve_ttl_for("op://CI/x/y", c.account("ci")),
            Duration::from_secs(14 * 86400)
        );
        assert_eq!(
            c.resolve_ttl_for("op://Private/x/y", None),
            Duration::from_secs(14 * 86400)
        );
        assert_eq!(c.op_command, Some(PathBuf::from("/opt/op")));
    }

    #[test]
    fn rejects_a_token_key_in_config() {
        // Tokens live only in the OS keyring.
        assert!(parse("[[service_account]]\nname = \"a\"\ntoken = \"x\"\n").is_err());
    }

    #[test]
    fn rejects_bad_and_duplicate_account_names() {
        assert!(parse("[[service_account]]\nname = \"a b\"\n").is_err());
        assert!(parse("[[service_account]]\nname = \"none\"\n").is_err());
        assert!(
            parse("[[service_account]]\nname = \"a\"\n[[service_account]]\nname = \"a\"\n")
                .is_err()
        );
    }
}
