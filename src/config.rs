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
///
/// Error messages never repeat the name: a mistyped command can put a token
/// where a name belongs.
pub fn validate_account_name(name: &str) -> Result<()> {
    anyhow::ensure!(
        !name.is_empty()
            && name.len() <= 64
            && !name.starts_with("ops_")
            && name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_' || c == '.'),
        "invalid service account name: use 1-64 characters from [A-Za-z0-9._-], not starting with 'ops_'"
    );
    anyhow::ensure!(
        !name.eq_ignore_ascii_case("none") && !name.eq_ignore_ascii_case("desktop"),
        "service account names 'none' and 'desktop' are reserved"
    );
    Ok(())
}

/// A name safe to repeat in messages: the name itself when valid.
pub fn display_account_name(name: &str) -> String {
    if validate_account_name(name).is_ok() {
        format!("{:?}", name)
    } else {
        "<invalid name, not shown>".to_string()
    }
}

/// Parse TOML without ever echoing file content (a mistaken `token = "..."`
/// line must not reach the terminal): message plus line number only.
fn parse_toml(content: &str) -> Result<RawConfig> {
    toml::from_str(content).map_err(|e| {
        let line = e.span().map(|span| {
            content[..span.start.min(content.len())]
                .matches('\n')
                .count()
                + 1
        });
        let message = e
            .message()
            .lines()
            .next()
            .unwrap_or("parse error")
            .to_string();
        match line {
            Some(line) => anyhow::anyhow!("{} (line {})", message, line),
            None => anyhow::anyhow!("{}", message),
        }
    })
}

/// Floor for `prompt_timeout`: a zero deadline would fail every fetch.
const MIN_PROMPT_TIMEOUT: Duration = Duration::from_secs(1);

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
            parse_toml(&content)
                .with_context(|| format!("Invalid config file {}", config_path.display()))?
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
            config.prompt_timeout = humantime::parse_duration(&v)
                .context("Invalid OP_FAST_PROMPT_TIMEOUT")?
                .max(MIN_PROMPT_TIMEOUT);
        }

        Ok(config)
    }

    /// Config for paths that must work even with a broken config file
    /// (bypass, doctor).
    pub fn load_or_default() -> Self {
        Self::load().unwrap_or_else(|e| {
            static WARNED: std::sync::Once = std::sync::Once::new();
            WARNED.call_once(|| {
                eprintln!(
                    "op-fast: warning: ignoring config ({:#}); using defaults",
                    e
                )
            });
            Self::defaults()
        })
    }

    /// Built-in defaults, ignoring the config file and environment.
    pub fn defaults() -> Self {
        Self::from_raw(RawConfig::default()).expect("default config is valid")
    }

    #[cfg(test)]
    pub fn load_from_str(src: &str) -> Result<Self> {
        Self::from_raw(parse_toml(src)?)
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
        let prompt_timeout = parse(raw.prompt_timeout, "prompt_timeout", DEFAULT_PROMPT_TIMEOUT)?
            .max(MIN_PROMPT_TIMEOUT);
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
        Config::from_raw(parse_toml(toml_src)?)
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
    fn rejects_a_token_key_in_config_without_echoing_it() {
        // Tokens live only in the OS keyring.
        let err = parse("[[service_account]]\nname = \"a\"\ntoken = \"FAKE-SECRET-VALUE\"\n")
            .unwrap_err();
        let text = format!("{:#}", err);
        assert!(text.contains("token"), "{}", text);
        assert!(text.contains("line 3"), "{}", text);
        assert!(!text.contains("FAKE-SECRET-VALUE"), "{}", text);
        // A syntax error on that line must not echo it either.
        let err = parse("token = \"FAKE-SECRET-VALUE\n").unwrap_err();
        assert!(!format!("{:#}", err).contains("FAKE-SECRET-VALUE"));
    }

    #[test]
    fn invalid_names_are_never_echoed() {
        let long = "x".repeat(65);
        for name in [long.as_str(), "ops_FAKE0000", "a b"] {
            let err = validate_account_name(name).unwrap_err().to_string();
            assert!(!err.contains(name), "{}", err);
            assert_eq!(display_account_name(name), "<invalid name, not shown>");
        }
    }

    #[test]
    fn prompt_timeout_is_floored_at_one_second() {
        assert_eq!(
            parse("prompt_timeout = \"0s\"").unwrap().prompt_timeout,
            Duration::from_secs(1)
        );
        assert_eq!(
            parse("prompt_timeout = \"5s\"").unwrap().prompt_timeout,
            Duration::from_secs(5)
        );
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
