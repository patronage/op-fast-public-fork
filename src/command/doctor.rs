use std::io::IsTerminal;

use anyhow::Result;
use clap::Parser;
use serde::Serialize;

use crate::account::{self, Auth};
use crate::config::Config;
use crate::delegate::{OpDelegate, deadline_for};
use crate::store::Store;

#[derive(Debug, Parser)]
#[clap(
    about = "Report op-fast health without prompting or reading secrets",
    long_about = "Report delegate, store, account, and timeout state.

Never raises a 1Password prompt and never reads a secret value: the only
`op` call is `op --version`. Use this instead of `op whoami` as a
pre-check."
)]
pub struct DoctorArgs {
    #[clap(long, help = "Print JSON")]
    pub json: bool,
}

#[derive(Serialize)]
struct Report {
    op_fast_version: &'static str,
    delegate: DelegateReport,
    config: ConfigReport,
    store: StoreReport,
    keyring: &'static str,
    service_accounts: Vec<AccountReport>,
    ambient_service_account_token: bool,
    forced_account: Option<String>,
    default_ttl: String,
    prompt_timeout: String,
    effective_desktop_deadline: String,
    stale_grace: String,
    stderr_is_tty: bool,
    bypass: bool,
}

#[derive(Serialize)]
struct DelegateReport {
    path: Option<String>,
    source: Option<&'static str>,
    version: Option<String>,
    error: Option<String>,
}

#[derive(Serialize)]
struct ConfigReport {
    path: String,
    exists: bool,
    error: Option<String>,
}

#[derive(Serialize)]
struct StoreReport {
    path: Option<String>,
    valid: usize,
    expired_in_grace: usize,
    expired: usize,
    error: Option<String>,
}

#[derive(Serialize)]
struct AccountReport {
    name: String,
    vaults: Vec<String>,
    token_present: bool,
}

fn dur(d: std::time::Duration) -> String {
    humantime::format_duration(d).to_string()
}

pub fn execute(args: DoctorArgs, sa: Option<&str>) -> Result<()> {
    let (config, config_error) = match Config::load() {
        Ok(c) => (c, None),
        Err(e) => (Config::load_or_default(), Some(format!("{:#}", e))),
    };
    let config_path = if config.path.as_os_str().is_empty() {
        std::env::var("OP_FAST_CONFIG").unwrap_or_default()
    } else {
        config.path.display().to_string()
    };

    let delegate = match OpDelegate::new(&config) {
        Ok(d) => DelegateReport {
            path: Some(d.path().display().to_string()),
            source: Some(d.source()),
            version: d.version(),
            error: None,
        },
        Err(e) => DelegateReport {
            path: None,
            source: None,
            version: None,
            error: Some(format!("{:#}", e)),
        },
    };

    let store = match Store::open_read_only().and_then(|s| s.list()) {
        Ok(entries) => {
            let mut r = StoreReport {
                path: Store::path().ok().map(|p| p.display().to_string()),
                valid: 0,
                expired_in_grace: 0,
                expired: 0,
                error: None,
            };
            for (_, meta) in entries {
                if !meta.is_expired() {
                    r.valid += 1;
                } else if meta.is_in_grace(config.stale_grace) {
                    r.expired_in_grace += 1;
                } else {
                    r.expired += 1;
                }
            }
            r
        }
        Err(e) => StoreReport {
            path: Store::path().ok().map(|p| p.display().to_string()),
            valid: 0,
            expired_in_grace: 0,
            expired: 0,
            error: Some(format!("{:#}", e)),
        },
    };

    let forced = sa
        .map(str::to_string)
        .or_else(|| std::env::var(account::FORCE_ENV).ok())
        .filter(|s| !s.is_empty());

    let report = Report {
        op_fast_version: env!("CARGO_PKG_VERSION"),
        delegate,
        config: ConfigReport {
            exists: std::path::Path::new(&config_path).exists(),
            path: config_path,
            error: config_error,
        },
        store,
        keyring: crate::keyring::backend_name(),
        service_accounts: config
            .service_accounts
            .iter()
            .map(|a| AccountReport {
                name: a.name.clone(),
                vaults: a.vaults.clone(),
                token_present: account::has_token(&a.name),
            })
            .collect(),
        ambient_service_account_token: std::env::var_os(account::TOKEN_ENV)
            .is_some_and(|v| !v.is_empty()),
        forced_account: forced,
        default_ttl: dur(config.default_ttl),
        prompt_timeout: dur(config.prompt_timeout),
        effective_desktop_deadline: dur(deadline_for(&Auth::Desktop, &config)),
        stale_grace: dur(config.stale_grace),
        stderr_is_tty: std::io::stderr().is_terminal(),
        bypass: crate::command::is_truthy(std::env::var_os("OP_FAST_BYPASS").as_deref()),
    };

    if args.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }

    let r = &report;
    println!("op-fast {}", r.op_fast_version);
    match (&r.delegate.path, &r.delegate.error) {
        (Some(path), _) => println!(
            "delegate:   {} (from {}; {})",
            path,
            r.delegate.source.unwrap_or("?"),
            r.delegate.version.as_deref().unwrap_or("version unknown")
        ),
        (None, Some(e)) => println!("delegate:   ERROR {}", e),
        _ => {}
    }
    println!(
        "config:     {}{}",
        r.config.path,
        match (&r.config.error, r.config.exists) {
            (Some(e), _) => format!(" (ERROR {})", e),
            (None, false) => " (absent; defaults)".to_string(),
            _ => String::new(),
        }
    );
    println!(
        "store:      {} (valid {}, expired-in-grace {}, expired {}){}",
        r.store.path.as_deref().unwrap_or("?"),
        r.store.valid,
        r.store.expired_in_grace,
        r.store.expired,
        r.store
            .error
            .as_ref()
            .map(|e| format!(" ERROR {}", e))
            .unwrap_or_default()
    );
    println!("keyring:    {}", r.keyring);
    if r.service_accounts.is_empty() {
        println!("accounts:   none configured (desktop auth for everything)");
    }
    for a in &r.service_accounts {
        println!(
            "account:    {} [{}] token {}",
            a.name,
            a.vaults.join(", "),
            if a.token_present {
                "present"
            } else {
                "MISSING"
            }
        );
    }
    if r.ambient_service_account_token {
        println!("env:        OP_SERVICE_ACCOUNT_TOKEN is set; op-fast selects no account");
    }
    if let Some(f) = &r.forced_account {
        println!("forced:     {}", f);
    }
    println!(
        "timeouts:   default_ttl {}, prompt_timeout {}, desktop deadline now {}, stale_grace {}",
        r.default_ttl, r.prompt_timeout, r.effective_desktop_deadline, r.stale_grace
    );
    println!("stderr tty: {}", r.stderr_is_tty);
    if r.bypass {
        println!("bypass:     OP_FAST_BYPASS is set; every command goes straight to op");
    }
    Ok(())
}
