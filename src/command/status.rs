use anyhow::Result;
use clap::Parser;
use serde::Serialize;

use crate::account::Selector;
use crate::config::Config;
use crate::store::Store;

#[derive(Debug, Parser)]
#[clap(
    about = "Show cache state for references (never values)",
    long_about = "Show whether each reference is cached, when it was stored, when it expires,
and which account would serve a fetch. Reads metadata only: never the value,
never the keyring, never 1Password."
)]
pub struct StatusArgs {
    #[clap(required = true, help = "Secret references")]
    pub references: Vec<String>,

    #[clap(long, help = "Print JSON")]
    pub json: bool,
}

#[derive(Debug, Serialize)]
struct Row<'a> {
    reference: &'a str,
    /// valid | expired-in-grace | expired | absent
    state: &'static str,
    stored_at: Option<u64>,
    expires_at: Option<u64>,
    account: String,
}

pub fn execute(args: StatusArgs, sa: Option<&str>) -> Result<()> {
    for reference in &args.references {
        crate::template::validate_reference(reference)?;
    }
    let config = Config::load()?;
    let selector = Selector::new(&config, sa)?;
    let store = Store::open_read_only()?;

    let mut rows = Vec::new();
    for reference in &args.references {
        let meta = store.meta(reference)?;
        let state = match &meta {
            None => "absent",
            Some(m) if !m.is_expired() => "valid",
            Some(m) if m.is_in_grace(config.stale_grace) => "expired-in-grace",
            Some(_) => "expired",
        };
        rows.push(Row {
            reference,
            state,
            stored_at: meta.as_ref().map(|m| m.stored_at),
            expires_at: meta.as_ref().map(|m| m.expires_at()),
            account: selector.for_reference(reference).label().to_string(),
        });
    }

    if args.json {
        println!("{}", serde_json::to_string_pretty(&rows)?);
        return Ok(());
    }
    for row in rows {
        let when = |t: Option<u64>| t.map(fmt_ts).unwrap_or_else(|| "-".to_string());
        println!(
            "{}\n  state: {}\n  stored: {}\n  expires: {}\n  account: {}",
            row.reference,
            row.state,
            when(row.stored_at),
            when(row.expires_at),
            row.account
        );
    }
    Ok(())
}

/// RFC 3339 UTC timestamp.
pub fn fmt_ts(secs: u64) -> String {
    humantime::format_rfc3339_seconds(std::time::UNIX_EPOCH + std::time::Duration::from_secs(secs))
        .to_string()
}
