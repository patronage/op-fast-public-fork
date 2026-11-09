use anyhow::Result;
use clap::{Parser, Subcommand};

use crate::config::Config;
use crate::store::Store;

#[derive(Debug, Parser)]
#[clap(
    about = "Manage op-fast store",
    long_about = "Manage op-fast store and OS keyring.

Secrets are automatically cached when read from 1Password and expire
based on the configured TTL (time-to-live).",
    after_help = "Examples:
  List all cached secrets:
    op-fast store list
    op-fast store list --json

  Clear a specific secret:
    op-fast store clear 'op://vault/item/field'

  Clear all cached secrets:
    op-fast store clear
"
)]
pub struct StoreCommand {
    #[clap(subcommand)]
    pub command: StoreSubcommand,
}

#[derive(Debug, Subcommand)]
pub enum StoreSubcommand {
    #[clap(about = "List all cached secrets (references and timestamps, never values)")]
    List {
        #[clap(long, help = "Print JSON")]
        json: bool,
    },

    #[clap(about = "Clear cached secrets")]
    Clear {
        #[clap(help = "Secret reference to clear (clears all if not specified)")]
        reference: Option<String>,
    },
}

pub fn execute(cmd: StoreCommand) -> Result<()> {
    let config = Config::load_or_default();
    let store = Store::open(config.stale_grace)?;

    match cmd.command {
        StoreSubcommand::List { json } => {
            let entries = store.list()?;
            if json {
                let rows: Vec<serde_json::Value> = entries
                    .iter()
                    .map(|(reference, meta)| {
                        let state = if !meta.is_expired() {
                            "valid"
                        } else if meta.is_in_grace(config.stale_grace) {
                            "expired-in-grace"
                        } else {
                            "expired"
                        };
                        serde_json::json!({
                            "reference": reference,
                            "stored_at": meta.stored_at,
                            "expires_at": meta.expires_at(),
                            "state": state,
                        })
                    })
                    .collect();
                println!("{}", serde_json::to_string_pretty(&rows)?);
                return Ok(());
            }
            if entries.is_empty() {
                println!("Store is empty");
                return Ok(());
            }

            println!("{:<60} {:<20} STATUS", "REFERENCE", "STORED_AT");
            println!("{}", "-".repeat(90));

            for (reference, meta) in entries {
                let status = if !meta.is_expired() {
                    "valid"
                } else if meta.is_in_grace(config.stale_grace) {
                    "expired-in-grace"
                } else {
                    "expired"
                };
                let stored_at = chrono_conversion(meta.stored_at);
                println!("{:<60} {:<20} {}", reference, stored_at, status);
            }
        }
        StoreSubcommand::Clear { reference } => match reference {
            Some(ref_str) => {
                crate::template::validate_reference(&ref_str)?;
                let deleted = store.delete(&ref_str)?;
                let outcome = if deleted { "cleared" } else { "not-found" };
                crate::audit::record("store", Some(&ref_str), outcome, None, None);
                if deleted {
                    println!("Deleted: {}", ref_str);
                } else {
                    println!("Not found: {}", ref_str);
                }
            }
            None => {
                store.clear()?;
                crate::audit::record("store", None, "cleared-all", None, None);
                println!("Store cleared");
            }
        },
    }

    Ok(())
}

fn chrono_conversion(timestamp: u64) -> String {
    use std::time::{SystemTime, UNIX_EPOCH};

    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();

    let elapsed = now.saturating_sub(timestamp);

    if elapsed < 60 {
        format!("{}s ago", elapsed)
    } else if elapsed < 3600 {
        format!("{}m ago", elapsed / 60)
    } else if elapsed < 86400 {
        format!("{}h ago", elapsed / 3600)
    } else {
        format!("{}d ago", elapsed / 86400)
    }
}
