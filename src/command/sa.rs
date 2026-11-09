//! `op-fast sa`: manage service-account tokens in the OS keyring.
//!
//! Named `sa` rather than `account` because `op account` and
//! `op service-account` are real `op` commands that op-fast must pass
//! through untouched when installed as `op`.

use std::io::{IsTerminal, Read, Write};

use anyhow::{Context, Result, bail};
use clap::{Parser, Subcommand};
use serde::Serialize;

use crate::account;
use crate::config::{Config, validate_account_name};

#[derive(Debug, Parser)]
#[clap(
    about = "Manage service-account tokens (stored only in the OS keyring)",
    long_about = "Manage 1Password service-account tokens for op-fast.

Declare accounts in config.toml:

  [[service_account]]
  name = \"agents\"                 # also the keyring account name
  vaults = [\"Agents\", \"Shared\"]   # vault names or IDs it covers
  ttl = \"15m\"                     # optional

then store each token with `op-fast sa add <name>`. A reference whose vault
is listed uses that account: op-fast sets OP_SERVICE_ACCOUNT_TOKEN on that
one `op` child only. Tokens never go in config, on argv, or in logs.",
    after_help = "Examples:
  op-fast sa add agents            # prompts with hidden input
  pbpaste | op-fast sa add agents --stdin
  op-fast sa list
  op-fast sa remove agents
"
)]
pub struct SaCommand {
    #[clap(subcommand)]
    pub command: SaSubcommand,
}

#[derive(Debug, Subcommand)]
pub enum SaSubcommand {
    #[clap(about = "Store a token (hidden TTY input, or --stdin)")]
    Add {
        name: String,
        #[clap(long, help = "Read the token from stdin instead of a hidden prompt")]
        stdin: bool,
    },

    #[clap(about = "List configured accounts and whether a token is stored")]
    List {
        #[clap(long, help = "Print JSON")]
        json: bool,
    },

    #[clap(about = "Delete a stored token")]
    Remove { name: String },
}

#[derive(Serialize)]
struct Row {
    name: String,
    vaults: Vec<String>,
    ttl: Option<String>,
    token: bool,
    configured: bool,
}

pub fn execute(cmd: SaCommand) -> Result<()> {
    match cmd.command {
        SaSubcommand::Add { name, stdin } => {
            validate_account_name(&name)?;
            let config = Config::load_or_default();
            if config.account(&name).is_none() {
                eprintln!(
                    "warning: no [[service_account]] named {:?} in {}; the token will be unused until you add one",
                    name,
                    config.path.display()
                );
            }
            let token = if stdin {
                let mut s = String::new();
                std::io::stdin().read_to_string(&mut s)?;
                s
            } else {
                read_hidden(&format!("Service account token for {}: ", name))?
            };
            let token = token.trim();
            if token.is_empty() {
                bail!("empty token; nothing stored");
            }
            if token.contains(char::is_whitespace) {
                bail!("token contains whitespace; nothing stored");
            }
            if !token.starts_with("ops_") {
                eprintln!("warning: token does not start with 'ops_'; storing it anyway");
            }
            account::store_token(&name, token)?;
            crate::audit::log(crate::audit::Entry {
                op: "sa",
                outcome: "token-stored",
                account: Some(&name),
                ..Default::default()
            });
            println!("Stored token for {}", name);
        }
        SaSubcommand::List { json } => {
            let config = Config::load()?;
            let rows: Vec<Row> = config
                .service_accounts
                .iter()
                .map(|a| Row {
                    name: a.name.clone(),
                    vaults: a.vaults.clone(),
                    ttl: a.ttl.map(|d| humantime::format_duration(d).to_string()),
                    token: account::has_token(&a.name),
                    configured: true,
                })
                .collect();
            if json {
                println!("{}", serde_json::to_string_pretty(&rows)?);
            } else if rows.is_empty() {
                println!(
                    "No [[service_account]] configured in {}",
                    config.path.display()
                );
            } else {
                println!("{:<20} {:<8} {:<10} VAULTS", "NAME", "TOKEN", "TTL");
                for r in rows {
                    println!(
                        "{:<20} {:<8} {:<10} {}",
                        r.name,
                        if r.token { "present" } else { "missing" },
                        r.ttl.as_deref().unwrap_or("default"),
                        r.vaults.join(", ")
                    );
                }
            }
        }
        SaSubcommand::Remove { name } => {
            validate_account_name(&name)?;
            let removed = account::remove_token(&name)?;
            crate::audit::log(crate::audit::Entry {
                op: "sa",
                outcome: if removed {
                    "token-removed"
                } else {
                    "not-found"
                },
                account: Some(&name),
                ..Default::default()
            });
            if removed {
                println!("Removed token for {}", name);
            } else {
                println!("No token stored for {}", name);
            }
        }
    }
    Ok(())
}

/// Read one line from the terminal with echo off.
fn read_hidden(prompt: &str) -> Result<String> {
    let stdin = std::io::stdin();
    if !stdin.is_terminal() {
        bail!("stdin is not a terminal; pass --stdin to read the token from a pipe");
    }
    eprint!("{}", prompt);
    std::io::stderr().flush().ok();

    let fd = libc::STDIN_FILENO;
    let mut term: libc::termios = unsafe { std::mem::zeroed() };
    if unsafe { libc::tcgetattr(fd, &mut term) } != 0 {
        bail!("could not read terminal settings");
    }
    let original = term;
    term.c_lflag &= !libc::ECHO;
    term.c_lflag |= libc::ECHONL;
    if unsafe { libc::tcsetattr(fd, libc::TCSANOW, &term) } != 0 {
        bail!("could not disable terminal echo");
    }
    let mut line = String::new();
    let result = stdin.read_line(&mut line).context("failed to read token");
    unsafe { libc::tcsetattr(fd, libc::TCSANOW, &original) };
    result?;
    Ok(line)
}
