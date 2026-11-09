use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, ValueHint};

use crate::config::Config;
use crate::fetch::Fetcher;

fn parse_file_mode(s: &str) -> Result<u32> {
    u32::from_str_radix(s, 8).context("Invalid file mode (expected octal)")
}

#[derive(Debug, Parser)]
#[clap(
    about = "Read a secret reference",
    long_about = "Read the value of the field in 1Password specified by a secret reference.

Secrets are cached in the OS keyring for offline access with configurable TTL.

Secret reference syntax: op://<vault>/<item>/<field>

Learn more about secret references:
https://developer.1password.com/docs/cli/secrets-reference-syntax/",
    after_help = "Examples:
  Read a password:
    op-fast read op://app-prod/db/password

  Read with variable substitution:
    VAULT=prod op-fast read 'op://$VAULT/db/password'

  Save to a file with restricted permissions:
    op-fast read -o ./key.pem op://app-prod/ssh/private-key

  Bypass the cache after a rotation (overwrites the cached entry):
    op-fast read --refresh op://app-prod/db/password

Flags op-fast does not model (--account, --format, ...) send the whole
invocation to the real `op` unchanged.
"
)]
pub struct ReadArgs {
    #[clap(help = "Secret reference (e.g., op://vault/item/field)")]
    pub reference: String,

    #[clap(
        long = "file-mode",
        value_name = "filemode",
        value_parser = parse_file_mode,
        default_value = "600",
        help = "Set file mode for the output file (octal, ignored without --out-file)"
    )]
    pub file_mode: u32,

    #[clap(
        short = 'f',
        long = "force",
        help = "Do not prompt for confirmation (does NOT refresh the cache; see --refresh)"
    )]
    pub force: bool,

    #[clap(
        long = "refresh",
        help = "Bypass the cache, fetch from 1Password, and overwrite the cached entry"
    )]
    pub refresh: bool,

    #[clap(
        short = 'n',
        long = "no-newline",
        help = "Do not print a newline after the secret"
    )]
    pub no_newline: bool,

    #[clap(
        short = 'o',
        long = "out-file",
        value_name = "FILE",
        value_hint = ValueHint::FilePath,
        help = "Write the secret to a file instead of stdout"
    )]
    pub out_file: Option<PathBuf>,
}

pub fn execute(args: ReadArgs, sa: Option<&str>) -> Result<()> {
    // Expand `$VAR` first so the cache key, account selection, and audit
    // all use the reference that is actually fetched.
    let reference = crate::template::resolve_variables(&args.reference);

    let config = Config::load()?;
    let fetcher = Fetcher::new(&config, sa, "read")?;
    let mut values = fetcher.resolve(std::slice::from_ref(&reference), args.refresh)?;
    let value = values
        .remove(&reference)
        .context("op returned no value for the reference")?;

    // Printed only on success, so exit 75 keeps its single stderr line.
    if args.force && args.out_file.is_none() {
        eprintln!("note: -f does not refresh the cache; use --refresh");
    }

    if let Some(out_file) = &args.out_file {
        crate::output::write_secret_file(out_file, value.as_bytes(), args.file_mode)?;
    } else if args.no_newline {
        print!("{}", value);
    } else {
        println!("{}", value);
    }

    Ok(())
}
