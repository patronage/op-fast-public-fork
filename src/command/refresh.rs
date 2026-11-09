use anyhow::{Result, bail};
use clap::Parser;

use crate::config::Config;
use crate::fetch::Fetcher;

#[derive(Debug, Parser)]
#[clap(
    about = "Re-fetch cached references from 1Password (prints no values)",
    long_about = "Bypass the cache for the given references (or every cached entry with
--all), fetch them from 1Password, and overwrite the cached entries.
Prints counts only, never values.

Use this after a secret is rotated. `read --refresh` does the same for one
reference and prints the value.",
    after_help = "Examples:
  op-fast refresh 'op://app-prod/db/password'
  op-fast refresh --all
"
)]
pub struct RefreshArgs {
    #[clap(help = "Secret references to refresh")]
    pub references: Vec<String>,

    #[clap(
        long,
        conflicts_with = "references",
        help = "Refresh every cached entry"
    )]
    pub all: bool,
}

pub fn execute(args: RefreshArgs, sa: Option<&str>) -> Result<()> {
    if args.references.is_empty() && !args.all {
        bail!("give one or more references, or --all");
    }
    let config = Config::load()?;
    let fetcher = Fetcher::new(&config, sa, "refresh")?;
    let refs = if args.all {
        crate::command::warm::store_references(&fetcher, &config)?.0
    } else {
        args.references
    };
    let report = fetcher.warm(&refs);
    crate::command::warm::finish(&report)
}
