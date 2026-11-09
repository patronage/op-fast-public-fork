use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, ValueHint};

use crate::config::Config;
use crate::error::{ErrorClass, ExitCode, NeedsApproval};
use crate::fetch::{Fetcher, WarmReport};

#[derive(Debug, Parser)]
#[clap(
    about = "Refresh every cached entry in one approval per account (prints no values)",
    long_about = "Refresh every entry in the store (valid and expired-but-in-grace), or the
references listed in a manifest file. Makes one batched `op inject` call per
account group, so desktop-authorized entries cost a single approval.

Run it at the desk before leaving agents unattended. Prints counts only
(refreshed, failed, skipped), never values.",
    after_help = "Examples:
  op-fast warm
  op-fast warm --dry-run
  op-fast warm --manifest ~/.config/op-fast/agents.refs

Manifest format: one secret reference per line; `#` starts a comment.
"
)]
pub struct WarmArgs {
    #[clap(
        long,
        value_name = "FILE",
        value_hint = ValueHint::FilePath,
        help = "Refresh the references listed in FILE instead of the store"
    )]
    pub manifest: Option<PathBuf>,

    #[clap(long, help = "List what would be refreshed, and by which account")]
    pub dry_run: bool,
}

/// References in the store worth warming (valid or expired-in-grace), and
/// those skipped because they are past the grace window.
pub fn store_references(fetcher: &Fetcher, config: &Config) -> Result<(Vec<String>, Vec<String>)> {
    let store = fetcher.store().context("store unavailable")?;
    let mut keep = Vec::new();
    let mut skipped = Vec::new();
    for (reference, meta) in store.list()? {
        if !meta.is_expired() || meta.is_in_grace(config.stale_grace) {
            keep.push(reference);
        } else {
            skipped.push(reference);
        }
    }
    Ok((keep, skipped))
}

pub fn parse_manifest(contents: &str) -> Vec<String> {
    contents
        .lines()
        .map(|l| l.split('#').next().unwrap_or("").trim())
        .filter(|l| !l.is_empty())
        .map(str::to_string)
        .collect()
}

pub fn execute(args: WarmArgs, sa: Option<&str>) -> Result<()> {
    let config = Config::load()?;
    let fetcher = Fetcher::new(&config, sa, "warm")?;

    let (refs, skipped) = match &args.manifest {
        Some(path) => {
            let contents = std::fs::read_to_string(path)
                .with_context(|| format!("Failed to read manifest {}", path.display()))?;
            (parse_manifest(&contents), Vec::new())
        }
        None => store_references(&fetcher, &config)?,
    };

    if args.dry_run {
        for r in &refs {
            let auth = fetcher.selector().for_reference(r);
            println!("{}\t{}", auth.label(), r);
        }
        println!("would refresh: {}, skipped: {}", refs.len(), skipped.len());
        return Ok(());
    }

    let mut report = fetcher.warm(&refs);
    report.skipped.extend(skipped);
    finish(&report)
}

/// Print counts and pick the exit code shared by `warm` and `refresh`.
pub fn finish(report: &WarmReport) -> Result<()> {
    println!(
        "refreshed: {}, failed: {}, skipped: {}",
        report.refreshed.len(),
        report.failed.len(),
        report.skipped.len()
    );
    let approval: Vec<String> = report
        .failed
        .iter()
        .filter(|(_, c)| *c == ErrorClass::ApprovalUnavailable)
        .map(|(r, _)| r.clone())
        .collect();
    if !approval.is_empty() {
        return Err(NeedsApproval { subjects: approval }.into());
    }
    if !report.failed.is_empty() {
        for (r, class) in &report.failed {
            eprintln!("failed: {} ({})", r, class.as_str());
        }
        return Err(ExitCode(1).into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifest_parsing_skips_comments_and_blanks() {
        let refs =
            parse_manifest("# header\nop://a/b/c\n\n  op://d/e/f  # trailing\n#op://x/y/z\n");
        assert_eq!(
            refs,
            vec!["op://a/b/c".to_string(), "op://d/e/f".to_string()]
        );
    }
}
