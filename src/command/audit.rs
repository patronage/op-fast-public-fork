use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use crate::audit;

#[derive(Debug, Parser)]
#[clap(
    about = "Inspect the local audit log",
    long_about = "Inspect the local audit log.

Every cache hit, delegate fetch, store mutation, and passthrough is
recorded as one JSON line under the audit directory, including the
calling process chain. Secret values are never logged.

The log is local-only and owned by your user: it provides attribution
and forensics, not tamper-proof evidence."
)]
pub struct AuditCommand {
    #[clap(subcommand)]
    pub command: AuditSubcommand,
}

#[derive(Debug, Subcommand)]
pub enum AuditSubcommand {
    #[clap(about = "Print the most recent audit events")]
    Tail {
        #[clap(short = 'n', long, default_value = "20", help = "Number of events")]
        lines: usize,
    },

    #[clap(about = "Summarize audit events by outcome, error class, account, and reference")]
    Summary {
        #[clap(long, help = "Print JSON")]
        json: bool,
    },
}

pub fn execute(cmd: AuditCommand) -> Result<()> {
    let dir = audit::audit_dir().context("Could not determine audit directory")?;

    let mut files: Vec<_> = match std::fs::read_dir(&dir) {
        Ok(entries) => entries
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|ext| ext == "jsonl"))
            .collect(),
        Err(_) => Vec::new(),
    };
    files.sort();

    let mut all_lines: Vec<String> = Vec::new();
    for file in &files {
        let contents = std::fs::read_to_string(file)
            .with_context(|| format!("Failed to read {}", file.display()))?;
        all_lines.extend(contents.lines().map(|l| l.to_string()));
    }

    if files.is_empty() && !matches!(cmd.command, AuditSubcommand::Summary { json: true }) {
        println!("No audit log yet ({})", dir.display());
        return Ok(());
    }

    match cmd.command {
        AuditSubcommand::Tail { lines } => {
            let start = all_lines.len().saturating_sub(lines);
            for line in &all_lines[start..] {
                println!("{}", line);
            }
        }
        AuditSubcommand::Summary { json } => {
            let summary = audit::summarize(all_lines.iter().map(|l| l.as_str()));
            if json {
                println!("{}", serde_json::to_string_pretty(&summary)?);
                return Ok(());
            }
            println!("Events: {}", summary.total);
            if summary.malformed > 0 {
                println!("Malformed lines: {}", summary.malformed);
            }
            println!("\nBy outcome:");
            for (outcome, count) in &summary.by_outcome {
                println!("  {:<12} {}", outcome, count);
            }
            if !summary.by_error_class.is_empty() {
                println!("\nBy error class:");
                for (class, count) in &summary.by_error_class {
                    println!("  {:<22} {}", class, count);
                }
            }
            if !summary.by_account.is_empty() {
                println!("\nBy account:");
                for (account, count) in &summary.by_account {
                    println!("  {:<22} {}", account, count);
                }
            }
            println!("\nBy reference:");
            for (reference, count) in &summary.by_reference {
                println!("  {:<60} {}", reference, count);
            }
        }
    }

    Ok(())
}
