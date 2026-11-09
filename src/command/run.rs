use std::collections::{BTreeMap, HashMap};
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::Stdio;

use anyhow::Result;
use clap::Parser;

use crate::config::Config;
use crate::fetch::Fetcher;
use crate::template;

const MASK: &str = "<concealed by 1Password>";

#[derive(Debug, Parser)]
#[clap(
    about = "Pass secrets as environment variables to a process",
    long_about = "Pass secrets as environment variables to an application or script.

Scans environment variables for secret references, loads the corresponding
secrets from 1Password, then runs the provided command with the secrets
made available as environment variables.

Precedence order (highest to lowest):
  1. Environment files (--env-file)
  2. Shell environment variables

Secrets printed to stdout and stderr are concealed by default.
Use --no-masking to disable masking.",
    after_help = "Examples:
  Run with environment variable:
    DB_PASSWORD='op://app-prod/db/password' op-fast run -- printenv DB_PASSWORD

  Use an environment file:
    echo 'DB_PASSWORD=op://app-dev/db/password' > .env
    op-fast run --env-file .env -- printenv DB_PASSWORD

  Use variables to switch environments:
    cat .env
    DB_PASSWORD=op://$APP_ENV/db/password

    APP_ENV=prod op-fast run --env-file .env -- printenv DB_PASSWORD

  Show secrets without masking:
    DB_PASSWORD='op://app-prod/db/password' op-fast run --no-masking -- printenv DB_PASSWORD

  Run a subshell to expand variables:
    MY_VAR='op://vault/item/field' op-fast run --no-masking -- sh -c 'echo \"$MY_VAR\"'
"
)]
pub struct RunArgs {
    #[clap(
        long = "env-file",
        value_name = "FILE",
        help = "Environment file to load (can be specified multiple times)"
    )]
    pub env_files: Vec<PathBuf>,

    #[clap(
        long = "no-masking",
        help = "Disable masking of secrets on stdout and stderr"
    )]
    pub no_masking: bool,

    #[clap(
        long = "refresh",
        help = "Bypass the cache, fetch from 1Password, and overwrite cached entries"
    )]
    pub refresh: bool,

    #[clap(
        trailing_var_arg = true,
        help = "Command to run (use -- to separate flags)"
    )]
    pub command: Vec<String>,
}

pub fn execute(args: RunArgs, sa: Option<&str>) -> Result<()> {
    if args.command.is_empty() {
        anyhow::bail!("No command specified");
    }

    // Precedence: --env-file entries over the inherited environment.
    // An inherited value is a secret reference only when the whole value
    // (trimmed) is one `op://vault/item/field` reference; its variables are
    // then expanded strictly. Every other inherited value reaches the child
    // byte-for-byte. Env-file values are variable-expanded, and references
    // embedded in larger values are resolved, as before.
    let mut with_refs: BTreeMap<String, String> = BTreeMap::new();
    for (key, value) in std::env::vars_os() {
        if let (Some(key), Some(value)) = (key.to_str(), value.to_str())
            && template::is_whole_reference(value)
        {
            let expanded = template::expand_reference(value.trim())?;
            with_refs.insert(key.to_string(), expanded);
        }
    }

    let mut overrides: BTreeMap<String, String> = BTreeMap::new();
    for env_file in &args.env_files {
        if env_file.exists() {
            let contents = std::fs::read_to_string(env_file)?;
            for line in contents.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') {
                    continue;
                }
                if let Some((key, value)) = line.split_once('=') {
                    let key = key.trim();
                    let value = value.trim();
                    let value = value
                        .strip_prefix('"')
                        .and_then(|v| v.strip_suffix('"'))
                        .or_else(|| value.strip_prefix('\'').and_then(|v| v.strip_suffix('\'')))
                        .unwrap_or(value);
                    let expanded = template::expand_text(value, true)?;
                    if expanded.contains("op://") {
                        with_refs.insert(key.to_string(), expanded.clone());
                    } else {
                        with_refs.remove(key);
                    }
                    overrides.insert(key.to_string(), expanded);
                }
            }
        }
    }

    let references: Vec<String> = with_refs
        .values()
        .flat_map(|v| template::extract_references(v))
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();
    for r in &references {
        template::validate_reference(r)?;
    }

    let stored_values: HashMap<String, String> = if references.is_empty() {
        HashMap::new()
    } else {
        let config = Config::load()?;
        let fetcher = Fetcher::new(&config, sa, "run")?;
        fetcher.resolve(&references, args.refresh)?
    };

    let resolver = |ref_str: &str| stored_values.get(ref_str).cloned();
    for (key, value) in &with_refs {
        overrides.insert(
            key.clone(),
            template::substitute_references(value, resolver),
        );
    }

    // The child's argv is passed through untouched: secrets reach it only
    // through its environment (like `op run`), never by op-fast expanding
    // variables or references inside arguments.
    let (program, cmd_args) = args
        .command
        .split_first()
        .ok_or_else(|| anyhow::anyhow!("Empty command"))?;

    let secrets = mask_patterns(stored_values.values());

    if args.no_masking {
        let status = std::process::Command::new(program)
            .args(cmd_args)
            .envs(&overrides)
            .status()?;
        std::process::exit(exit_code(status));
    }

    let mut child = std::process::Command::new(program)
        .args(cmd_args)
        .envs(&overrides)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

    let mut readers = Vec::new();
    if let Some(stdout) = child.stdout.take() {
        let secrets = secrets.clone();
        readers.push(std::thread::spawn(move || {
            copy_masked(stdout, std::io::stdout(), &secrets)
        }));
    }
    if let Some(stderr) = child.stderr.take() {
        let secrets = secrets.clone();
        readers.push(std::thread::spawn(move || {
            copy_masked(stderr, std::io::stderr(), &secrets)
        }));
    }

    let status = child.wait()?;
    // Drain every byte before exiting.
    for reader in readers {
        let _ = reader.join();
    }
    std::process::exit(exit_code(status));
}

/// The child's exit code, or `128 + signal` when a signal killed it.
fn exit_code(status: std::process::ExitStatus) -> i32 {
    use std::os::unix::process::ExitStatusExt;
    match (status.code(), status.signal()) {
        (Some(code), _) => code,
        (None, Some(sig)) => 128 + sig,
        _ => 1,
    }
}

/// Byte patterns to mask: every secret, plus each line (4+ characters) of a
/// multi-line secret, longest first so a shorter secret that is a substring
/// of a longer one cannot expose the longer one's remainder.
fn mask_patterns<'a>(values: impl Iterator<Item = &'a String>) -> Vec<Vec<u8>> {
    let mut patterns: std::collections::BTreeSet<Vec<u8>> = std::collections::BTreeSet::new();
    for value in values {
        if value.is_empty() {
            continue;
        }
        patterns.insert(value.as_bytes().to_vec());
        if value.contains('\n') {
            for line in value.split('\n') {
                let line = line.trim_end_matches('\r');
                if line.chars().count() >= 4 {
                    patterns.insert(line.as_bytes().to_vec());
                }
            }
        }
    }
    let mut patterns: Vec<Vec<u8>> = patterns.into_iter().collect();
    patterns.sort_by_key(|p| std::cmp::Reverse(p.len()));
    patterns
}

/// Copy `input` to `output` line by line as raw bytes (invalid UTF-8 is
/// preserved), replacing every secret with the mask.
fn copy_masked<R: std::io::Read, W: Write>(input: R, mut output: W, secrets: &[Vec<u8>]) {
    let mut reader = BufReader::new(input);
    let mut line = Vec::new();
    loop {
        line.clear();
        match reader.read_until(b'\n', &mut line) {
            Ok(0) | Err(_) => break,
            Ok(_) => {
                let masked = mask_bytes(&line, secrets);
                if output.write_all(&masked).is_err() {
                    break;
                }
            }
        }
    }
    let _ = output.flush();
}

/// Replace every occurrence of every secret with the mask in one pass:
/// all match ranges are found on the original bytes, overlapping and
/// adjacent ranges are merged, and each merged range is replaced once. Text
/// that was already masked is never matched again.
fn mask_bytes(input: &[u8], secrets: &[Vec<u8>]) -> Vec<u8> {
    let mut ranges: Vec<(usize, usize)> = Vec::new();
    for secret in secrets {
        if secret.is_empty() || secret.len() > input.len() {
            continue;
        }
        for start in 0..=input.len() - secret.len() {
            if input[start..].starts_with(secret) {
                ranges.push((start, start + secret.len()));
            }
        }
    }
    if ranges.is_empty() {
        return input.to_vec();
    }
    ranges.sort_unstable();
    let mut merged: Vec<(usize, usize)> = Vec::with_capacity(ranges.len());
    for (start, end) in ranges {
        match merged.last_mut() {
            Some(last) if start <= last.1 => last.1 = last.1.max(end),
            _ => merged.push((start, end)),
        }
    }
    let mut out = Vec::with_capacity(input.len());
    let mut pos = 0;
    for (start, end) in merged {
        out.extend_from_slice(&input[pos..start]);
        out.extend_from_slice(MASK.as_bytes());
        pos = end;
    }
    out.extend_from_slice(&input[pos..]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn masks_secrets_and_keeps_invalid_utf8() {
        let secrets = vec![b"s3cr3t".to_vec()];
        assert_eq!(
            mask_bytes(b"a s3cr3t b \xff s3cr3t\n", &secrets),
            b"a <concealed by 1Password> b \xff <concealed by 1Password>\n".to_vec()
        );
    }

    #[test]
    fn multi_line_secrets_mask_every_line_and_longest_first() {
        let pem = "-----BEGIN KEY-----\nabcdefgh\nxy\n-----END KEY-----".to_string();
        let short = "BEGIN".to_string();
        let patterns = mask_patterns([pem.clone(), short].iter());
        assert!(patterns.windows(2).all(|w| w[0].len() >= w[1].len()));
        let line = mask_bytes(b"leak: abcdefgh\n", &patterns);
        assert_eq!(line, b"leak: <concealed by 1Password>\n".to_vec());
        // "xy" is under 4 characters and stays as is.
        assert_eq!(mask_bytes(b"xy\n", &patterns), b"xy\n".to_vec());
        // The longer line wins over the substring secret "BEGIN".
        assert_eq!(
            mask_bytes(b"-----BEGIN KEY-----\n", &patterns),
            b"<concealed by 1Password>\n".to_vec()
        );
    }

    fn masked(line: &str, values: &[&str]) -> String {
        let values: Vec<String> = values.iter().map(|v| v.to_string()).collect();
        let patterns = mask_patterns(values.iter());
        String::from_utf8(mask_bytes(line.as_bytes(), &patterns)).unwrap()
    }

    #[test]
    fn b8_line_pattern_before_another_secret_does_not_hide_it() {
        assert_eq!(
            masked(
                "FAKEPEMHEAD-12345abcdefSECRET",
                &["FAKEPEMHEAD-12345ab\nFAKE-PEM-LINE-2", "abcdefSECRET"]
            ),
            "<concealed by 1Password>"
        );
    }

    #[test]
    fn b8_patterns_never_match_inside_inserted_mask_text() {
        for word in ["word", "concealed", "1Password"] {
            let values = [&*format!("{}\nother-line", word), "s3cr3t-value"];
            let out = masked("x s3cr3t-value y", &values);
            assert_eq!(out, "x <concealed by 1Password> y", "{}", word);
        }
    }

    #[test]
    fn b8_overlapping_and_prefix_secrets_mask_once() {
        assert_eq!(
            masked("aaXXXXbbbbYY", &["XXXXbb", "bbbbYY"]),
            "aa<concealed by 1Password>"
        );
        assert_eq!(
            masked("key=TOKEN123456", &["TOKEN", "TOKEN123456"]),
            "key=<concealed by 1Password>"
        );
        assert_eq!(
            masked("TOKEN and TOKEN123", &["TOKEN123", "TOKEN"]),
            "<concealed by 1Password> and <concealed by 1Password>"
        );
        assert_eq!(masked("abcabc", &["abc"]), "<concealed by 1Password>");
    }

    #[test]
    fn copy_masked_is_lossless() {
        let input: Vec<u8> = (0..20000u32)
            .flat_map(|n| format!("{}\n", n).into_bytes())
            .chain(b"\xff\xfe tail without newline".iter().copied())
            .collect();
        let mut out = Vec::new();
        copy_masked(&input[..], &mut out, &[]);
        assert_eq!(out, input);
    }
}
