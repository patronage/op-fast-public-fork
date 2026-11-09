use std::collections::HashMap;
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

    let mut env_vars: HashMap<String, String> = HashMap::new();

    for (key, value) in std::env::vars() {
        env_vars.insert(key, value);
    }

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
                    env_vars.insert(key.to_string(), value.to_string());
                }
            }
        }
    }

    // Expand `$VAR` first, then look for references, so `op://$VAULT/...`
    // resolves and the cache key is the expanded reference. Values without
    // a reference are passed through byte-for-byte.
    let mut expanded_env: HashMap<String, String> = HashMap::new();
    for (key, value) in &env_vars {
        if value.contains("op://") {
            expanded_env.insert(key.clone(), template::resolve_variables(value));
        }
    }

    let references: Vec<String> = expanded_env
        .values()
        .flat_map(|v| template::extract_references(v))
        .collect::<std::collections::BTreeSet<_>>()
        .into_iter()
        .collect();

    let stored_values: HashMap<String, String> = if references.is_empty() {
        HashMap::new()
    } else {
        let config = Config::load()?;
        let fetcher = Fetcher::new(&config, sa, "run")?;
        fetcher.resolve(&references, args.refresh)?
    };

    let resolver = |ref_str: &str| stored_values.get(ref_str).cloned();

    let mut resolved_env: HashMap<String, String> = env_vars;
    for (key, value) in &expanded_env {
        resolved_env.insert(
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

    let secrets: Vec<Vec<u8>> = stored_values
        .into_values()
        .filter(|s| !s.is_empty())
        .map(String::into_bytes)
        .collect();

    if args.no_masking {
        let status = std::process::Command::new(program)
            .args(cmd_args)
            .envs(&resolved_env)
            .status()?;
        std::process::exit(status.code().unwrap_or(1));
    }

    let mut child = std::process::Command::new(program)
        .args(cmd_args)
        .env_clear()
        .envs(&resolved_env)
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
    std::process::exit(status.code().unwrap_or(1));
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

fn mask_bytes(input: &[u8], secrets: &[Vec<u8>]) -> Vec<u8> {
    let mut result = input.to_vec();
    for secret in secrets {
        if secret.is_empty() {
            continue;
        }
        let mut out = Vec::with_capacity(result.len());
        let mut i = 0;
        while i < result.len() {
            if result[i..].starts_with(secret) {
                out.extend_from_slice(MASK.as_bytes());
                i += secret.len();
            } else {
                out.push(result[i]);
                i += 1;
            }
        }
        result = out;
    }
    result
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
