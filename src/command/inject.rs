use std::io::{self, Read};
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, ValueHint};

use crate::config::Config;
use crate::fetch::Fetcher;
use crate::template;

fn parse_file_mode(s: &str) -> Result<u32> {
    u32::from_str_radix(s, 8).context("Invalid file mode (expected octal)")
}

#[derive(Debug, Parser)]
#[clap(
    about = "Inject secrets into a config file",
    long_about = "Inject secrets into a file templated with secret references.

You can pass in a config file templated with secret references and receive a
config file with the actual secrets substituted. Secrets are cached in the
OS keyring for offline access.

Supports two syntaxes:
  - {{ op://vault/item/field }}  (enclosed)
  - op://vault/item/field        (unenclosed)

Variables are resolved using shell environment:
  - $VAR
  - ${VAR}
  - ${VAR:-default}

Learn more about loading secrets into config files:
https://developer.1password.com/docs/cli/secrets-config-files",
    after_help = "Examples:
  Inject from stdin:
    echo 'password: {{ op://app-prod/db/password }}' | op-fast inject

  Inject from file to file:
    op-fast inject -i config.yml.tpl -o config.yml

  Use environment variables in references:
    echo 'db: op://$ENV/db/password' | ENV=prod op-fast inject
"
)]
pub struct InjectArgs {
    #[clap(
        value_hint = ValueHint::FilePath,
        help = "Input template file (reads from stdin if not specified)"
    )]
    pub file: Option<PathBuf>,

    #[clap(
        short = 'i',
        long = "in-file",
        value_name = "FILE",
        value_hint = ValueHint::FilePath,
        help = "Input template file (alias for positional argument)"
    )]
    pub in_file: Option<PathBuf>,

    #[clap(
        short = 'o',
        long = "out-file",
        value_name = "FILE",
        value_hint = ValueHint::FilePath,
        help = "Write output to a file instead of stdout"
    )]
    pub out_file: Option<PathBuf>,

    #[clap(
        long = "file-mode",
        value_name = "filemode",
        value_parser = parse_file_mode,
        default_value = "600",
        help = "Set file mode for the output file (octal, ignored without --out-file)"
    )]
    pub file_mode: u32,

    #[clap(short = 'f', long = "force", help = "Do not prompt for confirmation")]
    pub force: bool,

    #[clap(
        long = "refresh",
        help = "Bypass the cache, fetch from 1Password, and overwrite cached entries"
    )]
    pub refresh: bool,
}

pub fn execute(args: InjectArgs, sa: Option<&str>) -> Result<()> {
    let input_path = args.in_file.as_ref().or(args.file.as_ref());

    let input = match input_path {
        Some(path) => std::fs::read_to_string(path)
            .with_context(|| format!("Failed to read input file: {:?}", path))?,
        None => {
            let mut s = String::new();
            io::stdin().read_to_string(&mut s)?;
            s
        }
    };

    // Variables inside references must be set; elsewhere they expand
    // leniently, as before.
    let resolved = template::expand_text(&input, true)?;

    let references: Vec<String> = template::extract_references(&resolved)
        .into_iter()
        .collect();

    let output = if references.is_empty() {
        resolved
    } else {
        let config = Config::load()?;
        let fetcher = Fetcher::new(&config, sa, "inject")?;
        let stored_values = fetcher.resolve(&references, args.refresh)?;

        template::substitute_references(&resolved, |ref_str| stored_values.get(ref_str).cloned())
    };

    if let Some(out_file) = &args.out_file {
        crate::output::write_secret_file(out_file, output.as_bytes(), args.file_mode)?;
    } else {
        print!("{}", output);
    }

    Ok(())
}
