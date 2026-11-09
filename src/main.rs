use std::ffi::OsString;

use clap::Parser;
use clap::error::ErrorKind;

mod account;
mod audit;
mod command;
mod config;
mod delegate;
mod error;
mod fetch;
mod keyring;
mod output;
mod store;
mod template;

use error::{DelegateError, EXIT_NEEDS_APPROVAL, ExitCode, NeedsApproval};

#[derive(Debug, Parser)]
#[clap(
    name = "op-fast",
    version,
    disable_help_subcommand = true,
    subcommand_required = true,
    arg_required_else_help = true,
    override_usage = "op-fast <command> [flags]",
    about = "1Password CLI proxy for instant access to secrets",
    long_about = "1Password CLI proxy for instant access to secrets

It caches 1Password secret references in the OS keyring with configurable TTL.
Provides instant access to previously fetched secrets without requiring
re-authentication or network roundtrips.

All other commands (item, vault, whoami, ...) and any read/run/inject call
with a flag op-fast does not model are passed through to the real 'op'.

Exit code 75 means 1Password approval was needed and unavailable; see
`op-fast agent-help`.",
    after_help = "Agents and scripts: start with `op-fast agent-help`."
)]
struct Cli {
    #[clap(
        long,
        global = true,
        value_name = "NAME",
        help = "Force a service account for this call ('none' forces desktop auth)"
    )]
    sa: Option<String>,

    #[clap(subcommand)]
    subcommand: command::Subcommand,
}

fn main() {
    env_logger::init();
    let code = match run(std::env::args_os().collect()) {
        Ok(()) => 0,
        Err(e) => report(e),
    };
    std::process::exit(code);
}

fn run(args: Vec<OsString>) -> anyhow::Result<()> {
    // Invoked as `op`: version, help, and a bare call belong to the real op.
    if command::is_op_meta_invocation(&args) {
        let rest: Vec<OsString> = args.iter().skip(1).cloned().collect();
        return command::raw_delegate(&rest, "meta");
    }

    if command::is_truthy(std::env::var_os("OP_FAST_BYPASS").as_deref())
        && !command::is_own_command(&args)
    {
        return command::bypass(&args);
    }

    store::init()?;

    match Cli::try_parse_from(&args) {
        Ok(cli) => command::execute(cli.subcommand, cli.sa.as_deref()),
        Err(err) if is_passthrough(&args, &err) => {
            // `--refresh` is ours only on read/run/inject.
            let accelerated = command::known_command(&args)
                .is_some_and(|c| command::ACCELERATED_COMMANDS.contains(&c.as_str()));
            let (rest, sa) = command::strip_own_flags(&args, accelerated);
            command::passthrough(&rest, sa.as_deref(), "unmodeled-flag")
        }
        Err(err) => err.exit(),
    }
}

/// An unknown flag on `read`/`run`/`inject` (or before an unknown command)
/// means the caller wants real `op` behavior op-fast does not model.
fn is_passthrough(args: &[OsString], err: &clap::Error) -> bool {
    if err.kind() != ErrorKind::UnknownArgument {
        return false;
    }
    match command::known_command(args) {
        Some(cmd) => command::ACCELERATED_COMMANDS.contains(&cmd.as_str()),
        None => true,
    }
}

fn report(e: anyhow::Error) -> i32 {
    if let Some(exit) = e.downcast_ref::<ExitCode>() {
        return exit.0;
    }
    if let Some(needs) = e.downcast_ref::<NeedsApproval>() {
        eprintln!("{}", needs.line());
        return EXIT_NEEDS_APPROVAL;
    }
    if let Some(de) = e.downcast_ref::<DelegateError>() {
        let msg = de.message.trim_end();
        if !msg.is_empty() {
            eprintln!("{}", msg);
        }
        return de.code;
    }
    eprintln!("op-fast: {:#}", e);
    1
}
