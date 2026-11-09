use std::ffi::{OsStr, OsString};

use anyhow::Result;
use clap::Parser;

use crate::account::{self, Selector};
use crate::audit::Entry;
use crate::config::Config;
use crate::delegate::OpDelegate;
use crate::error::ExitCode;

pub mod agent_help;
pub mod audit;
pub mod doctor;
pub mod inject;
pub mod read;
pub mod reference;
pub mod refresh;
pub mod run;
pub mod sa;
pub mod status;
pub mod store;
pub mod warm;

/// Commands op-fast implements itself. A clap error inside one of these is
/// a real usage error, never a passthrough.
pub const OWN_COMMANDS: &[&str] = &[
    "refresh",
    "warm",
    "status",
    "ref",
    "doctor",
    "agent-help",
    "sa",
    "store",
    "audit",
];

/// Commands op-fast accelerates; an unmodeled flag on these sends the whole
/// invocation to the real `op`.
pub const ACCELERATED_COMMANDS: &[&str] = &["read", "run", "inject"];

#[derive(Debug, Parser)]
pub enum Subcommand {
    Read(read::ReadArgs),

    Run(run::RunArgs),

    Inject(inject::InjectArgs),

    Refresh(refresh::RefreshArgs),

    Warm(warm::WarmArgs),

    Status(status::StatusArgs),

    Ref(reference::RefArgs),

    Doctor(doctor::DoctorArgs),

    AgentHelp(agent_help::AgentHelpArgs),

    Sa(sa::SaCommand),

    Store(store::StoreCommand),

    Audit(audit::AuditCommand),

    #[clap(external_subcommand)]
    Other(Vec<OsString>),
}

pub fn execute(subcommand: Subcommand, sa: Option<&str>) -> Result<()> {
    match subcommand {
        Subcommand::Read(args) => read::execute(args, sa),
        Subcommand::Run(args) => run::execute(args, sa),
        Subcommand::Inject(args) => inject::execute(args, sa),
        Subcommand::Refresh(args) => refresh::execute(args, sa),
        Subcommand::Warm(args) => warm::execute(args, sa),
        Subcommand::Status(args) => status::execute(args, sa),
        Subcommand::Ref(args) => reference::execute(args, sa),
        Subcommand::Doctor(args) => doctor::execute(args, sa),
        Subcommand::AgentHelp(args) => agent_help::execute(args),
        Subcommand::Sa(cmd) => sa::execute(cmd),
        Subcommand::Store(cmd) => store::execute(cmd),
        Subcommand::Audit(cmd) => audit::execute(cmd),
        Subcommand::Other(args) => passthrough(&args, sa, "delegated"),
    }
}

/// The first token naming a command op-fast knows about (own or
/// accelerated), skipping flags and our own `--sa <name>`.
pub fn known_command(args: &[OsString]) -> Option<String> {
    let mut iter = args.iter().skip(1);
    while let Some(arg) = iter.next() {
        let s = arg.to_string_lossy();
        if s == "--" {
            return None;
        }
        if s == "--sa" {
            iter.next();
            continue;
        }
        if OWN_COMMANDS.contains(&s.as_ref()) || ACCELERATED_COMMANDS.contains(&s.as_ref()) {
            return Some(s.into_owned());
        }
    }
    None
}

/// Remove op-fast's own flags (`--sa <name>`, `--sa=<name>`, `--refresh`)
/// from an invocation bound for the real `op`, stopping at `--`. Returns the
/// cleaned args (without argv[0]) and the `--sa` value.
pub fn strip_own_flags(args: &[OsString]) -> (Vec<OsString>, Option<String>) {
    let mut out = Vec::new();
    let mut sa = None;
    let mut iter = args.iter().skip(1);
    let mut after_dashdash = false;
    while let Some(arg) = iter.next() {
        if after_dashdash {
            out.push(arg.clone());
            continue;
        }
        let s = arg.to_string_lossy();
        if s == "--" {
            after_dashdash = true;
            out.push(arg.clone());
        } else if s == "--sa" {
            sa = iter.next().map(|v| v.to_string_lossy().into_owned());
        } else if let Some(v) = s.strip_prefix("--sa=") {
            sa = Some(v.to_string());
        } else if s == "--refresh" {
            // `op` always reads fresh; the flag only matters to the cache.
        } else {
            out.push(arg.clone());
        }
    }
    (out, sa)
}

/// Value of `--<name> <v>` or `--<name>=<v>` before any `--`.
fn flag_value<'a>(args: &'a [OsString], name: &str) -> Option<&'a str> {
    let long = format!("--{}", name);
    let eq = format!("--{}=", name);
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        let s = arg.to_str()?;
        if s == "--" {
            return None;
        }
        if s == long {
            return iter.next().and_then(|v| v.to_str());
        }
        if let Some(v) = s.strip_prefix(&eq) {
            return Some(v);
        }
    }
    None
}

/// Send an invocation to the real `op` unchanged (inherited stdio, no
/// deadline: `op run` may legitimately run for hours). Account selection
/// follows `--sa`/`OP_FAST_ACCOUNT`, then `--vault`, then desktop auth.
pub fn passthrough(args: &[OsString], sa: Option<&str>, outcome: &'static str) -> Result<()> {
    let config = Config::load()?;
    let selector = Selector::new(&config, sa)?;
    let auth = selector.for_vault(flag_value(args, "vault"));
    let token = account::token_for(&auth)?;

    let subcommand = args
        .first()
        .map(|arg| arg.to_string_lossy().into_owned())
        .unwrap_or_default();
    let reference = args
        .iter()
        .filter_map(|a| a.to_str())
        .find(|a| a.starts_with("op://"));
    crate::audit::log(Entry {
        op: "passthrough",
        reference,
        outcome,
        command: Some(&subcommand),
        account: Some(auth.label()),
        ..Entry::default()
    });

    let delegate = OpDelegate::new(&config)?;
    let mut cmd = delegate.command();
    cmd.args(args);
    if let Some(token) = &token {
        cmd.env(account::TOKEN_ENV, token);
    }
    let status = cmd.status()?;
    Err(ExitCode(status.code().unwrap_or(1)).into())
}

/// `OP_FAST_BYPASS=1`: every invocation goes straight to the real `op`.
pub fn bypass(args: &[OsString]) -> Result<()> {
    let config = Config::load_or_default();
    let rest: Vec<OsString> = args.iter().skip(1).cloned().collect();
    let subcommand = rest
        .first()
        .map(|a| a.to_string_lossy().into_owned())
        .unwrap_or_default();
    crate::audit::log(Entry {
        op: "passthrough",
        outcome: "bypass",
        command: Some(&subcommand),
        ..Entry::default()
    });
    let delegate = OpDelegate::new(&config)?;
    let status = delegate.command().args(&rest).status()?;
    Err(ExitCode(status.code().unwrap_or(1)).into())
}

pub fn is_truthy(v: Option<&OsStr>) -> bool {
    v.is_some_and(|v| !v.is_empty() && v != "0" && v != "false")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn os(v: &[&str]) -> Vec<OsString> {
        v.iter().map(OsString::from).collect()
    }

    #[test]
    fn strip_removes_only_our_flags_before_dashdash() {
        let (out, sa) = strip_own_flags(&os(&[
            "op",
            "run",
            "--sa",
            "agents",
            "--refresh",
            "--environment",
            "x",
            "--",
            "cmd",
            "--refresh",
            "--sa",
            "y",
        ]));
        assert_eq!(
            out,
            os(&[
                "run",
                "--environment",
                "x",
                "--",
                "cmd",
                "--refresh",
                "--sa",
                "y"
            ])
        );
        assert_eq!(sa.as_deref(), Some("agents"));

        let (out, sa) = strip_own_flags(&os(&[
            "op",
            "--sa=none",
            "read",
            "--account",
            "x",
            "op://a/b/c",
        ]));
        assert_eq!(out, os(&["read", "--account", "x", "op://a/b/c"]));
        assert_eq!(sa.as_deref(), Some("none"));
    }

    #[test]
    fn known_command_finds_first_known_token() {
        assert_eq!(
            known_command(&os(&["op", "--account", "x", "read", "r"])),
            Some("read".into())
        );
        assert_eq!(
            known_command(&os(&["op", "--sa", "store", "read"])),
            Some("read".into())
        );
        assert_eq!(
            known_command(&os(&["op", "store", "list", "--bogus"])),
            Some("store".into())
        );
        assert_eq!(known_command(&os(&["op", "item", "list"])), None);
    }

    #[test]
    fn flag_value_forms() {
        assert_eq!(
            flag_value(&os(&["item", "list", "--vault", "V"]), "vault"),
            Some("V")
        );
        assert_eq!(
            flag_value(&os(&["item", "list", "--vault=V"]), "vault"),
            Some("V")
        );
        assert_eq!(
            flag_value(&os(&["run", "--", "x", "--vault", "V"]), "vault"),
            None
        );
    }
}
