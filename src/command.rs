use std::ffi::{OsStr, OsString};

use anyhow::Result;
use clap::Parser;

use crate::account::{self, Auth, Selector};
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
        Subcommand::Other(args) => {
            // clap hands external subcommands everything, including our own
            // flags; strip them wherever they appear before `--`.
            let mut with_argv0 = vec![OsString::from("op-fast")];
            with_argv0.extend(args);
            let (rest, inner_sa) = strip_own_flags(&with_argv0, false);
            passthrough(&rest, inner_sa.as_deref().or(sa), "delegated")
        }
    }
}

/// `op` flags that take a value, so the value is not mistaken for a
/// subcommand when looking for positionals.
const VALUE_FLAGS: &[&str] = &[
    "--sa",
    "--account",
    "--config",
    "--encoding",
    "--format",
    "--session",
    "--vault",
    "--environment",
    "--env-file",
    "--out-file",
    "-o",
    "--in-file",
    "-i",
    "--file-mode",
];

/// Positional words before `--` (argv[0] excluded), skipping flags and the
/// values of known value-taking flags.
pub fn positionals(args: &[OsString]) -> Vec<String> {
    let mut out = Vec::new();
    let mut iter = args.iter().skip(1);
    while let Some(arg) = iter.next() {
        let s = arg.to_string_lossy();
        if s == "--" {
            break;
        }
        if s.starts_with('-') {
            if VALUE_FLAGS.contains(&s.as_ref()) {
                iter.next();
            }
            continue;
        }
        out.push(s.into_owned());
    }
    out
}

/// The subcommand, if op-fast knows it (own or accelerated).
pub fn known_command(args: &[OsString]) -> Option<String> {
    positionals(args).into_iter().next().filter(|s| {
        OWN_COMMANDS.contains(&s.as_str()) || ACCELERATED_COMMANDS.contains(&s.as_str())
    })
}

/// Remove op-fast's own flags (`--sa <name>`, `--sa=<name>`, and with
/// `refresh` also `--refresh`) wherever they appear before `--`. Returns
/// the cleaned args (without argv[0]) and the `--sa` value.
pub fn strip_own_flags(args: &[OsString], refresh: bool) -> (Vec<OsString>, Option<String>) {
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
        } else if refresh && s == "--refresh" {
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

/// Passthrough subcommands that may receive a service-account token: they
/// only talk to 1Password and never execute a caller-supplied program.
/// `args` excludes argv[0] and op-fast's own flags.
///
/// Strict shape: the subcommand must be the very first argument and its
/// sub-subcommand (for `item`, `vault`, `document`, `user`) the next one.
/// Any flag before them, a bare `run`/`plugin`, or `--debug`/`--config`
/// anywhere before `--` means no token.
pub fn token_allowed(args: &[OsString]) -> bool {
    let words: Vec<&str> = args
        .iter()
        .map(|a| a.to_str().unwrap_or("\u{fffd}"))
        .take_while(|a| *a != "--")
        .collect();
    if words.iter().any(|w| matches!(*w, "run" | "plugin")) {
        return false;
    }
    // `--debug` and `--config` change what `op` prints and where it reads
    // state from; never combine them with a token.
    if words.iter().any(|w| {
        *w == "--debug"
            || w.starts_with("--debug=")
            || *w == "--config"
            || w.starts_with("--config=")
    }) {
        return false;
    }
    let first = words.first().copied();
    let second = words.get(1).copied();
    match (first, second) {
        (Some("read" | "inject" | "whoami"), _) => true,
        (Some("item"), Some("get" | "list" | "create" | "edit" | "delete" | "template")) => true,
        (Some("vault"), Some("get" | "list")) => true,
        (Some("document"), Some("get")) => true,
        (Some("user"), Some("get")) => words.contains(&"--me"),
        _ => false,
    }
}

/// Send an invocation to the real `op` unchanged (inherited stdio, no
/// deadline: `op run` may legitimately run for hours). Account selection:
/// the account covering `--vault`, then `--sa`/`OP_FAST_ACCOUNT`, then
/// desktop auth. A token is only handed to allowlisted, non-executing
/// subcommands, and only to a 1Password-signed `op`.
pub fn passthrough(args: &[OsString], sa: Option<&str>, outcome: &'static str) -> Result<()> {
    // A reference with a control character is refused before any audit
    // write or delegate call.
    for arg in args.iter().take_while(|a| *a != "--") {
        let text = arg.to_string_lossy();
        if text.contains("op://") && text.chars().any(char::is_control) {
            anyhow::bail!("secret reference contains a control character; refusing it");
        }
    }
    let config = Config::load_or_default();
    let selector = Selector::new(&config, sa)?;
    let mut auth = selector.for_vault(flag_value(args, "vault"));

    let subcommand = args
        .first()
        .map(|arg| arg.to_string_lossy().into_owned())
        .unwrap_or_default();

    if let Auth::Account(name) = &auth
        && !token_allowed(args)
    {
        let first = positionals(
            &[OsString::from("op")]
                .into_iter()
                .chain(args.iter().cloned())
                .collect::<Vec<_>>(),
        )
        .into_iter()
        .next()
        .unwrap_or_default();
        if first == "run" {
            anyhow::bail!(
                "refusing to pass service account {:?} to `op run`: the token would reach the child process. \
                 Drop the flags op-fast does not model so `op-fast run` resolves the references itself, \
                 or pass `--sa none` with no `--vault`",
                name
            );
        }
        eprintln!(
            "note: service account {:?} is not used for `op {}`; passing through with desktop auth",
            name, first
        );
        auth = Auth::Desktop;
    }

    let delegate = OpDelegate::new(&config)?;
    let token = match &auth {
        Auth::Account(_) => {
            delegate.verify_for_token()?;
            account::token_for(&auth)?
        }
        _ => None,
    };

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

    let mut cmd = delegate.command_with_token(token.as_deref())?;
    cmd.args(args);
    let status = cmd.status()?;
    Err(ExitCode(status.code().unwrap_or(1)).into())
}

/// Hand an invocation (without argv[0]) to the real `op` with no token and
/// no account selection.
pub fn raw_delegate(args: &[OsString], outcome: &'static str) -> Result<()> {
    let config = Config::load_or_default();
    let subcommand = args
        .first()
        .map(|a| a.to_string_lossy().into_owned())
        .unwrap_or_default();
    crate::audit::log(Entry {
        op: "passthrough",
        outcome,
        command: Some(&subcommand),
        ..Entry::default()
    });
    let delegate = OpDelegate::new(&config)?;
    let status = delegate.command().args(args).status()?;
    Err(ExitCode(status.code().unwrap_or(1)).into())
}

/// `OP_FAST_BYPASS=1`: everything except op-fast-only commands goes
/// straight to the real `op`, with `--sa` stripped.
pub fn bypass(args: &[OsString]) -> Result<()> {
    let (rest, _) = strip_own_flags(args, false);
    raw_delegate(&rest, "bypass")
}

/// Whether this invocation is an op-fast-only command.
pub fn is_own_command(args: &[OsString]) -> bool {
    known_command(args).is_some_and(|c| OWN_COMMANDS.contains(&c.as_str()))
}

/// When invoked as `op`, these go to the real `op` so callers see its
/// version and help, not op-fast's.
pub fn is_op_meta_invocation(args: &[OsString]) -> bool {
    let invoked_as_op = args
        .first()
        .and_then(|a| std::path::Path::new(a).file_name())
        .is_some_and(|n| n == "op");
    if !invoked_as_op {
        return false;
    }
    match args.get(1).and_then(|a| a.to_str()) {
        None => args.len() == 1,
        Some("--version" | "-v" | "--help" | "-h" | "help") => true,
        // `op read --help` etc. show the real op's help.
        Some("read" | "run" | "inject") => args[2..]
            .iter()
            .take_while(|a| *a != "--")
            .any(|a| a == "--help" || a == "-h"),
        Some(_) => false,
    }
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
        let (out, sa) = strip_own_flags(
            &os(&[
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
            ]),
            true,
        );
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

        let (out, sa) = strip_own_flags(
            &os(&["op", "--sa=none", "read", "--account", "x", "op://a/b/c"]),
            true,
        );
        assert_eq!(out, os(&["read", "--account", "x", "op://a/b/c"]));
        assert_eq!(sa.as_deref(), Some("none"));

        let (out, _) = strip_own_flags(
            &os(&["op", "item", "list", "--sa", "a", "--refresh"]),
            false,
        );
        assert_eq!(out, os(&["item", "list", "--refresh"]));
    }

    #[test]
    fn known_command_is_the_first_positional() {
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
        assert_eq!(known_command(&os(&["op", "item", "get", "store"])), None);
        assert_eq!(known_command(&os(&["op", "item", "list"])), None);
    }

    #[test]
    fn token_allowlist() {
        let ok = |v: &[&str]| token_allowed(&os(v));
        assert!(ok(&["read", "--account", "x", "op://a/b/c"]));
        assert!(ok(&["inject", "-i", "x"]));
        assert!(ok(&["whoami"]));
        assert!(ok(&["item", "get", "x", "--vault", "V"]));
        assert!(ok(&["item", "list", "--vault", "V"]));
        assert!(ok(&["vault", "list"]));
        assert!(ok(&["document", "get", "x"]));
        assert!(ok(&["user", "get", "--me"]));
        assert!(!ok(&["user", "get", "someone"]));
        assert!(!ok(&["run", "--environment", "x", "--", "printenv"]));
        assert!(!ok(&["--account", "x", "run", "--", "sh"]));
        // Flag ordering cannot smuggle a different subcommand past the check.
        assert!(!ok(&[
            "--no-masking",
            "read",
            "run",
            "--",
            "/bin/sh",
            "-c",
            "x"
        ]));
        assert!(!ok(&["--format", "json", "item", "list"]));
        assert!(!ok(&["item", "--vault", "X", "get", "y"]));
        assert!(!ok(&["read", "plugin"]));
        assert!(!ok(&["read", "op://a/b/c", "--debug"]));
        assert!(!ok(&["item", "list", "--config", "/tmp/x"]));
        assert!(!ok(&["item", "list", "--config=/tmp/x"]));
        assert!(!ok(&["item", "get", "y", "--debug=1"]));
        assert!(!ok(&["item", "get", "y", "--debug=true"]));
        assert!(ok(&["read", "op://a/b/c", "--", "--debug"]));
        assert!(ok(&["read", "op://a/b/c", "--", "run"]));
        for cmd in [
            "plugin",
            "signin",
            "signout",
            "account",
            "service-account",
            "connect",
            "completion",
            "events-api",
        ] {
            assert!(!ok(&[cmd, "list"]), "{}", cmd);
        }
        assert!(!ok(&["vault", "create", "x"]));
        assert!(!ok(&["document", "create", "x"]));
    }

    #[test]
    fn op_meta_invocations() {
        assert!(is_op_meta_invocation(&os(&[
            "/usr/local/bin/op",
            "--version"
        ])));
        assert!(is_op_meta_invocation(&os(&["op", "-h"])));
        assert!(is_op_meta_invocation(&os(&["op", "help"])));
        assert!(is_op_meta_invocation(&os(&["op"])));
        assert!(!is_op_meta_invocation(&os(&["op", "read", "x"])));
        assert!(is_op_meta_invocation(&os(&["op", "read", "--help"])));
        assert!(is_op_meta_invocation(&os(&["op", "run", "-h"])));
        assert!(is_op_meta_invocation(&os(&["op", "inject", "--help"])));
        assert!(!is_op_meta_invocation(&os(&[
            "op", "run", "--", "x", "--help"
        ])));
        assert!(!is_op_meta_invocation(&os(&["op-fast", "read", "--help"])));
        assert!(!is_op_meta_invocation(&os(&["op-fast", "--version"])));
        assert!(!is_op_meta_invocation(&os(&["op-fast"])));
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
