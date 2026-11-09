use anyhow::Result;
use clap::Parser;

#[derive(Debug, Parser)]
#[clap(about = "One-screen guide for AI agents and scripts")]
pub struct AgentHelpArgs {}

pub const TEXT: &str = "\
op-fast: caching proxy for the 1Password CLI. Use it exactly like `op`.

WHICH COMMAND
  one secret to stdout       op-fast read 'op://Vault/Item/field'
  secrets into a process     op-fast run --env-file .env -- <cmd>
  secrets into a file        op-fast inject -i tpl -o out
  cache state, no values     op-fast status 'op://...' [--json]
  health check, no prompts   op-fast doctor [--json]
  stable ID-based reference  op-fast ref '<item>' '<field>' --vault <v>

PREFER `run` OVER `$(op-fast read ...)` IN ARGUMENTS
  Command-line arguments show up in `ps` and shell history. Put references
  in env vars or an env file and let `op-fast run` resolve them.

STALE VALUE AFTER A ROTATION?
  op-fast read --refresh 'op://...'     fetch, overwrite cache, print
  op-fast refresh 'op://...'            fetch, overwrite cache, print nothing
  `read -f` does NOT refresh; it only skips confirmation prompts like `op`.

EXIT CODE 75 = NEEDS APPROVAL
  1Password wanted a desktop approval and nobody gave one in time. Stderr
  has one line starting `op-fast: needs approval:`. Do not retry in a loop.
  Ask the human to run `op-fast warm` at the desk, or to configure a
  service account (`op-fast sa --help`) for the vault.
  If an expired cached value exists (within stale_grace), op-fast serves
  it with a `warning: served expired cache` line instead of failing.

DO NOT
  - use `op whoami` as a pre-check: under desktop integration it often
    says \"not signed in\" even when reads work. Use `op-fast doctor`.
  - paste `--reveal` output, `read` output, or env dumps into logs, chat,
    commits, or files that are not mode 600.
  - guess at item names with spaces or slashes; use `op-fast ref`.

SERVICE ACCOUNTS
  References in vaults listed under [[service_account]] in config.toml are
  fetched with that account's token (no desktop prompt). Force one with
  `--sa <name>` or OP_FAST_ACCOUNT; `--sa none` forces desktop auth.

ESCAPE HATCHES
  Any flag op-fast does not model (--account, --format, ...) sends the
  whole command to the real `op`. OP_FAST_BYPASS=1 skips op-fast entirely.
  op-fast store clear 'op://...' deletes one cached entry.
";

pub fn execute(_args: AgentHelpArgs) -> Result<()> {
    print!("{}", TEXT);
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn fits_on_one_screen() {
        assert!(super::TEXT.lines().count() < 60);
    }
}
