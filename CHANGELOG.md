# Version 0.2.0-patronage.1 (unreleased)

Makes op-fast safe to install as the machine-wide `op`.

- `--refresh` on `read`, `run`, `inject`; new `refresh <ref>...|--all` and
  `warm [--manifest FILE] [--dry-run]` commands. `read -f` keeps `op`
  semantics and prints a note that it does not refresh.
- Service accounts: `[[service_account]]` config, `op-fast sa add|list|remove`,
  per-vault selection, `--sa <name>|none`, `OP_FAST_ACCOUNT`. Tokens live only
  in the OS keyring and reach one delegate child.
- Delegate deadlines (60 s TTY / `prompt_timeout`, default 15 s / 30 s for
  service accounts) and exit code 75 with a single `op-fast: needs approval:`
  line.
- Stale on auth failure: expired entries are kept for `stale_grace` (default
  30 days) and served with a warning when approval is unavailable.
  `OP_FAST_NO_STALE=1` disables it. GC now removes entries only after the grace
  window.
- Drop-in compatibility: unmodeled flags on `read`/`run`/`inject` pass the
  whole invocation to real `op`; `op_command` config; the PATH search skips
  op-fast itself; `OP_FAST_BYPASS=1`.
- New `agent-help`, `doctor`, `status`, `ref` commands; every command is listed
  in `--help`; `store list --json`; `audit summary --json`.
- Audit events gain `error_class`, `account`, `session`, and an 8-level process
  chain. New outcomes `refreshed` and `stale-served`.
- `run` no longer treats unknown flags before `--` as part of the command.
- Hardening before use as the default `op`: service-account tokens only go to
  a 1Password-signed delegate and to non-executing passthrough subcommands;
  the PATH search ignores relative entries; configured delegate paths must be
  absolute; approval-unavailable needs an anchored message and a desktop call;
  invoked as `op`, version/help go to the real `op`; deadline kills take the
  process group; `prompt_timeout` has a 1 s floor; passthrough survives a
  broken config; doctor checks token presence without reading tokens.
- Fixes: `read`/`run` expand `$VAR` before caching; masked `run` output is
  byte-exact and fully drained; `run` leaves argv untouched; a reference no
  longer swallows a following `op://` or `NAME=` across whitespace.

# Unreleased

Remove db-store from dependencies. To make sure secrets are only stored in OS native keyring, and avoid binary bloating by accidently added turso library.

Binary size is shrunk down by ~16M (24M -> 8M)

# Version 0.1.0 (2026-02-26)

Initial release (alpha)
