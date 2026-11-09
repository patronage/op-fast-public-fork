# Patronage fork of op-fast

This is [Patronage](https://github.com/patronage)'s fork of
[cometkim/op-fast](https://github.com/cometkim/op-fast). We forked to own the
release channel for a binary that sits on the critical path of secret access,
and to carry a small patch queue on top of upstream.

## Carried changes

1. **Output file permissions applied at creation** — `read -o` / `inject -o`
   no longer have a window where the secret is world-readable; `inject -o`
   defaults to mode 600. *(Offered upstream.)*
2. **Sentinel-delimited batch parsing** — `run` / `inject` batch fetches can
   no longer mis-assign values between references; multi-line secrets (SSH
   keys, PEM) are safe. *(Offered upstream.)*
3. **Local audit log** — every cache hit, fetch, store mutation, and
   passthrough is logged as JSONL under `<store>/audit/` with calling
   process-chain attribution. Values are never logged. Inspect with
   `op-fast audit tail` / `op-fast audit summary`. Local-only and
   best-effort: attribution and forensics, not tamper-proof evidence.
   Since 0.2.0 each event also carries an `error_class`, the `account`
   used, a `session` id (from `CLAUDE_CODE_SESSION_ID`, `CODEX_SESSION_ID`,
   or `PI_SESSION_ID`), and up to 8 ancestors.

Added in `0.2.0-patronage.1` (safe to install as the machine-wide `op`):

4. **Refresh** — `--refresh` on `read`/`run`/`inject`, plus `op-fast refresh`
   and `op-fast warm` (one approval per account group, counts only).
   `read -f` keeps its `op` meaning and prints a note that it does not
   refresh.
5. **Service accounts** — `[[service_account]]` config with per-vault
   selection; tokens only in the OS keyring (`op-fast sa add|list|remove`),
   handed to one delegate child via `OP_SERVICE_ACCOUNT_TOKEN`.
6. **Fail fast** — delegate deadlines (60 s with a TTY, `prompt_timeout`
   otherwise, 30 s for service accounts); exit 75 with one
   `op-fast: needs approval:` line when nothing can be served.
7. **Stale on auth failure** — expired entries kept for `stale_grace`
   (default 30 days) and served with a warning only when approval was
   unavailable.
8. **Drop-in compatibility** — unmodeled flags on `read`/`run`/`inject`
   pass the whole invocation to real `op`; `op_command` config; the PATH
   search skips op-fast itself (so an `op` symlink works); delegate
   recursion guard; `OP_FAST_BYPASS=1`.
9. **Agent-facing surface** — all commands visible in `--help`;
   `agent-help`, `doctor`, `status`, `ref`; `store list --json`,
   `audit summary --json`.
10. **Test harness** — `tests/cli.rs` drives the built binary against
    `tests/fake-op.sh` with an isolated store, config, and (debug builds
    only) a directory-backed keyring, so tests never touch the real
    Keychain or 1Password.

These touch upstream files (`delegate.rs`, `store/db.rs`, the command
modules) more than the first three; new logic lives in new files
(`account.rs`, `fetch.rs`, `error.rs`, `keyring.rs`, `command/*.rs`) where
practical.

## Releases

Cut from tags matching `v<upstream-version>-patronage.<n>` by
[patronage-release.yml](.github/workflows/patronage-release.yml):
macOS ARM only, fail-closed `cargo deny` + `cargo audit` + tests before the
build, SHA-256 checksums, and Sigstore build-provenance attestation.
Binaries are **not** codesigned (no Apple Developer ID). Verify a download:

```sh
shasum -a 256 -c <archive>.sha256
gh attestation verify <archive> --repo patronage/op-fast
```

After upgrading the binary, run `op-fast store clear` once — macOS Keychain
ACLs bind cached items to the exact binary that wrote them. The same applies
to service-account tokens: re-run `op-fast sa add <name>` for each account
after an upgrade, or the first unattended token read may raise a Keychain
prompt. Then run `op-fast warm` (or let reads repopulate the cache) and
`op-fast doctor` to confirm.

To install a release as the machine-wide `op`, put a symlink named `op` to
the pinned op-fast binary in a directory that comes before the real `op` on
`PATH` (for example `ln -s ~/.local/bin/op-fast ~/.local/bin/op`), then run
`op doctor` and check that `delegate:` names the real 1Password CLI. To back
out, delete the symlink or export `OP_FAST_BYPASS=1`.

Patronage developers: install via `secrets/install-op-fast.sh` in
[patronage-internal](https://github.com/patronage/internal), which pins a
version and its checksum.

## Maintenance

- On upstream releases (or quarterly): merge upstream `main`, review the full
  delta by hand, re-run the release pipeline.
- Keep carried changes additive (own files where possible) so merges stay
  clean; drop patches as upstream absorbs them.
- Upstream base at fork time: `88523a6` (audited 2026-07-23).
