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
ACLs bind cached items to the exact binary that wrote them.

Patronage developers: install via `secrets/install-op-fast.sh` in
[patronage-internal](https://github.com/patronage/internal), which pins a
version and its checksum.

## Maintenance

- On upstream releases (or quarterly): merge upstream `main`, review the full
  delta by hand, re-run the release pipeline.
- Keep carried changes additive (own files where possible) so merges stay
  clean; drop patches as upstream absorbs them.
- Upstream base at fork time: `88523a6` (audited 2026-07-23).
