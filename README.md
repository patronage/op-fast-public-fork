# op-fast: Speed up your 1Password CLI

`op-fast` is a proxy for the [1Password CLI], to make secret access much faster, like instantly ⚡

```
Benchmark 1: op read "op://Employee/Test Note/test"
  Time (mean ± σ):      2.031 s ±  0.032 s    [User: 0.072 s, System: 0.052 s]
  Range (min … max):    1.980 s …  2.062 s    5 runs

Benchmark 2: op-fast read "op://Employee/Test Note/test"
  Time (mean ± σ):      22.6 ms ±   1.7 ms    [User: 4.9 ms, System: 4.1 ms]
  Range (min … max):    21.2 ms …  25.2 ms    5 runs

Summary
  op-fast read "op://Employee/Test Note/test" ran
   90.00 ± 6.91 times faster than op read "op://Employee/Test Note/test"
```

It leverages OS keyrings to cache secrets that have already been fetched. To make it fast re-access without requiring re-authentication or network roundtrips.

## Features

- **Offline access**: Secrets cached in OS keyring (macOS Keychain, Linux keyutils)
- **Configurable TTL**: Set default expiration or per-secret patterns
- **Full CLI compatibility**: Drop-in replacement for `op` command; any flag op-fast does not model goes to the real `op` unchanged
- **Refresh**: `--refresh`, `op-fast refresh`, and `op-fast warm` re-fetch after a rotation
- **Fail fast**: delegate calls that wait on a desktop approval get a deadline; exit code 75 when approval is unavailable
- **Stale on auth failure**: expired entries are served (with a warning) when 1Password approval is unavailable
- **Service accounts**: per-vault service-account tokens, kept only in the OS keyring
- **Agent-facing diagnostics**: `agent-help`, `doctor`, `status`, `ref`

> This is the Patronage fork. See [PATRONAGE.md](PATRONAGE.md) for what it
> carries on top of upstream and how releases are cut.

## Installation

Check out the [releases page](https://github.com/cometkim/op-fast/releases) for pre-built binaries.

You can install it using Homebrew:

```bash
brew install cometkim/tap/op-fast
```

Or from source:

```bash
cargo install op-fast
```

## Usage

Basic usage is same with the original [1Password CLI].

### read

Read a secret reference:

```bash
# Read a password
op-fast read op://app-prod/db/password

# With variable substitution
VAULT=prod op-fast read 'op://$VAULT/db/password'

# Save to file (default mode: 600)
op-fast read -o ./key.pem op://app-prod/ssh/private-key

# Custom file mode
op-fast read -o ./key.pem --file-mode 644 op://app-prod/ssh/private-key

# Bypass the cache after a rotation and overwrite the cached entry
op-fast read --refresh op://app-prod/db/password
```

`-f/--force` keeps its `op` meaning ("do not prompt for confirmation"). It
does **not** refresh the cache; without `-o` op-fast prints a note saying so.

### inject

Inject secrets into a config template:

```bash
# From stdin
echo 'password: {{ op://app-prod/db/password }}' | op-fast inject

# From file to file
op-fast inject -i config.yml.tpl -o config.yml

# With environment variables
echo 'db: op://$ENV/db/password' | ENV=prod op-fast inject

# Custom output file mode
op-fast inject -i config.yml.tpl -o config.yml --file-mode 600
```

Supports two secret reference syntaxes:
- `{{ op://vault/item/field }}` (enclosed)
- `op://vault/item/field` (unenclosed)

### run

Pass secrets as environment variables to a process:

```bash
# With environment variable
DB_PASSWORD='op://app-prod/db/password' op-fast run -- printenv DB_PASSWORD
# Output: <concealed by 1Password>

# With env file
echo 'DB_PASSWORD=op://app-dev/db/password' > .env
op-fast run --env-file .env -- printenv DB_PASSWORD

# Switch environments with variables
cat .env
# DB_PASSWORD=op://$APP_ENV/db/password

APP_ENV=prod op-fast run --env-file .env -- printenv DB_PASSWORD

# Show secrets without masking
DB_PASSWORD='op://app-prod/db/password' op-fast run --no-masking -- printenv DB_PASSWORD

# Re-fetch every reference instead of using the cache
op-fast run --refresh --env-file .env -- ./deploy.sh
```

`inject` also accepts `--refresh`.

### refresh and warm

```bash
# Re-fetch specific references (prints counts, never values)
op-fast refresh 'op://app-prod/db/password'

# Re-fetch every cached entry
op-fast refresh --all

# At the desk, before leaving agents unattended: refresh everything in the
# store (valid and expired-in-grace) with one approval per account group
op-fast warm
op-fast warm --dry-run
op-fast warm --manifest ~/.config/op-fast/agents.refs   # one reference per line, # comments
```

`warm` makes one batched `op inject` call per account group, so all
desktop-authorized entries cost a single approval. If one reference in a
group fails for a reason other than approval (for example it was deleted),
op-fast retries that group one reference at a time so the rest still
refresh.

### status, doctor, ref, agent-help

```bash
# Cache state without the value: cached or not, stored-at, expires-at, and
# which account would serve a fetch
op-fast status 'op://app-prod/db/password' [--json]

# Health report: delegate path and version, store counts, accounts and token
# presence, TTL, prompt_timeout, TTY. Never prompts; the only op call is
# `op --version`. Use this instead of `op whoami` as a pre-check.
op-fast doctor [--json]

# Stable ID-based reference for an item with an awkward name. Prints no values.
op-fast ref 'Stripe (live)' 'secret key' --vault Agents
# => op://<vault-id>/<item-id>/<field-id>

# One screen of guidance for AI agents and scripts
op-fast agent-help
```

### Service accounts

Declare accounts in the config file and store each token with `op-fast sa`:

```toml
[[service_account]]
name = "agents"                 # also the keyring account name
vaults = ["Agents", "Shared"]   # vault names or IDs this account covers
ttl = "15m"                     # optional; absent = normal TTL resolution
```

```bash
op-fast sa add agents                   # hidden prompt
pbpaste | op-fast sa add agents --stdin
op-fast sa list [--json]
op-fast sa remove agents
```

- A reference uses the first account whose `vaults` contains its vault
  segment. `--sa <name>` or `OP_FAST_ACCOUNT=<name>` forces an account;
  `--sa none` forces desktop auth.
- Passthrough commands use the forced account, else the account covering
  `--vault <v>`, else desktop auth.
- op-fast sets `OP_SERVICE_ACCOUNT_TOKEN` on that one `op` child only. The
  process started by `op-fast run` never sees it.
- If your environment already has `OP_SERVICE_ACCOUNT_TOKEN`, op-fast leaves
  it alone and selects no account.
- `run`, `inject`, and `warm` make one delegate call per account group.
- Tokens live only in the OS keyring (service `op-fast-service-account`):
  never in the config file, on argv, in the audit log, or in error text. A
  `token` key in the config file is rejected.
- With no `[[service_account]]` configured, behavior is unchanged.

The command is `sa`, not `account`, because `op account` and
`op service-account` are real `op` commands that must pass through.

### store

Manage the `op-fast` store (OS keyring + cache metadata):

```bash
# List all cached secrets
op-fast store list

# Clear a specific secret
op-fast store clear 'op://vault/item/field'

# Clear all cached secrets
op-fast store clear
```

### Passthrough

Any unrecognized command is passed through to the real `op` binary:

```bash
op-fast item list  # => op item list
op-fast vault list # => op vault list
op-fast whoami     # => op whoami
```

Any flag op-fast does not model on `read`, `run`, or `inject` (`--account`,
`--vault`, `--format`, `--environment`, `--session`, `--cache`, `--config`,
`--debug`, `--iso-timestamps`, or anything unknown) sends the whole
invocation to the real `op` unchanged, minus op-fast's own `--sa` and
`--refresh`. Passthrough calls inherit stdio and get no deadline (`op run`
may run a long-lived process).

`OP_FAST_BYPASS=1` sends every invocation straight to the real `op`.

### Installing as `op`

op-fast can be the machine-wide `op`. When it looks for the real `op` on
`PATH`, it skips any candidate that resolves to its own executable and takes
the next one, so a symlink or copy named `op` earlier on `PATH` works with no
configuration:

```bash
ln -s "$(command -v op-fast)" ~/.local/bin/op   # ~/.local/bin before the real op on PATH
op doctor                                       # check which delegate it found
```

To pin the real binary instead, set `op_command` in the config file or
`OP_FAST_COMMAND` (which wins). As a shell-only alternative:

```bash
alias op=op-fast
```

## Configuration

Configuration file: `~/.config/op-fast/config.toml`

```toml
# Default TTL for cached secrets (default: 1day)
default_ttl = "1day"

# Deadline for op calls that may wait on a desktop approval when stderr is
# not a TTY (default: 15s). With a TTY the deadline is 60s.
prompt_timeout = "15s"

# How long expired entries are kept and may be served when approval is
# unavailable (default: 30days)
stale_grace = "30days"

# Path to the real op (OP_FAST_COMMAND wins; default: first op on PATH that
# is not op-fast itself)
op_command = "/opt/homebrew/bin/op"

[[service_account]]
name = "agents"
vaults = ["Agents"]
ttl = "15m"

# Per-secret TTL patterns (glob syntax)
[ttl]
"op://prod/*" = "1hour"
"op://dev/*" = "7days"
"op://*/ssh/*" = "30days"
```

### Environment Variables

| Variable | Description |
|----------|-------------|
| `OP_FAST_CONFIG` | Custom config file path |
| `OP_FAST_STORE_DIR` | Custom cache directory (the audit log lives under it) |
| `OP_FAST_DEFAULT_TTL` | Override default TTL (e.g., `12h`, `1day`) |
| `OP_FAST_PROMPT_TIMEOUT` | Override `prompt_timeout` |
| `OP_FAST_COMMAND` | Path to the real `op` (wins over `op_command`) |
| `OP_FAST_ACCOUNT` | Force a service account (`none` = desktop auth); `--sa` wins |
| `OP_FAST_NO_STALE` | `1` disables stale-on-auth-failure |
| `OP_FAST_BYPASS` | `1` sends every invocation straight to the real `op` |
| `OP_FAST_KEYRING_SERVICE` | Rename the keyring service (default `op-fast`; tokens use `<name>-service-account`) |

### Fail fast and stale on auth failure

Any `op` call that may need a desktop approval gets a deadline: 60 s when
stderr is a TTY, otherwise `prompt_timeout`. Service-account calls get a
30 s network deadline. At the deadline op-fast kills the child.

Expired entries stay in the store for `stale_grace`. When a fetch fails
because approval was unavailable (deadline hit, `authorization timeout`,
`authorization prompt dismissed`, desktop app unreachable) and an expired
entry is inside the grace window, op-fast returns it and prints:

```
warning: served expired cache for <ref> (expired <age> ago); 1Password approval unavailable
```

It never serves stale for other failures (item not found, invalid
reference, permission denied), never under `--refresh`, and never with
`OP_FAST_NO_STALE=1`.

### Exit codes

| Code | Meaning |
|------|---------|
| `0` | Success |
| `75` | Approval was needed, was unavailable, and nothing could be served. Stderr has exactly one line starting `op-fast: needs approval:` naming the reference(s) and the remedy. |
| other | The delegate `op`'s own exit code, or `1` for op-fast errors |

### TTL Format

Human-readable duration format:
- `30s` - 30 seconds
- `5m` - 5 minutes
- `1h` - 1 hour
- `1day` - 1 day
- `1w` - 1 week

## How It Works

1. Cache layer: LMDB stores cache metadata (TTL, timestamps), OS keyring stores secret values
2. Batch fetching: Multiple uncached secrets fetched in a single `op inject` call per account
3. Automatic GC: Entries expired longer than `stale_grace` are cleaned up with 10% probability on each invocation
4. Audit log: every hit, fetch, refresh, stale serve, error (with an error class), and passthrough is appended to `<store>/audit/*.jsonl`; inspect with `op-fast audit tail` and `op-fast audit summary [--json]`

## Security

Secrets stored in OS-native keyring (encrypted at rest)

## License

MIT

[1Password CLI]: https://developer.1password.com/docs/cli
