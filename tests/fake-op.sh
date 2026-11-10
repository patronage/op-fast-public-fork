#!/bin/sh
# Fake 1Password CLI for op-fast integration tests. Never touches 1Password.
#
# Environment (all optional):
#   FAKE_OP_VALUES  file of "<reference>\t<value>" lines, re-read every call
#   FAKE_OP_LOG     append one line per call: "<token-label>\t<args...>"
#                   (inject calls append "\tstdin:<ref>" for each reference)
#   FAKE_OP_TOKENS  file of "<token>\t<label>" lines; the log records the
#                   label for OP_SERVICE_ACCOUNT_TOKEN, never the token
#   FAKE_OP_STDERR  fail every call (except --version) with this stderr
#   FAKE_OP_EXIT    exit code for FAKE_OP_STDERR / missing values (default 1)
#   FAKE_OP_FAIL_DESKTOP_ONLY  only fail when no token is set
#   FAKE_OP_SLEEP   sleep this many seconds before answering
#   FAKE_OP_ITEM_JSON  file printed for `item get`
#   FAKE_OP_ENV_LOG  append which OP_* variables are set (presence only)
#   FAKE_OP_TTY_READ  for `read`, read the value from /dev/tty instead
#   FAKE_OP_GRANDCHILD  background a `sleep` and write its PID to this file
#                       before sleeping (process-group kill test)
#
# `run ... -- cmd args` execs cmd, like the real `op run` would.

code="${FAKE_OP_EXIT:-1}"

if [ -n "${OP_SERVICE_ACCOUNT_TOKEN:-}" ]; then
  label="unknown"
  if [ -n "${FAKE_OP_TOKENS:-}" ] && [ -f "$FAKE_OP_TOKENS" ]; then
    found=$(awk -F '\t' -v t="$OP_SERVICE_ACCOUNT_TOKEN" '$1 == t { print $2; exit }' "$FAKE_OP_TOKENS")
    [ -n "$found" ] && label="$found"
  fi
else
  label="unset"
fi

stdin_refs=""
if [ "${1:-}" = "inject" ]; then
  template=$(cat)
  stdin_refs=$(printf '%s\n' "$template" | awk '/^op:\/\// { printf "\tstdin:%s", $0 }')
fi

if [ -n "${FAKE_OP_ENV_LOG:-}" ]; then
  # Presence only, never values.
  for v in OP_DEBUG OP_CONFIG_DIR OP_ACCOUNT OP_SESSION_fake OP_FORMAT; do
    eval "isset=\${$v+x}"
    if [ -n "$isset" ]; then printf '%s=set ' "$v"; else printf '%s=unset ' "$v"; fi
  done >> "$FAKE_OP_ENV_LOG"
  printf 'token=%s\n' "$label" >> "$FAKE_OP_ENV_LOG"
fi

if [ -n "${FAKE_OP_LOG:-}" ]; then
  line="$label"
  for a in "$@"; do line="$line	$a"; done
  printf '%s%s\n' "$line" "$stdin_refs" >> "$FAKE_OP_LOG"
fi

if [ "${1:-}" = "--version" ]; then
  echo "2.99.0-fake"
  exit 0
fi

for a in "$@"; do
  if [ "$a" = "--help" ] || [ "$a" = "-h" ]; then
    echo "fake-op: $*"
    exit 0
  fi
done

if [ -n "${FAKE_OP_GRANDCHILD:-}" ]; then
  sleep 30 &
  echo $! > "$FAKE_OP_GRANDCHILD"
  sleep 30
  exit 0
fi

if [ -n "${FAKE_OP_SLEEP:-}" ]; then
  exec sleep "$FAKE_OP_SLEEP"
fi

if [ -n "${FAKE_OP_STDERR:-}" ]; then
  if [ -z "${FAKE_OP_FAIL_DESKTOP_ONLY:-}" ] || [ "$label" = "unset" ]; then
    echo "$FAKE_OP_STDERR" >&2
    exit "$code"
  fi
fi

# Values may contain `\n` escapes for multi-line secrets.
lookup() {
  [ -n "${FAKE_OP_VALUES:-}" ] && [ -f "$FAKE_OP_VALUES" ] || return 1
  raw=$(awk -F '\t' -v r="$1" '$1 == r { print $2; found = 1; exit } END { exit !found }' "$FAKE_OP_VALUES") || return 1
  printf '%b' "$raw"
}

not_found() {
  echo "[ERROR] 2026/11/09 12:00:00 could not read secret '$1': \"item\" isn't an item in the \"vault\" vault" >&2
  exit "$code"
}

case "${1:-}" in
  read)
    if [ -n "${FAKE_OP_TTY_READ:-}" ]; then
      printf 'enter value: ' > /dev/tty
      IFS= read -r v < /dev/tty
      printf '%s\n' "$v"
      exit 0
    fi
    ref=""
    for a in "$@"; do
      case "$a" in op://*) ref="$a" ;; esac
    done
    value=$(lookup "$ref") || not_found "$ref"
    printf '%s\n' "$value"
    ;;
  inject)
    out=""
    nl='
'
    while IFS= read -r l; do
      case "$l" in
        op://*) v=$(lookup "$l") || not_found "$l"; out="$out$v$nl" ;;
        *) out="$out$l$nl" ;;
      esac
    done <<TEMPLATE
$template
TEMPLATE
    printf '%s' "$out"
    ;;
  run)
    while [ $# -gt 0 ] && [ "$1" != "--" ]; do shift; done
    [ $# -gt 0 ] && shift
    exec "$@"
    ;;
  item)
    if [ "${2:-}" = "get" ] && [ -n "${FAKE_OP_ITEM_JSON:-}" ]; then
      cat "$FAKE_OP_ITEM_JSON"
    else
      echo "fake-op: $*"
    fi
    ;;
  *)
    echo "fake-op: $*"
    ;;
esac
