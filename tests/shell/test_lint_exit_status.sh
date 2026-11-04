#!/usr/bin/env bash
# test_lint_exit_status.sh -- bash-side exit codes of the CI lints (#6470).
#
# The python-side codes (findings, scan errors, unresolvable --base, git
# ls-files failure) are asserted by each script's own --selftest. The two
# exits decided in the bash wrapper -- usage error and "no working python"
# -- cannot be, so they are asserted here for the two scripts that document
# them in their "Exit status" header.
#
# Run:  bash tests/shell/test_lint_exit_status.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/yuzu_test_lint_exit.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

# A PATH holding only what the wrapper needs before it looks for python.
# `dirname` and `bash` are the only externals; python3/python are absent.
NOPY="$TMP/nopy"
mkdir -p "$NOPY"
ln -s "$(command -v dirname)" "$NOPY/dirname"
ln -s "$(command -v bash)" "$NOPY/bash"

fail=0
expect() { # expect <want-rc> <desc> <cmd...>
  local want="$1" desc="$2"; shift 2
  local got=0
  "$@" >/dev/null 2>&1 || got=$?
  if [ "$got" -eq "$want" ]; then echo "ok   - $desc (rc=$got)"
  else echo "FAIL - $desc: wanted rc=$want, got rc=$got"; fail=1; fi
}

for s in check-portable-paths check-plugin-spawn-lexical check-metrics-help-ascii; do
  script="$ROOT/scripts/ci/$s.sh"
  expect 2 "$s --bogus is a usage error" bash "$script" --bogus
  expect 2 "$s with no python interpreter" env PATH="$NOPY" "$NOPY/bash" "$script" --selftest
done

exit "$fail"
