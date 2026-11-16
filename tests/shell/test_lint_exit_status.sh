#!/usr/bin/env bash
# test_lint_exit_status.sh -- bash-side exit codes of the CI lints (#6470).
#
# The python-side codes (findings, scan errors, unresolvable --base, git
# ls-files failure) are asserted by each script's own --selftest. The two
# exits decided in the bash wrapper -- usage error and "no working python"
# -- cannot be, so they are asserted here for all three scripts, which each
# document them in their "Exit status" header.
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
expect() { # expect <want-rc> <want-stderr-substring> <desc> <cmd...>
  local want="$1" needle="$2" desc="$3"; shift 3
  local got=0 err
  err="$("$@" 2>&1 >/dev/null)" || got=$?
  if [ "$got" -eq "$want" ] && [[ "$err" == *"$needle"* ]]; then
    echo "ok   - $desc (rc=$got)"
  else
    echo "FAIL - $desc: wanted rc=$want with stderr containing '$needle'; got rc=$got, stderr: $err"
    fail=1
  fi
}

for s in check-portable-paths check-plugin-spawn-lexical check-metrics-help-ascii; do
  script="$ROOT/scripts/ci/$s.sh"
  expect 2 "usage:" "$s --bogus is a usage error" bash "$script" --bogus
  expect 2 "no working python interpreter" "$s with no python interpreter" \
    env PATH="$NOPY" "$NOPY/bash" "$script" --selftest
done

# The unresolvable-base exit 2 through the real bash entrypoint (the selftest
# calls run_full_scan directly).
expect 2 "could not be resolved" "check-plugin-spawn-lexical unresolvable --base" \
  bash "$ROOT/scripts/ci/check-plugin-spawn-lexical.sh" --base refs/yuzu_test_no_such_ref

exit "$fail"
