#!/usr/bin/env bash
# Resolve the `<path>(+0xOFFSET) [0xADDR]` frames printed by the test crash handler
# (tests/unit/test_progress_listener.cpp, YUZU_TEST_CRASH_BACKTRACE) with addr2line.
# The binaries hide their symbols, so the raw log is unreadable. Best effort and
# diagnostic only: never fails the job (exit 0), prints nothing when no crash block exists.
# Usage: symbolise-crash-frames.sh <meson-logs-dir>
set -u
logs="${1:?usage: symbolise-crash-frames.sh <meson-logs-dir>}"
command -v addr2line >/dev/null 2>&1 || { echo "symbolise: addr2line not installed"; exit 0; }
shopt -s nullglob
files=("$logs"/testlog*.txt)
[[ ${#files[@]} -gt 0 ]] || exit 0
grep -qa '^\[crash\] fatal signal' "${files[@]}" 2>/dev/null || exit 0
echo "::group::Symbolised crash frames (addr2line)"
for f in "${files[@]}"; do
  awk '/^\[crash\] fatal signal/ {on=1} on {print} /^\[crash\] end of backtrace/ {on=0}' "$f" |
  while IFS= read -r line; do
    if [[ "$line" =~ ^(/[^\(\ ]+)\(([^+\)]*)\+0x([0-9a-fA-F]+)\) ]]; then
      bin="${BASH_REMATCH[1]}"; off="${BASH_REMATCH[3]}"
      if [[ -f "$bin" ]]; then
        res=$(addr2line -f -C -p -e "$bin" "0x$off" 2>/dev/null || true)
        echo "$line  =>  ${res:-?}"
        continue
      fi
    fi
    echo "$line"
  done
done
echo "::endgroup::"
exit 0
