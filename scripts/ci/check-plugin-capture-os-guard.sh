#!/usr/bin/env bash
# check-plugin-capture-os-guard.sh — regression test for the cross-OS capture
# certification blocker (PR #4112 review): tools/plugin-capture must reject a
# --os that does not match the platform it was actually compiled for, rather
# than silently certifying a wrong-platform sample as truth.
#
# Usage:
#   check-plugin-capture-os-guard.sh <BUILDDIR>
#
# BUILDDIR is the meson build directory (e.g. build-linux-gcc-15-debug). Run
# AFTER `meson compile` — the plugin-capture binary must already exist. No
# plugin library is loaded: the --os check runs during argument validation,
# strictly before any library is opened, so a nonexistent path is enough.
set -euo pipefail

if [ $# -ne 1 ]; then
  echo "usage: $0 <BUILDDIR>" >&2
  exit 2
fi
BUILDDIR="$1"

# Check .exe FIRST: on MSYS2/Cygwin bash (this repo's self-hosted Windows
# runner shell), `test -x <extensionless-path>` can return true by silently
# resolving to the co-located `<name>.exe` even though that exact
# extensionless string is not itself executable -- so invoking "$capture"
# later (not test -x "$capture") fails with rc=127 (exec format error),
# confirmed against the real Windows CI leg. Checking .exe first means the
# variable is only ever set to a path that is BOTH test -x true and
# directly invocable.
capture="$BUILDDIR/tools/plugin-capture/plugin-capture.exe"
[ -x "$capture" ] || capture="$BUILDDIR/tools/plugin-capture/plugin-capture"
if [ ! -x "$capture" ]; then
  echo "::error::plugin-capture binary not found/executable under $BUILDDIR/tools/plugin-capture/ — did the Build step run first?" >&2
  exit 1
fi

# Same host-OS derivation as scripts/setup.sh's HOST_OS block, so this script
# runs correctly on whichever OS's CI leg builds it (this repo's own CI runs
# Linux, macOS and Windows legs — never hardcode one).
if [[ "$(uname -s)" == MINGW* ]] || [[ "$(uname -s)" == MSYS* ]] || [[ "${OS:-}" == "Windows_NT" ]]; then
  HOST_OS="windows"
elif [[ "$(uname -s)" == "Darwin" ]]; then
  HOST_OS="macos"
else
  HOST_OS="linux"
fi

# plugin-capture links yuzu_agent_core dynamically (a shared_library --
# agents/core/meson.build), so on Windows the loader needs
# yuzu_agent_core.dll resolvable via PATH before the .exe can even start;
# without it Windows refuses to launch the process at all, and MSYS2/Cygwin
# bash reports that loader failure as rc=127 -- indistinguishable from
# "command not found" even though $capture is right there and directly
# invocable by path. Confirmed against the real Windows CI leg. Linux/macOS
# resolve their .so/.dylib via rpath at link time, so this is a no-op there.
if [ "$HOST_OS" = "windows" ]; then
  export PATH="$BUILDDIR/agents/core:$PATH"
fi

case "$HOST_OS" in
  windows) WRONG_OS="linux" ;;
  *)       WRONG_OS="windows" ;;
esac

fail=0

echo "-- Rejects a mismatched --os ($WRONG_OS on a $HOST_OS build) --"
out="$("$capture" /nonexistent.so --os "$WRONG_OS" --host-class vm --action probe 2>&1)" && rc=0 || rc=$?
if [ "$rc" -eq 0 ]; then
  echo "::error::plugin-capture --os $WRONG_OS exited 0 on a $HOST_OS build — the cross-OS " \
       "certification guard did not reject it" >&2
  fail=1
elif ! grep -qi "does not match this binary's compiled platform" <<<"$out"; then
  echo "::error::plugin-capture --os $WRONG_OS rejected (rc=$rc) but not with the expected " \
       "compiled-platform message; got: $out" >&2
  fail=1
else
  echo "OK: rejected with rc=$rc"
fi

echo "-- Does not reject the matching --os ($HOST_OS) on this compiled-platform check --"
out="$("$capture" /nonexistent.so --os "$HOST_OS" --host-class vm --action probe 2>&1)" || true
if grep -qi "does not match this binary's compiled platform" <<<"$out"; then
  echo "::error::plugin-capture --os $HOST_OS was rejected by the compiled-platform guard on its " \
       "own compiled platform; got: $out" >&2
  fail=1
else
  echo "OK: compiled-platform guard did not fire (any later failure is unrelated, e.g. the " \
       "nonexistent library path)"
fi

exit "$fail"
