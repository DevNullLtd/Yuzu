#!/bin/bash
# assert-toolchain.sh — BigMags macOS CI runner self-test.
#
# Verifies the shared build substrate a runner job depends on (README step 2)
# plus the reliability settings that keep the box a healthy runner. Run at
# provision time and as a pre-registration gate — it must pass before you trust
# the pool. Peer of deploy/windows/Assert-Toolchain.ps1 (macOS carries no
# Postgres section — agent-only platform, ADR-0035).
#
# Exit 0 = all required checks pass; non-zero = at least one required failure.
set -uo pipefail

fail=0
ok()   { printf '  \033[32mok\033[0m   %s\n' "$1"; }
bad()  { printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1)); }
warn() { printf '  \033[33mwarn\033[0m %s\n' "$1"; }

echo "== BigMags toolchain self-test =="

# --- platform ---------------------------------------------------------------
# OS family first, so a wrong-OS box fails with a clear message instead of a pile
# of confusingly-worded macOS-specific probe failures (sw_vers/xcode-select absent).
[ "$(uname -s)" = Darwin ] && ok "OS Darwin" || bad "OS $(uname -s) (expected Darwin)"
[ "$(uname -m)" = arm64 ] && ok "arch arm64" || bad "arch $(uname -m) (expected arm64)"

ver="$(sw_vers -productVersion 2>/dev/null || echo 0)"
# require >= 13.3 (meson native file deployment floor for std::format / from_chars)
maj="${ver%%.*}"; rest="${ver#*.}"; min="${rest%%.*}"
if [ "${maj:-0}" -gt 13 ] || { [ "${maj:-0}" -eq 13 ] && [ "${min:-0}" -ge 3 ]; }; then
  ok "macOS $ver (>= 13.3)"
else
  bad "macOS $ver (< 13.3 deployment floor)"
fi

# --- compiler ---------------------------------------------------------------
if xcode-select -p >/dev/null 2>&1; then
  ok "CLT at $(xcode-select -p)"
else
  bad "Command Line Tools not installed (xcode-select -p)"
fi
if command -v clang >/dev/null 2>&1; then
  cver="$(clang --version | sed -n 's/.*version \([0-9][0-9]*\).*/\1/p' | head -1)"
  if [ "${cver:-0}" -ge 16 ]; then ok "clang $cver (>= 16 for c++23)"; else bad "clang $cver (< 16, rejects -std=c++23)"; fi
else
  bad "clang not on PATH"
fi

# --- homebrew + CI packages -------------------------------------------------
if command -v brew >/dev/null 2>&1; then ok "brew $(brew --version | head -1 | awk '{print $2}')"; else bad "brew not on PATH"; fi
# glibtool is Homebrew's GNU libtool (Apple's /usr/bin/libtool shadows the name)
for t in pkg-config ninja ccache pipx autoconf automake glibtool; do
  if command -v "$t" >/dev/null 2>&1; then ok "$t"; else bad "$t missing (brew install $t)"; fi
done
[ "$(command -v pkg-config)" ] || bad "pkg-config missing — vcpkg abseil pkgconfig-fixup will fail (delta #1)"

# --- pinned toolchain (informational: the ci.yml job installs these per-run) --
if command -v cmake >/dev/null 2>&1; then
  kver="$(cmake --version | sed -n 's/cmake version \([0-9.]*\).*/\1/p' | head -1)"
  case "$kver" in
    4.4.*|4.5.*|5.*) bad "cmake $kver on PATH — 4.4.0+ poisons httplib cmake resolve; pin 4.3.4" ;;
    *) ok "cmake $kver (not the 4.4.0 trap)" ;;
  esac
else
  warn "cmake not on box PATH (fine — the ci.yml job pipx-installs 4.3.4 per run)"
fi

# --- CI dirs + reliability --------------------------------------------------
for d in /opt/ci /opt/ci/tool_cache; do
  [ -d "$d" ] && ok "dir $d" || bad "dir $d missing"
done
[ -x /opt/ci/vcpkg-fetch.sh ] && ok "vcpkg-fetch.sh installed" || warn "/opt/ci/vcpkg-fetch.sh absent (bootstrapping aid only)"

slp="$(pmset -g 2>/dev/null | awk '/[^a-z]sleep[^A-Za-z]/{print $2}' | head -1)"
[ "${slp:-1}" = 0 ] && ok "system sleep disabled" || bad "system sleep = ${slp:-?} — a sleeping runner hangs jobs (sudo pmset -a sleep 0). This gates: the self-test exists to catch exactly this drift."

echo
if [ "$fail" -eq 0 ]; then
  echo "== PASS (warnings are advisory) =="
else
  echo "== FAIL: $fail required check(s) failed =="
fi
exit "$fail"
