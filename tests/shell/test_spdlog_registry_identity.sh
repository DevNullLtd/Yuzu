#!/usr/bin/env bash
# test_spdlog_registry_identity.sh -- #4666 PR-2 W3a MI-2: report-only symbol-binding
# probe over the built exe / core lib / agent_actions plugin, showing how each image's
# own object exposes two spdlog symbols on the path every install()/set_level()/
# spdlog::info() call ultimately reaches:
#
#   1. spdlog::details::registry::instance() -- the process-wide singleton accessor.
#   2. spdlog::default_logger_raw() -- the free function spdlog::info()/warn()/etc. call
#      to fetch the process-wide default logger; internally calls #1.
#
# Both symbols are probed because #1 alone turned out to be misleading in practice
# (measured on this repo's own Linux build, kept here as a documented, not merely
# theoretical, caveat): registry::instance() is only ever CALLED from within spdlog's own
# compiled code, never directly from a consumer's own TU -- so on a build where spdlog
# supplies compiled (non-header-only) object code, only the ONE image that image's own
# spdlog_dep resolves against at link time (here: libyuzu_agent_core.so, linked first)
# carries a direct dynsym entry for it; a downstream image (the exe, a plugin) that gets
# its spdlog calls satisfied by importing from that SAME shared library never generates
# its own reference to registry::instance() at all, so #1 alone reports ABSENT there --
# NOT evidence of a separate/unshared registry, just evidence that this specific
# leaf-internal symbol isn't the one imported. #2 (default_logger_raw) is what a
# consumer's OWN spdlog::info()/set_default_logger() calls actually reference, so it
# shows the real DEFINED-vs-UNDEFINED-imported relationship between images.
#
# Deliberately report-only: static symbol-table inspection alone cannot prove RUNTIME
# interposition/binding (that needs a live process, which is exactly what MI-1/MI-3 are)
# -- this script only FAILS when an expected build artifact or `nm` itself is missing,
# never on the classification result itself. Print a topology table for human/reviewer
# inspection alongside MI-1/MI-3's own measurement.
#
# Run: bash tests/shell/test_spdlog_registry_identity.sh <BUILDDIR>
set -euo pipefail

usage() {
  echo "usage: test_spdlog_registry_identity.sh <BUILDDIR>" >&2
  exit 2
}

(( $# == 1 )) || usage

BUILDDIR="$(cd "$1" 2>/dev/null && pwd)" || { echo "missing build dir: $1" >&2; exit 2; }

# Windows: nothing to verify here in this task -- clean skip.
case "$(uname -s)" in
  MINGW*|MSYS*|CYGWIN*)
    echo "test_spdlog_registry_identity: SKIP -- Windows leg, nothing to verify here"
    exit 0
    ;;
esac

if ! command -v nm >/dev/null 2>&1; then
  echo "::error::test_spdlog_registry_identity: nm not found" >&2
  exit 1
fi

case "$(uname -s)" in
  Darwin) ext=".dylib" ;;
  *)      ext=".so" ;;
esac

EXE="$BUILDDIR/agents/core/yuzu-agent"
CORE_LIB="$BUILDDIR/agents/core/libyuzu_agent_core$ext"
PLUGIN_LIB="$BUILDDIR/agents/plugins/agent_actions/agent_actions$ext"

fail=0
for required in "$EXE" "$CORE_LIB" "$PLUGIN_LIB"; do
  if [ ! -e "$required" ]; then
    echo "::error::test_spdlog_registry_identity: missing required artifact: $required (build with -Dbuild_tests=true?)" >&2
    fail=1
  fi
done
(( fail == 0 )) || exit 1

# Mangled Itanium C++ ABI suffixes -- verified against this repo's vendored spdlog
# 1.17.0. Matched as a substring so both the itanium-mangled form (Linux) and Mach-O's
# underscore-prefixed form (Darwin) hit.
SYM_REGISTRY="spdlog7details8registry8instanceEv"
SYM_DEFAULT_LOGGER="spdlog18default_logger_rawEv"
# spdlog::set_level() -- the ACTUAL function agent_actions_plugin.cpp's do_set_log_level()
# calls. Probed as a third, plugin-relevant symbol: on a Darwin build where the plugin
# never directly references #1/#2 (its own code only calls set_level()/from_str()), this
# is the one symbol that shows the plugin's real binding -- e.g. "(undefined) external
# ... (from libyuzu_agent_core)", meaning the plugin's spdlog::set_level() call physically
# executes as libyuzu_agent_core's own compiled code, against ITS OWN registry.
SYM_SET_LEVEL="spdlog9set_levelENS_5level10level_enumE"

# Linux: nm -D --defined-only lists symbols this ELF image itself DEFINES in its dynamic
# symbol table (.dynsym); nm -D -u lists symbols it leaves UNDEFINED (resolved from
# elsewhere in the process's global symbol scope at load time -- see log_handoff.hpp's
# own MULTI-IMAGE note on RTLD_LAZY|RTLD_LOCAL/no RTLD_DEEPBIND). Absence from both means
# the symbol never reached the dynamic symbol table at all (eliminated, hidden
# visibility, or -- for registry::instance() specifically -- simply never referenced
# directly by this image's own compiled code; see the file banner).
classify_linux() {
  local file="$1" sym="$2" defined undefined
  defined="$(nm -D --defined-only "$file" 2>/dev/null | grep -c "$sym" || true)"
  undefined="$(nm -D -u "$file" 2>/dev/null | grep -c "$sym" || true)"
  if (( defined > 0 )); then
    echo "DEFINED (own dynsym entry, $defined line(s))"
  elif (( undefined > 0 )); then
    echo "UNDEFINED (imported, $undefined line(s) -- resolved from elsewhere in the process at load time)"
  else
    echo "ABSENT (no dynsym entry -- not referenced by this image's own code, hidden, or eliminated)"
  fi
}

# Darwin: Mach-O's two-level namespace makes `nm -m` tag every symbol with either a local
# definition ("(__TEXT,__text) external ...") or an undefined import annotated with its
# PROVIDING image ("(undefined) external ... (from libyuzu_agent_core)") -- the provider
# annotation is itself direct evidence of which image's copy a given image actually binds
# to, which is exactly the multi-image question this script exists to surface.
classify_darwin() {
  local file="$1" sym="$2" line provider
  line="$(nm -m "$file" 2>/dev/null | grep "$sym" || true)"
  if [ -z "$line" ]; then
    echo "ABSENT (no matching symbol in nm -m output)"
    return
  fi
  if echo "$line" | grep -q '(undefined)'; then
    provider="$(echo "$line" | grep -oE '\(from [^)]*\)' || true)"
    echo "UNDEFINED, imported ${provider:-(no provider annotation)}"
  else
    echo "DEFINED (local text symbol in this image)"
  fi
}

classify() {
  if [ "$(uname -s)" = "Darwin" ]; then
    classify_darwin "$1" "$2"
  else
    classify_linux "$1" "$2"
  fi
}

report_symbol() {
  local sym="$1" label="$2"
  echo "-- $label ($sym) --"
  printf '%-52s | %s\n' "yuzu-agent (exe)" "$(classify "$EXE" "$sym")"
  printf '%-52s | %s\n' "libyuzu_agent_core$ext (core lib)" "$(classify "$CORE_LIB" "$sym")"
  printf '%-52s | %s\n' "agent_actions$ext (plugin)" "$(classify "$PLUGIN_LIB" "$sym")"
}

echo "test_spdlog_registry_identity: symbol-binding topology"
report_symbol "$SYM_REGISTRY" "spdlog::details::registry::instance()"
echo ""
report_symbol "$SYM_DEFAULT_LOGGER" "spdlog::default_logger_raw()"
echo ""
report_symbol "$SYM_SET_LEVEL" "spdlog::set_level()"

# Darwin-specific interpretive note: a DEFINED (local, non-imported) classification for
# registry::instance() in BOTH the exe and the core lib means each image carries its OWN
# compiled copy of the function-local static singleton accessor -- i.e. two SEPARATE
# spdlog::details::registry objects under Mach-O's two-level namespace (no dyld symbol
# coalescing observed for this pair on this build). This is report-only supporting
# evidence, not proof by itself -- test_log_handoff_multi_image.cpp's MI-1b is the actual
# runtime discriminator between "two objects" and "two objects that still behave as one
# because they hold the same underlying shared_ptr<logger>".
if [ "$(uname -s)" = "Darwin" ]; then
  exe_registry_class="$(classify_darwin "$EXE" "$SYM_REGISTRY")"
  core_registry_class="$(classify_darwin "$CORE_LIB" "$SYM_REGISTRY")"
  if [[ "$exe_registry_class" == DEFINED* ]] && [[ "$core_registry_class" == DEFINED* ]]; then
    echo ""
    echo "NOTE (Darwin): yuzu-agent AND libyuzu_agent_core both carry their own DEFINED,"
    echo "non-imported copy of registry::instance() -- consistent with two SEPARATE"
    echo "spdlog::details::registry singletons under Mach-O's two-level namespace, one per"
    echo "image. See test_log_handoff_multi_image.cpp's MI-1b for the runtime-confirmed"
    echo "answer to what that implies for install_log_handoff_in_this_image()/"
    echo "release_log_handoff_from_this_image()."
  fi
fi

echo ""
echo "test_spdlog_registry_identity: OK -- report-only (see tables above); this cannot"
echo "prove RUNTIME binding from static symbol tables alone -- test_log_handoff_multi_image.cpp's MI-1/MI-1b/MI-3 are the actual measurement"
