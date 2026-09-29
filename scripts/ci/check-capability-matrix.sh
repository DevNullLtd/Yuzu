#!/usr/bin/env bash
# check-capability-matrix.sh — #2204 drift gate for docs/os-capability-matrix.md's
# generated block (PR1.1).
#
# Regenerates the capmatrix-gen Markdown fragment from the already-built
# plugin artifacts and byte-diffs it against the block committed between the
# <!-- BEGIN GENERATED --> / <!-- END GENERATED --> markers in
# docs/os-capability-matrix.md. This catches three drifts:
#   1. A hand-edit to the generated block (bypasses the generator entirely).
#   2. A stale commit after a plugin's ABI4 capability declaration changed
#      but the doc wasn't regenerated.
#   3. A plugin whose build artifact silently stopped being produced.
#
# Usage:
#   check-capability-matrix.sh <BUILDDIR>
#
# BUILDDIR is the meson build directory (e.g. build-linux-gcc-15-debug). The
# expected plugin set is discovered from agents/plugins/*/ source
# subdirectories (independent of the top-level meson.build subdir list PR1.3
# owns — every real plugin directory unconditionally builds a same-named
# shared object under -Dbuild_agent=true regardless of -Dbuild_examples
# (#4262; that flag now gates only the four decorative demo plugins), so
# the source tree itself is the complete, self-maintaining expected-artifact
# list; no second name list to keep in sync here). Run AFTER `meson compile`
# — capmatrix-gen and every discovered plugin's shared object must already
# exist by the time this runs; a missing artifact is a hard failure, never a
# silent skip (that silent-skip is exactly the drift this gate exists to
# catch).
#
# RATCHET MODE: the regenerated "Undeclared plugins" count is compared
# against RATCHET_BASELINE_UNDECLARED below. It may stay the same or SHRINK
# (a plugin adopting the ABI4 descriptor); it must never GROW. The baseline
# lives here (not a separate tracked file) so there is exactly one place to
# update when the discovered plugin set changes or a plugin adopts the
# descriptor.
#
# With the baseline now at 0 (every plugin declares), ratchet mode and
# hard-fail-on-any-undeclared have converged: a new plugin landing without
# descriptors grows the count above 0 and fails here. The gate did not need
# a separate mode flip to get there — lowering the baseline was the whole
# mechanism, which is why the ratchet was built this way.
#
# build-ci B1: -Dbuild_agent=false is a supported option that skips every
# agents/plugins/*/ subdir (and, matching that, the tools/capmatrix-gen
# subdir — see meson.build). With no plugins and no generator built, this
# gate has nothing to check; it queries the build directory's own
# build_agent value below and skips rather than hard-failing on an artifact
# that was never supposed to exist. -Dbuild_examples=false is NOT a skip
# condition (#4262) — it only omits four decorative demo plugins, so every
# real plugin this gate discovers still has an artifact to check.
set -euo pipefail

# Every discovered plugin now declares its ABI4 action_descriptors array —
# #2204 shipped the machinery, and per-plugin adoption completed across all
# 49 in this PR, so the floor is 0. DECREASE this the moment the count
# drops further (it cannot from 0); increasing it requires a deliberate,
# reviewed decision — and at 0 that means a NEW plugin directory landed
# under agents/plugins/ without descriptors, which is exactly the
# regression this ratchet now blocks outright.
RATCHET_BASELINE_UNDECLARED=0

usage() {
  echo "usage: check-capability-matrix.sh <BUILDDIR>" >&2
  exit 2
}

(( $# == 1 )) || usage

BUILDDIR="$1"

ROOT="$(git rev-parse --show-toplevel 2>/dev/null || { cd "$(dirname "$0")/../.." && pwd; })"
DOC="$ROOT/docs/os-capability-matrix.md"
[ -f "$DOC" ] || { echo "::error::missing $DOC" >&2; exit 2; }

case "$(uname -s)" in
  Linux)  plugin_ext=".so" ;;
  Darwin) plugin_ext=".dylib" ;;
  *)      plugin_ext=".dll" ;;
esac

capmatrix_gen="$BUILDDIR/tools/capmatrix-gen/capmatrix-gen"

# build-ci B1: -Dbuild_agent=false means no plugin subdirs and no
# capmatrix-gen were configured (meson.build gates both on it) — that is a
# supported build, not drift. Only introspect the build directory's
# build_agent option when the expected generator binary is absent —
# fixture repos (tests/shell/test_capability_matrix_gate.sh) and other
# callers that already provide capmatrix_gen supply no Meson build metadata
# at all, so unconditionally introspecting would hard-fail them for no
# reason.
if [ ! -x "$capmatrix_gen" ]; then
  if ! command -v meson >/dev/null 2>&1; then
    echo "::error::meson is required (already a hard build dependency) but was not found on PATH." >&2
    exit 2
  fi

  build_agent="$(meson introspect --buildoptions "$BUILDDIR" 2>/dev/null | python3 -c '
import json, sys
try:
    opts = json.load(sys.stdin)
except Exception:
    print("unknown")
    sys.exit(0)
for opt in opts:
    if opt.get("name") == "build_agent":
        print("true" if opt.get("value") else "false")
        sys.exit(0)
print("unknown")
' 2>/dev/null || echo "unknown")"

  if [ "$build_agent" = "false" ]; then
    echo "check-capability-matrix: SKIP — build_agent=false (no plugins configured, nothing to check)"
    exit 0
  fi

  echo "::error::capmatrix-gen binary not found/executable at $capmatrix_gen — did the Build step run first?" >&2
  exit 1
fi

# The four decorative demo plugins (#4262) are the ONLY ones -Dbuild_examples
# gates -- when it's false, exclude them from the expected-artifact set (they
# genuinely have no build output, by design) rather than treating their
# absence as drift. Best-effort: a caller supplying a directory with no real
# Meson build metadata (tests/shell/test_capability_matrix_gate.sh's
# hermetic fixture repos) gets "unknown" and this filter is skipped
# entirely, preserving today's strict all-plugins-expected behavior there.
build_examples="unknown"
if command -v meson >/dev/null 2>&1; then
  build_examples="$(meson introspect --buildoptions "$BUILDDIR" 2>/dev/null | python3 -c '
import json, sys
try:
    opts = json.load(sys.stdin)
except Exception:
    print("unknown")
    sys.exit(0)
for opt in opts:
    if opt.get("name") == "build_examples":
        print("true" if opt.get("value") else "false")
        sys.exit(0)
print("unknown")
' 2>/dev/null || echo "unknown")"
fi
DEMO_PLUGINS=(example chargen procfetch netprobe)
is_demo_plugin() {
  local n="$1" d
  for d in "${DEMO_PLUGINS[@]}"; do [ "$n" = "$d" ] && return 0; done
  return 1
}

PLUGIN_NAMES=()
for d in "$ROOT"/agents/plugins/*/; do
  name="$(basename "$d")"
  if [ "$build_examples" = "false" ] && is_demo_plugin "$name"; then
    continue
  fi
  PLUGIN_NAMES+=("$name")
done
(( ${#PLUGIN_NAMES[@]} > 0 )) || { echo "::error::no agents/plugins/*/ source directories found under $ROOT" >&2; exit 2; }

plugin_paths=()
for name in "${PLUGIN_NAMES[@]}"; do
  p="$BUILDDIR/agents/plugins/$name/$name$plugin_ext"
  if [ ! -f "$p" ]; then
    echo "::error::expected plugin artifact missing: $p (plugin '$name' did not build?)" >&2
    exit 1
  fi
  plugin_paths+=("$p")
done

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT
regen="$tmp/generated.md"

"$capmatrix_gen" --out "$regen" "${plugin_paths[@]}"

extract_block() {
  # Prints the committed <!-- BEGIN GENERATED: capmatrix-gen ... --> through
  # <!-- END GENERATED --> block (inclusive), or nothing if absent.
  awk '
    /<!-- BEGIN GENERATED: capmatrix-gen/ { flag = 1 }
    flag { print }
    /<!-- END GENERATED -->/ { if (flag) exit }
  ' "$1"
}

committed_block="$tmp/committed.md"
extract_block "$DOC" > "$committed_block"

if [ ! -s "$committed_block" ]; then
  echo "::error::no <!-- BEGIN GENERATED: capmatrix-gen --> ... <!-- END GENERATED --> block found in $DOC" >&2
  exit 1
fi

# CDX-FV-1 (#4262 code-review): the committed block always documents the
# FULL plugin set -- there is no separate "reduced" doc for
# -Dbuild_examples=false, so comparing it byte-for-byte against a
# regenerated block that's missing the four demo plugins' rows would ALWAYS
# report false drift for a perfectly correct reduced build. Strip the same
# four demo plugins' rows from the COMMITTED side before comparing, so the
# comparison stays apples-to-apples (does the real-plugin subset match?)
# instead of either false-failing or skipping real-plugin drift checking
# entirely.
if [ "$build_examples" = "false" ]; then
  filtered_committed="$tmp/committed-filtered.md"
  grep -Ev "^\| ($(IFS='|'; echo "${DEMO_PLUGINS[*]}")) \|" "$committed_block" > "$filtered_committed"
  committed_block="$filtered_committed"
fi

# git diff --no-index, not the `diff` binary: git is a hard build/CI
# dependency on every leg (unlike diffutils, which the Windows runner's
# msys2 bash does not carry) and --no-index is explicitly designed to work
# on two arbitrary files outside a repo. Exit codes match diff's (0 = no
# difference, 1 = differs, both with a unified diff on stdout) so the
# surrounding control flow needs no change.
if ! git diff --no-index -- "$committed_block" "$regen" > "$tmp/diff.txt"; then
  echo "::error::docs/os-capability-matrix.md's generated block is stale relative to the built plugins." >&2
  echo "::error::regenerate it: \"$capmatrix_gen\" --out <tmp-file> <plugin .so paths...>, then splice the" >&2
  echo "::error::<!-- BEGIN GENERATED --> .. <!-- END GENERATED --> block in docs/os-capability-matrix.md and commit." >&2
  cat "$tmp/diff.txt" >&2
  exit 1
fi

# RATCHET: count "Undeclared plugins" bullets in the just-verified (byte-
# identical to committed) regenerated block.
count_undeclared() {
  awk '
    /\*\*Undeclared plugins\*\*/ { flag = 1; next }
    /<!-- END GENERATED -->/     { flag = 0 }
    flag && /^- `/               { n++ }
    END                          { print n + 0 }
  ' "$1"
}

current_count="$(count_undeclared "$regen")"

if (( current_count > RATCHET_BASELINE_UNDECLARED )); then
  echo "::error::undeclared-plugin count grew ($RATCHET_BASELINE_UNDECLARED -> $current_count) — RATCHET mode forbids this." >&2
  echo "::error::adopt the ABI4 capability descriptor for the newly-undeclared plugin(s), or if this growth" >&2
  echo "::error::is a deliberate, reviewed decision (e.g. a new agents/plugins/ directory added)," >&2
  echo "::error::bump RATCHET_BASELINE_UNDECLARED in this script to match." >&2
  exit 1
fi

if (( current_count < RATCHET_BASELINE_UNDECLARED )); then
  # CDX-P2-006/K-25: the ratchet must be MONOTONIC. An improvement that does not
  # also lower the baseline leaves room for a later regression back UP to the
  # old baseline to pass. Require the adoption PR that reduces the count to lower
  # RATCHET_BASELINE_UNDECLARED in the SAME change, so the gain is sticky.
  echo "::error::undeclared-plugin count improved ($RATCHET_BASELINE_UNDECLARED -> $current_count)" >&2
  echo "::error::but RATCHET_BASELINE_UNDECLARED was not lowered to match — the ratchet would not be" >&2
  echo "::error::sticky (a later regression back to $RATCHET_BASELINE_UNDECLARED would pass). Lower" >&2
  echo "::error::RATCHET_BASELINE_UNDECLARED to $current_count in THIS PR." >&2
  exit 1
fi

echo "check-capability-matrix: OK (generated block matches; undeclared=$current_count," \
     "baseline=$RATCHET_BASELINE_UNDECLARED)"
