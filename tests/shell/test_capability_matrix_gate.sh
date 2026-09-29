#!/usr/bin/env bash
# test_capability_matrix_gate.sh — coverage for the #2204 capability-matrix
# machinery: tools/capmatrix-gen + scripts/ci/check-capability-matrix.sh (PR1.1
# finding F10).
#
# WHY: the production gate only ever observes ONE state at a time — today
# all 49 shipped plugins declare and RATCHET_BASELINE_UNDECLARED is 0, so it
# observes the all-declared, count-equals-baseline state (when this file was
# written the situation was the exact inverse: nothing declared, baseline 49).
# Either way a green production gate proves nothing about the ratchet's two
# REJECTION branches — grew, and improved-but-baseline-not-lowered — which no
# passing state can exercise. This file drives all of them deliberately, and
# it does so through throwaway fixture repos whose baseline it rewrites per
# scenario, so it is unaffected by whatever the real baseline happens to be.
#
# This closes both halves against the REAL binary and the REAL gate script:
#   1. Renderer: capmatrix-gen is run over tests/fixtures/abi4/'s declaring
#      fixture plugin and its output is compared BYTE-FOR-BYTE against the
#      expected fragment — every support level, the rung "-" default, the
#      NULL/empty mechanism+fallback defaults, and escape_cell()'s pipe /
#      backslash / newline neutralisation.
#   2. Ratchet: the gate script is run against a hermetic throwaway git repo
#      whose "plugins" are the declaring ABI4 fixture (renders rows) and the
#      frozen ABI3 fixture (lands in the undeclared list), with
#      RATCHET_BASELINE_UNDECLARED rewritten per scenario, so the count-grew
#      and improved-but-baseline-not-lowered branches are each observed
#      rejecting, and the drift diff is observed rejecting a hand-edit.
#
# Hermetic: no network, no GitHub, and the production tree is never mutated —
# every scenario runs inside its own mktemp'd git repo.
#
# Run:  bash tests/shell/test_capability_matrix_gate.sh <BUILDDIR>
set -euo pipefail

usage() {
  echo "usage: test_capability_matrix_gate.sh <BUILDDIR>" >&2
  exit 2
}

(( $# == 1 )) || usage

ROOT="$(git rev-parse --show-toplevel 2>/dev/null || { cd "$(dirname "$0")/../.." && pwd; })"
BUILDDIR="$(cd "$1" 2>/dev/null && pwd)" || { echo "missing build dir: $1" >&2; exit 2; }

case "$(uname -s)" in
  Linux)  ext=".so" ;;
  Darwin) ext=".dylib" ;;
  *)      ext=".dll" ;;
esac

CAPGEN="$BUILDDIR/tools/capmatrix-gen/capmatrix-gen"
ABI4="$BUILDDIR/tests/abi4_declared_fixture_plugin$ext"
ABI3="$BUILDDIR/tests/abi3_fixture_plugin$ext"
GATE="$ROOT/scripts/ci/check-capability-matrix.sh"

# Every input is a hard requirement, never a skip: an absent fixture or binary
# is exactly the silent regression this file exists to catch (same rule
# test_capability_descriptor.cpp's find_abi3_fixture() states).
for required in "$CAPGEN" "$ABI4" "$ABI3" "$GATE"; do
  [ -e "$required" ] || { echo "missing required input: $required (build with -Dbuild_tests=true?)" >&2; exit 2; }
done
[ -x "$CAPGEN" ] || { echo "not executable: $CAPGEN" >&2; exit 2; }

pass=0 fail=0
ok()   { printf '  [pass] %s\n' "$1"; pass=$((pass + 1)); }
bad()  { printf '  [FAIL] %s\n' "$1"; fail=$((fail + 1)); }

tmp="$(mktemp -d "${TMPDIR:-/tmp}/yuzu_test_capmatrix.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT

# ── Part 1: capmatrix-gen renders a DECLARED descriptor ─────────────────────

# Byte-exact expectation. Quoted heredoc: the backslashes below are escape_cell
# output, not shell escapes.
cat > "$tmp/expected_declared.md" <<'EXPECTED'
<!-- BEGIN GENERATED: capmatrix-gen (#2204) — do not hand-edit; regenerate with
     tools/capmatrix-gen, verified by scripts/ci/check-capability-matrix.sh -->
| Plugin | Action | OS | Support | Rung | Mechanism | Fallback |
|---|---|---|---|---|---|---|
| abi4_declared_fixture | scan | linux | supported | 3 | procfs | - |
| abi4_declared_fixture | scan | macos | constrained | 2 | endpoint_security | needs the ES entitlement |
| abi4_declared_fixture | scan | windows | planned | 1 | etw | - |
| abi4_declared_fixture | quarantine | linux | unsupported | - | - | - |
| abi4_declared_fixture | quarantine | macos | undeclared | - | - | - |
| abi4_declared_fixture | quarantine | windows | supported | 1 | wmi\|root\\cimv2 | reboot<br>required |

**Undeclared plugins** (ABI<4, or ABI4 with no capability declarations yet — RATCHET: this count must never grow):

_none — every built plugin has adopted the ABI4 capability descriptor._
<!-- END GENERATED -->
EXPECTED

"$CAPGEN" --out "$tmp/declared.md" "$ABI4" >/dev/null 2>&1
if git diff --no-index -- "$tmp/expected_declared.md" "$tmp/declared.md" > "$tmp/declared.diff"; then
  ok "declared ABI4 descriptor renders every per-OS leg byte-exactly"
else
  bad "declared ABI4 descriptor render drifted"
  cat "$tmp/declared.diff" >&2
fi

# Mixed set: the declaring plugin still renders its rows AND the frozen ABI3
# plugin lands in the undeclared list (the RATCHET input the gate counts).
sed 's/^_none — .*$/- `abi3_fixture`/' "$tmp/expected_declared.md" > "$tmp/expected_mixed.md"
"$CAPGEN" --out "$tmp/mixed.md" "$ABI4" "$ABI3" >/dev/null 2>&1
if git diff --no-index -- "$tmp/expected_mixed.md" "$tmp/mixed.md" > "$tmp/mixed.diff"; then
  ok "mixed declared + undeclared set renders rows and the undeclared bullet"
else
  bad "mixed declared + undeclared render drifted"
  cat "$tmp/mixed.diff" >&2
fi

# ── Part 2: the RATCHET rejection branches ──────────────────────────────────

# Build a throwaway repo the gate script can treat as a real checkout: two
# discovered plugin source dirs, their built artifacts (alpha = the declaring
# ABI4 fixture, beta = the undeclared ABI3 fixture -> undeclared count is 1),
# a committed doc block that already matches, and the real gate script with
# only RATCHET_BASELINE_UNDECLARED rewritten.
make_repo() {
  local repo="$1" baseline="$2"
  mkdir -p "$repo/docs" "$repo/scripts/ci" \
           "$repo/agents/plugins/alpha" "$repo/agents/plugins/beta" \
           "$repo/bd/tools/capmatrix-gen" \
           "$repo/bd/agents/plugins/alpha" "$repo/bd/agents/plugins/beta"
  GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null git -C "$repo" init -q

  cp "$ABI4" "$repo/bd/agents/plugins/alpha/alpha$ext"
  cp "$ABI3" "$repo/bd/agents/plugins/beta/beta$ext"

  # A wrapper, not a copy: the gate only needs an executable at that path, and
  # copying the binary out of the build tree would break the day capmatrix-gen
  # grows an @rpath/RUNPATH dependency on it.
  printf '#!/usr/bin/env bash\nexec %q "$@"\n' "$CAPGEN" \
    > "$repo/bd/tools/capmatrix-gen/capmatrix-gen"
  chmod +x "$repo/bd/tools/capmatrix-gen/capmatrix-gen"

  sed "s/^RATCHET_BASELINE_UNDECLARED=.*/RATCHET_BASELINE_UNDECLARED=$baseline/" "$GATE" \
    > "$repo/scripts/ci/check-capability-matrix.sh"

  # Seed the committed block from the generator itself so the drift diff
  # passes and the RATCHET arm is what each scenario actually exercises.
  "$CAPGEN" --out "$repo/block.md" \
    "$repo/bd/agents/plugins/alpha/alpha$ext" "$repo/bd/agents/plugins/beta/beta$ext" >/dev/null 2>&1
  { printf '# fixture capability matrix\n\n'; cat "$repo/block.md"; } \
    > "$repo/docs/os-capability-matrix.md"
  rm -f "$repo/block.md"
}

# Runs the gate inside the fixture repo, capturing stdout+stderr into $2.
# Returns the gate's exit code (captured by the caller — a command
# substitution would run this in a subshell and lose it).
run_gate() {
  local repo="$1" out_file="$2"
  ( cd "$repo" && GIT_CONFIG_NOSYSTEM=1 GIT_CONFIG_GLOBAL=/dev/null \
      bash scripts/ci/check-capability-matrix.sh bd ) > "$out_file" 2>&1
}

# expect_gate <want-rc> <desc> <repo> [<required substring>]
expect_gate() {
  local want="$1" desc="$2" repo="$3" needle="${4:-}"
  local out_file="$repo/gate.out" rc=0
  run_gate "$repo" "$out_file" || rc=$?
  if [ "$rc" != "$want" ]; then
    bad "$desc (want exit $want, got $rc)"; cat "$out_file" >&2; return
  fi
  if [ -n "$needle" ] && ! grep -qF -- "$needle" "$out_file"; then
    bad "$desc (exit $want ok, but output lacked: $needle)"; cat "$out_file" >&2; return
  fi
  ok "$desc"
}

# Control: count == baseline, and the block matches. Proves the fixture repo
# is well-formed, so the two rejections below are the RATCHET talking and not
# a broken harness.
make_repo "$tmp/eq" 1
expect_gate 0 "count == baseline with one DECLARED plugin: gate passes" \
  "$tmp/eq" "check-capability-matrix: OK (generated block matches; undeclared=1, baseline=1)"

# Rejection 1: a newly-undeclared plugin pushes the count above the baseline.
make_repo "$tmp/grew" 0
expect_gate 1 "undeclared count GROWS: gate rejects" \
  "$tmp/grew" "undeclared-plugin count grew (0 -> 1)"

# Rejection 2 (CDX-P2-006/K-25 stickiness): the count improved but the PR did
# not lower the baseline, so a later regression back up would pass.
make_repo "$tmp/improved" 2
expect_gate 1 "undeclared count IMPROVES without lowering the baseline: gate rejects" \
  "$tmp/improved" "but RATCHET_BASELINE_UNDECLARED was not lowered to match"

# Drift arm: a hand-edit to the generated block must fail before the ratchet is
# even consulted — otherwise a hand-written matrix could satisfy the count.
make_repo "$tmp/drift" 1
sed 's/| abi4_declared_fixture | scan | linux | supported |/| abi4_declared_fixture | scan | linux | unsupported |/' \
  "$tmp/drift/docs/os-capability-matrix.md" > "$tmp/drift/docs/os-capability-matrix.md.new"
mv "$tmp/drift/docs/os-capability-matrix.md.new" "$tmp/drift/docs/os-capability-matrix.md"
expect_gate 1 "hand-edited generated block: drift gate rejects" \
  "$tmp/drift" "generated block is stale relative to the built plugins"

echo "----"
echo "capability-matrix gate: pass=$pass fail=$fail"
[ "$fail" -eq 0 ]
