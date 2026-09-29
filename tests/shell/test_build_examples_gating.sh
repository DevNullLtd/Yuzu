#!/usr/bin/env bash
# test_build_examples_gating.sh — #4262 smoke test.
#
# `-Dbuild_examples=false` must still configure a full, working build: only
# the four decorative demo plugins (example, chargen, procfetch, netprobe)
# are omitted, every real plugin and the test suite's link_depends still
# resolve. Before #4262 this configuration failed at `meson setup` with an
# undefined-variable error the moment any real plugin's `*_plugin_lib`
# was referenced outside the (then much wider) build_examples gate.
#
# Configure only — no compile — to keep this cheap enough to run on every
# CI leg rather than a dedicated slow job. A full compile+link+test pass of
# this configuration is verified manually per-change; this smoke test's job
# is only to keep the flag from silently regressing.
#
# Beyond a bare `meson setup` exit code, this also introspects the
# configured targets (still configure-only — `meson introspect --targets`
# needs no compile) and asserts the EXACT boundary: EVERY agents/plugins/*/
# directory except the four demo plugins has a matching target present,
# and the four demo plugins are absent. A bare setup-succeeds check would
# stay green even if a real plugin were silently re-gated behind
# build_examples (as long as nothing else referenced its *_plugin_lib
# variable) -- true of 24 of the 48 real plugins, since only 24 are
# load-bearing link_depends of yuzu_agent_tests (governance Gate 4
# unhappy-path UP-6). Checking the full discovered set, not a fixed
# sample, closes that gap regardless of which plugin a future mistake
# targets.
set -euo pipefail

ROOT="$(git rev-parse --show-toplevel 2>/dev/null || { cd "$(dirname "$0")/../.." && pwd; })"
cd "$ROOT"

# Matches scripts/setup.sh's own host-triplet detection on every host this
# repo runs on (macOS, Linux, and Windows git-bash) -- including its own
# gap: native ARM64 Linux is not auto-detected there either, only an
# explicit --cross-file selects arm64-linux/arm-linux, so this
# intentionally does not do more than setup.sh does. The two scripts'
# catch-all `case` arm differs (setup.sh defaults to Linux, this defaults
# to Windows) but that arm is unreachable on any host either script
# actually targets.
case "$(uname -s)" in
  Darwin) TRIPLET="$([ "$(uname -m)" = "arm64" ] && echo arm64-osx || echo x64-osx)" ;;
  Linux)  TRIPLET="x64-linux" ;;
  *)      TRIPLET="x64-windows" ;;
esac

VCPKG_INSTALLED="$ROOT/vcpkg_installed/$TRIPLET"
if [ ! -d "$VCPKG_INSTALLED" ]; then
  echo "test_build_examples_gating: SKIP — no populated vcpkg_installed/$TRIPLET (run scripts/setup.sh first)"
  exit 0
fi

tmp="$(mktemp -d "${TMPDIR:-/tmp}/yuzu_test_build_examples_gating.XXXXXX")"
trap 'rm -rf "$tmp"' EXIT

if ! meson setup "$tmp/build" \
    -Dbuild_examples=false -Dbuild_tests=true \
    -Dcmake_prefix_path="$VCPKG_INSTALLED" \
    -Dpkg_config_path="$VCPKG_INSTALLED/lib/pkgconfig" \
    > "$tmp/setup.log" 2>&1; then
  echo "::error::meson setup -Dbuild_examples=false -Dbuild_tests=true failed to configure — #4262 regression?" >&2
  cat "$tmp/setup.log" >&2
  exit 1
fi

targets="$tmp/targets.json"
meson introspect --targets "$tmp/build" > "$targets" 2>"$tmp/introspect.log" || {
  echo "::error::meson introspect --targets failed after a successful setup" >&2
  cat "$tmp/introspect.log" >&2
  exit 1
}

# Resolve a WORKING interpreter, not merely one whose name is on PATH:
# `command -v python3` reports success on Windows even when the only thing
# answering to that name is the default python3.exe App Execution Alias
# stub, which prints a Microsoft-Store-redirect message and exits non-zero
# instead of running any code -- exactly what broke this test on the
# Windows CI leg (the runner's provisioned toolchain guarantees `python`,
# never `python3`; see check-plugin-spawn-lexical.sh's identical guard).
PYTHON_BIN=""
for _candidate in python3 python; do
  if command -v "$_candidate" >/dev/null 2>&1 && "$_candidate" -c "" >/dev/null 2>&1; then
    PYTHON_BIN="$_candidate"
    break
  fi
done
if [ -z "$PYTHON_BIN" ]; then
  echo "::error::no working python interpreter found (tried python3, python)" >&2
  exit 2
fi

"$PYTHON_BIN" - "$targets" "$ROOT" <<'PYEOF'
import json, os, sys

targets_path, root = sys.argv[1], sys.argv[2]

with open(targets_path) as f:
    names = {t["name"] for t in json.load(f)}

demo_plugins = {"example", "chargen", "procfetch", "netprobe"}

# The full, current plugin roster -- not a fixed sample -- discovered the
# same way scripts/ci/check-capability-matrix.sh does, so a future plugin
# addition/removal never silently drifts this test's expectations out of
# sync with reality.
plugins_dir = os.path.join(root, "agents", "plugins")
all_plugins = {
    name for name in os.listdir(plugins_dir)
    if os.path.isdir(os.path.join(plugins_dir, name))
}
if not all_plugins:
    print("::error::no agents/plugins/*/ directories found -- introspection setup is broken", file=sys.stderr)
    sys.exit(1)

real_plugins = all_plugins - demo_plugins
# The tool/test targets that must also build regardless of build_examples
# (#4262: tools/capmatrix-gen + tools/plugin-capture moved to `if
# build_agent` alone; yuzu_agent_tests links every real plugin's lib).
must_be_present = real_plugins | {"capmatrix-gen", "plugin-capture", "yuzu_agent_tests"}

present_demos = demo_plugins & names
missing_required = must_be_present - names

errors = []
if present_demos:
    errors.append(f"demo plugin target(s) unexpectedly present under build_examples=false: {sorted(present_demos)}")
if missing_required:
    errors.append(f"required target(s) missing under build_examples=false: {sorted(missing_required)}")

if errors:
    for e in errors:
        print(f"::error::{e}", file=sys.stderr)
    sys.exit(1)
PYEOF

echo "test_build_examples_gating: OK — -Dbuild_examples=false -Dbuild_tests=true configures cleanly, exactly the four demo plugins are absent, and every other plugin + capmatrix-gen/plugin-capture/yuzu_agent_tests are present"
