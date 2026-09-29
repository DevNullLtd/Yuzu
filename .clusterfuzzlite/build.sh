#!/bin/bash -eu
# ClusterFuzzLite build script — compiles each libFuzzer harness directly with
# the OSS-Fuzz-provided instrumented toolchain ($CC/$CXX/$CXXFLAGS/
# $LIB_FUZZING_ENGINE). Deliberately NO meson/vcpkg in here: the fuzz targets
# are closure-light (STL + nlohmann only), and a from-source vcpkg bootstrap
# inside this container would be minutes of fragility for zero extra coverage.
#
# KEEP IN SYNC with tests/fuzz/meson.build (same harness list, same extra
# sources). Drift is caught by the cflite-pr.yml build job on any PR touching
# these paths. A new or changed source here also needs its family glob in
# BOTH workflows' paths: lists (cflite-pr.yml + cflite-batch.yml) — the
# filters are what decide whether fuzzing runs at all on a source change.

# EXACT repo-name case — CFLite mounts the checkout at $SRC/Yuzu (see the
# Dockerfile comment).
SRC_DIR="$SRC/Yuzu"
INC="-I$SRC_DIR/server/core/src -I$SRC_DIR/common/include -I$SRC/nlohmann_json/include"
STD="-std=c++23"

build_target() {
  local name="$1"; shift
  # shellcheck disable=SC2086 — $CXXFLAGS is a flag list by contract
  $CXX $CXXFLAGS $STD $INC "$@" -o "$OUT/$name" $LIB_FUZZING_ENGINE
  # Seed corpus (optional per target).
  local corpus="$SRC_DIR/tests/fuzz/corpus/$name"
  if [ -d "$corpus" ]; then
    zip -j "$OUT/${name}_seed_corpus.zip" "$corpus"/* >/dev/null
  fi
}

build_target fuzz_preflight_parse \
  "$SRC_DIR/tests/fuzz/fuzz_preflight_parse.cpp"

build_target fuzz_deployment_parse \
  "$SRC_DIR/tests/fuzz/fuzz_deployment_parse.cpp"

build_target fuzz_yaml_scan \
  "$SRC_DIR/tests/fuzz/fuzz_yaml_scan.cpp" \
  "$SRC_DIR/server/core/src/yaml_scan.cpp"

build_target fuzz_guardian_rule_spec \
  "$SRC_DIR/tests/fuzz/fuzz_guardian_rule_spec.cpp" \
  "$SRC_DIR/server/core/src/guardian_rule_spec.cpp" \
  "$SRC_DIR/server/core/src/guardian_resilience_schema.cpp" \
  "$SRC_DIR/server/core/src/guardian_schema_registry.cpp"
