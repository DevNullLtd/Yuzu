# libFuzzer harnesses over the closure-light untrusted-input parsers.
# Built only with -Dbuild_fuzzers=true and a clang toolchain (libFuzzer is a
# clang runtime; gcc/MSVC configure with the option off, they just can't build
# these targets). Sanitizer flags are set here directly rather than via
# b_sanitize so a plain debug configure can still add fuzzers without
# reconfiguring the whole tree.
#
# ClusterFuzzLite builds the SAME harness sources via a direct-compile
# .clusterfuzzlite/build.sh (no meson/vcpkg inside the OSS-Fuzz container) —
# when adding a harness or a source file here, mirror it there. Drift is
# caught by the cflite-pr.yml build on the PR.
#
# The `fuzz` test suite runs each harness for a bounded number of random
# inputs (plus the checked-in seed corpus) as a cheap regression net:
#   meson test -C build-<os> --suite fuzz

cpp = meson.get_compiler('cpp')
if cpp.get_id() != 'clang'
  error('-Dbuild_fuzzers=true requires a clang toolchain (libFuzzer); got ' + cpp.get_id())
endif

fuzz_args = ['-fsanitize=fuzzer,address,undefined', '-fno-sanitize-recover=all']

server_src_inc = include_directories('../../server/core/src', '../../agents/shared')

fuzz_targets = {
  'fuzz_preflight_parse': {
    'sources': files('fuzz_preflight_parse.cpp'),
    'deps': [],
  },
  'fuzz_component_zip': {
    'sources': files('fuzz_component_zip.cpp'),
    'deps': [],
  },
  'fuzz_component_native': {
    'sources': files('fuzz_component_native.cpp'),
    'deps': [],
  },
  'fuzz_deployment_parse': {
    'sources': files('fuzz_deployment_parse.cpp'),
    'deps': [],
  },
  'fuzz_yaml_scan': {
    'sources': files('fuzz_yaml_scan.cpp', '../../server/core/src/yaml_scan.cpp'),
    'deps': [],
  },
  'fuzz_guardian_rule_spec': {
    'sources': files(
      'fuzz_guardian_rule_spec.cpp',
      '../../server/core/src/guardian_rule_spec.cpp',
      '../../server/core/src/guardian_resilience_schema.cpp',
      '../../server/core/src/guardian_schema_registry.cpp',
    ),
    'deps': [nlohmann_dep],
  },
}

foreach name, spec : fuzz_targets
  exe = executable(
    name,
    spec['sources'],
    include_directories: server_src_inc,
    cpp_args: fuzz_args,
    link_args: fuzz_args,
    dependencies: spec['deps'],
    build_by_default: true,
  )
  corpus = meson.current_source_dir() / 'corpus' / name
  test(
    name + ' smoke',
    exe,
    # -runs=0 = deterministic seed replay: execute every checked-in corpus
    # entry under ASan/UBSan and exit — no mutation, so nothing is ever
    # written back into the source-tree corpus. Random exploration is
    # ClusterFuzzLite's job (cflite-pr.yml), not the unit suite's.
    args: ['-runs=0', '-max_len=4096', corpus],
    # detect_container_overflow=0: prebuilt libFuzzer runtimes (homebrew
    # LLVM on macOS, apt clang on Linux) are compiled without ASan
    # container annotations, so libFuzzer's OWN std::vector use trips a
    # container-overflow false positive when the corpus dir grows (seen
    # macOS 2026-07: crash in fuzzer::ListFilesInDirRecursive, not in
    # Yuzu code). CFLite builds runtime + harness consistently and keeps
    # the check enabled there.
    env: ['ASAN_OPTIONS=detect_container_overflow=0'],
    suite: 'fuzz',
    timeout: 120,
  )
endforeach
