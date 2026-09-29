# tools/capmatrix-gen — #2204 capability-matrix generator (PR1.1).
#
# Host tool: dlopens each built plugin shared library (read-only descriptor
# inspection, no init() call — mirrors tests/unit/test_new_plugins.cpp's
# load_plugin() search/dlopen pattern) and emits the ABI4 per-action,
# per-OS capability matrix consumed by scripts/ci/check-capability-matrix.sh.
#
# Guarded by meson.can_run_host_binaries(): under cross-compilation the build
# machine cannot execute a binary built for the target machine, so building
# (and therefore ever invoking) this tool is skipped rather than producing an
# artifact nothing on the build host can run.
if meson.can_run_host_binaries()
  capmatrix_gen_link_deps = []
  if host_machine.system() != 'windows'
    # dlopen/dlclose: in libc on modern glibc/macOS, but explicitly linking
    # libdl (when present) keeps this working on older glibc without one.
    capmatrix_gen_link_deps += cxx.find_library('dl', required: false)
  endif

  capmatrix_gen_exe = executable(
    'capmatrix-gen',
    'capmatrix_gen.cpp',
    dependencies: [yuzu_sdk_dep] + capmatrix_gen_link_deps,
    install: false,
  )
endif
