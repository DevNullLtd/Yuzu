# execution_artifacts — Windows-only ShimCache / Amcache / Prefetch plugin.
# Multi-TU shape follows autoruns/meson.build: one portable plugin TU
# (execute()/descriptors, this package/P31) plus a single Windows-only leg TU
# (execution_artifacts_win.cpp, P32) that is CONDITIONALLY appended only when
# building for Windows — a single-OS non-Windows build simply omits the leg
# source, since every action on those platforms is the fixed <action>|unsupported|
# windows_only_artefact outcome the portable TU already handles with no OS
# call at all. (disk_actions/meson.build's shape differs: it lists every
# per-OS leg TU unconditionally, internally #ifdef-gated — not this plugin's
# pattern.)
execution_artifacts_deps = [yuzu_sdk_dep, yuzu_agent_core_dep, spdlog_dep]
execution_artifacts_sources = files('src/execution_artifacts_plugin.cpp')

if host_machine.system() == 'windows'
  # advapi32: RegQueryValueExW (ShimCache) + RegLoadAppKeyW/AdjustTokenPrivileges
  # (Amcache) — linked normally via cxx.find_library since these are ordinary
  # import-library symbols. ntdll's RtlGetCompressionWorkSpaceSize/
  # RtlDecompressBufferEx (Prefetch MAM decompression) are deliberately NOT
  # link-time dependencies: execution_artifacts_win.cpp resolves both via
  # GetProcAddress(GetModuleHandleW(L"ntdll.dll"), ...) at runtime (file
  # banner: "no #ifdef around the symbol... absence is a runtime outcome"),
  # matching confined_fs_win.cpp's precedent — so no `cxx.find_library('ntdll')`
  # here.
  execution_artifacts_deps += [
    cxx.find_library('advapi32'),
  ]
  execution_artifacts_sources += files(
    'src/execution_artifacts_win.cpp',
    'src/execution_artifacts_scratch_sweep_win.cpp',
  )
endif

# Assigned to a variable (mirrors disk_actions_plugin_lib /
# app_usage_plugin_lib) so tests/meson.build's link_depends can order this
# build ahead of test_execution_artifacts_local_dispatcher.cpp, which loads
# the real execution_artifacts.dll/.so/.dylib by path via
# yuzu::agent::PluginHandle::load.
execution_artifacts_plugin_lib = shared_library(
  'execution_artifacts',
  execution_artifacts_sources,
  name_prefix: '',
  include_directories: include_directories('../../shared'),  # win_profiles.hpp / win_reg_handle.hpp (the-rig 2026-09-07: C1083 without it)
  dependencies: execution_artifacts_deps,
  install: true,
  install_dir: get_option('libdir') / 'yuzu' / 'plugins',
)
