# No Windows-specific find_library here: DismApi.dll is runtime-bound via
# LoadLibraryExW(L"DismApi.dll", ..., LOAD_LIBRARY_SEARCH_SYSTEM32) +
# GetProcAddress at first use (windows_optional_features_plugin.cpp) rather
# than linked, because dismapi.h/DismApi.lib ship only with the Windows
# ADK's "Deployment Tools" feature, absent from every self-hosted Windows
# CI runner -- see tests/unit/fixtures/wave9/probes/the-rig-dism-findings.md.
windows_optional_features_deps = [yuzu_sdk_dep, yuzu_agent_core_dep, spdlog_dep]

windows_optional_features_plugin_lib = shared_library(
  'windows_optional_features',
  files('src/windows_optional_features_plugin.cpp'),
  name_prefix: '',
  # ../../shared: bounded_wait.hpp (the DISM bounded-call timeout) and
  # win_str.hpp (wide<->UTF-8 for feature names/descriptions), both _WIN32-gated.
  include_directories: include_directories('../../shared'),
  dependencies: windows_optional_features_deps,
  install: true,
  install_dir: get_option('libdir') / 'yuzu' / 'plugins',
)
