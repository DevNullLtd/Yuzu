shared_library(
  'quarantine',
  files('src/quarantine_plugin.cpp'),
  name_prefix: '',
  # agents/shared: sudo_argv.hpp (Linux/macOS sudo escalation, Decision-8
  # canonical form) and win_str.hpp (Windows netsh.exe path resolution,
  # #1681 -- from_wide) -- Wave-2 ADR-3002 migration.
  include_directories: include_directories('../../shared'),
  dependencies: [yuzu_sdk_dep, yuzu_agent_core_dep, spdlog_dep],
  install: true,
  install_dir: get_option('libdir') / 'yuzu' / 'plugins',
)
