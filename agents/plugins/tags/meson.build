shared_library(
  'tags',
  files('src/tags_plugin.cpp'),
  name_prefix: '',
  include_directories: include_directories('../../shared'),  # atomic_file_write.hpp
  dependencies: [yuzu_sdk_dep, yuzu_agent_core_dep, nlohmann_dep, spdlog_dep],
  install: true,
  install_dir: get_option('libdir') / 'yuzu' / 'plugins',
)
