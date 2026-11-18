procfetch_deps = [yuzu_sdk_dep, yuzu_agent_core_dep]

# Windows: bcrypt.lib linked via #pragma comment(lib) in source
if host_machine.system() != 'windows'
  openssl_dep = dependency('openssl', required: true, include_type: 'system')
  procfetch_deps += openssl_dep
endif

# Captured so tests/meson.build can order it ahead of agent_test_exe via link_depends.
procfetch_plugin_lib = shared_library(
  'procfetch',
  files('src/procfetch_plugin.cpp'),
  name_prefix: '',
  include_directories: include_directories('../../shared'),  # win_str.hpp (#1681)
  dependencies: procfetch_deps,
  install: true,
  install_dir: get_option('libdir') / 'yuzu' / 'plugins',
)
