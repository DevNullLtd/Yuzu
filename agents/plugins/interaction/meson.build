interaction_deps = [yuzu_sdk_dep, yuzu_agent_core_dep]

# Windows needs shell32 for Shell_NotifyIconW
if host_machine.system() == 'windows'
  interaction_deps += [
    meson.get_compiler('cpp').find_library('shell32'),
    meson.get_compiler('cpp').find_library('user32'),
  ]
endif

interaction_plugin_lib = shared_library(
  'interaction',
  files('src/interaction_plugin.cpp'),
  name_prefix: '',
  include_directories: include_directories('../../shared'),  # win_str.hpp (#1681)
  dependencies: interaction_deps,
  install: true,
  install_dir: get_option('libdir') / 'yuzu' / 'plugins',
)
# deploy_dlls (root meson.build) waits for every library in this list (#8926).
yuzu_plugin_libs += interaction_plugin_lib
