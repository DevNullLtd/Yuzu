windows_updates_deps = [yuzu_sdk_dep, yuzu_agent_core_dep, spdlog_dep]
if host_machine.system() == 'windows'
  # Header-only wmi_bounded.hpp (bounded WMI query) + the WUA COM search API
  # used directly from windows_updates_plugin.cpp -- wuapi.h needs no import
  # lib of its own (a COM interface header, not a DLL-export one).
  windows_updates_deps += [
    cxx.find_library('wbemuuid'),
    cxx.find_library('ole32'),
    cxx.find_library('oleaut32'),
  ]
endif

windows_updates_plugin_lib = shared_library(
  'windows_updates',
  files(
    'src/windows_updates_plugin.cpp',
  ),
  name_prefix: '',
  include_directories: include_directories('../../shared'),  # win_str.hpp (#1681), win_com.hpp, wmi_bounded.hpp
  dependencies: windows_updates_deps,
  install: true,
  install_dir: get_option('libdir') / 'yuzu' / 'plugins',
)
