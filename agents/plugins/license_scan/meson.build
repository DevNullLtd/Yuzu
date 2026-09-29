# license_scan — software licence detection plugin (SLE, ADR-0024 D2).
# Per-OS translation units are #ifdef-gated internally (the tar-plugin
# pattern): licensing_win.cpp compiles empty off Windows, licensing_linux.cpp
# / licensing_macos.cpp likewise on their platforms. The bounded WMI
# enumerator this plugin's slp_wmi surface uses lives at the all-inline,
# header-only agents/shared/wmi_bounded.hpp — this plugin was its origin
# (roadmap C-8); it is #include-d, not compiled as a separate source, like
# every other consumer (win_str.hpp / win_com.hpp pattern).
license_scan_deps = [yuzu_sdk_dep, yuzu_agent_core_dep]
if host_machine.system() == 'windows'
  # wmi_bounded.hpp (header-only): bounded WMI enumerator — COM + WbemLocator.
  # licensing_win.cpp: Reg*W registry probes + hive mounting (advapi32).
  license_scan_deps += [
    cxx.find_library('wbemuuid'),
    cxx.find_library('ole32'),
    cxx.find_library('oleaut32'),
    cxx.find_library('advapi32'),
  ]
endif

license_scan_plugin_lib = shared_library(
  'license_scan',
  files(
    'src/license_scan_plugin.cpp',
    'src/licensing_probes.cpp',
    'src/licensing_win.cpp',
    'src/licensing_linux.cpp',
    'src/licensing_macos.cpp',
  ),
  name_prefix: '',
  include_directories: include_directories('../../shared'),  # win_str.hpp (#1681, R17) + wmi_bounded.hpp / win_com.hpp
  dependencies: license_scan_deps,
  install: true,
  install_dir: get_option('libdir') / 'yuzu' / 'plugins',
)
