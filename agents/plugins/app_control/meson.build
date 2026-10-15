# app_control -- read-only WDAC / AppLocker posture (Windows-only concept).
# Shape follows execution_artifacts/meson.build: one portable plugin TU plus a
# Windows-only leg TU appended only on Windows; elsewhere every action is the fixed
# <action>|unsupported|windows_only_concept outcome the portable TU handles itself.
app_control_deps = [yuzu_sdk_dep, yuzu_agent_core_dep, spdlog_dep]
app_control_sources = files('src/app_control_plugin.cpp')

if host_machine.system() == 'windows'
  # advapi32: Reg*W; wbemuuid/ole32/oleaut32: agents/shared/wmi_bounded.hpp
  # (same trio hardware/meson.build links).
  app_control_deps += [
    cxx.find_library('advapi32'),
    cxx.find_library('wbemuuid'),
    cxx.find_library('ole32'),
    cxx.find_library('oleaut32'),
  ]
  app_control_sources += files('src/app_control_win.cpp')
endif

# Assigned so tests/meson.build's link_depends can order this build ahead of
# test_app_control_local_dispatcher.cpp, which loads the real library by path.
app_control_plugin_lib = shared_library(
  'app_control',
  app_control_sources,
  name_prefix: '',
  include_directories: include_directories('../../shared'),  # constraint_accumulator.hpp, win_*.hpp, wmi_bounded.hpp
  dependencies: app_control_deps,
  install: true,
  install_dir: get_option('libdir') / 'yuzu' / 'plugins',
)
