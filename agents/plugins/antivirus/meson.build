# Windows products/status read WMI in-process through the header-only
# agents/shared/wmi_bounded.hpp (+ win_com.hpp) -- every including plugin
# compiles its own private inline copy, so there is no shared .cpp to list
# here (agents/shared/ is header-only leaves ONLY, docs/cpp-conventions.md);
# only the wbemuuid/ole32/oleaut32 link deps the helper's COM/WMI calls need.
av_deps = [yuzu_sdk_dep, yuzu_agent_core_dep]
av_sources = files('src/antivirus_plugin.cpp')
if host_machine.system() == 'windows'
  av_deps += [cxx.find_library('wbemuuid'), cxx.find_library('ole32'), cxx.find_library('oleaut32')]
endif

shared_library(
  'antivirus',
  av_sources,
  name_prefix: '',
  include_directories: include_directories('../../shared'),  # win_reg_handle.hpp/win_profiles.hpp/wmi_bounded.hpp/win_com.hpp
  dependencies: av_deps,
  install: true,
  install_dir: get_option('libdir') / 'yuzu' / 'plugins',
)
