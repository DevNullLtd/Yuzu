wol_deps = [yuzu_sdk_dep, yuzu_agent_core_dep]

if host_machine.system() == 'windows'
  wol_deps += cxx.find_library('ws2_32')
  # iphlpapi: IcmpCreateFile/IcmpSendEcho/IcmpCloseHandle (icmp_probe.hpp's
  # IcmpSession, ADR-3002 `check` action migration off popen'd ping).
  wol_deps += cxx.find_library('iphlpapi')
endif

shared_library(
  'wol',
  files('src/wol_plugin.cpp'),
  name_prefix: '',
  dependencies: wol_deps,
  # agents/shared: icmp_probe.hpp (IcmpSession/tcp_sample) + host_arg.hpp
  # (is_safe_host_arg), both consumed by the `check` action.
  include_directories: include_directories('../../shared'),
  install: true,
  install_dir: get_option('libdir') / 'yuzu' / 'plugins',
)
