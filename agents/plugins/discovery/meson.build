discovery_deps = [yuzu_sdk_dep, yuzu_agent_core_dep]

# Windows needs iphlpapi for ARP table (GetIpNetTable2) and ws2_32 for
# socket functions (inet_pton, IcmpSendEcho's iphlpapi lives here too).
if host_machine.system() == 'windows'
  discovery_deps += [
    meson.get_compiler('cpp').find_library('iphlpapi'),
    meson.get_compiler('cpp').find_library('ws2_32'),
  ]
endif

shared_library(
  'discovery',
  files('src/discovery_plugin.cpp'),
  name_prefix: '',
  # ../../shared: icmp_probe.hpp (shared ping-sweep session, all platforms)
  # and route_sysctl_arp.hpp (macOS sysctl ARP read, __APPLE__-gated).
  include_directories: include_directories('../../shared'),
  dependencies: discovery_deps,
  install: true,
  install_dir: get_option('libdir') / 'yuzu' / 'plugins',
)
