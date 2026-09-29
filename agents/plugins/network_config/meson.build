network_config_deps = [yuzu_sdk_dep, yuzu_agent_core_dep, spdlog_dep]
network_config_cpp_args = []

if host_machine.system() == 'darwin'
  # dns_servers/proxy read SCDynamicStore (State:/Network/Global/DNS,
  # SCDynamicStoreCopyProxies). SystemConfiguration ships with the CLT SDK,
  # but keep required: false and gate the real path on the flag so a box
  # missing it still builds an honest UNAVAILABLE fallback instead of
  # failing (same soft-dep shape as agents/plugins/users/meson.build:10-19).
  network_config_sc_dep = dependency('appleframeworks', modules: ['SystemConfiguration', 'CoreFoundation'],
                                     required: false, include_type: 'system')
  if network_config_sc_dep.found()
    network_config_deps += network_config_sc_dep
    network_config_cpp_args += ['-DYUZU_HAVE_SYSTEMCONFIGURATION']
  else
    warning('NETWORK_CONFIG: SystemConfiguration framework not found -- dns_servers/proxy '
            + 'compile as an honest UNAVAILABLE fallback.')
  endif
endif

# Assigned (not anonymous) so tests/meson.build's test_network_config_local_
# dispatcher.cpp can depend on the real build output by path -- same shape
# as agents/plugins/users/meson.build's users_plugin_lib.
network_config_plugin_lib = shared_library(
  'network_config',
  files('src/network_config_plugin.cpp'),
  name_prefix: '',
  include_directories: include_directories('../../shared'),  # win_str.hpp (#1681); route_sysctl_arp.hpp (__APPLE__-gated)
  cpp_args: network_config_cpp_args,
  dependencies: network_config_deps,
  install: true,
  install_dir: get_option('libdir') / 'yuzu' / 'plugins',
)
