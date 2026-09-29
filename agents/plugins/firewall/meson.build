firewall_deps = [yuzu_sdk_dep, yuzu_agent_core_dep]
firewall_cpp_args = []

if host_machine.system() == 'windows'
  # ole32: CoInitializeEx/CoCreateInstance; oleaut32: BSTR (SysAllocString/
  # SysFreeString) + VARIANT (VariantInit/VariantClear) for the INetFwPolicy2
  # COM state/rules legs -- same shape as rdp_control/meson.build; no
  # hnetcfg.lib needed (__uuidof numeric CLSID/IID linkage, per
  # rdp_control_plugin.cpp's get_fw_policy()).
  firewall_deps += [cxx.find_library('ole32'), cxx.find_library('oleaut32')]
elif host_machine.system() == 'linux'
  # Linux firewalld leg (rung 1, bounded sd-bus) -- reuses agent-core's
  # existing systemd_guard feature option rather than minting a new one; same
  # required:get_option()/-D-flag shape as agents/core/meson.build.
  #   enabled (default) -- require libsystemd, configure fails without it.
  #   auto     -- use libsystemd if found, else the firewalld leg compiles as
  #               permanently unreachable (falls through to ufw/iptables).
  #   disabled -- always compiles as unreachable.
  libsystemd_dep = dependency('libsystemd', required: get_option('systemd_guard'),
                              include_type: 'system')
  if libsystemd_dep.found()
    firewall_deps += libsystemd_dep
    firewall_cpp_args += '-DYUZU_HAVE_LIBSYSTEMD'
  else
    message('FIREWALL: libsystemd not used (systemd_guard != enabled, and not found) -- '
          + 'firewalld leg compiles as unreachable, falls through to ufw/iptables')
  endif
endif

shared_library(
  'firewall',
  files('src/firewall_plugin.cpp'),
  name_prefix: '',
  include_directories: include_directories('../../shared'),  # win_com.hpp, win_str.hpp (Windows)
  cpp_args: firewall_cpp_args,
  dependencies: firewall_deps,
  install: true,
  install_dir: get_option('libdir') / 'yuzu' / 'plugins',
)
