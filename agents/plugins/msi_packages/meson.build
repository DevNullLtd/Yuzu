# macOS support (pkgutil --pkgs / --pkg-info) is subprocess-based, so it
# needs no extra link dependency the way the Windows msi.lib linkage below
# does; msi_packages_macos.hpp is a pure header pulled in by the .cpp and
# needs no meson registration of its own.
msi_packages_deps = [yuzu_sdk_dep, yuzu_agent_core_dep, spdlog_dep]

if host_machine.system() == 'windows'
  msi_packages_deps += cxx.find_library('msi')
endif

msi_packages_plugin_lib = shared_library(
  'msi_packages',
  files('src/msi_packages_plugin.cpp'),
  name_prefix: '',
  # subprocess_degradation.hpp (Gate-8 remediation, Wave 4 PR4.3a): the
  # degraded-run decision shared with installed_apps, matching that plugin's
  # own agents/shared include -- same precedent as antivirus/bitlocker/
  # license_scan/users' existing agents/shared consumption.
  include_directories: include_directories('../../shared'),
  dependencies: msi_packages_deps,
  install: true,
  install_dir: get_option('libdir') / 'yuzu' / 'plugins',
)
