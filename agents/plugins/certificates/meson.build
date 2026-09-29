# Platform-specific crypto dependencies for certificate store access
cert_deps = [yuzu_sdk_dep, yuzu_agent_core_dep, spdlog_dep]
if host_machine.system() == 'windows'
  cert_deps += cxx.find_library('crypt32')
else
  # Linux/macOS: in-process libcrypto X509 parse (certificates_x509.hpp,
  # WP-B) replaces the `openssl x509` subprocess entirely on Linux and backs
  # the macOS SecItem DER decode below -- same shape as
  # agents/plugins/procfetch/meson.build's non-Windows openssl dependency.
  cert_deps += dependency('openssl', required: true, include_type: 'system')
endif

certificates_plugin_lib = shared_library(
  'certificates',
  files('src/certificates_plugin.cpp'),
  name_prefix: '',
  include_directories: include_directories('../../shared'),  # macos_console_user.hpp
  dependencies: cert_deps,
  install: true,
  install_dir: get_option('libdir') / 'yuzu' / 'plugins',
)
