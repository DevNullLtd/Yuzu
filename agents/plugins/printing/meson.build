printing_deps = [yuzu_sdk_dep, yuzu_agent_core_dep, spdlog_dep]

if host_machine.system() == 'windows'
  printing_deps += cxx.find_library('winspool')
else
  # macOS + Linux: raw IPP over the CUPS Unix domain socket (cpp-httplib) —
  # no libcups, no OpenSSL. On darwin, httplib_dep already bundles the
  # CoreFoundation/Security/CFNetwork frameworks it needs (meson.build:350).
  printing_deps += httplib_dep
endif

printing_plugin_lib = shared_library(
  'printing',
  files('src/printing_plugin.cpp'),
  name_prefix: '',
  include_directories: include_directories('../../shared'),
  dependencies: printing_deps,
  install: true,
  install_dir: get_option('libdir') / 'yuzu' / 'plugins',
)
