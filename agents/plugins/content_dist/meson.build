cd_cpp_args = []
# Windows: bcrypt.lib linked via #pragma comment(lib) in source
if host_machine.system() == 'windows'
  # Try to find OpenSSL on Windows for HTTPS support
  _cd_openssl = dependency('openssl', method: 'cmake',
                            modules: ['OpenSSL::SSL', 'OpenSSL::Crypto'],
                            required: false, include_type: 'system')
  if not _cd_openssl.found()
    _cd_ssl_lib = cxx.find_library('libssl', required: false)
    _cd_crypto_lib = cxx.find_library('libcrypto', required: false)
    if _cd_ssl_lib.found() and _cd_crypto_lib.found()
      _cd_openssl = declare_dependency(dependencies: [_cd_ssl_lib, _cd_crypto_lib])
    endif
  endif
  if not is_disabler(_cd_openssl) and _cd_openssl.found()
    cd_extra_deps = [_cd_openssl]
    cd_cpp_args = ['-DCPPHTTPLIB_OPENSSL_SUPPORT']
  else
    cd_extra_deps = []
  endif
else
  _cd_openssl = dependency('openssl', required: true, include_type: 'system')
  cd_extra_deps = [_cd_openssl]
  cd_cpp_args = ['-DCPPHTTPLIB_OPENSSL_SUPPORT']
endif

content_dist_plugin_lib = shared_library(
  'content_dist',
  files('src/content_dist_plugin.cpp'),
  name_prefix: '',
  include_directories: include_directories('../../shared'),  # win_str.hpp (#1681, _WIN32-gated)
  cpp_args: cd_cpp_args,
  dependencies: [yuzu_sdk_dep, yuzu_agent_core_dep, httplib_dep] + cd_extra_deps,
  install: true,
  install_dir: get_option('libdir') / 'yuzu' / 'plugins',
)
