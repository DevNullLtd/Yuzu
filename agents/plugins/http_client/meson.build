http_cpp_args = []
# Windows: bcrypt.lib + ws2_32.lib linked via #pragma comment(lib) in source
if host_machine.system() == 'windows'
  # Try to find OpenSSL on Windows for HTTPS support
  _http_openssl = dependency('openssl', method: 'cmake',
                              modules: ['OpenSSL::SSL', 'OpenSSL::Crypto'],
                              required: false, include_type: 'system')
  if not _http_openssl.found()
    _http_ssl_lib = cxx.find_library('libssl', required: false)
    _http_crypto_lib = cxx.find_library('libcrypto', required: false)
    if _http_ssl_lib.found() and _http_crypto_lib.found()
      _http_openssl = declare_dependency(dependencies: [_http_ssl_lib, _http_crypto_lib])
    endif
  endif
  if not is_disabler(_http_openssl) and _http_openssl.found()
    http_extra_deps = [_http_openssl]
    http_cpp_args = ['-DCPPHTTPLIB_OPENSSL_SUPPORT']
  else
    http_extra_deps = []
  endif
else
  _http_openssl = dependency('openssl', required: true, include_type: 'system')
  http_extra_deps = [_http_openssl]
  http_cpp_args = ['-DCPPHTTPLIB_OPENSSL_SUPPORT']
endif

shared_library(
  'http_client',
  files('src/http_client_plugin.cpp'),
  name_prefix: '',
  cpp_args: http_cpp_args,
  include_directories: include_directories('../../shared'),  # atomic_file_write.hpp, local_path_policy.hpp, outbound_address_policy.hpp
  dependencies: [yuzu_sdk_dep, yuzu_agent_core_dep, httplib_dep] + http_extra_deps,
  install: true,
  install_dir: get_option('libdir') / 'yuzu' / 'plugins',
)
