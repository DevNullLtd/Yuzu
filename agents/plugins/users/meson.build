users_deps = [yuzu_sdk_dep, yuzu_agent_core_dep, spdlog_dep]
users_cpp_args = []

if host_machine.system() == 'windows'
  users_deps += cxx.find_library('wtsapi32')
  users_deps += cxx.find_library('netapi32')
  users_deps += cxx.find_library('wevtapi')
elif host_machine.system() == 'darwin'
  # Console/GUI-login user (agents/shared/macos_console_user.hpp) via
  # SCDynamicStoreCopyConsoleUser. SystemConfiguration ships with the CLT SDK,
  # but keep required: false and gate the real path on the flag so a box
  # missing it still builds the honest nullopt fallback instead of failing.
  sc_dep = dependency('appleframeworks', modules: ['SystemConfiguration', 'CoreFoundation'],
                      required: false, include_type: 'system')
  if sc_dep.found()
    users_deps += sc_dep
    users_cpp_args += ['-DYUZU_HAVE_SYSTEMCONFIGURATION']
  else
    message('USERS: SystemConfiguration framework not found -- console-user detection '
            + 'compiles as a no-op; local_users falls back to an honest no-GUI-user value.')
  endif
endif

users_plugin_lib = shared_library(
  'users',
  files('src/users_plugin.cpp'),
  name_prefix: '',
  include_directories: include_directories('../../shared'),  # win_str.hpp (#1681), macos_console_user.hpp
  cpp_args: users_cpp_args,
  dependencies: users_deps,
  install: true,
  install_dir: get_option('libdir') / 'yuzu' / 'plugins',
)
