installed_apps_deps = [yuzu_sdk_dep, yuzu_agent_core_dep, spdlog_dep]
installed_apps_cpp_args = []
if host_machine.system() == 'windows'
  # win_profiles.hpp / win_reg_handle.hpp: Reg*W + RegLoadKeyW/RegUnLoadKeyW,
  # AdjustTokenPrivileges (#2771). The plugin already called RegLoadKeyW via
  # MSVC's default libs; naming the dependency makes it explicit.
  installed_apps_deps += [cxx.find_library('advapi32')]
elif host_machine.system() == 'darwin'
  # #2273 list_inventory enrichment (installed_apps_macos_enrich.hpp):
  # CFBundleCreate + SecStaticCodeCreateWithPath/SecCodeCopySigningInformation.
  # required: false + a -D flag, same shape as certificates/meson.build's own
  # Security+CoreFoundation dependency, so a box without the Security
  # framework still builds an honest no-op enrichment (every field stays
  # empty) instead of failing configure.
  security_dep = dependency('appleframeworks', modules: ['Security', 'CoreFoundation'],
                            required: false, include_type: 'system')
  if security_dep.found()
    installed_apps_deps += security_dep
    installed_apps_cpp_args += ['-DYUZU_HAVE_SECURITY_FRAMEWORK']
  else
    message('INSTALLED_APPS: Security framework not found -- list_inventory\'s macOS '
            + 'per-app bundle-id/publisher/signature enrichment compiles as a no-op.')
  endif
endif

installed_apps_plugin_lib = shared_library(
  'installed_apps',
  files('src/installed_apps_plugin.cpp'),
  name_prefix: '',
  # win_profiles.hpp / win_reg_handle.hpp / user_profile_model.hpp (#2771).
  # NOT win_str.hpp: this plugin deliberately keeps its own
  # installed_apps_registry_utf8.hpp, whose reg_sz_to_utf8 differs from the
  # shared one on interior NULs — both headers carry a do-not-merge note.
  include_directories: include_directories('../../shared'),
  cpp_args: installed_apps_cpp_args,
  dependencies: installed_apps_deps,
  install: true,
  install_dir: get_option('libdir') / 'yuzu' / 'plugins',
)
