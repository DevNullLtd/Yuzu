wifi_deps = [yuzu_sdk_dep, yuzu_agent_core_dep]
wifi_sources = files('src/wifi_plugin.cpp')
wifi_objcpp_args = []
wifi_cpp_args = []

if host_machine.system() == 'windows'
  wifi_deps += cxx.find_library('wlanapi')
elif host_machine.system() == 'linux'
  # Linux rung 1: list_networks/connected primary via a bounded sd-bus
  # session to NetworkManager (org.freedesktop.NetworkManager), falling
  # back to the nmcli/iw/iwlist/iwconfig argv rungs on ANY sd-bus failure.
  # Same systemd_guard tri-state feature option agent-core/device_identity
  # already define (never a second option) and the same found-check +
  # YUZU_HAVE_LIBSYSTEMD compile-gate shape as
  # agents/plugins/device_identity/meson.build, so an sd-bus-less build
  # still compiles and falls back to the argv rungs unconditionally.
  libsystemd_dep = dependency('libsystemd', required: get_option('systemd_guard'),
                              include_type: 'system')
  if libsystemd_dep.found()
    wifi_deps += libsystemd_dep
    wifi_cpp_args += '-DYUZU_HAVE_LIBSYSTEMD'
  else
    message('libsystemd not used (systemd_guard != enabled, and not found) — wifi '
          + 'list_networks/connected fall back to the nmcli/iw argv rungs unconditionally')
  endif
elif host_machine.system() == 'darwin'
  # First Objective-C++ TU in the tree (still true — this is the worked example
  # for the reusable per-target appleframeworks/objcpp template, not a second
  # implementation of it). CoreWLAN is an Objective-C framework, so the
  # current-connection query lives in wifi_corewlan.mm. `add_languages('objcpp')`
  # and the shared `-std=c++23`/`-fvisibility=hidden`/`-fobjc-arc` args now live
  # ONCE at the top-level meson.build's `corefoundation_dep` site (`apple_objcpp_args`)
  # instead of here — this block only supplies what is genuinely wifi-specific:
  # its own .mm source and its own framework module list. CoreWLAN is a PUBLIC
  # framework in the base macOS SDK (present with the Command Line Tools SDK),
  # so this dependency() call is required: true — a failure here is a real
  # toolchain problem, not an optional-capability fallback. (EndpointSecurity
  # is NOT a counter-example of an SDK-gated framework — despite a long-
  # standing myth, it ships lib+header in both SDKs too. Its top-level probe
  # in THIS tree is still the broken required:false appleframeworks one
  # (correctly documented as such at the probe site, meson.build's darwin
  # block); a sibling slice (feat/macos-spark-a0.5-es-probe, not yet merged
  # onto this branch) will switch it to cxx.find_library()+cxx.has_header(),
  # which finds it on either SDK — see docs/darwin-compat.md's
  # EndpointSecurity row.) See docs/darwin-compat.md
  # and docs/native-objcpp-conventions.md.
  wifi_sources += files('src/wifi_corewlan.mm')
  wifi_deps += dependency('appleframeworks', modules: ['CoreWLAN', 'Foundation'],
                          include_type: 'system')
  wifi_objcpp_args += apple_objcpp_args
endif

# Assigned to a variable (mirrors device_identity_plugin_lib in
# agents/plugins/device_identity/meson.build) so tests/meson.build's
# link_depends can order this build ahead of test_wifi_local_dispatcher.cpp,
# which loads the real wifi.dylib/.so by path via
# yuzu::agent::PluginHandle::load.
wifi_plugin_lib = shared_library(
  'wifi',
  wifi_sources,
  name_prefix: '',
  include_directories: include_directories('../../shared'),  # win_str.hpp (#1681)
  dependencies: wifi_deps,
  cpp_args: wifi_cpp_args,
  objcpp_args: wifi_objcpp_args,
  install: true,
  install_dir: get_option('libdir') / 'yuzu' / 'plugins',
)
