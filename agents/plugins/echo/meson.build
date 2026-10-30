echo_deps = [yuzu_sdk_dep, yuzu_agent_core_dep, spdlog_dep, sqlite3_dep, nlohmann_dep]
echo_cpp_args = []
# Objective-C++ scaffold for the wave-2 removable/power darwin collectors
# (DiskArbitration / IOKit power notifications) — same shape as wifi/
# meson.build's wifi_objcpp_args: empty on every platform but darwin until a
# .mm source is added below, so this is inert everywhere else today.
echo_objcpp_args = []

echo_sources = files(
  'src/echo_plugin.cpp',
  'src/echo_db.cpp',
  'src/echo_diff.cpp',
  'src/echo_schema_registry.cpp',
  'src/echo_aggregator.cpp',
  'src/echo_usage.cpp',
  'src/echo_sql_executor.cpp',
  'src/echo_network_collector.cpp',
  'src/echo_netqual_boot.cpp',
  'src/echo_netconn_win.cpp',
  'src/echo_arp_collector.cpp',
  'src/echo_dns_collector.cpp',
  'src/echo_perf.cpp',
  'src/echo_proc_perf.cpp',
  'src/echo_proc_stream.cpp',
  'src/echo_module_stream.cpp',
  'src/echo_proc_etw.cpp',
  'src/echo_proc_es.cpp',
  'src/echo_netqual_nstat.cpp',
  'src/echo_module_etw.cpp',
  'src/echo_service_collector.cpp',
  'src/echo_user_collector.cpp',
  'src/echo_software_collector.cpp',
  'src/echo_software_core.cpp',
  'src/echo_mapdrive_collector.cpp',
  'src/echo_fleet_snapshot.cpp',
  'src/echo_cursor_sources.cpp',
)

# Wave 6 PR6.2-b: the power cursor source
echo_sources += files('src/echo_power_collector.cpp')
# Wave 6 PR6.3: the removable cursor source
echo_sources += files('src/echo_removable_collector.cpp')
# PR11.8: the registry cursor source (Windows key watch + baseline diff)
echo_sources += files('src/echo_registry_source.cpp')

if host_machine.system() == 'windows'
  echo_deps += cxx.find_library('advapi32')
  echo_deps += cxx.find_library('iphlpapi')
  echo_deps += cxx.find_library('ws2_32')
  echo_deps += cxx.find_library('wtsapi32')
  echo_deps += cxx.find_library('tdh')      # ETW event decoding (echo_proc_etw, echo_module_etw)
  echo_deps += cxx.find_library('dnsapi')   # DnsQuery_W / DnsRecordListFree (echo_dns_collector)
  echo_deps += cxx.find_library('wintrust') # WinVerifyTrust — image signing (echo_module_etw)
  echo_deps += cxx.find_library('crypt32')  # CertGetNameStringW — signer name from the WinVerifyTrust chain (echo_module_etw)
  echo_deps += cxx.find_library('version')  # GetFileVersionInfoW / VerQueryValueW (echo_proc_perf)
  echo_deps += cxx.find_library('wevtapi')  # EvtQuery / EvtNext / EvtRender (echo_netconn_win)
  echo_deps += cxx.find_library('mpr')      # WNetOpenEnumW / WNetGetUserW — outbound mapped drives (echo_mapdrive_collector)
  echo_deps += cxx.find_library('netapi32') # NetSessionEnum — inbound share sessions (echo_mapdrive_collector)
  echo_deps += cxx.find_library('powrprof') # PowerRegisterSuspendResumeNotification /
                                           # PowerSettingRegisterNotification (echo_power_collector)
elif host_machine.system() == 'linux'
  # Optional sd-bus leg for the wave-2 POWER cursor source: systemd-logind's
  # PrepareForSleep signal, which is the only sleep/wake source on Linux.
  # NOT for removable — that leg binds to a udev netlink socket, exactly as the
  # `removable`/linux row in echo_schema_registry.cpp declares. An earlier
  # revision of this comment said UDisks2 over D-Bus, which contradicted the
  # capability row shipping beside it and would have pointed the consuming
  # change at a binding no probe ever measured. Same tri-state systemd_guard feature option +
  # found-check + YUZU_HAVE_LIBSYSTEMD compile-gate shape as agents/plugins/
  # wifi/meson.build and device_identity/meson.build — never a second option
  # — so a build without systemd_guard enabled still compiles (the wave-2
  # removable collector falls back to udev/argv rungs unconditionally on an
  # sd-bus-less build).
  libsystemd_dep = dependency('libsystemd', required: get_option('systemd_guard'),
                              include_type: 'system')
  if libsystemd_dep.found()
    echo_deps += libsystemd_dep
    echo_cpp_args += '-DYUZU_HAVE_LIBSYSTEMD'
  else
    message('ECHO: libsystemd not used (systemd_guard != enabled, and not found) — '
            + 'the power source sleep/wake leg degrades to AC-state polling only unconditionally')
  endif
elif host_machine.system() == 'darwin'
  # Endpoint Security process stream (echo_proc_es). The probe is hoisted to the
  # top-level meson.build (A0, endpoint_security_dep/_deps/_args) -- Echo shares
  # it with agent-core (es_client.hpp) and the test executables, so it just
  # threads the shared result through rather than probing independently. See
  # docs/darwin-compat.md's EndpointSecurity pitfalls-table row.
  echo_deps += endpoint_security_deps
  echo_cpp_args += endpoint_security_args
  # Wave 6 PR6.3: DiskArbitration attach/detach lives in an Objective-C++ TU —
  # the worked pattern is wifi/meson.build's wifi_corewlan.mm. apple_objcpp_args
  # is defined ONCE at the top-level meson.build; never re-declare its flags.
  echo_sources += files('src/echo_removable_diskarb.mm')
  echo_deps += dependency('appleframeworks', modules: ['DiskArbitration', 'Foundation'],
                         include_type: 'system')
  echo_objcpp_args += apple_objcpp_args
endif

echo_plugin_lib = shared_library(
  'echo',
  echo_sources,
  name_prefix: '',
  # ../../shared: win_str.hpp (#1681, echo_module_etw)
  # ../../core/src: dex_linux_proc.hpp — reused pure /proc parsers (echo_perf, echo_proc_perf)
  # ../../../common/include: yuzu/audit_retention_rules.hpp (#2549 shared clock-guard core)
  include_directories: include_directories('../../shared', '../../core/src', '../../../common/include'),
  cpp_args: echo_cpp_args,
  objcpp_args: echo_objcpp_args,
  link_args: host_machine.system() == 'darwin' ? apple_objcpp_link_args : [],
  dependencies: echo_deps,
  install: true,
  install_dir: get_option('libdir') / 'yuzu' / 'plugins',
)
