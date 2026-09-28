tar_deps = [yuzu_sdk_dep, yuzu_agent_core_dep, spdlog_dep, sqlite3_dep, nlohmann_dep]
tar_cpp_args = []
# Objective-C++ scaffold for the wave-2 removable/power darwin collectors
# (DiskArbitration / IOKit power notifications) — same shape as wifi/
# meson.build's wifi_objcpp_args: empty on every platform but darwin until a
# .mm source is added below, so this is inert everywhere else today.
tar_objcpp_args = []

tar_sources = files(
  'src/tar_plugin.cpp',
  'src/tar_db.cpp',
  'src/tar_diff.cpp',
  'src/tar_schema_registry.cpp',
  'src/tar_aggregator.cpp',
  'src/tar_usage.cpp',
  'src/tar_sql_executor.cpp',
  'src/tar_network_collector.cpp',
  'src/tar_netqual_boot.cpp',
  'src/tar_netconn_win.cpp',
  'src/tar_arp_collector.cpp',
  'src/tar_dns_collector.cpp',
  'src/tar_perf.cpp',
  'src/tar_proc_perf.cpp',
  'src/tar_proc_stream.cpp',
  'src/tar_module_stream.cpp',
  'src/tar_proc_etw.cpp',
  'src/tar_proc_es.cpp',
  'src/tar_netqual_nstat.cpp',
  'src/tar_module_etw.cpp',
  'src/tar_service_collector.cpp',
  'src/tar_user_collector.cpp',
  'src/tar_software_collector.cpp',
  'src/tar_software_core.cpp',
  'src/tar_mapdrive_collector.cpp',
  'src/tar_fleet_snapshot.cpp',
  'src/tar_cursor_sources.cpp',
)

# Wave 6 PR6.2-b: the power cursor source
tar_sources += files('src/tar_power_collector.cpp')
# Wave 6 PR6.3: the removable cursor source
tar_sources += files('src/tar_removable_collector.cpp')

if host_machine.system() == 'windows'
  tar_deps += cxx.find_library('advapi32')
  tar_deps += cxx.find_library('iphlpapi')
  tar_deps += cxx.find_library('ws2_32')
  tar_deps += cxx.find_library('wtsapi32')
  tar_deps += cxx.find_library('tdh')      # ETW event decoding (tar_proc_etw, tar_module_etw)
  tar_deps += cxx.find_library('dnsapi')   # DnsQuery_W / DnsRecordListFree (tar_dns_collector)
  tar_deps += cxx.find_library('wintrust') # WinVerifyTrust — image signing (tar_module_etw)
  tar_deps += cxx.find_library('crypt32')  # CryptQueryObject — signer extraction (tar_module_etw)
  tar_deps += cxx.find_library('version')  # GetFileVersionInfoW / VerQueryValueW (tar_proc_perf)
  tar_deps += cxx.find_library('wevtapi')  # EvtQuery / EvtNext / EvtRender (tar_netconn_win)
  tar_deps += cxx.find_library('mpr')      # WNetOpenEnumW / WNetGetUserW — outbound mapped drives (tar_mapdrive_collector)
  tar_deps += cxx.find_library('netapi32') # NetSessionEnum — inbound share sessions (tar_mapdrive_collector)
  tar_deps += cxx.find_library('powrprof') # PowerRegisterSuspendResumeNotification /
                                           # PowerSettingRegisterNotification (tar_power_collector)
elif host_machine.system() == 'linux'
  # Optional sd-bus leg for the wave-2 POWER cursor source: systemd-logind's
  # PrepareForSleep signal, which is the only sleep/wake source on Linux.
  # NOT for removable — that leg binds to a udev netlink socket, exactly as the
  # `removable`/linux row in tar_schema_registry.cpp declares. An earlier
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
    tar_deps += libsystemd_dep
    tar_cpp_args += '-DYUZU_HAVE_LIBSYSTEMD'
  else
    message('TAR: libsystemd not used (systemd_guard != enabled, and not found) — '
            + 'the power source sleep/wake leg degrades to AC-state polling only unconditionally')
  endif
elif host_machine.system() == 'darwin'
  # Endpoint Security process stream (tar_proc_es). The probe is hoisted to the
  # top-level meson.build (A0, endpoint_security_dep/_deps/_args) -- TAR is one
  # of two consumers (agent-core's es_client.hpp is the other), so it just
  # threads the shared result through rather than probing independently. See
  # docs/darwin-compat.md's EndpointSecurity pitfalls-table row.
  tar_deps += endpoint_security_deps
  tar_cpp_args += endpoint_security_args
  # Wave 6 PR6.3: DiskArbitration attach/detach lives in an Objective-C++ TU —
  # the worked pattern is wifi/meson.build's wifi_corewlan.mm. apple_objcpp_args
  # is defined ONCE at the top-level meson.build; never re-declare its flags.
  tar_sources += files('src/tar_removable_diskarb.mm')
  tar_deps += dependency('appleframeworks', modules: ['DiskArbitration', 'Foundation'],
                         include_type: 'system')
  tar_objcpp_args += apple_objcpp_args
endif

tar_plugin_lib = shared_library(
  'tar',
  tar_sources,
  name_prefix: '',
  # ../../shared: win_str.hpp (#1681, tar_module_etw)
  # ../../core/src: dex_linux_proc.hpp — reused pure /proc parsers (tar_perf, tar_proc_perf)
  # ../../../common/include: yuzu/audit_retention_rules.hpp (#2549 shared clock-guard core)
  include_directories: include_directories('../../shared', '../../core/src', '../../../common/include'),
  cpp_args: tar_cpp_args,
  objcpp_args: tar_objcpp_args,
  dependencies: tar_deps,
  install: true,
  install_dir: get_option('libdir') / 'yuzu' / 'plugins',
)
