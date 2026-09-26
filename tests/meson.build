if host_os == 'windows'
  # Same #375-class IMPORTED_LOCATION_RELEASE problem as protobuf/grpc/cli11
  # in the top-level meson.build: meson's cmake dep translator picks
  # the release-CRT Catch2 lib for both debug and release consumers,
  # so a debug test binary linking with /MDd against release Catch2
  # trips dozens of LNK2038 _ITERATOR_DEBUG_LEVEL mismatches.
  #
  # Catch2's vcpkg layout (verified against vcpkg_installed/x64-linux/
  # — same convention on Windows with .lib instead of .a):
  #
  #   lib/Catch2.lib                              <- base lib
  #   lib/manual-link/Catch2Main.lib              <- defines main()
  #   debug/lib/Catch2d.lib                       <- debug, `d` suffix
  #   debug/lib/manual-link/Catch2Maind.lib
  #
  # Three quirks:
  #   1. Two libs in two directories. Catch2 is in plain lib/; only
  #      Catch2Main lives in lib/manual-link/. (vcpkg convention:
  #      libs that define main() — that the consumer must explicitly
  #      opt into linking — go in manual-link/.)
  #   2. The lib file is named Catch2Main, NOT Catch2WithMain. The
  #      cmake TARGET is Catch2::Catch2WithMain but the underlying
  #      filename omits the "With".
  #   3. Same `d` suffix convention as protobuf for the debug variant.
  #      _pbd is established in the top-level Windows block ('' for
  #      release, 'd' for debug).
  _cxx_tests = meson.get_compiler('cpp')
  _libcatch2     = _cxx_tests.find_library('Catch2'     + _pbd, dirs: [_vcpkg_lib_win],                 required: true)
  _libcatch2main = _cxx_tests.find_library('Catch2Main' + _pbd, dirs: [_vcpkg_lib_win / 'manual-link'], required: true)
  catch2_dep = declare_dependency(
    # Reuse the project-root-anchored IncludeDirs object from the top-level
    # meson.build. Recreating it here with include_directories() would resolve
    # the relative path against tests/ and fail with "vcpkg_installed/...
    # does not exist".
    include_directories: _vcpkg_inc_win,
    # Order matters: Catch2Main defines main() and references symbols
    # from Catch2. List Main first so the linker pulls it in, then
    # Catch2 satisfies the leftover refs.
    dependencies: [_libcatch2main, _libcatch2],
  )
  # No-main variant for yuzu_agent_tests AND yuzu_server_tests (#1648/#3507):
  # both suites supply their own main() via the shared unit/test_runner_main.cpp
  # so they can log Catch2's real return code and, on Windows, hard_exit()
  # immediately after a clean run — so neither must also pull in Catch2Main.
  catch2_nomain_dep = declare_dependency(
    include_directories: _vcpkg_inc_win,
    dependencies: [_libcatch2],
  )
else
  catch2_dep = dependency('Catch2', modules: ['Catch2::Catch2WithMain'], method: 'cmake', required: true, include_type: 'system')
  catch2_nomain_dep = dependency('Catch2', modules: ['Catch2::Catch2'], method: 'cmake', required: true, include_type: 'system')
endif

# ── Test fixture: plugin with a reserved name (#453) ─────────────────────────
# Built only when tests are enabled; test_plugin_loader.cpp scans against this
# shared library to verify the reserved-name rejection path.
reserved_name_fixture_plugin = shared_library(
  'reserved_name_fixture_plugin',
  files('unit/fixtures/reserved_name_plugin.cpp'),
  name_prefix: '',
  dependencies: [yuzu_sdk_dep, yuzu_agent_core_dep],
  install: false,
)

# ── Test fixture: plugin with a malformed name (#822) ────────────────────────
# Declares a name outside the [A-Za-z0-9_] identifier set; test_plugin_loader.cpp
# scans against it to verify the invalid-name rejection path.
invalid_name_fixture_plugin = shared_library(
  'invalid_name_fixture_plugin',
  files('unit/fixtures/invalid_name_plugin.cpp'),
  name_prefix: '',
  dependencies: [yuzu_sdk_dep, yuzu_agent_core_dep],
  install: false,
)

# PLAN-08: test_native_raii.cpp (PR1.3) includes <IOKit/IOKitLib.h> and
# <CoreFoundation/CoreFoundation.h> for the ScopedIOObject/ScopedCFRef vectors.
# agent-core links IOKit (a hard dependency, C0) and Security/CoreFoundation (A0's optional
# probe) itself (agents/core/meson.build's darwin arm), but the test exe still pulls its own copy here: yuzu_agent_core_dep
# (the declare_dependency() this exe consumes) declares no `dependencies:` kwarg at
# all, so agent_platform_deps (IOKit/CoreFoundation/Security/ES) never propagates to
# a consumer regardless of configuration -- not an AppleFrameworks -isystem quirk
# (dependency('appleframeworks', ...) never emits -isystem args in the first place).
# This stays a direct probe. Darwin-only; empty elsewhere.
agent_test_native_deps = []
agent_test_native_args = []
if host_machine.system() == 'darwin'
  agent_test_native_deps += dependency('appleframeworks', modules: ['IOKit', 'CoreFoundation'])
  # Wave 4 PR4.3a: test_installed_apps_macos_enrich.cpp exercises
  # installed_apps_macos_enrich.hpp's SecStaticCode path directly. Same
  # required:false + -D shape as installed_apps/meson.build's own block, so a
  # box without the Security framework compiles the header's honest no-op and
  # the test self-skips rather than failing configure.
  agent_test_security_dep = dependency('appleframeworks', modules: ['Security'],
                                       required: false, include_type: 'system')
  if agent_test_security_dep.found()
    agent_test_native_deps += agent_test_security_dep
    agent_test_native_args += ['-DYUZU_HAVE_SECURITY_FRAMEWORK']
  endif
  # Endpoint Security (A0): shared top-level probe, so a darwin test TU that
  # includes agent-core's ES-dependent headers (es_client.hpp today; a full
  # shared ES client in a later slice) compiles the same way core itself does.
  agent_test_native_deps += endpoint_security_deps
  agent_test_native_args += endpoint_security_args
elif host_machine.system() == 'windows'
  # test_icmp_probe.cpp (Wave 2 WP-0): ws2_32 for WSAStartup/getaddrinfo/
  # htons, iphlpapi for IcmpCreateFile/IcmpCloseHandle -- icmp_probe.hpp's
  # own consumers (discovery/wol) link these themselves; the test TU needs
  # its own copy, same shape as tar_test_deps' Windows block below.
  agent_test_native_deps += cxx.find_library('ws2_32')
  agent_test_native_deps += cxx.find_library('iphlpapi')
  # test_wmi_bounded.cpp / test_wmi_local_dispatcher.cpp include the
  # header-only agents/shared/wmi_bounded.hpp directly into this exe (same
  # shape as tar_test_deps' Windows block) — bounded WMI needs WbemLocator
  # (wbemuuid) + COM init/BSTR (ole32/oleaut32).
  agent_test_native_deps += cxx.find_library('wbemuuid')
  agent_test_native_deps += cxx.find_library('ole32')
  agent_test_native_deps += cxx.find_library('oleaut32')
endif

# ── Test fixture: FROZEN ABI3-layout plugin (PLAN-03 — real backward-compat) ──
# A genuine old-layout plugin compiled against the FROZEN tests/fixtures/abi3/
# plugin_abi3.h (quoted include, resolved next to the .cpp) — deliberately NOT
# yuzu_sdk_dep, so it never picks up the live ABI4 header. test_capability_
# descriptor.cpp dlopens it by explicit path to prove the ABI4 loader still
# accepts an ABI3 descriptor (MIN=1). name_prefix '' so it lands at
# <builddir>/tests/abi3_fixture_plugin<ext> like the fixtures above.
abi3_fixture_plugin = shared_library(
  'abi3_fixture_plugin',
  files('fixtures/abi3/abi3_fixture_plugin.cpp'),
  name_prefix: '',
  install: false,
)

# ── Test fixture: ABI4 plugin that DECLARES capabilities (PR1.1 finding F10) ─
# Every shipped plugin is still undeclared, so the capability-matrix gate only
# ever observed the all-undeclared state and proved nothing about how
# capmatrix-gen renders a real declaration. This fixture is the declared input
# tests/shell/test_capability_matrix_gate.sh feeds to the real binary.
# yuzu_sdk_dep only (header-only declare_dependency): the module must stay
# self-contained so the shell test can copy it into a hermetic fixture tree.
# name_prefix '' so it lands at <builddir>/tests/abi4_declared_fixture_plugin<ext>.
# build-ci B3: this target used to sit in no test's `depends:`/`link_depends`
# anywhere, so it built ONLY via build_by_default and nothing in the meson
# graph noticed if it stopped building — see the "capability matrix gate
# shell tests" test() near the end of this file, which now depends on it.
abi4_declared_fixture_plugin = shared_library(
  'abi4_declared_fixture_plugin',
  files('fixtures/abi4/abi4_declared_fixture_plugin.cpp'),
  name_prefix: '',
  dependencies: [yuzu_sdk_dep],
  install: false,
)

# Sibling of abi4_declared_fixture_plugin, built identically, but written
# through the C++ `yuzu::Plugin` + YUZU_PLUGIN_EXPORT path rather than
# hand-rolling the C descriptor. It is the regression proving the descriptor
# seam (the two non-pure virtuals on yuzu::Plugin) actually reaches
# capmatrix-gen — the path all 49 real plugins take.
abi4_cpp_wrapper_fixture_plugin = shared_library(
  'abi4_cpp_wrapper_fixture_plugin',
  files('fixtures/abi4/abi4_cpp_wrapper_fixture_plugin.cpp'),
  name_prefix: '',
  dependencies: [yuzu_sdk_dep],
  install: false,
)

# ── Test fixture: deterministic argv-echo binary (BR-006 exec-verify test) ───
# test_content_dist_exec_seam.cpp's real end-to-end B6 exec-verify test used
# to stage a copy of the host's /bin/echo and assert it echoed its argv back.
# That broke on a CI runner whose /bin/echo turned out to be a GNU coreutils
# multi-call binary: coreutils dispatches by inspecting /proc/self/exe, and
# B6's fd-based execveat(fd, "", ..., AT_EMPTY_PATH) exec presents
# /proc/self/exe as an fd-numbered path rather than a real one, so coreutils
# tried to dispatch to a utility literally named after the fd number and
# failed. A standalone, single-purpose binary has no argv[0]/exe-path-
# sensitive dispatch to break. No dependencies at all -- deliberately plain,
# so it stays a stable fixture regardless of what the rest of the tree links.
echo_argv_fixture = executable(
  'echo_argv_fixture',
  files('fixtures/echo_argv_fixture.cpp'),
  install: false,
)

# ── Agent unit tests ──────────────────────────────────────────────────────────
#
# Proto-dep choice is platform-conditional (#572 + Windows MSVC follow-up):
#
#   * Linux + macOS: yuzu_proto_headers_dep (no link_with). The proto
#     symbols are baked into libyuzu_agent_core.so as `.dynsym` entries
#     because proto/meson.build compiles with -fvisibility=default. The
#     test binary resolves them dynamically at runtime → single
#     descriptor registration → ASan-clean.
#
#   * Windows MSVC: yuzu_proto_dep (with link_with). MSVC shared_library
#     does NOT export symbols by default — there's no equivalent of
#     -fvisibility=default that lets every symbol cross the DLL boundary
#     without __declspec(dllexport). So libyuzu_agent_core.dll's import
#     lib does not surface proto symbols and the test binary must link
#     yuzu_proto.lib directly. Same proto archive, double-registered — the
#     nightly windows-asan job (.github/workflows/nightly.yml) builds and
#     runs this exact configuration under MSVC ASan, so whatever the
#     underlying reason, the duplicate-descriptor CHECK that drove #572
#     does not fire here either — not, as previously stated here, because
#     ASan is absent from Windows MSVC coverage entirely (it isn't — it
#     runs as nightly.yml's standalone windows-asan job; it genuinely IS
#     absent from ci.yml's own build matrix, a separate and narrower term
#     per docs/ci-architecture.md). See that job's own run history for
#     current pass/fail status per ref.
#
# Without this split, Windows MSVC fails LNK2019 on every .pb.o symbol
# in test_guardian_engine.cpp (the canary that surfaces the broken link).
if host_machine.system() == 'windows'
  agent_test_proto_dep = yuzu_proto_dep
else
  agent_test_proto_dep = yuzu_proto_headers_dep
endif

# test_plugin_loader.cpp uses OpenSSL CMS APIs to mint test fixtures
# (CA + signing cert + detached PEM signature) so the verifier tests do not
# depend on `openssl(1)` at runtime or pre-baked .pem files that drift.
agent_test_openssl_dep = dependency('openssl', required: true, include_type: 'system')

# Test fixtures deliberately partial-aggregate-init wide inventory structs
# (SwEntry / SoftwareEntry are 12 fields since blob contract v2; a 4-field
# init IS the contract — "the rest stays empty"). -Wextra's
# missing-field-initializers would flag every such fixture; suppress it for
# the TEST targets only — production code stays fully warned.
if cxx.get_id() == 'msvc'
  test_partial_init_args = []
else
  test_partial_init_args = ['-Wno-missing-field-initializers']
endif

agent_test_exe = executable(
  'yuzu_agent_tests',
  files(
    # Custom Catch2 entry point (#1648 diagnostic) — logs Session::run()'s
    # real return value; see unit/test_runner_main.cpp and catch2_nomain_dep
    # above.
    'unit/test_runner_main.cpp',
    'unit/test_progress_listener.cpp', # #4018 per-test START/END progress log, env-gated
    'unit/test_detached_signature.cpp', # shared detached-CMS verifier (#416/#3807)
    'unit/test_updater_signature.cpp', # OTA signature gate, end to end (#416/#3807)
    'unit/test_plugin_loader.cpp',
    'unit/test_capability_registry_tables.cpp',
    'unit/test_sdk_utilities.cpp',
    'unit/test_temp_file.cpp',
    'unit/test_updater.cpp',
    'unit/test_filesystem_read.cpp',
    'unit/test_filesystem_actions.cpp',
    'unit/test_confined_fs_rules.cpp',
    'unit/test_confined_fs_walk.cpp',
    'unit/test_confined_fs_posix.cpp',
    'unit/test_confined_fs_win.cpp',
    'unit/test_string_utils.cpp',
    'unit/test_vuln_rules.cpp',
    'unit/test_metrics.cpp',
    'unit/test_metrics_perf.cpp',
    'unit/test_kv_store.cpp',
    'unit/test_fake_journal_store.cpp', # IJournalStore test double contract (#4153)
    'unit/test_command_dedup_store.cpp',
    'unit/test_trigger_engine.cpp',
    'unit/test_guardian_engine.cpp',
    'unit/test_guardian_engine_legacy_sink.cpp', # #4783 commit 1: [!mayfail] red evidence only
    'unit/test_guardian_journal_format.cpp',
    'unit/test_guardian_lifecycle_journal.cpp',
    'unit/test_guardian_journal_heartbeat.cpp',
    'unit/test_guardian_arm_heartbeat.cpp', # rung 9c PR-3
    'unit/test_guardian_health_heartbeat.cpp',
    'unit/test_guardian_backend_heartbeat.cpp',
    'unit/test_guardian_unsupported_heartbeat.cpp',
    'unit/test_guard_registry.cpp',
    'unit/test_guard_file.cpp',
    'unit/test_guard_service.cpp',
    'unit/test_guard_systemd.cpp',
    'unit/test_dex_signals.cpp',
    'unit/test_dex_macos.cpp',
    'unit/test_dex_win_poll.cpp',
    'unit/test_dex_perf_breach.cpp',
    'unit/test_net_quality_sampler.cpp',
    'unit/test_dex_linux_proc.cpp',
    'unit/test_dex_macos_perf.cpp',
    'unit/test_dex_linux_journal.cpp',
    'unit/test_dex_linux_kmsg.cpp',
    'unit/test_dex_linux_sysfs.cpp',
    'unit/test_dex_rate_limiter.cpp',
    'unit/test_resilience_strategy.cpp',
    'unit/test_thread_pool.cpp',
    'unit/test_shutdown_pipe.cpp',
    'unit/test_hard_exit.cpp',
    'unit/test_shutdown_deadline_guard.cpp',
    'unit/test_log_handoff.cpp', # #4666 PR-1: bounded async log hand-off primitive
    'unit/test_service_completion.cpp', # #4666 PR-2: service shutdown completion handshake
    'unit/test_agent_log_wiring.cpp', # #4666 PR-2: install/release wrapper (agent_log_wiring.hpp)
    'unit/test_log_handoff_multi_image.cpp', # #4666 PR-2 W3a: macOS multi-image topology fixture (MI-1/MI-3)
    'unit/test_spark_detached_call.cpp',
    'unit/test_spark_disk.cpp',
    'unit/test_spark_engine.cpp',
    'unit/test_spark_key_rule_index.cpp',
    'unit/test_spark_mechanism.cpp',
    'unit/test_guardian_spark_bridge.cpp',
    'unit/test_guardian_spark_backend.cpp',
    'unit/test_guardian_emit_decider.cpp',
    'unit/test_guardian_rule_eval.cpp',
    'unit/test_guardian_drift_event.cpp',
    'unit/test_guardian_scope_guard.cpp',
    'unit/test_offline_hive_mutex.cpp',       # ScopedOfflineHiveLock RAII/mutual-exclusion contract
    'unit/test_guardian_outbox.cpp',
    'unit/test_guardian_spark_send.cpp',
    'unit/test_guardian_spark_runtime.cpp',
    'unit/test_guardian_state_reader.cpp',
    'unit/test_guardian_convergence_scheduler.cpp',
    'unit/test_guardian_io_executor.cpp',
    'unit/test_guardian_outbox_send_executor.cpp',
    'unit/test_guardian_legacy_sink_executor.cpp',
    'unit/test_guardian_outbox_drain_worker.cpp',
    'unit/test_guardian_engine_spark_reconcile.cpp',
    'unit/test_guardian_arm_ack.cpp',
    'unit/test_new_plugins.cpp',
    'unit/test_netprobe_stats.cpp',
    'unit/test_antivirus_parsers.cpp',
    'unit/test_firewall_parsers.cpp',
    'unit/test_disk_actions_local_dispatcher.cpp', # Wave 6 PR6.1-a-1: real disk_actions dylib/.so/.dll
    'unit/test_firewall_local_dispatcher.cpp',
    'unit/test_agent_csr.cpp',
    'unit/test_tls_policy.cpp', # #4722: shared TLS cipher policy (common/include/yuzu/tls_policy.hpp), pure
    'unit/test_cert_discovery.cpp',
    'unit/test_env_util.cpp',
    'unit/test_inventory_sync.cpp',
    'unit/test_agent_sync_command.cpp', # round-3 remediation: decide_sync_now pure-core extraction
                                          # from agent.cpp's __sync__.now reserved-command branch
    'unit/test_device_ci_sync.cpp',
    'unit/test_sync_source_app_perf.cpp',
    'unit/test_win_str_utils.cpp',
    'unit/test_launchctl_list.cpp',     # A0: shared launchctl-list row parser (agents/shared/launchctl_list.hpp)
    'unit/test_launchd_state.cpp',      # A0 fix round: launchd_state_for (yuzu/agent/launchd_state.hpp)
    'unit/test_wmi_bounded.cpp',        # shared bounded WMI helper (roadmap C-8 extraction); header-only, no separate .cpp to list
    'unit/test_installed_apps_registry_utf8.cpp',
    'unit/test_service_binpath.cpp',
    'unit/test_agent_log_options.cpp', # #4666 PR-2: make_log_handoff_options CLI-flags translator
    'unit/test_installed_apps_inventory.cpp',
    'unit/test_licensing_parsers.cpp',
    'unit/test_licensing_sync.cpp',
    'unit/test_wifi_corewlan.cpp',
    'unit/test_wifi_parsers.cpp',           # PKG-WIFI: pure nmcli/iw/iwlist/iwconfig/airport/
                                              # system_profiler text parsers + NM D-Bus AP-tuple helpers
    'unit/test_wifi_local_dispatcher.cpp',  # PKG-WIFI remediation: real wifi.dylib/.so driven
                                              # end to end via LocalDispatcher (POSIX-only; a no-op
                                              # TU on Windows via the file's own #ifndef _WIN32 guard),
                                              # same pattern as test_users_posix_actions.cpp
    'unit/test_interaction_parsers.cpp',
    'unit/test_hardware_disks_macos.cpp',
    'unit/test_certificates_macos.cpp',  # A-1.11 (INT-2 handoff): existed unregistered on the branch;
                                          # macos_console_user.hpp already reachable via the agents/shared
                                          # include_directories entry below.
    'unit/test_certificates_store_honesty.cpp',  # WS-A: pure Windows/Linux store-honesty + #3245 delete-recheck decision vectors (certificates_macos_parsers.hpp)
    'unit/test_certificates_linux_store.cpp',  # WS-A a1: real syscall-level delete against a TempDir (certificates_linux_store.hpp; POSIX-guarded, runs on macOS too)
    'unit/test_certificates_macos_actions.cpp',  # WS-B: action-level LocalDispatcher tests for the SecItem
                                                  # sentinel + console-owner recheck orchestration (#4374 fix
                                                  # shape 2 + 3); __APPLE__-guarded, empty TU elsewhere.
    'unit/test_passwd_lookup.cpp',       # #3406: bounded passwd resolution (agent-core seam). The
                                          # load-bearing case injects a NEVER-RETURNING lookup and asserts
                                          # the caller is released inside its budget -- the regression that
                                          # argv-izing the login-keychain read introduced.
    'unit/test_keychain_read.cpp',        # #3246: bounded SecItem keychain read (agent-core seam); never-returning-read case is the regression test
    'unit/agent/test_services_macos.cpp',     # C-1.12: launchctl print-disabled parser (P8)
    'unit/agent/test_msi_macos.cpp',          # C-1.21: pkgutil --pkg-info parser (P8)
    'unit/agent/test_bitlocker_macos.cpp',    # A-1.16: diskutil apfs list parser (P8)
    'unit/test_subprocess_runner.cpp',        # #2273: agent-core bounded subprocess runner (POSIX deadline/reap)
    'unit/test_es_client.cpp',                # A0: pure ES helpers relocated from tar_proc_es.cpp (yuzu/agent/es_client.hpp)
    'unit/test_native_raii.cpp',              # PR1.3: ScopedCFRef/ScopedIOObject/ScopedFd RAII
    'unit/test_subprocess_launch_spec.cpp',   # PR1.2: host-agnostic pure launch-spec tests (run on Windows too)
    'unit/test_capability_descriptor.cpp',    # PR1.1: ABI4 descriptor + plugin->host result seam + declared-vs-observable honesty
    'unit/test_filesystem_macos_sig.cpp',     # #2273/1.14: pure codesign/plutil classifiers
    'unit/test_event_logs_macos.cpp',         # BR-08: pure `log show` SubprocessResult classifier
    'unit/test_event_logs_parsers.cpp',       # Wave 4 PR4.2: pure Windows event-XML / journal row parse+format helpers
    'unit/test_event_logs_journalctl.cpp',    # Wave 4 PR4.2: pure Linux journalctl-fallback outcome classifier (runs on every host)
    'unit/test_event_logs_posix_actions.cpp', # Wave 4 PR4.2 remediation: real event_logs.dylib/.so driven
                                                # end to end via LocalDispatcher (POSIX-only; a no-op
                                                # TU on Windows via the file's own #ifndef _WIN32 guard)
    'unit/test_event_logs_win_actions.cpp',   # Wave 4 PR4.2 remediation: real event_logs.dll driven
                                                # end to end via LocalDispatcher (Windows-only; a no-op
                                                # TU elsewhere via the file's own #ifdef _WIN32 guard)
    'unit/test_users_macos_last.cpp',         # qe-M1: pure `last -y` timestamp/weekday parsers
    'unit/test_user_profile_model.cpp',       # PR1.7: pure ProfileList/HKU model (runs on every host)
    'unit/test_value_enumeration.cpp',        # Wave 3 gate-2 remediation: pure registry-enumeration
                                                # completeness decision (runs on every host)
    'unit/test_registry_local_dispatcher.cpp', # PR1.7 remediation fix #3: real registry.dll driven
                                                # end to end via LocalDispatcher (Windows-only; a no-op
                                                # TU elsewhere via the file's own #ifdef _WIN32 guard)
    'unit/test_wmi_local_dispatcher.cpp',      # gate-1 remediation: real wmi.dll's query/get_instance
                                                # actions driven end to end via LocalDispatcher, same
                                                # pattern as test_registry_local_dispatcher.cpp above
                                                # (Windows-only; a no-op TU elsewhere)
    'unit/test_content_dist_upload_parsers.cpp', # PR1.6b: pure upload-protocol planner/classifier (no I/O)
    'unit/test_runner_status.cpp',             # Wave 2 WP-0: pure runner-outcome -> ABI4 result-seam table
    'unit/test_host_arg.cpp',                 # Wave 2 WP-0: shared leading-'-' host-arg gate (Decision 6)
    'unit/test_sudo_argv.cpp',                # Wave 2 WP-0: Decision-8 canonical sudo argv form (POSIX-only TU)
    'unit/test_icmp_probe.cpp',               # Wave 2 WP-0: RFC-1071 checksum + numeric-literal resolve/set_port
    'unit/test_users_win_events.cpp',         # Wave 2 WP-A: pure wevtapi event-XML -> LogonEvent parser
    'unit/test_users_posix_actions.cpp',      # Wave 2 WP-A remediation: real users.dylib/.so driven
                                                # end to end via LocalDispatcher (POSIX-only; a no-op
                                                # TU on Windows via the file's own #ifndef _WIN32 guard)
    'unit/test_script_exec_actions.cpp',       # Wave 5 PR5.1: script_exec exec/bash dispatch via LocalDispatcher (POSIX-only TU guard)
    'unit/test_script_exec_win_actions.cpp',   # Wave 5 PR5.1 round-3 remediation (BR3-003): script_exec
                                                # exec/powershell dispatch via LocalDispatcher, real
                                                # script_exec.dll (Windows-only TU guard; proves BR3-001's
                                                # windows_system_directory() PowerShell resolution end to end)
    'unit/test_script_exec_parsers.cpp',       # Wave 5 PR5.1: pure argv-assembly / PATH-resolution helpers (no I/O)
    'unit/test_content_dist_actions.cpp',      # Wave 5 PR5.1: content_dist dispatch gates via LocalDispatcher (POSIX-only TU guard)
    'unit/test_content_dist_exec_parsers.cpp', # Wave 5 PR5.1: pure SubprocessResult -> wire mapping + options builder (no I/O)
    'unit/test_content_dist_exec_seam.cpp',    # Wave 5 PR5.1 round-2 remediation (BR-006): real staged-file
                                                # execute_verified_payload() end to end (real chmod, real
                                                # runner spawn, no KV/g_ctx wall; POSIX-only TU guard)
    'unit/test_content_dist_exec_seam_win.cpp', # Wave 5 PR5.1 round-3 remediation (BR3-003): Windows twin of
                                                # the above -- real staged/copied executable payload, real
                                                # runner spawn (Windows-only TU guard)
    'unit/test_certificates_x509.cpp',        # Wave 2 WP-B: pure libcrypto PEM/DER field extraction
    'unit/test_quarantine_parsers.cpp',       # Wave 2 WP-F: pure netsh/iptables/pfctl output parsers
    'unit/test_quarantine_argv.cpp',          # Wave 2 WP-F remediation: pure mutating-argv construction (FN-03)
    'unit/test_quarantine_serialization.cpp', # Wave 2 P4: MutationGate bounded-wait serialization (#3286)
    'unit/test_server_address_parsers.cpp',   # #3429 round 4: pure host:port / IP-literal helpers for
                                                # server_address_resolver.cpp's boot-time DNS resolution
    'unit/test_server_address_resolver.cpp',  # #3429 round 4 fix: resolve_bounded's deadline wrapper,
                                                # resolver injected (no network) -- proves the caller
                                                # returns at the deadline, not after the resolver finishes
    'unit/test_network_actions_parsers.cpp',  # Wave 2 WP-D: pure resolver-flush-flag selection
    'unit/test_wol_check_plan.cpp',           # Wave 2 WP-E: pure check-mechanism decision logic
    'unit/test_services_parsers.cpp',         # Wave 2 WP-G: pure systemctl/launchctl output parsers
    'unit/test_discovery_parsers.cpp',        # Wave 2 WP-C: pure /proc/net/arp parser
    'unit/test_discovery_scan_plan.cpp',      # Wave 2 WP-C: pure sweep bounds + honest-degrade decisions
    'unit/test_network_config_parsers.cpp',   # PKG-NC: pure /proc/net/arp, dns_cache line filters,
                                                # rtnetlink + PF_ROUTE default-route binary decoders
    'unit/test_network_config_local_dispatcher.cpp', # PKG-NC: real network_config.dylib/.so driven
                                                # end to end via LocalDispatcher (POSIX-only; a no-op
                                                # TU on Windows via the file's own #ifndef _WIN32 guard)
    'unit/test_route_sysctl_arp.cpp',         # Wave 2 WP-C: pure sysctl NET_RT_FLAGS/RTF_LLINFO binary parser
    'unit/test_bounded_wait.cpp',             # Wave 2 WP-C remediation: uncancellable-call timeout wrapper
    'unit/agent/test_socket_walk.cpp',        # Wave 3 PR3.1: macos_socket_walk.hpp libproc walk (Darwin-only, self-gated)
    'unit/agent/test_netstat_attribution.cpp', # gate-1 remediation (#3403/#3404): real netstat.dylib
                                                # attribution action driven end to end via LocalDispatcher
                                                # (Darwin-only, self-gated) -- same shape as
                                                # test_wave3_pr31_macos_actions.cpp
    'unit/test_netstat_parsers.cpp',          # gate-2 remediation: pure escape_pipes() CR/LF handling
                                                # (netstat_parsers.hpp, portable, every host)
    'unit/test_os_info_macos.cpp',            # Wave 3 PR3.1: os_info_macos.hpp SystemVersion.plist extractor (pure, every host)
    'unit/agent/test_wave3_pr31_macos_actions.cpp', # Wave 3 PR3.1 remediation: real os_info/processes/
                                                # network_diag/ioc .dylib driven end to end via
                                                # LocalDispatcher (Darwin-only, self-gated) -- same
                                                # shape as test_users_posix_actions.cpp
    'unit/test_hardware_macos_bios.cpp',      # Wave 3 PR3.2: pure Boot ROM / System Firmware Version parser
    'unit/test_hardware_linux_parsers.cpp',   # Wave 3 PR3.2: pure dmidecode memory parser + injected /sys/block disk-row builder
    'unit/test_device_identity_macos.cpp',    # Wave 3 PR3.2: pure dsconfigad -show parser (device_identity's first tests)
    'unit/test_hardware_device_identity_posix_actions.cpp', # Wave 3 PR3.2 gate-1 remediation: real
                                                # hardware.dylib/device_identity.dylib driven end to end
                                                # via LocalDispatcher (macOS-only; a no-op TU elsewhere
                                                # via the file's own #if defined(__APPLE__) guard)
    'unit/test_windows_updates_parsers.cpp',  # Wave 3: pure installed/missing parse+format helpers
    'unit/test_windows_updates_posix_actions.cpp', # Wave 3 PR33d remediation: real windows_updates.dylib/.so driven (Linux/macOS)
    'unit/test_windows_updates_win_actions.cpp',   # Wave 3 PR33d remediation: real windows_updates.dll driven (Windows WMI)
    'unit/test_sccm_parsers.cpp',             # Wave 3 PR33d: pure SCM-status mirror + real authority-key/IDispatch decision logic
    'unit/test_sccm_win_actions.cpp',         # Wave 3 PR33d remediation: real sccm.dll driven (Windows SCM/COM)
    'unit/test_bitlocker_windows_wmi.cpp',    # Wave 3: pure WMI-row -> BitLocker output-row mapping
    'unit/test_bitlocker_linux_parsers.cpp',  # Wave 3: pure dm-crypt uuid / LUKS state parser
    'unit/test_antivirus_local_dispatcher.cpp', # Wave 3 gate remediation: real antivirus.dll driven
                                                # end to end via LocalDispatcher (Windows-only; a no-op
                                                # TU elsewhere via the file's own #ifdef _WIN32 guard)
    'unit/test_bitlocker_local_dispatcher.cpp', # Wave 3 gate remediation: real bitlocker.dll driven
                                                # end to end via LocalDispatcher (Windows-only; a no-op
                                                # TU elsewhere via the file's own #ifdef _WIN32 guard)
    'unit/test_installed_apps_parsers.cpp',   # Wave 4 PR4.3a: pure dpkg/rpm/pacman/system_profiler/
                                                # brew/pkgutil parsers (installed_apps_parsers.hpp)
    'unit/test_installed_apps_actions.cpp',   # Wave 4 PR4.3a remediation: real installed_apps.dylib/.so
                                                # driven end to end via LocalDispatcher (POSIX-only; a
                                                # no-op TU on Windows via the file's own #ifndef _WIN32 guard)
    'unit/test_msi_packages_actions.cpp',     # Wave 4 PR4.3a remediation: real msi_packages.dylib driven
                                                # end to end via LocalDispatcher (Darwin-only, self-gated)
    'unit/test_installed_apps_macos_enrich.cpp', # Wave 4 PR4.3a gate-1 fix: SecStaticCode signed/unsigned
                                                # discrimination (macOS-only; a no-op TU elsewhere)
    'unit/test_installed_apps_macos_receipts.cpp', # round-3 sync-speed fix: pure receipt-plist byte
                                                # parser against a real captured fixture (macOS-only;
                                                # a no-op TU elsewhere)
    'unit/test_software_actions_parsers.cpp', # Wave 4 PR4.3b: software_actions' FIRST tests --
                                                # pure winget/apt/yum/softwareupdate/dpkg-query parsers
    'unit/test_software_actions_actions.cpp', # Wave 4 PR4.3b: real software_actions.dylib/.so/.dll
                                                # driven end to end via LocalDispatcher
                                                # (installed_count only; the Windows leg covers the
                                                # native rung-1 Uninstall-key registry read)
    'unit/test_license_scan_actions.cpp',    # Wave 4 PR4.3b: real license_scan.dylib/.so driven
                                                # end to end via LocalDispatcher after the Linux-leg
                                                # runner migration (POSIX-only, a no-op TU on Windows)
    'unit/test_filesystem_posture_parsers.cpp', # Wave 6 PR6.1-b: pure /proc/self/mountinfo, quotactl
                                                # errno classification, fs_snapshot_list attrlist walk,
                                                # and the legs.hpp pure row formatters
    'unit/test_filesystem_posture_local_dispatcher.cpp', # Wave 6 PR6.1-b: real filesystem_posture dylib
                                                # driven end to end via LocalDispatcher (POSIX-only; a no-op
                                                # TU on Windows via the file's own #ifndef _WIN32 guard)
    'unit/test_power_health_parsers.cpp',        # Wave 6 PR6.2-a: pure power_health parser/decision tests, fixture-driven, no OS calls
    'unit/test_windows_optional_features_parsers.cpp',           # Wave 9 PR9.2a: DismSlot CAS state machine +
                                                # row/parameter parsers (agents/shared, agent-core primitive)
    'unit/test_windows_optional_features_local_dispatcher.cpp',  # Wave 9 PR9.2b: real windows_optional_features
                                                # dylib/.so/.dll driven end to end via LocalDispatcher
    'unit/test_app_control_parsers.cpp',         # Wave 8 PR8.6: pure app_control mappers/row formatters/dump
                                                # parsers over the-rig REAL CAPTURE fixtures (REQUIRE(exists))
    'unit/test_app_control_local_dispatcher.cpp', # Wave 8 PR8.6: real app_control dylib/.so/.dll driven end to
                                                # end via LocalDispatcher (unguarded: non-Windows asserts the
                                                # exact unsupported row)
    'unit/test_power_health_local_dispatcher.cpp', # Wave 6 PR6.2-a: real power_health dylib/.so via
                                                # LocalDispatcher. Deliberately NOT platform-guarded — it
                                                # runs on every OS, and on a host with no battery it emits an
                                                # explicit named SKIP rather than passing silently.
    'unit/test_autoruns_parsers.cpp',   # Wave 7 PR7.1: pure parsers over REAL CAPTURE fixtures (dispatcher test lands with the OS legs)
    'unit/test_autoruns_local_dispatcher.cpp',  # Wave 7 PR7.1: real plugin via LocalDispatcher, unguarded on every OS
    'unit/test_autoruns_win_local.cpp',         # Wave 7 PR7.1: Windows leg (+ OS-independent WMI join tests)
    'unit/test_autoruns_linux_local.cpp',       # Wave 7 PR7.1: Linux leg (+ read_file_bounded internals)
    'unit/test_autoruns_macos_local.cpp',       # Wave 7 PR7.1: macOS leg (CFPropertyList over REAL plists)
    'unit/test_peripherals_parsers.cpp',           # Wave 9 PR9.1a: pure row formatters/hex helpers, fixture-driven
    'unit/test_peripherals_local_dispatcher.cpp',  # Wave 9 PR9.1a: real peripherals dylib/.so/.dll via LocalDispatcher, unguarded on every OS
    'unit/test_peripherals_linux_parsers.cpp',     # Wave 9 PR9.1a: pure sysfs walk/attr parsers over a committed fixture tree
    'unit/test_peripherals_macos_parsers.cpp',     # Wave 9 PR9.1a: pure IOKit OSData decoders over this-Mac REAL CAPTURE fixtures
    'unit/test_peripherals_win_parsers.cpp',       # Wave 9 PR9.1a2: pure SetupAPI hardware-id parsers over the-rig REAL CAPTURE fixtures
    'unit/test_app_usage_parsers.cpp',           # Wave 7b PR7b.3: pure sqlite seam, :memory: db seeded from the REAL CAPTURE export
    'unit/test_app_usage_local_dispatcher.cpp',  # Wave 7b PR7b.3: real plugin via LocalDispatcher, unguarded on every OS; seeded via StandalonePluginContext
    'unit/test_sync_source_app_usage.cpp',       # Wave 7b PR7b.3: app_usage daily-sync source
    'unit/test_execution_artifacts_parsers.cpp',   # Wave 7b PR7b.1: pure binary parsers over REAL CAPTURE fixtures + mutation fuzz
    'unit/test_execution_artifacts_local_dispatcher.cpp',  # Wave 7b PR7b.1: real plugin via LocalDispatcher, unguarded on every OS
    'unit/test_execution_artifacts_win_local.cpp',  # Wave 7b PR7b.1: Windows leg shape assertions, unguarded TU
    'unit/test_execution_artifacts_scratch_sweep.cpp',  # #4390: portable scratch-dir selection policy (every OS) + Windows handle-relative sweep, init()/dispatch e2e
    'unit/test_execution_artifacts_win_internals.cpp',  # #4392: TU-inclusion seam over execution_artifacts_win.cpp (Windows-only body, empty TU elsewhere)
    'unit/test_posix_dir_walk.cpp',     # PR #4154 round-8 remediation: shared capped
                                        # directory-walk primitive (agents/shared/posix_dir_walk.hpp)
    'unit/test_printing_parsers.cpp',            # Wave 9 PR9.1b
    'unit/test_printing_local_dispatcher.cpp',   # Wave 9 PR9.1b
    'unit/test_firmware_posture_parsers.cpp',           # Wave 8 PR8.4: pure SMBIOS/DMI/fwupd/IODeviceTree decoders over REAL CAPTURE fixtures
    'unit/test_firmware_posture_local_dispatcher.cpp',  # Wave 8 PR8.4: real firmware_posture plugin via LocalDispatcher, unguarded on every OS
    'unit/test_platform_security_parsers.cpp',            # Wave 8 PR8.1-a1: pure decoders/classifiers/status over REAL CAPTURE fixtures
    'unit/test_platform_security_win_parsers.cpp',        # Wave 8 PR8.1-a1: pure registry-state mappers + reg-export parser over the-rig REAL CAPTURE fixtures
    'unit/test_platform_security_local_dispatcher.cpp',   # Wave 8 PR8.1-a1: real platform_security dylib/.so/.dll via LocalDispatcher, unguarded on every OS
    'unit/test_browser_inventory_parsers.cpp',          # Wave 10 P2a: pure JSON row parsers, fixture-driven
    'unit/test_browser_inventory_linux_parsers.cpp',    # Wave 10 P2a: Linux leg walk over an injected root
    'unit/test_browser_inventory_local_dispatcher.cpp', # Wave 10 P2a: real plugin via LocalDispatcher, unguarded on every OS
    'unit/test_asset_tags_parsers.cpp',   # #232: pure cap/escape/apply_sync/snapshot helpers (asset_tags_parsers.hpp)
    'unit/test_asset_tags_store.cpp',   # #232: atomic state-file lifecycle (asset_tags_store.hpp), TempDir-based
    'unit/test_asset_tags_actions.cpp',   # #232: real asset_tags dylib/.so/.dll via LocalDispatcher, unguarded on every OS
    'unit/test_asset_tags_sync_lock.cpp', # #232: TU-inclusion seam over asset_tags_plugin.cpp -- sync writes under g_mu (POSIX body, empty TU on Windows)
    'unit/test_system_hardening_parsers.cpp',            # Wave 8 PR8.1-b: pure state mappers + errno classifier over REAL CAPTURE fixtures
    'unit/test_system_hardening_win_parsers.cpp',        # Wave 8 PR8.1-b: pure mitigation-registry decoder over the-rig REAL CAPTURE fixtures
    'unit/test_system_hardening_local_dispatcher.cpp',   # Wave 8 PR8.1-b: real system_hardening dylib/.so/.dll via LocalDispatcher, unguarded on every OS
    'unit/test_runtimes_parsers.cpp',            # Wave 10 PR10.1-b: pure parsers over REAL CAPTURE fixtures, unguarded on every OS
    'unit/test_runtimes_linux_parsers.cpp',      # Wave 10 PR10.1-b: Linux walk over materialized tree manifests (REAL CAPTURE structure plus labelled reconstructions; walk bodies POSIX-only)
    'unit/test_runtimes_local_dispatcher.cpp',   # Wave 10 PR10.1-b: real plugin via LocalDispatcher, unguarded on every OS
    'unit/test_pkg_inventory_parsers.cpp',          # Wave 10 PR10.1-c: pure row formatters/tokens + synthetic in-code macOS walk cases (no committed fixture)
    'unit/test_pkg_inventory_macos_parsers.cpp',    # Wave 10 PR10.1-c: injected-root Homebrew walk over a REAL CAPTURE Cellar tree
    'unit/test_pkg_inventory_local_dispatcher.cpp', # Wave 10 PR10.1-c: real pkg_inventory plugin via LocalDispatcher, unguarded on every OS
    '../agents/plugins/pkg_inventory/src/pkg_inventory_macos.cpp', # Wave 10 PR10.1-c: run_macos (the slot-guarded entry point execute() calls); self-gated to __APPLE__, empty elsewhere
  ),
  include_directories: [
    include_directories('../agents/plugins/vuln_scan/src'),  # cve_rules.hpp
    include_directories('../agents/plugins/netprobe/src'),   # netprobe_stats.hpp (pure helpers)
    include_directories('../agents/plugins/antivirus/src'),  # antivirus_parsers.hpp (pure helpers)
    include_directories('../agents/plugins/firewall/src'),   # firewall_parsers.hpp (pure helpers)
    include_directories('../agents/plugins/installed_apps/src'),  # installed_apps_registry_utf8.hpp (#1662 test)
    include_directories('../agents/plugins/disk_actions/src'), # disk_actions_legs.hpp (pure formatters)
    include_directories('../agents/plugins/printing/src'),  # printing_ipp.hpp / printing_parsers.hpp (pure helpers)
    include_directories('../agents/plugins/runtimes/src'),  # runtimes_*parsers.hpp / runtimes_legs.hpp (Wave 10 PR10.1-b pure helpers)
    include_directories('../agents/plugins/browser_inventory/src'),  # browser_inventory_*_parsers.hpp (pure helpers)
    include_directories('../agents/plugins/power_health/src'),  # power_health_parsers.hpp (pure helpers)
    include_directories('../agents/plugins/windows_optional_features/src'),  # windows_optional_features_plugin.cpp (Wave 9 PR9.2b)
    include_directories('../agents/plugins/peripherals/src'),  # peripherals_*_parsers.hpp (pure helpers)
    include_directories('../agents/plugins/firmware_posture/src'),  # firmware_posture_parsers.hpp (pure helpers)
    include_directories('../agents/plugins/platform_security/src'),  # platform_security_*parsers.hpp / _legs.hpp (pure helpers), Wave 8 PR8.1-a1
    include_directories('../agents/plugins/system_hardening/src'),  # system_hardening_*parsers.hpp (pure helpers), Wave 8 PR8.1-b
    include_directories('../agents/plugins/pkg_inventory/src'),  # Wave 10 PR10.1-c: pkg_inventory_*_parsers.hpp (pure helpers)
    include_directories('../agents/plugins/autoruns/src'),  # Wave 7 PR7.1
    include_directories('../agents/plugins/app_usage/src'),  # Wave 7b PR7b.3: app_usage_parsers.hpp
    include_directories('../agents/plugins/execution_artifacts/src'),  # Wave 7b PR7b.1
    include_directories('../agents/plugins/license_scan/src'),    # licensing_parsers.hpp / licensing_record.hpp (pure, SLE PR1)
    include_directories('../agents/plugins/wifi/src'),            # wifi_corewlan.hpp (pure connected-record formatter)
    include_directories('../agents/plugins/interaction/src'),     # interaction_parsers.hpp (pure helpers)
    include_directories('../agents/core/src'),               # dex_event.hpp (proto-aware mapping)
    include_directories('../agents/shared'),         # win_str.hpp (#1681, _WIN32-gated); also macos_console_user.hpp (test_certificates_macos.cpp)
    include_directories('../agents/plugins/hardware/src'),  # hardware_disks_macos.hpp (pure parser, PR1.8)
    include_directories('../agents/plugins/services/src'),      # services_macos_launchd.hpp (P8 test)
    include_directories('../agents/plugins/msi_packages/src'),  # msi_packages_macos.hpp (P8 test)
    include_directories('../agents/plugins/bitlocker/src'),     # bitlocker_macos_apfs.hpp (P8 test); Wave 3: bitlocker_windows_wmi.hpp, bitlocker_linux_parsers.hpp
    include_directories('../agents/plugins/filesystem/src'),    # filesystem_macos_sig.hpp (#2273/1.14)
    include_directories('../agents/plugins/event_logs/src'),    # event_logs_macos.hpp (BR-08)
    include_directories('../agents/plugins/certificates/src'),  # certificates_macos_parsers.hpp (Gate-7 FIX A: pure helpers shared with the plugin)
    include_directories('../agents/plugins/quarantine/src'),    # quarantine_parsers.hpp (Wave 2 WP-F)
    include_directories('../agents/plugins/users/src'),         # users_macos_last.hpp (qe-M1 pure parser)
    include_directories('../agents/plugins/content_dist/src'),  # content_dist_upload_parsers.hpp (PR1.6b pure helpers)
    include_directories('../agents/plugins/script_exec/src'),   # script_exec_parsers.hpp (Wave 5 PR5.1 pure helpers)
    include_directories('../agents/plugins/network_actions/src'), # network_actions_parsers.hpp (Wave 2 WP-D)
    include_directories('../agents/plugins/wol/src'),             # wol_check_plan.hpp (Wave 2 WP-E)
    include_directories('../agents/plugins/discovery/src'),      # discovery_parsers.hpp (Wave 2 WP-C pure parser)
    include_directories('../agents/plugins/network_config/src'), # network_config_parsers.hpp (PKG-NC pure parser)
    include_directories('../agents/plugins/os_info/src'),        # os_info_macos.hpp (Wave 3 PR3.1 pure plist parser)
    include_directories('../agents/plugins/device_identity/src'), # device_identity_macos.hpp (Wave 3 PR3.2 pure parser)
    include_directories('../agents/plugins/netstat/src'),        # netstat_parsers.hpp (gate-2 remediation pure parser)
    include_directories('../agents/plugins/windows_updates/src'), # windows_updates_parsers.hpp (Wave 3 pure parser)
    include_directories('../agents/plugins/sccm/src'),           # sccm_parsers.hpp (Wave 3 PR33d pure parser)
    include_directories('../agents/plugins/software_actions/src'), # software_actions_parsers.hpp (Wave 4 PR4.3b pure parser)
    include_directories('../agents/plugins/filesystem_posture/src'), # filesystem_posture_parsers.hpp / _legs.hpp (Wave 6 PR6.1-b pure headers)
    include_directories('../agents/plugins/asset_tags/src'),     # asset_tags_parsers.hpp / asset_tags_store.hpp (#232)
  ],
  # agent_platform_args carries -DYUZU_HAVE_LIBSYSTEMD (Linux + libsystemd found)
  # so Linux real-mechanism Service spark tests can compile-gate on it, exactly
  # as agents/core/meson.build gates guard_systemd.cpp/spark_service.cpp.
  # agent_test_native_args carries darwin's -DYUZU_HAVE_SECURITY_FRAMEWORK
  # (Wave 4 PR4.3a) so test_installed_apps_macos_enrich.cpp compiles the real
  # SecStaticCode path instead of the header's no-op.
  # YUZU_AGENT_SRC_DIR (#2233 item 1 / #3831 source-tripwire tests): mirrors
  # YUZU_SERVER_SRC_DIR below - mechanically scans the real agents/core/src tree at
  # test run time rather than hand-copying a snippet that would go stale exactly like
  # the ordering property it proves. Same backslash-normalisation requirement as that
  # define: on Windows meson.project_source_root() is a native path, and unescaped
  # backslashes either fail to compile or silently mangle the path (see that define's
  # own comment for the full reasoning).
  cpp_args: test_partial_init_args + agent_platform_args + agent_test_native_args +
            ['-DYUZU_AGENT_SRC_DIR="' +
             (meson.project_source_root() / 'agents' / 'core' / 'src').replace('\\', '/') +
             '"',
             # Wave 7 PR7.1: committed fixture root; autoruns' REAL CAPTURE tests
             # REQUIRE(exists), never skip. Wave 9 PR9.2a: test_windows_optional_features_parsers.cpp
             # reads the-rig REAL CAPTURE fixtures via this same define. Wave 9 PR9.1a:
             # test_peripherals_{macos,linux}_parsers.cpp read the-rig/this-Mac REAL
             # CAPTURE fixtures via this same define. Wave 9 PR9.1a2:
             # test_peripherals_win_parsers.cpp reads the-rig REAL CAPTURE fixtures too.
             # Wave 8 PR8.4: test_firmware_posture_parsers.cpp reads REAL CAPTURE fixtures via
             # this same define.
             # Wave 8 PR8.1-a1: test_platform_security_{parsers,win_parsers}.cpp read
             # Wave 8 PR8.1-b: test_system_hardening_{parsers,win_parsers}.cpp read
             # Docker/this-Mac/the-rig REAL CAPTURE fixtures via this same define.
             # Wave 10 PR10.1-c: test_pkg_inventory_macos_parsers.cpp reads the this-Mac REAL
             # CAPTURE tree manifest via this same define.
             '-DYUZU_TEST_FIXTURE_DIR="' +
             (meson.project_source_root() / 'tests' / 'unit' / 'fixtures').replace('\\', '/') +
             '"'],
  # catch2_nomain_dep (#1648 diagnostic): yuzu_agent_tests supplies its own main()
  # via unit/test_runner_main.cpp, so it links Catch2 without Catch2Main.
  # spdlog_dep (brings fmt): test_thread_pool.cpp instantiates spdlog logging in
  # thread_pool.hpp directly in the test TU, so it needs fmt symbols linked here.
  # sqlite3_dep: test_kv_store.cpp opens a SECOND raw connection to the same file to
  # provoke a genuine SQLite failure (dropping the table so prepare fails), which is the
  # only way to exercise KvStore's fallible-read branches end to end rather than through
  # an injected stand-in. Already a transitive dep of yuzu_agent_core; naming it here is
  # what puts sqlite3.h on the test TU's include path (same shape as tar_test_deps).
  # libxml2_dep: test_autoruns_parsers.cpp #includes autoruns_parsers.hpp,
  # which parses Task Scheduler XML via real libxml2 unconditionally on
  # every platform -- this test TU needs it on its include/link path too.
  dependencies: [yuzu_agent_core_dep, yuzu_sdk_dep, agent_test_proto_dep, nlohmann_dep, catch2_nomain_dep, agent_test_openssl_dep, spdlog_dep, sqlite3_dep, libxml2_dep] + agent_test_native_deps,
  # Ensure the fixture plugins are built before the test runs so the lookups
  # inside test_plugin_loader.cpp / test_capability_descriptor.cpp find them
  # under MESON_BUILD_ROOT/tests/.
  # users_plugin_lib (agents/plugins/users/meson.build): test_users_posix_actions.cpp
  # loads the real users plugin by path -- without this, the plugin build isn't
  # ordered ahead of the test binary, and a not-yet-built plugin makes those
  # cases WARN-and-skip instead of failing (code-review re-verification finding).
  # os_info_plugin_lib / processes_plugin_lib / network_diag_plugin_lib / ioc_plugin_lib:
  # same reasoning, for test_wave3_pr31_macos_actions.cpp (Wave 3 PR3.1 remediation).
  # hardware_plugin_lib / device_identity_plugin_lib (agents/plugins/{hardware,device_identity}/meson.build):
  # test_hardware_device_identity_posix_actions.cpp loads both real plugins by
  # path for the identical reason (Wave 3 PR3.2 gate-1 remediation).
  # netstat_plugin_lib (agents/plugins/netstat/meson.build): test_netstat_attribution.cpp
  # loads the real netstat plugin by path for the identical reason (gate-1 remediation,
  # #3403/#3404 netstat.attribution + hardware WMI bounded-migration test-coverage gap).
  # windows_updates_plugin_lib / sccm_plugin_lib: same reasoning for
  # test_windows_updates_{posix,win}_actions.cpp / test_sccm_win_actions.cpp
  # (Wave 3 PR33d code-review remediation).
  # wifi_plugin_lib (agents/plugins/wifi/meson.build): test_wifi_local_dispatcher.cpp
  # loads the real wifi plugin by path for the same reason (PKG-WIFI).
  # event_logs_plugin_lib: same reasoning for test_event_logs_{posix,win}_actions.cpp
  # (Wave 4 PR4.2 native-acquisition migration remediation).
  # installed_apps_plugin_lib / msi_packages_plugin_lib
  # (agents/plugins/{installed_apps,msi_packages}/meson.build):
  # test_installed_apps_actions.cpp / test_msi_packages_actions.cpp load both
  # real plugins by path for the identical reason (Wave 4 PR4.3a remediation).
  # network_config_plugin_lib (agents/plugins/network_config/meson.build):
  # test_network_config_local_dispatcher.cpp loads the real network_config
  # plugin by path for the identical reason (PKG-NC).
  # content_dist_plugin_lib / script_exec_plugin_lib: same reasoning, for
  # test_content_dist_actions.cpp / test_script_exec_actions.cpp.
  # agent_actions_plugin_lib (agents/plugins/agent_actions/meson.build):
  # test_log_handoff_multi_image.cpp's MI-3 loads the real agent_actions plugin by path
  # for the identical reason (#4666 PR-2 W3a macOS multi-image fixture).
  # echo_argv_fixture: test_content_dist_exec_seam.cpp's real B6 exec-verify
  # test stages and execs this fixture binary by path -- without it in
  # link_depends, a fresh build could leave the test executable built before
  # the fixture exists (build-ci B3's lesson: a fixture with no consumer in
  # the meson graph can silently stop building unnoticed).
  # One identifier per line, alphabetized: this array has been repeatedly
  # corrupted (a stray extra closing bracket followed by more list items,
  # breaking meson configure on every platform) by the automated dev-merge-
  # into-open-PR-branches bot's line-based 3-way merge -- two different PRs
  # each appending one plugin identifier to the same shared wrapped line look
  # like non-conflicting inserts to a line-based merge, but the combined
  # result is invalid. One-per-line makes two independent appends land as
  # two independent inserted lines, which merges cleanly. Do not repack this
  # onto fewer lines -- see the identical, already-safe shape in
  # scripts/ci/check-plugin-spawn-lexical.sh's GRANDFATHERED set.
  link_depends: [
                abi3_fixture_plugin,
                agent_actions_plugin_lib,  # #4666 PR-2 W3a: MI-3 loads the real agent_actions plugin by path
                certificates_plugin_lib,
                content_dist_plugin_lib,
                disk_actions_plugin_lib,
                device_identity_plugin_lib,
                echo_argv_fixture,
                event_logs_plugin_lib,
                filesystem_posture_plugin_lib,
                hardware_plugin_lib,
                installed_apps_plugin_lib,
                invalid_name_fixture_plugin,
                ioc_plugin_lib,
                license_scan_plugin_lib,
                msi_packages_plugin_lib,
                netstat_plugin_lib,
                network_config_plugin_lib,
                network_diag_plugin_lib,
                os_info_plugin_lib,
                processes_plugin_lib,
                reserved_name_fixture_plugin,
                sccm_plugin_lib,
                script_exec_plugin_lib,
                software_actions_plugin_lib,
                users_plugin_lib,
                wifi_plugin_lib,
                power_health_plugin_lib,
                autoruns_plugin_lib,  # Wave 7 PR7.1
                app_usage_plugin_lib,  # Wave 7b PR7b.3
                execution_artifacts_plugin_lib,  # Wave 7b PR7b.1
                windows_optional_features_plugin_lib,  # Wave 9 PR9.2b
                app_control_plugin_lib,  # Wave 8 PR8.6
                platform_security_plugin_lib,  # Wave 8 PR8.1-a1
                peripherals_plugin_lib,  # Wave 9 PR9.1a
                windows_updates_plugin_lib,
                printing_plugin_lib,  # Wave 9 PR9.1b
                firmware_posture_plugin_lib,  # Wave 8 PR8.4
                browser_inventory_plugin_lib,  # Wave 10 P2a
                asset_tags_plugin_lib,  # #232: test_asset_tags_actions.cpp loads the real plugin by path
                system_hardening_plugin_lib,  # Wave 8 PR8.1-b
                runtimes_plugin_lib,  # Wave 10 PR10.1-b
                pkg_inventory_plugin_lib,  # Wave 10 PR10.1-c
                ],
)
# ONE agent test is [tsan-heavy] as of #4153 (down from three): the #3848 concurrency soak
# against a BLOCKING Spark backend/send callback ("...TSan checkpoint, #3848)"). It is
# SQLite-free (FakeBackend + BlockingGate, no KvStore anywhere in it) but genuinely
# contention-dominated in the same way its two former siblings were - a real 60ms backend
# deadline, 30s watchdogs, a releaser pulsing sleep_for(1ms) - ~4-15s under TSan, and the
# reason it stays out of the plain/coverage suite: a PLAIN build has no instrumentation to
# find a race with, so the cost buys no signal there, and its concurrent code paths are
# line-covered by the sequential prune/page/gauge tests plus the cheap [tsan] cases below.
# It keeps its OWN test() with its own budget (below) so a stall here cannot time out the
# fast entry's other cases.
#
# The other two used to live here too - "concurrent pagers + a drainer" and QE-1 "concurrent
# persist + page + prune + drain" - and were genuinely SQLite-bound: four to five threads
# spinning UNTHROTTLED `while(!stop)` loops against a real on-disk KvStore (WAL, a 5s busy
# timeout), with termination depending on the MAIN thread winning lock races against those
# spinning workers. That starved under contention - it ballooned under Big Tam filesystem
# contention (four CI jobs sharing one host's /tmp), where one stalled ~8 minutes and timed
# out the whole agent suite (#2345), and the same mechanism recurred on Wee Tam/Windows under
# ASan (#4018, one run took 1010s, the other never finished in 1200s). #4153 redesigned both
# off SQLite entirely (an in-memory FakeJournalStore, IJournalStore seam) and off the
# stop-flag race (fixed per-thread iteration counts; a portable jthread-alike with fixed
# producer loops, latches, and bounded/stop-token-aware polling waits for the drainer and
# persister, replacing a spin) - termination now depends on fixed iteration counts and
# 30s-bounded main-thread waits, never on the main thread winning a lock race, so they
# moved to [tsan] (below with the other cheap cases) and run in EVERY build, not only
# sanitizer ones.
# #2373 (the split that first isolated [tsan-heavy] into its own budgeted entry, keeping a
# stall here from timing out the fast suite) is superseded for those two tests by #4153's
# redesign above; it remains the reason the sole survivor still gets its own entry. A
# wall-clock cap inside these tests was tried and backed out before either fix (a busy main
# thread starving the workers it waited on) - #4153's fixed iteration counts are a different
# shape, not a revival of that approach.
# ── #2270 allocation-budget probe (separate binary, deliberately) ────────────
# test_spark_alloc_budget.cpp REPLACES the global operator new/delete to count
# allocations, which is process-wide and cannot be scoped to one test. Two
# reasons it is not a source of yuzu_agent_tests:
#   * a sanitizer owns the allocator, so the replacement must be ABSENT from
#     those binaries, not merely disabled inside them;
#   * a global allocator replacement has no business in the agent test
#     binary that gates every push.
# Executable-side interposition for libyuzu_agent_core.so is an ELF/libstdc++
# property (measured on Linux, and it does hold) — not a portable contract, so
# the target is Linux-only and the cross-platform pin stays with the fault seams
# in test_spark_mechanism.cpp. See the file header.
if host_machine.system() == 'linux' and get_option('b_sanitize') == 'none'
  spark_alloc_budget_exe = executable(
    'yuzu_spark_alloc_budget_tests',
    files('unit/test_spark_alloc_budget.cpp'),
    include_directories: [include_directories('../agents/core/src')],
    cpp_args: test_partial_init_args + agent_platform_args,
    dependencies: [yuzu_agent_core_dep, yuzu_sdk_dep, agent_test_proto_dep, catch2_dep,
                   spdlog_dep],
  )
  test(
    'spark allocation budget',
    spark_alloc_budget_exe,
    # BR4-005 sibling (this executable is Linux-only, so the macOS branch
    # review never reached it): a plugin-scoped `--test-args '[tag]'` against
    # the agent suite appends that filter here too, where it never matches —
    # see the cert_store_fallback_test_exe comment above for the full
    # rationale.
    args: ['--allow-running-no-tests'],
    suite: 'agent',
    timeout: 60,
  )
endif

# [tsan-heavy] is ALWAYS excluded from this entry (previously only in a plain build) - see
# the #2373/#4153 split comment above and the dedicated 'agent tsan-heavy checkpoints' entry
# below, which is the only place a sanitizer build runs the sole survivor now.
#
# [flaky-4086] is excluded the same way: a single quarantined case (test_guard_file.cpp,
# "FileGuard rename: the compliant edge cache...") with a measured 9/10 standalone failure
# rate (issue #4086 - guard_win_handle.hpp's cancel_and_close_ doesn't drain a cancelled
# OVERLAPPED read before reuse). Its own [.] tag was NOT reliably observed to keep it out
# of this entry on its own - repeat real-hardware runs against this entry's `~[tsan-heavy]`
# filter gave inconsistent results, so the exact Catch2 hidden-tag rule here is left
# unresolved. The explicit `~[flaky-4086]` exclusion is what's reliably, repeatedly
# verified to work - see the header comment on the TEST_CASE for detail.
agent_test_args = ['~[tsan-heavy]~[flaky-4086]']
test(
  'agent unit tests',
  agent_test_exe,
  args: agent_test_args,
  suite: 'agent',
  timeout: 240, # restored after moving [tsan-heavy] tests to sanitizer-only (#2345): plain suite is ~28-60s, so 240s is generous headroom and surfaces a genuine hang rather than absorbing it into a loose ceiling. #4153 moved two of the three former [tsan-heavy] cases INTO this entry (retagged [tsan]) - still comfortably inside this budget (measured).
  depends: [reserved_name_fixture_plugin, invalid_name_fixture_plugin, abi3_fixture_plugin],
)

if get_option('b_sanitize') != 'none'
  # #2373's split (below) still applies to the ONE remaining [tsan-heavy] case (#3848, a
  # BLOCKING-backend soak, SQLite-free but genuinely contention-dominated: a real 60ms backend
  # deadline, 30s watchdogs, a releaser pulsing sleep_for(1ms), ~4-15s under TSan uncontended).
  # CORRECTION (#4153 round 3, governance-caught): #2345's ~8-minute Big Tam stall and #4018's
  # Wee Tam/Windows ASan recurrence were NEVER #3848 - #3848 wasn't added until 2026-09-04, six
  # weeks after #2345 merged, so it cannot have caused an incident that predates it. Both
  # incidents belonged to the two SQLite-bound [tsan-heavy] cases this entry ALSO held before
  # #4153 (below). This entry's own budget means a stall here times out AT ITS OWN BUDGET,
  # classifiably, instead of either being absorbed into the fast suite's tight 240s
  # ceiling (windows-asan's prior state, #4018) or dragging the whole fast suite down with it.
  # #4153 redesigned the OTHER two former [tsan-heavy] cases off real on-disk SQLite entirely
  # (an in-memory FakeJournalStore) and off the unbounded stop-flag race that caused #2345/
  # #4018's stalls - they moved to [tsan] and now run in the fast entry above, in every build.
  # 600s here was ORIGINALLY sized off the measured ~480s (8-minute) stall when this entry held
  # all three cases; #4153 removed the two tests that stall belonged to, so #3848 alone now
  # runs against this budget with generous headroom (measured ~3s uncontended, within the ~4-15s
  # range above once real contention is added, both well under 600s) -
  # left unchanged rather than tightened, since a single-test entry has no other case to protect
  # from a stall's blast radius, and #3848's own 30s watchdogs already bound its own worst case.
  # Not the plain suite's ~28-60s fast-entry baseline above; nightly's own --timeout-multiplier 2
  # (Linux legs) / the windows-asan job's now-added multiplier scale 600s to 1200s under
  # sanitizer instrumentation plus contention. Do NOT replace this with a wall-clock cap inside
  # the tests themselves -
  # that was tried and backed out (comment above): a busy main thread starves the worker
  # threads whose progress it is waiting on. #4153's fixed-iteration-count redesign of the two
  # moved-out tests is a DIFFERENT shape, not a revival of that approach - see their own
  # comments in test_guardian_spark_runtime.cpp.
  #
  # is_parallel: false on Windows ONLY (governance Gate 4/6, #4018 hardening round):
  # neither this entry nor 'agent unit tests' caps --num-processes, so meson's own
  # scheduler is free to run both as concurrent OS processes sharing suite: 'agent' -
  # exactly the shared-disk/Defender-minifilter contention docs/ci-architecture.md's
  # "Windows test-phase concurrency gate" measures as real ACROSS jobs, now possible
  # WITHIN one job between these two sibling entries. A barrier is nearly free on
  # windows-asan (its only sibling under --suite agent is the ~28s-baseline fast
  # entry) but must NOT apply on Linux's unfiltered `meson test` (sanitize-asan/tsan):
  # forcing a full drain-then-run-alone there adds real critical-path time to legs
  # already sized close to their timeout-minutes budget.
  tsan_heavy_checkpoints_is_parallel = host_machine.system() != 'windows'
  test(
    'agent tsan-heavy checkpoints',
    agent_test_exe,
    args: ['[tsan-heavy]'],
    suite: 'agent',
    timeout: 600,
    is_parallel: tsan_heavy_checkpoints_is_parallel,
    depends: [reserved_name_fixture_plugin, invalid_name_fixture_plugin, abi3_fixture_plugin],
  )
endif

# ── cert_store macOS honest-unsupported unit test (A-1.20 / P8; BR-001/BR-003
#    branch-review fix) ────────────────────────────────────────────────────
# cert_store.cpp's __APPLE__ branch unconditionally returns an honest
# "unsupported" CertStoreResult (the macOS agent runs as a root LaunchDaemon
# with no user login keychain — see the file header comment on
# read_cert_from_store() there). This dedicated executable recompiles that
# SAME cert_store.cpp source standalone — no Security/CoreFoundation
# frameworks, not linked against the rest of yuzu_agent_core — purely to
# check the contract in isolation. macOS only: on Linux/Windows
# cert_store.cpp's OTHER branches are the real (non-stub) implementations,
# which this target is not meant to probe.
if host_machine.system() == 'darwin'
  cert_store_fallback_test_exe = executable(
    'yuzu_cert_store_fallback_tests',
    files(
      'unit/agent/test_cert_store_fallback.cpp',
      '../agents/core/src/cert_store.cpp',
    ),
    include_directories: [
      include_directories('../agents/core/include'),  # yuzu/agent/cert_store.hpp
    ],
    # spdlog_dep only for the header include path (cert_store.cpp's
    # unconditional #include <spdlog/spdlog.h>); the macOS stub never
    # actually calls into it.
    dependencies: [yuzu_sdk_dep, spdlog_dep, catch2_dep],
  )
  # BR4-005 (branch-review round 4): `meson test --suite agent --test-args
  # '[some-tag]'` appends that tag filter to EVERY test in the agent suite,
  # including this standalone executable — which has no tag matching a
  # plugin-specific filter like `[autoruns]`/`[app_usage]`. Catch2 exits 2 on
  # a zero-match tag filter by default, so a plugin-scoped `--test-args`
  # invocation (documented practice for a fast, targeted local check)
  # deterministically fails this ENTIRELY UNRELATED test. --allow-running-no-tests
  # makes a zero-match filter here report success (0 run) instead, matching
  # what the caller actually meant: "run autoruns's tests", not "fail
  # anything that isn't autoruns's tests".
  test('cert_store macOS honest-unsupported', cert_store_fallback_test_exe,
       args: ['--allow-running-no-tests'], suite: 'agent', timeout: 30)
endif

# ── TAR plugin unit tests ────────────────────────────────────────────────────
tar_test_deps = [yuzu_agent_core_dep, yuzu_sdk_dep, nlohmann_dep, spdlog_dep, sqlite3_dep, catch2_dep]
tar_test_cpp_args = []
tar_test_objcpp_args = []
if host_machine.system() == 'windows'
  # tar_perf.cpp (compiled directly into this exe) → GetIfTable2 / FreeMibTable
  tar_test_deps += cxx.find_library('iphlpapi')
  tar_test_deps += cxx.find_library('tdh') # tar_proc_etw.cpp / tar_module_etw.cpp ETW decode
  tar_test_deps += cxx.find_library('wintrust') # tar_module_etw.cpp WinVerifyTrust
  tar_test_deps += cxx.find_library('crypt32')  # tar_module_etw.cpp CryptQueryObject
  tar_test_deps += cxx.find_library('version')  # tar_proc_perf.cpp GetFileVersionInfoW
  tar_test_deps += cxx.find_library('wevtapi')  # tar_netconn_win.cpp EvtQuery/EvtRender
  tar_test_deps += cxx.find_library('ws2_32')   # winsock2 symbols the iphlpapi/netioapi headers in tar_netqual_boot.cpp pull in
  tar_test_deps += cxx.find_library('mpr')      # tar_mapdrive_collector.cpp WNet outbound
  tar_test_deps += cxx.find_library('netapi32') # tar_mapdrive_collector.cpp NetSessionEnum inbound
  tar_test_deps += cxx.find_library('powrprof') # tar_power_collector.cpp PowerRegisterSuspendResumeNotification
elif host_machine.system() == 'linux'
  # tar_power_collector.cpp is compiled DIRECTLY into this exe, and its Linux
  # sleep/wake leg is compile-gated on YUZU_HAVE_LIBSYSTEMD. That define was
  # added to the plugin's args only, so the whole sd-bus leg -- and the two test
  # cases that exercise it -- compiled OUT of this binary on Linux, where the
  # #else branch SUCCEEDs with a "skipped" message. The suite stayed green while
  # testing nothing, on the one platform that is this leg's enforcement point.
  # Mirror the plugin's block (agents/plugins/tar/meson.build) so the tests
  # compile in wherever the plugin's leg does.
  libsystemd_test_dep = dependency('libsystemd', required: get_option('systemd_guard'),
                                   include_type: 'system')
  if libsystemd_test_dep.found()
    tar_test_deps += libsystemd_test_dep
    tar_test_cpp_args += '-DYUZU_HAVE_LIBSYSTEMD'
  endif
elif host_machine.system() == 'darwin'
  # tar_proc_es.cpp (compiled directly into this exe) → Endpoint Security client +
  # audit-token helpers, gated on the ES SDK being present (lib+header pair,
  # present in both the Command Line Tools SDK and the full Xcode SDK --
  # "needs full Xcode" is a myth, see docs/darwin-compat.md's ES row).
  # The live client never starts in CI (unentitled) so the pure-mapping + clean-
  # fallback tests run regardless. Threads the SHARED top-level probe
  # (meson.build's endpoint_security_dep/_deps/_args) through -- governance
  # A0 fix round: a second, independent ES probe here duplicated the single
  # top-level one this exe otherwise shares with agent-core and TAR.
  tar_test_deps += endpoint_security_deps
  tar_test_cpp_args += endpoint_security_args
  # Wave 6 PR6.3: test_tar_removable.cpp calls make_removable_cursor_source(), so
  # this exe compiles the removable collector — which on darwin needs its
  # DiskArbitration Objective-C++ TU and framework, exactly as the plugin does.
  tar_test_deps += dependency('appleframeworks', modules: ['DiskArbitration', 'Foundation'],
                              include_type: 'system')
  tar_test_objcpp_args += apple_objcpp_args
endif

tar_test_removable_darwin_sources = []
if host_machine.system() == 'darwin'
  tar_test_removable_darwin_sources = files('../agents/plugins/tar/src/tar_removable_diskarb.mm')
endif

tar_test_exe = executable(
  'yuzu_tar_tests',
  files(
    'unit/test_tar_diff.cpp',
    'unit/test_tar_netconn.cpp',
    'unit/test_tar_software.cpp',
    'unit/test_tar_store.cpp',
    'unit/test_tar_schema_registry.cpp',
    'unit/test_tar_capability_table.cpp',
    'unit/test_tar_warehouse.cpp',
    'unit/test_tar_aggregator.cpp',
    'unit/test_tar_usage.cpp',
    'unit/test_tar_perf.cpp',
    'unit/test_tar_proc_perf.cpp',
    'unit/test_app_perf_rollup_query.cpp',
    'unit/test_tar_proc_etw.cpp',
    'unit/test_tar_proc_es.cpp',
    'unit/test_tar_netqual_nstat.cpp',
    'unit/test_tar_module_stream.cpp',
    'unit/test_tar_module_etw.cpp',
    'unit/test_tar_mapdrive.cpp',
    'unit/test_tar_service.cpp',   # Wave 5 PR5.2: pure systemctl/launchctl list parsers (fixture-fed, no spawn)
    'unit/test_tar_arp.cpp',       # Wave 5 PR5.2: pure /proc/net/arp parser + macOS record mapping (fixture-fed)
    'unit/test_tar_capture_status.cpp', # BR-001 remediation: pure subprocess-capture completeness predicate
    'unit/test_tar_win_raii_guards.cpp', # Gate 3 remediation: injectable-closer RAII guard coverage (Windows-only body, empty TU elsewhere)
    'unit/test_tar_cursor.cpp',                  # Wave 6: cursor-source seam — lifecycle + persistence, atomic event+cursor commit, record_key dedupe, ack-by-sequence incl. the R-005 overflow regression (on-disk TarDb via unique_temp_path)
    'unit/test_tar_power.cpp',                   # Wave 6 PR6.2-b: pmset parser + exact-tail cursor/gap decisions, REAL-CAPTURE fixtures, RunFn-injected
    'unit/test_tar_removable.cpp',               # Wave 6 PR6.3: event-log channel parsers + identity + per-channel cursors, REAL-CAPTURE fixtures
    'unit/test_fleet_snapshot.cpp',
    '../agents/plugins/tar/src/tar_db.cpp',
    # Wave 6: the cursor seam's factory AND lookback_seconds_or_forward_only,
    # the fail-closed reader for the lookback privacy control (tar_cursor.hpp
    # rule 5). Linking it also means the suite exercises the real factory
    # rather than a test-local stand-in.
    '../agents/plugins/tar/src/tar_cursor_sources.cpp',
    '../agents/plugins/tar/src/tar_sql_executor.cpp',
    '../agents/plugins/tar/src/tar_diff.cpp',
    '../agents/plugins/tar/src/tar_software_core.cpp',
    '../agents/plugins/tar/src/tar_schema_registry.cpp',
    '../agents/plugins/tar/src/tar_aggregator.cpp',
    '../agents/plugins/tar/src/tar_usage.cpp',
    '../agents/plugins/tar/src/tar_perf.cpp',
    '../agents/plugins/tar/src/tar_proc_perf.cpp',
    '../agents/plugins/tar/src/tar_proc_stream.cpp',
    '../agents/plugins/tar/src/tar_module_stream.cpp',
    '../agents/plugins/tar/src/tar_proc_etw.cpp',
    '../agents/plugins/tar/src/tar_proc_es.cpp',
    '../agents/plugins/tar/src/tar_module_etw.cpp',
    '../agents/plugins/tar/src/tar_netqual_boot.cpp',
    '../agents/plugins/tar/src/tar_netqual_nstat.cpp',
    '../agents/plugins/tar/src/tar_netconn_win.cpp',
    '../agents/plugins/tar/src/tar_mapdrive_collector.cpp',
    '../agents/plugins/tar/src/tar_arp_collector.cpp',     # Wave 5 PR5.2 Finding 4: real enumerate_arp() macOS smoke test
    '../agents/plugins/tar/src/tar_service_collector.cpp', # Wave 5 PR5.2 Finding 3: real enumerate_services() argv-assertion tests
    '../agents/plugins/tar/src/tar_fleet_snapshot.cpp',
    # Wave 6 PR6.2-b: test_tar_power.cpp drives mac_power_collect_impl with an
    # injected runner, so the real collector links into this exe.
    '../agents/plugins/tar/src/tar_power_collector.cpp',
    # Wave 6 PR6.3: the TU exercises the real CursorSource via the factory.
    '../agents/plugins/tar/src/tar_removable_collector.cpp',
  ) + tar_test_removable_darwin_sources,
  include_directories: [
    include_directories('../agents/plugins/tar/src'),
    include_directories('../agents/shared'),  # win_str.hpp — tar_module_etw.cpp is compiled into this test exe (#1681, relocated plugins/shared -> agents/shared)
    include_directories('../agents/core/src'),        # sync_source_app_perf.hpp — app_perf rollup-query integration test
  ],
  cpp_args: tar_test_cpp_args,
  objcpp_args: tar_test_objcpp_args,
  dependencies: tar_test_deps,
)
test('tar unit tests', tar_test_exe, suite: 'tar', timeout: 90)

# ── Server unit tests ─────────────────────────────────────────────────────────
if build_server
  server_test_exe = executable(
    'yuzu_server_tests',
    files(
      # Custom Catch2 entry point (#1648/#3507 diagnostic + Windows-only
      # hard_exit) — logs Session::run()'s real return value; see
      # unit/test_runner_main.cpp and catch2_nomain_dep above.
      'unit/test_runner_main.cpp',
      'unit/server/test_auth.cpp',
      'unit/server/test_auth_routes.cpp',
      'unit/server/test_auth_list_read_gate.cpp',
      'unit/server/test_auth_routes_mfa.cpp',
      'unit/server/test_auth_jit_elevation.cpp',
      'unit/server/test_auth_sso_identity.cpp',
      'unit/server/test_auth_routes_hardened.cpp',
      'unit/server/test_sso_boot_guard.cpp',
      'unit/server/test_settings_routes_mfa.cpp',
      'unit/server/test_totp.cpp',
      'unit/server/test_mfa_step_up.cpp',
      'unit/server/test_mfa_qr.cpp',
      'unit/server/test_mfa_store.cpp',
      'unit/server/test_auth_lockout.cpp',
      'unit/server/test_auth_break_glass.cpp',
      'unit/server/test_auth_db_pg.cpp',
      'unit/server/test_auto_approve.cpp',
      'unit/server/test_cidr_match.cpp',
      'unit/server/test_runtime_config_secret_redaction.cpp',
      'unit/server/test_runtime_config_store.cpp',
      'unit/server/test_nvd.cpp',
      'unit/server/test_cpe_identity_resolver.cpp',
      'unit/server/test_ota_signature_sidecar.cpp', # server half of OTA signature delivery (#416/#3807)
      'unit/server/test_update_registry.cpp',
      'unit/server/test_legacy_sqlite_probe.cpp',
      'unit/server/test_https_config.cpp',
      'unit/server/test_response_store.cpp',
      'unit/server/test_response_routes.cpp', # #2542 PR-11: the 3-route legacy pre-v1 Responses API, extracted onto the HttpRouteSink seam
      'unit/server/test_preflight_parse.cpp',
      'unit/server/test_preflight_eval.cpp',
      'unit/server/test_preflight_run_store.cpp',
      'unit/server/test_preflight_runner.cpp',
      'unit/server/test_preflight_routes.cpp',
      'unit/server/test_deployment_parse.cpp',
      'unit/server/test_deployment_run_store.cpp',
      'unit/server/test_deployment_engine.cpp',
      'unit/server/test_deployment_routes.cpp',
      'unit/server/test_bundle_service.cpp',
      'unit/server/test_bundle_orchestrator.cpp',
      'unit/server/test_rest_bundle.cpp',
      'unit/server/test_audit_store.cpp',
      'unit/server/test_background_jobs.cpp',
      'unit/server/test_pg_retention_guard.cpp',
      'unit/server/test_audit_retention_rules.cpp',
      'unit/server/test_log_token.cpp',
      'unit/server/test_sqlite_raii.cpp',
      'unit/server/test_rest_audit_sample.cpp',
      'unit/server/test_rest_audit_helper.cpp',
      'unit/server/test_rest_scope_v1_routes.cpp', # #2146 Batch B2: POST /api/v1/scope/validate + /preview
      'unit/server/test_tag_store.cpp',
      'unit/server/test_tag_routes.cpp', # #2542 PR-11: the 4-route Tags API, extracted onto the HttpRouteSink seam
      'unit/server/test_scope_engine.cpp',
      'unit/server/test_web_utils.cpp',
      'unit/server/test_mcp_body_cap.cpp',
      'unit/server/test_dispatch_target_shape.cpp',
      'unit/server/test_sensitive_instruction_params.cpp',
      'unit/server/test_workflow_routes.cpp',
      'unit/server/test_compliance_routes.cpp',
      'unit/server/test_policy_admin_routes.cpp', # ADR-0031 WS-A4 Task B: policy/fragment mutator routes
      'unit/server/test_compliance_model.cpp',
      'unit/server/test_verify_routes.cpp',
      'unit/server/test_notification_routes.cpp',
      'unit/server/test_command_routes.cpp',
      'unit/server/test_page_routes.cpp',
      'unit/server/test_dashboard_api_routes.cpp',
      'unit/server/test_nvd_routes.cpp',
      'unit/server/test_result_set_routes.cpp',
      'unit/server/test_approval_routes.cpp', # #2542 PR-9: the 4-route Approval API, extracted onto the HttpRouteSink seam
      'unit/server/test_config_routes.cpp', # #2542 PR-12: the 2-route Runtime Configuration API (7.3), extracted onto the HttpRouteSink seam
      'unit/server/test_legacy_diagnostic_routes.cpp', # #2542 PR-12: the 5-route Chargen + Procfetch diagnostic API (diagnostics_routes.cpp), extracted onto the HttpRouteSink seam -- named away from test_diagnostics_*/test_chargen_*/test_procfetch_* to avoid a plugin_doc_gen.py filename collision with the agent plugins of those names
      'unit/server/test_legacy_events_routes.cpp', # #2542 PR-12: the legacy GET /events SSE stream, extracted onto the HttpRouteSink seam
      'unit/server/test_instruction_fragment_routes.cpp', # #2542 PR-12: the 2-route Instructions HTMX fragment pair, extracted onto the HttpRouteSink seam
      'unit/server/test_approvals_fragment_routes.cpp', # #2542 PR-12: the Approvals HTMX fragment, extracted onto the HttpRouteSink seam
      'unit/server/test_mcp_disabled_routes.cpp', # #2542 PR-12: the 3-route MCP-disabled stub triple, extracted onto the HttpRouteSink seam
      'unit/server/test_agent_service_impl.cpp',
      'unit/server/test_analytics_event.cpp',
      'unit/server/test_agent_health_store.cpp',
      'unit/server/test_instruction_store.cpp',
      'unit/server/test_instruction_store_signing.cpp',
      'unit/server/test_instruction_yaml.cpp',
      'unit/server/test_instruction_routes.cpp', # #2542 PR-7: the 13-route Instruction Definitions + Instruction Sets API, extracted onto the HttpRouteSink seam
      'unit/server/test_execution_tracker.cpp',
      'unit/server/test_execution_routes.cpp', # #2542 PR-7: the 7-route legacy pre-v1 Executions API, extracted onto the HttpRouteSink seam
      'unit/server/test_health_routes.cpp', # #2542 PR-10: the 6-route Health/Infra cluster, extracted onto the HttpRouteSink seam
      'unit/server/test_leader_elector.cpp',
      'unit/server/test_leader_gate.cpp',
      'unit/server/test_coord_dsn.cpp',
      'unit/server/test_pg_reachability_probe.cpp', # HA WS-8: /readyz pg_reachable rule + probe
      'unit/server/test_multi_host_dsn.cpp', # HA WS-8: multi-host DSN target_session_attrs guard
      'unit/server/test_command_outbox_store.cpp', # WS-3 3.3: transactional command outbox
      'unit/server/test_command_outbox_delivery.cpp', # WS-3 3.3: leader-gated delivery loop
      'unit/server/test_gateway_route_store.cpp', # HA WS-4 4.1: fenced agent->cluster routing directory
      'unit/server/test_gateway_route_reap_rules.cpp', # HA WS-4 4.2a: PURE decide_reap decision set (PR #4299 round-3 decide/apply split)
      'unit/server/test_gateway_route_wiring.cpp', # HA WS-4 4.1: GatewayUpstreamServiceImpl wiring onto GatewayRouteStore (re-announce-vs-fresh, connect/disconnect/heartbeat, fail-open)
      'unit/server/test_gateway_mgmt_stub_pool.cpp', # HA WS-4 4.3: parse_gateway_cluster_addrs + GatewayMgmtStubPool resolution (cross-cluster fan-out)

      'unit/server/test_execution_event_bus.cpp',
      'unit/server/test_approval_manager.cpp',
      'unit/server/test_schedule_engine.cpp',
      'unit/server/test_schedule_routes.cpp',
      'unit/server/test_schedule_runner.cpp',
      'unit/server/test_rbac_store.cpp',
      'unit/server/test_list_read_confinement.cpp',
      'unit/server/test_response_execution_scope_authz.cpp', # #1634: response/execution fleet-read confinement
      'unit/server/test_legacy_executions_scope_authz.cpp', # #3789: legacy /api/executions* fleet-read confinement
      'unit/server/test_oidc_principal_key.cpp',
      'unit/server/test_oidc_principal.cpp',
      'unit/server/test_oidc_provider.cpp',
      'unit/server/test_oidc_scim_link.cpp',
      'unit/server/test_oidc_routes.cpp',
      'unit/server/test_saml_principal.cpp',
      'unit/server/test_saml_provider.cpp',
      'unit/server/test_saml_routes.cpp',
      'unit/server/test_saml_scim_link.cpp',
      'unit/server/test_error_codes.cpp',
      'unit/server/test_result_envelope.cpp',
      'unit/server/test_legacy_shim.cpp',
      'unit/server/test_management_group_store.cpp',
      'unit/server/test_dashboard_tar_retention.cpp',
      'unit/server/test_dashboard_tar_fragments.cpp',
      'unit/server/test_dashboard_group_from_results.cpp',
      'unit/server/test_dashboard_results_columns.cpp', # PR1.7 remediation: resolve_render_columns/render_results
      'unit/server/test_dashboard_results_fragment.cpp', # #1712 / #3290 Phase 2: /fragments/results fleet-read gate
      'unit/server/test_route_sink_harness.cpp',
      'unit/server/test_rest_tar_purge.cpp',
      'unit/server/test_api_token_store.cpp',
      'unit/server/test_rotation_sweep_naming.cpp', # P2 #11: sweep-driver metric/audit family discrimination by principal_kind
      'unit/server/test_rotation_warn_dedup.cpp', # P2 #11: successor-unused log/count/audit cadence (audit is once per state, never per tick)
      'unit/server/test_engine_principal_store.cpp',
      'unit/server/test_engine_principal_integration.cpp',
      # #2367: test-only definition of EngineLivenessTestAccess::revalidate,
      # kept OFF the production link line so the private cached path has no
      # public trampoline in server_core.
      'unit/server/engine_liveness_test_access.cpp',
      # PR1.9c: same #2367 pattern for ClassifiedCommandTestAccess::make — the
      # ONLY definition, deliberately off the production link line so a
      # production caller that tries to forge a ClassifiedCommand (bypassing
      # classification and authorization) fails to LINK rather than compiling.
      'unit/server/classified_command_test_access.cpp',
      'unit/server/test_rest_engine_principal_roles.cpp',
      'unit/server/test_mcp_engine_principal_roles.cpp',
      'unit/server/test_engine_principal_lifecycle.cpp',
      'unit/server/test_engine_store_error_class.cpp',
      'unit/server/test_rotation_confirm_state.cpp',
      'unit/server/test_access_review_model.cpp',
      'unit/server/test_access_review_store.cpp',
      'unit/server/test_session_store.cpp',
      'unit/server/test_session_dbclock.cpp',
      'unit/server/test_auth_session_store.cpp',
      'unit/server/test_clock_drift_monitor.cpp',
      'unit/server/test_dispatch_chokepoint.cpp',
      'unit/server/test_capability_catalogue.cpp',
      'unit/server/test_operator_surface_twins.cpp',
      'unit/server/test_schedule_params.cpp',
      'unit/server/test_plugin_config_parsers.cpp',
      'unit/server/test_plugin_config_store_pg.cpp',
      'unit/server/test_plugin_config_routes.cpp',
      'unit/server/test_upload_grant_parsers.cpp',
      'unit/server/test_upload_grant_store_pg.cpp',
      'unit/server/test_file_retrieval_routes.cpp',
      'unit/server/test_command_capability.cpp',
      'unit/server/test_dex_obs_table.cpp',
      'unit/server/test_rest_access_review.cpp',
      'unit/server/test_secure_random.cpp',
      'unit/server/test_quarantine_store.cpp',
      'unit/server/test_quarantine_dispatch_decision.cpp', # #3127: pure write/response classification — no Postgres, no MCP transport, no agent
      'unit/server/test_quarantine_dispatch_gate.cpp',     # #881: containment gate at the dispatch chokepoint — pure arm/degradation logic, no store
      'unit/server/test_plugin_presence_dispatch_gate.cpp', # #3424/#3511: plugin-presence filter at the dispatch chokepoint — mirrors test_quarantine_dispatch_gate.cpp
      'unit/server/test_quarantine_reapply.cpp',           # #3425: shared stored-containment re-dispatch recipe (Layer A) — pure, no store
      'unit/server/test_quarantine_containment_reconciler.cpp', # #3425: reconnect re-application state machine — real store/registry, mock dispatch
      'unit/server/test_result_set_store.cpp',
      'unit/server/test_result_set_matcher.cpp',
      'unit/server/test_rest_result_sets_async.cpp',
      'unit/server/test_chrome_ir_chain.cpp',
      'unit/server/test_result_sets_ui.cpp',
      'unit/server/test_scope_walking_authz.cpp',
      'unit/server/test_scope_yaml.cpp',
      'unit/server/test_yaml_scan.cpp',
      'unit/server/test_policy_store.cpp',
      'unit/server/test_policy_evaluator.cpp',
      'unit/server/test_guaranteed_state_store.cpp',
      'unit/server/test_guardian_ingest.cpp',
      'unit/server/test_baseline_store.cpp',
      'unit/server/test_guardian_push_builder.cpp',
      'unit/server/test_guardian_resilience_schema.cpp',
      'unit/server/test_guardian_routes.cpp',
      'unit/server/test_dex_routes.cpp',
      'unit/server/test_device_ui.cpp',
      'unit/server/test_device_routes.cpp',
      'unit/server/test_device_lens_routes.cpp', # ADR-0031 WS-A4 wave 2: DEX/Guardian device lenses (no public twin — outside the seam)
      'unit/server/test_hardware_list_model.cpp', # round-3: Hardware CI list/record pure model
      'unit/server/test_hardware_ui.cpp',         # round-3: Hardware CI list/record HTML fragment
      'unit/server/test_hardware_routes.cpp',     # round-3: Hardware CI list/record routes + REST twin
      'unit/server/test_inventory_routes.cpp',
      'unit/server/test_inventory_store.cpp',
      'unit/server/test_data_inventory_routes.cpp', # #2542 PR-11: the 3-route generic plugin-data Inventory API, extracted onto the HttpRouteSink seam
      'unit/server/test_sle_routes.cpp',
      'unit/server/test_inventory_ci_join.cpp',
      'unit/server/test_software_catalog_rollup.cpp',
      'unit/server/test_tar_process_tree.cpp',
      'unit/server/test_tar_tree_routes.cpp',
      'unit/server/test_dex_perf_model.cpp',
      'unit/server/test_dex_app_perf_model.cpp',
      'unit/server/test_app_perf_compare.cpp',
      'unit/server/test_dex_app_perf_ui.cpp',
      'unit/server/test_network_perf_model.cpp',
      'unit/server/test_network_api.cpp', # ADR-0031 WS-A4: the first per-family in-process API seam pilot
      'unit/server/test_verify_api.cpp', # ADR-0031 WS-A4: the second per-family in-process API seam
      'unit/server/test_compliance_api.cpp', # ADR-0031 WS-A4: the third per-family in-process API seam
      'unit/server/test_device_api.cpp', # ADR-0031 WS-A4: the fourth per-family in-process API seam
      'unit/server/test_dex_api.cpp', # ADR-0031 WS-A4: the fifth per-family in-process API seam (DEX signals)
      'unit/server/test_dex_perf_api.cpp', # ADR-0031 WS-A4: the sixth per-family in-process API seam (DEX app-perf-over-time)
      'unit/server/test_schedule_api.cpp', # ADR-0031 WS-A4: the seventh per-family in-process API seam (schedule read)
      'unit/server/test_workflow_api.cpp', # ADR-0031 WS-A4: the eighth per-family in-process API seam (workflow read)
      'unit/server/test_guardian_api.cpp', # ADR-0031 WS-A4: the ninth per-family in-process API seam (Guardian read)
      'unit/server/test_spark_fleet_tags.cpp',
      'unit/server/test_guardian_journal_fleet_tags.cpp',
      'unit/server/test_guardian_arm_fleet_tags.cpp', # rung 9c PR-3 — arm-ledger + io-ceiling fleet rollup pin
      'unit/server/test_guardian_health_fleet_tags.cpp', # #2298 gate 3 item 6d — M1 health-stream fleet rollup pin
      'unit/server/test_dex_alert_router.cpp',
      'unit/server/test_dex_blast_radius.cpp',
      'unit/server/test_guardian_form_render.cpp',
      'unit/server/test_heartbeat_ingestion.cpp',
      'unit/server/test_compliance_eval.cpp',
      'unit/server/test_cel_eval.cpp',
      'unit/server/test_custom_properties_store.cpp',
      'unit/server/test_custom_properties_routes.cpp', # #2542 PR-4: the 5-route Custom Properties API (7.6), extracted onto the HttpRouteSink seam
      'unit/server/test_props_scope_authz.cpp',
      'unit/server/test_tag_scope_authz.cpp',
      'unit/server/test_notification_store.cpp',
      'unit/server/test_webhook_store.cpp',
      'unit/server/test_webhook_routes.cpp',
      'unit/server/test_migration_runner.cpp',
      'unit/server/test_rate_limiter.cpp',
      'unit/server/test_cert_reloader.cpp',
      'unit/server/test_x509_ca.cpp',
      'unit/server/test_ca_store.cpp',
      'unit/server/test_ca_routes.cpp',
      'unit/server/test_kek_routes.cpp', # #2395 track D — KEK rotation REST surface
      'unit/server/test_kek_op_lock_holder.cpp', # #2530 B6 — advisory-lock holder query
      'unit/server/test_pg_session_advisory_lock.cpp', # #2964 round 3 — PgAdvisoryLockKey + aborted-txn unlock recovery
      'unit/server/test_kek_rotate_control.cpp', # #2530 B3/B4 — rotate control-flow ordering + half-commit classification
      'unit/server/test_secret_column_registration_tripwire.cpp', # #2530 C3 — registered-column trip-wire
      'unit/server/test_key_provider.cpp',
      'unit/server/test_rest_mgmt_group_roles_floor.cpp', # #2376: the mgmt-group role graph needs the floored UserManagement:Read
      'unit/server/test_rest_management_group_detail_degrade.cpp', # #1762 governance round-1: GET /management-groups/{id} fails closed on a degraded member read
      'unit/server/test_authz_model.cpp', # PR1.4: registry-independent authz model + #1788 per-device visibility (all four arms)
      'unit/server/test_authz_gates.cpp', # service-scope-confinement PR2: require_fleet_read / confine_agent_target
      'unit/server/test_agent_properties_scope_authz.cpp', # #3700: require_scoped_permission on /api/agents/:id/properties
      'unit/server/test_authz_topology_floor.cpp', # #2376: the RBAC-off legacy-fallback topology floor (AccessReview/UserManagement/EnginePrincipal Read)
      'unit/server/test_body_cap_policy.cpp', # #2407: pre-auth request-body cap policy table (method+segment-boundary path -> cap/requires_measurable/metric label)
      'unit/server/test_body_cap_route_inventory.cpp', # #2407: architect-mandated route-inventory coverage — every ACTUALLY REGISTERED POST/PUT/PATCH route resolves to a deliberate class, mechanically scanned from server/core/src at test run time
      'unit/server/test_store_wiring_order.cpp', # #3261: every agent_service_/gateway_service_ store setter runs after its member's construction, mechanically scanned from server.cpp at test run time
      'unit/server/test_shutdown_join_order.cpp', # #3495: agent_server_->Shutdown(deadline) runs before the policy-eval/pre-flight/quarantine/schedule joins + the heartbeat fn-null wait, mechanically scanned from server.cpp at test run time
      'unit/server/test_store_worker_pool.cpp', # #3261: StoreWorkerPool submit/quiesce/backpressure/exception-firewall, no HTTP (avoids the unrelated TSan/glibc crash #2504)
      'unit/server/test_dispatch_confined_arms.cpp', # PR1.4: the production per-arm intersection, bound by exact-send-set assertions
      'unit/server/test_dispatch_destructive_gate.cpp', # #3685: Destructive targeting gate — pure verdict + confinement + refusal-string pins
      'unit/server/test_printing_clear_queue_gate.cpp', # Wave 9 PR9.1b: printing.clear_queue against the same Destructive targeting gate + AdminOrApproval chokepoint
      'unit/server/test_dashboard_destructive_gate.cpp', # PR6.0b: the same gate wired into POST /api/dashboard/execute
      'unit/server/test_default_certs.cpp',
      'unit/server/test_mcp_route_registration.cpp', # #2542 PR-6: McpServer register_routes(HttpRouteSink&, ...) seam — registration shape + kill-switch-before-auth ordering + server.cpp wiring tripwire
      'unit/server/test_mcp_server.cpp',
      'unit/server/test_mcp_session.cpp',
      'unit/server/test_mcp_stream.cpp',
      'unit/server/test_mcp_stream_bridge.cpp',
      'unit/server/test_sse_saturation.cpp',
      'unit/server/test_mcp_transport.cpp',
      'unit/server/test_process_health.cpp',
      'unit/server/test_patch_manager.cpp',
      'unit/server/test_workflow_engine.cpp',
      'unit/server/test_inventory_eval.cpp',
      'unit/server/test_execution_statistics.cpp',
      'unit/server/test_device_token_store.cpp',
      'unit/server/test_device_token_rejection.cpp',
      'unit/server/test_agent_registry_token_revocation.cpp',
      'unit/server/test_software_deployment_store.cpp',
      'unit/server/test_license_store.cpp',
      'unit/server/test_rest_api_t2.cpp',
      'unit/server/test_rest_api_tokens.cpp',
      'unit/server/test_rest_api_tokens_rotation.cpp',   # P2 #11: human token-keyed rotate/confirm REST surface
      'unit/server/test_token_rotation_lookup.cpp',   # P2 #11: derive_rotation_successor, DB-free unit coverage
      'unit/server/test_rest_tag_routes.cpp',   # K-05: REST tag-route authz wiring (CDX-03/CDX-R4-02/B4)
      'unit/server/test_rest_quarantine_routes.cpp',   # CDX-P1-02: REST quarantine-route authz wiring
      'unit/server/test_rest_api_events.cpp',
      'unit/server/test_openapi_spec_completeness.cpp',   # #3991 F1: ADR-0031 INV-31-4 / #842 unit-test half
      'unit/server/test_rest_software_packages.cpp',
      'unit/server/test_rest_inventory_software.cpp',
      'unit/server/test_rest_dex_app_perf_devices.cpp',   # version-row "which devices" drill: GET /api/v1/dex/perf/app/devices
      'unit/server/test_rest_devices.cpp',   # #4033 (#2146 Batch A): GET /api/v1/devices[/{id}] + agent-count-preview
      'unit/server/test_group_agent_count_preview.cpp',   # #4033: pure shared create-group-preview model
      'unit/server/test_rest_sessions.cpp',
      'unit/server/test_rest_guaranteed_state.cpp',
      'unit/server/test_deployment_store.cpp', # ADR-0043: deployment_jobs Postgres migration
      'unit/server/test_discovery_routes.cpp', # A2 discovery surface (Issue 17.1)
      'unit/server/test_enrollment_directory_routes.cpp', # #4031: enrollment/directory/OIDC-config read twins
      'unit/server/test_security_headers.cpp',
      'unit/server/test_on_behalf_guard.cpp', # ADR-1005 PR 1.1 reserved-key guard
      'unit/server/test_principal_quota.cpp', # PR 4.4 per-principal quota cap primitive
      'unit/server/test_ota_transfer_watchdog.cpp', # OTA transfer deadline watchdog (#911 UP-101)
      'unit/server/test_ota_download_bound.cpp', # OTA admission + identity gates over real gRPC (#913/#416)
      'unit/server/test_ota_transfer_rules.cpp', # OTA chunk-write outcome decision (#911/#934/#941)
      'unit/server/test_ota_total_admission.cpp', # server-wide OTA gate occupancy (#913)
      'unit/server/test_ota_audit_key.cpp', # OTA identity-deny audit bucket key (#416/#913)
      'unit/server/test_ota_identity_mtls.cpp', # OTA identity audit bound over real mTLS (#416)
      'unit/server/test_grpc_tls_policy.cpp', # #4722: TLS 1.2 floor + cipher allow-list over REAL handshakes against the production builders
      'unit/server/test_ota_stalled_write.cpp', # TryCancel unblocks a stalled sync Write (#911 UP-101)
      'unit/server/test_server_ota_options.cpp', # OTA CLI/env contract + gRPC bound derivation (#913/#911)
      'unit/server/test_principal_quota_denial.cpp', # PR 4.4 dual-transport classifier lock (#2291)
      'unit/server/test_principal_quota_chokepoint.cpp', # PR 4.4 chokepoint wiring coverage
      'unit/server/test_grpc_on_behalf_enforce.cpp', # ADR-1005 PR 1.1 gRPC end-to-end enforcement
      'unit/server/test_principal_class.cpp', # ADR-1005 PR 1.2 actor-class label
      'unit/server/test_insecure_tls_gate.cpp',
      'unit/server/test_settings_routes_users.cpp',
      'unit/server/test_settings_routes_dex_alerts.cpp',
      'unit/server/test_settings_routes_ota_audit.cpp',
      'unit/server/test_settings_routes_management_groups.cpp', # stored-XSS regression (mgmt-group name/id escaping)
      'unit/server/test_settings_routes_oidc.cpp',
      'unit/server/test_settings_model.cpp',        # #4028 — pure Settings read-twin builder unit tests
      'unit/server/test_settings_read_twins.cpp',   # #4028 — REST v1 read-twin route coverage
      'unit/server/test_plugin_signing_helpers.cpp',
      'unit/server/test_store_errors.cpp',
      'unit/server/test_static_js_bundle.cpp',
      'unit/server/test_result_parsing.cpp',
      'unit/server/test_visualization_engine.cpp',
      'unit/server/test_rest_visualization.cpp',
      'unit/server/test_rest_executions_v1_twins.cpp',
      'unit/server/test_rest_responses_v1_twins.cpp', # #2146 A2-R2: GET /api/v1/responses{,/aggregate,/export}
      'unit/server/test_response_templates_engine.cpp',
      'unit/server/test_rest_response_templates.cpp',
      'unit/server/test_rest_instructions_productpacks.cpp', # #4029: GET /api/v1/instructions*, /api/v1/product-packs*
      'unit/server/test_offload_target_store.cpp',
      'unit/server/test_rest_offload_targets.cpp',
      'unit/server/test_directory_sync.cpp', # ADR-0063: directory_sync Postgres migration
      'unit/server/test_fleet_topology_store.cpp',
      'unit/server/test_viz_routes.cpp',
      'unit/server/test_product_pack_store.cpp',
      'unit/server/test_pg_raii.cpp',
      'unit/server/test_pg_pool.cpp',
      'unit/server/test_pg_migration_runner.cpp',
      'unit/server/test_pg_hardening.cpp',
      'unit/server/test_pg_migration_skip_predicate.cpp',
      'unit/server/test_pg_template_cleanup.cpp',
      'unit/server/test_offline_endpoint_store.cpp',
      'unit/server/test_agent_registry_presence.cpp',
      'unit/server/test_secret_codec.cpp',
      'unit/server/test_software_inventory_store.cpp',
      'unit/server/test_vuln_finding_store.cpp',
      'unit/server/test_vuln_finding_store_adversarial.cpp',
      'unit/server/test_product_normalize.cpp',
      'unit/server/test_product_registry_store.cpp',
      'unit/server/test_software_licensing_store.cpp',
      'unit/server/test_software_licensing_ingestion.cpp',
      'unit/server/test_app_usage_store.cpp',       # Wave 7b PR7b.2
      'unit/server/test_app_usage_ingestion.cpp',   # Wave 7b PR7b.2
      'unit/server/test_app_usage_routes.cpp',      # Wave 7b PR7b.2
      'unit/server/test_device_inventory_store.cpp',
      'unit/server/test_agent_decommission.cpp',
      'unit/server/test_app_perf_daily_store.cpp',
      'unit/server/test_app_perf_ingestion.cpp',
      'unit/server/test_app_perf_rollup.cpp',
      'unit/server/test_app_perf_group_reader.cpp',
      'unit/server/test_app_perf_cohort_reader.cpp',
      'unit/server/test_pg_array.cpp',
      'unit/server/test_scim_store.cpp',
      'unit/server/test_scim_store_pg.cpp',
      'unit/server/test_scim_json.cpp',
      'unit/server/test_scim_routes.cpp',
      'unit/server/test_discovery_store.cpp',
      'unit/server/test_discovery_scan_route.cpp',
    ),
    include_directories: [
      include_directories('../server/core/src'),  # private headers (nvd_db.hpp, web_utils.hpp, etc.)
      # C3b cross-check: test_guardian_resilience_schema.cpp includes the agent's
      # resilience_strategy.hpp for resilience_keys to assert the server param-spec
      # table matches the agent parser (contract G9 drift guard). Header-only
      # constexpr — no link to yuzu_agent_core, just the include path.
      include_directories('../agents/core/include'),
      # Tag-key pins: test_spark_fleet_tags.cpp includes the agent's
      # spark_heartbeat.hpp (emit_spark_heartbeat_tags),
      # test_guardian_journal_fleet_tags.cpp includes guardian_journal_heartbeat.hpp
      # (emit_guardian_journal_heartbeat_tags), test_guardian_health_fleet_tags.cpp
      # includes guardian_health_heartbeat.hpp (emit_guardian_health_heartbeat_tags,
      # #2298 gate 3 item 6d), and test_guardian_arm_fleet_tags.cpp (rung 9c PR-3)
      # includes guardian_arm_heartbeat.hpp + guardian_io_ceiling_heartbeat.hpp - each
      # asserting the agent's actual emitted keys equal the
      # matching server-side *_fleet_tags.hpp table - a full writer↔reader compile/run
      # bind, no silent zero-reporting drift. Header-only templates - no link to
      # yuzu_agent_core, just the include path.
      #
      # CONSTRAINT (governance Gate-3 architect). This puts 47 PRIVATE agent headers on
      # the include path of every server test TU. It is safe TODAY only because there is
      # zero CASE-INSENSITIVE basename collision (APFS/NTFS resolve case-insensitively,
      # so a Linux-only case-sensitive check under-detects) between agents/core/src/*.hpp
      # and server/core/src/*.hpp,
      # and because server/core/src is listed FIRST so it would win a future clash. A
      # same-named header added on both sides later SILENTLY SHADOWS — there is no
      # diagnostic. Do NOT add a private-agent-src include for any other target, and do
      # NOT solve a future collision by having server PRODUCTION code include an agent
      # header: that would be an upward dependency edge (server → agent), which the build
      # graph does not have and must not gain. The durable fix is to hoist the shared tag
      # keys into one source of truth. NOTE THE SCOPE: that hoist is triggered by spark's
      # rung 2, "when the wire contract changes anyway" - but the GUARDIAN JOURNAL and
      # GUARDIAN HEALTH keys are not part of that wire-contract change, so a rung-2 hoist
      # sweeping only spark would leave the 30 yuzu.guardian_journal_* and 3
      # yuzu.guardian_unhealthy_*/guardian_priority_demoted literals behind while this
      # comment still read as though it covered them. ALL THREE key families must move
      # together; the journal and health sides must be added to #2298's cutover-gate
      # list (not yet filed there as of this commit). Concrete target when it
      # happens: a hand-written header carried by proto/meson.build's
      # yuzu_proto_headers_dep - a DOWNWARD edge for both server and agent, no cycle, no
      # new build-graph node. NOT sdk/, which is the public plugin ABI surface.
      include_directories('../agents/core/src'),
    ],
    # httplib.h is header-only and its Client/Server class layout depends on
    # CPPHTTPLIB_OPENSSL_SUPPORT — yuzu_server_core compiles every TU with
    # https_cpp_args, so any test TU that includes <httplib.h> (directly or
    # via test_route_sink.hpp / workflow_routes.hpp) MUST match or MSVC emits
    # C4743 (vtable size mismatch) and the linked binary crashes with
    # STATUS_STACK_BUFFER_OVERRUN (0xC0000409) on first httplib::Server /
    # ::Client construction. LISTEN_BACKLOG kept aligned for completeness.
    #
    # YUZU_TEST_ENABLE_PG exposes the PostgresTestDb fixture in
    # test_helpers.hpp — only the server suite links libpq, so the guard
    # keeps the agent/tar suites (which share the header) libpq-free.
    # /bigobj: yuzu_server_core_lib already carries it; this target did not, and it
    # links test_mcp_server.cpp (10k+ lines, 263 TEST_CASEs) plus
    # test_mcp_stream_bridge.cpp. Catch2 emits per-TEST_CASE COMDAT sections and
    # MSVC's C1128 limit is a hard 65,279 - so the gap is a build-time cliff on one
    # platform only, with no runtime component. Free on every other compiler.
    cpp_args: https_cpp_args + test_partial_init_args +
              ['-DCPPHTTPLIB_LISTEN_BACKLOG=128', '-DYUZU_TEST_ENABLE_PG',
               # #2407 route-inventory test (test_body_cap_route_inventory.cpp):
               # mechanically scans the real server/core/src tree at test run
               # time rather than hand-copying a route list that would go
               # stale exactly like the thing it's testing.
               '-DYUZU_SERVER_SRC_DIR="' +
               # Backslashes MUST be normalised before this lands in a C string
               # literal. On Windows meson.project_source_root() is a native path
               # (D:\ci\work-0\...), and `\c`/`\w` are invalid escape sequences —
               # the TU either fails to compile or, worse, compiles to a MANGLED
               # path, scans zero files and the inventory passes vacuously. The
               # REQUIRE_FALSE(files.empty()) floor in the test catches the second
               # case, but there is no reason to rely on it. std::filesystem and
               # the Win32 API both accept forward slashes.
               (meson.project_source_root() / 'server' / 'core' / 'src').replace('\\', '/') +
               '"'] +
              (cxx.get_id() == 'msvc' ? ['/bigobj'] : []),
    # MSVC's default 1 MiB thread stack reserve is marginal for this binary's
    # deliberately re-entrant tests (e.g. test_mcp_server.cpp's "duplicate id
    # arriving MID-FLIGHT" SECTION, which calls back into the full streamed-POST
    # handler stack from INSIDE a dispatch callback already on that same stack -
    # two nested traversals of the JSON-RPC/session/stream-bridge/dispatch chain
    # in one thread, in an unoptimized debug build). Growing this file's tool
    # table (kTools[]) and test count over time has repeatedly pushed it closer
    # to Windows-specific limits (see the C1128 COMDAT-section-count comment
    # above) - a genuine EXCEPTION_STACK_OVERFLOW (0xC00000FD) here is a stack
    # headroom problem, not a test-logic bug, so the fix is headroom, not
    # touching the recursive test. 16 MiB is reserve only (Windows commits
    # pages on demand), so this costs no real memory unless the recursion
    # actually needs it. GCC/Clang are unaffected (larger default stacks,
    # and no /STACK equivalent needed here).
    link_args: (cxx.get_id() == 'msvc' ? ['/STACK:16777216'] : []),
    # Server unit tests #include <openssl/...> directly (e.g.
    # test_plugin_signing_helpers.cpp). yuzu_server_core_dep does not
    # propagate the OpenSSL include path, so declare it explicitly here
    # rather than relying on the transitive declare_dependency carry —
    # makes the dependency visible to Meson's graph and survives a
    # future static-merge refactor of yuzu_server_core (governance
    # hardening round 1, qe-B2).
    # catch2_nomain_dep (#1648/#3507): yuzu_server_tests supplies its own
    # main() via unit/test_runner_main.cpp (shared with yuzu_agent_tests), so
    # it links Catch2 without Catch2Main.
    # cli11_dep: test_server_ota_options.cpp parses real CLI::App argv in-process
    # to pin the OTA flag/env contract (header-only, no link cost).
    dependencies: [yuzu_server_core_dep, catch2_nomain_dep, cli11_dep, dependency('openssl', required: true, include_type: 'system')],
  )
  # Sharded 2026-07-13 (#2092 — the split the 2026-07-12 recalibration comment
  # promised): test() entries over the SAME binary, partitioned by Catch2
  # tag filter. '~[pg]' is everything not Postgres-backed; '[pg]' is the
  # Postgres-substrate cases. The complement is exact: every Postgres-touching
  # test carries [pg] and no [pg] test is hidden ([.]), so the shards partition
  # the visible case set with nothing lost or run twice (guard: --list-tests
  # counts, N_all == N_nonpg + N_pg).
  #
  # RE-SHARDED 2026-07-16 (auth.db -> Postgres migration, ADR-0006): that cutover
  # moved the entire auth/scim/mfa/route surface onto Postgres, ~doubling [pg]
  # from ~330 to ~660 cases. Two failure modes surfaced and are fixed here:
  #   (1) ~180 newly-Postgres route/store tests had been left UNTAGGED, so they
  #       ran in the ~[pg] shard — a partition violation (they only skip-not-run
  #       there when a DSN is absent; with a DSN, e.g. every CI leg, they RUN and
  #       inflate ~[pg]). Empirical fix: every case that skips a no-DSN run via
  #       the PG helper now carries [pg] (verified: ~[pg] no-DSN POSTGRES-skips == 0).
  #   (2) the single ~660-case [pg] entry blew the 900s budget on the slow
  #       GHA-hosted macos-15 runner. [pg] is now SPLIT into two balanced shards
  #       by a count-based discriminator (per-case CREATE DATABASE ... TEMPLATE
  #       clone cost is near-uniform, so case-count tracks wall time):
  #         shard A = [pg] AND (routes|store|token)   ~321 cases
  #         shard B = [pg] AND NOT (routes|store|token) ~338 cases
  #       Exact-partition guard: N([pg]) == N(A) + N(B). meson runs all three
  #       entries in parallel, so suite wall time is max(shard).
  # Budgets are sized for the *contended* Wee Tam box, not per-op cost:
  # ~[pg] = 600s (quiet Windows ~231s); each [pg] half = 600s (each is ~half the
  # old 900s full-[pg] load, so 600s is generous even under Wee Tam c4 contention).
  #
  # HISTORY / do-not-regress: [pg] was raised 600->900 on 2026-07-14 when the
  # fsync-bound CREATE DATABASE ... TEMPLATE + DROP DATABASE WITH (FORCE) (~20x
  # costlier on Windows) hit exactly-600s TIMEOUTs. The two fixes that pattern
  # blamed have since LANDED and are verified live on Wee Tam (2026-07-21):
  # per-agent Postgres (#2094; 4 clusters :5433-:5436) AND durability-off
  # (fsync/synchronous_commit/full_page_writes; scripts/ci/ensure-postgres.sh +
  # deploy/windows/Provision-Windows-Runner.ps1). Do NOT "return [pg] to 600":
  # the residual is NOT Postgres durability — it is box-wide concurrency
  # contention. Wee Tam runs 4 CCD-pinned runners on ONE host; affinity partitions
  # cores but not DRAM bandwidth, the shared disk, or the Defender minifilter, so
  # every heavy suite's wall time scales with how many Windows jobs share the box
  # (measured server ~[pg]: c0 289s -> c4 603s; [pg] up to 816s at c4). The real
  # fix is the Test-phase concurrency gate in ci.yml (scripts/ci/with-test-slot.sh
  # caps concurrent heavy Windows test phases per box), NOT a bigger budget —
  # raising a number just moves the cliff. A real hang is still bounded by the
  # job-level timeouts (90-120 min in ci.yml, 60 min in nightly.yml). The Catch2
  # cleanup/sweep listener (test_pg_template_cleanup.cpp) fires in all shards —
  # idempotent, harmless without a DSN. Constraints the shards must keep:
  #   - only tag-filter specs may appear as POSITIONAL args (flake-retry.py
  #     strips positional tag specs before an isolated case retry — Catch2 ORs
  #     positional specs). Each [pg] half is ONE comma-OR spec (Catch2 ORs
  #     inside a single arg; multiple positional args would AND, not OR).
  #     Catch2 OPTION flags (--long form, e.g. --allow-running-no-tests on an
  #     all-skip-on-macOS shard) are permitted: they are not positional, so
  #     the selftest exempts them from the tag-spec pin, and the whole-shard
  #     enumeration re-run preserves them (still needed for a DSN-less
  #     all-skip). The ISOLATED SINGLE-CASE retry does NOT preserve
  #     --allow-running-no-tests specifically — it strips that flag so a
  #     comma-containing case name can never silently zero-match-and-succeed
  #     (2026-08-17, see scripts/ci/flake-retry.py's _cmd_for_case_retry);
  #   - no entry name may be a substring of another (flake-retry maps
  #     meson-junit names by longest substring match) — 'shard A'/'shard B'/
  #     'shard C'/'shard D'/'shard E'/'shard F'/'shard G'/'shard H'/'shard I'/
  #     'shard J'/'shard K', 'server pg smoke', and 'server unit tests' are
  #     pairwise non-substring. The Windows CI test-phase-split PR (#3443,
  #     2026-08-28) added a second non-pg 'shard C' ('server unit tests
  #     shard C', distinct from the pg 'server pg unit tests shard C') —
  #     the full prefixed names stay pairwise non-substring (checked: neither
  #     contains the other, since 'server pg unit tests shard C' never
  #     contains the contiguous text 'server unit tests shard C').
  #   - UPDATED Phase 2 (#3443) — this used to say ci.yml's Linux Test step
  #     hardcodes the full pg shard name list with "No automated check
  #     enforces this yet"; that was true before Phase 1 and is stale now.
  #     Since Phase 1, the 11 pg shards (10 + K, added 2026-08-28) are
  #     selected structurally via `--suite server-pg` — adding/splitting/
  #     rebalancing a shard needs only the right suite: kwarg here, ci.yml
  #     is untouched, and the partition invariant below proves the property.
  #     ci.yml DOES still hardcode BY NAME: the 3 non-pg server test names
  #     (A/B/C), 'mcp bridge teardown allocation budget', 'server pg shard
  #     partition invariant', and (Phase 2) 'server pg smoke' — renaming any
  #     of those, or adding a new top-level `suite:`
  #     anywhere in the build (tests/meson.build or the root meson.build —
  #     see the 'gateway' suite, registered there, not here), still needs a
  #     matching ci.yml update, and by-name selection fails LOUD on a
  #     mismatch (meson errors on an unmatched positional test name) rather
  #     than silently dropping coverage — verify with meson test --list
  #     against each ci.yml invocation before trusting a change to either side.
  # If a quiet leg pushes a shard past the #2093 80%-of-budget warning, the first
  # move is the concurrency gate / per-op cost (Defender TEMP exclusion, RAM disk),
  # then split or rebalance — raising the number is the last resort, not the first.
  #
  # #2395 split the non-PG '~[pg]' entry, which had reached 603/600s (101%) on
  # Windows and tripped the #2092 unrecovered-timeout gate. The suite was already
  # AT budget: 18 added cases (~0.5%) were the straw, not the cause — at 100% any
  # PR adding a single test trips it. Split rather than a timeout bump, which is
  # what the warning itself asks for.
  #
  # Partition is by [auth]+[mcp] vs the rest, chosen by MEASURED TIME, not case
  # count: [auth] alone is ~14s of the ~35s local total and dominates everything
  # else ([mcp] 4.1s, [rest] 0.8s, [dex] 0.5s, the rest <0.5s each). The result is
  # lopsided by count (430 vs 3057 cases) and balanced by time (~17.5s vs ~26s) —
  # a timeout cares about seconds. Verified an exact partition: 430 + 3057 = 3487,
  # Catch2's own counts. Catch2's native --shard-count/--shard-index would be
  # tidier but is DELIBERATELY not used: those are options, not positional specs,
  # so flake-retry.py's _cmd_without_test_specs would keep them across an isolated
  # case retry and silently filter out the very case being retried.
  #
  # WINDOWS CI TEST-PHASE-SPLIT (#3443, 2026-08-28): two more carves, sized by
  # WINDOWS per-case time (0.34-1.40s/case across the old pg shards, so count
  # alone would misbalance) rather than by case count:
  #   pg: shard C (640 cases, the Windows makespan floor at 310s) split into
  #     C (320 cases, kept) + K (320 cases, carved: 10 named store tags —
  #     policy_store/instruction_store/ca_store/device_token/tag_store/bundle/
  #     pki/offload_store/webhook_store/baseline_store — none claimed by any
  #     other shard's filter). Exact partition verified locally against the
  #     real binary (640 = 320 + 320; re-verified governance 2026-08-28, the
  #     "832 = 406 + 426" figure this comment originally carried was wrong —
  #     see the shard-K-specific comment below for the same correction); a
  #     DSN-less run of K exits 0 (same as C's own precedent, no
  #     --allow-running-no-tests needed).
  #   non-pg: shard B split into B (kept, narrowed by excluding auth/mcp/cel/
  #     viz/scope/dispatch/nvd/dex, already carved to A/its own [auth][mcp]
  #     split earlier) + a NEW non-pg 'shard C' (the six excluded tag groups).
  #     Named 'shard C', not 'shard B2' — the pairwise-non-substring rule
  #     above rejects any name that is a substring of another live entry;
  #     'shard B2' is not itself a substring hazard, but 'shard C' keeps the
  #     single-letter-per-shard convention this file already uses everywhere
  #     else, and the pg/non-pg 'shard C' pair is proven non-colliding above.
  # This is shared infrastructure (`tests/meson.build` is not platform-gated),
  # so both new shards run on Linux too, not only Windows — Linux's own pg
  # shard count moves from 10 to 11 as a direct consequence; see the
  # "Worst-case job-budget arithmetic" note in docs/ci-architecture.md for
  # what that does to the Linux degenerate-case timeout ceiling.
  #
  # NON-PG SHARD D (staged Windows measurement follow-up, same date range as
  # PR #3677's own widening pushes): shard B's own [body_cap] tests carved
  # out, sized this time by LOCAL Linux per-case TIME (--durations yes), not
  # case count — the lesson from shard C above (case-count split "is the
  # starting point, not a tuned result") applied. [body_cap] is 20 of B's
  # then-1969 cases (1%) but 16.58s of B's 39.60s measured total (42%): real
  # httplib loopback round-trips (test_body_cap_policy.cpp,
  # test_body_cap_route_inventory.cpp) cost ~40x an average case here. This
  # is a FROZEN single-run measurement (case counts/times at the moment this
  # carve was made, before #3677's own fix round separately landed 2 new
  # untagged cases into B) — do not read "1969"/"1949" as current totals,
  # and do not bump them on a future shard-B change; check-pg-shard-
  # partition.py's live count against the real binary is the current-state
  # source of truth. Filter repeats B's own exclusion suffix rather than
  # bare [body_cap] (26 cases repo-wide; 6 already belong to shard A, via
  # [mcp], and must not be double-claimed — verified empirically, not shard
  # C, which claims none) — verified 20 + 1949 = 1969, exact partition of
  # B's pre-carve population AT THE TIME OF THIS CARVE.
  test('server unit tests shard A', server_test_exe,
       args: ['~[pg][auth],~[pg][mcp]'], suite: ['server', 'server-nonpg'], timeout: 600,
       priority: 20)
  test('server unit tests shard B', server_test_exe,
       args: ['~[pg]~[auth]~[mcp]~[cel]~[viz]~[scope]~[dispatch]~[nvd]~[dex]~[body_cap]'],
       suite: ['server', 'server-nonpg'], timeout: 600, priority: 50)
  # server unit tests shard C — carved from shard B 2026-08-28 (Windows CI
  # test-phase restructuring, #3443): six tags whose combined case count
  # (820 of B's 3150) made B the floor of the Windows non-pg step. Case-count
  # split only — B's own per-case cost was measured uniform-ish on Windows
  # (0.05 s/case for the whole shard), but these six tags were never measured
  # INDIVIDUALLY before this split, so this is the starting point, not a
  # tuned result; the staged Windows measurement protocol
  # (docs/ci-architecture.md "PG coverage by platform") rebalances by
  # measured wall time, never by case count alone.
  test('server unit tests shard C', server_test_exe,
       args: ['~[pg]~[auth]~[mcp][cel],~[pg]~[auth]~[mcp][viz],~[pg]~[auth]~[mcp][scope],~[pg]~[auth]~[mcp][dispatch],~[pg]~[auth]~[mcp][nvd],~[pg]~[auth]~[mcp][dex]'],
       suite: ['server', 'server-nonpg'], timeout: 600, priority: 45)
  # server unit tests shard D — carved from shard B (staged Windows
  # measurement follow-up, see the PR #3677 comment thread): [body_cap]
  # alone, chosen by LOCAL Linux per-case TIME measurement (--durations
  # yes), not case count — 20 cases, 16.58s of shard B's then-39.60s
  # measured total (41.9%), by far the single largest tag by time despite
  # its small case count. FROZEN single-run measurement, taken before
  # #3677's own fix round separately landed 2 new untagged cases into B —
  # do not read these as current totals or bump them on a future shard-B
  # change; check-pg-shard-partition.py's live count against the real
  # binary is the current-state source of truth. These are real httplib
  # loopback round-trips (test_body_cap_policy.cpp,
  # test_body_cap_route_inventory.cpp), not pure in-process assertions, so
  # their per-case cost (~0.83s average) is ~40x the shard's own overall
  # per-case average (~0.02s) — exactly the kind of outlier case-count-based
  # splitting misses. The filter repeats shard B's own exclusion suffix
  # (not bare [body_cap], which matches 26 cases repo-wide — 6 of them
  # already belong to shard A via [mcp] and must not be double-claimed;
  # none land via shard C's tags): verified locally, 20 + 1949 = 1969,
  # exact partition of shard B's original population AT THE TIME OF THIS
  # CARVE.
  # A DSN-less run needs no --allow-running-no-tests: none of these are
  # [pg]-tagged (confirmed: '[pg][body_cap]' matches zero cases).
  # Priority 48 (between C's 45 and B's 50): even after this carve, B's
  # REMAINING population still measures larger than D (23.02s vs 16.58s,
  # both drawn from the same 39.60s baseline) — D isn't the new floor, B
  # still is. Not ranked against C's own priority precisely: C's 45 predates
  # any time measurement (case-count only, its own comment says so), and D's
  # 16.58s isn't on the same measured baseline as C's unmeasured population,
  # so this ordering is a reasonable placement, not a claimed comparison.
  test('server unit tests shard D', server_test_exe,
       args: ['[body_cap]~[auth]~[mcp]~[cel]~[viz]~[scope]~[dispatch]~[nvd]~[dex]'],
       suite: ['server', 'server-nonpg'], timeout: 600, priority: 48)
  # [audit_store] is in shard A's OR-list because ADR-0040 moved that whole file
  # onto PG in one change: without it, every one of its cases lands in B, which
  # is the heavier half already. MEASURED on Linux at that change's head, same
  # box, live PG: A 89.7s -> 95.8s, B 116.0s -> 113.4s. That is a ~3% shift, not
  # a rescue — the ~1.9x case-count drift between these two halves PREDATES this
  # change and is not addressed here. The partition is preserved
  # (N([pg]) == N(A) + N(B)); if you add a tag to one side, exclude it on the
  # other in the same edit.
  #
  # RE-BALANCED 2026-08-15: measured case counts had drifted to 586 (A) vs 1361
  # (B) — a 2.3x split, up from the ~1.9x already flagged above — and B was
  # TIMEOUT-ing at 600s on Linux and Windows both (#2092/#2093's own warning:
  # "split the suite or rebalance before this flakes"). [rbac_store],
  # [guaranteed_state_store] and [response_store] moved to A by the same
  # AUDIT_STORE precedent above — each is a dedicated store's own tag, confined
  # to that one test file, same shape as [audit_store] (verified: `grep -rl`
  # each tag matches exactly one file). Moves 207 cases (93+61+53), landing at
  # 793 (A) / 1154 (B) — better, not perfect; [custom_props] was considered and
  # left out because it also tags test_props_scope_authz.cpp (a scope-authz
  # suite, not pure store CRUD), so its per-case PG cost isn't confirmed uniform
  # with the others.
  #
  # PR1.6a review remediation (same day) additionally moved [operator_surface]
  # (the 3 new upload-grant MCP-twin PG integration tests) to A the same way —
  # untagged, all 3 would land in B, which is already the heavier half and had
  # separately reached 600.57/600s (killed by TIMEOUT) on CI before this move.
  # Partition preserved: N([pg]) == N(A) + N(B).
  #
  # RE-BALANCED (ADR-0048, LicenseStore, 2026-08-15/16): B kept growing as
  # sibling Wave 2 stores merged in and kept TIMEOUT-ing on Windows (and
  # eventually Linux) even after this store's own [license_store] (33 cases,
  # confined to test_license_store.cpp) was moved off it once already.
  #
  # RE-BALANCED AGAIN 2026-08-16 (PR #3156 review-response round, cherry-picked
  # here — 3f0796777, now also merged to dev via #3156 itself): the day after
  # the rebalance above, B TIMEOUT-ed again — 66 new/extended PG-backed cases
  # split 25/41, landing B's already-heavier share disproportionately. A
  # same-day two-shard fix (moving more tags onto A) was reviewed and rejected
  # before merge: A's own prior measurement (0.616s/case, already 84% of
  # budget) is a HIGHER per-case rate than B's, contradicting the
  # "near-uniform per-case cost" premise these rebalances lean on —
  # concentrating more cases onto the already-more-expensive shard projected
  # to ~577s (96%), likely relocating the timeout rather than fixing it.
  #
  # SPLIT INTO THREE SHARDS instead. The store-heavy tag set (expensive: real
  # CREATE DATABASE ... TEMPLATE clones per case, unlike lighter route/handler
  # tests) is itself split across two shards rather than concentrated in one:
  #   shard A = [routes]/[store]/[token]
  #   shard B = [audit_store]/[rbac_store]/[guaranteed_state_store]/
  #             [response_store]/[operator_surface]/[guardian_routes]/
  #             [workflow]/[deployment_store]/[license_store], minus anything
  #             already in A
  #   shard C = everything else [pg]-tagged
  # [license_store] folded into shard B's tag list on the cherry-pick (not
  # present on PR #3156's branch, which has no reason to know about this
  # store) — same confined-to-one-file precedent as every other tag in that
  # list, re-verified against this merge's actual case counts via --list-tests
  # on the built binary, not assumed from either side's pre-merge numbers.
  # Partition preserved: N([pg]) == N(A) + N(B) + N(D) + N(E) + N(I) + N(F) +
  # N(G) + N(J) + N(C) + N(H) (adversarial-review COD-P1-001/K5: an earlier
  # version of this comment omitted F and G, which don't appear until further
  # below in this file — the omission was prose-only, the filters and the
  # verified sum at line ~1062 were always correct). (shard B split into B+D
  # on 2026-08-16, shard C split further into C+E on 2026-08-17, shard A
  # split into A+H on 2026-08-22, shard E split into E+I and shard G split
  # into G+J on 2026-08-25 — see the blocks below.)
  #
  # SPLIT INTO A+H on 2026-08-22 (#2185-adjacent — same "reddening dev,
  # unclassifiable TIMEOUT, no failing case on enumeration re-run" signature
  # #3322 diagnosed for shard E on 2026-08-19): shard A reached 600.12/600s
  # TIMEOUT on Linux gcc-15/clang-21 across a whole day's worth of dev pushes
  # (confirmed via CI history: 549-580s on quiet runs, TIMEOUT under any
  # added load, unrelated to any single PR — a #2093-style creep from many
  # small additions, same as every prior split on this file). Per the
  # standing house rule ("if it warns, split shard C itself" — the C->C+E
  # precedent) and the "measure, don't just count" rule this file's own
  # history rejected an unmeasured split for once already: the boundary was
  # DESIGNED via an exhaustive tag-partition check (every candidate tag
  # cross-referenced against every OTHER file using it, so no case straddling
  # two shards, no case left in neither) and then VERIFIED on the built
  # binary both ways — exact partition (`--list-tests`: A 251 + H 313 = 564,
  # matching the pre-split undifferentiated shard A exactly; at the time of
  # the split, the full 8-shard sum A+B+D+E+F+G+C+H = 2270 matched the
  # binary's total [pg] case count — since risen to 2290 as later governance
  # rounds restored migration-only tests found to be sole regression coverage
  # for named catastrophic properties; re-verify the sum against --list-tests
  # rather than trusting either number as current) and real wall-time
  # against live Postgres, local :5433, quiet box:
  # A 89.6s (251 cases, 4296 assertions), H 102.4s (313 cases, 27707
  # assertions) — both ~15-17% of the 600s budget even before accounting for
  # CI's ~2x contention multiplier. H's per-case rate (0.327s) is slightly
  # CHEAPER than A's (0.357s) despite carrying more cases, consistent with
  # the "store-CRUD cases cost more than route-handler cases" premise below.
  #
  # shard H carves out four DOMAINS that were only in shard A because they
  # happen to carry the broad [routes]/[token] category tags shard A claimed
  # unconditionally BEFORE this split (shard A's pre-split clause had no
  # exclusions — everything HERE already only reached A because no OTHER
  # shard's clause tolerated routes/store/token; docs-writer, governance Gate
  # 2 2026-08-22 — the parenthetical previously read present-tense against
  # code that, three lines below, now plainly does carry exclusions):
  # SCIM routes (test_scim_routes.cpp, 101 cases),
  # DEX routes (test_dex_routes.cpp + one case in test_dex_perf_model.cpp:916
  # that also carries [pg][routes][dex], 37 — adversarial-review COD-P2-005/K4
  # caught the initial 36-only count; the partition was never affected, only
  # this prose), the whole MFA route surface (test_auth_routes_mfa.cpp +
  # test_settings_routes_mfa.cpp via the shared [mfa] tag, 34+14=48), and
  # token rotation (test_api_token_store.cpp's [rotation]-tagged subset +
  # test_rest_api_tokens_rotation.cpp + test_engine_principal_lifecycle.cpp +
  # test_mcp_server.cpp's [token][rotation] cases, 95+25+2+5=127) —
  # 101+37+48+127=313, matching H's verified --list-tests count exactly. Each
  # carve-out tag was checked
  # against every OTHER file using it to confirm the exclusion added to A
  # below can't orphan a same-tag case that belongs in a DIFFERENT shard
  # (e.g. [mfa] alone would be unsafe — test_mfa_step_up.cpp/test_mfa_qr.cpp/
  # test_mfa_store.cpp/test_totp.cpp also carry it but never with [routes],
  # so they were never in A and are untouched either way; [rotation] alone
  # would be unsafe too — test_rotation_sweep_naming.cpp/
  # test_rotation_warn_dedup.cpp carry it with no [pg] tag at all, never
  # shard candidates). H's own clauses require the SAME co-tag ([routes] or
  # [token]) shard A's own clause already required, so nothing changes
  # about which cases were ever reachable from A — only which of two A-side
  # shards now claims them. 313 cases, 55% of the pre-split 564 — the larger
  # half on a case-count basis but NOT the larger half on time (see the
  # measured numbers above: H's per-case rate is the cheaper of the two, so
  # 313 cases lands at 102.4s vs A's 251 at 89.6s — close to balanced by
  # wall-time despite the count skew). All of H's cases are [pg]-tagged
  # store/route behaviour tests with no non-DSN survivor — confirmed on the
  # built binary (no-DSN run: exit 4 without the flag, exit 0 with it) —
  # needs --allow-running-no-tests like shard D.
  test('server pg unit tests shard A', server_test_exe,
       args: ['[pg][routes]~[scim]~[dex]~[mfa],[pg][store],[pg][token]~[rotation]'],
       suite: ['server', 'server-pg'], timeout: 700, priority: 80)
  # H's four clauses each add `~[store]` (fable review, structural hardening):
  # A's own `[pg][store]` clause carries NO exclusions, so any [pg][store]
  # case is unconditionally claimed by A regardless of what else it carries —
  # excluding `[store]` from H therefore can never orphan a case, only ever
  # remove a case H would otherwise have double-run with A. This closes the
  # largest of the two theoretical (currently empty, but not structurally
  # impossible) overlap classes a future case could fall into; the smaller
  # one is NOT closable this way without risking an orphan (Catch2's flat tag
  # algebra can't express "unless it's also elsewhere in H"), so it stays a
  # documented residual, not a bug. The actual hazard shapes (verified by
  # working the filter algebra, gov Gate 2 docs-writer — an earlier draft of
  # this comment named the wrong pairing, one that in fact matches ONLY H,
  # never A, since A's [routes] clause excludes every domain tag and A's
  # [token] clause excludes rotation): a bare [routes][token][rotation] case
  # with NO domain tag (matches A via its undomained-routes clause AND H via
  # its rotation clause), or a [routes]+{scim|dex|mfa}+[token] case with NO
  # [rotation] (matches A via its non-rotation-token clause AND H via that
  # domain's routes clause). Verify with --list-tests that no case matches
  # more than one of H's four clauses before adding a new routes+token-domain
  # tag to any surviving store file.
  test('server pg unit tests shard H', server_test_exe,
       args: ['[pg][routes][scim]~[store],[pg][routes][dex]~[store],[pg][routes][mfa]~[store],[pg][token][rotation]~[store]',
              '--allow-running-no-tests'],
       suite: ['server', 'server-pg'], timeout: 700, priority: 75)
  # shard B SPLIT into B+D on 2026-08-16 (#2092/#2093): the store-tag half had
  # reached 600/600s (100%) and flaked. BALANCED BY TIME, NOT COUNT — case count
  # is not proportional to wall-time (shard C carries ~1082 cases comfortably;
  # this store-tag set of ~428 was timing out, because each store-behaviour case
  # does heavy per-test PG DDL / pre-migrated-template clones). Measured per-tag
  # wall-time (isolated, local :5433 — a proxy; CI under c4 contention is ~2x+):
  # [rbac_store] alone is the whale at ~57s, vs ~48s for the OTHER EIGHT tags
  # COMBINED. So shard B = [rbac_store] alone; shard D = the other eight. This is
  # count-lopsided (93 vs 335) ON PURPOSE — it is the time-balanced split (~57s
  # vs ~48s), and time is what blows the 600s ceiling. Each shard is a strict
  # SUBSET of the former at-600s run, so both are well under budget; B and D are
  # disjoint and together cover exactly the tag set shard C excludes, so the
  # partition N([pg]) == N(A)+N(B)+N(D)+N(C) is preserved (shard C UNCHANGED
  # at the time of THIS split — shard C was later split again into C+E on
  # 2026-08-17, see the shard-E block below).
  # When adding a new [pg] store tag: measure it, put it in whichever of B/D is
  # lighter by TIME, add it to shard C's exclusion list, AND add it to each of
  # shard E's, shard I's, shard G's AND shard J's per-clause exclusion suffixes
  # below (all of them or none — a tag added to D/C but not to every E/I/G/J
  # clause double-runs any future case that also carries one of their category
  # tags; E and I between them hold E's original ten since the 2026-08-25
  # split, G and J likewise hold G's original ten). If [rbac_store] itself
  # grows toward the ceiling, split IT next (it is already the single densest
  # tag).
  #
  # 2026-08-16 (ADR-0051, SoftwareDeploymentStore, PR #3174) followed exactly
  # that recipe for [software_deployment] (66 cases): measured in isolation on
  # this store's own dedicated Postgres container — [software_deployment]
  # 4.0s, vs. shard B ([rbac_store]) 55.2s and shard D (the other eight tags)
  # 31.5s on the same container — D is by far the lighter destination, so
  # [software_deployment] joins D, not B. Also added to shard C's exclusion
  # list per the same instruction (both or neither).
  test('server pg unit tests shard B', server_test_exe,
       args: ['[pg][rbac_store]~[routes]~[store]~[token]'],
       suite: ['server', 'server-pg'], timeout: 700)
  # --allow-running-no-tests: shard D's tags are ALL DSN-gated store
  # behaviour tests, so on a DSN-less platform (macOS, ADR-0035) every case
  # SKIPs and Catch2 exits 4 on an all-skipped run — reddening the leg (#2092,
  # found on the B/D split's first CI). Shards A/B/C survive the same all-skip
  # only because each happens to carry a non-DSN case that runs to completion;
  # D has none, so it needs the flag explicitly. The flag is a no-op where PG is
  # present (Linux/Windows CI): the cases run normally. It is an OPTION, not a
  # positional tag spec — its hygiene selftest exempts --flags from the
  # tag-spec pin, and the whole-shard enumeration re-run preserves it (still
  # needed there for the DSN-less all-skip). The isolated SINGLE-CASE retry
  # strips it specifically, so a comma-containing case name can never
  # silently zero-match-and-succeed instead of honestly failing (2026-08-17,
  # see scripts/ci/flake-retry.py's _cmd_for_case_retry).
  test('server pg unit tests shard D', server_test_exe,
       args: ['[pg][audit_store]~[routes]~[store]~[token],[pg][response_store]~[routes]~[store]~[token],[pg][operator_surface]~[routes]~[store]~[token],[pg][guaranteed_state_store]~[routes]~[store]~[token],[pg][workflow]~[routes]~[store]~[token],[pg][license_store]~[routes]~[store]~[token],[pg][deployment_store]~[routes]~[store]~[token],[pg][guardian_routes]~[routes]~[store]~[token],[pg][software_deployment]~[routes]~[store]~[token]',
              '--allow-running-no-tests'],
       suite: ['server', 'server-pg'], timeout: 700, priority: 70)
  # 2026-08-17 (PR #3174 CI, run 32004956605): shard C STILL TIMEOUT-ed at
  # 600.07/600s on the real contended Big Tam pool after the [software_deployment]
  # move above — the local-measurement projection (sre's own Gate 6 finding on
  # this PR) undersold the real contention multiplier. Per that finding's own
  # recommendation ("if it warns, split shard C itself, not a revert"): shard E
  # carves a further block of tags out of C, the same "broad category" shape
  # shard A already uses for routes/store/token — grep -rl checked before
  # picking the set: most of these 22 tags are multi-file, and the two that
  # are single-file ([agent_service], [notification_store]) are included
  # anyway, since file-confinement was never the safety property being relied
  # on here — the --list-tests case-count/partition verification below is.
  # Verified via --list-tests on the built binary: A 554 / B 93 / D 401 /
  # E 812 / C 271, summing to the unchanged 2131-case [pg] total. All five
  # shards passed a full run against a live Postgres database with zero
  # failures. Like shards A/B/C (but unlike shard D), shard E survives a
  # DSN-less all-skip without --allow-running-no-tests: it carries at least
  # one non-DSN-gated case (verified: no DSN set -> exit 0, 10 passed / 802
  # skipped, not the flag's exit-0-on-zero-match path).
  #
  # 2026-08-17 (PR #3216, service-scope-confinement Phase 0): dev's OWN CI
  # (run 32047363814, head f8c068fe3 — no PR-specific tests at all) TIMEOUT-ed
  # shard E at 600.11/600s on BOTH Linux legs (gcc-15, clang-21) — the E split
  # above already runs at its ceiling with zero of this PR's tests, confirmed
  # via `gh run view` against the dev run itself, not inferred. This PR's own
  # 19 new [pg][auth_routes] cases (test_authz_gates.cpp) then reproduced the
  # identical failure twice more (600.58s, 600.60s) on top of that pre-existing
  # saturation. Per the same "split, don't raise the timeout" house rule the
  # C->C+E split above already established: measured shard E's true LOCAL
  # (uncontended, single combined invocation — NOT summed per-tag runs, which
  # double-count the 275 cases carrying 2+ of E's 22 tags) wall time at 180.45s
  # against a live Postgres instance. [dex] and [mcp] measured as the two
  # heaviest individual tags (39.42s / 38.56s in isolation) and carry the
  # bulk of E's cross-tag overlap with each other and with [rbac]/
  # [guaranteed_state]/[discovery]/[audit] — carving BOTH out together (rather
  # than picking one) empirically confirmed via a real combined run: candidate
  # new-E (20 tags, excludes dex+mcp) = 139.09s local / 702 cases; candidate
  # shard F (dex+mcp) = 47.52s local / 159 cases. 702+159+3(non-DSN skip in E)
  # = 864, matching the unsplit shard E's own 864-case total exactly — zero
  # loss, zero duplication. Verified via a File:Line-identity set-equality
  # script against the built binary's `--list-tests -r xml` output (not case
  # counts alone, which can't detect a same-count swap): A 554 / B 93 / D 407
  # / E 705 / F 159 / C 271, summing to this branch's [pg] total of 2189 with
  # zero pairwise overlap and zero cases missing from every shard. (D/C's own
  # counts drifted from the 401/271 recorded when E was first split, and total
  # from 2131 — dev moved during the same day; this PR's own +19 [auth_routes]
  # cases account for part of the difference, the rest is unrelated same-day
  # merges, neither is this split's concern.) Both new shards passed a full
  # run against a live Postgres database with zero failures: E 138.58s, F
  # 48.30s. Shard E still survives a DSN-less all-skip the same way it
  # already did (the non-DSN cases it carries aren't dex/mcp-tagged). Shard F
  # was verified the same way: no DSN set -> exit 0, 3 passed / 156 skipped —
  # it does NOT need --allow-running-no-tests (unlike shard D, #2092).
  # 2026-08-19 (#3322): shard E timed out at its 600s ceiling on 10 of 14
  # consecutive Linux gcc-15 runs, reddening dev itself — Fail: 0 every time,
  # so nothing was failing, it simply did not finish. E held 608 of the 1876
  # [pg] cases (32%) in one of six shards; at the ~1.0 s/case this suite runs
  # at, that lands exactly on the ceiling.
  #
  # E had already been split TWICE that week (79040f7da carved it out of C,
  # 1a509645e split E into E+F, 0f5fa1638 split F out of E again) and came
  # straight back each time, because each split carved off a SMALL piece —
  # F is only 138 cases — and left E oversized. This one halves it: measured
  # E=329, G=278, against the same 607 distinct cases as before, with ZERO
  # cases in both halves.
  #
  # SPLIT AGAIN into E+I and G+J on 2026-08-25 (PR #3582), combined with a
  # 600->700s timeout bump on all four. Trigger: PR #3582's own real CI run
  # TIMEOUT'd E and G at 600.51s/600.54s with ZERO cross-job contention (the
  # cross-job slot gate acquired in 0s) — a direct diagnostic run on Big Tam
  # (--num-processes 1, no other job on the box) then measured shard E SOLO
  # at ~353-363s, essentially unchanged whether the box was quiet or under
  # deliberate concurrent load from 3 other PRs' full CI runs (within 3%) —
  # so this was never contention, and E's own local-uncontended baseline had
  # roughly DOUBLED since its 180.45s measurement at the 2026-08-19 split
  # (case count grew 329->405, +23%, which alone does not explain a 2x wall-
  # time increase — Big Tam's own per-op cost for this fsync-heavy DDL
  # workload also drifted up over the same window; not further diagnosed
  # here). G had grown 278->351 (+26%) over the same window.
  #
  # Split by case count as a TIME proxy (no live-PG isolated per-tag timing
  # taken this round — case count was treated as adequate given this
  # workload's fairly uniform per-case CREATE DATABASE/DROP DATABASE cost;
  # unlike the B/D split's [rbac_store] whale, no single tag here dominates).
  # Greedy-balanced each ten-tag set into two five/five-ish groups by raw
  # count: E keeps {scim, guaranteed_state, oidc, software_inventory} (193
  # cases); I takes {engine_principal, rbac, custom_props, quarantine,
  # management_group, notification_store} (212 cases) — I DEFERS TO E (each
  # I clause additionally excludes E's four remaining tags; the first
  # attempt without this deferral double-counted 12 cases carrying a tag
  # from each side, caught by --list-tests before trusting it: 193+224=417
  # raw vs 405 OR'd). G keeps {auth_routes, agent_service, authz, tar} (207
  # cases); J takes {saml, result_set, audit, access_review, secrets,
  # discovery} (144 cases) — J DEFERS TO G the same way (without it, 47
  # cases double-counted: 207+191=398 raw vs 351 OR'd). Verified via
  # --list-tests on the built binary: E 193 + I 212 = 405 (old E's total,
  # exact), G 207 + J 144 = 351 (old G's total, exact), all four combined =
  # 756 (old E+G total, exact) — zero cases lost, zero cases duplicated.
  # These four figures (193/212/207/144, and the 405/351/756 sums) are
  # SPLIT-TIME snapshots, not a maintained invariant — like the D/C counts
  # noted elsewhere in this file, they drift as the case population changes
  # and re-verifying them isn't this split's (or any single commit's)
  # concern. Post-#3626-prune (2026-08-26) actuals, for reference only:
  # I=181, E=188 — see the 2026-08-26 note below shard I's definition.
  # E and I both survived a DSN-less all-skip without --allow-running-no-tests
  # at split time (E: 6 non-DSN cases; I: 1) — G and J both needed it, same as
  # old G did (every one of G's original ten tags is DSN-gated;
  # subdividing a DSN-gated tag set keeps every piece DSN-gated). All four
  # ran clean against a live Postgres database with zero failures: local
  # (bigcolin, single container, quiet) wall time E 65.6s / I 34.4s / G(new)
  # 55.6s / J 35.8s — each roughly half its parent's own last-measured local
  # baseline, consistent with the case-count split ratio.
  #
  # The 600->700s timeout bump originally shipped E/I/G/J-only (PR #3582,
  # 2026-08-25) as a DELIBERATE, TEMPORARY exception to this file's own
  # "split, don't raise the timeout" house rule (the C->C+E and A->A+H
  # precedents above never raised it). EXTENDED to all remaining shards
  # (A/B/D/F/H/C) the same day, after dev's own CI (run 32833097478, merge of
  # PR #3466 — no PR-specific pg-shard changes) TIMEOUT'd shard E at 600.51s
  # AND landed shard G at 585-590/600s (97-98%) on all four Linux legs — live
  # confirmation that the 600s ceiling was already tight fleet-wide, not just
  # on the two shards #3582 happened to split. Justification, corrected after
  # Gate 2 governance review (2026-08-25) caught the original wording
  # overclaiming a settled near-term timeline: `docs/postgres-migration-ladder.md`
  # explicitly disclaims one ("mutable state that drains over time, not a
  # contract"), and completing that ladder is architecturally more likely to
  # GROW this population than shrink it — every store that migrates onto
  # Postgres adds its own [pg]-tagged CRUD/behaviour cases, while only each
  # store's narrow, already-thin migrate_from_sqlite backfill suite becomes
  # prunable. So this margin is NOT bought against an expected population
  # shrink — it is a plain safety cushion on top of whatever headroom each
  # shard's own split already earns. Revisit on a fixed cadence, not on an
  # assumed completion date — tighten back to 600, or drop, per shard, once
  # that shard is comfortably under budget. Tracked at issue #3443 (the
  # existing linked home for the pg-shard-reliability lineage) — a prose-only
  # "revisit later" with no dated/metric trigger has this file's own track
  # record of being forgotten until the next stale-pin incident forces it.
  test('server pg unit tests shard E', server_test_exe,
       args: ['[pg][scim]~[routes]~[store]~[token]~[audit_store]~[rbac_store]~[guaranteed_state_store]~[response_store]~[operator_surface]~[guardian_routes]~[workflow]~[deployment_store]~[license_store]~[software_deployment]~[dex]~[mcp],[pg][guaranteed_state]~[routes]~[store]~[token]~[audit_store]~[rbac_store]~[guaranteed_state_store]~[response_store]~[operator_surface]~[guardian_routes]~[workflow]~[deployment_store]~[license_store]~[software_deployment]~[dex]~[mcp],[pg][oidc]~[routes]~[store]~[token]~[audit_store]~[rbac_store]~[guaranteed_state_store]~[response_store]~[operator_surface]~[guardian_routes]~[workflow]~[deployment_store]~[license_store]~[software_deployment]~[dex]~[mcp],[pg][software_inventory]~[routes]~[store]~[token]~[audit_store]~[rbac_store]~[guaranteed_state_store]~[response_store]~[operator_surface]~[guardian_routes]~[workflow]~[deployment_store]~[license_store]~[software_deployment]~[dex]~[mcp]'],
       suite: ['server', 'server-pg'], timeout: 700, priority: 90)
  # 2026-08-26 (#3626): shard I's one non-DSN survivor noted above --
  # NotificationStore's "migrate_from_sqlite returns false on an unopened
  # store" ([notification_store][pg], asserts against a deliberately
  # unreachable PgPool so it needs no real DSN) -- was removed as part of
  # this branch's backfill-test-suite pruning sweep (ADR-0009). That makes
  # every one of shard I's tags fully DSN-gated, same as G/J: on a DSN-less
  # leg (the GHA-hosted macOS runner, no live Postgres) all matching cases
  # now skip, dropping the executed-case count to zero and tripping the
  # same "no tests ran" exit(4) shard E/I were split off to avoid needing
  # this flag for. Verified via --list-tests + a DSN-less local run before
  # trusting it (0/181 cases execute without the flag; --allow-running-no-tests
  # makes the identical filter exit 0). This branch's pruning sweep also
  # dropped shard B's own "RbacStore: migrate_from_sqlite returns false on
  # an unopened store" non-DSN case (its exact structural twin) -- B's
  # survivor count fell 4->3 but didn't reach zero, so B needed no flag
  # change. I was the only shard whose non-DSN survivor count reached zero;
  # verified empirically for every currently-flagless shard (A/B/C/E/F), not
  # just B, before trusting this claim.
  test('server pg unit tests shard I', server_test_exe,
       args: ['[pg][engine_principal]~[routes]~[store]~[token]~[audit_store]~[rbac_store]~[guaranteed_state_store]~[response_store]~[operator_surface]~[guardian_routes]~[workflow]~[deployment_store]~[license_store]~[software_deployment]~[dex]~[mcp]~[scim]~[guaranteed_state]~[oidc]~[software_inventory],[pg][rbac]~[routes]~[store]~[token]~[audit_store]~[rbac_store]~[guaranteed_state_store]~[response_store]~[operator_surface]~[guardian_routes]~[workflow]~[deployment_store]~[license_store]~[software_deployment]~[dex]~[mcp]~[scim]~[guaranteed_state]~[oidc]~[software_inventory],[pg][custom_props]~[routes]~[store]~[token]~[audit_store]~[rbac_store]~[guaranteed_state_store]~[response_store]~[operator_surface]~[guardian_routes]~[workflow]~[deployment_store]~[license_store]~[software_deployment]~[dex]~[mcp]~[scim]~[guaranteed_state]~[oidc]~[software_inventory],[pg][quarantine]~[routes]~[store]~[token]~[audit_store]~[rbac_store]~[guaranteed_state_store]~[response_store]~[operator_surface]~[guardian_routes]~[workflow]~[deployment_store]~[license_store]~[software_deployment]~[dex]~[mcp]~[scim]~[guaranteed_state]~[oidc]~[software_inventory],[pg][management_group]~[routes]~[store]~[token]~[audit_store]~[rbac_store]~[guaranteed_state_store]~[response_store]~[operator_surface]~[guardian_routes]~[workflow]~[deployment_store]~[license_store]~[software_deployment]~[dex]~[mcp]~[scim]~[guaranteed_state]~[oidc]~[software_inventory],[pg][notification_store]~[routes]~[store]~[token]~[audit_store]~[rbac_store]~[guaranteed_state_store]~[response_store]~[operator_surface]~[guardian_routes]~[workflow]~[deployment_store]~[license_store]~[software_deployment]~[dex]~[mcp]~[scim]~[guaranteed_state]~[oidc]~[software_inventory]',
              '--allow-running-no-tests'],
       suite: ['server', 'server-pg'], timeout: 700)
  # G DEFERS TO E's original ten tags (unchanged from the 2026-08-19 split);
  # J additionally DEFERS TO G — see the shard-E comment block above for the
  # 2026-08-25 split rationale, measurements, and verification shared by all
  # four of E/I/G/J.
  test('server pg unit tests shard G', server_test_exe,
       args: ['[pg][auth_routes]~[routes]~[store]~[token]~[audit_store]~[rbac_store]~[guaranteed_state_store]~[response_store]~[operator_surface]~[guardian_routes]~[workflow]~[deployment_store]~[license_store]~[software_deployment]~[dex]~[mcp]~[scim]~[custom_props]~[engine_principal]~[guaranteed_state]~[rbac]~[oidc]~[management_group]~[software_inventory]~[notification_store]~[quarantine],[pg][agent_service]~[routes]~[store]~[token]~[audit_store]~[rbac_store]~[guaranteed_state_store]~[response_store]~[operator_surface]~[guardian_routes]~[workflow]~[deployment_store]~[license_store]~[software_deployment]~[dex]~[mcp]~[scim]~[custom_props]~[engine_principal]~[guaranteed_state]~[rbac]~[oidc]~[management_group]~[software_inventory]~[notification_store]~[quarantine],[pg][authz]~[routes]~[store]~[token]~[audit_store]~[rbac_store]~[guaranteed_state_store]~[response_store]~[operator_surface]~[guardian_routes]~[workflow]~[deployment_store]~[license_store]~[software_deployment]~[dex]~[mcp]~[scim]~[custom_props]~[engine_principal]~[guaranteed_state]~[rbac]~[oidc]~[management_group]~[software_inventory]~[notification_store]~[quarantine],[pg][tar]~[routes]~[store]~[token]~[audit_store]~[rbac_store]~[guaranteed_state_store]~[response_store]~[operator_surface]~[guardian_routes]~[workflow]~[deployment_store]~[license_store]~[software_deployment]~[dex]~[mcp]~[scim]~[custom_props]~[engine_principal]~[guaranteed_state]~[rbac]~[oidc]~[management_group]~[software_inventory]~[notification_store]~[quarantine]',
              '--allow-running-no-tests'],
       suite: ['server', 'server-pg'], timeout: 700, priority: 65)
  test('server pg unit tests shard J', server_test_exe,
       args: ['[pg][saml]~[routes]~[store]~[token]~[audit_store]~[rbac_store]~[guaranteed_state_store]~[response_store]~[operator_surface]~[guardian_routes]~[workflow]~[deployment_store]~[license_store]~[software_deployment]~[dex]~[mcp]~[scim]~[custom_props]~[engine_principal]~[guaranteed_state]~[rbac]~[oidc]~[management_group]~[software_inventory]~[notification_store]~[quarantine]~[auth_routes]~[agent_service]~[authz]~[tar],[pg][result_set]~[routes]~[store]~[token]~[audit_store]~[rbac_store]~[guaranteed_state_store]~[response_store]~[operator_surface]~[guardian_routes]~[workflow]~[deployment_store]~[license_store]~[software_deployment]~[dex]~[mcp]~[scim]~[custom_props]~[engine_principal]~[guaranteed_state]~[rbac]~[oidc]~[management_group]~[software_inventory]~[notification_store]~[quarantine]~[auth_routes]~[agent_service]~[authz]~[tar],[pg][audit]~[routes]~[store]~[token]~[audit_store]~[rbac_store]~[guaranteed_state_store]~[response_store]~[operator_surface]~[guardian_routes]~[workflow]~[deployment_store]~[license_store]~[software_deployment]~[dex]~[mcp]~[scim]~[custom_props]~[engine_principal]~[guaranteed_state]~[rbac]~[oidc]~[management_group]~[software_inventory]~[notification_store]~[quarantine]~[auth_routes]~[agent_service]~[authz]~[tar],[pg][access_review]~[routes]~[store]~[token]~[audit_store]~[rbac_store]~[guaranteed_state_store]~[response_store]~[operator_surface]~[guardian_routes]~[workflow]~[deployment_store]~[license_store]~[software_deployment]~[dex]~[mcp]~[scim]~[custom_props]~[engine_principal]~[guaranteed_state]~[rbac]~[oidc]~[management_group]~[software_inventory]~[notification_store]~[quarantine]~[auth_routes]~[agent_service]~[authz]~[tar],[pg][secrets]~[routes]~[store]~[token]~[audit_store]~[rbac_store]~[guaranteed_state_store]~[response_store]~[operator_surface]~[guardian_routes]~[workflow]~[deployment_store]~[license_store]~[software_deployment]~[dex]~[mcp]~[scim]~[custom_props]~[engine_principal]~[guaranteed_state]~[rbac]~[oidc]~[management_group]~[software_inventory]~[notification_store]~[quarantine]~[auth_routes]~[agent_service]~[authz]~[tar],[pg][discovery]~[routes]~[store]~[token]~[audit_store]~[rbac_store]~[guaranteed_state_store]~[response_store]~[operator_surface]~[guardian_routes]~[workflow]~[deployment_store]~[license_store]~[software_deployment]~[dex]~[mcp]~[scim]~[custom_props]~[engine_principal]~[guaranteed_state]~[rbac]~[oidc]~[management_group]~[software_inventory]~[notification_store]~[quarantine]~[auth_routes]~[agent_service]~[authz]~[tar]',
              '--allow-running-no-tests'],
       suite: ['server', 'server-pg'], timeout: 700)
  test('server pg unit tests shard F', server_test_exe,
       args: ['[pg][dex]~[routes]~[store]~[token]~[audit_store]~[rbac_store]~[guaranteed_state_store]~[response_store]~[operator_surface]~[guardian_routes]~[workflow]~[deployment_store]~[license_store]~[software_deployment],[pg][mcp]~[routes]~[store]~[token]~[audit_store]~[rbac_store]~[guaranteed_state_store]~[response_store]~[operator_surface]~[guardian_routes]~[workflow]~[deployment_store]~[license_store]~[software_deployment]'],
       suite: ['server', 'server-pg'], timeout: 700, priority: 85)
  # server pg unit tests shard K — carved from shard C 2026-08-28 (Windows CI
  # test-phase restructuring, #3443): ten named store tags, none claimed by
  # any other shard's filter (grepped against every shard entry before this
  # split). Verified locally against the real binary: shard C's old filter
  # matched 640 cases; K matches 320, the new C 320 — an exact partition
  # (320 + 320 = 640), and a DSN-less run of K exits 0 (some cases assert
  # before reaching a PG-requiring line), so no --allow-running-no-tests,
  # matching shard C's own precedent. (Corrected 2026-08-28, governance
  # review: an earlier version of this comment said "832 cases (406 + 426)" —
  # wrong, measured against a since-changed intermediate state and never
  # re-verified against what actually shipped; the real binary has always
  # partitioned 640 = 320 + 320 for the filters below.)
  test('server pg unit tests shard K', server_test_exe,
       args: ['[pg][policy_store]~[routes]~[store]~[token]~[audit_store]~[rbac_store]~[guaranteed_state_store]~[response_store]~[operator_surface]~[guardian_routes]~[workflow]~[deployment_store]~[license_store]~[software_deployment]~[engine_principal]~[auth_routes]~[scim]~[saml]~[oidc]~[access_review]~[management_group]~[rbac]~[audit]~[authz]~[mcp]~[dex]~[secrets]~[quarantine]~[agent_service]~[custom_props]~[guaranteed_state]~[notification_store]~[discovery]~[software_inventory]~[result_set]~[tar],[pg][instruction_store]~[routes]~[store]~[token]~[audit_store]~[rbac_store]~[guaranteed_state_store]~[response_store]~[operator_surface]~[guardian_routes]~[workflow]~[deployment_store]~[license_store]~[software_deployment]~[engine_principal]~[auth_routes]~[scim]~[saml]~[oidc]~[access_review]~[management_group]~[rbac]~[audit]~[authz]~[mcp]~[dex]~[secrets]~[quarantine]~[agent_service]~[custom_props]~[guaranteed_state]~[notification_store]~[discovery]~[software_inventory]~[result_set]~[tar],[pg][ca_store]~[routes]~[store]~[token]~[audit_store]~[rbac_store]~[guaranteed_state_store]~[response_store]~[operator_surface]~[guardian_routes]~[workflow]~[deployment_store]~[license_store]~[software_deployment]~[engine_principal]~[auth_routes]~[scim]~[saml]~[oidc]~[access_review]~[management_group]~[rbac]~[audit]~[authz]~[mcp]~[dex]~[secrets]~[quarantine]~[agent_service]~[custom_props]~[guaranteed_state]~[notification_store]~[discovery]~[software_inventory]~[result_set]~[tar],[pg][device_token]~[routes]~[store]~[token]~[audit_store]~[rbac_store]~[guaranteed_state_store]~[response_store]~[operator_surface]~[guardian_routes]~[workflow]~[deployment_store]~[license_store]~[software_deployment]~[engine_principal]~[auth_routes]~[scim]~[saml]~[oidc]~[access_review]~[management_group]~[rbac]~[audit]~[authz]~[mcp]~[dex]~[secrets]~[quarantine]~[agent_service]~[custom_props]~[guaranteed_state]~[notification_store]~[discovery]~[software_inventory]~[result_set]~[tar],[pg][tag_store]~[routes]~[store]~[token]~[audit_store]~[rbac_store]~[guaranteed_state_store]~[response_store]~[operator_surface]~[guardian_routes]~[workflow]~[deployment_store]~[license_store]~[software_deployment]~[engine_principal]~[auth_routes]~[scim]~[saml]~[oidc]~[access_review]~[management_group]~[rbac]~[audit]~[authz]~[mcp]~[dex]~[secrets]~[quarantine]~[agent_service]~[custom_props]~[guaranteed_state]~[notification_store]~[discovery]~[software_inventory]~[result_set]~[tar],[pg][bundle]~[routes]~[store]~[token]~[audit_store]~[rbac_store]~[guaranteed_state_store]~[response_store]~[operator_surface]~[guardian_routes]~[workflow]~[deployment_store]~[license_store]~[software_deployment]~[engine_principal]~[auth_routes]~[scim]~[saml]~[oidc]~[access_review]~[management_group]~[rbac]~[audit]~[authz]~[mcp]~[dex]~[secrets]~[quarantine]~[agent_service]~[custom_props]~[guaranteed_state]~[notification_store]~[discovery]~[software_inventory]~[result_set]~[tar],[pg][pki]~[routes]~[store]~[token]~[audit_store]~[rbac_store]~[guaranteed_state_store]~[response_store]~[operator_surface]~[guardian_routes]~[workflow]~[deployment_store]~[license_store]~[software_deployment]~[engine_principal]~[auth_routes]~[scim]~[saml]~[oidc]~[access_review]~[management_group]~[rbac]~[audit]~[authz]~[mcp]~[dex]~[secrets]~[quarantine]~[agent_service]~[custom_props]~[guaranteed_state]~[notification_store]~[discovery]~[software_inventory]~[result_set]~[tar],[pg][offload_store]~[routes]~[store]~[token]~[audit_store]~[rbac_store]~[guaranteed_state_store]~[response_store]~[operator_surface]~[guardian_routes]~[workflow]~[deployment_store]~[license_store]~[software_deployment]~[engine_principal]~[auth_routes]~[scim]~[saml]~[oidc]~[access_review]~[management_group]~[rbac]~[audit]~[authz]~[mcp]~[dex]~[secrets]~[quarantine]~[agent_service]~[custom_props]~[guaranteed_state]~[notification_store]~[discovery]~[software_inventory]~[result_set]~[tar],[pg][webhook_store]~[routes]~[store]~[token]~[audit_store]~[rbac_store]~[guaranteed_state_store]~[response_store]~[operator_surface]~[guardian_routes]~[workflow]~[deployment_store]~[license_store]~[software_deployment]~[engine_principal]~[auth_routes]~[scim]~[saml]~[oidc]~[access_review]~[management_group]~[rbac]~[audit]~[authz]~[mcp]~[dex]~[secrets]~[quarantine]~[agent_service]~[custom_props]~[guaranteed_state]~[notification_store]~[discovery]~[software_inventory]~[result_set]~[tar],[pg][baseline_store]~[routes]~[store]~[token]~[audit_store]~[rbac_store]~[guaranteed_state_store]~[response_store]~[operator_surface]~[guardian_routes]~[workflow]~[deployment_store]~[license_store]~[software_deployment]~[engine_principal]~[auth_routes]~[scim]~[saml]~[oidc]~[access_review]~[management_group]~[rbac]~[audit]~[authz]~[mcp]~[dex]~[secrets]~[quarantine]~[agent_service]~[custom_props]~[guaranteed_state]~[notification_store]~[discovery]~[software_inventory]~[result_set]~[tar]'],
       suite: ['server', 'server-pg'], timeout: 700, priority: 95)
  # server pg unit tests shard L — carved from shard C 2026-08-30 (ADR-0065
  # instruction-cluster migration, PR 5): seven tags newly heavy after
  # ExecutionTracker/ApprovalManager/ScheduleEngine moved to Postgres and
  # ~200 formerly non-pg cases across their dependent test files became
  # [pg]. Measured live (this box, warm cache, YUZU_TEST_POSTGRES_DSN set):
  # shard C's old filter matched 584 cases / 116.8s; the exact-tag-plus-
  # exclusion-suffix scoped shard L filter below matches 202 cases / 14.3s,
  # the new C filter (same additions to its own exclusion list) matches
  # 382 cases / 101.6s — an exact partition (202 + 382 = 584). The
  # exclusion suffix is shard C's own (same one shard K reuses) rather than
  # a bespoke list: [rest_api_t2] is a whole-file tag in test_rest_api_t2.cpp
  # also carried by 9 device_token/software_deployment cases already
  # claimed by shard K, and [events] is shared with 5 discovery-tagged
  # cases already claimed by shard J's [pg][discovery] positive branch —
  # reusing the identical suffix here excludes exactly those already-homed
  # cases from shard L instead of duplicating them, which a naive
  # `[pg][tag]` OR-list without the suffix would have done (verified: the
  # naive form matched 258, not 202). A DSN-less run of L exits 0 (some
  # cases assert before reaching a PG-requiring line), matching shard C/K's
  # own precedent.
  test('server pg unit tests shard L', server_test_exe,
       args: ['[pg][approval_manager]~[routes]~[store]~[token]~[audit_store]~[rbac_store]~[guaranteed_state_store]~[response_store]~[operator_surface]~[guardian_routes]~[workflow]~[deployment_store]~[license_store]~[software_deployment]~[engine_principal]~[auth_routes]~[scim]~[saml]~[oidc]~[access_review]~[management_group]~[rbac]~[audit]~[authz]~[mcp]~[dex]~[secrets]~[quarantine]~[agent_service]~[custom_props]~[guaranteed_state]~[notification_store]~[discovery]~[software_inventory]~[result_set]~[tar]~[policy_store]~[instruction_store]~[ca_store]~[device_token]~[tag_store]~[bundle]~[pki]~[offload_store]~[webhook_store]~[baseline_store],[pg][execution_tracker]~[routes]~[store]~[token]~[audit_store]~[rbac_store]~[guaranteed_state_store]~[response_store]~[operator_surface]~[guardian_routes]~[workflow]~[deployment_store]~[license_store]~[software_deployment]~[engine_principal]~[auth_routes]~[scim]~[saml]~[oidc]~[access_review]~[management_group]~[rbac]~[audit]~[authz]~[mcp]~[dex]~[secrets]~[quarantine]~[agent_service]~[custom_props]~[guaranteed_state]~[notification_store]~[discovery]~[software_inventory]~[result_set]~[tar]~[policy_store]~[instruction_store]~[ca_store]~[device_token]~[tag_store]~[bundle]~[pki]~[offload_store]~[webhook_store]~[baseline_store],[pg][execution_statistics]~[routes]~[store]~[token]~[audit_store]~[rbac_store]~[guaranteed_state_store]~[response_store]~[operator_surface]~[guardian_routes]~[workflow]~[deployment_store]~[license_store]~[software_deployment]~[engine_principal]~[auth_routes]~[scim]~[saml]~[oidc]~[access_review]~[management_group]~[rbac]~[audit]~[authz]~[mcp]~[dex]~[secrets]~[quarantine]~[agent_service]~[custom_props]~[guaranteed_state]~[notification_store]~[discovery]~[software_inventory]~[result_set]~[tar]~[policy_store]~[instruction_store]~[ca_store]~[device_token]~[tag_store]~[bundle]~[pki]~[offload_store]~[webhook_store]~[baseline_store],[pg][schedule_engine]~[routes]~[store]~[token]~[audit_store]~[rbac_store]~[guaranteed_state_store]~[response_store]~[operator_surface]~[guardian_routes]~[workflow]~[deployment_store]~[license_store]~[software_deployment]~[engine_principal]~[auth_routes]~[scim]~[saml]~[oidc]~[access_review]~[management_group]~[rbac]~[audit]~[authz]~[mcp]~[dex]~[secrets]~[quarantine]~[agent_service]~[custom_props]~[guaranteed_state]~[notification_store]~[discovery]~[software_inventory]~[result_set]~[tar]~[policy_store]~[instruction_store]~[ca_store]~[device_token]~[tag_store]~[bundle]~[pki]~[offload_store]~[webhook_store]~[baseline_store],[pg][schedule]~[routes]~[store]~[token]~[audit_store]~[rbac_store]~[guaranteed_state_store]~[response_store]~[operator_surface]~[guardian_routes]~[workflow]~[deployment_store]~[license_store]~[software_deployment]~[engine_principal]~[auth_routes]~[scim]~[saml]~[oidc]~[access_review]~[management_group]~[rbac]~[audit]~[authz]~[mcp]~[dex]~[secrets]~[quarantine]~[agent_service]~[custom_props]~[guaranteed_state]~[notification_store]~[discovery]~[software_inventory]~[result_set]~[tar]~[policy_store]~[instruction_store]~[ca_store]~[device_token]~[tag_store]~[bundle]~[pki]~[offload_store]~[webhook_store]~[baseline_store],[pg][events]~[routes]~[store]~[token]~[audit_store]~[rbac_store]~[guaranteed_state_store]~[response_store]~[operator_surface]~[guardian_routes]~[workflow]~[deployment_store]~[license_store]~[software_deployment]~[engine_principal]~[auth_routes]~[scim]~[saml]~[oidc]~[access_review]~[management_group]~[rbac]~[audit]~[authz]~[mcp]~[dex]~[secrets]~[quarantine]~[agent_service]~[custom_props]~[guaranteed_state]~[notification_store]~[discovery]~[software_inventory]~[result_set]~[tar]~[policy_store]~[instruction_store]~[ca_store]~[device_token]~[tag_store]~[bundle]~[pki]~[offload_store]~[webhook_store]~[baseline_store],[pg][rest_api_t2]~[routes]~[store]~[token]~[audit_store]~[rbac_store]~[guaranteed_state_store]~[response_store]~[operator_surface]~[guardian_routes]~[workflow]~[deployment_store]~[license_store]~[software_deployment]~[engine_principal]~[auth_routes]~[scim]~[saml]~[oidc]~[access_review]~[management_group]~[rbac]~[audit]~[authz]~[mcp]~[dex]~[secrets]~[quarantine]~[agent_service]~[custom_props]~[guaranteed_state]~[notification_store]~[discovery]~[software_inventory]~[result_set]~[tar]~[policy_store]~[instruction_store]~[ca_store]~[device_token]~[tag_store]~[bundle]~[pki]~[offload_store]~[webhook_store]~[baseline_store]'],
       suite: ['server', 'server-pg'], timeout: 700, priority: 92)
  test('server pg unit tests shard C', server_test_exe,
       args: ['[pg]~[routes]~[store]~[token]~[audit_store]~[rbac_store]~[guaranteed_state_store]~[response_store]~[operator_surface]~[guardian_routes]~[workflow]~[deployment_store]~[license_store]~[software_deployment]~[engine_principal]~[auth_routes]~[scim]~[saml]~[oidc]~[access_review]~[management_group]~[rbac]~[audit]~[authz]~[mcp]~[dex]~[secrets]~[quarantine]~[agent_service]~[custom_props]~[guaranteed_state]~[notification_store]~[discovery]~[software_inventory]~[result_set]~[tar]~[policy_store]~[instruction_store]~[ca_store]~[device_token]~[tag_store]~[bundle]~[pki]~[offload_store]~[webhook_store]~[baseline_store]~[approval_manager]~[execution_tracker]~[execution_statistics]~[schedule_engine]~[schedule]~[events]~[rest_api_t2]'],
       suite: ['server', 'server-pg'], timeout: 700, priority: 100)

  # #3443 Phase 2: PG portability smoke subset - runs INSTEAD of the 11 shards
  # above on the 3 non-primary Linux push legs (ci.yml pg_mode=smoke); the
  # gcc-15/debug leg (every PR, plus the primary push leg) keeps the full
  # server-pg suite unchanged. Membership is the [pg-smoke] tag, hand-picked
  # across 11 existing cases for libpq connection/RAII, migration, CRUD,
  # NULL-vs-empty, pool exhaustion/reconnect, GUC hardening, transaction
  # rollback, a real BYTEA+bigint wire round-trip, and UTF-8 truncation -
  # enough to prove libpq linkage + basic runtime behavior without paying
  # full PG-shard cost. Measured live (this box, warm cache): 280 assertions
  # in 11 cases, ~2.8s.
  #
  # 'server pg shard partition invariant' below proves this is a nonzero,
  # EXACT-count (SMOKE_EXACT_CASES in check-pg-shard-partition.py), correctly-
  # named, correctly-flagged subset of [pg] - not a hand-maintained duplicate
  # of the tag list, the exact defect class Phase 1 exists to cure.
  #
  # NOT in suite server-pg: the partition invariant above would see these 11
  # cases as double-claimed (already owned by their real shards). suite:
  # 'server-pg-smoke' is a dedicated suite so the smoke entry stays outside
  # that partition while still being --suite-selectable on its own.
  #
  # --allow-running-no-tests is REQUIRED here (unlike Correction 1's original
  # "no flag" wording): every [pg-smoke] case is all-DSN-gated, so a flagless
  # entry would exit 4 (Catch2's AllTestsSkippedExitCode) on every DSN-less
  # UNFILTERED `meson test` - local dev without Postgres, and any future
  # sanitizer/nightly leg that runs the whole suite - breaking the documented
  # skip contract in test_helpers.hpp. Loud-fail duty for a broken/missing DSN
  # moves to ci.yml's own "Resolve pg_mode + assert Postgres DSN" step instead
  # (checked BEFORE this or any other PG invocation runs) and to the checker's
  # exact-count + flag-present assertions below.
  #
  # Invoked BY NAME from ci.yml, not by --suite: meson's positional test-name
  # matching is an exact match (fnmatch with no glob characters in a literal
  # name, mtest.py's tests_from_args) - a rename that doesn't update the
  # ci.yml invocation errors loud ("test name does not match any test"), it
  # does not silently keep matching on a substring. A --suite typo, by
  # contrast, would exit 0 silently on a plain `meson test` RUN (mtest.py's
  # get_tests/doit print "No suitable tests defined" and return success) -
  # by-name selection is the one that fails safe on the real CI invocation.
  # NOTE (adversarial review, both reviewers independently probed this):
  # `meson test --list --suite <bad>` is a DIFFERENT code path and exits 1 -
  # only the plain run (what ci.yml actually invokes, no --list) exits 0.
  #
  # Runs REDUNDANTLY (harmless, ~11 cases/seconds) under any unfiltered
  # `meson test` - local dev, nightly.yml's 3 unfiltered legs,
  # sanitizer-tests.yml's 2 unfiltered legs - since every test() entry runs
  # once there regardless of suite; these 11 cases already run once via their
  # owning shard too. Not worth special-casing for that cost.
  #
  # timeout: 60s is ~20x the measured solo cost (2.8s, 280 assertions) -
  # generous margin for CI box contention (this step is deliberately UNGATED
  # by with-test-slot.sh, see ci.yml) while still catching a genuine hang.
  test('server pg smoke', server_test_exe,
       args: ['[pg-smoke]', '--allow-running-no-tests'],
       suite: ['server', 'server-pg-smoke'], timeout: 60)

  # Structural partition-invariant check (Phase 1, #3443). Proves every
  # [pg]-tagged case above lands in EXACTLY ONE 'server-pg'-suite shard --
  # against the real compiled binary via --list-tests, not a hand-maintained
  # pin of the filter strings above (the pin that replaced -- see
  # scripts/ci/flake-retry.py's own selftest -- had to be updated by hand on
  # every split/rebalance and was missed 3 times in as many weeks, each time
  # reddening CI unconditionally). Discovery is via `meson introspect --tests`
  # keyed on suite membership, so adding/splitting/rebalancing a shard needs
  # no update here: give the new/changed test() entry the right suite: kwarg
  # (['server', 'server-pg']) and this check verifies the rest on its own.
  # depends: ensures ninja builds the binary before this runs; it needs no
  # Postgres DSN (--list-tests only enumerates TEST_CASE macros, never runs
  # one).
  #
  # EXTENDED Phase 2 (#3443) to also prove 'server pg smoke' above (suite:
  # 'server-pg-smoke') is a genuine subset: exactly one entry, the expected
  # name, the expected exact case count, --allow-running-no-tests present,
  # and every matched case also carries [pg] (script's check_smoke()).
  _pg_shard_python3 = find_program('python3', 'python')
  test('server pg shard partition invariant',
    _pg_shard_python3,
    args: [files('../scripts/ci/check-pg-shard-partition.py'),
           '--builddir', meson.project_build_root()],
    suite: ['server', 'server-checks'],
    depends: [server_test_exe],
    timeout: 60,
  )

  # 2026-08-20 (ADR-0056, PolicyStore, batch-6): PolicyStore moved off SQLite
  # onto Postgres, and test_policy_store.cpp / test_policy_evaluator.cpp went
  # from carrying zero [pg]-tagged cases to 57 ([policy_store][pg], one
  # holdout case tests an unreachable-pool failure path and stays untagged
  # on purpose — 58 [policy_store] cases total) + 11 ([pg][policy][evaluator])
  # = 68 new [pg] cases. Neither tag appears outside its one file (grep -rl
  # checked). No shard's tag list names [policy_store]/[policy]/[evaluator],
  # so — unlike every prior addition recorded above — this needed no
  # meson.build edit to land correctly: the 68 cases fall into shard C by the
  # catch-all's own exclusion list, automatically, same as any tag never
  # added to A/B/D/E/F/G.
  #
  # Measured whether that default placement was SAFE rather than assuming it
  # (per this file's own house rule) — isolated, live Postgres, this box:
  # [policy_store] 58 cases (57 [pg] + the 1 untagged) 2.9s; [pg][policy]
  # [evaluator] 11 cases 2.1s — cheap, ~0.07s/case, nothing like [rbac_store]'s
  # per-case outlier rate. Shard C itself, before vs after (--list-tests
  # case counts, then a full live-PG run of each): 336 cases/88.0s ->
  # 404 cases/92.7s (meson test: 92.69s) — a ~4.7s/5% shift tracking the
  # isolated measurement almost exactly. 92.69/600s is ~15% of budget, nowhere
  # near the ceiling that drove the [license_store]/[software_deployment]
  # dedicated-shard-D precedent (both of those reacted to a shard already AT
  # or OVER 600s) — so a dedicated [policy_store] tag on D was considered and
  # NOT taken; leaving both files' cases in shard C is correct as-is, no
  # rebalance needed. Revisit if shard C's own growth later pushes it toward
  # budget and this population no longer looks cheap in isolation.
  #
  # Partition reverified after the merge: A 559 / B 93 / D 410 / E 404 /
  # F 193 / G 351 / C 404, summing to the current whole-binary [pg] total of
  # 2414 exactly — zero double-counted, zero missing.

  # ── #2519 MCP bridge teardown allocation-budget probe (separate binary) ────
  # Same rationale as the #2270 spark probe above: a global operator new/delete
  # replacement is process-wide, so it cannot share the multi-thousand-case
  # server binary, and it must be ABSENT (not merely disabled) from sanitizer
  # builds, which own the allocator themselves. Linux-only for the same
  # ELF/libstdc++-interposition reason; see the file header.
  if host_machine.system() == 'linux' and get_option('b_sanitize') == 'none'
    mcp_bridge_alloc_budget_exe = executable(
      'yuzu_mcp_bridge_alloc_budget_tests',
      files('unit/server/test_mcp_bridge_alloc_budget.cpp'),
      cpp_args: https_cpp_args + test_partial_init_args +
                (cxx.get_id() == 'msvc' ? ['/bigobj'] : []),
      dependencies: [yuzu_server_core_dep, catch2_dep,
                     dependency('openssl', required: true, include_type: 'system')],
    )
    test(
      'mcp bridge teardown allocation budget',
      mcp_bridge_alloc_budget_exe,
      suite: ['server', 'server-checks'],
      timeout: 60,
    )
  endif
endif

# ── Proto codegen tests ────────────────────────────────────────────────────
_python3_test = find_program('python3', 'python')
test('proto gen_proto version check',
  _python3_test,
  args: [files('test_gen_proto_version.py')],
  suite: 'proto',
  timeout: 30,
)

# ── Gateway build wrapper ──────────────────────────────────────────────────
# scripts/build_gateway.py (+ the shared erlang_toolchain.py) driven with a
# fake Python child — no Erlang needed, so it runs on every leg, including the
# Windows one whose stdio/timeout/Ctrl-C behaviour it mostly pins. ~51s
# measured (Windows and Linux); several cases deliberately wait out a
# grandchild to prove the whole tree was killed, so the timeout leaves room
# for a loaded shared runner box.
test('gateway build wrapper',
  _python3_test,
  args: [files('test_build_gateway.py')],
  suite: 'docs',
  timeout: 180,
)

# ── Repo hygiene tests ─────────────────────────────────────────────────────
test('changelog order',
  _python3_test,
  args: [files('test_changelog_order.py')],
  suite: 'docs',
  timeout: 10,
)

# PR1.9 data-gate: every plugin action has exactly one capability-catalogue row
# across the six fragment headers, and no fragment claims an action no plugin
# declares. Hermetic — parses sources, builds nothing.
test('capability catalogue completeness',
  _python3_test,
  args: [files('test_capability_catalogue_complete.py')],
  suite: 'docs',
  timeout: 30,
)

# #1398 data-gate: every capability-catalogue row's authored ExecuteGate
# matches the strictest approval.mode any shipped InstructionDefinition
# declares for that plugin.action pair, and a content-declared pair with no
# catalogue row is exempt from gating only when it is server-side (never
# agent-dispatched). Hermetic — parses sources, builds nothing.
test('capability gate consistency',
  _python3_test,
  args: [files('test_capability_gate_consistency.py')],
  suite: 'docs',
  timeout: 30,
)

# firmware_posture's definition-column contract (content/definitions/firmware_posture.yaml):
# row_kind must be the first result column and the order must match the wire row
# firmware_posture_parsers.hpp emits. Parses the YAML directly -- catches a reordered or
# renamed column the C++ test's hard-coded literal cannot.
test('firmware_posture definition columns',
  _python3_test,
  args: [files('test_firmware_posture_definition.py')],
  suite: 'docs',
  timeout: 30,
)

# runtimes' definition-column contract (content/definitions/runtimes.yaml): row_kind first and the
# column order match the wire row runtimes_parsers.hpp emits; parses the YAML directly.
test('runtimes definition columns',
  _python3_test,
  args: [files('test_runtimes_definition.py')],
  suite: 'docs',
  timeout: 30,
)

# Plugin README standard (docs/plugin-readme-standard.md): unit tests of the
# generator's pure functions, then the tree gate — README-existence ratchet,
# section contract, generated fences/index/nav/manifests byte-match the
# sources, every supported leg has a parseable capture with a current
# leg-hash. Hermetic — parses sources, builds nothing.
test('plugin doc-gen unit',
  _python3_test,
  args: [files('test_plugin_doc_gen.py')],
  suite: 'docs',
  timeout: 30,
)
test('plugin readme gate',
  _python3_test,
  args: [files('test_plugin_readmes.py')],
  suite: 'docs',
  # Measured ~25-31s standalone; the self-hosted runner pools share one OS
  # identity across 4 runner agents on one box (CLAUDE.md's documented
  # shared-runner-under-load invariant), and this test was observed hitting
  # the old 60s timeout under exactly that kind of concurrent docs-suite
  # load on this session's own Mac (governance Gate 3, build-ci finding).
  timeout: 120,
)

# Prometheus alert-rule unit tests (#2553). The same script the docs-lint
# workflow runs, so self-hosted legs and /test exercise the same code path CI
# does -- WHEREVER A USABLE PROMTOOL IS PRESENT. No CI leg sets the opt-in below
# and none is documented as carrying a 3.x promtool, so the realistic outcome on
# all three is SKIP; the authoritative run is the workflow job. Rationale for the
# tests themselves: tests/prometheus/run_promtool_tests.py.
#
# DOES NOT PULL A CONTAINER unless you opt in. `scripts/ci/flake-retry.py` runs
# `meson test` with NO --suite filter on three REQUIRED build legs, so a
# docker-dependent test registered here puts a container registry on all three;
# an earlier version of this wiring did exactly that and was reverted. Without
# YUZU_TEST_ENABLE_PROMTOOL_DOCKER the harness needs a native promtool of the
# pinned major and skips (77) otherwise.
#
# TIMEOUT (#2340 PR-4): the harness now runs TWO full gates per invocation -
# the shipped RULES/TESTS pair, then the marker-extracted yuzu-guardian-journal
# group (CH-2 + CH-5-PROM) - each up to 4x120s (check + test + the canary's own
# test + check) = 480s worst case, plus ~225s for the docker daemon probe and
# pull ladder under the opt-in (0 under a native promtool). Worst case is
# 225 + 480x2 = 1185s; 1500 keeps ~300s of margin over that, the same
# methodology run_promtool_tests.py's own pull_with_retry() comment uses for
# its ladder ("must fit inside the timeouts that enclose it") - see that
# comment for the full arithmetic and how it composes with the CI job's own
# `timeout-minutes` in docs-lint.yml.
test('prometheus alert rules',
  _python3_test,
  args: [files('prometheus/run_promtool_tests.py')],
  suite: 'docs',
  timeout: 1500,
)

# Pure-logic selftest for the harness above (version-banner parsing, docker argv
# construction, the pin's own shape). No promtool, no docker, no network, so it
# runs everywhere -- mirroring the flake-retry and plugin-spawn selftests below.
test('prometheus harness selftest',
  _python3_test,
  args: [files('prometheus/run_promtool_tests.py'), '--selftest'],
  suite: 'docs',
  timeout: 30,
)

# Audit-retention alert coverage manifest gate (#2854 rung B). Same
# SKIP-vs-FAIL contract as the entry above -- no CI leg here sets
# YUZU_TEST_ENABLE_PROMTOOL_DOCKER and none carries a 3.x native promtool, so
# the realistic local/CI-matrix outcome is SKIP (77); the authoritative run is
# the docs-lint.yml `prometheus-rules` job, which does set the opt-in.
# Timeout sized to the sweep's own worst-case ceiling, not typical runtime:
# with both scenarios' alerts shipped (#2854 rung D) all 6 (scenario,
# interval) measure() calls run for real -- pull ladder ~195s plus 6 x
# (30s check + 90s test) = ~915s -- so 1200 keeps a real margin over that.
# A third sweep scenario adds another ~360s: re-derive, don't inherit.
test('audit retention alert coverage manifest',
  _python3_test,
  args: [files('prometheus/blind_band_sweep.py'), '--check'],
  suite: 'docs',
  timeout: 1200,
)

# Pure-logic selftest for the sweep (cycles_for, the seconds-resolution grid,
# extract()'s present/absent handling, the manifest compare()). No promtool,
# no docker, no network.
test('audit retention coverage sweep selftest',
  _python3_test,
  args: [files('prometheus/blind_band_sweep.py'), '--selftest'],
  suite: 'docs',
  timeout: 30,
)

# Tracker close-automation regression corpus (ADR-3001 A1 §11-§12): the frozen
# parser fixtures (incl. PR #1711, the canonical negated close) + the decision
# ladder's never-close/fail-closed/cap contracts. No network. scripts/ changes
# always run the heavy platform jobs, so meson coverage alone is sufficient.
test('close automation logic',
  _python3_test,
  args: [files('test_close_automation.py')],
  suite: 'docs',
  timeout: 30,
)

# The native Windows runner contract is pure PowerShell with injected fixture
# probes, so it is safe on every host that has pwsh. Keeping it in the docs
# suite makes deleted schema/probe coverage fail in CI instead of depending on
# an operator remembering the standalone command before provisioning.
_pwsh_test = find_program('pwsh', required: false)
if _pwsh_test.found()
  test('Windows toolchain contract',
    _pwsh_test,
    args: ['-NoProfile', '-File', files('../deploy/windows/Test-ToolchainContract.ps1')],
    suite: 'docs',
    timeout: 30,
  )
endif

# flake-retry's pure-logic selftest (tag-spec surgery, suite matching, junit
# parsing, budget rows). Wired here (#2092) so the shard-retry contract the
# server entries above rely on is enforced on every platform, not just when
# someone remembers to run it by hand.
test('flake-retry selftest',
  _python3_test,
  args: [files('../scripts/ci/flake-retry.py'), '--selftest'],
  suite: 'docs',
  timeout: 30,
)

# PR1.2 (ADR-3002 Decision-10a): pure-logic selftest of the lexical spawn gate —
# a seeded raw-spawn fixture must fail and the sanctioned-runner allowlist case
# must pass. Wired here so the gate's own matcher is enforced on every platform
# with bash, mirroring the flake-retry selftest above. Guarded so Windows (no
# bash) skips cleanly rather than erroring at configure.
_bash_test = find_program('bash', required: false)
if _bash_test.found()
  test('plugin-spawn lexical gate selftest',
    _bash_test,
    args: [files('../scripts/ci/check-plugin-spawn-lexical.sh'), '--selftest'],
    suite: 'docs',
    timeout: 60,
  )
  # docs/plugin-readme-standard.md rule 7 — the README touch rule's own
  # fixture run (a fake `git` on PATH; no repository, no network).
  test('plugin readme touch-rule selftest',
    _bash_test,
    args: [files('../scripts/ci/check-plugin-readme-touch.sh'), '--selftest'],
    suite: 'docs',
    timeout: 60,
  )
  # #4262: -Dbuild_examples=false must keep configuring a real build.
  # Configure-only smoke test (no compile) so it stays cheap on every leg;
  # SKIPs cleanly when vcpkg_installed/<triplet> isn't populated yet.
  test('build_examples=false gating smoke test',
    _bash_test,
    args: [files('shell/test_build_examples_gating.sh')],
    suite: 'docs',
    timeout: 120,
  )
endif

# QE-INFO / build-ci B3: tests/shell/test_capability_matrix_gate.sh (PR1.1
# finding F10 — see the abi4_declared_fixture_plugin comment near the top of
# this file) was wired ONLY as a separate post-build step in ci.yml, never as
# a meson test(), so a local `meson test` never ran it. Wiring it here also
# gives abi4_declared_fixture_plugin its first `depends:` entry anywhere in
# the meson graph: until now it built ONLY via build_by_default, so nothing
# noticed if it silently stopped building (build-ci B3).
#
# capmatrix-gen itself cannot be added to `depends:` here: the top-level
# meson.build subdirs `tools/capmatrix-gen` AFTER `tests`, so its
# executable() object is not yet in scope in this file — reordering that is
# a root-meson.build change outside this package. The script hard-requires
# the binary to already exist (`[ -e "$CAPGEN" ]`) and fails loudly, exactly
# as it does from its ci.yml step today, so a build that skipped it is still
# caught — just by this test failing rather than by the meson graph refusing
# to schedule it.
#
# CDX-P1-04/K-5: that "caught, not skipped" reasoning only holds when
# capmatrix-gen SHOULD have been built. Under `-Dbuild_agent=false` the
# top-level build deliberately never builds capmatrix-gen at all — there is
# no agent, no plugins, nothing for it to inspect — so this test's hard
# `[ -x "$CAPGEN" ]` requirement would fail loudly for a configuration that
# is correct by design, not broken. Gate registration on the SAME condition
# tools/capmatrix-gen's own build is gated on (root meson.build: `if
# build_agent`), so `-Dbuild_agent=false` (with -Dbuild_tests=true) gets a
# clean `meson test` rather than a false-red gate. `build_examples` is
# deliberately NOT part of this condition (#4262): every real plugin now
# builds unconditionally under build_agent regardless of build_examples, so
# capmatrix-gen always has something to inspect once build_agent is on.
if _bash_test.found() and meson.can_run_host_binaries() and build_agent
  test('capability matrix gate shell tests (#2204 F10)',
    _bash_test,
    args: [files('shell/test_capability_matrix_gate.sh'), meson.project_build_root()],
    suite: 'docs',
    timeout: 120,
    depends: [
      abi3_fixture_plugin,
      abi4_declared_fixture_plugin,
      abi4_cpp_wrapper_fixture_plugin,
    ],
  )
endif

# #4666 PR-2 W3a: static lexical gate over main.cpp's log-handoff wiring call sites (the
# four textual invariants agent_log_wiring.hpp's/log_handoff.hpp's own header banners
# describe -- see the script's own header). No build required, so gated only on bash
# being present, same as the other lexical selftests above.
if _bash_test.found()
  test('log handoff wiring lexical gate (#4666 PR-2 W3a)',
    _bash_test,
    args: [files('shell/test_log_handoff_wiring_lexical.sh')],
    suite: 'agent',
    timeout: 60,
  )
endif

# #4666 PR-2 W3a MI-2: report-only symbol-binding probe over the built exe/core-lib/
# agent_actions plugin (see the script's own header for what it does and does not prove).
# Gated on build_agent the same way the capability matrix gate above is -- nothing to
# inspect without a real agent build.
if _bash_test.found() and meson.can_run_host_binaries() and build_agent
  test('spdlog registry identity symbol-binding report (#4666 PR-2 W3a MI-2)',
    _bash_test,
    args: [files('shell/test_spdlog_registry_identity.sh'), meson.project_build_root()],
    suite: 'agent',
    timeout: 60,
    depends: [
      yuzu_agent_exe,
      yuzu_agent_core_lib,
      agent_actions_plugin_lib,
    ],
  )
endif

# #4666 PR-2 acceptance-evidence harness: formalizes the hand-verified manual
# repro of the blocked-log-sink SIGTERM scenario (main.cpp's async log
# hand-off, log_handoff.hpp) into a committed, repeatable shell test against
# the real yuzu-agent binary. Linux-only -- the blockage-detection mechanism
# reads /proc/<pid>/task/*/wchan, which has no equivalent on macOS/Windows.
# `yuzu_agent_exe` (agents/core/meson.build) is named specifically so this
# depends: entry can pin the real agent binary as a build dependency.
if (_bash_test.found() and meson.can_run_host_binaries() and build_agent
    and host_machine.system() == 'linux')
  test('blocked log sink SIGTERM harness (#4666 PR-2)',
    _bash_test,
    args: [files('shell/test_blocked_log_sink_sigterm.sh'), meson.project_build_root()],
    suite: 'agent',
    timeout: 300,
    depends: [yuzu_agent_exe],
  )
endif

# End-to-end fake-Meson contract. In particular, an expired/malformed flake
# registry must fail before the real test runner could be invoked. The script
# uses POSIX executable fakes and returns a clean platform skip on Windows.
test('flake-retry integration selftest',
  _python3_test,
  args: [files('../scripts/ci/test_flake_retry.py')],
  suite: 'docs',
  timeout: 30,
)

# check-pg-shard-partition.py's own detection logic (#3443 Phase 1, governance
# Gate 3/4: shipped with no permanent regression test, only ad-hoc uncommitted
# manual mutation testing). Pure-function unit test against synthetic
# `meson introspect`/Catch2-XML fixtures -- no real build needed, matching why
# this lives in the cheap docs suite alongside flake-retry's own selftests
# rather than needing a real yuzu_server_tests binary the way the checker's
# OWN meson test() entry (search 'server pg shard partition invariant') does.
test('check-pg-shard-partition selftest',
  _python3_test,
  args: [files('../scripts/ci/test_check_pg_shard_partition.py')],
  suite: 'docs',
  timeout: 30,
)

# assert-suite-cover.py's own detection logic (#3443 Windows restructuring,
# governance Gate 3: shipped with no permanent regression test, the same gap
# check-pg-shard-partition.py had before the entry above closed it). Pure-
# function unit test against synthetic `meson introspect --tests` fixtures,
# same cheap-docs-suite precedent as its sibling above.
test('assert-suite-cover selftest',
  _python3_test,
  args: [files('../scripts/ci/test_assert_suite_cover.py')],
  suite: 'docs',
  timeout: 30,
)

# Issue-lifecycle hygiene (ADR-3001 A1): CLAUDE.md character budget,
# do-not-close.txt parses clean (the never-close guard every automated close
# path reads), and issue-standard.md keeps its never-close section.
test('issue lifecycle docs',
  _python3_test,
  args: [files('test_issue_docs.py')],
  suite: 'docs',
  timeout: 10,
)

# RBAC doc/seed parity (#480): rbac.md's system-role, securable-type, operation
# and authorization-topology-floor tables must match rbac_store.cpp's seed
# arrays and authz_topology_floor.hpp's kTopologyFloor. Also runs in
# .github/workflows/docs-lint.yml on every PR; registered here for local
# `meson test --suite docs` parity with the sibling python doc-tests.
test('rbac doc counts',
  _python3_test,
  args: [files('test_rbac_doc_counts.py')],
  suite: 'docs',
  timeout: 10,
)

# ADR-0032 split interlock merge-gate: the tripwire (no engine-path symbol may
# merge while the gate is red) and its self-test (the ledger's load-bearing
# constants are pinned so the gate cannot be silently neutered). Both also run in
# .github/workflows/docs-lint.yml on every PR; registered here for local `meson
# test --suite docs` parity with the sibling python doc-tests.
test('split interlock tripwire',
  _python3_test,
  args: [files('test_split_interlock_tripwire.py')],
  suite: 'docs',
  timeout: 30,
)
test('split interlock tripwire selftest',
  _python3_test,
  args: [files('test_split_interlock_tripwire_selftest.py')],
  suite: 'docs',
  timeout: 30,
)

# #1611 tripwire: the TSan suppression in unit/test_runner_main.cpp is honest
# only while no first-party code references the conn-less libpq escape APIs
# PQescapeString/PQescapeBytea (libpq's sole readers of the suppressed globals).
# Also runs in .github/workflows/docs-lint.yml on every PR.
test('no conn-less libpq escape references',
  _python3_test,
  args: [files('test_no_connless_pq_escape.py')],
  suite: 'docs',
  timeout: 30,
)

# #4665 lockstep: the #4606-pinned format_arm_committed_line shape
# (tests/unit/fixtures/spark/arm_committed_line.json) still parses through the #3990
# driver's own T2_RE, and the driver's evidence regexes still refuse a forged rule-id/Spark-key
# free-text injection. Also runs in .github/workflows/docs-lint.yml on every PR.
test('spark evidence format lockstep (#4665)',
  _python3_test,
  args: [files('test_spark_evidence_format_lockstep.py')],
  suite: 'docs',
  timeout: 30,
)

# #4665 regression net: a position-aware lexical scanner over the Guardian/Spark
# subsystem (agents/core/src + server/core/src + common/include, filtered to the
# guardian_*/guard_*/spark_*/guaranteed_state* basename glob) that fails the moment
# a NEW spdlog:: call prints a rule-id/Spark-key-shaped argument unwrapped -- see the
# script's own module docstring for the full design (why position-aware, file scope,
# known limitations). Also runs in .github/workflows/docs-lint.yml on every PR.
test('guardian/spark log-injection tripwire (#4665)',
  _python3_test,
  args: [files('test_guardian_spark_log_injection_tripwire.py')],
  suite: 'docs',
  timeout: 30,
)

# Runner-local CI telemetry contract: v2->v3 migration preserves history,
# GitHub reruns remain distinct, and Meson suite durations/timeouts plus known
# flake recoveries land in the persistent per-runner test-runs.db.
test('ci telemetry selftest',
  _python3_test,
  args: [files('../scripts/ci/test_ci_telemetry.py')],
  suite: 'docs',
  timeout: 30,
)

# Windows SDK is selected at four independent boundaries: native MSYS2,
# runner provisioning/manifest, GHA environment activation, and documentation.
# Keep them exact and keep the GHA action itself visible to Dependabot.
test('windows sdk contract',
  _python3_test,
  args: [files('test_windows_sdk_contract.py')],
  suite: 'docs',
  timeout: 10,
)

# The nightly TSan gdb capture's pure-logic selftest (#1038): junit -> failing
# entries, testlog.txt -> per-entry Catch2 seed, introspect -> binary + args, and
# the cancelled-path "which entry never finished" inference. It reuses
# flake-retry.py's junit-name -> introspected-entry mapping rather than keeping a
# second copy, so the shard-naming contract documented above now has two
# consumers — and this selftest is what makes a break in it loud. Wired here for
# the same reason flake-retry's is: the alternative to failing in `meson test` is
# failing silently at 06:00 UTC, in the one nightly that needed a stack trace.
test('tsan-gdb-capture selftest',
  _python3_test,
  args: [files('../scripts/ci/tsan-gdb-capture.py'), '--selftest'],
  suite: 'docs',
  timeout: 30,
)
