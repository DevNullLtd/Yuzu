# OpenSSL is required on every platform — used by:
#   * updater.cpp + plugin_loader.cpp SHA-256 (Linux/macOS path; Windows
#     SHA-256 still goes through bcrypt for the digest, but
#   * plugin_loader.cpp CMS signature verification needs OpenSSL
#     unconditionally (CMS_verify, X509_STORE) so the verifier behaves
#     identically on all hosts. On Windows libssl/libcrypto are already
#     linked transitively via gRPC; this declaration just brings in the
#     include path so #include <openssl/cms.h> resolves.
agent_openssl_dep = dependency('openssl', required: true, include_type: 'system')
agent_crypto_deps = [agent_openssl_dep]

# Linux: the systemd service guard (guard_systemd.cpp) AND the Service spark
# mechanism (spark_service.cpp, ADR-0021 Stage 1 PR 1c) watch unit run-state over
# sd-bus, which libsystemd provides. Both are wrapped in
# `#if defined(__linux__) && defined(YUZU_HAVE_LIBSYSTEMD)` and compile to a no-op
# stub (start() returns false / make_service_mechanism() returns nullptr, like the
# off-Linux build) when libsystemd is not used. The `systemd_guard` feature option
# (default `enabled`) controls the dependency for BOTH:
#   enabled  — require libsystemd, so the shipped agent always offers the guard and a
#              build that has lost libsystemd-dev FAILS loudly instead of silently
#              shipping a guard-less agent. Default ⇒ CI / Docker / release stay
#              unchanged and keep the guarantee with no extra flags.
#   auto     — use libsystemd if found, else build the no-op stub (no configure error).
#   disabled — always build the no-op stub.
# Pass `-Dsystemd_guard=auto` (or `disabled`) for musl/Alpine/non-systemd/minimal
# images where libsystemd is absent.
agent_platform_deps = []
agent_platform_args = []
if host_machine.system() == 'linux'
  libsystemd_dep = dependency('libsystemd', required: get_option('systemd_guard'),
                              include_type: 'system')
  if libsystemd_dep.found()
    agent_platform_deps += libsystemd_dep
    agent_platform_args += '-DYUZU_HAVE_LIBSYSTEMD'
  else
    message('libsystemd not used (systemd_guard != enabled, and not found) — Linux '
          + 'systemd service guard built as a no-op stub')
  endif
elif host_machine.system() == 'darwin'
  # macOS agent-owned mTLS client identity (roadmap 1.20): --cert-store
  # keychain identity is intentionally NOT implemented here. The macOS agent
  # runs as a root LaunchDaemon (docs/agent-privilege-model.md) with no
  # attached user login session, so there is no user login keychain an
  # operator-provisioned identity could come from — cert_store.cpp's
  # __APPLE__ branch is an honest-error stub unconditionally, same as the
  # Linux branch. The top-level meson.build's darwin `corefoundation_dep`
  # (Security + CoreFoundation + CFNetwork) still exists separately for
  # gRPC/abseil/cpp-httplib and is untouched by this.
  #
  # keychain_read.cpp (#3246) DOES need Security.framework directly: the
  # bounded SecItem keychain-read seam it implements links against
  # SecKeychainOpen/SecItemCopyMatching itself, distinct from the
  # top-level dependency above.
  #
  agent_security_dep = dependency('appleframeworks',
                                  modules: ['Security', 'CoreFoundation'],
                                  required: false, include_type: 'system')
  if agent_security_dep.found()
    agent_platform_deps += agent_security_dep
    agent_platform_args += '-DYUZU_HAVE_SECURITY_FRAMEWORK'
  else
    message('Security/CoreFoundation frameworks not found — macOS bounded '
          + 'keychain read (keychain_read.cpp) built as a stub')
  endif

  # IOKit is a HARD dependency (C0): dex_macos_perf.cpp calls the IOBlockStorageDriver walk
  # (sum_block_storage_stats/read_driver_stats/read_disk_totals) UNCONDITIONALLY, with no
  # "if found" guard. So a box without IOKit must fail LOUD at meson configure time -- the
  # earliest, clearest point -- rather than silently building a broken dylib that only fails
  # at link or at runtime. That is why IOKit is NOT in the `required: false` Security probe
  # above: A0 originally folded it there, and C0 reconciled the two to this one hard copy at
  # merge time, as both slices' comments anticipated.
  agent_platform_deps += dependency('appleframeworks', modules: ['IOKit', 'CoreFoundation'],
                                     include_type: 'system')
  # Endpoint Security (A0): shared top-level probe (meson.build), consumed
  # here for agent-core's pure ES helpers (es_client.hpp). Empty lists on a
  # CLT-only host -- no behaviour change until a later slice adds a real
  # ES-dependent agent-core TU.
  agent_platform_deps += endpoint_security_deps
  agent_platform_args += endpoint_security_args
endif

yuzu_agent_core_lib = shared_library(
  'yuzu_agent_core',
  files('src/agent.cpp', 'src/agent_csr.cpp', 'src/cert_discovery.cpp', 'src/cert_store.cpp', 'src/cloud_identity.cpp', 'src/command_dedup_store.cpp', 'src/confined_fs_posix.cpp', 'src/confined_fs_win.cpp', 'src/detached_signature.cpp', 'src/dex_event.cpp', 'src/dex_linux_collector.cpp', 'src/dex_linux_journal.cpp', 'src/dex_linux_kmsg.cpp', 'src/dex_linux_proc.cpp', 'src/dex_linux_storage.cpp', 'src/dex_linux_sysfs.cpp', 'src/dex_macos_collector.cpp', 'src/dex_macos_iokit.cpp', 'src/dex_macos_oslog.cpp', 'src/dex_macos_perf.cpp', 'src/dex_macos_signals.cpp', 'src/dex_observer.cpp', 'src/dex_perf_breach.cpp', 'src/dex_rate_limiter.cpp', 'src/dex_signal_catalog.cpp', 'src/dex_win_poll.cpp', 'src/dism_bounded_call.cpp', 'src/es_client.cpp', 'src/file_hash.cpp', 'src/fork_lock.cpp', 'src/guard_file.cpp', 'src/guard_registry.cpp', 'src/guard_service.cpp', 'src/guard_systemd.cpp', 'src/guardian_arm_ack.cpp', 'src/guardian_convergence_scheduler.cpp', 'src/guardian_detached_worker_role.cpp', 'src/guardian_drift_event.cpp', 'src/guardian_engine.cpp', 'src/guardian_journal_format.cpp', 'src/guardian_lifecycle_journal.cpp', 'src/guardian_outbox_drain_worker.cpp', 'src/guardian_rule_eval.cpp', 'src/guardian_scope_guard.cpp', 'src/guardian_spark_runtime.cpp', 'src/guardian_spark_send.cpp', 'src/guardian_spark_timing.cpp', 'src/guardian_state_reader.cpp', 'src/identity_store.cpp', 'src/keychain_read.cpp', 'src/kv_store.cpp', 'src/local_dispatcher.cpp', 'src/log_handoff.cpp', 'src/net_quality_sampler.cpp', 'src/network_interfaces.cpp', 'src/offline_hive_mutex.cpp', 'src/passwd_lookup.cpp', 'src/plugin_loader.cpp', 'src/process_enum.cpp', 'src/resilience_strategy.cpp', 'src/sdk_utilities.cpp', 'src/server_address_resolver.cpp', 'src/spark_disk.cpp', 'src/spark_engine.cpp', 'src/spark_file.cpp', 'src/spark_interval.cpp', 'src/spark_registry.cpp', 'src/spark_service.cpp', 'src/spark_spec.cpp', 'src/spark_startup.cpp', 'src/subprocess_runner.cpp', 'src/sync_canonical.cpp', 'src/sync_scheduler.cpp', 'src/sync_source_app_perf.cpp', 'src/sync_source_app_usage.cpp', 'src/sync_source_device_ci.cpp', 'src/sync_source_installed_software.cpp', 'src/sync_source_software_licensing.cpp', 'src/temp_file.cpp', 'src/trigger_engine.cpp', 'src/updater.cpp', 'src/wua_noop_callback.cpp'),
  include_directories: [
    include_directories('include'),
    include_directories('../../sdk/include'),
    include_directories('../../common/include'),
    include_directories('../shared'),  # win_str.hpp shared wide<->UTF-8 helpers (#1681, _WIN32-gated); windows_optional_features_parsers.hpp (dism_bounded_call.cpp, C1 fix)
  ],
  dependencies: [yuzu_sdk_dep, yuzu_proto_dep, spdlog_dep, sqlite3_dep, nlohmann_dep] + agent_crypto_deps + agent_platform_deps,
  cpp_args: ['-DYUZU_AGENT_CORE_BUILDING'] + agent_platform_args,
  install: true,
)

yuzu_agent_core_dep = declare_dependency(
  link_with: yuzu_agent_core_lib,
  include_directories: [
    include_directories('include'),
    include_directories('../../sdk/include'),
    include_directories('../../common/include'),
    # '../shared': exported here (not just on yuzu_agent_core_lib's own
    # include_directories) because a PUBLIC agents/core header can itself
    # depend on an agents/shared/ header -- launchd_state.hpp includes
    # launchctl_list.hpp -- and an external consumer reaching launchd_state.hpp
    # only through this dependency object (A2's macOS launchd Spark mechanism,
    # sec2-2/UP2-4 governance A0 fix round) must be able to resolve that
    # transitive include without separately re-adding '../shared' itself.
    # ADDITIVE-ONLY, on purpose (bci3-2, governance A0 fix round): this is
    # the LAST entry in the list, so it can only resolve a basename no
    # earlier root (include/, sdk/include, common/include) already provides
    # -- it can never shadow one of them. Keep it last; reordering this list
    # would turn an additive-only -I into a potentially-shadowing one with
    # no compiler signal either way.
    include_directories('../shared'),
  ],
)

# Named (not a bare executable() call) so tests/meson.build can `depends:` on the real
# agent binary for the #4666 PR-2 multi-image / blocked-sink-harness fixtures.
yuzu_agent_exe = executable(
  'yuzu-agent',
  files('src/main.cpp', 'src/service_win.cpp'),
  include_directories: [
    include_directories('include'),
    include_directories('../../sdk/include'),
    include_directories('../shared'),  # win_sc_handle.hpp SC_HANDLE RAII owner (#1822, _WIN32-gated)
  ],
  dependencies: [yuzu_agent_core_dep, spdlog_dep, cli11_dep, sqlite3_dep],
  install: true,
)
