#pragma once

#include <yuzu/plugin.hpp>

#include <chrono>
#include <cstddef>
#include <filesystem>
#include <memory>
#include <string>
#include <vector>

namespace yuzu::agent {

struct Config {
    std::string server_address;       // e.g. "server.example.com:50051"
    std::string agent_id;             // Stable UUID; generated on first run if empty
    std::filesystem::path plugin_dir; // Directory to scan for plugin .so/.dll
    std::filesystem::path data_dir;   // Directory for persistent state (agent.db)
    std::chrono::seconds heartbeat_interval{30};
    bool tls_enabled{true};
    std::filesystem::path tls_ca_cert;     // PEM CA certificate for server verification
    std::filesystem::path tls_client_cert; // Optional mTLS client cert (PEM file)
    std::filesystem::path tls_client_key;  // Optional mTLS client key (PEM file)
    std::string cert_store;                // Windows cert store name (e.g. "MY")
    std::string cert_subject;              // Subject CN match for cert store lookup
    std::string cert_thumbprint;           // SHA-1 thumbprint for cert store lookup
    bool cert_auto_discovery{true};        // Auto-discover certs from well-known paths
    // PKI #1303: fail-closed posture. When TLS is on but NO CA can be pinned (no
    // --ca-cert AND no install CA auto-discovered, #1289), the agent refuses to start
    // rather than silently falling back to the system trust store (which does NOT
    // trust a Yuzu self-signed install CA — a fail-open MITM window on the command
    // fan-out plane). Set this ONLY when the server leaf chains to a CA already in the
    // system store (public CA / corporate root) — a deliberate operator choice.
    bool tls_allow_system_trust{false};    // --tls-system-roots / YUZU_TLS_SYSTEM_ROOTS
    // PKI PR3: directory for the auto-provisioned per-agent mTLS credential
    // (agent-client.{key,pem} + agent-ca.pem). When tls is enabled with a CA but
    // no explicit client cert/store, the agent generates a CSR at enrollment,
    // persists the server-issued leaf here (key 0600), and reconnects with mTLS.
    // Empty → defaults to data_dir/"certs". --no-auto-provision-cert disables it.
    std::filesystem::path cert_dir;
    bool auto_provision_cert{true};        // PKI PR3: enable CSR-at-enrollment flow
    std::string enrollment_token;          // Pre-shared enrollment token (Tier 2)
    std::string log_level{"info"};         // Current log level
    bool debug_mode{false};                // Debug mode flag (diagnostic features)
    bool verbose_logging{false};           // Verbose logging flag

    // Plugin security
    std::filesystem::path plugin_allowlist;     // --plugin-allowlist (sha256sum-format file)
    std::filesystem::path plugin_trust_bundle;  // --plugin-trust-bundle (PEM CA bundle for code-sig)
    bool plugin_require_signature{false};       // --plugin-require-signature

    /// OTA update signing (#416/#3807). Deliberately SEPARATE from the plugin
    /// bundle above: a site may trust one signer for plugins and another for
    /// agent builds, and collapsing them would silently widen whichever is
    /// narrower. Point both at the same file if that is what you want.
    std::filesystem::path update_trust_bundle;  // --update-trust-bundle
    bool update_require_signature{false};       // --update-require-signature

    // OTA updates
    bool auto_update{true};                               // --no-auto-update disables
    std::chrono::seconds update_check_interval{6 * 3600}; // --update-check-interval


    // Guardian DEX (Digital Experience) — fleet-wide crash recorder (slice 1)
    bool dex_disable{false}; // --dex-disable / YUZU_AGENT_DEX_DISABLE: deploy-time opt-out;
                             // when set, the crash recorder never arms and no crash
                             // telemetry is collected.

    // Agent daily-sync (ADR-0016) — installed-software inventory to central Postgres.
    bool inventory_disable{false}; // --inventory-disable / YUZU_AGENT_INVENTORY_DISABLE:
                                   // deploy-time opt-out; when set, the daily-sync thread
                                   // never starts and no installed-software inventory is
                                   // collected or pushed. On personally-assigned devices,
                                   // installed-software enumeration may be works-council
                                   // co-determination-relevant — this is the control for
                                   // jurisdictions/agreements that require it off.

    // SparkEngine (ADR-0021 Stage-2, rung 1) — next-gen event-driven detection engine,
    // instantiated observe-only alongside the enforcing legacy IGuard path.
    bool spark_disable{false}; // --spark-disable / YUZU_AGENT_SPARK_DISABLE: boot-time
                               // deploy opt-out. SparkEngine is never instantiated, watches
                               // nothing, and reports no capability or health counters — but
                               // the heartbeat DOES still carry the posture itself
                               // (spark_running=0 + spark_disabled=1), so the fleet can tell
                               // a deliberate opt-out apart from an engine that FAILED to
                               // start. Emitting nothing at all is what made a fleet-wide
                               // boot failure invisible. The enforcing legacy Guardian path
                               // is unaffected.

    // Software Licensing & Entitlements (SLE, ADR-0024) — the per-user `user_ref`
    // knob for the `software_licensing` daily-sync source (Decision 11). One of
    // "collect" | "hash" | "omit"; default "hash" (a per-agent keyed pseudonym).
    // --license-scan-user-ref / YUZU_AGENT_LICENSE_SCAN_USER_REF. Validated to
    // the closed set at parse (main.cpp). This governs only how a detected
    // per-user licence's local profile name is recorded; it does not disable the
    // per-user probe (that shares the inventory_disable opt-out above, roadmap R2).
    std::string license_scan_user_ref{"hash"};
};

/**
 * Agent is the main object that manages the plugin lifecycle, gRPC connection
 * to the server, and the heartbeat/command dispatch loop.
 *
 * Usage:
 *   auto agent = yuzu::agent::Agent::create(config);
 *   agent->run();  // blocks until shutdown is requested
 */
class YUZU_EXPORT Agent {
public:
    virtual ~Agent() = default;

    [[nodiscard]] static std::unique_ptr<Agent> create(Config config);

    /** Block and run until stop() is called or a fatal error occurs. */
    virtual void run() = 0;

    /** Signal the agent to gracefully shut down. Thread-safe. */
    virtual void stop() noexcept = 0;

    /** Returns the stable agent ID (may be auto-generated). */
    [[nodiscard]] virtual std::string_view agent_id() const noexcept = 0;

    /** Returns the list of loaded plugins. */
    [[nodiscard]] virtual std::vector<std::string> loaded_plugins() const = 0;

    /**
     * True if run() returned because of a FATAL FAILURE rather than a normal stop() — so main()
     * maps it to a non-zero exit and systemd Restart= / Docker / the Windows SCM observe the
     * failure instead of a silent EXIT_SUCCESS.
     *
     * NOT ONLY A STARTUP FAILURE, DESPITE THE NAME. It covers:
     *   * a fatal startup failure (e.g. the #1303 fail-closed TLS posture refused to connect with
     *     no pinnable CA), AND
     *   * a fatal MID-LIFE failure: a dispatch-thread-pool re-creation that fails on the reconnect
     *     path (host out of threads). That used to return EXIT_SUCCESS, so the agent simply
     *     vanished from the fleet — a clean exit fires no Restart=on-failure / k8s OnFailure
     *     policy, and on Windows it denies FAILURE_ACTIONS the failure exit those actions key on.
     * The name is a historical narrowing; `Agent` is an exported interface, so it is not renamed
     * here. If you widen it further, widen this contract and the Windows SCM mapping with it
     * (service_win.cpp reports specific-error 1 for BOTH). (governance: consistency-auditor.)
     */
    [[nodiscard]] virtual bool startup_failed() const noexcept = 0;

    /**
     * Live count of every detached worker the process must not race normal
     * C++ teardown against (F3). Two additive sources, summed:
     *   - Guardian's own bounded-I/O workers (ADR-0021 rung 7.6 - see
     *     guardian_io_executor.hpp's "ORPHAN PROCESS-EXIT CONTRACT"). Zero
     *     whenever Guardian's spark path was never wired (today's default -
     *     rung 7.7 is what wires it).
     *   - Spark mechanisms' own detached probe/arm workers (#2012/#3840
     *     plan, "F3 orphan-exit accounting - Route A (corrected)" -
     *     spark_detached_call.hpp's SparkDetachedLane). Summed from an
     *     agent-lifetime counter that is NEVER read through the SparkEngine
     *     pointer or its boot-completion latch - a source gated behind
     *     either of those would go uncounted in exactly the windows (pre-
     *     boot, mid-boot, post-exception-reset, post-sticky-stop-skip-
     *     wiring) where an orphaned worker is most likely to exist.
     * main()/the Windows SCM path poll this after run() returns and
     * hard_exit() with a nonzero code if it has not reached zero within a
     * bounded grace, rather than let normal process exit run C++
     * static/DSO teardown concurrently with a worker that may still be
     * executing library code through a wedged syscall.
     */
    [[nodiscard]] virtual std::size_t guardian_active_io_workers() const noexcept = 0;
};

} // namespace yuzu::agent
