#include <yuzu/json_log_formatter.hpp>
#include <yuzu/server/auth.hpp>
#include <yuzu/server/auth_db.hpp>

#include "audit_store.hpp"
#include <yuzu/server/server.hpp>
#include <yuzu/version.hpp>

#include "gateway_mgmt_stub_pool.hpp" // parse_gateway_cluster_addrs
#include "gateway_service_impl.hpp"   // detail::kMaxClusterIdLen
#include "insecure_tls_gate.hpp"
#include "kek_rotate_control.hpp" // detail::kKekMaxLiveVersionsDefault / kek_ceiling_is_risk_acceptance
#include "key_provider.hpp"
#include "pg/multi_host_dsn.hpp" // HA WS-8: multi-host DSN must use target_session_attrs=read-write
#include "pg/pg_pool.hpp"
#include "pg/secret_codec.hpp"
#include "scim_routes.hpp"
#include "security_headers.hpp"
#include "sso_boot_guard.hpp" // sso_only_boot_guard_ok / *_config_complete (CC6.3)

#include <CLI/CLI.hpp>

#include "server_ota_options.hpp"
#include "shutdown_drain_rules.hpp" // HA WS-8: --shutdown-drain-seconds bound
#include "stream_budget.hpp" // detail::kMaxHttpWorkerThreads (pool ceiling)
#include "web_utils.hpp"     // normalise_trusted_origins (#2537 CSRF allowlist)
#include <spdlog/sinks/rotating_file_sink.h>
#include <spdlog/sinks/stdout_color_sinks.h>
#include <spdlog/spdlog.h>

#ifndef _WIN32
#include <yuzu/shutdown_watcher.hpp> // POSIX self-pipe + watcher thread (#3007, mirrors the agent)
#endif
#include <yuzu/tls_policy.hpp> // #4722: shared TLS 1.2 cipher allow-list

#include <atomic>
#include <chrono>
#include <csignal>
#include <cstdlib>
#include <mutex>

#ifdef _WIN32
// clang-format off
#include <winsock2.h>  // must precede windows.h to avoid redefinition
#include <windows.h>
// clang-format on
#include <crtdbg.h>
#include <io.h>
#include <lmcons.h>  // UNLEN for GetUserNameA
#else
#include <pwd.h>     // getpwuid for the real OS principal
#include <unistd.h>
#endif
#include <sqlite3.h>

#include <filesystem>
#include <format>
#include <iostream>
#include <memory>
#include <optional>
#include <string>
#include <string_view>

static std::atomic<yuzu::server::Server*> g_server{nullptr};

// Read FROM A SIGNAL HANDLER. Only a lock-free atomic is legal there ([support.signal]) —
// a non-lock-free one takes an internal spinlock, and a handler interrupting a thread that
// holds it deadlocks the process. Mirrors agents/core/src/main.cpp's g_agent.
static_assert(std::atomic<yuzu::server::Server*>::is_always_lock_free);

#ifdef _WIN32
/// WINDOWS ONLY. Serialises the console handler's `g_server->stop()` against main()'s
/// unpublish-and-destroy, so the Server cannot be destroyed while a stop() is still running
/// on it. Taken ONLY inside the `#ifdef _WIN32` branch of on_signal, where the CRT has
/// already handed us an ordinary thread, so locking is legal — never on the POSIX path,
/// where the self-pipe below gets this same barrier for free from ~ShutdownWatcher's
/// join(). Mirrors agents/core/src/main.cpp's g_agent_mu (#1822 / Gate-8 round 8 UP8-1).
/// There is no Windows SCM service path for the server today (unlike the agent's
/// service_win.cpp), so the console handler is the only Windows caller of stop().
static std::mutex g_server_mu;
#endif

/// Signals seen. The SECOND one escalates — see on_signal. Deliberately not under
/// `#ifndef _WIN32`: escalation must exist on both platforms and must run BEFORE any lock
/// (agents/core/src/main.cpp, Gate-8 round 9) — a wedged stop() parks the watcher thread
/// (POSIX) or holds g_server_mu across s->stop() (Windows) indefinitely, so a second
/// signal must be able to act regardless of which side is stuck.
static std::atomic<int> g_signal_count{0};
static_assert(std::atomic<int>::is_always_lock_free);

#ifndef _WIN32
/// Write end of the shutdown self-pipe. The handler's ONLY job is to poke this.
static std::atomic<int> g_shutdown_wfd{-1};
static_assert(std::atomic<int>::is_always_lock_free);
#endif

/// LAST-RESORT HANDLER — used before the shutdown watcher exists (the boot window ahead
/// of Server::create(), which is not the trivial construction the agent's make_agent() is:
/// TLS cert bootstrap, the gateway mTLS client, and the full gRPC BuildAndStart() can run
/// for a real interval), if the watcher failed to construct or died, and after run()
/// returns (see the "handlers must not outlive what serves them" comment below). It does
/// not try to be graceful — there is nothing to run a graceful teardown, or nothing left
/// worth waiting on — it only guarantees the process stays KILLABLE, including as PID 1 in
/// a container, where the kernel discards a default-disposition signal entirely.
/// Async-signal-safe: no locks, no stdio, no spdlog (which allocates and RETHROWS non-std
/// exceptions — a throw here has no enclosing handler and std::terminate()s WITHOUT
/// unwinding). Body is a deliberate 2-line duplicate of agents/core/src/hard_exit.hpp's
/// hard_exit(), not a reuse — that header lives under agents/core/src, outside the server's
/// include graph (server/core/meson.build only exposes include/ + ../../common/include),
/// and pulling it in for a two-line function isn't worth the cross-binary header dependency.
/// If a THIRD call site ever needs this, hoist it to common/include/yuzu/ alongside
/// shutdown_watcher.hpp instead of adding a fourth copy. See that header anyway for why
/// TerminateProcess, not ::_exit(), on Windows (no DllMain, no loader lock) and ::_exit(),
/// not std::exit(), on POSIX (async-signal-safe, cannot block) — the rationale, not the code.
static void on_signal_hard_exit(int sig) noexcept {
    (void)sig;
#ifdef _WIN32
    ::TerminateProcess(::GetCurrentProcess(), 1);
#else
    ::_exit(1);
#endif
}

// ─────────────────────────────────────────────────────────────────────────────────
// SIGNAL HANDLING — the handler must do NOTHING but poke a pipe (#3007). Ported from
// agents/core/src/main.cpp, which already fixed this exact defect for the agent daemon.
// This used to call `s->stop()` directly, under a comment claiming "only async-signal-safe
// calls allowed here" — ServerImpl::stop() is nothing of the sort: it takes mutexes across
// ~60 stores, joins ~8 background threads, calls grpc::Server::Shutdown(), and logs
// through spdlog — undefined behaviour inside a signal handler per signal-safety(7).
// Reproduced empirically: SIGABRT "dying due to potential deadlock" from abseil's
// DebugOnlyDeadlockCheck during grpc::Server::ShutdownInternal() while the main thread was
// blocked in Wait(); the detector is compiled out under NDEBUG, so a release build is
// expected to hit the identical interleaving as a silent, probabilistic hang instead — that
// specific claim is inference from the mechanism (#3007), not separately observed on a
// release binary.
//
// See agents/core/src/main.cpp's on_signal for the full trap list this dodges — the
// mechanism (common/include/yuzu/shutdown_watcher.hpp) is now shared verbatim between the
// two binaries. Windows keeps the direct call: the CRT dispatches console/CTRL signals on
// a freshly created thread, so it is already an ordinary thread context, and there is no
// SCM control path for the server to share it with (unlike the agent's service_win.cpp).
// ─────────────────────────────────────────────────────────────────────────────────
static void on_signal(int sig) {
    // A process-directed signal lands on an ARBITRARY unmasked thread. Every write()
    // below can set errno (the O_NONBLOCK write end is *expected* to return EAGAIN), so
    // clobbering it here would silently rewrite an unrelated thread's error.
    const int saved_errno = errno;
    const char msg[] = "Received signal, shutting down...\n";
    (void)sig;

    // Second signal => escalate, both platforms, BEFORE any lock. See
    // agents/core/src/main.cpp's on_signal for the full rationale (Gate-8 round 9).
    if (g_signal_count.fetch_add(1, std::memory_order_acq_rel) >= 1) {
        on_signal_hard_exit(sig);
    }

#ifdef _WIN32
    _write(2, msg, sizeof(msg) - 1);
    // Hold g_server_mu ACROSS s->stop(), not merely across the load — main() takes the
    // same mutex to unpublish, so it blocks until an in-flight stop() has returned
    // before destroying the Server. See agents/core/src/main.cpp's on_signal, Gate-8
    // round 8 UP8-1.
    {
        std::lock_guard<std::mutex> lock(g_server_mu);
        if (auto* s = g_server.load(std::memory_order_acquire))
            s->stop();
    }
#else
    // The pipe byte goes first — it cannot block (the write end is O_NONBLOCK). The
    // stderr log is best-effort and comes after: see shutdown_watcher.hpp.
    const int wfd = g_shutdown_wfd.load(std::memory_order_acquire);
    if (wfd >= 0) {
        const char byte = yuzu::ShutdownWatcher::kSignal;
        ssize_t n = ::write(wfd, &byte, 1); // async-signal-safe, and CANNOT block
        (void)n; // EAGAIN on a full pipe just means a shutdown is already pending.
    }
    (void)::write(STDERR_FILENO, msg, sizeof(msg) - 1); // best-effort; may block, harmlessly
#endif
    errno = saved_errno;
}

// Resolve the real OS account running this process for break-glass audit
// attribution. Reads the kernel-authoritative identity (getpwuid(geteuid) /
// GetUserNameA) rather than getenv("USER"), which is inherited from the parent
// and trivially forgeable — a forged principal would poison the very evidence
// the break-glass audit row exists to provide (#1226 H-2).
static std::string resolve_os_principal() {
#ifdef _WIN32
    char name[UNLEN + 1];
    DWORD len = static_cast<DWORD>(sizeof(name));
    if (GetUserNameA(name, &len) && len > 1) {
        return std::string(name, len - 1); // len counts the trailing NUL
    }
    return "unknown";
#else
    if (struct passwd* pw = ::getpwuid(::geteuid()); pw && pw->pw_name && pw->pw_name[0] != '\0') {
        return std::string(pw->pw_name);
    }
    return "unknown";
#endif
}

// Minimal RFC 8259 string-content escaper for emitting a username inside a JSON
// status line. is_valid_username already restricts the charset so no escaping is
// strictly needed today, but output-encoding (not input validation) is the
// correct defence: this stays correct if the validator is ever relaxed (#1226 M-2).
static std::string json_escape(std::string_view s) {
    std::string out;
    out.reserve(s.size() + 8);
    for (char c : s) {
        switch (c) {
        case '"': out += "\\\""; break;
        case '\\': out += "\\\\"; break;
        case '\b': out += "\\b"; break;
        case '\f': out += "\\f"; break;
        case '\n': out += "\\n"; break;
        case '\r': out += "\\r"; break;
        case '\t': out += "\\t"; break;
        default:
            if (static_cast<unsigned char>(c) < 0x20) {
                out += std::format("\\u{:04x}", static_cast<unsigned char>(c));
            } else {
                out += c;
            }
        }
    }
    return out;
}

// Thin main-side wrapper over the testable `break_glass_account_problem` free
// function in auth_db (which carries the FAIL-CLOSED mandatory-MFA contract —
// SOC 2 CC6.6 — so the sso-only escape hatch is never a bare-password account).
// Shared by the server-start guard and the --break-glass-arm one-shot. Returns
// true on success; on failure returns false and sets `err` to the reason.
static bool break_glass_user_valid(yuzu::server::AuthDB& db, const std::string& user,
                                   std::string& err) {
    if (auto problem = yuzu::server::break_glass_account_problem(db, user)) {
        err = *problem;
        return false;
    }
    return true;
}

// Open the Postgres audit store for a one-shot break-glass CLI path, and bring
// it to a state where writing an evidence row is SAFE.
//
// No legacy-backfill gate (retired: ADR-0009 hard-cutover Update, 2026-09-04) —
// AuditStore is born-on-PG with no migration path held open, same as every
// other retired store. Returns nullptr, having logged and printed, when the
// store is unusable; `refuse_action` names the mutation being refused.
static std::unique_ptr<yuzu::server::AuditStore>
open_one_shot_audit(yuzu::server::pg::PgPool& pool, int retention_days, std::string_view flag,
                    std::string_view refuse_action, std::string_view extra_remediation = {}) {
    // Retention comes from config, NOT the constructor default: a site running
    // --audit-retention-days=90 would otherwise get break-glass evidence rows on
    // a 365-day horizon — the highest-stakes rows outliving the policy that
    // governs the rest of the trail (adversarial review, Kimi L1).
    auto audit = std::make_unique<yuzu::server::AuditStore>(pool, retention_days);
    if (!audit->is_open()) {
        spdlog::error("{}: Postgres audit store (schema audit_store) is not writable; refusing to "
                      "{} without an audit record. Check --postgres-dsn reachability and retry.{}",
                      flag, refuse_action, extra_remediation);
        std::cerr << "error: audit store unavailable; refusing to " << refuse_action
                  << " without an audit record\n";
        return nullptr;
    }
    return audit;
}

int main(int argc, char* argv[]) {
#ifdef _WIN32
    // Suppress all CRT/abort pop-up dialogs — route to stderr instead.
    _CrtSetReportMode(_CRT_ASSERT, _CRTDBG_MODE_FILE);
    _CrtSetReportFile(_CRT_ASSERT, _CRTDBG_FILE_STDERR);
    _CrtSetReportMode(_CRT_ERROR, _CRTDBG_MODE_FILE);
    _CrtSetReportFile(_CRT_ERROR, _CRTDBG_FILE_STDERR);
    _CrtSetReportMode(_CRT_WARN, _CRTDBG_MODE_FILE);
    _CrtSetReportFile(_CRT_WARN, _CRTDBG_FILE_STDERR);
    _set_abort_behavior(0, _WRITE_ABORT_MSG | _CALL_REPORTFAULT);
    SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);

    // Winsock must be initialised before any socket work (httplib, gRPC).
    WSADATA wsa_data;
    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
        std::cerr << "WSAStartup failed\n";
        return EXIT_FAILURE;
    }
#endif

    // #4722: gRPC's ConfigVars snapshots GRPC_SSL_CIPHER_SUITES on first use;
    // pin it before any gRPC symbol can run (unconditional overwrite — see
    // tls_policy.hpp). ORDERING IS THE CONTRACT: no automated test observes
    // this line (the test executable pins from its own static initialiser);
    // moving it below the first gRPC call silently restores gRPC's default
    // TLS 1.2 cipher list.
    if (!yuzu::tls::pin_grpc_cipher_env()) {
        std::cerr << "Failed to pin " << yuzu::tls::kGrpcCipherSuitesEnvVar
                  << " in the process environment; refusing to start\n";
        return EXIT_FAILURE;
    }

    CLI::App app{"Yuzu Server", "yuzu-server"};
    app.set_version_flag("--version",
                         std::format("{}  ({})", yuzu::kFullVersionString, yuzu::kGitCommitHash));

    yuzu::server::Config cfg;
    std::string log_level = "info";
    std::string log_format = "text";
    std::string log_file;
    size_t log_max_size = 50 * 1024 * 1024; // 50 MB
    int log_max_files = 5;
    std::string config_file;
    int rate_limit = 100;
    int login_rate_limit = 10;

    app.add_option("--config", config_file, "Path to yuzu-server.cfg")->envname("YUZU_CONFIG");
    app.add_option("--data-dir", cfg.data_dir,
                   "Data directory for SQLite DBs (default: same directory as config file)")
        ->envname("YUZU_DATA_DIR");
    app.add_option("--postgres-dsn", cfg.postgres_dsn,
                   "PostgreSQL connection string (libpq conninfo or URI) for the server "
                   "storage substrate. REQUIRED — the server fails closed without a reachable "
                   "database (ADR-0006/0007). The agent stays SQLite.")
        ->envname("YUZU_POSTGRES_DSN");
    app.add_option("--postgres-pool-size", cfg.postgres_pool_size,
                   "Max concurrent PostgreSQL connections in the shared pool (default 16). "
                   "Raise for high agent counts / slow managed-PG links; tune against "
                   "yuzu_pg_pool_in_use and yuzu_pg_acquire_wait_seconds.")
        ->default_val(16)
        ->check(CLI::PositiveNumber)
        ->envname("YUZU_POSTGRES_POOL_SIZE");
    app.add_option("--shutdown-drain-seconds", cfg.shutdown_drain_seconds,
                   "On shutdown, keep serving for at least this many seconds after /readyz "
                   "starts answering 503, so a load balancer stops routing here before the "
                   "listener closes (default 0; 0-60). Set it to at least the load balancer's "
                   "health-check interval x unhealthy threshold, plus one interval.")
        ->default_val(0)
        ->check(CLI::Range(0, yuzu::server::shutdown_drain::kMaxShutdownDrainSeconds))
        ->envname("YUZU_SHUTDOWN_DRAIN_SECONDS");
    app.add_option("--listen", cfg.listen_address, "Agent gRPC address (host:port)")
        ->default_val("0.0.0.0:50051")
        ->envname("YUZU_LISTEN_ADDRESS");
    app.add_option("--management", cfg.management_address, "Management gRPC address (host:port)")
        ->default_val("0.0.0.0:50052")
        ->envname("YUZU_MANAGEMENT_ADDRESS");
    app.add_option("--web-address", cfg.web_address, "Web UI bind address")
        ->default_val("127.0.0.1")
        ->envname("YUZU_WEB_ADDRESS");
    app.add_option("--web-port", cfg.web_port, "Web UI port")
        ->default_val(8080)
        ->envname("YUZU_WEB_PORT");
    app.add_option("--csrf-trusted-origin", cfg.csrf_trusted_origins,
                   "External origin the dashboard is served on, for the CSRF same-site check "
                   "(repeatable; a single value may be comma-separated). Set this when a reverse "
                   "proxy rewrites Host, otherwise every CSRF-gated dashboard action is refused "
                   "with 403 because the browser's Origin cannot match the proxied Host. Forms: "
                   "'https://yuzu.example' (matched on scheme AND host) or a bare 'yuzu.example' "
                   "(host only). Wildcards are NOT supported. No forwarded header is consulted.")
        // Comma-splitting is done ONCE, in normalise_trusted_origins (web_utils.hpp),
        // NOT here — do NOT add CLI11 `->delimiter(',')`, or a comma-separated value
        // would be split twice (CLI11 tokens × the parser's own comma loop) and mangle
        // entries. Same rule, and same reason, as --cert-san (#1271).
        ->envname("YUZU_CSRF_TRUSTED_ORIGIN");
    app.add_flag("--no-tls", "Disable TLS (insecure, for development only)")
        ->each([&cfg](const std::string&) { cfg.tls_enabled = false; });
    app.add_option("--cert", cfg.tls_server_cert, "PEM server certificate")->envname("YUZU_CERT");
    app.add_option("--key", cfg.tls_server_key, "PEM server private key")->envname("YUZU_KEY");
    app.add_flag("--no-default-certs",
                 "Do not auto-generate built-in default certificates on first boot; require "
                 "operator-provided certs instead (legacy refuse-to-start behaviour)")
        ->each([&cfg](const std::string&) { cfg.no_default_certs = true; })
        ->envname("YUZU_NO_DEFAULT_CERTS");
    app.add_option("--ca-dir", cfg.ca_dir,
                   "Directory for the built-in CA + default certs (default: platform cert dir)")
        ->envname("YUZU_CA_DIR");
    app.add_option("--cert-san", cfg.cert_sans,
                   "Extra Subject Alternative Name for the auto-generated default certs "
                   "(repeatable). Forms: 'dns:<name>', 'ip:<addr>', or a bare value "
                   "(auto-classified); a single value may be comma-separated. Added to the "
                   "https/agent/gateway default leaves so they validate for a deployment "
                   "hostname or IP (e.g. 'dns:gateway'). Ignored when operator certs are "
                   "supplied or --no-default-certs is set.")
        // #1271 cpp-expert: comma-splitting is done ONCE, in parse_extra_sans
        // (default_certs.cpp), NOT here — do NOT add CLI11 `->delimiter(',')`, or a
        // comma-separated value would be split twice (CLI11 tokens × the parser's
        // own comma loop) and mangle entries. Each CLI/env token reaches the parser
        // whole; the parser owns the comma semantics.
        ->envname("YUZU_CERT_SAN");
    app.add_option("--cert-group", cfg.cert_group,
                   "Shared POSIX group (name or gid) for the auto-generated cert volume "
                   "(PKI #1289). When set, the cert dir (0750) + default-gateway.key (0640) "
                   "are made group-readable so a gateway/agent running as a different uid in a "
                   "sibling container can read the shared CA + leaf out of /etc/yuzu/certs. "
                   "All three users must belong to this group. Empty (default) keeps tight "
                   "single-host perms (0700/0600). POSIX-only.")
        ->envname("YUZU_CERT_GROUP");
    app.add_option("--ca-cert", cfg.tls_ca_cert, "PEM CA cert (for mTLS agent verification)")
        ->envname("YUZU_CA_CERT");
    bool deprecated_tls_flag_used = false;
    app.add_flag("--insecure-skip-client-verify",
                 "Allow TLS without --ca-cert (disables mTLS client verification). "
                 "Requires YUZU_ALLOW_INSECURE_TLS=1.")
        ->each([&cfg](const std::string&) { cfg.insecure_skip_client_verify = true; });
    app.add_flag("--allow-one-way-tls", "[DEPRECATED] Renamed to --insecure-skip-client-verify; "
                                        "still accepted for backward compatibility.")
        ->each([&cfg, &deprecated_tls_flag_used](const std::string&) {
            cfg.insecure_skip_client_verify = true;
            deprecated_tls_flag_used = true;
        });
    app.add_option("--management-cert", cfg.mgmt_tls_server_cert,
                   "PEM management server certificate override");
    app.add_option("--management-key", cfg.mgmt_tls_server_key,
                   "PEM management server private key override");
    app.add_option("--management-ca-cert", cfg.mgmt_tls_ca_cert,
                   "PEM CA cert for management client cert verification");
    app.add_option("--gateway-upstream", cfg.gateway_upstream_address,
                   "Gateway upstream gRPC address (host:port); empty = disabled")
        ->envname("YUZU_GATEWAY_UPSTREAM");
    app.add_flag("--gateway-mode", "Enable gateway mode (relax peer-mismatch in Subscribe)")
        ->each([&cfg](const std::string&) { cfg.gateway_mode = true; });
    app.add_option("--gateway-command-addr", cfg.gateway_command_address,
                   "Gateway ManagementService address for command forwarding (host:port)")
        ->envname("YUZU_GATEWAY_COMMAND_ADDR");
    // HA WS-4 4.3: raw entries, parsed+validated into cfg.gateway_cluster_addresses
    // after CLI11_PARSE below (parse_gateway_cluster_addrs needs to reject a
    // malformed entry with a CLI exit, not a lenient warning — see that
    // function's doc comment, gateway_mgmt_stub_pool.hpp).
    std::vector<std::string> gateway_cluster_addr_entries;
    app.add_option("--gateway-cluster-addr", gateway_cluster_addr_entries,
                   "Per-cluster gateway ManagementService address(es) for cross-cluster command "
                   "fan-out, cluster_id=host:port (e.g. us-east=10.0.1.5:50063). Repeatable or "
                   "comma-separated. Unset (default) = single-cluster mode: "
                   "--gateway-command-addr alone is used for every cluster_id. Per-cluster "
                   "routing only -- trust-zone isolation between clusters is not yet provided "
                   "(#4669); do not rely on this to keep one cluster's gateway from being able "
                   "to answer for an agent on another cluster.")
        ->delimiter(',')
        ->envname("YUZU_GATEWAY_CLUSTER_ADDR");
    app.add_option("--trusted-nat-cidr", cfg.trusted_nat_cidrs,
                   "Multi-egress NAT/proxy CIDR(s) (e.g. 203.0.113.0/24,2001:db8::/32). A direct "
                   "agent whose Register and Subscribe source IPs both fall in one range is "
                   "tolerated instead of rejected (#1128). Repeatable or comma-separated.")
        ->delimiter(',')
        ->envname("YUZU_TRUSTED_NAT_CIDR");
    app.add_flag("--nat-trust-mtls-identity", cfg.nat_trust_mtls_identity,
                 "Also tolerate a peer-IP mismatch when the Subscribe mTLS identity matches the "
                 "Register-bound identity (#1128). SAFE ONLY WITH PER-AGENT CLIENT CERTS — a "
                 "shared fleet-wide cert makes this a session-replay bypass. Default off.")
        ->envname("YUZU_NAT_TRUST_MTLS_IDENTITY");
    app.add_option("--max-agents", cfg.max_agents, "Maximum concurrent agent connections")
        ->default_val(10000)
        ->envname("YUZU_MAX_AGENTS");
    app.add_option("--log-level", log_level, "Log level: trace|debug|info|warn|error")
        ->default_val("info")
        ->envname("YUZU_LOG_LEVEL");
    app.add_option("--log-format", log_format, "Log format: text|json")
        ->default_val("text")
        ->envname("YUZU_LOG_FORMAT");
    app.add_option("--log-file", log_file, "Log file path (enables file logging)")
        ->envname("YUZU_LOG_FILE");
    app.add_option("--log-max-size", log_max_size, "Max log file size in bytes (default: 50MB)")
        ->default_val(50 * 1024 * 1024)
        ->envname("YUZU_LOG_MAX_SIZE");
    app.add_option("--log-max-files", log_max_files, "Max rotated log files (default: 5)")
        ->default_val(5)
        ->envname("YUZU_LOG_MAX_FILES");
    app.add_option("--rate-limit", rate_limit, "Max API requests/second per IP (default: 100)")
        ->default_val(100)
        ->envname("YUZU_RATE_LIMIT");
    app.add_option("--login-rate-limit", login_rate_limit,
                   "Max login attempts/second per IP (default: 10)")
        ->default_val(10)
        ->envname("YUZU_LOGIN_RATE_LIMIT");
    app.add_option("--principal-max-concurrency", cfg.principal_max_concurrency,
                   "Max in-flight requests per engine principal (default: 16)")
        ->default_val(16)
        // A 0/negative value self-bricks every engine principal (every
        // request 429s forever) with no clear signal why; reject at boot
        // with CLI11's message instead of silently shipping a dead cap.
        ->check(CLI::PositiveNumber)
        ->envname("YUZU_PRINCIPAL_MAX_CONCURRENCY");
    app.add_option("--principal-rate-limit", cfg.principal_rate_limit,
                   "Max requests/second per engine principal (default: 20)")
        ->default_val(20.0)
        // Same footgun as --principal-max-concurrency above: 0/negative
        // would zero every engine principal's token bucket.
        ->check(CLI::PositiveNumber)
        ->envname("YUZU_PRINCIPAL_RATE_LIMIT");

    // Agent OTA pull bounds (#913 per-peer limit, #911 deadlines) and the
    // server-wide gRPC bounds. Registered from server_ota_options.hpp so the flag
    // names, defaults, env spellings and validators are pinned by a test —
    // see test_server_ota_options.cpp.
    register_ota_options(app, cfg);

    // MFA / TOTP — SOC 2 CC6.6. See docs/auth-mfa-design.md.
    app.add_option("--mfa-enforcement", cfg.mfa_enforcement,
                   "MFA enforcement (default: optional). \"optional\" = self-service "
                   "enrollment, login never requires it. \"admin-only\" = admins must "
                   "enrol before login completes. \"required\" = every role must enrol. "
                   "Under admin-only/required an un-enrolled login is redirected through "
                   "TOTP enrollment (POST /login/mfa/enroll) before a session is minted.")
        ->default_val("optional")
        ->check(CLI::IsMember({"optional", "admin-only", "required"}))
        ->envname("YUZU_MFA_ENFORCEMENT");
    app.add_option("--mfa-step-up-window-secs", cfg.mfa_step_up_window_secs,
                   "Seconds after a TOTP proof that high-risk endpoints accept the session as "
                   "stepped-up (default: 300)")
        ->default_val(300)
        ->envname("YUZU_MFA_STEP_UP_WINDOW_SECS");
    app.add_option("--mfa-login-pending-secs", cfg.mfa_login_pending_secs,
                   "Seconds the intermediate mfa-pending token is valid between password "
                   "success and TOTP submission (default: 120)")
        ->default_val(120)
        ->envname("YUZU_MFA_LOGIN_PENDING_SECS");

    // Hardened authentication mode + break-glass — SOC 2 CC6.3/CC6.6.
    // See docs/auth-architecture.md "Hardened mode".
    app.add_option("--auth-mode", cfg.auth_mode,
                   "Local-password login policy (default: standard). \"standard\" = "
                   "password login enabled. \"sso-only\" = local-password login is "
                   "disabled fleet-wide (only SSO mints a session); the server refuses to "
                   "start unless an SSO provider is configured — OIDC (--oidc-issuer + "
                   "--oidc-client-id), or on Linux/macOS with HTTPS a complete SAML SP "
                   "config. A single --break-glass-user "
                   "is exempt while armed (see --break-glass-arm).")
        ->default_val("standard")
        ->check(CLI::IsMember({"standard", "sso-only"}))
        ->envname("YUZU_AUTH_MODE");
    app.add_option("--break-glass-user", cfg.break_glass_user,
                   "Username of the single local account exempt from --auth-mode=sso-only "
                   "while armed. Must exist and have MFA enrolled (enforced at boot). "
                   "Arm it out-of-band with --break-glass-arm.")
        ->envname("YUZU_BREAK_GLASS_USER");
    app.add_option("--break-glass-window-secs", cfg.break_glass_window_secs,
                   "Seconds the break-glass account stays armed after --break-glass-arm "
                   "(default: 86400 = 24h, max 2592000 = 30d). The arm auto-expires — it is "
                   "never permanent.")
        ->default_val(86400)
        // Bounded 1s..30d: rejects a fat-finger like INT_MAX (~68y) that would
        // make the "auto-expiring" exemption effectively permanent, and (with the
        // arm one-shot's overflow guard) keeps datetime('now','+N seconds') well
        // clear of SQLite's overflow-to-NULL range (Hermes INFO).
        ->check(CLI::Range(1, 2592000))
        ->envname("YUZU_BREAK_GLASS_WINDOW_SECS");

    // SCIM v2 provisioning (`/scim/v2/*`) — enterprise IdP (Okta/Entra)
    // auto-provisioning + auto-deprovisioning. Disabled by default; fail-closed
    // checks (token required, HTTPS required) run just before serving — see below.
    app.add_flag("--scim-enable", cfg.scim_enable,
                "Enable the SCIM v2 provisioning surface (/scim/v2/*). Requires "
                "--scim-token and HTTPS; refuses to start otherwise.")
        ->envname("YUZU_SCIM_ENABLE");
    app.add_option("--scim-token", cfg.scim_token,
                  "Bearer credential IdPs present on every /scim/v2/* request. "
                  "Required when --scim-enable is set; stored as a sha256 hash only.")
        ->envname("YUZU_SCIM_TOKEN");
    app.add_option("--scim-admin-group", cfg.scim_admin_group,
                  "SCIM Group displayName that maps to admin role; empty disables "
                  "SCIM-group-to-admin mapping")
        ->envname("YUZU_SCIM_ADMIN_GROUP");

    // Account lockout — SOC 2 CC6.3. See docs/auth-architecture.md.
    app.add_option("--auth-lockout-threshold", cfg.auth_lockout_threshold,
                   "Consecutive failed local-password attempts before an account is temporarily "
                   "locked (default: 5). 0 disables lockout. The counter resets on a successful "
                   "login or an admin unlock.")
        ->default_val(5)
        // Fail fast on a negative value rather than silently treating it as
        // "disabled" (Hermes cyber-review F5 / Codex note). 0 is valid (off).
        ->check(CLI::NonNegativeNumber)
        ->envname("YUZU_AUTH_LOCKOUT_THRESHOLD");
    app.add_option("--auth-lockout-window-secs", cfg.auth_lockout_window_secs,
                   "Seconds an account stays locked after the threshold is crossed (default: 900). "
                   "The lock auto-expires after this window — it is never permanent.")
        ->default_val(900)
        // Reject 0 / negative at parse time instead of the runtime clamp-to-1s
        // surprise (Hermes cyber-review F5). A lock window must be >= 1 second.
        ->check(CLI::PositiveNumber)
        ->envname("YUZU_AUTH_LOCKOUT_WINDOW_SECS");

    // JIT admin elevation — SOC 2 CC6.3/CC6.6. See docs/auth-architecture.md.
    app.add_option("--jit-max-elevation-secs", cfg.jit_max_elevation_secs,
                   "Maximum lifetime (seconds) of a time-boxed admin elevation granted via "
                   "POST /api/v1/elevate (default: 3600 = 1h, max 86400 = 24h). A request asking "
                   "for longer is clamped. Eligibility is the per-user users.elevation_eligible "
                   "flag; elevation is in-memory per-session and auto-reverts on lapse.")
        ->default_val(3600)
        ->check(CLI::Range(1, 86400))
        ->envname("YUZU_JIT_MAX_ELEVATION_SECS");

    app.add_flag("--jit-oidc-amr-elevation,!--no-jit-oidc-amr-elevation",
                 cfg.jit_oidc_amr_elevation,
                 "Allow an OIDC session whose IdP login attested MFA (the `amr` claim) to "
                 "satisfy POST /api/v1/elevate's mandatory second-factor requirement without "
                 "local TOTP enrollment (default: true). A no-amr (single-factor) OIDC session "
                 "is still denied regardless. Pass --no-jit-oidc-amr-elevation to disable it — "
                 "OIDC sessions then cannot use JIT elevation at all (an operator must elevate "
                 "from a local session with local TOTP).")
        ->envname("YUZU_JIT_OIDC_AMR_ELEVATION");

    // Operator dashboard idle (inactivity) session timeout — SOC 2 CC6.3.
    app.add_option("--session-inactivity-secs", cfg.session_inactivity_secs,
                   "Seconds of inactivity after which an operator dashboard session is invalidated "
                   "server-side — a sliding window UNDER the absolute 8h session lifetime "
                   "(default: 0 = disabled; recommended 900 = 15 min). Only affects cookie "
                   "sessions; OIDC re-login and API tokens are unaffected.")
        ->default_val(0)
        ->check(CLI::NonNegativeNumber) // 0 disables; negative is rejected
        ->envname("YUZU_SESSION_INACTIVITY_SECS");

    // Metrics auth
    app.add_flag("--metrics-no-auth", "Allow unauthenticated /metrics access from any source")
        ->each([&cfg](const std::string&) { cfg.metrics_require_auth = false; })
        ->envname("YUZU_METRICS_NO_AUTH");

    // Security response headers (SOC2-C1)
    app.add_option("--csp-extra-sources", cfg.csp_extra_sources,
                   "Extra CSP sources appended to script-src/style-src/connect-src/img-src "
                   "(space-separated, e.g. \"https://cdn.example.com https://beacon.example.com\")")
        ->envname("YUZU_CSP_EXTRA_SOURCES");

    // MCP (Model Context Protocol) server
    app.add_flag("--mcp-disable", cfg.mcp_disable,
                 "Disable MCP endpoint entirely (rejects all /mcp/v1/ requests)")
        ->envname("YUZU_MCP_DISABLE");
    app.add_flag("--mcp-read-only", cfg.mcp_read_only,
                 "Restrict MCP to read-only tools only (no write/execute)")
        ->envname("YUZU_MCP_READ_ONLY");
    // MCP Streamable HTTP transport (ADR-1005 Decision 15, track 2f)
    app.add_flag("--mcp-no-streaming", cfg.mcp_streaming_disable,
                 "Disable MCP Streamable HTTP (sessions, GET/DELETE channels); plain "
                 "JSON-RPC POST only")
        ->envname("YUZU_MCP_NO_STREAMING");
    app.add_flag("--mcp-enable-streamed-post,!--no-mcp-streamed-post", cfg.mcp_streamed_post_enable,
                 "Enable SSE-on-POST for execute_instruction callers that send a "
                 "progressToken (default: true). Pass --no-mcp-streamed-post to disable.")
        ->envname("YUZU_MCP_ENABLE_STREAMED_POST");
    app.add_option("--mcp-allowed-origin", cfg.mcp_allowed_origins,
                   "Allowed Origin header value for /mcp/v1/ (scheme+host+port, exact match; "
                   "repeatable). Empty rejects any present Origin (absent is always allowed).")
        ->envname("YUZU_MCP_ALLOWED_ORIGINS");
    app.add_option("--max-sse-streams", cfg.max_sse_streams,
                   "Concurrent held-open SSE responses this server is sized for, across ALL "
                   "streaming surfaces (MCP GET, MCP streamed POST, /api/v1/events, dashboard, "
                   "legacy /events). "
                   "The HTTP worker pool is derived from this: a stream costs one blocked "
                   "thread (no CPU; resident cost is a fraction of a virtual, platform-dependent stack reservation and is not yet measured). 0 = default (128). See ADR-0034.")
        ->check(CLI::Range(std::size_t{0}, std::size_t{4096}))
        ->envname("YUZU_MAX_SSE_STREAMS");
    app.add_option("--mcp-max-streams-per-principal", cfg.mcp_max_streams_per_principal,
                   "Max concurrent MCP GET SSE streams for a single principal — an anti-monopoly "
                   "policy, not a capacity limit (capacity is --max-sse-streams). Does NOT govern "
                   "streamed POST responses: those are capped separately at a fixed 4 concurrent "
                   "calls per principal — numerically the same as, but counted and enforced "
                   "separately from, any single session's own replay-ring pin-slot count — so a "
                   "principal's steady-state held-open sum across both channels is this value "
                   "+ 4 — not a hard ceiling; a GET-channel reconnect can transiently double "
                   "the GET component (see docs/user-manual/server-admin.md)")
        // Range-checked like its two siblings above. 0 would admit nothing at all, so the
        // floor is 1; the ceiling matches --max-sse-streams (a per-principal cap above the
        // global capacity is meaningless, and the global cap clamps it anyway).
        ->check(CLI::Range(std::size_t{1}, std::size_t{4096}))
        ->envname("YUZU_MCP_MAX_STREAMS_PER_PRINCIPAL");
    app.add_option("--http-worker-threads", cfg.http_worker_threads,
                   "Pin the shared HTTP worker pool size by hand. 0 (default) derives it from "
                   "--max-sse-streams, which is what you want; setting it clamps the stream "
                   "target to what your pool can carry. The whole pool is created at BOOT, so "
                   "size the host's process/thread limit (systemd TasksMax, container pids) at "
                   "or above this number before starting.")
        // Ceiling is the real clamp the server applies (kMaxHttpWorkerThreads), so the
        // flag cannot accept a value the pool will silently refuse to honour.
        ->check(CLI::Range(std::size_t{0}, yuzu::server::detail::kMaxHttpWorkerThreads))
        ->envname("YUZU_HTTP_WORKER_THREADS");

    // Fleet visualization (PR 3 of feat/viz-engine ladder)
    app.add_flag("--viz-disable", cfg.viz_disable,
                 "Disable fleet visualization endpoints (/api/v1/viz/fleet/topology, "
                 "/fragments/viz/fleet/topology); both return 503")
        ->envname("YUZU_VIZ_DISABLE");

    // Product pack signature enforcement (#802 / W7.4)
    app.add_flag("--allow-unsigned-packs", cfg.allow_unsigned_packs,
                 "Accept product packs without an Ed25519 signature at install time. "
                 "DANGEROUS — exposes the fleet to arbitrary instruction/plugin execution "
                 "from any pack upload. Default off; set only for legacy environments that "
                 "have not yet adopted signing. Emits a `server.unsigned_packs_allowed` "
                 "audit event + startup warning when enabled.")
        ->envname("YUZU_ALLOW_UNSIGNED_PACKS");

    // Instruction-definition signature enforcement (#1073 / W7.4 sibling-gap)
    app.add_flag("--allow-unsigned-definitions", cfg.allow_unsigned_definitions,
                 "Accept InstructionDefinition imports without an Ed25519 signature at "
                 "import time. DANGEROUS — exposes the same fleet arbitrary-code-execution "
                 "surface that --allow-unsigned-packs covers on the ProductPack side: an "
                 "operator with InstructionDefinition:Write can publish a definition that "
                 "dispatches a malicious plugin invocation. Default off; set only for "
                 "legacy environments that have not yet adopted signing. Emits a "
                 "`server.unsigned_definitions_allowed` audit event + startup warning "
                 "when enabled.")
        ->envname("YUZU_ALLOW_UNSIGNED_DEFINITIONS");

    // KEK rotation runaway control (#2530 B5). See kek_routes.hpp.
    //
    // This is a RUNAWAY/ABUSE GUARD, not a rotation-schedule knob — it exists
    // to stop a looping caller (buggy automation, a compromised token) from
    // hammering /rotate, not to express how often you intend to rotate. The
    // default of 1h is sized for that job and most operators should never
    // touch this flag.
    //
    // Raising it has a real, sharp cost the operator must see BEFORE they
    // change it: it directly delays emergency re-rotation after a suspected
    // KEK compromise — the single most time-critical operation this surface
    // exists to support — and there is NO bypass. `/rewrap` only resumes a
    // half-committed rotation; it does not mint a new version. If this is
    // set to (say) 90 days to "match" a quarterly rotation cadence, a
    // routine rotation followed by a compromise the next day leaves the
    // operator refused with a 429 for the next three months, with no escape
    // short of a restart with a lower value — mid-incident. Do NOT set this
    // to your rotation cadence; leave it at the default unless you have a
    // specific, understood reason to raise it.
    //
    // Upper bound 31536000s (365d) is a sanity ceiling that rejects a
    // fat-fingered value, not an endorsement of setting the flag that high.
    // `cooldown_retry_after_ms` is a uint32 millisecond count;
    // evaluate_rotate_preconditions() (kek_rotate_control.hpp) saturates
    // rather than wraps on overflow, so this bound is defence-in-depth on
    // top of that, not the only thing keeping the retry hint honest.
    app.add_option("--kek-min-rotate-interval", cfg.kek_min_rotate_interval_secs,
                   "Durable rate limit (seconds) between KEK rotation attempts — a runaway/abuse "
                   "guard against looping automation, NOT a rotation-schedule setting (default: "
                   "3600 = 1h; most operators should never change this). Raising it delays "
                   "emergency re-rotation after a suspected key compromise, with no bypass short "
                   "of a restart. Read from the database server's own clock so it holds "
                   "cluster-wide, not just per process (max: 31536000 = 365d, a sanity ceiling — "
                   "not a suggestion to match your rotation cadence). A rotate request inside the "
                   "window is refused with a 429 carrying an honest retry_after_ms.")
        ->default_val(3600)
        ->check(CLI::Range(1, 31536000))
        ->envname("YUZU_KEK_MIN_ROTATE_INTERVAL");
    app.add_option("--kek-max-live-versions", cfg.kek_max_live_versions,
                   "Backstop ceiling on the number of non-retired KEK versions (default: 32). "
                   "A rotate request at or above the ceiling is refused with a 409. There is no "
                   "retire route (#2525), so raising this above the default is the supported "
                   "escape hatch that keeps rotation usable once an install hits it — doing so "
                   "is an explicit, logged and audited temporary risk acceptance pending #2525, "
                   "not a routine tuning knob.")
        ->default_val(yuzu::server::detail::kKekMaxLiveVersionsDefault)
        ->check(CLI::PositiveNumber)
        ->envname("YUZU_KEK_MAX_LIVE_VERSIONS");

    // Batch token generation mode (runs and exits, no server startup)
    int generate_tokens = 0;
    std::string gen_label;
    int gen_max_uses = 1;
    int gen_ttl_hours = 0;
    app.add_option("--generate-tokens", generate_tokens,
                   "Generate N enrollment tokens and print to stdout (JSON), then exit");
    app.add_option("--token-label", gen_label, "Label prefix for generated tokens");
    app.add_option("--token-max-uses", gen_max_uses, "Max uses per token (default: 1)");
    app.add_option("--token-ttl-hours", gen_ttl_hours, "Token TTL in hours (0 = no expiry)");

    // Break-glass MFA reset mode (runs and exits, no server startup). Clears a
    // user's MFA enrollment out-of-band so an operator locked out by MFA
    // enforcement (lost device, IdP not asserting amr, sole admin who could not
    // enroll) can recover. Run on the server host as the service account. The
    // reset is audited (unlike the manual SQL break-glass it replaces). #1226.
    std::string mfa_reset_user;
    app.add_option("--mfa-reset", mfa_reset_user,
                   "Break-glass: clear MFA enrollment for the named user, then exit "
                   "(audited recovery from MFA lockout)");

    // Break-glass arm mode (runs and exits, no server startup). Arms the
    // configured --break-glass-user for --break-glass-window-secs so it can log
    // in locally under --auth-mode=sso-only. Run on the server host as the
    // service account (the IdP being down is precisely why break-glass exists,
    // so arming must NOT depend on a session). Audited. SOC 2 CC6.6.
    bool break_glass_arm = false;
    app.add_flag("--break-glass-arm", break_glass_arm,
                 "Break-glass: arm --break-glass-user for the configured window, then exit "
                 "(audited; enables local login under --auth-mode=sso-only)");

    // NVD CVE feed options
    int nvd_sync_hours = 4;
    app.add_option("--nvd-api-key", cfg.nvd_api_key, "NVD API key (for higher rate limits)")
        ->envname("YUZU_NVD_API_KEY");
    app.add_option("--nvd-proxy", cfg.nvd_proxy, "HTTP proxy for NVD API (e.g. http://proxy:8080)")
        ->envname("YUZU_NVD_PROXY");
    app.add_option("--nvd-sync-interval", nvd_sync_hours, "NVD sync interval in hours (default: 4)")
        ->default_val(4)
        ->envname("YUZU_NVD_SYNC_INTERVAL");
    app.add_flag("--no-nvd-sync", "Disable NVD CVE feed sync")
        ->each([&cfg](const std::string&) { cfg.nvd_sync_enabled = false; })
        ->envname("YUZU_NO_NVD_SYNC");
    app.add_option("--nvd-backfill-years", cfg.nvd_backfill_years,
                   "How many years back the newest-first NVD backfill walks (<=0 = full history; "
                   "default: 8)")
        ->default_val(8)
        ->envname("YUZU_NVD_BACKFILL_YEARS");

    // OTA agent update options
    app.add_option("--update-dir", cfg.update_dir, "Directory for agent update binaries")
        ->envname("YUZU_UPDATE_DIR");
    app.add_flag("--no-ota", "Disable OTA agent updates")->each([&cfg](const std::string&) {
        cfg.ota_enabled = false;
    });

    // HTTPS web dashboard options
    app.add_flag("--no-https", "Disable HTTPS (insecure, for development only)")
        ->each([&cfg](const std::string&) { cfg.https_enabled = false; })
        ->envname("YUZU_NO_HTTPS");
    app.add_option("--https-port", cfg.https_port, "HTTPS port (default: 8443)")
        ->default_val(8443)
        ->envname("YUZU_HTTPS_PORT");
    app.add_option("--https-cert", cfg.https_cert_path, "PEM certificate for HTTPS")
        ->envname("YUZU_HTTPS_CERT");
    app.add_option("--https-key", cfg.https_key_path, "PEM private key for HTTPS")
        ->envname("YUZU_HTTPS_KEY");
    app.add_flag("--no-https-redirect", "Disable HTTP→HTTPS redirect")
        ->each([&cfg](const std::string&) { cfg.https_redirect = false; });

    // Certificate hot-reload options
    app.add_flag("--no-cert-reload", "Disable automatic certificate hot-reload")
        ->each([&cfg](const std::string&) { cfg.cert_reload_enabled = false; })
        ->envname("YUZU_NO_CERT_RELOAD");
    app.add_option("--cert-reload-interval", cfg.cert_reload_interval_seconds,
                   "Certificate reload polling interval in seconds (default: 60)")
        ->default_val(60)
        ->envname("YUZU_CERT_RELOAD_INTERVAL");

    // OIDC SSO options
    app.add_option("--oidc-issuer", cfg.oidc_issuer,
                   "OIDC issuer URL (e.g. https://login.microsoftonline.com/{tenant}/v2.0)")
        ->envname("YUZU_OIDC_ISSUER");
    app.add_option("--oidc-client-id", cfg.oidc_client_id, "OIDC client ID (app registration)")
        ->envname("YUZU_OIDC_CLIENT_ID");
    app.add_option("--oidc-client-secret", cfg.oidc_client_secret,
                   "OIDC client secret (required for Entra/Azure AD web apps)")
        ->envname("YUZU_OIDC_CLIENT_SECRET");
    app.add_option("--oidc-redirect-uri", cfg.oidc_redirect_uri,
                   "OIDC redirect URI (default: auto-computed from web address/port)")
        ->envname("YUZU_OIDC_REDIRECT_URI");
    app.add_option("--oidc-admin-group", cfg.oidc_admin_group,
                   "Entra group object ID that maps to admin role")
        ->envname("YUZU_OIDC_ADMIN_GROUP");
    app.add_flag("--oidc-skip-tls-verify", cfg.oidc_skip_tls_verify,
                 "Disable TLS certificate verification for OIDC endpoints (INSECURE, dev only)")
        ->envname("YUZU_OIDC_SKIP_TLS_VERIFY");
    // ADR-2001 §1 — selects which validated ID token claim is used as the
    // SCIM-externalId join key at login. "sub" (default) matches Okta's
    // typical externalId; "oid" matches Entra (whose externalId rides the
    // `oid` claim, not `sub`). Boot rejects anything outside the allow-list
    // fail-closed (CLI::IsMember below), never a silent fallback.
    app.add_option("--oidc-scim-link-claim", cfg.oidc_scim_link_claim,
                   "ID token claim used as the SCIM externalId join key at OIDC login "
                   "(default: sub). Entra deployments typically need \"oid\".")
        ->default_val("sub")
        ->check(CLI::IsMember({"sub", "oid"}))
        ->envname("YUZU_OIDC_SCIM_LINK_CLAIM");

    // SAML 2.0 SSO options (not supported on Windows — fail-closed)
    app.add_option("--saml-idp-entity-id", cfg.saml_idp_entity_id,
                   "SAML IdP entityID (must match Issuer element in assertions)")
        ->envname("YUZU_SAML_IDP_ENTITY_ID");
    app.add_option("--saml-idp-sso-url", cfg.saml_idp_sso_url,
                   "SAML IdP SSO URL (HTTP-Redirect binding endpoint)")
        ->envname("YUZU_SAML_IDP_SSO_URL");
    app.add_option("--saml-idp-cert", cfg.saml_idp_cert,
                   "Filesystem path to IdP signing certificate PEM (pinned key)")
        ->envname("YUZU_SAML_IDP_CERT");
    app.add_option("--saml-sp-entity-id", cfg.saml_sp_entity_id,
                   "SAML SP entityID (used as AudienceRestriction in assertions)")
        ->envname("YUZU_SAML_SP_ENTITY_ID");
    app.add_option("--saml-sp-acs-url", cfg.saml_sp_acs_url,
                   "SAML SP Assertion Consumer Service URL (POST binding endpoint)")
        ->envname("YUZU_SAML_SP_ACS_URL");
    app.add_option("--saml-sp-key", cfg.saml_sp_key,
                   "Filesystem path to SP AuthnRequest signing private-key PEM (RSA); when "
                   "set, AuthnRequests are signed (HTTP-Redirect binding)")
        ->envname("YUZU_SAML_SP_KEY");
    app.add_option("--saml-group-attribute", cfg.saml_group_attribute,
                   "SAML <Attribute Name=\"...\"> whose values are group identifiers "
                   "(e.g. the Entra groups claim URI); empty disables group parsing")
        ->envname("YUZU_SAML_GROUP_ATTRIBUTE");
    app.add_option("--saml-admin-group", cfg.saml_admin_group,
                   "SAML group value (from --saml-group-attribute) that maps to admin role")
        ->envname("YUZU_SAML_ADMIN_GROUP");
    app.add_option("--saml-name-attribute", cfg.saml_name_attribute,
                   "SAML <Attribute Name=\"...\"> whose first value is the user's display name "
                   "(e.g. the Entra displayname claim URI); empty leaves the display as the raw "
                   "NameID. Display/audit only, never an identity or authz input")
        ->envname("YUZU_SAML_NAME_ATTRIBUTE");
    app.add_option("--saml-email-attribute", cfg.saml_email_attribute,
                   "SAML <Attribute Name=\"...\"> whose first value is the user's email "
                   "(e.g. the Entra emailaddress claim URI); empty disables email parsing. "
                   "Used only as a display fallback and logged, never stored or used for identity")
        ->envname("YUZU_SAML_EMAIL_ATTRIBUTE");

    // Data infrastructure options
    app.add_option("--response-retention-days", cfg.response_retention_days,
                   "Response retention period in days (default: 90)")
        ->default_val(90)
        ->envname("YUZU_RESPONSE_RETENTION_DAYS");
    app.add_option("--audit-retention-days", cfg.audit_retention_days,
                   "Audit log retention period in days (default: 365)")
        ->default_val(365)
        ->envname("YUZU_AUDIT_RETENTION_DAYS");
    app.add_option("--guardian-event-retention-days", cfg.guardian_event_retention_days,
                   "Guardian (guaranteed-state) event retention period in days (default: 30)")
        ->default_val(30)
        ->envname("YUZU_GUARDIAN_EVENT_RETENTION_DAYS");

    // Analytics options
    app.add_flag("--no-analytics", "Disable analytics event collection")
        ->each([&cfg](const std::string&) { cfg.analytics_enabled = false; });
    app.add_option("--analytics-drain-interval", cfg.analytics_drain_interval_seconds,
                   "Analytics drain interval in seconds (default: 10)")
        ->default_val(10)
        // governance Gate 3 sre finding, 2026-08-16: an interval <= 0 makes
        // run_drain()'s inner sleep loop execute zero iterations, busy-
        // spinning claim transactions against the shared pool with no delay.
        ->check(CLI::PositiveNumber);
    app.add_option("--analytics-batch-size", cfg.analytics_batch_size,
                   "Analytics drain batch size (default: 100)")
        ->default_val(100)
        ->check(CLI::PositiveNumber);
    app.add_option("--analytics-jsonl", cfg.analytics_jsonl_path,
                   "Path for JSON Lines analytics output file")
        ->envname("YUZU_ANALYTICS_JSONL");
    app.add_option("--clickhouse-url", cfg.clickhouse_url,
                   "ClickHouse HTTP URL (e.g. http://localhost:8123)")
        ->envname("YUZU_CLICKHOUSE_URL");
    app.add_option("--clickhouse-database", cfg.clickhouse_database,
                   "ClickHouse database name (default: yuzu)")
        ->default_val("yuzu")
        ->envname("YUZU_CLICKHOUSE_DATABASE");
    app.add_option("--clickhouse-table", cfg.clickhouse_table,
                   "ClickHouse table name (default: yuzu_events)")
        ->default_val("yuzu_events")
        ->envname("YUZU_CLICKHOUSE_TABLE");
    app.add_option("--clickhouse-user", cfg.clickhouse_username, "ClickHouse username")
        ->envname("YUZU_CLICKHOUSE_USER");
    app.add_option("--clickhouse-password", cfg.clickhouse_password, "ClickHouse password")
        ->envname("YUZU_CLICKHOUSE_PASSWORD");

    // Windows service management
    bool install_service = false;
    bool remove_service = false;
    app.add_flag("--install-service", install_service, "Install as Windows service and exit");
    app.add_flag("--remove-service", remove_service, "Remove Windows service and exit");

    CLI11_PARSE(app, argc, argv);

    // Apply configuration floors ONCE, before anything reads cfg, so the metrics,
    // the settings page and the docs all report the value the server enforces.
    yuzu::server::normalize_ota_options(cfg);

    // ── CSRF trusted origins: normalise ONCE, here (#2537) ──
    // Comma-splitting, trimming, lowercasing and default-port stripping happen
    // exactly once at boot rather than per request. Storing the normalised form
    // back into cfg means every consumer compares like for like, and the gate
    // itself stays a pure comparison.
    // Count what was SUPPLIED before normalising, so a rejected entry can be
    // reported. Normalisation legitimately drops pieces (empty, host-less,
    // userinfo, the reserved `null`, an ambiguous bare `h:443`), and a raw token
    // may itself be comma-separated, so the count is per piece, not per flag.
    std::size_t supplied = 0;
    for (const auto& token : cfg.csrf_trusted_origins) {
        std::size_t pos = 0;
        while (pos <= token.size()) {
            const auto comma = token.find(',', pos);
            const auto piece = token.substr(pos, comma == std::string::npos ? std::string::npos
                                                                           : comma - pos);
            pos = (comma == std::string::npos) ? token.size() + 1 : comma + 1;
            if (piece.find_first_not_of(" \t\r\n") != std::string::npos)
                ++supplied;
        }
    }
    cfg.csrf_trusted_origins = yuzu::server::normalise_trusted_origins(cfg.csrf_trusted_origins);
    const std::size_t accepted = cfg.csrf_trusted_origins.size();

    if (accepted > 0) {
        // Boot-log the accepted set as deployment evidence: an operator who
        // mistypes an entry sees an opaque 403 at the dashboard, and this line
        // is what turns that into a two-second diagnosis.
        std::string joined;
        for (const auto& o : cfg.csrf_trusted_origins) {
            if (!joined.empty())
                joined += ", ";
            joined += o;
        }
        spdlog::info("CSRF same-site gate: accepting {} operator-declared external origin(s) "
                     "in addition to the request Host — {}",
                     accepted, joined);
    }
    // A config whose entries were ALL rejected previously logged nothing — boot
    // output byte-identical to not passing the flag, followed by every proxied
    // dashboard POST 403ing opaquely. That is the exact diagnosis this logging
    // exists to provide, so silence was the one outcome it could not afford.
    // Partial rejection was equally quiet: `null,https://h` logged "1 origin"
    // while the operator supplied two.
    if (supplied > accepted) {
        spdlog::warn("CSRF same-site gate: {} of {} supplied --csrf-trusted-origin value(s) were "
                     "REJECTED as invalid and are NOT trusted. Rejected shapes: empty, host-less "
                     "(`:443`), userinfo (`u@h`), the reserved token `null`, and a bare host with "
                     "an explicit default port (`h:443` — write `https://h` or `http://h`).",
                     supplied - accepted, supplied);
    }

    // ── MFA enforcement mode advisory ──
    // Surface the active enforcement mode once at startup so an auditor
    // reading the boot log can confirm the deployment's posture (SOC 2
    // CC6.6 evidence). `admin-only` and `required` redirect an un-enrolled
    // login through TOTP enrollment before a session is minted; `optional`
    // (default) leaves enrollment self-service.
    if (cfg.mfa_enforcement != "optional") {
        spdlog::info("MFA enforcement active: mode={} — un-enrolled {} must complete TOTP "
                     "enrollment at login before a session is issued.",
                     cfg.mfa_enforcement,
                     cfg.mfa_enforcement == "required" ? "users" : "admins");
    }
    // ── JIT elevation OIDC-amr posture advisory (SRE SHOULD) ──
    // Surface once at boot, alongside the other auth-posture lines, so an
    // incident responder can discover this without reading source or an
    // individual audit row's `mfa=` detail. Gated on the SAME predicate
    // `oidc::Config::is_enabled()` uses (issuer AND client-id both set — see
    // the --auth-mode=sso-only guard below) so a local-only deployment never
    // sees an OIDC-flavoured log line.
    if (!cfg.oidc_issuer.empty() && !cfg.oidc_client_id.empty() &&
        cfg.jit_oidc_amr_elevation) {
        spdlog::info("OIDC MFA (amr) may satisfy the elevation second-factor without local TOTP "
                     "enrollment — pass --no-jit-oidc-amr-elevation to disable it, in which case "
                     "OIDC sessions cannot use JIT elevation at all (an operator must elevate from "
                     "a local session with local TOTP).");
    }
    // NOTE: the --auth-mode=sso-only fail-closed guard + posture log live just
    // before the server starts to SERVE (below), NOT here — so the host-CLI
    // one-shots (--break-glass-arm, --mfa-reset) can run on an sso-only
    // deployment even when OIDC is unreachable, which is the exact situation
    // break-glass exists for (governance happy-path finding). Standard-mode
    // deployments that pre-seed --break-glass-user are warned there too.
    // Account lockout posture (SOC 2 CC6.3 evidence). Surfaced once at boot
    // so an operator/auditor can confirm the deployment's brute-force
    // protection from journald without scraping per-event logs. The posture is
    // gated on the Postgres auth store being wired (--postgres-dsn set):
    // lockout state lives in Postgres (users.failed_login_count / locked_until,
    // ADR-0006), not the legacy auth.db. Without --postgres-dsn there is no
    // auth store at all (ADR-0006/0007 fail-closed, no SQLite fallback) and the
    // server will refuse to start below — claiming "active" here would overstate
    // a deployment that will not boot (governance/adversarial C4), so warn honest.
    if (cfg.auth_lockout_threshold > 0) {
        if (cfg.postgres_dsn.empty()) {
            spdlog::warn("Account lockout CONFIGURED (threshold={}) but INACTIVE: failed-login "
                         "lockout requires the Postgres auth store, which needs --postgres-dsn "
                         "(or YUZU_POSTGRES_DSN). This deployment has no auth store wired and "
                         "will fail closed at boot.",
                         cfg.auth_lockout_threshold);
        } else {
            spdlog::info("Account lockout active: {} failed local-password attempts → locked "
                         "for {}s (auto-expiring).",
                         cfg.auth_lockout_threshold, cfg.auth_lockout_window_secs);
        }
    } else {
        spdlog::warn("Account lockout DISABLED (--auth-lockout-threshold=0) — local-password "
                     "logins have no brute-force throttle.");
    }
    // Idle (inactivity) session-timeout posture (SOC 2 CC6.3 evidence). Unlike
    // lockout this is an in-memory control (no auth.db dependency), so it is
    // honestly "active" whenever configured. The absolute 8h session lifetime
    // applies regardless.
    if (cfg.session_inactivity_secs > 0) {
        // Derive the absolute-lifetime seconds from the single source of truth
        // (kSessionDuration) so this warn threshold and the docs can't silently
        // drift if the absolute lifetime ever changes (governance consistency).
        const auto abs_lifetime_secs = std::chrono::duration_cast<std::chrono::seconds>(
                                           yuzu::server::auth::AuthManager::kSessionDuration)
                                           .count();
        spdlog::info("Idle session timeout active: operator dashboard sessions are invalidated "
                     "after {}s of inactivity (under the absolute {}s session lifetime).",
                     cfg.session_inactivity_secs, abs_lifetime_secs);
        if (cfg.session_inactivity_secs >= abs_lifetime_secs) {
            spdlog::warn("--session-inactivity-secs={} >= the absolute session lifetime ({}s); "
                         "the idle window will never trigger before absolute expiry.",
                         cfg.session_inactivity_secs, abs_lifetime_secs);
        }
    } else {
        spdlog::info("Idle session timeout DISABLED (--session-inactivity-secs=0) — only the "
                     "absolute 8h session lifetime applies.");
    }
    // PR2 governance Gate 2 sec-M6: the step-up gate honours
    // window_secs <= 0 as an "escape hatch" that lets every request
    // through without re-prompting. The helper itself doesn't log on
    // every skip (too noisy), so we surface it once at startup so the
    // operator sees the disabled state in journald and an auditor
    // reading the boot log can spot a misconfigured deployment. The JIT
    // elevation handlers are the exception: AuthRoutes substitutes a 300 s window
    // for them when this flag is <= 0 (auth_routes.cpp, kElevationStepUpWindow),
    // so they keep prompting and keep emitting their audit rows.
    if (cfg.mfa_step_up_window_secs <= 0) {
        spdlog::warn(
            "--mfa-step-up-window-secs={} disables the MFA step-up gate on every high-risk "
            "REST + Settings endpoint except the JIT-elevation endpoints (POST /api/v1/elevate "
            "and the elevation-eligibility routes), which still require an MFA-enrolled "
            "caller's proof (local TOTP or IdP `amr`) to be no older than 300s. The "
            "disabled endpoints will NOT re-prompt for MFA proof and emit no SOC 2 CC6.6 "
            "`mfa.step_up.required` evidence rows. Set to a positive value (default 300) "
            "to re-enable.",
            cfg.mfa_step_up_window_secs);
    }

    // KEK rotation runaway control posture (#2530 B5). --kek-max-live-versions
    // above the shipped default of 32 is a deliberate, temporary risk
    // acceptance pending #2525 (no retire route exists yet, so raising the
    // ceiling is the only way to keep rotation usable once an install hits
    // it) — surface it loudly here; the matching `server.kek_ceiling_raised`
    // audit event fires in server.cpp once audit_store_ exists (mirrors the
    // --allow-unsigned-packs log+audit pattern above).
    if (yuzu::server::detail::kek_ceiling_is_risk_acceptance(cfg.kek_max_live_versions)) {
        spdlog::warn("--kek-max-live-versions={} is ABOVE the default of {} — this is a "
                     "deliberate, temporary risk acceptance: there is no KEK retire route "
                     "(#2525), so raising the ceiling is the supported way to keep rotation "
                     "usable once an install hits it. This will be audited as "
                     "`server.kek_ceiling_raised`.",
                     cfg.kek_max_live_versions, yuzu::server::detail::kKekMaxLiveVersionsDefault);
    }

    // ── Validate operator-supplied CSP extras (SOC2-C1, gov UP-1/UP-2) ──
    // Done immediately after CLI parse so operators see a clear startup
    // error rather than a silently-dropped CSP header on every response.
    if (auto validated = yuzu::server::security::validate_csp_extra_sources(cfg.csp_extra_sources);
        validated.has_value()) {
        cfg.csp_extra_sources = std::move(*validated);
    } else {
        std::cerr << "Invalid --csp-extra-sources: " << validated.error() << "\n";
        return EXIT_FAILURE;
    }

    // ── Validate --gateway-cluster-addr (HA WS-4 4.3) ──
    // A malformed/duplicate entry here is a routing-correctness defect, not
    // an advisory allowlist like --trusted-nat-cidr's own lenient parse —
    // fail the CLI outright rather than silently dropping or half-applying
    // an entry (Fable pre-implementation review, 4.3 plan).
    if (auto parsed = yuzu::server::parse_gateway_cluster_addrs(
            gateway_cluster_addr_entries, yuzu::server::detail::kMaxClusterIdLen);
        parsed.has_value()) {
        cfg.gateway_cluster_addresses = std::move(*parsed);
    } else {
        std::cerr << "Invalid --gateway-cluster-addr: " << parsed.error() << "\n";
        return EXIT_FAILURE;
    }

#ifdef _WIN32
    if (install_service || remove_service) {
        SC_HANDLE scm = OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS);
        if (!scm) {
            std::cerr << "Failed to open SCM (run as administrator)\n";
            return EXIT_FAILURE;
        }
        if (install_service) {
            wchar_t exe_path[MAX_PATH];
            GetModuleFileNameW(nullptr, exe_path, MAX_PATH);
            SC_HANDLE svc =
                CreateServiceW(scm, L"YuzuServer", L"Yuzu Server", SERVICE_ALL_ACCESS,
                               SERVICE_WIN32_OWN_PROCESS, SERVICE_AUTO_START, SERVICE_ERROR_NORMAL,
                               exe_path, nullptr, nullptr, nullptr, nullptr, nullptr);
            if (svc) {
                SERVICE_DESCRIPTIONW desc;
                desc.lpDescription = const_cast<wchar_t*>(L"Yuzu endpoint management server");
                ChangeServiceConfig2W(svc, SERVICE_CONFIG_DESCRIPTION, &desc);
                SERVICE_DELAYED_AUTO_START_INFO delayed = {TRUE};
                ChangeServiceConfig2W(svc, SERVICE_CONFIG_DELAYED_AUTO_START_INFO, &delayed);
                SC_ACTION actions[3] = {{SC_ACTION_RESTART, 60000},
                                        {SC_ACTION_RESTART, 60000},
                                        {SC_ACTION_RESTART, 60000}};
                SERVICE_FAILURE_ACTIONSW failure = {};
                failure.dwResetPeriod = 86400;
                failure.cActions = 3;
                failure.lpsaActions = actions;
                ChangeServiceConfig2W(svc, SERVICE_CONFIG_FAILURE_ACTIONS, &failure);
                CloseServiceHandle(svc);
                std::cout << "Service 'YuzuServer' installed successfully\n";
            } else {
                auto err = GetLastError();
                std::cerr << (err == ERROR_SERVICE_EXISTS ? "Service already exists\n"
                                                          : "Failed to create service\n");
                CloseServiceHandle(scm);
                return EXIT_FAILURE;
            }
        }
        if (remove_service) {
            SC_HANDLE svc = OpenServiceW(scm, L"YuzuServer", DELETE | SERVICE_STOP);
            if (svc) {
                SERVICE_STATUS status;
                ControlService(svc, SERVICE_CONTROL_STOP, &status);
                DeleteService(svc) ? std::cout << "Service removed\n"
                                   : std::cerr << "Failed to delete service\n";
                CloseServiceHandle(svc);
            } else {
                std::cerr << "Service not found\n";
                CloseServiceHandle(scm);
                return EXIT_FAILURE;
            }
        }
        CloseServiceHandle(scm);
        return EXIT_SUCCESS;
    }
#endif

    // Auto-compute OIDC redirect URI if not explicitly set
    if (!cfg.oidc_issuer.empty() && cfg.oidc_redirect_uri.empty()) {
        auto scheme = cfg.https_enabled ? "https" : "http";
        auto port = cfg.https_enabled ? cfg.https_port : cfg.web_port;
        cfg.oidc_redirect_uri = std::format("{}://localhost:{}/auth/callback", scheme, port);
    }

    cfg.nvd_sync_interval = std::chrono::seconds(nvd_sync_hours * 3600);
    cfg.rate_limit = rate_limit;
    cfg.login_rate_limit = login_rate_limit;

    // Configure logging — stderr + optional rotating file
    spdlog::set_level(spdlog::level::from_str(log_level));
    if (!log_file.empty()) {
        auto file_sink = std::make_shared<spdlog::sinks::rotating_file_sink_mt>(
            log_file, log_max_size, log_max_files);
        auto stderr_sink = std::make_shared<spdlog::sinks::stderr_color_sink_mt>();
        auto logger =
            std::make_shared<spdlog::logger>("", spdlog::sinks_init_list{stderr_sink, file_sink});
        logger->set_level(spdlog::level::from_str(log_level));
        spdlog::set_default_logger(logger);
    }
    if (log_format == "json") {
        spdlog::set_formatter(std::make_unique<yuzu::JsonLogFormatter>("server"));
    } else {
        spdlog::set_pattern("[%Y-%m-%d %H:%M:%S.%e] [%^%l%$] [%t] %v");
    }

    spdlog::info("Yuzu Server v{} ({})", yuzu::kFullVersionString, yuzu::kGitCommitHash);

    // ── Multi-host Postgres DSN guard (HA WS-8) ──
    // A multi-host DSN without target_session_attrs=read-write lets libpq put the
    // pool's connections on a standby, and /readyz cannot see them all. Add
    // read-write when the attribute is absent; refuse a weaker explicit value, and
    // refuse load_balance_hosts. Done after logging is configured (so the line
    // reaches --log-file and --log-format json) and before the auth bootstrap
    // pool and Server::create, so every connection — both pools, the leader
    // elector and the readiness probe — uses the same normalised DSN. See
    // pg/multi_host_dsn.hpp.
    if (auto guarded = yuzu::server::pg::enforce_multi_host_read_write(cfg.postgres_dsn);
        guarded.has_value()) {
        if (guarded->appended)
            spdlog::warn("Postgres connection names {} hosts{} without target_session_attrs; "
                         "using target_session_attrs=read-write so the server only connects to "
                         "a writable primary (set it explicitly to silence this)",
                         guarded->hosts,
                         guarded->hosts_from_env ? " (from PGHOST/PGHOSTADDR)" : "");
        cfg.postgres_dsn = std::move(guarded->dsn);
    } else {
        spdlog::critical("Invalid --postgres-dsn: {}", guarded.error());
        return EXIT_FAILURE;
    }

    // ── TLS cipher policy self-check (#4722) ─────────────────────────────────
    // Refuse to start rather than silently serve on an OpenSSL build where our
    // allow-list resolves to zero usable TLS 1.2 ciphers.
    {
        const auto tls_policy = yuzu::tls::resolve_cipher_policy();
        if (!tls_policy) {
            spdlog::critical("{}", yuzu::tls::describe_cipher_policy_error(tls_policy.error()));
            return EXIT_FAILURE;
        }
        for (const auto& line : yuzu::tls::tls_policy_report_lines(*tls_policy))
            spdlog::info("{}", line);
    }

    // ── Insecure-TLS gate (issue #79) ────────────────────────────────────────
    // Disabling client certificate verification requires BOTH a CLI flag AND
    // an explicit environment variable, so that no single misconfiguration
    // (typo, copy-pasted command, leaked CLI history) can silently downgrade
    // the agent listener from mTLS to one-way TLS.
    if (deprecated_tls_flag_used) {
        spdlog::warn("--allow-one-way-tls is deprecated; use --insecure-skip-client-verify "
                     "instead (this flag will be removed in a future release).");
    }
    if (cfg.insecure_skip_client_verify && cfg.tls_enabled) {
        if (!yuzu::server::security::insecure_tls_env_authorized()) {
            spdlog::error("--insecure-skip-client-verify requires YUZU_ALLOW_INSECURE_TLS=1 "
                          "in the environment as a second confirmation. Refusing to start.");
            return EXIT_FAILURE;
        }
        spdlog::error("***********************************************************************");
        spdlog::error("*** CLIENT CERTIFICATE VERIFICATION DISABLED (one-way TLS)          ***");
        spdlog::error("*** Any network peer can connect to the agent listener AND the      ***");
        spdlog::error("*** management listener without an mTLS client certificate. This is ***");
        spdlog::error("*** acceptable ONLY for short-term development or migration         ***");
        spdlog::error("*** scenarios. Re-enable mTLS by supplying --ca-cert (and           ***");
        spdlog::error("*** --management-ca-cert if a management override is configured)    ***");
        spdlog::error("*** and removing --insecure-skip-client-verify.                     ***");
        spdlog::error("***********************************************************************");
    }

    // ── --no-tls warning banner ──────────────────────────────────────────────
    // --no-tls is the supported posture for UAT and customer demos until the
    // CA/CSR pipeline is automated. It is intentionally NOT gated behind an
    // env var (an operator passing --no-tls is opting in to plaintext loudly
    // and explicitly), but we make the degradation impossible to miss in logs.
    if (!cfg.tls_enabled) {
        spdlog::error("***********************************************************************");
        spdlog::error("*** --no-tls IS UNSAFE                                              ***");
        spdlog::error("*** TLS is fully disabled. The agent gRPC listener AND the          ***");
        spdlog::error("*** management gRPC listener accept plaintext connections from any  ***");
        spdlog::error("*** network peer with no encryption and no peer authentication.     ***");
        spdlog::error("*** The administrative surface is ungated. Anyone reachable on the  ***");
        spdlog::error("*** management port can issue admin RPCs.                           ***");
        spdlog::error("*** Use --no-tls ONLY for local UAT, customer demos, and dev work.  ***");
        spdlog::error("***********************************************************************");
    }

    // Verify SQLite was compiled with thread-safety (FULLMUTEX requires SQLITE_THREADSAFE != 0)
    if (sqlite3_threadsafe() == 0) {
        spdlog::critical("SQLite compiled with SQLITE_THREADSAFE=0 — FULLMUTEX disabled, "
                         "concurrent access unsafe");
        return EXIT_FAILURE;
    }

    // -- Auth config loading / first-run setup --------------------------------

    namespace auth = yuzu::server::auth;

    auto cfg_path =
        config_file.empty() ? auth::default_config_path() : std::filesystem::path(config_file);

    auth::AuthManager auth_mgr;
    // Idle (inactivity) session timeout — SOC 2 CC6.3. In-memory feature, set
    // unconditionally (works with or without auth.db). 0 = disabled.
    auth_mgr.set_session_inactivity(std::chrono::seconds(cfg.session_inactivity_secs));

    if (!auth_mgr.load_config(cfg_path)) {
        spdlog::warn("No user config found at {}", cfg_path.string());
        spdlog::info("Running first-time setup...");

        if (!auth::AuthManager::first_run_setup(cfg_path)) {
            spdlog::error("First-run setup failed — exiting");
            return EXIT_FAILURE;
        }

        // Reload after setup
        if (!auth_mgr.load_config(cfg_path)) {
            spdlog::error("Failed to load config after setup — exiting");
            return EXIT_FAILURE;
        }
    }

    cfg.auth_config_path = cfg_path;

    // AuthDB is now Postgres-backed (ADR-0006 substrate migration) and, for
    // actual SERVING, is constructed + owned by ServerImpl off its own
    // pg_pool_ (server.cpp) — main.cpp no longer builds the long-lived
    // instance or calls auth_mgr.set_auth_db() (server.cpp does, inside
    // Server::create()).
    //
    // main.cpp DOES still need its own short-lived AuthDB here, for two
    // reasons that both run BEFORE Server::create() exists to ask:
    //   1. Fresh-start admin seeding (below) — auth.users is empty on a
    //      brand-new Postgres database, so the config-file admin (loaded
    //      into auth_mgr above) must be persisted once via
    //      seed_admin_if_empty(), which is TOCTOU-free against a second
    //      server instance racing first boot.
    //   2. The host-CLI one-shots (--mfa-reset / --break-glass-arm) and the
    //      --auth-mode=sso-only break-glass validation, all of which run
    //      (and may exit) before Server::create() is ever called.
    // Constructing a second, independent PgPool/FileKeyProvider/SecretCodec/
    // AuthDB stack here is safe: schema migration (PgMigrationRunner) and
    // secret-column registration + first-boot KEK generation
    // (SecretCodec::init) are both idempotent — ServerImpl's own stack,
    // built moments later against the same database, just re-verifies an
    // already-migrated schema and an already-generated KEK. Declared in the
    // same dependency order server.cpp uses (pool → provider → codec →
    // authdb) so destruction is safe, and torn down (out of scope) before
    // Server::create() is invoked below — this process never holds two
    // live AuthDB reaper threads at once.
    std::optional<yuzu::server::pg::PgPool> auth_pg_pool;
    std::optional<yuzu::server::FileKeyProvider> auth_key_provider;
    std::optional<yuzu::server::pg::SecretCodec> auth_secret_codec;
    std::unique_ptr<yuzu::server::AuthDB> auth_db;

    if (cfg.postgres_dsn.empty()) {
        // Server::create() will itself refuse to start (ADR-0006/0007 fail
        // closed, no SQLite fallback) — nothing to seed or validate here.
        spdlog::warn("--postgres-dsn is not set: no auth store is available. Server startup will "
                     "fail closed; any --mfa-reset / --break-glass-arm one-shot will also fail.");
    } else {
        // Small, short-lived pool — this stack exists only to seed/validate
        // before Server::create() builds the real, fully-sized pool.
        auth_pg_pool.emplace(
            yuzu::server::pg::PgPool::Options{.conninfo = cfg.postgres_dsn, .size = 2});
        if (!auth_pg_pool->valid()) {
            spdlog::error("Cannot connect to PostgreSQL for auth store bootstrap: {}",
                          auth_pg_pool->last_error());
            return EXIT_FAILURE;
        }
        // HA WS-8: the multi-host guard above sees only the DSN and PG* env; a
        // service file (service= / PGSERVICE) is applied by libpq at connect time.
        // Check what libpq actually resolved on a live connection, and refuse to
        // start on load_balance_hosts or a host list without read-write (Gate 8
        // round 7). libpq re-reads a service file on every connect; the readiness
        // probe repeats this check on each connection IT makes, so a later edit
        // shows on /readyz only at the probe's next reconnect (contract residual
        // (2), pg_reachability_probe.hpp) — restart the server after editing it.
        {
            auto lease = auth_pg_pool->acquire();
            if (!lease) {
                spdlog::error("Cannot connect to PostgreSQL to check the connection settings");
                return EXIT_FAILURE;
            }
            if (auto ok = yuzu::server::pg::check_effective_connection(lease.get()); !ok) {
                spdlog::critical("Invalid Postgres connection settings: {}", ok.error());
                return EXIT_FAILURE;
            }
        }
        const std::filesystem::path key_dir =
            cfg.ca_dir.empty() ? yuzu::server::auth::default_cert_dir() : cfg.ca_dir;
        auth_key_provider.emplace(key_dir);
        auth_secret_codec.emplace(*auth_key_provider);
        auth_db = std::make_unique<yuzu::server::AuthDB>(*auth_pg_pool, *auth_secret_codec);
        if (!auth_db->is_open()) {
            spdlog::error("Failed to open the Postgres auth store (auth.users migration failed)");
            return EXIT_FAILURE;
        }
        {
            auto lease = auth_pg_pool->acquire();
            if (!lease) {
                spdlog::error("Cannot acquire a connection to run SecretCodec::init() for the "
                              "auth store bootstrap: {}",
                              auth_pg_pool->last_error());
                return EXIT_FAILURE;
            }
            auto init_res = auth_secret_codec->init(lease.get());
            lease.reset();
            if (!init_res) {
                spdlog::error("SecretCodec::init() failed for the auth store bootstrap — {}: {}",
                              yuzu::server::pg::SecretCodec::to_string(init_res.error().kind),
                              init_res.error().message);
                return EXIT_FAILURE;
            }
        }

        // Fresh-start seed (ADR-0006 cutover): seed the configured admin
        // (loaded into auth_mgr above via load_config()/first_run_setup())
        // iff auth.users is genuinely empty. A seed ERROR is FATAL — never
        // warning-only (a boot that silently fails to seed leaves an
        // operator locked out of a brand-new deployment with no diagnosis).
        const auto cfg_users = auth_mgr.list_users();
        const yuzu::server::auth::UserEntry* seed_user = nullptr;
        for (const auto& u : cfg_users) {
            if (u.role == yuzu::server::auth::Role::admin) {
                seed_user = &u;
                break;
            }
        }
        if (!seed_user && !cfg_users.empty()) {
            seed_user = &cfg_users.front();
        }
        if (seed_user != nullptr) {
            auto seeded = auth_db->seed_admin_if_empty(seed_user->username, seed_user->hash_hex,
                                                        seed_user->salt_hex);
            if (!seeded) {
                spdlog::error(
                    "Fatal: failed to seed the admin user into the Postgres auth store "
                    "(error={}) — refusing to start rather than boot into an unusable auth "
                    "store.",
                    static_cast<int>(seeded.error()));
                return EXIT_FAILURE;
            }
            if (*seeded) {
                spdlog::warn(
                    "AUTH DATA RESET ON POSTGRES CUTOVER — admin user '{}' was re-seeded into "
                    "the Postgres auth store because it was empty. Any prior local accounts, "
                    "roles, and MFA enrollments (from a legacy auth.db / a different Postgres "
                    "database) are GONE. This warning is logged once, only when a seed actually "
                    "occurs.",
                    seed_user->username);
                // Threaded into ServerImpl via Config (metrics_ doesn't exist
                // yet at this point — Server::create() hasn't run) — see
                // Config::auth_fresh_start_seeded doc comment.
                cfg.auth_fresh_start_seeded = true;
            }
        }
    }

    // If --data-dir was specified, ensure it exists and resolve to canonical path.
    // Unrelated to AuthDB (now Postgres-backed) — this still gates the
    // legacy SQLite stores (audit.db, responses.db, ...).
    if (!cfg.data_dir.empty()) {
        std::error_code ec;
        std::filesystem::create_directories(cfg.data_dir, ec);
        if (ec) {
            spdlog::error("Cannot create data directory {}: {}", cfg.data_dir.string(),
                          ec.message());
            return EXIT_FAILURE;
        }
        // Resolve symlinks to prevent privileged write redirection
        auto canonical = std::filesystem::canonical(cfg.data_dir, ec);
        if (ec) {
            spdlog::error("Cannot resolve data directory {}: {}", cfg.data_dir.string(),
                          ec.message());
            return EXIT_FAILURE;
        }
        cfg.data_dir = canonical;

        // Writable probe — fail startup if directory is not writable rather than
        // deferring to the first DB open (which would leave the server running
        // but returning 503 on every store operation).
        auto probe = cfg.data_dir / ".yuzu-probe";
        {
            std::ofstream f(probe);
            if (!f.is_open()) {
                spdlog::error("Data directory {} is not writable", cfg.data_dir.string());
                return EXIT_FAILURE;
            }
        }
        std::filesystem::remove(probe, ec); // best-effort cleanup

        auth_mgr.set_data_dir(cfg.data_dir);
        // Re-load tokens and pending agents from the new data directory.
        // The initial load_config() loaded them from cfg_path_ parent (the old
        // location) because set_data_dir() hadn't been called yet.
        auth_mgr.reload_state();

        spdlog::info("Data directory: {}", cfg.data_dir.string());
    }

    // -- Break-glass MFA reset mode (exits without starting server) -----------
    // Out-of-band recovery for an operator locked out by MFA enforcement.
    // Runs on the server host as the service account; clears the user's MFA
    // and writes an audit row (the manual SQL break-glass it replaces bypassed
    // the audit chain — #1226). Under enforcement the user is walked through
    // re-enrollment at their next login.
    if (!mfa_reset_user.empty()) {
        if (!auth_db) {
            spdlog::error("--mfa-reset requires the Postgres auth store; --postgres-dsn is not "
                          "configured (or could not be opened above).");
            return EXIT_FAILURE;
        }
        // Defence-in-depth: validate the CLI arg before it touches the store
        // (governance sec-LOW-1). The SQL is parameterised and user_exists
        // would reject a non-conforming value anyway, but validating up front
        // keeps the charset guarantee local to the entry point.
        if (!yuzu::server::is_valid_username(mfa_reset_user)) {
            spdlog::error("--mfa-reset: '{}' is not a valid username", mfa_reset_user);
            std::cerr << "error: invalid username\n";
            return EXIT_FAILURE;
        }
        auto exists = auth_db->user_exists(mfa_reset_user);
        if (!exists) {
            // Distinguish a store error from a genuinely-absent user so an
            // operator mid-lockout isn't misled (governance cpp-safety SHOULD).
            spdlog::error("--mfa-reset: auth store error checking '{}': {}", mfa_reset_user,
                          static_cast<int>(exists.error()));
            std::cerr << "error: auth store unavailable\n";
            return EXIT_FAILURE;
        }
        if (!*exists) {
            spdlog::error("--mfa-reset: user '{}' not found", mfa_reset_user);
            std::cerr << "error: user '" << mfa_reset_user << "' not found\n";
            return EXIT_FAILURE;
        }
        // Audit is MANDATORY for break-glass: the whole point of #1226 is to
        // replace the manual-SQL path that left no evidence (SOC 2 CC6.6). So
        // open + verify the audit store is WRITABLE *before* mutating MFA — if
        // it isn't, refuse to proceed rather than silently clear a second factor
        // with no record (H-1). This also gives the operator an actionable error
        // instead of a buried warning during a stressful recovery.
        // ADR-0040: AuditStore is Postgres-backed. Reuse the already-open,
        // validated break-glass PgPool (auth_pg_pool is non-null here — this
        // block is guarded by `if (!auth_db)` above, and auth_db only exists
        // when auth_pg_pool is valid).
        auto audit = open_one_shot_audit(
            *auth_pg_pool, cfg.audit_retention_days, "--mfa-reset", "clear MFA",
            " Or perform the reset via your documented break-glass SQL path (which you must then "
            "record in change management).");
        if (!audit)
            return EXIT_FAILURE;
        if (auto r = auth_db->mfa_disable(mfa_reset_user); !r) {
            spdlog::error("--mfa-reset: failed to clear MFA for '{}'", mfa_reset_user);
            return EXIT_FAILURE;
        }
        // Attribute the break-glass to the KERNEL-AUTHORITATIVE OS identity, not
        // getenv("USER") — the env var is inherited from the parent and trivially
        // forgeable (USER=root ./yuzu-server --mfa-reset ...), which would let the
        // actor poison the very evidence this audit exists to provide (H-2).
        const std::string os_user = resolve_os_principal();
        yuzu::server::AuditEvent ev;
        ev.timestamp = std::chrono::duration_cast<std::chrono::seconds>(
                           std::chrono::system_clock::now().time_since_epoch())
                           .count();
        ev.principal = os_user;
        ev.principal_role = "break-glass";
        ev.action = "mfa.reset.breakglass";
        ev.target_type = "User";
        ev.target_id = mfa_reset_user;
        ev.result = "success";
        ev.detail = std::format("MFA enrollment cleared via --mfa-reset CLI (os_identity={})",
                                os_user);
        if (!audit->log(ev)) {
            // The pre-check passed but the write failed (e.g. disk filled mid-op).
            // MFA is already cleared; fail loudly and non-zero so automation and
            // the operator know the evidence row is missing and must be recorded.
            spdlog::error("--mfa-reset: MFA cleared for '{}' but the audit row failed to persist — "
                          "record this reset manually in your change-management system NOW",
                          mfa_reset_user);
            std::cerr << "error: MFA cleared but audit row failed to persist; record this reset "
                         "manually\n";
            return EXIT_FAILURE;
        }
        spdlog::info("Break-glass: MFA cleared for '{}'. The user can now sign in with their "
                     "password alone; under MFA enforcement they will be walked through "
                     "enrollment at next login.",
                     mfa_reset_user);
        std::cout << std::format("{{\"status\":\"ok\",\"user\":\"{}\",\"action\":\"{}\"}}\n",
                                 json_escape(mfa_reset_user), "mfa.reset.breakglass");
        return EXIT_SUCCESS;
    }

    // -- Break-glass arm mode (exits without starting server) -----------------
    // Arms the configured --break-glass-user for --break-glass-window-secs so it
    // can log in locally under --auth-mode=sso-only. Runs on the server host as
    // the service account — arming must NOT require a session, because the IdP
    // being down is exactly when you need it. The arm is audited (SOC 2 CC6.6),
    // attributed to the kernel-authoritative OS identity (not the forgeable
    // USER env var), and the audit store is verified writable BEFORE the mutate
    // so the exemption is never granted without an evidence row — mirrors the
    // --mfa-reset break-glass contract (#1226).
    if (break_glass_arm) {
        if (cfg.break_glass_user.empty()) {
            spdlog::error("--break-glass-arm requires --break-glass-user (or "
                          "YUZU_BREAK_GLASS_USER) to name the account to arm.");
            std::cerr << "error: --break-glass-arm requires --break-glass-user\n";
            return EXIT_FAILURE;
        }
        if (!auth_db) {
            spdlog::error("--break-glass-arm requires the Postgres auth store; --postgres-dsn is "
                          "not configured (or could not be opened above).");
            return EXIT_FAILURE;
        }
        // Same fail-closed validation the running server applies: the account
        // must exist and carry a second factor before it can be armed.
        std::string why;
        if (!break_glass_user_valid(*auth_db, cfg.break_glass_user, why)) {
            spdlog::error("--break-glass-arm: refusing to arm '{}': {}", cfg.break_glass_user, why);
            std::cerr << "error: cannot arm break-glass account: " << why << "\n";
            return EXIT_FAILURE;
        }
        // Audit is MANDATORY (CC6.6): verify the audit store is WRITABLE before
        // arming, so the exemption is never granted without a record.
        // ADR-0040: Postgres-backed AuditStore; reuse the validated PgPool
        // (auth_pg_pool non-null — guarded by `if (!auth_db)` above).
        auto audit = open_one_shot_audit(*auth_pg_pool, cfg.audit_retention_days,
                                         "--break-glass-arm", "arm break-glass");
        if (!audit)
            return EXIT_FAILURE;
        auto armed = auth_db->arm_break_glass(cfg.break_glass_user, cfg.break_glass_window_secs);
        if (!armed) {
            spdlog::error("--break-glass-arm: failed to arm '{}' (auth store error {})",
                          cfg.break_glass_user, static_cast<int>(armed.error()));
            std::cerr << "error: failed to arm break-glass account\n";
            return EXIT_FAILURE;
        }
        // Governance UP-4: a window so large that datetime('now','+N seconds')
        // overflows to NULL leaves the row dormant (armed=false, armed_until="")
        // — the UPDATE "succeeds" but the account is NOT armed. Detect that and
        // fail loudly rather than print "ARMED until " (empty) and exit 0, which
        // would leave the operator believing the glass is open when it is not.
        if (!armed->armed || armed->armed_until.empty()) {
            spdlog::error("--break-glass-arm: window {}s produced no valid expiry (too large?) — "
                          "the account is NOT armed. Choose a smaller --break-glass-window-secs.",
                          cfg.break_glass_window_secs);
            std::cerr << "error: window too large; account not armed\n";
            return EXIT_FAILURE;
        }
        // Non-atomic across two stores: the arm mutated schema `auth`, the audit
        // row lands in schema `audit_store`. Same Postgres database since
        // ADR-0040, but each store takes its OWN pool lease, so the two writes
        // are still separate transactions. The order is arm-then-audit (a false
        // audit row for an arm that didn't happen would be worse), but a HANDLED
        // audit-write failure is COMPENSATED below by un-arming, so the "never
        // granted without a record" guarantee holds (review #1735 HIGH-2). The
        // only residual window is a SIGKILL / power loss in the ~microseconds
        // between the UPDATE and the INSERT — and the next break-glass login
        // still emits auth.breakglass.login as a backstop signal.
        const std::string os_user = resolve_os_principal();
        yuzu::server::AuditEvent ev;
        ev.timestamp = std::chrono::duration_cast<std::chrono::seconds>(
                           std::chrono::system_clock::now().time_since_epoch())
                           .count();
        ev.principal = os_user;
        ev.principal_role = "break-glass";
        ev.action = "auth.breakglass.armed";
        ev.target_type = "User";
        ev.target_id = cfg.break_glass_user;
        ev.result = "success";
        ev.detail = std::format("break-glass armed until {} ({}s window) via --break-glass-arm "
                                "CLI (os_identity={})",
                                armed->armed_until, cfg.break_glass_window_secs, os_user);
        if (!audit->log(ev)) {
            // COMPENSATING UN-ARM (review #1735 HIGH-2): the mandatory evidence
            // row didn't persist, so roll the arm back — the exemption must never
            // stand without a record (docs/ops-runbooks/auth-db-recovery.md).
            if (auto un = auth_db->disarm_break_glass(cfg.break_glass_user); !un) {
                // Double fault: audit AND the rollback both failed. The account
                // may be left armed with no record — this needs manual operator
                // intervention NOW.
                spdlog::error("--break-glass-arm: audit row FAILED to persist AND the compensating "
                              "un-arm of '{}' ALSO failed (error {}). The account may be ARMED "
                              "WITH NO AUDIT RECORD — manually clear break_glass_armed_until and "
                              "record this in change management IMMEDIATELY.",
                              cfg.break_glass_user, static_cast<int>(un.error()));
                std::cerr << "error: audit failed AND un-arm failed; account may be armed without "
                             "a record — manual intervention required\n";
                return EXIT_FAILURE;
            }
            spdlog::error("--break-glass-arm: audit row for '{}' failed to persist; the arm was "
                          "ROLLED BACK (account NOT armed). Fix the Postgres audit_store schema "
                          "(reachability/permissions/disk) and retry.",
                          cfg.break_glass_user);
            std::cerr << "error: audit row failed to persist; arm rolled back (account not armed)\n";
            return EXIT_FAILURE;
        }
        spdlog::warn("Break-glass account '{}' ARMED until {} ({}s). It can now sign in locally "
                     "under --auth-mode=sso-only (MFA still required). The arm auto-expires.",
                     cfg.break_glass_user, armed->armed_until, cfg.break_glass_window_secs);
        std::cout << std::format(
            "{{\"status\":\"ok\",\"user\":\"{}\",\"action\":\"auth.breakglass.armed\","
            "\"armed_until\":\"{}\"}}\n",
            json_escape(cfg.break_glass_user), json_escape(armed->armed_until));
        return EXIT_SUCCESS;
    }

    // -- Batch token generation mode (exits without starting server) ----------

    if (generate_tokens > 0) {
        auto ttl = gen_ttl_hours > 0 ? std::chrono::seconds(gen_ttl_hours * 3600)
                                     : std::chrono::seconds(0);

        auto tokens =
            auth_mgr.create_enrollment_tokens_batch(gen_label, generate_tokens, gen_max_uses, ttl);

        // Output JSON to stdout for scripting (Ansible, etc.)
        std::cout << "{\"count\":" << tokens.size() << ",\"tokens\":[\n";
        for (size_t i = 0; i < tokens.size(); ++i) {
            if (i > 0)
                std::cout << ",\n";
            std::cout << "  \"" << tokens[i] << "\"";
        }
        std::cout << "\n]}\n";

        spdlog::info("Generated {} enrollment tokens", tokens.size());
        return EXIT_SUCCESS;
    }

    // -------------------------------------------------------------------------

    // ── Hardened auth mode guard + posture (SOC 2 CC6.3/CC6.6) ──
    // Runs HERE (just before serving), after every host-CLI one-shot has already
    // early-returned, so --break-glass-arm / --mfa-reset are never blocked by it.
    if (cfg.auth_mode == "sso-only") {
        // sso-only disables the local-password path, so at least one SSO provider
        // must be able to mint a session or every operator is locked out (the
        // break-glass account is for an IdP OUTAGE, not for never wiring SSO at
        // all). Fail closed rather than booting an unreachable server. The
        // OIDC/SAML/HTTPS/platform preconditions live in the testable
        // `sso_only_boot_guard_ok` (sso_boot_guard.cpp), which gates on the SAME
        // predicate each provider uses to enable itself — OIDC needs BOTH issuer
        // and client-id (review #1735 HIGH-1); SAML (non-Windows) needs its five
        // SP fields AND HTTPS (server.cpp leaves the provider null under
        // --no-https). Mirrors the SCIM boot guard below.
        std::string sso_err;
        if (!yuzu::server::sso_only_boot_guard_ok(cfg, sso_err)) {
            spdlog::error("{}", sso_err);
            return EXIT_FAILURE;
        }
        // The break-glass account is the ONLY local-login path under sso-only, so
        // it must exist and carry a second factor. Enforce fail-closed at boot
        // rather than discovering the misconfiguration during an IdP outage when
        // an operator is trying to break the glass.
        if (!cfg.break_glass_user.empty()) {
            if (!auth_db) {
                spdlog::error("--auth-mode=sso-only with --break-glass-user requires the "
                              "Postgres auth store; set --postgres-dsn.");
                return EXIT_FAILURE;
            }
            std::string why;
            if (!break_glass_user_valid(*auth_db, cfg.break_glass_user, why)) {
                spdlog::error("--break-glass-user='{}' is invalid under --auth-mode=sso-only: {}. "
                              "Fix the account (create it / enroll MFA) or correct the flag — "
                              "refusing to start with an unusable break-glass account.",
                              cfg.break_glass_user, why);
                return EXIT_FAILURE;
            }
        }
        // Name the active SSO path(s) so this CC6.3 evidence line is accurate
        // under an OIDC-only, SAML-only, or dual deployment (the boot guard above
        // has already proven at least one is present).
        std::string sso_providers;
        if (yuzu::server::oidc_config_complete(cfg))
            sso_providers = "OIDC";
#ifndef _WIN32
        if (yuzu::server::saml_config_complete(cfg) && cfg.https_enabled)
            sso_providers += sso_providers.empty() ? "SAML" : " + SAML";
#endif
        spdlog::warn("Hardened auth mode ACTIVE (--auth-mode=sso-only): local-password login is "
                     "DISABLED fleet-wide; only SSO ({}) can mint a session.{}",
                     sso_providers,
                     cfg.break_glass_user.empty()
                         ? std::string(" No break-glass account is configured.")
                         : std::format(" Break-glass account '{}' is exempt only while armed "
                                       "(--break-glass-arm).",
                                       cfg.break_glass_user));
    } else if (!cfg.break_glass_user.empty()) {
        // A break-glass user only means something under sso-only. Warn rather
        // than fail so a standard-mode deployment that pre-seeds the env var
        // (e.g. ahead of a planned hardening) still boots.
        spdlog::warn("--break-glass-user='{}' is set but --auth-mode is 'standard' — the "
                     "break-glass exemption only applies under --auth-mode=sso-only; ignoring.",
                     cfg.break_glass_user);
    }

    // ── SCIM v2 provisioning fail-closed guard (CC6.2) ──────────────────────
    // An unauthenticated /scim/v2/* provisioning surface would be catastrophic
    // (any anonymous caller could mint/deactivate operator accounts), so refuse
    // to start rather than boot it half-configured. The token/HTTPS
    // preconditions live in the testable `scim_boot_guard_ok` (S-BOOTGUARD-TEST,
    // scim_routes.cpp) — this is the thin main-side wrapper, mirroring
    // `break_glass_user_valid` above.
    if (cfg.scim_enable) {
        std::string err;
        if (!yuzu::server::scim_boot_guard_ok(cfg, err)) {
            spdlog::error("{}", err);
            return EXIT_FAILURE;
        }
        spdlog::warn("SCIM v2 provisioning ACTIVE (--scim-enable): /scim/v2/* accepts a "
                     "bearer-token-authenticated IdP push that can provision AND deprovision "
                     "operator accounts (read-only 'user' role only).");
    }

    // Tear down the standalone auth-store bootstrap stack now — ServerImpl
    // builds its own long-lived AuthDB (off its own pg_pool_) inside
    // Server::create() below; this process must never hold two live AuthDB
    // background-reaper threads / PgPool connections open at once. Reverse
    // declaration order (authdb → codec → provider → pool) via the optional/
    // unique_ptr destructors below is the same safe order server.cpp uses.
    auth_db.reset();
    auth_secret_codec.reset();
    auth_key_provider.reset();
    auth_pg_pool.reset();

    // #3007: installed BEFORE Server::create(), not deferred to right-before-publish
    // the way the agent's make_agent() registration is. Server::create() is not the
    // agent's trivial construction — TLS cert bootstrap, the gateway mTLS client, and
    // the full gRPC BuildAndStart() can run for a real interval — and the server ships
    // as PID 1 in every published container image, where a default disposition is
    // discarded by the kernel. Nothing can be served gracefully yet, so a signal here
    // should make the process LEAVE rather than hang: this replaces the old behaviour
    // (silently swallowed, because g_server was still null and on_signal no-ops) with
    // something strictly better (killable), at the honest cost of losing the
    // graceful-attempt illusion the old code never actually delivered on this window
    // anyway. Upgraded to the real handler once the watcher is live and g_server is
    // published, below.
    std::signal(SIGINT, on_signal_hard_exit);
    std::signal(SIGTERM, on_signal_hard_exit);

    try {
        auto server = yuzu::server::Server::create(std::move(cfg), auth_mgr); // 1st: destroyed LAST

#ifndef _WIN32
        // RAII, and DECLARATION ORDER IS LOAD-BEARING: declared AFTER `server`, so
        // reverse-order destruction destroys the watcher FIRST — joining its thread,
        // which runs any in-flight stop() to completion — before the Server it calls
        // stop() on is destroyed. This is also half of the #3007 addendum fix: the old
        // stop_entered_ CAS let a losing caller (~ServerImpl, reached via `server`'s own
        // destructor below) return immediately while another thread was still
        // mid-teardown; ~ShutdownWatcher's join() now makes main WAIT for that teardown
        // to finish before ~ServerImpl even runs, so ServerImpl::stop()'s own completion
        // barrier (server.cpp) never has to arbitrate a live race on this path — only
        // the redundant, sequential, same-thread re-entry from run()'s
        // startup_failed_ early return.
        //
        // CONSTRUCTED INSIDE A TRY. ShutdownWatcher's constructor body firewalls
        // std::thread's ctor itself (catches std::system_error under EAGAIN internally,
        // calls degrade(), never rethrows) — so this try is NOT for that. It's for
        // `state_{std::make_shared<WatcherState>(...)}` in the ctor's mem-init-list,
        // which runs BEFORE the body's try block and so is NOT firewalled: a bad_alloc
        // there escapes to here. (#3007 governance cpp-expert LOW — corrected from an
        // earlier version of this comment that misattributed the throw source.) Either
        // way: if it throws, the hard-exit handler installed above is simply left in
        // place.
        std::optional<yuzu::ShutdownWatcher> shutdown_watcher;
        try {
            shutdown_watcher.emplace(
                g_shutdown_wfd,
                [] {
                    auto* s = g_server.load(std::memory_order_acquire);
                    if (!s)
                        return false; // not published yet — keep waiting, don't consume
                    s->stop();        // ordinary thread: safe to lock, join, malloc, log
                    return true;
                },
                [] {
                    // TRAP 6 (shutdown_watcher.hpp) — the watcher died on a read()
                    // error. Leaving the handlers installed means on_signal keeps
                    // writing bytes into a pipe with no reader: every SIGTERM is
                    // swallowed and the server becomes unkillable by anything but
                    // SIGKILL. SIG_DFL is not the answer either — the server is PID 1
                    // in every shipped container image, and the kernel discards a
                    // default-disposition signal there.
                    std::signal(SIGINT, on_signal_hard_exit);
                    std::signal(SIGTERM, on_signal_hard_exit);
                });
        } catch (...) {
            // Firewalled — see shutdown_watcher.hpp's construction-failure comment. The
            // hard-exit handler is already installed (pre-create, above), so this path
            // just means it stays installed instead of being upgraded below.
            spdlog::warn("could not construct the shutdown watcher (out of memory or "
                         "threads) — SIGINT/SIGTERM will exit the process immediately "
                         "and UNGRACEFULLY (no store flush, no clean DB close).");
        }
#endif

        g_server.store(server.get(), std::memory_order_release);

        // UNPUBLISH ON EVERY PATH, BEFORE the watcher is destroyed — declared AFTER
        // both `server` and `shutdown_watcher`, so reverse-order destruction runs this
        // FIRST. On Windows this also WAITS (via g_server_mu) for any in-flight
        // console-handler stop() to return before nulling g_server, closing the same
        // race the POSIX side closes structurally via ~ShutdownWatcher's join(). Mirrors
        // agents/core/src/main.cpp's AgentUnpublisher (#1822 / Gate-8 round 8 UP8-1).
        //
        // #3007 governance (cpp-expert LOW, unhappy-path UP-1): also reinstalls the
        // hard-exit handlers, unconditionally. The explicit reinstall a few lines below
        // `server->run();` only runs on NORMAL return — if run() itself throws, that
        // line is skipped by the unwind, and the still-installed graceful `on_signal`
        // would find a retracted/about-to-retract pipe for the whole span of
        // `~ShutdownWatcher`'s join + `~ServerImpl`'s (first-time, synchronous) teardown,
        // silently swallowing a signal there instead of leaving. This destructor runs
        // FIRST on every exit path including that one, so putting the reinstall here
        // covers both — redundant-but-harmless on the normal path (the explicit call
        // already ran), and the only reinstall on the unwind path.
        struct ServerUnpublisher {
            ~ServerUnpublisher() {
                std::signal(SIGINT, on_signal_hard_exit);
                std::signal(SIGTERM, on_signal_hard_exit);
#ifdef _WIN32
                std::lock_guard<std::mutex> lock(g_server_mu);
#endif
                g_server.store(nullptr, std::memory_order_release);
            }
        } server_unpublisher;

#ifndef _WIN32
        // ONLY install the graceful handlers if the watcher is live. If it is not (pipe
        // or thread creation failed), on_signal would catch the signal, find no pipe,
        // and RETURN — swallowing it, with no default disposition left. The fallback is
        // the hard-exit handler installed above (never SIG_DFL — pid 1 discards it).
        if (shutdown_watcher && shutdown_watcher->ok()) {
            std::signal(SIGINT, on_signal);
            std::signal(SIGTERM, on_signal);
            // RE-CHECK after the install (TOCTOU): a watcher dying between the ok()
            // test above and these installs runs its died-callback FIRST — which
            // installs the hard-exit handler — and the two std::signal calls above
            // would then OVERWRITE it with on_signal, which finds wfd < 0 and returns:
            // signal swallowed, server unkillable. See agents/core/src/main.cpp
            // Gate-8 SHOULD-1.
            if (!shutdown_watcher->ok()) {
                std::signal(SIGINT, on_signal_hard_exit);
                std::signal(SIGTERM, on_signal_hard_exit);
            }
        } else {
            spdlog::warn("shutdown watcher unavailable — SIGINT/SIGTERM will now exit "
                         "the process IMMEDIATELY and UNGRACEFULLY (no store flush, no "
                         "clean DB close). A default disposition would be IGNORED by "
                         "PID 1 in a container, so this is the killable posture.");
        }
#else
        std::signal(SIGINT, on_signal);
        std::signal(SIGTERM, on_signal);
#endif

        server->run();

        // THE HANDLERS MUST NOT OUTLIVE WHAT SERVES THEM. From here the watcher is
        // about to be joined and g_shutdown_wfd cleared — on_signal would find wfd == -1
        // and simply return, swallowing the signal, for the whole span of
        // ~ServerImpl's teardown, which is not brief: #3261's quiesce waits alone total
        // up to 120s. Leave a handler that guarantees the process LEAVES instead of
        // hanging to the supervisor's kill timeout. See agents/core/src/main.cpp
        // Gate-8 round 7 UP-2.
        std::signal(SIGINT, on_signal_hard_exit);
        std::signal(SIGTERM, on_signal_hard_exit);

        if (server->startup_failed()) {
#ifdef _WIN32
            WSACleanup();
#endif
            return EXIT_FAILURE;
        }
    } catch (const std::exception& ex) {
        spdlog::error("Fatal exception: {}", ex.what());
#ifdef _WIN32
        WSACleanup();
#endif
        return EXIT_FAILURE;
    } catch (...) {
        spdlog::error("Fatal unknown exception");
#ifdef _WIN32
        WSACleanup();
#endif
        return EXIT_FAILURE;
    }

#ifdef _WIN32
    WSACleanup();
#endif
    return EXIT_SUCCESS;
}
