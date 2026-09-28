#ifdef _WIN32
#include <io.h>
#pragma section(".CRT$XCB", read)
[[maybe_unused]] static void __cdecl diag_dll_static_init() {
    const char msg[] = "[DIAG] DLL static-init starting (before proto registration)\n";
    _write(2, msg, sizeof(msg) - 1);
}
__declspec(allocate(".CRT$XCB"))
    [[maybe_unused]] static void(__cdecl* p_dll_diag)() = diag_dll_static_init;
#endif

#include <yuzu/agent/detached_signature.hpp>
#include <yuzu/agent/agent.hpp>
#include <yuzu/agent/agent_csr.hpp>
#include <yuzu/agent/cert_discovery.hpp>
#include <yuzu/agent/cert_store.hpp>
#include <yuzu/agent/cloud_identity.hpp>
#include <yuzu/agent/command_dedup_store.hpp>
#include <yuzu/agent/dex_observer.hpp>
#include <yuzu/agent/guardian_engine.hpp>
#include <yuzu/agent/kv_store.hpp>
#include <yuzu/agent/plugin_loader.hpp>
#include <yuzu/agent/server_address_resolver.hpp>
#include <yuzu/agent/subprocess_runner.hpp>
#include <yuzu/agent/trigger_engine.hpp>
#include <yuzu/agent/updater.hpp>
#include <yuzu/metrics.hpp>
#include <yuzu/secure_zero.hpp>
#include <yuzu/version.hpp>

#include <grpcpp/grpcpp.h>
#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

// Generated protobuf/gRPC headers (flat output from YuzuProto.cmake)
#include "agent.grpc.pb.h"
#include "guaranteed_state.pb.h"

// Local-only helper, exposed for unit testing.
#include "plugin_config_sync.hpp"
#include "local_dispatcher.hpp"
#include "shutdown_deadline_guard.hpp" // #2233 item 3: end-to-end stop() deadline
#include "sync_now_decision.hpp"               // __sync__.now decision core (pure, unit-tested)
#include "sync_scheduler.hpp"                 // ADR-0016 daily-sync framework
#include "sync_source_installed_software.hpp" // ADR-0016 source #1
#include "sync_source_app_perf.hpp"           // DEX app-perf-over-time B1 source
#include "sync_source_device_ci.hpp"          // ADR-0016 device-CI inventory source
#include "sync_source_software_licensing.hpp" // SLE (ADR-0024) software_licensing source
#include "sync_source_app_usage.hpp"          // Wave 7 PR7.2 app_usage (last_used) source
#include "dex_event.hpp" // SignalObservation -> GuaranteedStateEvent mapping (proto-aware)
#include "dex_linux_proc.hpp" // A4 Linux heartbeat perf reads (parse_proc_stat / parse_commit_pct)
#include "dex_perf_breach.hpp" // A4: heartbeat device-utilization tags (perf counter reads)
#include "net_quality_sampler.hpp" // slice 4a: heartbeat network-quality facts
#include "guardian_spark_send.hpp" // rung 7.7a: OutboxEntry -> GuaranteedStateEvent send mapping
#include "guardian_spark_timing.hpp" // #4606 criterion-10 T_wire: SendTimingRecord/format_send_timing_line
#include "spark_engine.hpp"    // ADR-0021 Stage-2 rung 1: instantiate observe-only
#include "guardian_arm_heartbeat.hpp"     // emit_guardian_arm_heartbeat_tags (rung 9c PR-3)
#include "guardian_backend.hpp"           // GuardianBackend, guardian_backend_from_state/label (F7)
#include "guardian_health_heartbeat.hpp"  // emit_guardian_health_heartbeat_tags (M1)
#include "guardian_io_ceiling_heartbeat.hpp" // emit_guardian_io_ceiling_heartbeat_tags (rung 9c PR-3)
#include "guardian_journal_heartbeat.hpp" // emit_guardian_journal_heartbeat_tags (item 7 PR-Ag)
#include "guardian_legacy_sink_executor.hpp" // #4783: LegacySendOutcome (EventSink's return type)
#include "guardian_unsupported_heartbeat.hpp" // emit_guardian_unsupported_heartbeat_tags (F7)
#include "spark_heartbeat.hpp" // emit_spark_heartbeat_tags — spark fleet telemetry
#include "spark_mechanism.hpp" // make_{file,registry,service}_mechanism factories
#include "thread_pool.hpp" // bounded dispatch pool + per-task exception firewall (#2037)

#ifdef _WIN32
#include <winsock2.h> // gethostname (must precede windows.h)
#include <windows.h>  // GetModuleHandleW, GetProcAddress
#include <winternl.h> // RTL_OSVERSIONINFOW (for RtlGetVersion)
#else
#include <sys/utsname.h> // uname (OS version)
#include <unistd.h>      // gethostname
#endif

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <filesystem>
#include <format>
#include <fstream>
#include <iterator>
#include <optional>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <queue>
#include <random>
#include <string>
#include <thread>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace yuzu::agent {

namespace {

namespace pb = ::yuzu::agent::v1;
namespace gpb = ::yuzu::guardian::v1;
constexpr const char* kSessionMetadataKey = "x-yuzu-session-id";

// #2233 item 3 ("S+"): ShutdownDeadlineGuard's grace period for both AgentImpl::stop()
// and run()'s teardown ScopeExit. NOT a measured value — named sub-budgets inside the
// blocking chain sum to roughly 15-20s (GuardianEngine's two persist_lifecycle_journal_
// locked calls, each documented as "worst case one KvStore 5s busy timeout"; SparkEngine's
// kConsumerJoinBudgetMs = 2'000) but dex_observer_'s drain wait and stop_all_guards_
// locked()'s per-guard stops have NO named bound at all — so this sits AT that named floor,
// not comfortably above it (corrected per external review, PR #3737 — the earlier wording
// overstated the margin), without claiming to be a derived guarantee (matching
// spark_file.cpp's arm_ancestor deadline comment: state plainly that it's not a wall-clock
// bound where it isn't one). Also constrained from above: service_win.cpp reports a 30s
// STOP_PENDING hint to the Windows SCM, so a SINGLE watchdog must stay under that — 20s
// leaves only a 10s margin, not a comfortable one (matching service_win.cpp's own wording
// on the same relationship, not "well under").
//
// TWO watchdogs on the external-trigger path, and their budgets are independent, not
// shared: run()'s ScopeExit re-calls guardian_->stop() on EVERY exit (comment below),
// unconditionally, even when AgentImpl::stop() already called it — and GuardianEngine::
// stop() has no early-out (verified above), so a second call blocks on its own mtx_ then
// RE-EXECUTES. In the worst case this composes SEQUENTIALLY in wall-clock time: stop()'s
// own watchdog (W1) bounds its guardian_->stop() call to <20s without firing, then run()'s
// thread notices stop_requested_ and the ScopeExit's watchdog (W2) separately bounds ITS
// OWN guardian_->stop() re-run to <20s without firing — up to ~40s total elapsed before
// either individually reaches its own floor, exceeding the 30s SCM hint with NEITHER
// watchdog firing (external review, PR #3737, verified against this exact call graph).
// Accepted, not fixed here: in this specific composed-but-neither-fires case the process
// is NOT stuck — both phases genuinely complete, just slowly, and the agent reaches a
// normal SERVICE_STOPPED/NO_ERROR report. Per SERVICE_FAILURE_ACTIONS_FLAG's documented
// semantics (verified directly, not re-derived from this file), --install-service's
// recovery actions (below) fire ONLY on a process that terminates without reporting
// SERVICE_STOPPED, or reports it with a non-zero exit code — a slow-but-clean stop
// satisfies neither, so NO restart fires here (an earlier revision of this comment
// wrongly claimed one always does — corrected against Microsoft's own documented flag
// semantics). The actual consequence is milder than a restart: the service simply
// reports STOPPED later than the SCM's hint anticipated, no automatic action either way.
// If either watchdog instead genuinely FIRES (hard_exit(4)), the separate auto-restart
// claim below is unaffected — a TerminateProcess exit never reports SERVICE_STOPPED,
// which IS the recovery-actions trigger condition.
//
// This two-watchdog analysis does NOT cover every hang: the reconnect loop's own inline
// final-teardown block (trigger_engine_.stop() + the per-plugin shutdown() loop, see that
// code) runs on run()'s own thread BETWEEN stop_requested_ being noticed and the ScopeExit
// even arming its watchdog (W2) — if a plugin's shutdown() hangs there, run() never
// returns, W2 never arms, and NEITHER watchdog catches it (external review, PR #3737).
// Pre-existing, not introduced by this PR; tracked as #3756 item 5 (item 3 on that same
// issue is the separate composition-aware-budget design work above), not fixed here.
//
// Also unwatched by this analysis: the OTA self-stop path can race stop_mu_ against an
// external trigger — a caller that blocks on the mutex is still bounded by ITS OWN
// already-armed watchdog, so purely losing that race can independently hard_exit() the
// whole process even while the winning call was healthy (external review, PR #3737).
// Same outcome bucket as the composition case (an extra restart, not a hang) but a
// different trigger worth naming.
//
// Making the two watchdogs composition-aware (deriving W2's budget from
// elapsed-time-since-stop()-began) is deliberately deferred — it needs a design and its
// own review, not a quick patch to an externally-reviewed primitive — grouped with the
// other open #2233 watchdog-tuning items as #3756.
// That margin matters on Windows regardless: --install-service's own
// SERVICE_CONFIG_FAILURE_ACTIONS (main.cpp, #1822 — SC_ACTION_RESTART x3, and
// SERVICE_CONFIG_FAILURE_ACTIONS_FLAG=TRUE so it also fires on a clean exit with no
// SERVICE_STOPPED report, not just a crash) DOES auto-restart on a watchdog fire — an
// earlier revision of this comment claimed the opposite (governance Gate 6 sre finding,
// corrected at Gate 8 re-verify after direct code read) — but that restart only happens if
// TerminateProcess actually lands inside this margin before the SCM gives up waiting on
// STOP_PENDING; see "Stopping a wedged agent" in docs/user-manual/server-admin.md.
constexpr std::chrono::milliseconds kShutdownDeadlineGrace{20'000};

// #2303 sec-L. The daily-sync scheduler (ADR-0016) persists last-hash / need_full state in this
// kv_store namespace, keyed the same way plugin storage is (by the plugin's own declared name).
// It MUST be a reserved plugin name, or a native plugin could claim it and forge/clear the sync
// state to force or suppress a daily push. The static_assert binds this constant to
// kReservedPluginNames so the two cannot drift; both kv_store call sites use it.
constexpr std::string_view kSyncKvNamespace = "__sync__";
static_assert(is_reserved_plugin_name(kSyncKvNamespace),
              "kSyncKvNamespace must be a reserved plugin name (plugin_loader.hpp)");

#if defined(_WIN32)
constexpr const char* kAgentOs = "windows";
constexpr const char* kAgentArch = "x86_64";
#elif defined(__APPLE__)
#if defined(__aarch64__)
constexpr const char* kAgentOs = "darwin";
constexpr const char* kAgentArch = "aarch64";
#else
constexpr const char* kAgentOs = "darwin";
constexpr const char* kAgentArch = "x86_64";
#endif
#elif defined(__aarch64__)
constexpr const char* kAgentOs = "linux";
constexpr const char* kAgentArch = "aarch64";
#else
constexpr const char* kAgentOs = "linux";
constexpr const char* kAgentArch = "x86_64";
#endif

// Returns the running OS version string (e.g. "10.0.26200" on Windows,
// "5.15.0-89-generic" on Linux, "23.4.0" on macOS). Empty string on
// failure. Used at registration time so the server's AgentInfo.platform
// can identify which build of which OS the agent is running on.
//
// On Windows we use RtlGetVersion via NTDLL rather than the deprecated
// GetVersionEx (which is subject to manifest-based version spoofing
// since Windows 8.1) — RtlGetVersion always reports the true OS version.
// On Unix we use the standard uname syscall.
[[nodiscard]] std::string get_os_version() {
#ifdef _WIN32
    HMODULE ntdll = ::GetModuleHandleW(L"ntdll.dll");
    if (!ntdll)
        return {};
    using RtlGetVersionFn = LONG(WINAPI*)(PRTL_OSVERSIONINFOW);
    auto fn = reinterpret_cast<RtlGetVersionFn>(::GetProcAddress(ntdll, "RtlGetVersion"));
    if (!fn)
        return {};
    RTL_OSVERSIONINFOW v{};
    v.dwOSVersionInfoSize = sizeof(v);
    if (fn(&v) != 0)
        return {};
    return std::format("{}.{}.{}", v.dwMajorVersion, v.dwMinorVersion, v.dwBuildNumber);
#else
    struct utsname u {};
    if (::uname(&u) != 0)
        return {};
    return std::string{u.release};
#endif
}

std::string read_file_contents(const std::filesystem::path& p) {
    std::ifstream f(p, std::ios::binary);
    if (!f)
        return {};
    return std::string(std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>());
}

// Stream type alias: agent writes CommandResponse, reads CommandRequest.
// (Subscribe RPC: stream CommandResponse -> stream CommandRequest)
using SubscribeStream = grpc::ClientReaderWriter<pb::CommandResponse, pb::CommandRequest>;

// ThreadPool (bounded dispatch pool + per-task exception firewall, #2037) now
// lives in thread_pool.hpp so the firewall behaviour is unit-testable in
// isolation. Used unqualified below via namespace yuzu::agent.


// Context implementations
// These are passed to plugins; they bridge the C ABI callbacks to gRPC streams.

struct PluginContextImpl {
    std::unordered_map<std::string, std::string> config;
    KvStore* kv_store{nullptr};             // non-owning; lifetime managed by AgentImpl
    TriggerEngine* trigger_engine{nullptr}; // non-owning; lifetime managed by AgentImpl
    std::string plugin_name;                // set per-plugin during init/execute for KV namespacing
};

// Per-command output is buffered and flushed in a single gRPC Write instead of
// issuing one Write per line. This reduces serialized gRPC writes from N-per-
// command to 1-per-command for most plugins.
static constexpr size_t kOutputFlushThreshold = 64 * 1024; // 64 KB auto-flush

struct CommandContextImpl {
    std::shared_ptr<SubscribeStream> stream;
    std::mutex* write_mu; // protects concurrent stream->Write()
    std::string command_id;
    std::chrono::steady_clock::time_point start_time;
    std::atomic<bool> first_output_sent{false};

    // Buffered output — flushed once after execute(), or when buffer exceeds threshold
    std::vector<std::string> output_buffer;
    size_t output_buffer_bytes{0};
    std::mutex buf_mu;

    // PR 10 / UAT 2026-05-12 — Push-based snapshot ingestion.
    //
    // When `capture` is non-null, plugin output is accumulated into
    // this string (newline-joined between calls) instead of being
    // streamed back to the server. The snapshot-pump thread uses this
    // path to invoke `tar.fleet_snapshot` locally and harvest the JSON
    // payload without touching the gRPC channel. `stream` and
    // `write_mu` are nullptr/unused in that mode; `flush_output_locked`
    // short-circuits.
    std::string* capture{nullptr};

    // PR 10 hardening — capture-mode upper bound (UP-9). The pump
    // ships the captured string in the next HeartbeatRequest; gRPC's
    // default 4 MiB inbound cap is the hard server-side ceiling, but
    // we want a tighter agent-side cap so an oversized snapshot is
    // *truncated with a marker* rather than retained-and-failing. The
    // 2 MiB value matches `FleetTopologyStore::kPushedSnapshotMaxBytes`
    // on the server (in-tree convention: same constant in two places
    // until typed proto lands and renders both moot). This is the
    // DEFAULT; a caller that needs a larger bounded payload (the
    // installed_software sync's v2 rows, blob contract v2) overrides it
    // per-dispatch via `capture_max_bytes` below — see dispatch_with_capture.
    static constexpr std::size_t kCaptureMaxBytes = 2ull * 1024 * 1024;
    std::size_t capture_max_bytes{kCaptureMaxBytes};
    bool capture_truncated{false};

    // CC-07 plugin→host typed result seam (ABI4, sdk/include/yuzu/plugin.h).
    // Written at most by the single plugin thread executing this command's
    // execute() call (yuzu_ctx_set_result_status, below) — same single-writer
    // assumption as the rest of this struct's non-output-buffer fields.
    // UNDECLARED (the default) means the plugin never called it — either an
    // ABI<4 plugin, or an ABI4 plugin that didn't report a typed status for
    // this call; execute_command_task then derives a coarse status from the
    // int return code alone.
    YuzuResultStatus result_status{YUZU_RESULT_STATUS_UNDECLARED};
    YuzuResultCompleteness result_completeness{YUZU_RESULT_COMPLETENESS_UNKNOWN};
    std::string result_provenance;

    void append_output(const char* text) {
        std::lock_guard lock(buf_mu);
        size_t len = std::strlen(text);
        if (capture) {
            // Capture mode: append directly to the operator-owned buffer
            // with a newline separator between successive writes, matching
            // the wire format the plugin would have emitted if streamed.
            if (capture_truncated)
                return;
            std::size_t prospective = capture->size() + (capture->empty() ? 0 : 1) + len;
            if (prospective > capture_max_bytes) {
                // Truncate with a sentinel suffix so the server-side
                // parser cleanly rejects the payload as malformed JSON
                // rather than ingesting a half-finished structure. The
                // pump emits a WARN; next pump cycle overwrites.
                capture->append("\n/* TRUNCATED — exceeded kCaptureMaxBytes */");
                capture_truncated = true;
                return;
            }
            if (!capture->empty())
                capture->push_back('\n');
            capture->append(text, len);
            return;
        }
        output_buffer.emplace_back(text, len);
        output_buffer_bytes += len;
        if (output_buffer_bytes >= kOutputFlushThreshold) {
            flush_output_locked();
        }
    }

    void flush_output() {
        std::lock_guard lock(buf_mu);
        flush_output_locked();
    }

private:
    void flush_output_locked() {
        // Capture mode keeps everything in `capture` already; nothing to
        // flush over the wire. Skipping this guard would call into
        // `stream->Write` on a null stream and crash the pump thread.
        if (capture)
            return;
        if (output_buffer.empty())
            return;

        // Concatenate all buffered lines into a single payload
        std::string combined;
        combined.reserve(output_buffer_bytes + output_buffer.size()); // +size for newlines
        for (size_t i = 0; i < output_buffer.size(); ++i) {
            if (i > 0)
                combined += '\n';
            combined += output_buffer[i];
        }
        output_buffer.clear();
        output_buffer_bytes = 0;

        pb::CommandResponse resp;
        resp.set_command_id(command_id);
        resp.set_status(pb::CommandResponse::RUNNING);
        resp.set_output(std::move(combined));

        std::lock_guard lock(*write_mu);
        stream->Write(resp, grpc::WriteOptions());
    }
};

// COPY/MOVE (governance Gate 8, considered and left alone): this is an
// AGGREGATE, so it has the implicit copy/move constructors, and a copy
// would run `fn()` TWICE. Deliberately NOT `= delete`d — a user-declared
// (even deleted) special member function disqualifies a class from being
// an aggregate, and every construction here goes through the deduction
// guide's aggregate-init form (`ScopeExit cleanup{lambda}`).
//
// An earlier revision of this comment claimed no converting constructor
// could take the aggregate's place, and that this had been "confirmed
// locally". A reviewer disproved it by compiling the counter-example:
// `explicit ScopeExit(F f) : fn(std::move(f)) {}` alongside deleted
// copy/move preserves the exact `ScopeExit name{lambda}` form at every
// call site. So the honest reason to stay aggregate is not impossibility
// — it is that there is no hazard to prevent: every use in this file is a
// single local RAII variable, never copied or moved out of its declaring
// scope, so the double-fire the deletion would guard against cannot
// occur. Same reasoning, and the same corrected justification, apply to
// the byte-identical siblings in `server/core/src/api_token_store.cpp`
// and `agents/core/src/spark_engine.cpp` (#2050) — keep all three
// aggregate, not just this one.
template <typename F> struct ScopeExit {
    F fn;
    ~ScopeExit() { fn(); }
};
template <typename F> ScopeExit(F) -> ScopeExit<F>;

// CC-07: map the plugin-reported (or int-return-code-derived) ABI4 status to
// the wire enum. Kept as the one place that does this mapping so the two
// enums cannot drift silently. The switch below is belt-and-suspenders —
// these static_asserts are the actual drift guard: the two enums are pinned
// numerically identical, so any future edit to either one that breaks the
// pairing fails the BUILD rather than relying on a runtime test staying
// in sync.
static_assert(static_cast<int>(pb::CommandResponse::PLUGIN_RESULT_UNDECLARED) ==
              static_cast<int>(YUZU_RESULT_STATUS_UNDECLARED));
static_assert(static_cast<int>(pb::CommandResponse::PLUGIN_RESULT_OK) ==
              static_cast<int>(YUZU_RESULT_STATUS_OK));
static_assert(static_cast<int>(pb::CommandResponse::PLUGIN_RESULT_UNAVAILABLE) ==
              static_cast<int>(YUZU_RESULT_STATUS_UNAVAILABLE));
static_assert(static_cast<int>(pb::CommandResponse::PLUGIN_RESULT_PERMISSION_DENIED) ==
              static_cast<int>(YUZU_RESULT_STATUS_PERMISSION_DENIED));
static_assert(static_cast<int>(pb::CommandResponse::PLUGIN_RESULT_CONSTRAINED) ==
              static_cast<int>(YUZU_RESULT_STATUS_CONSTRAINED));

pb::CommandResponse::PluginResultStatus to_proto_result_status(YuzuResultStatus status) {
    switch (status) {
    case YUZU_RESULT_STATUS_OK:
        return pb::CommandResponse::PLUGIN_RESULT_OK;
    case YUZU_RESULT_STATUS_UNAVAILABLE:
        return pb::CommandResponse::PLUGIN_RESULT_UNAVAILABLE;
    case YUZU_RESULT_STATUS_PERMISSION_DENIED:
        return pb::CommandResponse::PLUGIN_RESULT_PERMISSION_DENIED;
    case YUZU_RESULT_STATUS_CONSTRAINED:
        return pb::CommandResponse::PLUGIN_RESULT_CONSTRAINED;
    case YUZU_RESULT_STATUS_UNDECLARED:
        break;
    }
    return pb::CommandResponse::PLUGIN_RESULT_UNDECLARED;
}

} // anonymous namespace

// CC-07: derive the "effective" typed status for a finished command — the
// plugin's reported status if it called yuzu_ctx_set_result_status(), else a
// coarse one from the int return code alone (the same fallback an ABI<4
// plugin gets by construction, since no such call exists for it). Pulled out
// of execute_command_task as its own externally-linked, header-free function
// (same forward-declare-at-the-call-site pattern dispatch_with_capture below
// uses for local_dispatcher.cpp) so
// tests/unit/test_capability_descriptor.cpp can pin the declared-vs-observable
// honesty contract directly, without needing a live gRPC stream.
// YUZU_EXPORT (default visibility): agents/core builds -fvisibility=hidden, and
// unlike dispatch_with_capture (called only within this dylib) this helper is
// linked from the separate yuzu_agent_tests binary, so it must be exported. The
// mangled C++ name is not part of the extern "C" plugin ABI.
YUZU_EXPORT YuzuResultStatus derive_effective_result_status(YuzuResultStatus reported, int rc) {
    if (reported != YUZU_RESULT_STATUS_UNDECLARED)
        return reported;
    return (rc == 0) ? YUZU_RESULT_STATUS_OK : YUZU_RESULT_STATUS_UNAVAILABLE;
}

// #1001 / arch-S3 — shim used by LocalDispatcher to invoke a plugin
// descriptor in-process with output captured into a caller-owned buffer.
// Kept here (rather than in local_dispatcher.cpp) because CommandContextImpl
// carries gRPC-typed streaming fields that would force local_dispatcher.cpp
// to pull in grpcpp; this shim is the narrow boundary that contains that
// coupling.
int dispatch_with_capture(const YuzuPluginDescriptor* descriptor, const char* action,
                          const YuzuParam* params, std::size_t param_count,
                          std::string* capture_out, bool* truncated_out, std::size_t capture_cap,
                          YuzuResultStatus* result_status_out,
                          YuzuResultCompleteness* result_completeness_out,
                          std::string* result_provenance_out) {
    CommandContextImpl ctx_impl{};
    ctx_impl.command_id = "__local_dispatch__";
    ctx_impl.start_time = std::chrono::steady_clock::now();
    ctx_impl.capture = capture_out;
    // Per-dispatch cap: append_output enforces ctx_impl.capture_max_bytes, not
    // the class-static kCaptureMaxBytes default. The two DEFAULTS are pinned
    // equal by the static_assert below so a caller relying on the default
    // (every caller except the installed_software sync source) is unaffected;
    // a caller that passes a non-default capture_cap (LocalDispatcher::run's
    // parameter) actually gets that bound enforced here.
    static_assert(CommandContextImpl::kCaptureMaxBytes ==
                  yuzu::agent::LocalDispatcher::kCaptureMaxBytes);
    ctx_impl.capture_max_bytes = capture_cap;

    auto* raw_ctx = reinterpret_cast<YuzuCommandContext*>(&ctx_impl);
    int rc = descriptor->execute(raw_ctx, action, params, param_count);
    ctx_impl.flush_output(); // no-op in capture mode
    if (truncated_out)
        *truncated_out = ctx_impl.capture_truncated;
    // BR-001: read back whatever the plugin reported via
    // yuzu_ctx_set_result_status() on THIS SAME ctx_impl -- lets a caller
    // (LocalDispatcher::run) prove a migrated plugin's forward_runner_failure
    // call actually reached the ABI4 CC-07 result-status seam, not just that
    // the call site exists in source.
    if (result_status_out)
        *result_status_out = ctx_impl.result_status;
    if (result_completeness_out)
        *result_completeness_out = ctx_impl.result_completeness;
    if (result_provenance_out)
        *result_provenance_out = ctx_impl.result_provenance;
    return rc;
}

// StandalonePluginContext (local_dispatcher.hpp): the one way a non-daemon
// host obtains a real PluginContextImpl for descriptor->init/shutdown. Kept
// here for the same reason as dispatch_with_capture — PluginContextImpl is
// this TU's private type.
StandalonePluginContext::StandalonePluginContext(std::string plugin_name,
                                                 std::unordered_map<std::string, std::string> config)
    : impl_(new PluginContextImpl{std::move(config), nullptr, nullptr, std::move(plugin_name)},
            [](void* p) { delete static_cast<PluginContextImpl*>(p); }) {}

YuzuPluginContext* StandalonePluginContext::get() const noexcept {
    return reinterpret_cast<YuzuPluginContext*>(impl_.get());
}

// cpp-expert A4 test seam (no public header — same convention as
// derive_effective_result_status/dispatch_with_capture above): drives a
// status value through the REAL yuzu_ctx_set_result_status() entry point
// against a throwaway CommandContextImpl, then returns whatever ended up
// stored in impl->result_status. tests/unit/test_capability_descriptor.cpp
// forward-declares this to observe the RAW stored value the clamp above
// writes — to_proto_result_status's switch already falls through any
// unmatched value to PLUGIN_RESULT_UNDECLARED, so a proto-level assertion
// cannot tell a clamped UNDECLARED(0) apart from an unclamped out-of-range
// raw status; this seam can.
YUZU_EXPORT YuzuResultStatus set_result_status_and_read_back(YuzuResultStatus status) {
    CommandContextImpl ctx_impl{};
    auto* raw_ctx = reinterpret_cast<YuzuCommandContext*>(&ctx_impl);
    yuzu_ctx_set_result_status(raw_ctx, status, YUZU_RESULT_COMPLETENESS_UNKNOWN, nullptr);
    return ctx_impl.result_status;
}

// C ABI context function implementations

extern "C" {

YUZU_EXPORT void yuzu_ctx_write_output(YuzuCommandContext* ctx, const char* text) {
    if (!ctx || !text)
        return;
    auto* impl = reinterpret_cast<CommandContextImpl*>(ctx);
    impl->append_output(text);
}

YUZU_EXPORT void yuzu_ctx_report_progress(YuzuCommandContext* ctx, int percent) {
    (void)ctx;
    spdlog::debug("Plugin progress: {}%", percent);
}

YUZU_EXPORT void yuzu_ctx_set_result_status(YuzuCommandContext* ctx, YuzuResultStatus status,
                                            YuzuResultCompleteness completeness,
                                            const char* provenance) {
    if (!ctx)
        return;
    auto* impl = reinterpret_cast<CommandContextImpl*>(ctx);
    // cpp-expert A4: `status` crosses the C ABI from a third-party plugin as
    // a bare int — nothing upstream guarantees it is one of the five
    // declared YuzuResultStatus enumerators. to_proto_result_status()
    // (above) already maps any unmatched value to PLUGIN_RESULT_UNDECLARED
    // on the WIRE, but that alone leaves the RAW out-of-range value sitting
    // in result_status forever (logged, compared, read by any future
    // consumer of the stored field). Clamp at the source instead. Compare
    // in `int` explicitly: YuzuResultStatus is an unscoped C enum whose
    // underlying type is implementation-defined and may be unsigned (every
    // declared enumerator is non-negative), which would make a direct
    // `status < YUZU_RESULT_STATUS_UNDECLARED` silently unreachable on some
    // compilers/ABIs.
    const int raw_status = static_cast<int>(status);
    if (raw_status < static_cast<int>(YUZU_RESULT_STATUS_UNDECLARED) ||
        raw_status > static_cast<int>(YUZU_RESULT_STATUS_CONSTRAINED)) {
        status = YUZU_RESULT_STATUS_UNDECLARED;
    }
    impl->result_status = status;
    impl->result_completeness = completeness;
    impl->result_provenance = provenance ? provenance : "";
}

YUZU_EXPORT const char* yuzu_ctx_get_config(YuzuPluginContext* ctx, const char* key) {
    if (!ctx || !key)
        return nullptr;
    auto* impl = reinterpret_cast<PluginContextImpl*>(ctx);
    auto it = impl->config.find(key);
    if (it == impl->config.end())
        return nullptr;
    return it->second.c_str();
}

YUZU_EXPORT const char* yuzu_ctx_get_secret(YuzuPluginContext* ctx, const char* key) {
    (void)ctx;
    (void)key;
    return nullptr;
}

// ── KV Storage C ABI (ABI v2) ────────────────────────────────────────────────

YUZU_EXPORT int yuzu_ctx_storage_set(YuzuPluginContext* ctx, const char* key, const char* value) {
    if (!ctx || !key || !value)
        return -1;
    auto* impl = reinterpret_cast<PluginContextImpl*>(ctx);
    if (!impl->kv_store || impl->plugin_name.empty())
        return -2;
    return impl->kv_store->set(impl->plugin_name, key, value) ? 0 : 1;
}

YUZU_EXPORT const char* yuzu_ctx_storage_get(YuzuPluginContext* ctx, const char* key) {
    if (!ctx || !key)
        return nullptr;
    auto* impl = reinterpret_cast<PluginContextImpl*>(ctx);
    if (!impl->kv_store || impl->plugin_name.empty())
        return nullptr;
    auto val = impl->kv_store->get(impl->plugin_name, key);
    if (!val.has_value())
        return nullptr;
    // Caller must free with yuzu_free_string()
    char* result = static_cast<char*>(std::malloc(val->size() + 1));
    if (!result)
        return nullptr;
    std::memcpy(result, val->c_str(), val->size() + 1);
    return result;
}

YUZU_EXPORT int yuzu_ctx_storage_delete(YuzuPluginContext* ctx, const char* key) {
    if (!ctx || !key)
        return -1;
    auto* impl = reinterpret_cast<PluginContextImpl*>(ctx);
    if (!impl->kv_store || impl->plugin_name.empty())
        return -2;
    return impl->kv_store->del(impl->plugin_name, key) ? 0 : 1;
}

YUZU_EXPORT int yuzu_ctx_storage_exists(YuzuPluginContext* ctx, const char* key) {
    if (!ctx || !key)
        return -1;
    auto* impl = reinterpret_cast<PluginContextImpl*>(ctx);
    if (!impl->kv_store || impl->plugin_name.empty())
        return -2;
    return impl->kv_store->exists(impl->plugin_name, key) ? 0 : 1;
}

YUZU_EXPORT const char* yuzu_ctx_storage_list(YuzuPluginContext* ctx, const char* prefix) {
    if (!ctx)
        return nullptr;
    auto* impl = reinterpret_cast<PluginContextImpl*>(ctx);
    if (!impl->kv_store || impl->plugin_name.empty())
        return nullptr;
    auto keys = impl->kv_store->list(impl->plugin_name, prefix ? prefix : "");

    // Build JSON array: ["key1","key2",...]
    std::string json = "[";
    for (size_t i = 0; i < keys.size(); ++i) {
        if (i > 0)
            json += ',';
        json += '"';
        // Escape any quotes in key names
        for (char c : keys[i]) {
            if (c == '"')
                json += "\\\"";
            else if (c == '\\')
                json += "\\\\";
            else
                json += c;
        }
        json += '"';
    }
    json += ']';

    char* result = static_cast<char*>(std::malloc(json.size() + 1));
    if (!result)
        return nullptr;
    std::memcpy(result, json.c_str(), json.size() + 1);
    return result;
}

YUZU_EXPORT int yuzu_register_trigger(YuzuPluginContext* ctx, const char* trigger_id,
                                      const char* trigger_type, const char* config_json) {
    if (!ctx || !trigger_id || !trigger_type || !config_json)
        return -1;
    auto* impl = reinterpret_cast<PluginContextImpl*>(ctx);
    if (!impl->trigger_engine) {
        // The agent did not wire a TriggerEngine into this context. Without
        // it the registration cannot take effect — fail loudly rather than
        // returning success and silently dropping the trigger (the old
        // stub's bug — it cost the whole interval-trigger feature).
        spdlog::error("yuzu_register_trigger('{}'): no TriggerEngine in plugin context",
                      trigger_id);
        return -2;
    }
    // No exception may cross this C ABI boundary -- doing so is UB. Catch
    // everything (parse_trigger_config is exception-safe, but
    // register_trigger does map/vector insertion that can throw bad_alloc).
    try {
        auto cfg = yuzu::agent::parse_trigger_config(trigger_id, trigger_type, config_json);
        if (!cfg) {
            // parse_trigger_config already logged the specific reason.
            return -3;
        }
        impl->trigger_engine->register_trigger(std::move(*cfg));
        return 0;
    } catch (const std::exception& e) {
        spdlog::error("yuzu_register_trigger('{}'): threw: {}", trigger_id, e.what());
        return -4;
    } catch (...) {
        spdlog::error("yuzu_register_trigger('{}'): threw non-std exception", trigger_id);
        return -4;
    }
}

YUZU_EXPORT int yuzu_unregister_trigger(YuzuPluginContext* ctx, const char* trigger_id) {
    if (!ctx || !trigger_id)
        return -1;
    auto* impl = reinterpret_cast<PluginContextImpl*>(ctx);
    if (!impl->trigger_engine)
        return -2;
    // No exception may cross this C ABI boundary.
    try {
        impl->trigger_engine->unregister_trigger(trigger_id);
        return 0;
    } catch (const std::exception& e) {
        spdlog::error("yuzu_unregister_trigger('{}'): threw: {}", trigger_id, e.what());
        return -4;
    } catch (...) {
        spdlog::error("yuzu_unregister_trigger('{}'): threw non-std exception", trigger_id);
        return -4;
    }
}

} // extern "C"

// AgentImpl

class AgentImpl final : public Agent {
public:
    explicit AgentImpl(Config cfg) : cfg_{std::move(cfg)} {
        metrics_.describe("yuzu_agent_uptime_seconds", "Agent uptime in seconds", "gauge");
        metrics_.describe("yuzu_agent_commands_executed_total", "Total commands executed by plugin",
                          "counter");
        metrics_.describe("yuzu_agent_plugins_loaded", "Number of loaded plugins", "gauge");
        metrics_.describe("yuzu_agent_plugin_rejected_total",
                          "Plugins rejected at load time, labeled by reason", "counter");
        metrics_.describe("yuzu_agent_dex_observer_armed",
                          "1 if the Guardian DEX signal observer is armed AND all its channel "
                          "subscriptions are live, else 0. Tracks runtime health: a runtime "
                          "EvtSubscribe error on any channel (EventLog restart / channel ACL "
                          "change) flips it to 0 via the observer error callback. NOT whether the "
                          "underlying reporters are enabled (a WER-disabled host stays armed=1 yet "
                          "emits no crash events). Surfaced fleet-wide via the heartbeat rollup "
                          "yuzu_fleet_agents_dex_observer_disarmed (the agent has no /metrics "
                          "endpoint).",
                          "gauge");
        // PKI PR3 (gov UP-9 / enterprise): make a stuck/failed per-agent mTLS
        // provisioning observable to fleet alerting, not just the agent log.
        metrics_.describe("yuzu_agent_cert_provision_failed_total",
                          "Per-agent mTLS provisioning failures, labeled by reason "
                          "(persist_failed|no_cert_issued)", "counter");
    }

    void run() override {
        spdlog::info("Yuzu agent starting (id={})", cfg_.agent_id);

        // 1. Load plugins (with optional allowlist + code-signing verification)
        auto allowlist = load_plugin_allowlist(cfg_.plugin_allowlist);
        PluginSigningPolicy signing{cfg_.plugin_trust_bundle, cfg_.plugin_require_signature};
        // Fail-closed guard against silent fail-open. If the operator passed
        // --plugin-require-signature but forgot --plugin-trust-bundle (or
        // passed an empty path), PluginSigningPolicy::enabled() would be
        // false and the entire signing block in PluginLoader::scan() would
        // be skipped — so unsigned plugins would silently load while the
        // operator believed enforcement was active. Refuse to start.
        // Governance hardening round 1 (UP-7).
        if (cfg_.plugin_require_signature && !signing.enabled()) {
            spdlog::critical("--plugin-require-signature is set but --plugin-trust-bundle "
                             "is empty. Refusing to start: this combination would silently "
                             "fail-open (every plugin would load unverified).");
            std::exit(EXIT_FAILURE);
        }
        auto scan = PluginLoader::scan(cfg_.plugin_dir, allowlist, signing);

        // Collect successfully loaded handles first (before init)
        std::vector<PluginHandle> candidates;
        for (auto& handle : scan.loaded) {
            candidates.push_back(std::move(handle));
        }

        // Build the plugin context config map with agent state
        plugin_ctx_.config["agent.id"] = cfg_.agent_id;
        plugin_ctx_.config["agent.version"] = std::string{yuzu::kFullVersionString};
        plugin_ctx_.config["agent.build_number"] = std::to_string(yuzu::kBuildNumber);
        plugin_ctx_.config["agent.git_commit"] = std::string{yuzu::kGitCommitHash};
        plugin_ctx_.config["agent.server_address"] = cfg_.server_address;
        // Resolved ONCE, here, at startup -- see server_address_resolver.hpp
        // for why this must not be re-resolved later by a plugin at
        // quarantine-dispatch time (the quarantine plugin used to do this
        // itself; #3429 round 4 moved it here after round 3's review found
        // that let a possibly-already-compromised host's own DNS resolution
        // decide what survives its own containment).
        plugin_ctx_.config["agent.server_address_resolved"] =
            yuzu::agent::resolve_server_address_literals(cfg_.server_address);
        plugin_ctx_.config["agent.tls_enabled"] = cfg_.tls_enabled ? "true" : "false";
        plugin_ctx_.config["agent.heartbeat_interval"] =
            std::to_string(cfg_.heartbeat_interval.count());
        plugin_ctx_.config["agent.plugin_dir"] = cfg_.plugin_dir.string();
        plugin_ctx_.config["agent.data_dir"] = cfg_.data_dir.string();
        plugin_ctx_.config["agent.log_level"] = cfg_.log_level;
        plugin_ctx_.config["agent.debug_mode"] = cfg_.debug_mode ? "true" : "false";
        plugin_ctx_.config["agent.verbose_logging"] = cfg_.verbose_logging ? "true" : "false";
        plugin_ctx_.config["agent.reconnect_count"] = "0";

        // Wire the trigger engine into the master plugin context BEFORE the
        // per-plugin contexts are snapshotted from it (the load loop copies
        // plugin_ctx_.trigger_engine into each pctx). Plugins call
        // ctx.register_trigger() inside their own init(), which routes
        // through yuzu_register_trigger -> pctx->trigger_engine; if this
        // pointer is still null at init time, every registration is dropped.
        plugin_ctx_.trigger_engine = &trigger_engine_;

        // 1b. Open KV store for plugin persistent storage
        {
            auto kv_path = cfg_.data_dir / "kv_store.db";
            auto kv_result = KvStore::open(kv_path);
            if (kv_result.has_value()) {
                kv_store_ = std::make_unique<KvStore>(std::move(*kv_result));
                plugin_ctx_.kv_store = kv_store_.get();
                spdlog::info("KV store ready: {}", kv_path.string());
            } else {
                spdlog::error("Failed to open KV store: {}", kv_result.error().message);
                spdlog::warn("Plugin KV storage will be unavailable");
            }
        }

        // 1b'. Open the durable command-dedup store (HA WS-0, ADR-2002). Survives
        // restart and remembers each command's terminal outcome so a redelivered
        // duplicate replays the original result instead of a bare REJECTED. A
        // failure to open is NOT fatal — the agent runs with replay protection
        // degraded (a redelivered command may re-execute), which is logged loudly.
        {
            auto dedup_path = cfg_.data_dir / "command_dedup.db";
            auto dedup_result = CommandDedupStore::open(dedup_path);
            if (dedup_result.has_value()) {
                command_dedup_ =
                    std::make_unique<CommandDedupStore>(std::move(*dedup_result));
                spdlog::info("Command dedup store ready: {}", dedup_path.string());
            } else {
                spdlog::error("Failed to open command dedup store: {}",
                              dedup_result.error().message);
                spdlog::warn("Durable command replay protection unavailable — a redelivered "
                             "command may re-execute (fail-open, degraded)");
                metrics_.counter("yuzu_agent_dedup_open_failed_total").increment();
            }
        }

        // 1c. Initialise the Guardian engine (Phase 1 startup, pre-network).
        // The engine persists rules into the KV store and answers __guard__
        // dispatches once the Subscribe stream is open. Construction is
        // safe even when KV failed to open (it degrades to in-memory only).
        guardian_ = std::make_unique<GuardianEngine>(kv_store_.get(), cfg_.agent_id);
        // Spread this endpoint's journal maintenance and its forced (boot / reconnect) replay
        // pages over their intervals - the ONLY place jitter is turned on, so every test keeps
        // a deterministic cadence. Must precede wire_spark_engine(), which builds the worker.
        // What it protects against is a CORRELATED fleet event - a gateway bounce, a mass
        // restart, a restored snapshot - handing thousands of agents the same full journal
        // scan and token burst in the same second (C0 flip-checklist item 12).
        guardian_->set_maintenance_jitter(true);
        // start_local() (the pre-network cached-rule re-arm) is DEFERRED until after
        // the SparkEngine is constructed, started, and wired below (ADR-0021 rung
        // 7.7a): wire_spark_engine() must run before start_local() (the header
        // contract), and SparkEngine::start() must precede start_local() so a
        // mechanism's `inert` capability state is populated before reconcile reads it
        // (load-bearing at rung 7.7b; inert at 7.7a since prefer_spark is false).

        // 1c-bis. Fleet-wide DEX signal observer (Guardian DEX, multi-signal).
        // RULELESS observations — records every catalogued reliability signal
        // (crash, hang, service failure, bugcheck, boot duration, …; see
        // dex_signal_catalog.cpp), independent of any rule. Windows/macOS/Linux each
        // have a real observer; no-op only on a platform without one.
        // Armed pre-network; emit_guardian_event() self-guards on the Subscribe
        // stream being up, so signals before first connect are dropped (like
        // guard events pre-sink; durable buffering is A3).
        // --dex-disable / YUZU_AGENT_DEX_DISABLE is a deploy-time opt-out: when set,
        // the observer never arms and NO DEX signal telemetry is collected.
        dex_observer_ = make_dex_observer();
        // Runtime health flag — the single source of truth for the heartbeat arm tag.
        // A shared_ptr<atomic> (NOT `this`) so the observer's error callback, which fires
        // on an OS threadpool thread and may outlive this agent, can flip it to false
        // without a use-after-free. A runtime EvtSubscribeActionError on ANY channel
        // (EventLog restart / channel ACL change → that channel goes deaf after a
        // successful start) flips it, so the next heartbeat reports armed=0 and the
        // fleet `disarmed` gauge rises — the arm signal tracks runtime health, not just
        // the initial arm (UP-1).
        // Seeded OPTIMISTICALLY true: the error callback may fire DURING start() (once
        // EvtSubscribe arms, before start() returns), so we must NOT blind-store the
        // start() result afterwards — that would clobber a false the callback wrote in
        // that window. The disable / not-armed branches clear it explicitly instead.
        dex_health_ = std::make_shared<std::atomic<bool>>(true);
        if (cfg_.dex_disable) {
            dex_health_->store(false, std::memory_order_relaxed);
            spdlog::info(
                "dex_observer: disabled by --dex-disable — no DEX signal telemetry collected");
        } else if (dex_observer_->start([this](const SignalObservation& obs) {
                       const auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                                               std::chrono::system_clock::now().time_since_epoch())
                                               .count();
                       const auto seq = dex_seq_.fetch_add(1, std::memory_order_relaxed);
                       // Include agent_id: the at-least-once event_id is a GLOBAL primary key
                       // server-side, so two agents observing in the same ms (e.g. a bad
                       // fleet-wide deploy) would otherwise mint identical ids and all but one
                       // would be dropped at ingest — losing signals exactly when they matter.
                       const std::string event_id = std::string(kObservationRuleSentinel) + "-" +
                                                     cfg_.agent_id + "-" + std::to_string(now_ms) +
                                                     "-" + std::to_string(seq);
                       // dex_seq_ (incremented above) doubles as the per-agent observed-signal
                       // total surfaced in the heartbeat → fleet rollup; no separate counter.
                       emit_guardian_event(signal_observation_to_event(obs, event_id));
                   },
                   [h = dex_health_] { h->store(false, std::memory_order_relaxed); })) {
            // Armed — leave dex_health_ as-is: true, or false if the error callback
            // already fired during start(). Do NOT blind-store — see the seed comment.
        } else {
            dex_health_->store(false, std::memory_order_relaxed);
            spdlog::debug("dex_observer: not armed on this platform — DEX signals disabled");
        }
        // Arm gauge: seeded from dex_health_ (so a during-start error is reflected) and
        // re-synced from it at each heartbeat, so it tracks runtime subscription health,
        // not just the initial arm (UP-1).
        metrics_.gauge("yuzu_agent_dex_observer_armed")
            .set(dex_health_->load(std::memory_order_relaxed) ? 1.0 : 0.0);

        // Record start time for uptime calculation
        auto start_epoch = std::chrono::duration_cast<std::chrono::seconds>(
                               std::chrono::system_clock::now().time_since_epoch())
                               .count();
        plugin_ctx_.config["agent.start_time_epoch"] = std::to_string(start_epoch);

        // Module roster — every plugin file in plugin_dir is recorded here,
        // both successful loads and load failures (signature_invalid,
        // reserved_name, etc.). The post-load sync_master_config_to_plugins
        // call below makes these `agent.modules.N.*` entries readable by
        // every successfully-loaded plugin via get_config(). Operators rely
        // on this for diagnostics (status_plugin's `do_modules` action), but
        // it does mean every loaded plugin can read the names + reasons of
        // plugins that were rejected. This is acceptable today (single trust
        // domain on the agent host) but is worth revisiting if a future
        // change introduces sandboxed / lower-trust plugin contexts.
        size_t module_index = 0;
        auto record_module = [this, &module_index](std::string_view name, std::string_view version,
                                                   std::string_view description,
                                                   std::string_view status) {
            auto prefix = std::format("agent.modules.{}", module_index++);
            plugin_ctx_.config[prefix + ".name"] = std::string{name};
            plugin_ctx_.config[prefix + ".version"] = std::string{version};
            plugin_ctx_.config[prefix + ".description"] = std::string{description};
            plugin_ctx_.config[prefix + ".status"] = std::string{status};
        };

        for (const auto& err : scan.errors) {
            auto module_name = std::filesystem::path{err.path}.stem().string();
            record_module(module_name, "", err.reason, "load_failed");
            // #453 + #80: categorise rejections so operators can alert on
            // reserved-name attempts, signature failures, and generic
            // load failures separately. Order is most-specific first;
            // fall through to "load_failed" for everything else.
            std::string_view reason = "load_failed";
            if (err.reason.starts_with(yuzu::agent::kReservedNameReason)) {
                reason = "reserved_name";
            } else if (err.reason.starts_with(yuzu::agent::kInvalidNameReason)) {
                // #822: a plugin declared a malformed name (empty, over-length,
                // or outside [A-Za-z0-9_]) — distinct from a reserved-name
                // attempt so operators can alert on crafted-name loads.
                reason = "invalid_name";
            } else if (err.reason.starts_with(yuzu::agent::kSignatureMissingReason)) {
                reason = "signature_missing";
            } else if (err.reason.starts_with(yuzu::agent::kSignatureUntrustedReason)) {
                reason = "signature_untrusted_chain";
            } else if (err.reason.starts_with(yuzu::agent::kSignatureInvalidReason)) {
                reason = "signature_invalid";
            }
            metrics_.counter("yuzu_agent_plugin_rejected_total", {{"reason", std::string{reason}}})
                .increment();
        }

        for (auto& handle : candidates) {
            const auto* descriptor = handle.descriptor();
            // Create a per-plugin context with the correct plugin_name for KV namespacing.
            // Each plugin gets its own PluginContextImpl so concurrent executions
            // don't clobber each other's KV namespace (was a data corruption bug).
            auto pctx = std::make_unique<PluginContextImpl>();
            pctx->config = plugin_ctx_.config;
            pctx->kv_store = plugin_ctx_.kv_store;
            pctx->trigger_engine = plugin_ctx_.trigger_engine;
            pctx->plugin_name = descriptor->name;

            auto* raw_pctx = reinterpret_cast<YuzuPluginContext*>(pctx.get());
            if (handle.descriptor()->init) {
                int rc = handle.descriptor()->init(raw_pctx);
                if (rc != 0) {
                    spdlog::warn("Plugin {} init returned {}, skipping", handle.descriptor()->name,
                                 rc);
                    record_module(descriptor->name, descriptor->version,
                                  std::format("{} (init rc={})", descriptor->description, rc),
                                  "init_failed");
                    continue;
                }
            }
            per_plugin_ctx_[descriptor->name] = std::move(pctx);
            record_module(descriptor->name, descriptor->version, descriptor->description, "loaded");
            plugin_names_.emplace_back(handle.descriptor()->name);
            plugins_.push_back(std::move(handle));
        }

        // Populate plugin list in config (available to all plugins via get_config)
        plugin_ctx_.config["agent.plugins.count"] = std::to_string(plugins_.size());
        plugin_ctx_.config["agent.modules.count"] = std::to_string(module_index);
        for (size_t i = 0; i < plugins_.size(); ++i) {
            auto prefix = std::format("agent.plugins.{}", i);
            plugin_ctx_.config[prefix + ".name"] = plugins_[i].descriptor()->name;
            plugin_ctx_.config[prefix + ".version"] = plugins_[i].descriptor()->version;
            plugin_ctx_.config[prefix + ".description"] = plugins_[i].descriptor()->description;
        }

        // Per-plugin contexts were snapshotted from plugin_ctx_.config during
        // the load loop above, so they are missing every key written after
        // their own snapshot point: agent.plugins.count, agent.modules.count,
        // the agent.plugins.N.* roster, and agent.modules.N.* entries for
        // any module recorded after the plugin's own init. Re-sync the master
        // map into every per-plugin context so calls like agent_actions:info
        // see the complete post-load state instead of "(not set)".
        //
        // Plugins whose init() is *itself* reading these keys cannot observe
        // them — init runs before this sync. agent_actions::info is dispatched
        // post-init via execute(), so the fix is correct for that consumer.
        // Runtime keys written AFTER this point (agent.session_id at register
        // time, agent.reconnect_count, agent.latency_ms, agent.grpc_channel_state,
        // agent.connected_since) do NOT propagate — see CONS-B1 follow-up.
        //
        // Implementation extracted to plugin_config_sync.hpp so it can be
        // unit-tested without exposing PluginContextImpl outside this TU.
        detail::sync_master_config_to_plugins(plugin_ctx_.config, per_plugin_ctx_);

        metrics_.gauge("yuzu_agent_plugins_loaded").set(static_cast<double>(plugins_.size()));
        start_time_ = std::chrono::steady_clock::now();
        spdlog::info("Loaded {} plugin(s)", plugins_.size());

        ScopeExit cleanup{[this]() {
            // #2233 item 3 ("S+"): armed first, covers this whole ScopeExit body —
            // guardian_/spark_engine_ teardown (the confirmed hazard), the worker joins,
            // trigger_engine_, every plugin's shutdown() callback (arbitrary third-party
            // code), and thread_pool_.reset() below. Independent of stop()'s own watchdog;
            // see shutdown_deadline_guard.hpp — multiple concurrent guards need no
            // coordination with each other.
            yuzu::agent::ShutdownDeadlineGuard watchdog{kShutdownDeadlineGrace};
            // Guardian BEFORE SparkEngine, on EVERY run() exit - not just the
            // externally-triggered Agent::stop() path (handler_ex / the shutdown
            // watcher / the console handler). A run() exit that never went
            // through an explicit stop() request (e.g. the dispatch-pool
            // re-creation failure below setting stop_requested_ directly)
            // previously left guardian_->stop() never called at all, so F3's
            // orphan check in main()/service_win.cpp could sample
            // guardian_active_io_workers() before Guardian I/O admission was
            // ever closed - not merely before it finished, but before it had
            // even started (Sol rung-7.6 review round 3, finding 1).
            //
            // THIS ORDER (guardian_ first) is load-bearing and matches
            // Agent::stop()'s own pre-existing order: GuardianEngine::stop()'s
            // own doc comment requires spark teardown to close Guardian's
            // internal admission (spark_runtime_/scheduler/drain-worker) FIRST,
            // so the EXTERNAL spark_engine_->stop() below can safely tear down
            // the SparkEngine consumer afterward without racing a live commit.
            // An earlier version of this guard had these reversed (governance
            // Gate 3/4 finding, this PR) - harmless only because no production
            // call site wires a consumer onto spark_engine_ yet. Idempotent:
            // Agent::stop() may already have called both - safe, but the two engines get
            // there differently (governance Gate 2 finding, this PR - corrected from an
            // earlier draft that overclaimed symmetry). SparkEngine::stop() has a genuine
            // completion barrier (lifecycle_mu_+teardown_complete_, early-out on repeat -
            // its own header comment names this exact stop()-vs-ScopeExit scenario as the
            // reason). GuardianEngine::stop() has no such early-out: it takes mtx_ and
            // RE-EXECUTES its whole body on a second call, safe only because every
            // downstream step in it (ConvergenceScheduler::stop(), OutboxDrainWorker::stop(),
            // stop_all_guards_locked(), GuardianSparkRuntime::begin_stop(),
            // lifecycle_journal_->request_stop()) is independently idempotent - verified, not
            // a barrier. #2233 item 3's watchdog above
            // covers the case where the call THIS thread is executing hangs; it is
            // deliberately NOT layered with an AgentImpl-level once-only guard on top of
            // these calls - an earlier revision of this PR added one (stop_guardian_once/
            // stop_spark_engine_once, mutex + bool flags) and it introduced a real
            // regression (adversarial review Kimi K1): the spark variant set its "done"
            // flag even when the boot-latch gate below caused it to skip the actual call,
            // permanently disabling the ScopeExit's own retry. Reverted - trust each
            // engine's own proven safety on a repeat call instead of re-deriving one here
            // (SparkEngine's genuine completion barrier; GuardianEngine's verified
            // idempotency - see above, neither needed an AgentImpl-level layer on top).
            if (guardian_)
                guardian_->stop();
            // Before thread_pool_ is reset below. Rung 1's engine does not
            // borrow the pool, but rung 2's queued Guardian consumer is expected
            // to dispatch through it (#2037's bounded-dispatch pattern), and this
            // guard resets the pool on every run() exit. Stopping spark here
            // means its threads are quiesced before anything it may borrow goes
            // away - on the exception and early-return paths too, not just the
            // graceful one. Deliberately NO boot-latch gate here (unlike stop()'s own
            // call above) - this runs on run()'s own thread, after run()'s boot block has
            // already executed one way or another, so there is no cross-thread pointer
            // race to guard against; gating this call the same way stop()'s is gated was
            // exactly the mistake reverted above.
            if (spark_engine_)
                spark_engine_->stop();
            // #1420 / #1434 — quiesce and join the Run()-spawned worker threads
            // (snapshot pump, heartbeat, OTA updater) FIRST, before any plugin
            // teardown. The snapshot pump dispatches `tar.fleet_snapshot` into
            // the TAR plugin through a borrowed descriptor, so it must not
            // outlive the plugins; and leaving any of these `this`-capturing
            // threads joinable on an early `return` out of Run() (the hard
            // registration rejection and the PKI persist/rebuild bail-outs)
            // aborts the process via std::terminate. This guard runs on EVERY
            // Run() exit — early returns and exceptions included — so it is the
            // universal backstop. The reconnect-loop final teardown repeats the
            // pump join to order it ahead of plugins_.clear() on the normal path.
            quiesce_run_workers();
            // Stop the trigger engine FIRST — before plugins are torn down —
            // so an in-flight interval/file/service trigger can't dispatch
            // into a plugin that's mid-shutdown. stop() joins the worker
            // threads, so once it returns no further dispatch can occur.
            trigger_engine_.stop();
            for (auto& handle : plugins_) {
                if (handle.descriptor()->shutdown) {
                    // Use per-plugin context if available, fall back to shared
                    auto it = per_plugin_ctx_.find(handle.descriptor()->name);
                    auto* ctx_ptr = (it != per_plugin_ctx_.end())
                                        ? reinterpret_cast<YuzuPluginContext*>(it->second.get())
                                        : reinterpret_cast<YuzuPluginContext*>(&plugin_ctx_);
                    handle.descriptor()->shutdown(ctx_ptr);
                }
            }
            // Destroy the thread pool — signals stop, drains queue, joins workers
            thread_pool_.reset();
            spdlog::info("Yuzu agent stopped");
        }};

        // NOTE: constructed AFTER the ScopeExit above is armed. The failure path below
        // returns early, and before this reorder that return escaped WITHOUT the guard —
        // so plugins already dlopen'd and init()'d were dlclose'd without ever having
        // their shutdown() called (~PluginHandle only DLCLOSEs; the ScopeExit is the sole
        // caller of shutdown()). Unflushed plugin state, unreleased OS handles, and any
        // plugin-init thread left executing unmapped code. (governance Gate-8 UP8-3.)
        // Initialize bounded thread pool for command dispatch.
        //
        // ThreadPool's ctor now joins whatever it managed to spawn and RETHROWS on
        // std::thread's EAGAIN (thread/pid exhaustion — a pids-capped container,
        // RLIMIT_NPROC). That fixed the terminate-in-~vector, but the rethrow has nowhere
        // to go: main.cpp's `agent->run()` is a BARE call with no enclosing handler, and
        // this construction sits before run()'s own inner try. So the exception escaped
        // main() and std::terminate'd anyway — trading one terminate for another
        // (governance Gate-4 UP-5).
        //
        // Catch it here and report a CLEAN STARTUP FAILURE instead: a non-zero exit that
        // systemd Restart= / Docker / the Windows SCM can react to (#1303), and — the
        // point of rung 1 — an agent that lives long enough to SAY spark degraded, rather
        // than a crash-loop that destroys the very signal the degrade path produces.
        try {
            thread_pool_ = std::make_unique<ThreadPool>(std::thread::hardware_concurrency());
        } catch (const std::exception& e) {
            spdlog::critical("could not create the command dispatch thread pool ({}) — the host "
                             "is out of threads. Exiting with a startup failure rather than "
                             "aborting.",
                             e.what());
            startup_failed_ = true;
            return;
        } catch (...) {
            // Belt-and-braces, and NOT theoretical: ThreadPool's ctor now logs INSIDE its own
            // try, and spdlog RETHROWS non-std exceptions. A catch(std::exception&) alone
            // would let such a throw escape the bare `agent->run()` in main.cpp and
            // std::terminate — re-opening the very hole this catch exists to close
            // (governance Gate-8 cpp-safety).
            spdlog::critical("could not create the command dispatch thread pool (non-std "
                             "exception) — exiting with a startup failure rather than aborting.");
            startup_failed_ = true;
            return;
        }

        // SparkEngine (ADR-0021 Stage-2, rung 1 — INSTANTIATE + OBSERVE).
        //
        // POSITION IS LOAD-BEARING — this block must stay AFTER thread_pool_'s
        // construction and AFTER the ScopeExit above. Two governance findings pin it:
        //
        //  (a) DEGRADATION PRIORITY (Gate-4 UP-3). Spark spawns up to 4 threads and
        //      degrades gracefully if it cannot (the catch below). ThreadPool does NOT:
        //      its ctor emplace_back()s std::threads, and on EAGAIN the throw destroys a
        //      vector<std::thread> holding JOINABLE threads → std::terminate. Standing
        //      spark up FIRST let the OPTIONAL subsystem eat the thread budget that the
        //      MANDATORY one then died for — an optional feature crash-looping the agent
        //      on a pids-capped host. Mandatory subsystems claim their threads first.
        //
        //  (b) SCOPEEXIT COVERAGE. Constructed before the guard was armed, a throw between
        //      here and the guard left spark's threads running with no cleanup on the
        //      run()-exit path. NOTE: the guard did not stop spark either until Gate-8
        //      cpp-safety pointed out that it never touched it — it does now, as its FIRST
        //      statement, ahead of thread_pool_.reset().
        //
        // See also the member declaration order (spark_engine_ AFTER thread_pool_) so
        // spark is DESTROYED before the pool it may borrow at rung 2.
        // The next-generation event-driven detection engine is stood up here
        // OBSERVE-ONLY: no consumer is registered at rung 1, so it is not yet wired
        // to drive Guardian and the legacy IGuard path remains the sole ENFORCING
        // detection path. Detection cutover is rung 2; enforce is rung 3. Standing it
        // up now proves the engine runs and reports at rest, so its resource +
        // observability envelope can be measured before it carries any load.
        //
        // --spark-disable / YUZU_AGENT_SPARK_DISABLE is a boot-time deploy opt-out:
        // when set, SparkEngine is never instantiated and watches nothing — but the
        // heartbeat still carries the posture itself (spark_running=0 + spark_disabled=1),
        // so the fleet can tell a deliberate opt-out apart from an engine that FAILED
        // to start (see the DISABLED branch in the heartbeat emit block below).
        // The flag selects exactly one detection path at instantiation, establishing
        // the "old and new never both drive enforce" property the rung-2/3 cutover
        // leans on (moot at rung 1 - spark has no consumer - but pinned here).
        //
        // spark_detached_workers_ (F3, #2012/#3840 plan "Route A corrected")
        // needs no construction step here - it is already live via its own
        // default member initializer, unconditionally before this line runs
        // on every path (including --spark-disable, and including a run()
        // that is never reached at all). See its member declaration's own
        // comment for why that is deliberate and sufficient.
        if (cfg_.spark_disable) {
            spdlog::info("SparkEngine: disabled by --spark-disable — not instantiated; "
                         "Guardian detection path = legacy IGuard (enforcing)");
        } else {
            // DEGRADE-TO-NO-SPARK on any boot exception. SparkEngine::start() (and a
            // mechanism start()) spawns threads; thread creation throws
            // std::system_error under EAGAIN / thread-or-handle exhaustion — most
            // likely on exactly the overloaded endpoint where the agent must SURVIVE,
            // not crash-loop. run() is not wrapped by a catch at its call site
            // (main.cpp `agent->run()`), and this block runs before run()'s own inner
            // try, so an escape here would std::terminate the process (gov UP-1).
            try {
                spark_engine_ = std::make_unique<SparkEngine>();
                // Register the platform event-driven mechanisms. Each factory returns
                // nullptr off its platform (File/Registry: Windows-only; Service:
                // Windows-SCM + Linux-systemd), so an unsupported type is simply left
                // unregistered — SparkEngine then rejects any future arm() of it. The
                // set actually registered IS the agent's spark capability, surfaced to
                // the fleet via the yuzu.spark_mechs heartbeat tag.
                const auto try_register = [&](SparkType type,
                                             std::unique_ptr<ISparkMechanism> mech) {
                    if (!mech)
                        return; // unsupported on this OS — leave the type unregistered
                    if (auto r = spark_engine_->register_mechanism(type, std::move(mech)); !r)
                        spdlog::warn("SparkEngine: register {} mechanism failed: {}",
                                     spark_type_token(type), r.error());
                };
                // File, Registry, and Service all take the shared F3 counter
                // (#2012/#3840 PR-B1 for Registry, PR-B2 for File, PR-B3 for
                // Service's Windows probe lane): their detached discovery
                // workers are admitted against spark_detached_workers_, which
                // guardian_active_io_workers() sums. Passed unconditionally -
                // the platform split lives inside each factory (real on
                // Windows for all three, plus Linux-with-libsystemd for
                // Service, nullptr elsewhere), same as the zero-argument
                // forms. Service's Linux mechanism accepts and ignores the
                // counter (it launches no detached workers - only the
                // Windows SCM half restructures off mech_ops_mu_by_type_).
                try_register(SparkType::File, make_file_mechanism(spark_detached_workers_));
                try_register(SparkType::Registry, make_registry_mechanism(spark_detached_workers_));
                try_register(SparkType::Service, make_service_mechanism(spark_detached_workers_));
                spark_engine_->start();
                spdlog::info("SparkEngine: instantiated OBSERVE-ONLY (no consumer at rung 1); "
                             "Guardian detection path = legacy IGuard (enforcing)");
            } catch (const std::exception& e) {
                // ~SparkEngine (via reset) joins whatever already started; the
                // heartbeat's else branch then ships the FAILED posture
                // (spark_running=0, no disabled key) — a boot failure is visible
                // on the wire, never silent.
                spark_engine_.reset();
                spdlog::warn("SparkEngine: instantiation failed ({}) — continuing WITHOUT "
                             "spark; legacy IGuard detection is unaffected",
                             e.what());
            } catch (...) {
                // Belt-and-braces: NOTHING may terminate the agent for an observe-only
                // best-effort subsystem, even a non-std throw (gov re-review NICE).
                spark_engine_.reset();
                spdlog::warn("SparkEngine: instantiation failed (unknown exception) — "
                             "continuing WITHOUT spark; legacy IGuard detection is unaffected");
            }
        }
        // 1c-ter. Wire Guardian's spark detection path (ADR-0021 rung 7.7a),
        // lifecycle-only. Called on EVERY branch of the spark block above:
        // spark_engine_ is null when --spark-disable was set (records SparkDisabled)
        // or when instantiation threw (records SparkFailed); non-null records
        // Available. The kill-switch flag disambiguates the two null cases. This is
        // the FIRST production call site of wire_spark_engine(); prefer_spark stays
        // false (2-arg ctor above), so no rule places on spark and detection behavior
        // is unchanged - the wiring exercises construction/shutdown of the spark
        // subsystem before rung 7.7b turns on placement.
        guardian_->wire_spark_engine(
            spark_engine_.get(), cfg_.spark_disable,
            [this](const OutboxEntry& e) { return send_guardian_outbox_entry(e); });
        // F7: derive the reported backend from the SAME function the
        // yuzu.guardian_backend heartbeat tag uses, so this log and the tag can
        // never drift apart again the way "detection backend = legacy IGuard"
        // (hardcoded, unconditionally) used to once prefer_spark_ could be true.
        const bool ps = guardian_->prefer_spark();
        const auto avail = guardian_->spark_availability();
        const char* backend = guardian_backend_label(guardian_backend_from_state(ps, avail));
        switch (avail) {
        case GuardianEngine::SparkAvailability::Available:
            spdlog::info("Guardian: spark path WIRED (prefer_spark={}); detection backend = {}",
                         ps, backend);
            break;
        case GuardianEngine::SparkAvailability::SparkDisabled:
            spdlog::info("Guardian: spark path wired as DISABLED (--spark-disable); "
                         "detection backend = {}",
                         backend); // accurate regardless of prefer_spark_: SparkDisabled always means legacy
            break;
        case GuardianEngine::SparkAvailability::SparkFailed:
            spdlog::warn("Guardian: spark path wired as FAILED (SparkEngine did not boot); "
                         "detection backend = {}",
                         backend);
            break;
        case GuardianEngine::SparkAvailability::Unwired:
            // Reachable, and NOT an error: wire_spark_engine() bails leaving Unwired when
            // a stop() already ran (a SIGTERM / service-stop during boot). Log at info -
            // the agent is shutting down; legacy was never displaced.
            spdlog::info("Guardian: spark path left Unwired (stop requested during boot); "
                         "detection backend = {}",
                         backend);
            break;
        }

        // Phase-1 pre-network startup: re-arm cached rules from the KV store. Runs
        // AFTER wire_spark_engine() (header contract) and after SparkEngine::start()
        // (so mechanism capability state is populated before reconcile reads it).
        if (auto r = guardian_->start_local(); !r) {
            spdlog::warn("Guardian engine start_local failed: {} - continuing without Guardian",
                         r.error());
        }

        // Publish "the spark slot is final" to cross-thread readers — REQUIRED, not
        // advisory. Handlers are installed and g_agent is published BEFORE run() (so a
        // wedged make_agent can still be interrupted), which means Agent::stop() on the
        // shutdown-watcher / SCM / console thread is concurrent with THIS boot block —
        // and the catch paths above FREE the engine via reset(). A bare `if
        // (spark_engine_)` in stop() during that window is a load racing a store/free:
        // TSan caught it for real (randomized-SIGTERM fuzz, 101 ms delay — read at
        // stop()'s spark gate vs the make_unique store above). stop() therefore gates
        // its spark access on this latch and SKIPS spark before it flips: that is safe,
        // not a leak, because this thread's OWN ScopeExit (armed above) stops the
        // engine on every run() exit — same thread, no race. After the latch flips the
        // slot is never written again until ~AgentImpl, which runs after the watcher
        // join / g_agent_mu barrier. (Governance Gate-3 cpp-safety SAFE-1; the same
        // boot-window shape updater_ already handles with updater_mu_.)
        spark_boot_done_.store(true, std::memory_order_release);

        // Wire trigger dispatch + start the engine. Plugins registered their
        // triggers during init() (above); the engine has been holding them
        // inert until now. The dispatch callback resolves the plugin by name
        // and runs the action in-process via LocalDispatcher — the same
        // mechanism the snapshot pump uses. start() spins up the interval /
        // file-watch / service-watch worker threads and fires any
        // AgentStartup triggers immediately.
        trigger_engine_.set_dispatch([this](const std::string& plugin, const std::string& action,
                                            const std::map<std::string, std::string>& params) {
            const YuzuPluginDescriptor* descriptor = nullptr;
            for (const auto& handle : plugins_) {
                if (std::string_view{handle.descriptor()->name} == plugin) {
                    descriptor = handle.descriptor();
                    break;
                }
            }
            if (!descriptor) {
                spdlog::warn("Trigger dispatch: plugin '{}' not loaded — skipping action '{}'",
                             plugin, action);
                return;
            }
            // Convert the param map into the C-ABI YuzuParam span. The map
            // outlives this synchronous run() call (it's owned by the
            // TriggerConfig snapshot in the engine's worker loop), so the
            // c_str() views stay valid for the duration of the dispatch.
            std::vector<YuzuParam> yparams;
            yparams.reserve(params.size());
            for (const auto& [k, v] : params)
                yparams.push_back(YuzuParam{k.c_str(), v.c_str()});

            LocalDispatcher dispatcher;
            auto result = dispatcher.run(descriptor, action, yparams);
            if (result.rc != 0) {
                spdlog::warn("Trigger dispatch: {}.{} returned rc={}", plugin, action, result.rc);
            }
        });
        trigger_engine_.start();

        // 2. Connect to server (tuned for low-latency bidirectional streaming)
        grpc::ChannelArguments ch_args;
        ch_args.SetInt(GRPC_ARG_KEEPALIVE_TIME_MS, 60000);
        ch_args.SetInt(GRPC_ARG_KEEPALIVE_TIMEOUT_MS, 20000);
        ch_args.SetInt(GRPC_ARG_KEEPALIVE_PERMIT_WITHOUT_CALLS, 1);
        ch_args.SetInt(GRPC_ARG_HTTP2_MAX_PINGS_WITHOUT_DATA, 0);

        // Auto-discover client certificate if none explicitly configured
        if (cfg_.cert_auto_discovery && cfg_.tls_client_cert.empty() && cfg_.cert_store.empty()) {
            auto discovered = discover_client_cert();
            if (discovered) {
                cfg_.tls_client_cert = discovered->cert_path;
                cfg_.tls_client_key = discovered->key_path;
                spdlog::info("Using auto-discovered cert from {} (source: {})",
                             discovered->cert_path.string(), discovered->source);
            }
        }

        // PKI PR3: per-agent mTLS provisioning. When TLS is on with a CA but the
        // operator supplied no explicit client cert / OS-store cert, the agent
        // obtains its OWN client leaf from the server — it generates a keypair +
        // CSR, sends the CSR in Register, persists the issued leaf (key 0600), and
        // reconnects presenting it. `pending_csr_pem` rides the next Register; a
        // non-empty `pending_key_pem` is the key awaiting its issued leaf.
        //
        // Renewal is evaluated here at startup (NeedsRenew at 2/3 life). A
        // continuously-running agent that never restarts renews on its next
        // process start / re-provision; a mid-run renewal thread is a follow-up.
        std::string pending_csr_pem;
        std::string pending_key_pem;
        // cpp-safety (#1239): the agent private key lives in `pending_key_pem`
        // from generation until it is persisted (then explicitly zeroed below).
        // A stop/return BETWEEN those points — e.g. shutdown mid-enrollment, or
        // any early return on the connect path — would otherwise leave the key
        // resident in process memory. This guard scrubs it on EVERY exit from
        // run() (the explicit zeroes below clear() too, so the guard then no-ops).
        struct KeyScrub {
            std::string& k;
            ~KeyScrub() { yuzu::secure_zero(k); }
        } pending_key_scrub{pending_key_pem};
        int csr_attempts = 0; // Hermes HIGH-2: bound enrolled-but-no-cert retries.
        const std::filesystem::path cert_dir =
            cfg_.cert_dir.empty() ? (cfg_.data_dir / "certs") : cfg_.cert_dir;
        // HIGH-1 (#1314): resolve the effective CA path BEFORE the provisioning gate.
        // The install-CA auto-discovery used to live only inside build_channel and
        // never wrote back cfg_.tls_ca_cert, so a no-`--ca-cert` agent connected over
        // server-authenticated TLS but `provisioning_eligible` stayed false → it sent
        // no CSR and never got its per-agent client leaf, with no error. Promoting the
        // discovered path into cfg_.tls_ca_cert here makes both the provisioning gate
        // and build_channel see the same effective CA (an explicit --ca-cert is left
        // untouched, so this is a no-op when one was given).
        if (cfg_.tls_enabled && cfg_.tls_ca_cert.empty()) {
            if (auto ca = discover_install_ca_path()) {
                cfg_.tls_ca_cert = *ca;
                spdlog::info("PKI: auto-discovered install CA at {} — using it as the trust "
                             "anchor and enabling per-agent enrollment",
                             cfg_.tls_ca_cert.string());
            }
        }
        const bool provisioning_eligible =
            cfg_.auto_provision_cert && cfg_.tls_enabled && !cfg_.tls_ca_cert.empty() &&
            cfg_.tls_client_cert.empty() && cfg_.cert_store.empty();
        if (provisioning_eligible) {
            const auto state = inspect_provisioned_cert(cert_dir);
            const auto paths = provisioned_cert_paths(cert_dir);
            if (state == CertState::Valid || state == CertState::NeedsRenew) {
                // A usable leaf exists — present it (mTLS from the first connect).
                cfg_.tls_client_cert = paths.cert_path;
                cfg_.tls_client_key = paths.key_path;
                spdlog::info("PKI: using provisioned client cert {} ({})", paths.cert_path.string(),
                             state == CertState::NeedsRenew ? "past 2/3 life — will renew"
                                                            : "valid");
            }
            if (state != CertState::Valid) {
                // Missing / Expired → enroll; NeedsRenew → renew. Either way mint a
                // fresh keypair + CSR to present in Register.
                if (auto kc = generate_key_and_csr(cfg_.agent_id)) {
                    pending_key_pem = std::move(kc->private_key_pem);
                    pending_csr_pem = std::move(kc->csr_pem);
                    spdlog::info("PKI: generated EC P-256 keypair + CSR ({})",
                                 state == CertState::NeedsRenew ? "renewal" : "first enrollment");
                } else {
                    spdlog::error("PKI: failed to generate agent keypair/CSR — continuing without "
                                  "per-agent mTLS");
                }
            }
        }

        CloudIdentity cloud_id; // Populated before registration (step 2b)
        std::shared_ptr<grpc::Channel> channel;
        std::unique_ptr<pb::AgentService::Stub> stub;
        // Build (or rebuild, post-issuance) the credentials + channel + stub from
        // the current cfg_ cert paths. Returns false on an unreadable cert/key.
        auto build_channel = [&]() -> bool {
            std::shared_ptr<grpc::ChannelCredentials> creds;
            if (cfg_.tls_enabled) {
                grpc::SslCredentialsOptions ssl_opts;
                if (!cfg_.tls_ca_cert.empty()) {
                    ssl_opts.pem_root_certs = read_file_contents(cfg_.tls_ca_cert);
                    if (ssl_opts.pem_root_certs.empty()) {
                        spdlog::error("Failed to read CA cert from {}", cfg_.tls_ca_cert.string());
                        return false;
                    }
                } else {
                    // PKI #1303: fail CLOSED. No --ca-cert was given and the install-CA
                    // auto-discovery above run() found nothing usable at the standard
                    // shared-cert-volume path (a found CA is promoted into
                    // cfg_.tls_ca_cert there, so reaching this branch means none existed;
                    // discover_install_ca_path() also rejects an empty/truncated file, so
                    // it never pins nothing). An empty pem_root_certs makes gRPC verify
                    // against the SYSTEM trust store, which does NOT trust a Yuzu
                    // self-signed install CA. With the gateway one-way-TLS edge live that
                    // is a fail-open MITM window (any publicly-trusted impostor cert for
                    // the dial host would be accepted) on the command fan-out plane.
                    // Refuse unless the operator has DELIBERATELY opted into the system
                    // trust store (server leaf signed by a public/corporate CA).
                    if (!cfg_.tls_allow_system_trust) {
                        spdlog::error(
                            "TLS is enabled but no CA could be pinned: --ca-cert was not given "
                            "and no install CA was found at the standard path(s) "
#ifdef _WIN32
                            "(C:/ProgramData/Yuzu/certs/default-ca.pem). "
#elif defined(__APPLE__)
                            "(/etc/yuzu/certs/default-ca.pem, plus "
                            "~/Library/Application Support/Yuzu/certs/default-ca.pem for a "
                            "non-root agent). "
#else
                            "(/etc/yuzu/certs/default-ca.pem). "
#endif
                            "Refusing to connect with the "
                            "SYSTEM trust store, which does NOT trust a Yuzu self-signed install "
                            "CA — that would be a fail-open MITM posture. Fix one of: provide "
                            "--ca-cert; ensure the install CA exists at that path; pass "
                            "--tls-system-roots if the server cert is signed by a public/"
                            "corporate CA already in the system store; or --no-tls for a "
                            "dev/demo stack.");
                        return false;
                    }
                    spdlog::warn("TLS is enabled with no pinned CA — using the SYSTEM trust "
                                 "store by explicit --tls-system-roots. Safe ONLY if the server "
                                 "certificate chains to a CA already trusted by the system "
                                 "(public/corporate root), NOT a Yuzu self-signed install CA.");
                }

                // Client certificate: prefer cert store, fall back to PEM files
                if (!cfg_.cert_store.empty()) {
                    // Read client cert + key from OS certificate store
                    spdlog::info("Reading client certificate from {} store...", cfg_.cert_store);
                    auto store_result = read_cert_from_store(cfg_.cert_store, cfg_.cert_subject,
                                                             cfg_.cert_thumbprint);

                    if (!store_result.ok()) {
                        spdlog::error("Certificate store error: {}", store_result.error);
                        return false;
                    }

                    ssl_opts.pem_cert_chain = std::move(store_result.pem_cert_chain);
                    ssl_opts.pem_private_key = std::move(store_result.pem_private_key);
                    spdlog::info("mTLS enabled: using certificate from {} store", cfg_.cert_store);
                } else {
                    const bool has_client_cert = !cfg_.tls_client_cert.empty();
                    const bool has_client_key = !cfg_.tls_client_key.empty();
                    if (has_client_cert != has_client_key) {
                        spdlog::error("mTLS requires both --client-cert and --client-key");
                        return false;
                    }

                    if (has_client_cert && has_client_key) {
                        ssl_opts.pem_cert_chain = read_file_contents(cfg_.tls_client_cert);
                        ssl_opts.pem_private_key = read_file_contents(cfg_.tls_client_key);
                        if (ssl_opts.pem_cert_chain.empty() || ssl_opts.pem_private_key.empty()) {
                            spdlog::error("Failed to read client cert/key for mTLS");
                            return false;
                        } else {
                            spdlog::info("mTLS enabled: using client certificate files");
                        }
                    }
                }
                creds = grpc::SslCredentials(ssl_opts);
                yuzu::secure_zero(ssl_opts.pem_private_key);
            } else {
                creds = grpc::InsecureChannelCredentials();
            }

            channel = grpc::CreateCustomChannel(cfg_.server_address, creds, ch_args);
            stub = pb::AgentService::NewStub(channel);
            return true;
        };

        if (!build_channel()) {
            // The initial build_channel() failed closed — most importantly the #1303
            // fail-closed TLS posture (no pinnable CA under secure-by-default), but also
            // an unreadable CA/client cert/key. This is a fatal STARTUP failure, not a
            // normal shutdown: flag it so main() exits non-zero and systemd Restart= /
            // Docker / Windows SCM see the failure instead of a silent EXIT_SUCCESS.
            startup_failed_ = true;
            return;
        }

        // 2b. Detect cloud instance identity (for auto-approve)
        {
            cloud_id = detect_cloud_identity();
            if (cloud_id.valid()) {
                spdlog::info("Cloud identity detected: provider={}, instance={}, region={}",
                             cloud_id.provider, cloud_id.instance_id, cloud_id.region);
            }
        }

        // PR 10 / UAT 2026-05-12 — snapshot pump is spawned ONCE, not
        // per-reconnect. The pump runs through reconnects, keeping the
        // shared `latest_snapshot_` buffer warm; the heartbeat thread
        // (which IS re-spawned per connection) reads from it and ships
        // it on the next heartbeat. This means a brief disconnect does
        // not cost us the next push — the pump kept producing while
        // the link was down, the first reconnected heartbeat carries
        // the latest snapshot.
        //
        // Pump is gated on the TAR plugin being loaded; minimal /
        // embedded agent variants without TAR simply leave the slot
        // empty and the server falls back to dispatch-on-get.
        {
            const YuzuPluginDescriptor* tar_descriptor = nullptr;
            for (const auto& handle : plugins_) {
                if (std::string_view{handle.descriptor()->name} == "tar") {
                    tar_descriptor = handle.descriptor();
                    break;
                }
            }
            if (tar_descriptor) {
                snapshot_pump_thread_ = std::thread([this, tar_descriptor]() {
                    spdlog::info("Snapshot pump started (interval=30s, action=tar.fleet_snapshot)");
                    constexpr auto kFirstDelay = std::chrono::seconds{5};
                    constexpr auto kInterval = std::chrono::seconds{30};
                    auto sleep_for = [this](std::chrono::seconds total) {
                        auto remaining = total;
                        while (remaining.count() > 0 &&
                               !stop_requested_.load(std::memory_order_acquire)) {
                            auto step = std::min(remaining, std::chrono::seconds{2});
                            std::this_thread::sleep_for(step);
                            remaining -= step;
                        }
                    };
                    sleep_for(kFirstDelay);
                    LocalDispatcher dispatcher;
                    while (!stop_requested_.load(std::memory_order_acquire)) {
                        // #1001 / arch-S3 — local-dispatch concerns
                        // (capture buffer, byte cap, truncation sentinel)
                        // live in LocalDispatcher. The pump just decides
                        // what to do with each cycle's result.
                        auto result = dispatcher.run(tar_descriptor, "fleet_snapshot");
                        if (result.truncated) {
                            spdlog::warn("Snapshot pump: capture truncated at {}B; "
                                         "dropping this cycle's snapshot",
                                         result.captured.size());
                        } else if (result.rc == 0 && !result.captured.empty()) {
                            std::lock_guard lock(snapshot_mu_);
                            latest_snapshot_ = std::move(result.captured);
                            latest_snapshot_seq_.fetch_add(1, std::memory_order_acq_rel);
                        } else if (result.rc != 0) {
                            spdlog::warn("Snapshot pump: tar.fleet_snapshot rc={}, captured={}B",
                                         result.rc, result.captured.size());
                        }
                        sleep_for(kInterval);
                    }
                    spdlog::info("Snapshot pump stopped");
                });
            } else {
                spdlog::info("Snapshot pump skipped: TAR plugin not loaded");
            }
        }

        // 3. Register with server — with reconnect loop
        int reconnect_count = 0;
        constexpr int kMaxReconnectDelaySecs = 300; // 5 minutes max backoff
        /// Ceiling on a single Register attempt. Generous — a busy server plus TLS plus an
        /// approval check is not instant — but FINITE, which is the whole point: without it a
        /// server that completes TLS and then goes silent parks the main thread forever, and on
        /// the OTA self-stop path there is no signal and no supervisor timeout to rescue it.
        /// A failed attempt just falls into the existing reconnect backoff.
        constexpr auto kRegisterTimeout = std::chrono::seconds{30};
        constexpr int kMaxCsrAttempts = 5; // PKI: bound enrolled-but-no-cert retries

        while (!stop_requested_.load(std::memory_order_acquire)) {
            if (reconnect_count > 0) {
                // Exponential backoff: 2^n seconds, capped at 5 minutes
                int delay = std::min(1 << std::min(reconnect_count, 8), kMaxReconnectDelaySecs);
                spdlog::info("Reconnecting in {}s (attempt #{})", delay, reconnect_count);
                plugin_ctx_.config["agent.reconnect_count"] = std::to_string(reconnect_count);
                for (int i = 0; i < delay && !stop_requested_.load(std::memory_order_acquire); ++i)
                    std::this_thread::sleep_for(std::chrono::seconds(1));
                if (stop_requested_.load(std::memory_order_acquire))
                    break;
            }

            {
                grpc::ClientContext ctx;
                // THE FOURTH ClientContext — and until now the only one outside the CtxSlot
                // regime: no deadline, and no cancellable slot.
                //
                // Register is a BLOCKING unary call on the main thread. Against a server or
                // gateway that completes TCP+TLS and then never answers — a sick gateway, a
                // hung load balancer, an approval backlog — SIGTERM did this: the watcher ran
                // Agent::stop(), which cancelled subscribe/heartbeat/sync (ALL NULL: none is
                // published until AFTER registration succeeds), returned, and exited. Main
                // stayed parked in Register. run() never returned, ~Agent never ran, and the
                // agent hung until the supervisor's SIGKILL — 90s under systemd, and under
                // Docker a SIGKILL mid-teardown. It is the same class the code calls out as a
                // cpp-safety BLOCKING one screen down, on the drain.
                //
                // Two independent fixes, because either alone leaves a hole:
                //   * a DEADLINE, so a silent server cannot park us forever even with no signal
                //     (this is also the OTA self-stop path, which gets no signal at all); and
                //   * a CtxSlot, so stop() can cancel an in-flight Register immediately rather
                //     than waiting the deadline out.
                // MEASURED against a black-hole server (accepts TCP, never answers), Linux, 49
                // plugins: 18.0s -> 8-9s (n=4). The 18.0s was gRPC's own transport timeout
                // expiring. An earlier version of this comment said "~1s", which was the
                // second-signal figure pasted onto the wrong case; it is corrected here rather
                // than left to justify a bound nobody measured.
                // (governance: cpp-safety BLOCKING, unhappy-path UP-C11/C12, enterprise C1.)
                ctx.set_deadline(std::chrono::system_clock::now() + kRegisterTimeout);
                CtxSlot register_slot{ctx_mu_, register_ctx_, &ctx};

                // PUBLISH, THEN RE-CHECK. The loop tested stop_requested_ above, but a stop()
                // landing in the window between that test and the publish above finds
                // register_ctx_ still NULL — so it cancels nothing, and this Register runs to its
                // full 30s deadline while the supervisor's grace (Docker's is 10s) expires and
                // SIGKILLs us mid-teardown. The window is a few instructions wide; the fix is one
                // line, and it closes it structurally rather than by argument.
                // (governance: security-guardian, cpp-safety — independently, this PR.)
                if (stop_requested_.load(std::memory_order_acquire))
                    break;
                pb::RegisterRequest req;
                auto* info = req.mutable_info();
                info->set_agent_id(cfg_.agent_id);
                info->set_agent_version(std::string{yuzu::kFullVersionString});

                // Populate Platform sub-message so the server (and the dashboard
                // scope panel via /fragments/scope-list) can identify which OS
                // and architecture this agent is running on. kAgentOs and
                // kAgentArch are compile-time constants pinned per build target;
                // get_os_version() probes the running kernel for the version
                // string. The OTA updater also reads platform.os/arch to find
                // matching binaries, so this fix unblocks OTA selection too.
                {
                    auto* platform = info->mutable_platform();
                    platform->set_os(kAgentOs);
                    platform->set_arch(kAgentArch);
                    platform->set_version(get_os_version());
                }

                // Set hostname for auto-approve hostname_glob matching
                {
                    char host_buf[256] = {};
                    if (gethostname(host_buf, sizeof(host_buf) - 1) == 0) {
                        info->set_hostname(host_buf);
                    }
                }

                // Load agent tags from tags.json and populate scopable_tags
                {
                    auto tags_path = cfg_.data_dir / "tags.json";
                    std::error_code tag_ec;
                    if (std::filesystem::exists(tags_path, tag_ec)) {
                        std::ifstream tags_file(tags_path);
                        if (tags_file) {
                            try {
                                std::string tags_content = read_file_contents(tags_path);
                                auto* tags_map = info->mutable_scopable_tags();
                                // Quick manual JSON parse for flat {"key":"value",...} objects
                                size_t pos = 0;
                                while ((pos = tags_content.find('"', pos)) != std::string::npos) {
                                    size_t key_start = pos + 1;
                                    size_t key_end = tags_content.find('"', key_start);
                                    if (key_end == std::string::npos)
                                        break;
                                    std::string key =
                                        tags_content.substr(key_start, key_end - key_start);
                                    pos = key_end + 1;
                                    pos = tags_content.find(':', pos);
                                    if (pos == std::string::npos)
                                        break;
                                    pos = tags_content.find('"', pos);
                                    if (pos == std::string::npos)
                                        break;
                                    size_t val_start = pos + 1;
                                    size_t val_end = tags_content.find('"', val_start);
                                    if (val_end == std::string::npos)
                                        break;
                                    std::string val =
                                        tags_content.substr(val_start, val_end - val_start);
                                    (*tags_map)[key] = val;
                                    pos = val_end + 1;
                                }
                                if (!tags_map->empty()) {
                                    spdlog::info("Loaded {} tags from {}", tags_map->size(),
                                                 tags_path.string());
                                }
                            } catch (...) {
                                spdlog::warn("Failed to parse tags.json");
                            }
                        }
                    }
                }

                for (const auto& handle : plugins_) {
                    auto* pi = info->add_plugins();
                    pi->set_name(handle.descriptor()->name);
                    pi->set_version(handle.descriptor()->version);
                    pi->set_description(handle.descriptor()->description);
                    if (handle.descriptor()->actions) {
                        for (const char* const* a = handle.descriptor()->actions; *a; ++a) {
                            pi->add_capabilities(*a);
                        }
                    }
                }

                // Tier 2: Include enrollment token if provided
                if (!cfg_.enrollment_token.empty()) {
                    req.set_enrollment_token(cfg_.enrollment_token);
                    spdlog::info("Including enrollment token in registration");
                }

                // Tier 3: Include cloud identity attestation if available
                if (cloud_id.valid()) {
                    req.set_attestation_provider(cloud_id.provider);
                    req.set_machine_certificate(cloud_id.identity_document.data(),
                                                cloud_id.identity_document.size());
                    spdlog::info("Including {} cloud attestation in registration",
                                 cloud_id.provider);
                }

                // PKI PR3: present the CSR so the server signs a per-agent client
                // leaf (CN=<agent_id>). Only set when enrolling/renewing — once a
                // leaf is issued and the channel rebuilt, pending_csr_pem is cleared
                // so a steady-state re-Register never triggers a re-issue.
                if (!pending_csr_pem.empty()) {
                    req.set_csr_pem(pending_csr_pem);
                    spdlog::info("Including CSR for per-agent mTLS enrollment");
                }

                pb::RegisterResponse resp;
                auto register_start = std::chrono::steady_clock::now();
                auto status = stub->Register(&ctx, req, &resp);
                if (!status.ok()) {
                    spdlog::error("Failed to register with server: {}", status.error_message());
                    ++reconnect_count;
                    continue; // Retry registration
                }
                if (!resp.accepted()) {
                    if (resp.reject_reason().find("pending") != std::string::npos) {
                        spdlog::warn("Registration pending admin approval — retrying");
                        ++reconnect_count;
                        continue; // Retry until approved
                    }
                    spdlog::error("Server permanently rejected registration: {}",
                                  resp.reject_reason());
                    return; // Hard rejection — no retry
                }

                auto enrollment_status = resp.enrollment_status();
                if (enrollment_status == "pending") {
                    spdlog::warn("Registration pending admin approval - retrying in backoff");
                    ++reconnect_count;
                    continue; // Retry until approved
                }

                reconnect_count = 0; // Registration succeeded — reset backoff

                // PKI PR3: the server signed our CSR. Persist the leaf + key (0600)
                // + issuing chain, point the config at it, and rebuild the channel
                // so the next connection is mutual TLS. We then `continue` to
                // re-Register over mTLS — the FIRST (server-auth) session bound an
                // empty client identity, so the data plane (Subscribe) would reject
                // it; re-registering binds the leaf's CN=<agent_id> to a fresh
                // session. The CSR is cleared first so the re-Register doesn't
                // request a second cert.
                if (!pending_csr_pem.empty()) {
                    if (!resp.issued_certificate().empty()) {
                        const bool persisted = persist_provisioned_cert(
                            cert_dir, pending_key_pem, resp.issued_certificate(),
                            resp.issued_ca_chain());
                        // Zero the in-memory key on every path; clear the CSR once we
                        // no longer need to act on it.
                        yuzu::secure_zero(pending_key_pem);
                        pending_key_pem.clear();
                        pending_csr_pem.clear();
                        if (persisted) {
                            // Pairs with yuzu_agent_cert_provision_failed_total so an
                            // operator can distinguish a provisioned (mutual-TLS) agent
                            // from one that gave up and is running unauthenticated —
                            // the observability half of the silent-downgrade concern
                            // (#1239 should-fix; the enforcement half is the planned
                            // --require-agent-identity flag, see auth-architecture.md).
                            metrics_.counter("yuzu_agent_cert_provisioned_total").increment();
                            const auto paths = provisioned_cert_paths(cert_dir);
                            cfg_.tls_client_cert = paths.cert_path;
                            cfg_.tls_client_key = paths.key_path;
                            spdlog::info("PKI: received per-agent client cert — reconnecting with "
                                         "mutual TLS");
                            if (!build_channel()) {
                                spdlog::error("PKI: failed to rebuild channel with issued cert");
                                return;
                            }
                            continue; // re-Register over mTLS (binds the cert identity)
                        }
                        // Persist failed (disk full / perms). The server recorded the
                        // leaf but we can't use it; falling through would Subscribe
                        // with no client identity and be rejected, then reconnect with
                        // an empty CSR and never recover. Exit so the service manager
                        // restarts us — on restart the pre-step mints a fresh CSR.
                        metrics_.counter("yuzu_agent_cert_provision_failed_total",
                                         {{"reason", "persist_failed"}})
                            .increment();
                        spdlog::error("PKI: failed to persist the issued client cert under {} — "
                                      "exiting for a clean restart-driven retry",
                                      cert_dir.string());
                        return;
                    }
                    // Hermes HIGH-2: enrolled but NO cert returned (server signer
                    // unavailable/rate-limited, or an active MITM stripped the field).
                    // reconnect_count was reset to 0 above, so without a bound the
                    // agent would tight-loop re-minting/dropping certs. Back off and
                    // retry the SAME CSR a bounded number of times; then give up
                    // provisioning (clear the pending CSR) and proceed — if the server
                    // requires client identity Subscribe will be rejected and the
                    // normal reconnect backoff applies (no more cert churn), and if it
                    // does not (one-way TLS) the agent runs without a client cert.
                    if (++csr_attempts >= kMaxCsrAttempts) {
                        metrics_.counter("yuzu_agent_cert_provision_failed_total",
                                         {{"reason", "no_cert_issued"}})
                            .increment();
                        spdlog::error("PKI: enrolled but the server issued no client certificate "
                                      "after {} attempts — giving up auto-provisioning for this "
                                      "run (check the server CA / signer)",
                                      csr_attempts);
                        yuzu::secure_zero(pending_key_pem);
                        pending_key_pem.clear();
                        pending_csr_pem.clear();
                        // fall through unauthenticated
                    } else {
                        spdlog::warn("PKI: enrolled but no client cert issued (attempt {}/{}); "
                                     "backing off and retrying",
                                     csr_attempts, kMaxCsrAttempts);
                        reconnect_count = csr_attempts; // drive exponential backoff
                        continue;                       // retry Register with the same CSR
                    }
                }

                session_id_ = resp.session_id();
                auto connected_since_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                                              std::chrono::system_clock::now().time_since_epoch())
                                              .count();
                plugin_ctx_.config["agent.session_id"] = session_id_;
                plugin_ctx_.config["agent.connected_since"] = std::to_string(connected_since_ms);

                // Measure Register RPC latency
                auto register_elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                                            std::chrono::steady_clock::now() - register_start)
                                            .count();
                plugin_ctx_.config["agent.latency_ms"] = std::to_string(register_elapsed);

                // Query gRPC channel state
                if (channel) {
                    auto state = channel->GetState(false);
                    const char* state_str = "UNKNOWN";
                    switch (state) {
                    case GRPC_CHANNEL_IDLE:
                        state_str = "IDLE";
                        break;
                    case GRPC_CHANNEL_CONNECTING:
                        state_str = "CONNECTING";
                        break;
                    case GRPC_CHANNEL_READY:
                        state_str = "READY";
                        break;
                    case GRPC_CHANNEL_TRANSIENT_FAILURE:
                        state_str = "TRANSIENT_FAILURE";
                        break;
                    case GRPC_CHANNEL_SHUTDOWN:
                        state_str = "SHUTDOWN";
                        break;
                    }
                    plugin_ctx_.config["agent.grpc_channel_state"] = state_str;
                }
                spdlog::info("Registered with server (session={}, enrollment={})", session_id_,
                             enrollment_status.empty() ? "enrolled" : enrollment_status);

                // Mark Guardian as network-connected. PR 4 will use this hook to
                // drain a buffered-events queue back over the command stream.
                if (guardian_)
                    guardian_->sync_with_server();
            }

            // 3b. OTA updater: rollback check and old binary cleanup
            {
                // Publish the fresh Updater, then work through the LOCAL copy — the slot can
                // be re-read by Agent::stop() on another thread at any moment.
                auto updater = std::make_shared<Updater>(
                    UpdateConfig{.enabled = cfg_.auto_update,
                                 .check_interval = cfg_.update_check_interval,
                                 .signature_trust_bundle = cfg_.update_trust_bundle,
                                 .require_signature = cfg_.update_require_signature,
                                 .metrics = &metrics_},
                    cfg_.agent_id,
                    std::string{yuzu::kFullVersionString}, kAgentOs, kAgentArch,
                    current_executable_path());
                set_updater(updater);

                if (updater->rollback_if_needed()) {
                    spdlog::warn("OTA rollback was triggered - running previous binary");
                }
                updater->cleanup_old_binary();
            }

            // 4. Open Subscribe bidi stream
            {
                // DECLARATION ORDER IS LOAD-BEARING: `sub_ctx` MUST be declared BEFORE its
                // CtxSlot. Destruction is reverse-order, so ~CtxSlot retracts the pointer
                // (under ctx_mu_, blocking any in-flight cancel) and only THEN is `sub_ctx`
                // destroyed. Swap these two lines and the context dies while still published —
                // reopening the exact use-after-free this slot exists to close, with every test
                // still green. TSan will not catch the reorder. (Gate-8 round 8 unhappy-path
                // UP8-4.)
                grpc::ClientContext sub_ctx;
                if (!session_id_.empty()) {
                    sub_ctx.AddMetadata(kSessionMetadataKey, session_id_);
                }
                // Published for the whole of this scope; retracted under ctx_mu_ by the dtor
                // on EVERY exit — including the `continue` below and any throw.
                //
                // It stays published LONGER than the old hand-written clear did (which fired
                // before the joins below): the plugin shutdown loop, the thread-pool reset and
                // the heartbeat/sync joins now all run with it live, so stop() can TryCancel a
                // context whose stream is already gone. That is safe — gRPC's ClientContext
                // owns the underlying call ref, so TryCancel after the stream dies is a no-op,
                // not a UAF — and `sub_ctx` outlives every moment it is published.
                CtxSlot sub_slot{ctx_mu_, subscribe_ctx_, &sub_ctx};
                // PUBLISH-THEN-RE-CHECK, the register_slot pattern's SIBLING SITE. A stop()
                // that ran to completion in the window between Register success and this
                // publish — a WIDE window: CSR/TLS handling, Updater construction,
                // rollback_if_needed()'s and cleanup_old_binary()'s file I/O — cancelled
                // nothing (all slots were null) and is already consumed (the watcher callback
                // fires once). Without this re-check, run() would open Subscribe against a
                // HEALTHY server and park at stream->Read() with no in-process canceller
                // left: the hb/sync/update threads see their stop flags and exit instantly,
                // so nothing ever cancels the stream, and the only exits are server-side
                // session reap or the supervisor's SIGKILL (Docker: 10s grace) — the exact
                // class this PR removes for Register. A stop() landing AFTER this check and
                // before the call binds is covered by gRPC's call_canceled_ latch, with the
                // stream's own lifecycle as backstop. The original hand-split applied the
                // re-check to register_slot only and orphaned this sibling.
                // (governance gate round: cpp-safety BLOCKING, this branch.)
                if (stop_requested_.load(std::memory_order_acquire))
                    break;

                std::shared_ptr<SubscribeStream> stream{stub->Subscribe(&sub_ctx)};
                if (!stream) {
                    spdlog::error("Failed to open Subscribe stream");
                    if (!stop_requested_.load(std::memory_order_acquire)) {
                        ++reconnect_count;
                        spdlog::warn("Subscribe failed — will attempt reconnect");
                        continue;
                    }
                    break;
                }
                spdlog::info("Subscribe stream opened - waiting for commands");

                // Step 4: publish this stream as the Guardian sink target and wire
                // the event-sink now the stream is up and BEFORE any push arrives, so
                // a guard started by a push has a live sink. Drift events ship as a
                // self-describing CommandResponse{plugin:"__guard__", action:"event",
                // payload}. The sink captures only `this` and writes through
                // guardian_sink_stream_ (H4 / #1209): a guard worker fires
                // asynchronously and outlives any single stream, so capturing a
                // specific `stream` would let it write to a cancelled stream across a
                // reconnect. The holder is reset on read-loop exit, under the same
                // mutex, before the stream is torn down.
                if (guardian_) {
                    {
                        std::lock_guard lock(stream_write_mu_);
                        guardian_sink_stream_ = stream;
                    }
                    // #4783: this lambda now runs on GuardianLegacySinkExecutor's own detached
                    // worker, never on a guard's own thread — `this` stays valid across that
                    // because the executor's orphan-exit contract (active_io_workers()'s
                    // fourth term, guardian_engine.cpp) is what keeps main.cpp/service_win.cpp
                    // from tearing this AgentImpl down while a send is still detached and
                    // running, exactly like send_guardian_outbox_entry's own capture below.
                    guardian_->set_event_sink([this](const gpb::GuaranteedStateEvent& ev) {
                        const auto outcome = emit_guardian_event(ev);
                        const bool sent = (outcome == LegacySendOutcome::Sent);
                        // #4606 criterion-10 T_wire (legacy non-Spark drift-sink path only — the
                        // DEX observer's call to this same method stays uninstrumented, see
                        // emit_guardian_event's own comment).
                        try {
                            SendTimingRecord r;
                            r.event_id = ev.event_id();
                            r.sent = sent;
                            r.wire_wall_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                                                 std::chrono::system_clock::now().time_since_epoch())
                                                 .count();
                            spdlog::info("{}", format_send_timing_line(r));
                        } catch (...) { // best-effort diagnostic; never propagate
                        }
                        return outcome;
                    });
                    // Replay the durable lifecycle journal into the send window now that the
                    // sink is live on the new stream (item 7 PR-Ag). The drain worker sends the
                    // paged backlog on its next pass. Inert unless prefer_spark.
                    guardian_->page_journal();
                }

                // 4b. Spawn OTA update check thread
                if (cfg_.auto_update && updater()) {
                    auto* raw_stub = static_cast<void*>(stub.get());
                    // The thread CAPTURES its own shared_ptr. It must not re-read updater_ on
                    // every iteration: run() may publish a new Updater on the next reconnect,
                    // and this thread would then be using a different object mid-flight (and,
                    // with a unique_ptr, a freed one).
                    update_thread_ = std::thread([this, raw_stub,
                                                  updater = updater()]() {
                        spdlog::info("OTA update checker started (interval={}s)",
                                     cfg_.update_check_interval.count());
                        while (!stop_requested_.load(std::memory_order_acquire)) {
                            auto result = updater->check_and_apply(raw_stub);
                            if (result.has_value() && result.value()) {
                                spdlog::info("OTA update applied - agent will restart");
                                stop();
                                return;
                            }
                            if (!result.has_value()) {
                                spdlog::warn("OTA update check failed: {}", result.error().message);
                            }
                            // Sleep in small increments so we can respond to stop quickly
                            auto remaining = cfg_.update_check_interval;
                            while (remaining.count() > 0 &&
                                   !stop_requested_.load(std::memory_order_acquire)) {
                                auto sleep_time = std::min(remaining, std::chrono::seconds{5});
                                std::this_thread::sleep_for(sleep_time);
                                remaining -= sleep_time;
                            }
                        }
                    });
                }

                // 4b-sync. Spawn the daily-sync thread (ADR-0016). Per-connection,
                // mirroring the heartbeat thread: its own ReportInventory stub from
                // `channel`, joined on disconnect. Sync state (last_hash / next_fire)
                // persists in kv_store_ namespace "__sync__" across reconnects, so a
                // flap does not lose or duplicate a daily push.
                {
                    const YuzuPluginDescriptor* ia_descriptor = nullptr;
                    const YuzuPluginDescriptor* tar_descriptor = nullptr;
                    // device_ci source plugins (ADR-0016): hardware / device_identity /
                    // os_info / network_config, reused in-process via LocalDispatcher.
                    const YuzuPluginDescriptor* hw_descriptor = nullptr;
                    const YuzuPluginDescriptor* devid_descriptor = nullptr;
                    const YuzuPluginDescriptor* osinfo_descriptor = nullptr;
                    const YuzuPluginDescriptor* netcfg_descriptor = nullptr;
                    // SLE (ADR-0024): the software_licensing source's backing plugin.
                    const YuzuPluginDescriptor* license_descriptor = nullptr;
                    // Wave 7 PR7.2: the app_usage source's backing plugin (last-used
                    // state, read-only over TAR's usage_daily fold).
                    const YuzuPluginDescriptor* app_usage_descriptor = nullptr;
                    for (const auto& handle : plugins_) {
                        const std::string_view pname{handle.descriptor()->name};
                        if (pname == "installed_apps")
                            ia_descriptor = handle.descriptor();
                        else if (pname == "tar")
                            tar_descriptor = handle.descriptor();
                        else if (pname == "hardware")
                            hw_descriptor = handle.descriptor();
                        else if (pname == "device_identity")
                            devid_descriptor = handle.descriptor();
                        else if (pname == "os_info")
                            osinfo_descriptor = handle.descriptor();
                        else if (pname == "network_config")
                            netcfg_descriptor = handle.descriptor();
                        else if (pname == "license_scan")
                            license_descriptor = handle.descriptor();
                        else if (pname == "app_usage")
                            app_usage_descriptor = handle.descriptor();
                    }
                    if (cfg_.inventory_disable) {
                        // Deploy-time opt-out (ADR-0016 / works-council co-determination
                        // control): never start the daily-sync thread — NO source collects
                        // or pushes (installed_software, app_perf, device_ci device identity).
                        spdlog::info("Daily-sync disabled (--inventory-disable / "
                                     "YUZU_AGENT_INVENTORY_DISABLE) — no inventory collected or "
                                     "pushed (sources: installed_software, app_perf, device_ci, "
                                     "software_licensing, app_usage)");
                    } else {
                    sync_stop_.store(false, std::memory_order_release);
                    auto sync_stub = pb::AgentService::NewStub(channel);
                    sync_thread_ = std::thread([this, ia_descriptor, tar_descriptor, hw_descriptor,
                                                devid_descriptor, osinfo_descriptor,
                                                netcfg_descriptor, license_descriptor,
                                                app_usage_descriptor,
                                                sync_stub = std::move(sync_stub)]() {
                        auto should_stop = [this]() {
                            return stop_requested_.load(std::memory_order_acquire) ||
                                   sync_stop_.load(std::memory_order_acquire);
                        };
                        auto kv_get = [this](const std::string& key) -> std::string {
                            auto v = kv_store_ ? kv_store_->get(kSyncKvNamespace, key) : std::nullopt;
                            return v ? *v : std::string{};
                        };
                        auto kv_set = [this](const std::string& key, const std::string& value) {
                            if (kv_store_)
                                kv_store_->set(kSyncKvNamespace, key, value);
                        };
                        auto sender =
                            [this, &sync_stub](
                                const std::vector<std::pair<std::string, std::string>>& hashes,
                                const std::vector<std::pair<std::string, std::string>>& blobs)
                            -> std::optional<std::vector<std::string>> {
                            pb::InventoryReport report;
                            report.set_session_id(session_id_);
                            auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                                              std::chrono::system_clock::now().time_since_epoch())
                                              .count();
                            report.mutable_collected_at()->set_millis_epoch(now_ms);
                            auto& ch = *report.mutable_content_hashes();
                            for (const auto& [k, v] : hashes)
                                ch[k] = v;
                            auto& pd = *report.mutable_plugin_data();
                            for (const auto& [k, v] : blobs)
                                pd[k] = v;
                            grpc::ClientContext ctx;
                            // Publish the in-flight context so teardown can TryCancel it
                            // (mirrors heartbeat_ctx_), bounding the shutdown-join wait when a
                            // sync coincides with a disconnect; the 30s deadline is the backstop.
                            ctx.set_deadline(std::chrono::system_clock::now() +
                                             std::chrono::seconds{30});
                            // Was a BARE store/store(nullptr) pair — the one slot that got no
                            // lock at all, so a teardown cancel could TryCancel this frame's
                            // `ctx` after it had been destroyed. Retracted under ctx_mu_ by the
                            // dtor, on the early `return std::nullopt` below too.
                            CtxSlot sync_slot{ctx_mu_, sync_ctx_, &ctx};
                            pb::InventoryAck ack;
                            auto status = sync_stub->ReportInventory(&ctx, report, &ack);
                            if (!status.ok()) {
                                spdlog::debug("sync: ReportInventory RPC failed: {}",
                                              status.error_message());
                                return std::nullopt;
                            }
                            std::vector<std::string> need;
                            for (const auto& n : ack.need_full())
                                need.push_back(n);
                            return need;
                        };
                        auto scheduler_ptr =
                            std::make_shared<SyncScheduler>(cfg_.agent_id, kv_get, kv_set, sender);
                        SyncScheduler& scheduler = *scheduler_ptr;
                        // Clear the sync-on-demand handle on EVERY exit of this thread
                        // (normal stop, or a throw out of tick()) so the command loop
                        // never arms a scheduler whose thread is gone.
                        ScopeExit clear_sync_handle{[this]() {
                            std::lock_guard<std::mutex> lk(sync_sched_mu_);
                            sync_scheduler_.reset();
                        }};
                        // DEX app-perf-over-time B1. Rides the same daily-sync thread +
                        // transport; collection is further gated by procperf_enabled (an
                        // empty rollup → the source skips the cycle) and the TAR plugin
                        // being loaded (null descriptor → idle).
                        scheduler.add_source(make_app_perf_source(tar_descriptor));
                        // ADR-0016 device-CI inventory: stable hardware/OS identity (CMDB
                        // CI record). Idles unless all four source plugins are loaded.
                        scheduler.add_source(make_device_ci_source(hw_descriptor, devid_descriptor,
                                                                   osinfo_descriptor,
                                                                   netcfg_descriptor));
                        // SLE (ADR-0024): detected software licences. Idles when the
                        // license_scan plugin isn't loaded (null descriptor). The
                        // per-user user_ref knob (Decision 11) and its persisted
                        // k_agent (roadmap R16, `license_scan` KvStore namespace) are
                        // injected here; the HMAC key never leaves that namespace.
                        {
                            SoftwareLicensingConfig lic_cfg;
                            lic_cfg.user_ref_mode =
                                parse_user_ref_mode(cfg_.license_scan_user_ref)
                                    .value_or(UserRefMode::hash);
                            lic_cfg.kv_get = [this](std::string_view key) -> std::string {
                                auto v = kv_store_ ? kv_store_->get("license_scan", key)
                                                   : std::nullopt;
                                return v ? *v : std::string{};
                            };
                            lic_cfg.kv_set = [this](std::string_view key,
                                                    std::string_view value) -> bool {
                                // Propagate the persist result so the sync source can skip
                                // a cycle rather than use an unpersisted HMAC key (D-11).
                                return kv_store_ && kv_store_->set("license_scan", key, value);
                            };
                            scheduler.add_source(make_software_licensing_source(
                                license_descriptor, std::move(lic_cfg)));
                        }
                        // Wave 7 PR7.2: per-executable last-used state, derived from TAR's
                        // usage_daily fold via the read-only app_usage plugin. Idles when
                        // the app_usage plugin isn't loaded (null descriptor) or TAR's usage
                        // source is disabled (constrained capture — skipped, not idled).
                        // Registered here (before installed_software) rather than last: it's
                        // a fast, local SQLite read, not the slow collector the reorder below
                        // exists to deprioritize.
                        scheduler.add_source(make_app_usage_source(app_usage_descriptor));
                        // Registers LAST (round-3 item 4 / sync-speed fix): SyncScheduler's
                        // per-forced-source immediate-RPC pass (tick()) processes forced
                        // indices in ascending registration order, so when the header's
                        // "Sync now" forces every source at once (kAllSources), the faster
                        // collectors above report back to the server before this one's —
                        // installed_software's macOS leg alone can take several seconds
                        // (system_profiler + per-package pkgutil spawns) — even starts.
                        // Registration order carries NO persisted meaning (KV keys and
                        // request_now()'s name match are both name-keyed, per
                        // sync_scheduler.hpp's own contract), so this reorder is safe.
                        scheduler.add_source(make_installed_software_source(ia_descriptor));
                        // Publish AFTER the last add_source: request_now() reads sources_
                        // without the mutex on the append-only-before-publication contract.
                        {
                            std::lock_guard<std::mutex> lk(sync_sched_mu_);
                            sync_scheduler_ = scheduler_ptr;
                        }
                        spdlog::info("Daily-sync thread started (sources=5: installed_software, "
                                     "app_perf, device_ci, software_licensing, app_usage)");
                        while (!should_stop()) {
                            auto now_secs = std::chrono::duration_cast<std::chrono::seconds>(
                                                std::chrono::system_clock::now().time_since_epoch())
                                                .count();
                            auto sleep = scheduler.tick(now_secs);
                            auto remaining = sleep;
                            while (remaining.count() > 0 && !should_stop()) {
                                // __sync__.now: re-tick immediately; the drain at the top of
                                // tick() fires the requested source(s). Checked before the
                                // first sleep so a request landing mid-tick is not lost.
                                if (sync_wake_.exchange(false, std::memory_order_acq_rel))
                                    break;
                                auto step = std::min(remaining, std::chrono::seconds{2});
                                std::this_thread::sleep_for(step);
                                remaining -= step;
                            }
                        }
                        spdlog::info("Daily-sync thread stopped");
                    });
                    } // end else: daily-sync enabled (inventory_disable == false)
                }

                // 4c. Spawn heartbeat thread — piggybacks agent metrics in status_tags
                {
                    heartbeat_stop_.store(false, std::memory_order_release);
                    auto hb_stub = pb::AgentService::NewStub(channel);
                    heartbeat_thread_ = std::thread([this, hb_stub = std::move(hb_stub)]() {
                        spdlog::info("Heartbeat thread started (interval={}s)",
                                     cfg_.heartbeat_interval.count());
                        auto should_stop = [this]() {
                            return stop_requested_.load(std::memory_order_acquire) ||
                                   heartbeat_stop_.load(std::memory_order_acquire);
                        };
                        // PR 10: per-thread last-shipped snapshot generation.
                        // Stays inside the heartbeat lambda so reconnects
                        // see seq=0 first and re-ship whatever the pump
                        // last produced — important so a flapping link
                        // doesn't leave the server reading a stale slot.
                        uint64_t last_attached_seq = 0;
                        // A4: previous perf-counter reading for the heartbeat's
                        // device-utilization tags (deriving a rate needs two
                        // readings; lambda-local so a reconnect re-baselines and
                        // the first heartbeat of a session ships no stale rate).
#if defined(_WIN32)
                        win::PerfBreachCounters hb_prev_perf;
#elif defined(__linux__)
                        lnx::CpuJiffies hb_prev_cpu_lnx; // A4 Linux heartbeat CPU% delta baseline
#endif
                        // Slice 4a: previous interface byte counters for the
                        // heartbeat network throughput delta (same re-baseline
                        // semantics as hb_prev_perf).
                        netq::NetCounters hb_prev_net;
                        // 4b.3: rolling window of raw cumulative Σretrans/Σsegs
                        // readings — the device retransmit RATE is the interval
                        // delta over this window, not a single sample's absolute
                        // ratio. Lambda-local so a reconnect re-baselines (a new
                        // session ships no rate until it has ≥2 readings again).
                        netq::RetransWindow hb_net_retrans_window;
                        while (!should_stop()) {
                            // Sleep in small increments for responsive shutdown
                            auto remaining = cfg_.heartbeat_interval;
                            while (remaining.count() > 0 && !should_stop()) {
                                auto sleep_time = std::min(remaining, std::chrono::seconds{5});
                                std::this_thread::sleep_for(sleep_time);
                                remaining -= sleep_time;
                            }
                            if (should_stop())
                                break;

                            // Build heartbeat with piggybacked metrics
                            grpc::ClientContext ctx;
                            // Per-iteration: the dtor retracts it under ctx_mu_ at the end of
                            // this loop body, before `ctx` is destroyed.
                            CtxSlot hb_slot{ctx_mu_, heartbeat_ctx_, &ctx};
                            pb::HeartbeatRequest req;
                            req.set_session_id(session_id_);
                            auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                                              std::chrono::system_clock::now().time_since_epoch())
                                              .count();
                            req.mutable_sent_at()->set_millis_epoch(now_ms);

                            auto& tags = *req.mutable_status_tags();
                            auto uptime = std::chrono::duration_cast<std::chrono::seconds>(
                                              std::chrono::steady_clock::now() - start_time_)
                                              .count();
                            tags["yuzu.uptime_s"] = std::to_string(uptime);
                            tags["yuzu.commands_executed"] = std::to_string(static_cast<int64_t>(
                                metrics_.counter("yuzu_agent_commands_executed_total").value()));
                            tags["yuzu.plugins_loaded"] = std::to_string(plugins_.size());
                            // HA WS-0 dedup safety-net signals, emitted every
                            // heartbeat (the agent has no /metrics; the server-side
                            // yuzu_fleet_* derivation + alert land with WS-11).
                            // "degraded"=1 means the durable store never OPENED (a
                            // real 0/1 reading, never absent-reads-as-zero). It is
                            // the OPEN-failure signal ONLY; a store that opened then
                            // fails to WRITE (post-boot disk-full) is surfaced by the
                            // "claim_errors"/"record_errors"/"release_errors"
                            // counters below — each a command that ran undeduplicated
                            // or a possibly-leaked claim, so a post-boot degradation
                            // is not invisible. "misses" counts terminal outcomes
                            // that matched no in-flight row (ran undeduplicated, or a
                            // duplicate terminal) — NOT the eviction double-execute,
                            // which is not separately detectable. "replays" counts
                            // served terminal replays.
                            tags["yuzu.dedup_degraded"] = command_dedup_ ? "0" : "1";
                            tags["yuzu.dedup_replays"] = std::to_string(static_cast<int64_t>(
                                metrics_.counter("yuzu_agent_dedup_replays_total").value()));
                            tags["yuzu.dedup_claim_errors"] = std::to_string(static_cast<int64_t>(
                                metrics_.counter("yuzu_agent_dedup_claim_errors_total").value()));
                            tags["yuzu.dedup_record_terminal_misses"] =
                                std::to_string(static_cast<int64_t>(
                                    metrics_.counter("yuzu_agent_dedup_record_terminal_miss_total")
                                        .value()));
                            tags["yuzu.dedup_record_errors"] = std::to_string(static_cast<int64_t>(
                                metrics_.counter("yuzu_agent_dedup_record_errors_total").value()));
                            tags["yuzu.dedup_release_errors"] = std::to_string(static_cast<int64_t>(
                                metrics_.counter("yuzu_agent_dedup_release_errors_total").value()));
                            // OTA signature refusals (#416/#3807). Carried on the
                            // heartbeat for the same reason as the dedup counters
                            // above: the agent has no /metrics endpoint, so this
                            // is the ONLY channel by which an operator learns that
                            // an endpoint is refusing updates. Without it a
                            // fleet-wide refusal is discovered when machines stop
                            // patching, which is exactly the failure the signing
                            // work exists to make visible.
                            {
                                // Summed over the SHARED reason list, not a
                                // hardcoded copy: a reason added in updater.cpp
                                // and forgotten here would be counted by neither
                                // this tag nor the fleet gauge derived from it.
                                double refused = 0.0;
                                for (const auto reason :
                                     yuzu::agent::kSignatureRefusalReasons) {
                                    refused += metrics_
                                                   .counter("yuzu_agent_ota_signature_refused_total",
                                                            {{"reason", std::string(reason)}})
                                                   .value();
                                }
                                tags["yuzu.ota_signature_refused"] =
                                    std::to_string(static_cast<int64_t>(refused));
                            }
                            tags["yuzu.os"] = kAgentOs;
                            tags["yuzu.arch"] = kAgentArch;
                            tags["yuzu.agent_version"] = std::string{yuzu::kFullVersionString};
                            tags["yuzu.healthy"] = "1";
                            // Guardian policy generation (M5 / #1209): lets the
                            // server detect an agent that missed a push (offline at
                            // push time, or reconnected) and re-push it without a
                            // manual operator action. Always emitted — including
                            // generation 0 — so an agent that has never received a
                            // push still converges once rules exist server-side.
                            if (guardian_) {
                                // Drive durable lifecycle-journal maintenance on the
                                // heartbeat cadence: retry any persist a prior write left
                                // pending, so a failed write self-heals with no new push /
                                // reconnect (item 7 PR-Ag; inert unless prefer_spark). rung
                                // 9c PR-2 Unit 6: this is now ALSO the ack-bookkeeping drain
                                // (§R5.3) - called BEFORE the generation tag is read below so
                                // an acknowledgment this tick produces is visible on THIS
                                // heartbeat rather than one late.
                                guardian_->journal_maintenance_tick();
                                // #4783 commit 4: legacy-sink loss visibility. Deliberately
                                // NOT inside journal_maintenance_tick()'s prefer_spark_ gate
                                // (nor any other prefer_spark_ conditional in this block) -
                                // the legacy IGuard sink is the LIVE production path
                                // regardless of the Spark flip state, so a stranded worker
                                // or an open integrity gap must be observed and repaired on
                                // every heartbeat, not only when Spark is preferred. See
                                // GuardianEngine::legacy_sink_kick()'s own doc comment.
                                guardian_->legacy_sink_kick();
                                tags["yuzu.guardian_generation"] =
                                    std::to_string(guardian_->policy_generation());
                                // Sparse durable-journal telemetry (item 7 PR-Ag §8): only
                                // non-zero counters ship, so a quiescent / inert journal adds
                                // no heartbeat tags.
                                emit_guardian_journal_heartbeat_tags(tags, guardian_->journal_stats());
                                // Journal AGE gauges (flip item 6 + #2364): the staleness pair
                                // ships every heartbeat INCLUDING zero while the drain worker is
                                // live (zero is a real "fresh" reading), the blocked age ships
                                // sparsely. Dormancy is journal_age_stats() returning nullopt
                                // (prefer_spark off / worker not started), not a zero - so an
                                // inert journal still adds no tags here.
                                emit_guardian_journal_age_tags(tags, guardian_->journal_age_stats());
                                // rung 9c PR-3: ack-ledger re-statable gauges
                                // (yuzu.guardian_arm_pending / yuzu.guardian_arm_failed).
                                // Dormancy is guardian_->arm_stats() returning nullopt:
                                // prefer_spark_ off, the engine stopped, Spark itself
                                // unavailable (Unwired/SparkFailed/SparkDisabled), or no
                                // current application yet - see GuardianEngine::arm_stats()'s
                                // own doc comment for why that four-way gate cannot be
                                // inferred from the ledger alone.
                                // A live application emits both tags including a genuine
                                // zero, mirroring the journal age-gauge pair above.
                                emit_guardian_arm_heartbeat_tags(tags, guardian_->arm_stats());
                                // rung 9c PR-3 (Decision 3, Option B): R5.1's physical-
                                // ceiling refusal count, a plain sparse monitor-only
                                // counter (0 omits the tag) - not gated on prefer_spark_,
                                // a zero count is equally truthful whether spark is
                                // dormant or has simply never hit the ceiling.
                                emit_guardian_io_ceiling_heartbeat_tags(
                                    tags, guardian_->io_ceiling_rejections());
                                // M1: a rule stuck Unknown re-evals every ~5s; guard.unhealthy is
                                // edge-emitted, each suppressed repeat is counted (unhealthy_
                                // suppressed), and each errored_refresh_ms-cadence re-emission is
                                // separately counted (unhealthy_refreshed, F5 6b) - so the split is
                                // observable, not silent. priority_demoted (F5 6c) counts rules
                                // evicted off the 5s priority lane. Sparse: non-zero only. Keys
                                // pinned in guardian_health_heartbeat.hpp (drift-proofs the #2298
                                // server-side rollup reader).
                                // outbox_backpressure_drops (#2993): the MAIN compliance/health
                                // outbox's own capacity-rejection counter, previously wired to
                                // NOTHING in production - an on-call operator had no fleet
                                // signal for a chronic main-outbox jam. Sparse: 0 omits its tag.
                                emit_guardian_health_heartbeat_tags(
                                    tags,
                                    GuardianHealthStats{
                                        .unhealthy_suppressed = guardian_->unhealthy_suppressed(),
                                        .unhealthy_refreshed = guardian_->unhealthy_refreshed(),
                                        .priority_demoted = guardian_->priority_demoted(),
                                        .outbox_backpressure_drops =
                                            guardian_->outbox_backpressure_drops(),
                                        // #4783 commit 4: never gated on prefer_spark_ -
                                        // legacy_sink_executor_ is always live, so these
                                        // three report truthfully whichever backend is
                                        // actually enforcing. legacy_sink_dropped_unwired
                                        // (governance follow-up) is the third: the
                                        // pre-network-arm drop, previously counted
                                        // in-process only with no fleet visibility.
                                        .legacy_sink_events_lost =
                                            guardian_->legacy_sink_events_lost(),
                                        .legacy_sink_gap_rules =
                                            guardian_->legacy_sink_gap_rules(),
                                        .legacy_sink_dropped_unwired =
                                            guardian_->legacy_sink_dropped_unwired()});
                                // F7 (#2298 rung 2): per-type CURRENT count of rules classified
                                // Unsupported (neither backend enforces them) - fleet-loud via
                                // mech_unsupported_total, sparse (0 omits its tag).
                                emit_guardian_unsupported_heartbeat_tags(
                                    tags, guardian_->unsupported_counts_by_type());
                                // F7: which backend is ACTUALLY enforcing - always emitted (a
                                // categorical value, not a sparse counter), so the server can
                                // distinguish SparkFailed (nothing enforced fleet-wide) from a
                                // routine per-rule Unsupported classification.
                                emit_guardian_backend_heartbeat_tag(
                                    tags, guardian_->prefer_spark(), guardian_->spark_availability());
                            }
#if defined(_WIN32) || defined(__linux__) || defined(__APPLE__)
                            // DEX signal observer (every platform with a real observer —
                            // Windows / Linux / macOS; no-op platforms have none). Both tags are
                            // omitted when --dex-disable opted the agent out, so the server rollups
                            // reflect genuine state, not opt-outs. The agent has no /metrics
                            // endpoint; these heartbeat tags are the ONLY path that makes a
                            // silently-deaf observer and the fleet signal count observable (see
                            // AgentHealthStore::recompute_metrics).
                            if (!cfg_.dex_disable) {
                                const bool healthy =
                                    dex_health_ &&
                                    dex_health_->load(std::memory_order_relaxed);
                                tags["yuzu.dex_observer_armed"] = healthy ? "1" : "0";
                                tags["yuzu.dex_observed"] =
                                    std::to_string(dex_seq_.load(std::memory_order_relaxed));
                                metrics_.gauge("yuzu_agent_dex_observer_armed")
                                    .set(healthy ? 1.0 : 0.0);
                            }
#endif
                            // A4 fleet perf rollup: ship the device's current
                            // utilization as heartbeat tags — the agent has no
                            // /metrics endpoint, so this is the ONLY channel by
                            // which fleet perf gauges exist (see
                            // AgentHealthStore::recompute_metrics). Derived over
                            // the heartbeat interval from the same raw counter
                            // reads as the A3 breach detector. The first
                            // heartbeat of a session only baselines (invalid
                            // sample -> tags omitted; the server simply doesn't
                            // count this agent that cycle). Gated like the DEX
                            // observer: --dex-disable means no DEX telemetry of
                            // any kind. Windows and Linux each read their own
                            // counters here; macOS / other ship no perf tags yet.
                            if (!cfg_.dex_disable) {
#if defined(_WIN32)
                                const auto cur = win::read_perf_breach_counters();
                                const auto ps = win::derive_breach_sample(hb_prev_perf, cur);
                                hb_prev_perf = cur;
                                if (ps.valid) {
                                    tags["yuzu.perf_cpu_pct"] =
                                        std::format("{:.1f}", ps.cpu_pct);
                                    // Per-domain validity (gov review MEDIUM #1):
                                    // omit a sub-metric whose read failed rather
                                    // than ship a healthy 0% into the fleet gauge.
                                    if (ps.commit_valid)
                                        tags["yuzu.perf_commit_pct"] =
                                            std::format("{:.1f}", ps.commit_pct);
                                    if (ps.disk_valid)
                                        tags["yuzu.perf_disk_lat_ms"] =
                                            std::format("{:.2f}", ps.disk_lat_ms);
                                }
#elif defined(__linux__)
                                // Linux: read /proc here independently (mirrors the Windows
                                // path — the heartbeat does its own read, separate from the A3
                                // breach collector). CPU% needs a delta vs the prior heartbeat;
                                // commit% is instantaneous. The first heartbeat (or an unreadable
                                // /proc) only baselines, so the tag is omitted that cycle. No
                                // disk-latency metric on Linux yet — that perf source is a later
                                // slice.
                                const auto read_proc =
                                    [](const char* p) -> std::optional<std::string> {
                                    std::ifstream f(p);
                                    if (!f.is_open())
                                        return std::nullopt;
                                    const std::istreambuf_iterator<char> begin(f), end;
                                    std::string s(begin, end);
                                    return f.bad() ? std::nullopt : std::optional<std::string>(s);
                                };
                                // A throw here (bad_alloc reading /proc, std::format)
                                // must not unwind out of the heartbeat thread — that
                                // would stop heartbeats and read as the agent going
                                // offline. Swallow; the tag is just omitted this cycle.
                                try {
                                    if (const auto st = read_proc("/proc/stat")) {
                                        const lnx::CpuJiffies cur = lnx::parse_proc_stat(*st);
                                        if (const auto pct =
                                                lnx::cpu_busy_pct(hb_prev_cpu_lnx, cur))
                                            tags["yuzu.perf_cpu_pct"] =
                                                std::format("{:.1f}", *pct);
                                        hb_prev_cpu_lnx = cur;
                                    }
                                    // Gate commit% the SAME way the collector gates
                                    // perf.memory_pressure: under vm.overcommit_memory=1
                                    // ("always") CommitLimit is advisory and commit% reads
                                    // ~100% on healthy overcommit hosts — omit the tag so the
                                    // fleet gauge stays consistent with the breach signal
                                    // (shared lnx::overcommit_is_always, fjarvis review).
                                    const auto oc = read_proc("/proc/sys/vm/overcommit_memory");
                                    if (!(oc && lnx::overcommit_is_always(*oc)))
                                        if (const auto mi = read_proc("/proc/meminfo"))
                                            if (const auto pct = lnx::parse_commit_pct(*mi))
                                                tags["yuzu.perf_commit_pct"] =
                                                    std::format("{:.1f}", *pct);
                                } catch (...) {
                                    // omit perf tags this heartbeat
                                }
#endif
                            }

                            // Slice 4a: device network-quality facts — the ONLY
                            // channel for the fleet net gauges + /network
                            // Overview, same as the perf tags above. Gated like
                            // perf; this is aggregate device telemetry with NO
                            // per-destination data (that warehouse tier + its
                            // own opt-in are a later slice). Per-platform
                            // coverage: Linux ships RTT + retransmit +
                            // throughput (netlink TCP_INFO + /proc/net/dev);
                            // Windows ships throughput + retransmit
                            // (GetIfTable2 + GetTcpStatisticsEx, RTT deferred);
                            // macOS ships throughput only (NET_RT_IFLIST2,
                            // retransmit + RTT deferred); other platforms are
                            // all-invalid, so no tags ship (absent, not zero).
                            // Same containment as the perf block above: a throw
                            // here (bad_alloc sizing the routing buffer,
                            // std::format) must not unwind out of the heartbeat
                            // thread. Swallow; the tags are omitted this cycle.
                            if (!cfg_.dex_disable) try {
                                const auto net_cur = netq::read_net_counters();
                                const auto ns =
                                    netq::sample_net_quality(hb_prev_net, net_cur);
                                hb_prev_net = net_cur;
                                // TAG-KEY PIN: these literals MUST match
                                // network_perf_rules.hpp kNetTag* (the server
                                // parses by those constants) — a drift = silent
                                // zero-reporting; pinned by static_assert in
                                // tests/unit/server/test_network_perf_model.cpp.
                                if (ns.rtt_valid)
                                    tags["yuzu.net_rtt_p50_ms"] =
                                        std::format("{:.1f}", ns.rtt_p50_ms);
                                // Interval retransmit RATE (ΔΣretr/ΔΣsegs over a
                                // short window), NOT the absolute lifetime ratio
                                // (which is diluted to noise). Push this cycle's
                                // raw device sums, then ship the windowed delta
                                // once there are ≥2 readings (absent on the first
                                // of a session — never a fabricated 0).
                                // MEASUREMENT-FIRST: no `net_degraded` verdict —
                                // a hard threshold needs real-fleet baseline
                                // calibration (a later slice), so it is retired
                                // here rather than shipped loopback-calibrated.
                                if (ns.retrans_valid)
                                    hb_net_retrans_window.push(ns.retrans_total,
                                                               ns.segs_out_total);
                                if (auto rp = hb_net_retrans_window.rate_pct())
                                    tags["yuzu.net_retrans_pct"] =
                                        std::format("{:.2f}", *rp);
                                if (ns.throughput_valid)
                                    tags["yuzu.net_throughput_bps"] =
                                        std::format("{:.0f}", ns.throughput_bps);
                            } catch (...) {
                                // Omitted this cycle; next heartbeat retries.
                                // catch (...) like the perf/spark blocks: the
                                // heartbeat thread has no top-level handler, so
                                // anything narrower risks std::terminate.
                            }

                            // SparkEngine fleet telemetry (ADR-0021 Stage-2 rung 1 —
                            // OBSERVE-ONLY). Keys are pinned to
                            // server/core/src/spark_fleet_tags.hpp by
                            // tests/unit/server/test_spark_fleet_tags.cpp — a drift is
                            // silent zero-reporting. Counters ship SPARSELY (only when >0):
                            // fleet-scale, and every counter is 0 at rung 1 (no consumer
                            // armed), so a quiescent agent ships just the two always-present
                            // capability keys.
                            //
                            // The FOUR postures are DISTINGUISHABLE on the wire (see
                            // spark_heartbeat.hpp): RUNNING reports spark_running=1; FAILED and
                            // DISABLED both report spark_running=0 and are told apart by
                            // spark_disabled=1 on DISABLED only; ABSENT emits no spark keys at
                            // all (a stopped engine, and any pre-rung-1 agent).
                            // Emitting nothing on the failure path (the old behaviour) made
                            // a fleet-wide boot failure invisible — the exact condition
                            // rung 1 exists to detect (governance Gate-4 consistency/UP-10).
                            //
                            // try/catch: this runs on the heartbeat thread, whose callable
                            // has NO top-level handler — an escaping bad_alloc from the
                            // stats map or the tag strings would std::terminate the agent,
                            // on precisely the memory-exhausted host where the boot-time
                            // degrade guard was written to keep it alive. NOTHING may
                            // terminate the agent for an observe-only subsystem
                            // (governance Gate-4 UP-2).
                            try {
                                if (stop_requested_.load(std::memory_order_acquire)) {
                                    // SHUTTING DOWN — emit NOTHING (the ABSENT posture).
                                    //
                                    // Agent::stop() and run()'s ScopeExit both call
                                    // spark_engine_->stop(), and this thread can compose a
                                    // beat AFTER that. STOPPED is not FAILED: bucketing a
                                    // cleanly-stopping agent into yuzu_fleet_spark_failed{os}
                                    // — the ONE gauge documented "alert on it" — would page
                                    // on-call on every `systemctl restart` and every OTA cycle
                                    // with a fault that never happened (governance Gate-2
                                    // security). ABSENT is the honest wire state, and the
                                    // server reads absence as "did not report", never as 0.
                                    //
                                    // THIS GUARD IS DEFENCE IN DEPTH, AND THE SECOND LAYER IS
                                    // THE LOAD-BEARING ONE. An earlier version of this comment
                                    // claimed a stopped engine "would fall through to the
                                    // FAILED posture below" without this branch. It would not:
                                    // `else if (spark_engine_)` is taken, and
                                    // emit_spark_heartbeat_tags(running=false) early-returns
                                    // emitting nothing — ABSENT either way. Do not delete THAT
                                    // early-return on the strength of this guard, or this guard
                                    // on the strength of it; and do not "simplify" by trusting
                                    // a rationale (as this comment used to state one) that the
                                    // code does not actually implement.
                                } else if (cfg_.spark_disable) {
                                    emit_spark_absent_tags(tags, /*disabled=*/true);
                                } else if (spark_engine_) {
                                    emit_spark_heartbeat_tags(tags, spark_engine_->is_running(),
                                                              spark_engine_->stats(),
                                                              spark_engine_->stats_by_type());
                                } else {
                                    // Enabled, but boot-time instantiation threw.
                                    emit_spark_absent_tags(tags, /*disabled=*/false);
                                }
                            } catch (...) {
                                // Best-effort telemetry: drop this beat's spark tags rather
                                // than kill the agent. The server reads the absence as
                                // "did not report", never as 0.
                            }

                            // PR 10: attach pushed fleet snapshot if the
                            // pump produced something newer than what
                            // we last shipped. `last_attached_seq` is a
                            // per-heartbeat-thread local; the pump's
                            // monotonic counter is the source of truth.
                            // Empty attach when no new snapshot is
                            // available — keeps quiescent heartbeats at
                            // their pre-PR-10 size.
                            {
                                const auto cur_seq =
                                    latest_snapshot_seq_.load(std::memory_order_acquire);
                                if (cur_seq > last_attached_seq) {
                                    std::lock_guard lock(snapshot_mu_);
                                    if (!latest_snapshot_.empty()) {
                                        req.set_fleet_snapshot_json(latest_snapshot_);
                                        last_attached_seq = cur_seq;
                                    }
                                }
                            }

                            pb::HeartbeatResponse resp;
                            auto status = hb_stub->Heartbeat(&ctx, req, &resp);
                            if (!status.ok()) {
                                spdlog::warn("Heartbeat failed: {}", status.error_message());
                                // Orphan condition (#1894): the Subscribe stream is
                                // still up but the server rejects our session —
                                // NOT_FOUND (reaped as stale / forgotten across a
                                // server restart) or UNAUTHENTICATED (session auth
                                // expired, e.g. a mid-session cert rotation). The
                                // stream never breaks for these, so the Read-loop
                                // reconnect never fires and we would heartbeat a
                                // dead session forever. Other codes (UNAVAILABLE /
                                // DEADLINE_EXCEEDED) break the stream naturally and
                                // are already covered. Force a reconnect by
                                // cancelling the Subscribe stream.
                                const auto hb_code = status.error_code();
                                if (hb_code == grpc::StatusCode::NOT_FOUND ||
                                    hb_code == grpc::StatusCode::UNAUTHENTICATED) {
                                    // A successful Register resets reconnect_count
                                    // (the normal backoff), so without a damper here
                                    // a server that reaps every fresh session would
                                    // drive a fleet-wide register→beat→reject→
                                    // register storm (governance UP-1). Apply an
                                    // escalating, capped, cancellable cooldown keyed
                                    // on forced_rereg_streak_ (a member, so it
                                    // survives the reconnect; reset on a healthy
                                    // beat below).
                                    constexpr auto kBase = std::chrono::seconds{2};
                                    constexpr auto kCap = std::chrono::seconds{300};
                                    // Cap the counter itself at 8 (not just the
                                    // shift) so it can never overflow to a negative
                                    // shift over a very long-lived orphan; streak 8
                                    // already pins the cooldown at kCap. Serialized
                                    // heartbeat threads → load/store is race-free.
                                    const int streak = forced_rereg_streak_.load(
                                        std::memory_order_acquire);
                                    forced_rereg_streak_.store(std::min(streak + 1, 8),
                                                               std::memory_order_release);
                                    const auto cooldown =
                                        std::min(kBase * (1 << std::min(streak, 8)), kCap);
                                    spdlog::warn("Server rejected our session ({}) — "
                                                 "re-registering after {}s (#1894)",
                                                 status.error_message(),
                                                 static_cast<long long>(cooldown.count()));
                                    for (auto left = cooldown;
                                         left.count() > 0 && !should_stop();) {
                                        const auto slice = std::min<std::chrono::seconds>(
                                            left, std::chrono::seconds{5});
                                        std::this_thread::sleep_for(slice);
                                        left -= slice;
                                    }
                                    if (!should_stop())
                                        cancel_ctx(subscribe_ctx_); // owned by run()'s frame
                                    break; // this connection is done; a fresh
                                           // heartbeat thread spawns on reconnect
                                }
                            } else {
                                spdlog::debug("Heartbeat acknowledged (uptime={}s)", uptime);
                                // Healthy beat — session is valid again; clear the
                                // storm damper so a later isolated rejection starts
                                // from the base cooldown (#1894).
                                forced_rereg_streak_.store(0, std::memory_order_release);
                            }
                        }
                        // No store(nullptr) here: the per-iteration CtxSlot already retracted
                        // it under ctx_mu_ on every way out of the loop body.
                        spdlog::info("Heartbeat thread stopped");
                    });
                }

                // 4d. Spawn the concurrency-claim keepalive thread (CHAOS-TTL-1,
                // PR #3784 fix round). One central, bounded ticker — NOT one
                // thread per command — that sends a periodic empty `RUNNING`
                // response for every command still in `in_flight_ids_`
                // (populated from queue-accept to terminal write, see
                // `record_command_terminal`'s erase). This is independent of
                // plugin cooperation: neither a plugin's own output volume
                // (`CommandContextImpl::flush_output_locked`'s 64KB threshold)
                // nor its `report_progress()` calls (a local no-op) are a
                // reliable mid-execution liveness signal, so a quiet, long-
                // running, mutating action like `script_exec.*` could otherwise
                // have its server-side `per-device` concurrency claim
                // (ADR-1007) force-released by the reconciler's TTL while
                // still genuinely executing, admitting a duplicate dispatch
                // that repeats a non-idempotent mutation. The interval is
                // sparse and well under the server's one-hour TTL default —
                // this is a liveness ping, not a progress channel, and its
                // wire cost must stay negligible even for a fleet with
                // thousands of concurrently in-flight commands.
                {
                    keepalive_stop_.store(false, std::memory_order_release);
                    keepalive_thread_ = std::thread([this, stream]() {
                        constexpr auto kKeepaliveInterval = std::chrono::seconds(300); // 5 min
                        auto should_stop = [this]() {
                            return stop_requested_.load(std::memory_order_acquire) ||
                                   keepalive_stop_.load(std::memory_order_acquire);
                        };
                        spdlog::info("Concurrency-claim keepalive thread started (interval={}s)",
                                     kKeepaliveInterval.count());
                        while (!should_stop()) {
                            auto remaining = kKeepaliveInterval;
                            while (remaining.count() > 0 && !should_stop()) {
                                auto step = std::min(remaining, std::chrono::seconds{5});
                                std::this_thread::sleep_for(step);
                                remaining -= step;
                            }
                            if (should_stop())
                                break;
                            // Snapshot under the lock, write outside it — mirrors
                            // every other stream_write_mu_ site in this file, and
                            // keeps in_flight_mu_ held only as long as the copy.
                            std::vector<std::string> ids;
                            {
                                std::lock_guard lock(in_flight_mu_);
                                ids.assign(in_flight_ids_.begin(), in_flight_ids_.end());
                            }
                            for (const auto& id : ids) {
                                pb::CommandResponse ping;
                                ping.set_command_id(id);
                                ping.set_status(pb::CommandResponse::RUNNING);
                                // Recognized sentinel, matching the existing
                                // __timing__ frame's own intercept pattern —
                                // the server's agent_service_impl.cpp special-
                                // cases this exact output on both the direct
                                // and gateway-streamed RUNNING paths so it
                                // renews the concurrency claim without landing
                                // as a response row / SSE output line.
                                ping.set_output("__keepalive__");
                                auto epoch = std::chrono::duration_cast<std::chrono::milliseconds>(
                                                 std::chrono::system_clock::now().time_since_epoch())
                                                 .count();
                                ping.mutable_sent_at()->set_millis_epoch(epoch);
                                std::lock_guard lock(stream_write_mu_);
                                // Best-effort: a Write failure here means the
                                // stream is already dead, which the read loop
                                // and reconnect logic handle independently —
                                // this thread does not itself drive reconnect.
                                stream->Write(ping, grpc::WriteOptions());
                            }
                        }
                        spdlog::info("Concurrency-claim keepalive thread stopped");
                    });
                }

                // cpp-safety BLOCKING (Gate re-review, this fix round): the manual
                // teardown below (stop+join keepalive_thread_) only runs on the
                // ORDINARY fall-through exit from this connection's scope. An
                // exception escaping anywhere between here and that teardown —
                // this file's own thread_pool_ re-creation try/catch a few lines
                // up exists BECAUSE this exact region has thrown in production
                // under host resource exhaustion, so this is not a hypothetical
                // path — unwinds straight past the manual teardown code (it is
                // plain sequential statements, not itself exception-safe) to the
                // destructors below: `sub_slot`'s ~CtxSlot only retracts
                // subscribe_ctx_ to null, it does NOT cancel `sub_ctx`, which is
                // then destroyed while `keepalive_thread_` may still be inside (or
                // about to enter) `stream->Write()` — a uses-after-free on
                // `sub_ctx` through gRPC's internal context reference, exactly the
                // class `CtxSlot`'s own doc comment three lines up (1955) warns
                // about for a DIFFERENT ordering mistake.
                //
                // Declared AFTER `stream`/`sub_slot`/`sub_ctx` (all above), so
                // C++'s reverse-destruction-order guarantee makes this the FIRST
                // thing to run during unwind — stopping and joining
                // keepalive_thread_ before it, guaranteeing the thread is done
                // touching `stream`/`sub_ctx` before either becomes invalid.
                //
                // cpp-safety BLOCKING (Gate 3 re-review, this fix round): on the
                // exception-unwind path specifically — as opposed to the two
                // ordinary manual-teardown join sites below/in
                // quiesce_run_workers(), both reached only AFTER stream->Read()
                // has already returned false, proving the connection dead — the
                // exception can land at ANY point in this scope, including while
                // the stream is alive but merely STALLED (gateway up, not
                // draining). If keepalive_thread_ is at that moment blocked
                // inside stream->Write(), a bare join() below blocks forever
                // with no rescue. This is the EXACT hazard class stop() already
                // treats as BLOCKING for guardian_sink_stream_'s writer (see
                // stop()'s own comment a few hundred lines down): a synchronous
                // Write() can wedge on a stalled-but-not-dead stream, and the
                // fix there is TryCancel BEFORE the drain/join, not after.
                // subscribe_ctx_ is still published here (sub_slot retracts it
                // only after this guard runs), so the same rescue is available
                // — cancel it first, same as stop() does, before joining.
                ScopeExit keepalive_unwind_guard{[this]() {
                    keepalive_stop_.store(true, std::memory_order_release);
                    cancel_ctx(subscribe_ctx_);
                    if (keepalive_thread_.joinable())
                        keepalive_thread_.join();
                }};

                // 5. Read commands from server and dispatch to plugins.
                // Command replay protection is now durable (command_dedup_, HA
                // WS-0): it survives reconnect AND restart, so there is no
                // per-connection reset here.
                bool update_verified = false;
                pb::CommandRequest cmd;
                while (stream->Read(&cmd)) {
                    if (stop_requested_.load(std::memory_order_acquire))
                        break;

                    // True only when THIS delivery's claim() succeeded — gates the
                    // queue-full release so it never deletes a concurrent owner's row.
                    bool claimed_here = false;

                    // Command replay protection (HA WS-0, ADR-2002). claim() is the
                    // atomic first-writer-wins gate: on a duplicate we REPLAY the
                    // original terminal outcome (never a bare REJECTED that would
                    // lose the first result), or answer RUNNING while the first
                    // attempt is still in flight — we never re-execute, because
                    // re-running a destructive command is the failure the whole HA
                    // design forbids. An empty command_id cannot be keyed and
                    // proceeds unprotected; a store failure (Error) degrades to no
                    // dedup for that one command, both falling through to dispatch.
                    // The Guardian __guard__ side channel (handled below) is NOT
                    // normal command execution — it carries no dedupable side
                    // effect, must stay free to re-run (e.g. reconcile), and its
                    // branch resolves via its own write + continue, so claiming it
                    // would leak an unresolved in-flight record AND wrongly answer a
                    // re-sent control command RUNNING. It is the ONLY dispatch that
                    // bypasses the claim: gating on the literal (not the whole
                    // reserved-name set) keeps durable idempotency the SAFE DEFAULT
                    // for any future reserved-name command — a future __update__ OTA
                    // path is deduplicated unless it, too, opts out here.
                    if (cmd.command_id().empty()) {
                        spdlog::warn("Received command with empty command_id — replay "
                                     "protection cannot apply");
                    } else if (command_dedup_ && cmd.plugin() != "__guard__") {
                        auto claim = command_dedup_->claim(cmd.command_id());
                        // Own the in-flight record ONLY when WE claimed it — a
                        // fall-through on Error (fail-open) must NOT later release a
                        // row a concurrent first delivery owns.
                        claimed_here = (claim.status == ClaimStatus::Claimed);
                        if (claim.status == ClaimStatus::Error)
                            metrics_.counter("yuzu_agent_dedup_claim_errors_total").increment();
                        if (claim.status == ClaimStatus::Duplicate) {
                            pb::CommandResponse dup_resp;
                            bool replayed = false;
                            if (claim.state == DedupState::Terminal) {
                                pb::CommandResponse stored;
                                if (stored.ParseFromString(claim.response)) {
                                    dup_resp = std::move(stored);
                                    auto now_ms =
                                        std::chrono::duration_cast<std::chrono::milliseconds>(
                                            std::chrono::system_clock::now().time_since_epoch())
                                            .count();
                                    dup_resp.mutable_sent_at()->set_millis_epoch(now_ms);
                                    replayed = true;
                                    metrics_.counter("yuzu_agent_dedup_replays_total").increment();
                                    spdlog::info("Replay of command {} — returning stored "
                                                 "terminal outcome",
                                                 cmd.command_id());
                                } else {
                                    spdlog::error("Stored terminal outcome for {} failed to "
                                                  "parse — answering RUNNING",
                                                  cmd.command_id());
                                }
                            }
                            if (!replayed) {
                                dup_resp.set_command_id(cmd.command_id());
                                dup_resp.set_status(pb::CommandResponse::RUNNING);
                                // Plain progress text — NOT a parsed sentinel (no
                                // "__x__|" contract); nothing consumes this string.
                                dup_resp.set_output("duplicate command still in flight");
                                if (claim.state == DedupState::InFlight)
                                    spdlog::warn("Duplicate command {} still in flight — "
                                                 "answering RUNNING",
                                                 cmd.command_id());
                            }
                            std::lock_guard lock(stream_write_mu_);
                            stream->Write(dup_resp, grpc::WriteOptions());
                            continue;
                        }
                        // Claimed / Error both fall through: Claimed owns the
                        // in-flight record (resolved at a terminal write below or
                        // released if the dispatch queue is full); Error runs
                        // undeduplicated for this one command.
                    }

                    // Write health marker after first successful read (OTA rollback guard)
                    if (!update_verified) {
                        update_verified = true;
                        auto marker =
                            current_executable_path().parent_path() / ".yuzu-update-verified";
                        std::ofstream{marker} << "ok";
                        spdlog::debug("Wrote update verification marker: {}", marker.string());
                    }

                    spdlog::info("Received command: plugin={}, action={}, id={}", cmd.plugin(),
                                 cmd.action(), cmd.command_id());

                    // Reserved-name dispatch — must run before the plugin match
                    // loop so a third-party plugin cannot shadow Guardian (the
                    // load-time check in plugin_loader.cpp also rejects reserved
                    // names, but defence-in-depth keeps both halves explicit).
                    // See docs/yuzu-guardian-design-v1.1.md §7.2.
                    if (cmd.plugin() == "__guard__") {
                        pb::CommandResponse resp;
                        resp.set_command_id(cmd.command_id());
                        auto epoch_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                                            std::chrono::system_clock::now().time_since_epoch())
                                            .count();
                        resp.mutable_sent_at()->set_millis_epoch(epoch_ms);
                        if (!guardian_) {
                            resp.set_status(pb::CommandResponse::FAILURE);
                            resp.set_exit_code(1);
                            resp.set_output("guardian engine not initialised");
                        } else {
                            // Thread-boundary backstop (#2037 class): guardian_->dispatch
                            // (apply_rules teardown/reconcile) allocates and can throw a
                            // bad_alloc under memory pressure. This runs on the run() thread,
                            // which has no enclosing catch, so an escape aborts the whole
                            // agent daemon. apply_rules firewalls internally, but keep a
                            // defensive boundary here so ANY guardian command that throws
                            // degrades to a FAILURE response instead of a crash (Gate 4 UP-1).
                            try {
                                auto dr = guardian_->dispatch(cmd);
                                resp.set_status(dr.exit_code == 0 ? pb::CommandResponse::SUCCESS
                                                                  : pb::CommandResponse::FAILURE);
                                resp.set_exit_code(dr.exit_code);
                                resp.set_output(std::move(dr.output));
                            } catch (...) {
                                resp.set_status(pb::CommandResponse::FAILURE);
                                resp.set_exit_code(1);
                                try {
                                    resp.set_output("guardian dispatch threw (firewalled)");
                                } catch (...) {
                                }
                            }
                        }
                        // Stamp the response so the server routes it via the Guardian
                        // ingest branch (plugin=="__guard__") and skips the response
                        // store / executions drawer. action mirrors the request.
                        resp.set_plugin("__guard__");
                        resp.set_action(cmd.action());
                        metrics_
                            .counter("yuzu_agent_commands_executed_total",
                                     {{"plugin", "__guard__"}})
                            .increment();
                        std::lock_guard lock(stream_write_mu_);
                        stream->Write(resp, grpc::WriteOptions());
                        continue;
                    }

                    // Reserved-name dispatch #2: `__sync__.now` — operator-triggered
                    // sync-on-demand (ADR-0016 update). Arms the daily-sync scheduler
                    // to run one source (or all) in its next pass and breaks its
                    // sleep, so the report lands in seconds instead of ≤24h. Unlike
                    // __guard__ this command IS dedup-claimed (the claim above exempts
                    // only the literal "__guard__"), so its terminal MUST be recorded
                    // before the write or a server re-send answers RUNNING forever.
                    if (cmd.plugin() == "__sync__") {
                        pb::CommandResponse resp;
                        resp.set_command_id(cmd.command_id());
                        auto epoch_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                                            std::chrono::system_clock::now().time_since_epoch())
                                            .count();
                        resp.mutable_sent_at()->set_millis_epoch(epoch_ms);
                        std::string source{SyncScheduler::kAllSources};
                        if (auto it = cmd.parameters().find("source");
                            it != cmd.parameters().end() && !it->second.empty())
                            source = it->second;
                        std::shared_ptr<SyncScheduler> sched;
                        {
                            std::lock_guard<std::mutex> lk(sync_sched_mu_);
                            sched = sync_scheduler_;
                        }
                        // Decision logic (unknown action / no scheduler / unknown
                        // source / success) lives in sync_now_decision.hpp — a pure
                        // free function unit-tested without gRPC or a live command
                        // loop (tests/unit/test_agent_sync_command.cpp). Everything
                        // else about this command (the metrics counter below,
                        // record_command_terminal-before-write, the stream->Write)
                        // stays here, unchanged.
                        auto decision = decide_sync_now(cmd.action(), source, cfg_.inventory_disable,
                                                         sched.get());
                        resp.set_status(decision.status == SyncNowDecision::Status::Success
                                             ? pb::CommandResponse::SUCCESS
                                             : pb::CommandResponse::FAILURE);
                        resp.set_exit_code(decision.exit_code);
                        resp.set_output(std::move(decision.output));
                        if (decision.status == SyncNowDecision::Status::Success)
                            sync_wake_.store(true, std::memory_order_release);
                        resp.set_plugin("__sync__");
                        resp.set_action(cmd.action());
                        metrics_
                            .counter("yuzu_agent_commands_executed_total",
                                     {{"plugin", "__sync__"}})
                            .increment();
                        record_command_terminal(cmd.command_id(), resp);
                        std::lock_guard lock(stream_write_mu_);
                        stream->Write(resp, grpc::WriteOptions());
                        continue;
                    }

                    // Find the matching plugin
                    const YuzuPluginDescriptor* target = nullptr;
                    for (const auto& handle : plugins_) {
                        if (cmd.plugin() == handle.descriptor()->name) {
                            target = handle.descriptor();
                            break;
                        }
                    }

                    if (!target) {
                        spdlog::warn("No plugin '{}' found", cmd.plugin());
                        pb::CommandResponse resp;
                        resp.set_command_id(cmd.command_id());
                        resp.set_status(pb::CommandResponse::REJECTED);
                        resp.set_output("plugin not found: " + cmd.plugin());
                        // Deterministic terminal for a claimed command (the plugin
                        // set is fixed at boot): memoise so a redelivery replays
                        // this REJECTED rather than re-running the claim path.
                        record_command_terminal(cmd.command_id(), resp);
                        std::lock_guard lock(stream_write_mu_);
                        stream->Write(resp, grpc::WriteOptions());
                        continue;
                    }

                    // CHAOS-TTL-1: mark this command in-flight BEFORE submit — the
                    // keepalive thread must be able to see a command that is still
                    // sitting in the bounded queue, not just one already inside
                    // execute(). Removed at the single terminal-write chokepoint,
                    // record_command_terminal, on every exit path (success/
                    // failure/rejection/queue-full/dispatch-exception) — see that
                    // function for the erase. An empty command_id is never tracked
                    // (nothing to key a keepalive ping on; the dedup path already
                    // treats it as unprotected).
                    if (!cmd.command_id().empty()) {
                        std::lock_guard lock(in_flight_mu_);
                        in_flight_ids_.insert(cmd.command_id());
                    }

                    // Dispatch execute() via bounded thread pool.
                    // chargen_start blocks until chargen_stop sets the atomic flag,
                    // so concurrent dispatch is required.
                    // Each task captures the shared_ptr to guarantee the stream
                    // outlives all writers (fixes use-after-free risk from #66).
                    bool submitted = thread_pool_->submit([this, target, cmd, stream]() {
                        // Outer exception firewall (#2037). The ThreadPool worker
                        // already contains any escaped exception so the agent
                        // process survives; catching here additionally lets the
                        // server receive a terminal FAILURE instead of waiting on
                        // its own timeout for a command whose dispatch task threw
                        // outside the plugin execute() guard.
                        try {
                            execute_command_task(target, cmd, stream);
                        } catch (const std::exception& e) {
                            spdlog::error("Command {} dispatch failed outside plugin execute: {}",
                                          cmd.command_id(), e.what());
                            send_dispatch_failure(stream, cmd.command_id(),
                                                  std::string("agent dispatch error: ") + e.what());
                        } catch (...) {
                            spdlog::error("Command {} dispatch failed outside plugin execute "
                                          "(non-std exception)",
                                          cmd.command_id());
                            send_dispatch_failure(stream, cmd.command_id(),
                                                  "agent dispatch error: non-std exception");
                        }
                    });

                    if (!submitted) {
                        spdlog::warn("Thread pool queue full — rejecting command {}",
                                     cmd.command_id());
                        // Submission never happened, so record_command_terminal's
                        // own erase (below) is never reached for this id — remove
                        // it here instead. Gate 3 architect/cpp-safety review
                        // (this fix round): in_flight_ids_ has NO reconnect-time
                        // reset (it deliberately survives reconnect, matching
                        // command_dedup_'s own durability — a corrected earlier
                        // draft of this comment claimed otherwise), so skipping
                        // this erase would leak the entry PERMANENTLY, until
                        // process exit — a real, not cosmetic, reason this erase
                        // is required.
                        if (!cmd.command_id().empty()) {
                            std::lock_guard lock(in_flight_mu_);
                            in_flight_ids_.erase(cmd.command_id());
                        }
                        pb::CommandResponse reject_resp;
                        reject_resp.set_command_id(cmd.command_id());
                        reject_resp.set_status(pb::CommandResponse::REJECTED);
                        reject_resp.set_output("agent overloaded: command queue full");
                        // Queue-full is TRANSIENT and the command never executed —
                        // release OUR claim so a redelivery can be attempted (never
                        // memoise a terminal outcome). Only when we actually claimed
                        // here: releasing otherwise could delete a concurrent first
                        // delivery's in-flight row. A failed release leaks the claim
                        // (RUNNING-forever), so count it.
                        if (command_dedup_ && claimed_here &&
                            command_dedup_->release(cmd.command_id()) == ReleaseOutcome::Error)
                            metrics_.counter("yuzu_agent_dedup_release_errors_total").increment();
                        std::lock_guard lock(stream_write_mu_);
                        stream->Write(reject_resp, grpc::WriteOptions());
                    }
                }

                // No store(nullptr) here: `sub_slot` retracts subscribe_ctx_ under ctx_mu_ when
                // this scope ends, and it also covers the `continue` paths above that this
                // hand-written clear never did.

                // Detach the Guardian event-sink from this (now broken) stream BEFORE
                // it is torn down (H4 / #1209). Taking stream_write_mu_ waits for any
                // in-flight sink Write to finish, then nulls the holder so a send firing
                // during teardown drops the event instead of writing to a cancelled
                // stream. #4783: that send no longer runs on a guard's own thread - it
                // is legacy_sink_executor_'s own detached worker (or the DEX observer's
                // still-synchronous OS-callback thread) that can be mid-Write here, never
                // a guard. Guards keep running across the reconnect; the next iteration
                // republishes the new stream and the heartbeat reconcile (M5) catches up
                // any generation missed while the link was down.
                {
                    std::lock_guard lock(stream_write_mu_);
                    guardian_sink_stream_.reset();
                }

                // Destroy thread pool BEFORE stream goes out of scope — this drains
                // the queue, waits for in-flight tasks, and joins all worker threads,
                // ensuring no task holds a dangling stream pointer.
                thread_pool_.reset();

                // Stop and join the OTA update thread
                if (auto u = updater()) {
                    u->stop(); // local copy keeps it alive even if run() swaps the slot
                }
                if (update_thread_.joinable()) {
                    update_thread_.join();
                }

                // Signal heartbeat thread to exit and cancel any in-flight RPC.
                // cancel_ctx() holds ctx_mu_ across the load+TryCancel, so the heartbeat
                // thread's ~CtxSlot cannot retire `ctx` underneath us — this fires on every
                // TRANSIENT RECONNECT, not just shutdown, so it was the most-executed of the
                // four UAF sites the first ctx_mu_ patch missed. The lock is released before
                // the join below (never hold ctx_mu_ across a join).
                heartbeat_stop_.store(true, std::memory_order_release);
                cancel_ctx(heartbeat_ctx_);
                if (heartbeat_thread_.joinable()) {
                    heartbeat_thread_.join();
                }
                // Concurrency-claim keepalive thread (CHAOS-TTL-1) is
                // per-connection like heartbeat — it captures THIS stream by
                // shared_ptr and must stop before the reconnect loop opens a
                // new one. This site is reached only AFTER `stream->Read()`
                // above returned false, i.e. the connection is already known
                // dead (not merely stalled) — a Write() on it fails fast
                // rather than blocking (contrast `stop()`'s own comment on
                // `guardian_sink_stream_`, which documents a synchronous
                // Write() blocking on a STALLED-but-not-dead stream; that
                // hazard does not apply here because Read()'s own return
                // already proves the stream is dead). No dedicated
                // ClientContext of its own to cancel either way; its
                // should_stop() poll (5s steps) bounds the join regardless.
                // The exception-escape gap this reasoning does NOT cover —
                // an exception unwinding straight past this manual teardown
                // block, before Read() has necessarily returned false — is
                // handled separately by `keepalive_unwind_guard` below,
                // declared after `sub_slot`/`sub_ctx` so it destructs first
                // on any unwind.
                keepalive_stop_.store(true, std::memory_order_release);
                if (keepalive_thread_.joinable()) {
                    keepalive_thread_.join();
                }
                // Daily-sync thread is per-connection (like heartbeat): stop +
                // join it on disconnect; its state persists in kv_store_.
                sync_stop_.store(true, std::memory_order_release);
                cancel_ctx(sync_ctx_); // unblock an in-flight ReportInventory (mirrors heartbeat)
                if (sync_thread_.joinable()) {
                    sync_thread_.join();
                }
                // PR 10: the snapshot pump is intentionally NOT joined on a
                // transient (non-final) disconnect. It is a Run()-lifetime
                // thread that survives reconnects, so the heartbeat thread of
                // the next connection cycle finds a warm latest_snapshot_ and
                // ships it immediately. The pump is joined only on FINAL
                // shutdown — by quiesce_run_workers() in the stop_requested_
                // branch just below (and by the Run()-exit ScopeExit backstop).

                // Only shutdown plugins on final exit — keep them loaded for reconnect
                if (stop_requested_.load(std::memory_order_acquire)) {
                    // #1420 — the snapshot pump borrows a descriptor into
                    // `plugins_`; join it (and the other Run() workers) BEFORE
                    // shutting the plugins down and clearing the vector below,
                    // otherwise an in-flight pump cycle dispatches into freed
                    // plugin state (use-after-free / abort on a clean exit).
                    // This call's SOLE purpose is that ordering relative to
                    // plugins_.clear(); the Run()-exit ScopeExit is the backstop
                    // for every early-return/exception exit, and re-invoking the
                    // helper there is a joinable()-guarded no-op.
                    quiesce_run_workers();
                    // Stop the TRIGGER ENGINE before the plugin shutdown loop, for the same
                    // reason the ScopeExit does (:766) — its workers dispatch into plugins_
                    // from their own threads, so shutting plugins down (and clearing the
                    // vector below) under running workers is a dispatch-into-dlclose race.
                    // The ScopeExit's own trigger_engine_.stop() runs too LATE for this
                    // branch (after the plugin loop below has already run) and re-invoking
                    // it there is an idempotent no-op. PRE-EXISTING on dev, byte-identical —
                    // fixed here because this branch's charter is exactly this shutdown
                    // crash class. (adversarial review K3/C-P2-2 — found by one external
                    // reviewer, adopted by the other on cross-examination.)
                    trigger_engine_.stop();
                    for (auto& handle : plugins_) {
                        if (handle.descriptor()->shutdown) {
                            auto it = per_plugin_ctx_.find(handle.descriptor()->name);
                            auto* ctx_ptr =
                                (it != per_plugin_ctx_.end())
                                    ? reinterpret_cast<YuzuPluginContext*>(it->second.get())
                                    : reinterpret_cast<YuzuPluginContext*>(&plugin_ctx_);
                            handle.descriptor()->shutdown(ctx_ptr);
                        }
                    }
                    plugins_.clear(); // Prevent ScopeExit from calling shutdown again
                }

                spdlog::info("Subscribe stream ended");

                if (!stop_requested_.load(std::memory_order_acquire)) {
                    // RE-CREATE THE POOL ONLY IF WE ARE ACTUALLY RECONNECTING, AND INSIDE A TRY.
                    //
                    // Two defects lived on the old unconditional line, both of them mine:
                    //
                    // 1. It ran on the SHUTDOWN path too. Every SIGTERM spawned 4-32 threads
                    //    that were never used and were joined seconds later by run()'s ScopeExit
                    //    — pure added teardown latency, in the very change whose purpose is to
                    //    cut teardown latency.
                    //
                    // 2. It was inside NO try. The exception-safe ThreadPool ctor earlier in this
                    //    branch converted thread exhaustion from a terminate-in-~vector into a
                    //    THROW — and the boot site (see the ctor at the top of run()) catches it
                    //    and degrades to startup_failed_. This site did not. Under EAGAIN, or a
                    //    docker `--pids-limit`, the throw escaped run(), and main.cpp calls
                    //    `agent->run()` bare — so it was std::terminate WITHOUT UNWINDING: the
                    //    ScopeExit never ran, plugins never got shutdown(), the SQLite stores
                    //    never closed, the watcher thread was never joined. A pid-pressure event
                    //    took the endpoint out hard, and systemd's Restart= then hot-looped it.
                    //
                    // Degrade the way the boot site does: stop, and let the supervisor restart us
                    // cleanly. (governance: cpp-safety BLOCKING, sre OR-5, happy-path F1.)
                    try {
                        thread_pool_ =
                            std::make_unique<ThreadPool>(std::thread::hardware_concurrency());
                    } catch (const std::exception& e) {
                        spdlog::critical("could not re-create the command dispatch thread pool on "
                                         "reconnect ({}) — the host is out of threads. Stopping "
                                         "cleanly rather than aborting.",
                                         e.what());
                        // AND MARK IT A FAILURE, so the exit code says "I could not continue"
                        // rather than "I was asked to stop".
                        //
                        // BE PRECISE ABOUT WHAT THIS BUYS, because the first version of this
                        // comment overstated it and was itself a false claim: the Windows SCM does
                        // NOT read this as a clean stop today — service_win.cpp already reports
                        // specific-error 2 for a run() that returns unsolicited, and the failure
                        // actions flag is set, so recovery ALREADY fires there. Likewise
                        // `Restart=always` (the shipped systemd unit) and compose's
                        // `restart: unless-stopped` both restart on exit 0 anyway.
                        // What this actually fixes: a `Restart=on-failure` unit (or a k8s
                        // OnFailure policy), which is the posture a customer with their own unit
                        // file is most likely to use, and which would NEVER have restarted the
                        // agent; and it makes the failure DISTINGUISHABLE from an operator stop in
                        // any log or monitor that reads the exit code.
                        // (governance: unhappy-path B / B-6 — the second of which caught the first
                        // version of this very comment asserting something the tree contradicts.)
                        startup_failed_ = true;
                        stop_requested_.store(true, std::memory_order_release);
                        yuzu::agent::request_subprocess_cancel(true);
                        break;
                    } catch (...) {
                        spdlog::critical("could not re-create the command dispatch thread pool on "
                                         "reconnect (non-std exception) — stopping cleanly rather "
                                         "than aborting.");
                        // AND MARK IT A FAILURE, so the exit code says "I could not continue"
                        // rather than "I was asked to stop".
                        //
                        // BE PRECISE ABOUT WHAT THIS BUYS, because the first version of this
                        // comment overstated it and was itself a false claim: the Windows SCM does
                        // NOT read this as a clean stop today — service_win.cpp already reports
                        // specific-error 2 for a run() that returns unsolicited, and the failure
                        // actions flag is set, so recovery ALREADY fires there. Likewise
                        // `Restart=always` (the shipped systemd unit) and compose's
                        // `restart: unless-stopped` both restart on exit 0 anyway.
                        // What this actually fixes: a `Restart=on-failure` unit (or a k8s
                        // OnFailure policy), which is the posture a customer with their own unit
                        // file is most likely to use, and which would NEVER have restarted the
                        // agent; and it makes the failure DISTINGUISHABLE from an operator stop in
                        // any log or monitor that reads the exit code.
                        // (governance: unhappy-path B / B-6 — the second of which caught the first
                        // version of this very comment asserting something the tree contradicts.)
                        startup_failed_ = true;
                        stop_requested_.store(true, std::memory_order_release);
                        yuzu::agent::request_subprocess_cancel(true);
                        break;
                    }

                    ++reconnect_count;
                    metrics_.counter("yuzu_agent_reconnections_total").increment();
                    spdlog::warn("Connection lost — will attempt reconnect");
                    continue; // Back to reconnect loop
                }
            }
            break; // stop_requested
        }          // end while (reconnect loop)

        // #1420 / #1434: the snapshot pump, heartbeat, and OTA-updater threads
        // are quiesced and joined by quiesce_run_workers() — invoked from the
        // final-shutdown teardown above (before plugins_.clear(), so a pump
        // cycle can't dispatch into freed plugin state) and, as the universal
        // backstop for every exit path including the early-return rejections,
        // from the Run()-exit ScopeExit `cleanup`. No separate post-loop join
        // is needed here.
    }

    void stop() noexcept override {
        // #2233 item 3 ("S+"): armed BEFORE the stop_mu_ wait below, so a caller queued
        // behind a wedged first caller is bounded by its OWN deadline too, not just the
        // executing caller's. See shutdown_deadline_guard.hpp for the full rationale.
        yuzu::agent::ShutdownDeadlineGuard watchdog{kShutdownDeadlineGrace};
        // Serializes this whole method — see stop_mu_'s own comment for why (the OTA
        // self-stop thread takes no other lock at all, and dex_observer_'s stop() is not
        // safe against concurrent entry). A second concurrent/later caller returns here
        // once the first has completed, rather than re-running any of the below.
        std::lock_guard<std::mutex> stop_lk(stop_mu_);
        if (stop_completed_)
            return;
        stop_requested_.store(true, std::memory_order_release);
        yuzu::agent::request_subprocess_cancel(true);
        heartbeat_stop_.store(true, std::memory_order_release);
        // Cancel the Subscribe stream FIRST — best-effort, not a guaranteed completion
        // time (#4783). Until #4783, the Guardian drift workers AND the DEX observer
        // both emitted through emit_guardian_event()'s synchronous gRPC Write() on
        // their OWN thread, so an in-flight Write during a stalled-but-not-dead
        // stream (gateway up, not draining) could wedge guardian_->stop()'s /
        // dex_observer_->stop()'s unbounded drain forever unless cancelled first
        // (cpp-safety BLOCKING). #4783 routes the Guardian drift-sink path through
        // GuardianLegacySinkExecutor's detached worker instead, so guardian_->stop()
        // below now joins the guard threads promptly — they never enter Write()
        // themselves, they only enqueue — and only stops the executor from admitting
        // NEW sends; it does not join whatever send is already in flight. Cancelling
        // the stream FIRST is still load-bearing for two reasons: (1) the DEX
        // observer still emits SYNCHRONOUSLY on its own OS-callback thread, and
        // dex_observer_->stop() below still drains that with an unbounded wait, so
        // cancelling only afterward would reopen the exact same wedge for DEX signals
        // alone; and (2) it is a best-effort means of unblocking a legacy-sink send
        // that is already mid-stall on the executor's detached worker, giving
        // active_io_workers() a better chance of reaching 0 before OrphanExitGuard's
        // grace expires — NOT a guaranteed bound: if the cancelled Write does not
        // return promptly, the worker stays counted and OrphanExitGuard hard_exit()s
        // after kOrphanDrainGrace instead of wedging. Either way, TryCancel does NOT
        // tear the stream down — the stream holder and stream_write_mu_ are members
        // destroyed AFTER guardian_/dex_observer_, so they stay live through both
        // drains and emit_guardian_event's null-check under the lock remains
        // UAF-safe.
        // Cancel under ctx_mu_ — see the member's note. The context is a STACK object owned
        // by run()'s reconnect frame, and this runs on the watcher / SCM thread.
        cancel_ctx(subscribe_ctx_);
        if (guardian_)
            guardian_->stop();
        if (dex_observer_)
            dex_observer_->stop();
        // Gate on the boot latch BEFORE touching the pointer. This runs on the watcher /
        // SCM / console thread; run()'s boot block stores AND (on the degrade path) FREES
        // spark_engine_ until the latch flips — a bare `if (spark_engine_)` here raced
        // that window (TSan-confirmed via the randomized-SIGTERM fuzz at 101 ms).
        // Skipping spark pre-latch is safe: run()'s ScopeExit stops the engine on every
        // run() exit, on run()'s own thread, with NO boot-latch gate of its own (adversarial
        // review Kimi K1: an earlier revision of this PR gave the ScopeExit's call the same
        // gate via a shared once-only-flag method, which broke this exact safety net - a
        // stop() that raced the boot window would set the flag without ever having called
        // spark_engine_->stop(), permanently skipping the ScopeExit's retry too. Reverted -
        // each caller keeps its own, deliberately different, gating). Acquire pairs with the
        // release store at the end of the boot block, so a post-latch read sees the final
        // pointer value.
        if (spark_boot_done_.load(std::memory_order_acquire) && spark_engine_)
            spark_engine_->stop(); // idempotent; completion-barriered by lifecycle_mu_
        // LOCAL COPY. This runs on the watcher / SCM thread while run() may be publishing a
        // fresh Updater on reconnect; the copy keeps this one alive for the whole stop().
        if (auto u = updater())
            u->stop();
        // Cancel any in-flight heartbeat / daily-sync RPC to unblock those threads. Both
        // contexts are STACK objects owned by their own thread's frame, and this runs on the
        // watcher / SCM thread — so both go through cancel_ctx()'s locked load+TryCancel.
        // sync_ctx_ was missed entirely by the first ctx_mu_ patch.
        cancel_ctx(heartbeat_ctx_);
        cancel_ctx(sync_ctx_);
        // Registration wedge: on a stop during registration this is the ONLY live context —
        // subscribe/heartbeat/sync are not published until Register has SUCCEEDED, so cancelling
        // only those three left main parked in Register with nothing to interrupt it.
        cancel_ctx(register_ctx_);
        stop_completed_ = true;
    }

    std::string_view agent_id() const noexcept override { return cfg_.agent_id; }

    std::vector<std::string> loaded_plugins() const override { return plugin_names_; }

    [[nodiscard]] bool startup_failed() const noexcept override { return startup_failed_; }

    [[nodiscard]] std::size_t guardian_active_io_workers() const noexcept override {
        // Route A (corrected), #2012/#3840 plan: additive sum of Guardian's
        // own bounded-I/O workers and every Spark mechanism's detached probe
        // workers (spark_detached_workers_, see its own doc comment on why
        // this NEVER dereferences spark_engine_/spark_boot_done_ - that is
        // the whole point of Route A, which fixed a real gap Route B (an
        // earlier design summing only through guardian_'s wired pointer)
        // had: a window where a mechanism's detached worker could exist
        // while guardian_'s pointer to spark_engine_ was still null, or
        // already reset).
        return (guardian_ ? guardian_->active_io_workers() : 0) +
              (spark_detached_workers_ ? spark_detached_workers_->load(std::memory_order_acquire)
                                        : 0);
    }

private:
    // Serialize a Guardian event into the __guard__/event CommandResponse and write
    // it through the current Subscribe stream. Shared by the GuardianEngine drift
    // sink and the (ruleless) DEX signal observer. Drops the event if the link is
    // down between reconnects (guardian_sink_stream_ null) — durable buffering is A3.
    // Returns the delivery outcome (LegacySendOutcome, #4783: LinkDown when the
    // stream is null, WriteFailed when Write() itself returns false, Sent otherwise)
    // so a caller can distinguish those two failure shapes and log it (#4606
    // criterion-10 T_wire) — deliberately instrumented ONLY at the drift-sink call
    // site (set_event_sink's lambda), never here and never at the DEX observer's
    // call site: DEX signal telemetry is a different kind of traffic than the
    // Guardian-violation latency this benchmark measures, and instrumenting it here
    // would flood the log at DEX observation volume. A new caller of this method
    // should make the same choice deliberately rather than copy whichever pattern it
    // happens to see first.
    LegacySendOutcome emit_guardian_event(const gpb::GuaranteedStateEvent& ev) {
        pb::CommandResponse resp;
        resp.set_plugin("__guard__");
        resp.set_action("event");
        resp.set_status(pb::CommandResponse::SUCCESS);
        resp.set_payload(ev.SerializeAsString());
        std::lock_guard lock(stream_write_mu_);
        if (!guardian_sink_stream_)
            return LegacySendOutcome::LinkDown;
        return guardian_sink_stream_->Write(resp, grpc::WriteOptions()) ? LegacySendOutcome::Sent
                                                                        : LegacySendOutcome::WriteFailed;
    }

    // The send callback the Guardian spark outbox drain worker uses (rung 7.7a). It
    // maps one buffered OutboxEntry to the wire event and writes it over the current
    // Subscribe stream, mirroring emit_guardian_event but returning a SendResult so
    // the drain can retain-and-retry: Retain when the stream is down (pre-network arm
    // or a reconnect gap) or the Write fails, Sent on a successful Write. Capturing
    // `this` is lifetime-safe, but NOT via a synchronous join (#2233 item 4, revised):
    // this callback runs on GuardianOutboxSendExecutor's DETACHED worker
    // (guardian_outbox_send_executor.hpp), which guardian_->stop() does NOT join. Safety
    // instead rests on the orphan-exit contract - active_send_workers() is summed into
    // GuardianEngine::active_io_workers() (guardian_engine.cpp), and main.cpp/
    // service_win.cpp's hard_exit.hpp guard refuses normal C++ teardown of AgentImpl
    // (and therefore of stream_write_mu_/guardian_sink_stream_, which this callback
    // touches) while that count is nonzero - hard_exit()ing instead after a bounded
    // grace. NOTE: at 7.7a prefer_spark is false, so no rule arms, the outbox is always
    // empty, and this callback is never actually invoked in production - the mapping is
    // proven by unit tests ([sendmap]) ahead of rung 7.7b.
    SendResult send_guardian_outbox_entry(const OutboxEntry& e) {
        static constexpr std::string_view kHostPlatform =
#if defined(_WIN32)
            "windows";
#elif defined(__APPLE__)
            "macos";
#else
            "linux";
#endif
        pb::CommandResponse resp;
        resp.set_plugin("__guard__");
        resp.set_action("event");
        resp.set_status(pb::CommandResponse::SUCCESS);
        resp.set_payload(guardian_outbox_entry_to_event(e, kHostPlatform).SerializeAsString());
        bool ok;
        {
            std::lock_guard lock(stream_write_mu_);
            if (!guardian_sink_stream_)
                return SendResult::Retain; // link down between reconnects; keep + retry (A3)
            ok = guardian_sink_stream_->Write(resp, grpc::WriteOptions());
        } // stream_write_mu_ released before any I/O below — a slow/blocked log write must never
          // stall every other sender on this stream (heartbeats, command responses, the legacy
          // Guardian drift-sink), matching evaluate_key's own unlock-before-I/O discipline.
        // #4606 criterion-10 T_wire: local Write() outcome only, NOT server receipt/commit (see
        // T_server, guardian_ingest.cpp). Best-effort, always-on info level (the shipped default
        // is what the benchmark must measure) — a log throw must never flip a real Sent into
        // Retain, so this stays strictly after `ok` is captured and before the return. It is
        // still a synchronous write on the detached send worker of its lane (each lane's
        // executor is single-flight), so a log sink that blocks delays the NEXT entry's send
        // on that lane (see guardian_spark_timing.hpp).
        try {
            const auto r = make_outbox_send_timing(
                e, ok,
                std::chrono::duration_cast<std::chrono::nanoseconds>(
                    std::chrono::system_clock::now().time_since_epoch())
                    .count());
            spdlog::info("{}", format_send_timing_line(r));
        } catch (...) { // best-effort diagnostic; never propagate
        }
        return ok ? SendResult::Sent : SendResult::Retain;
    }

    // Per-command dispatch task (#2037): runs one CommandRequest through its
    // plugin and streams timing + terminal status back. Extracted from the
    // dispatch lambda so the ThreadPool exception firewall and the
    // FAILURE-on-throw path around it stay small and readable. A `return`
    // here skips this command's remaining status writes exactly as it did
    // inside the lambda.
    void execute_command_task(const YuzuPluginDescriptor* target, const pb::CommandRequest& cmd,
                              const std::shared_ptr<SubscribeStream>& stream) {
        // -- Stagger/delay: prevent thundering herd on large-fleet dispatch --
        const int32_t stagger_s = std::min(cmd.stagger_seconds(), int32_t{300}); // cap 5 min
        const int32_t delay_s = std::min(cmd.delay_seconds(), int32_t{300});     // cap 5 min
        if (stagger_s > 0 || delay_s > 0) {
            int32_t random_stagger = 0;
            if (stagger_s > 0) {
                std::random_device rd;
                std::mt19937 gen(rd());
                std::uniform_int_distribution<int32_t> dist(0, stagger_s);
                random_stagger = dist(gen);
            }
            const int32_t total_delay =
                std::min((delay_s > 0 ? delay_s : 0) + random_stagger, int32_t{600});
            spdlog::debug("Command {} stagger {}s + delay {}s = {}s", cmd.command_id(),
                          random_stagger, delay_s, total_delay);

            if (total_delay > 0) {
                std::this_thread::sleep_for(std::chrono::seconds(total_delay));
            }

            // Check expiration after the delay — skip stale commands
            if (cmd.has_expires_at() && cmd.expires_at().millis_epoch() > 0) {
                auto now_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                                  std::chrono::system_clock::now().time_since_epoch())
                                  .count();
                if (now_ms > cmd.expires_at().millis_epoch()) {
                    spdlog::warn("Command {} expired after stagger/delay "
                                 "(expired_at={}, now={})",
                                 cmd.command_id(), cmd.expires_at().millis_epoch(), now_ms);
                    pb::CommandResponse expired_resp;
                    expired_resp.set_command_id(cmd.command_id());
                    expired_resp.set_status(pb::CommandResponse::REJECTED);
                    expired_resp.set_output("command expired after stagger/delay");
                    auto epoch = std::chrono::duration_cast<std::chrono::milliseconds>(
                                     std::chrono::system_clock::now().time_since_epoch())
                                     .count();
                    expired_resp.mutable_sent_at()->set_millis_epoch(epoch);

                    // Deterministic terminal (expires_at is fixed): memoise so a
                    // redelivery replays this rather than sleeping the stagger again.
                    record_command_terminal(cmd.command_id(), expired_resp);
                    std::lock_guard lock(stream_write_mu_);
                    stream->Write(expired_resp, grpc::WriteOptions());
                    return;
                }
            }
        }

        metrics_.counter("yuzu_agent_commands_executed_total", {{"plugin", cmd.plugin()}})
            .increment();
        CommandContextImpl ctx_impl{
            .stream = stream,
            .write_mu = &stream_write_mu_,
            .command_id = cmd.command_id(),
            .start_time = std::chrono::steady_clock::now(),
        };
        auto* raw_ctx = reinterpret_cast<YuzuCommandContext*>(&ctx_impl);

        // Convert protobuf parameter map -> C ABI YuzuParam array
        // Direct construction: single vector of YuzuParam pointing at proto map
        // entries (no intermediate string copies — proto owns the data).
        const auto& proto_params = cmd.parameters();
        std::vector<YuzuParam> params;
        params.reserve(proto_params.size());
        for (const auto& [k, v] : proto_params) {
            params.push_back(YuzuParam{k.c_str(), v.c_str()});
        }

        // Defence-in-depth: wrap the plugin's execute() so a
        // thrown C++ exception cannot propagate up into the
        // command-dispatch thread and terminate() the whole
        // agent process. Plugins are expected to convert
        // failures into a non-zero `rc`; this is the safety
        // net for the cases they miss. Observed 2026-05-12:
        // agent_logging.get_log threw filesystem_error from
        // fs::exists on EACCES and brought the agent down
        // mid-test. The plugin bug is fixed separately;
        // this catch is so the next plugin's mistake
        // doesn't have the same blast radius.
        int rc;
        try {
            rc = target->execute(raw_ctx, cmd.action().c_str(), params.data(), params.size());
        } catch (const std::exception& e) {
            spdlog::error("Plugin {} action {} threw std::exception: {}", cmd.plugin(),
                          cmd.action(), e.what());
            std::string msg = "plugin threw exception: ";
            msg += e.what();
            ctx_impl.append_output(msg.c_str());
            rc = 1;
        } catch (...) {
            spdlog::error("Plugin {} action {} threw non-std exception", cmd.plugin(),
                          cmd.action());
            ctx_impl.append_output("plugin threw non-std exception");
            rc = 1;
        }

        // Flush any buffered output before sending timing/status
        ctx_impl.flush_output();

        auto end_time = std::chrono::steady_clock::now();
        auto exec_ms =
            std::chrono::duration_cast<std::chrono::milliseconds>(end_time - ctx_impl.start_time)
                .count();

        // Send timing metadata before the final status
        {
            pb::CommandResponse timing_resp;
            timing_resp.set_command_id(cmd.command_id());
            timing_resp.set_status(pb::CommandResponse::RUNNING);
            timing_resp.set_output("__timing__|exec_ms=" + std::to_string(exec_ms));

            std::lock_guard lock(stream_write_mu_);
            stream->Write(timing_resp, grpc::WriteOptions());
        }

        // CC-07 log presentation: a coarse "effective" status derived from the
        // plugin's report (or the int rc when it never reported) is convenient
        // for the operator log line below. It is a READ-TIME/PRESENTATION
        // derivation ONLY — see derive_effective_result_status(), unit-tested in
        // tests/unit/test_capability_descriptor.cpp.
        YuzuResultStatus effective_result_status =
            derive_effective_result_status(ctx_impl.result_status, rc);

        // Log before the terminal write so nothing that can throw runs AFTER a
        // terminal status has been sent — otherwise the dispatch firewall's
        // catch would send a second terminal status (FAILURE after SUCCESS) for
        // the same command_id (#2037 hardening).
        spdlog::info("Command {} finished (rc={}, exec={}ms, effective_result_status={}, "
                     "completeness={}, provenance={})",
                     cmd.command_id(), rc, exec_ms, static_cast<int>(effective_result_status),
                     static_cast<int>(ctx_impl.result_completeness), ctx_impl.result_provenance);

        // Send final status (must be the last statement — see above)
        {
            pb::CommandResponse final_resp;
            final_resp.set_command_id(cmd.command_id());
            final_resp.set_status(rc == 0 ? pb::CommandResponse::SUCCESS
                                          : pb::CommandResponse::FAILURE);
            final_resp.set_exit_code(rc);
            // BR-006: serialize the RAW reported status, never the rc-derived
            // one. agent.proto pins 0/UNDECLARED as "the plugin never called
            // yuzu_ctx_set_result_status() (including every ABI<4 plugin)", so
            // deriving OK/UNAVAILABLE here would violate the wire contract and
            // erase the declared-vs-inferred distinction — and the pass/fail
            // outcome is already carried by status + exit_code. Consumers that
            // want a coarse status derive it at read time.
            final_resp.set_plugin_result_status(to_proto_result_status(ctx_impl.result_status));

            auto now_epoch = std::chrono::duration_cast<std::chrono::milliseconds>(
                                 std::chrono::system_clock::now().time_since_epoch())
                                 .count();
            final_resp.mutable_sent_at()->set_millis_epoch(now_epoch);

            // Persist the terminal outcome BEFORE the wire send (HA WS-0): the
            // durable record is the source of truth, the send is best-effort and
            // replayable. record_command_terminal is noexcept + runs before the
            // terminal Write, so it cannot cause the #2037 second-terminal hazard.
            record_command_terminal(cmd.command_id(), final_resp);
            std::lock_guard lock(stream_write_mu_);
            stream->Write(final_resp, grpc::WriteOptions());
        }
    }

    // Record a claimed command's terminal outcome into the durable dedup store
    // (HA WS-0). Caps the stored blob so a huge plugin output cannot bloat
    // command_dedup.db across up to kMaxDedupRows rows: beyond the cap the slim
    // form preserves status/exit_code/result-status (the effectively-once signal)
    // and drops the full output (a replay then returns the status, not the
    // bytes). A Miss — the terminal matched no in-flight row (evicted or never
    // claimed) — is counted: it is the signal a redelivery of this command could
    // re-execute. noexcept + internally guarded: a failure here only degrades
    // durability, it never propagates into the command path.
    void record_command_terminal(const std::string& command_id,
                                 const pb::CommandResponse& resp) noexcept {
        // CHAOS-TTL-1: this is the ONE chokepoint every terminal write already
        // passes through regardless of dedup state, so it is also the correct
        // place to erase from in_flight_ids_ — unconditional on command_dedup_
        // (that guard below is scoped to the dedup-store logic only; the
        // keepalive's in-flight set has nothing to do with it and must not stay
        // populated just because dedup is degraded).
        if (!command_id.empty()) {
            std::lock_guard lock(in_flight_mu_);
            in_flight_ids_.erase(command_id);
        }
        if (!command_dedup_ || command_id.empty())
            return;
        try {
            static constexpr size_t kMaxDedupResponseBytes = 64 * 1024;
            static constexpr int kMaxDedupErrorMessageBytes = 1024;
            std::string blob;
            if (resp.ByteSizeLong() > kMaxDedupResponseBytes) {
                // Store a slim form: keep the terminal SIGNAL (status/exit_code/
                // result-status/error) that effectively-once needs; replace only
                // the large `output` field with a fixed sentinel. `error.code` +
                // a bounded `error.message` are preserved so a replayed failure
                // still carries its reason.
                pb::CommandResponse slim;
                slim.set_command_id(resp.command_id());
                slim.set_status(resp.status());
                slim.set_exit_code(resp.exit_code());
                slim.set_plugin_result_status(resp.plugin_result_status());
                if (resp.has_sent_at())
                    *slim.mutable_sent_at() = resp.sent_at();
                if (resp.has_error()) {
                    slim.mutable_error()->set_code(resp.error().code());
                    slim.mutable_error()->set_message(
                        resp.error().message().substr(0, kMaxDedupErrorMessageBytes));
                }
                slim.set_output("[output replaced in dedup store: response exceeded size cap; "
                                "command completed]");
                blob = slim.SerializeAsString();
            } else {
                blob = resp.SerializeAsString();
            }
            switch (command_dedup_->record_terminal(command_id, blob)) {
            case RecordOutcome::Recorded:
                break;
            case RecordOutcome::Miss:
                // A terminal outcome matched no in-flight row: the command ran
                // undeduplicated (claim had failed — fail-open) or this is a
                // duplicate terminal write. NOT the same as the eviction-driven
                // double-execute, which produces a fresh claim and is not
                // separately detectable here (bounded by kMaxDedupRows).
                metrics_.counter("yuzu_agent_dedup_record_terminal_miss_total").increment();
                break;
            case RecordOutcome::Error:
                // A durable WRITE failed (full disk / I/O error) after a healthy
                // open — the write-side of the fail-open degradation, which must
                // stay observable (invariant 7), not just logged in the store.
                metrics_.counter("yuzu_agent_dedup_record_errors_total").increment();
                break;
            }
        } catch (...) {
            // Best-effort + noexcept: an allocation/serialization failure here
            // leaves the row IN-FLIGHT (the terminal was never recorded), so a
            // redelivery answers RUNNING and the command does NOT re-execute —
            // durability degraded, not a double-run. Count + log so it is not
            // silent; the log is itself guarded (spdlog can throw under OOM).
            metrics_.counter("yuzu_agent_dedup_record_errors_total").increment();
            try {
                spdlog::error("record_command_terminal failed to persist outcome for {}",
                              command_id);
            } catch (...) {
            }
        }
    }

    // Best-effort terminal FAILURE for a command whose dispatch task threw
    // outside the plugin execute() guard (#2037). Invoked from the dispatch
    // exception firewall so the server receives a terminal status instead of
    // waiting on its timeout. Must not itself throw — the Write is guarded.
    void send_dispatch_failure(const std::shared_ptr<SubscribeStream>& stream,
                               const std::string& command_id, const std::string& message) noexcept {
        try {
            pb::CommandResponse resp;
            resp.set_command_id(command_id);
            resp.set_status(pb::CommandResponse::FAILURE);
            resp.set_exit_code(1);
            // Carry the reason in the structured error field, NOT output: the
            // server finalizes a terminal frame onto prior RUNNING rows in place
            // only when output is empty (agent_service_impl.cpp). A non-empty
            // output would instead INSERT a second row and leave any already-
            // streamed RUNNING output rows un-finalized (#2037 UP-1).
            resp.mutable_error()->set_code("agent_dispatch_error");
            resp.mutable_error()->set_message(message);
            auto epoch = std::chrono::duration_cast<std::chrono::milliseconds>(
                             std::chrono::system_clock::now().time_since_epoch())
                             .count();
            resp.mutable_sent_at()->set_millis_epoch(epoch);
            // Terminal outcome for a claimed command whose task threw before its
            // own terminal write — memoise it so a redelivery replays this FAILURE
            // instead of re-running (HA WS-0).
            record_command_terminal(command_id, resp);
            std::lock_guard lock(stream_write_mu_);
            if (stream)
                stream->Write(resp, grpc::WriteOptions());
        } catch (...) {
            // Last-resort log, itself guarded: this function is noexcept, so a
            // throw from spdlog here would be an immediate terminate() — the
            // exact failure #2037 exists to prevent.
            try {
                spdlog::error("Command {} failed to send dispatch-failure response", command_id);
            } catch (...) {}
        }
    }

    // #1420 / #1434 — single quiesce-and-join chokepoint for the three
    // `this`-capturing worker threads Run() spawns: the Run()-lifetime snapshot
    // pump, the per-connection heartbeat, and the OTA-updater thread. Every one
    // of them must be stopped and joined before the agent's plugins are torn
    // down and before AgentImpl is destroyed:
    //   * the snapshot pump dispatches `tar.fleet_snapshot` into the TAR plugin
    //     through a borrowed descriptor — a cycle that runs after plugin
    //     teardown is a use-after-free (#1420);
    //   * any Run() exit that leaves one of these threads joinable aborts the
    //     process via std::terminate when the std::thread is destroyed (#1434,
    //     e.g. the hard registration-rejection `return`).
    // Invoked from EVERY Run() exit path: the Run()-exit ScopeExit `cleanup`
    // (covers the early returns and exceptions) and the reconnect-loop final
    // teardown (orders the pump join ahead of plugins_.clear()). Idempotent —
    // the joinable() guards make repeat calls and the not-yet-started register
    // loop returns (where heartbeat/updater don't exist yet) no-ops.
    //
    // Unblock-before-join keeps the joins bounded: the pump observes the stop
    // flag on its ≤2 s sleep slices (worst case it finishes one in-flight local
    // `fleet_snapshot` enumerate — no blocking I/O, so the join is bounded by a
    // single capture, not a network wait); the heartbeat may be parked in a
    // Heartbeat RPC and the updater in an OTA RPC, so we TryCancel the heartbeat
    // context and stop() the updater first — `Updater::stop()` now TryCancels
    // its in-flight OTA RPC too (#1434 UP-1), so a stalled download can't hang
    // the join. This is a SUPERSET of what stop() unblocks (stop() additionally
    // cancels the Subscribe stream and drains guardian_/dex_observer_, which are
    // member-owned and joined by their own dtors — deliberately NOT joined here).
    //
    // TERMINAL-ONLY: this sets stop_requested_, so it must be called only on a
    // path that is actually shutting the agent down (the Run()-exit ScopeExit,
    // or the reconnect-loop teardown already gated on stop_requested_). Never
    // call it on a transient-reconnect path — doing so would euthanise a healthy
    // agent and break the across-reconnect warm-snapshot continuity (PR 10).
    void quiesce_run_workers() noexcept {
        stop_requested_.store(true, std::memory_order_release);
        yuzu::agent::request_subprocess_cancel(true);
        heartbeat_stop_.store(true, std::memory_order_release);
        if (auto u = updater())
            u->stop();
        // Both cancels go through the locked chokepoint. The lock is released before every
        // join below — holding ctx_mu_ across a join() would deadlock against the very thread
        // whose ~CtxSlot needs it to exit.
        cancel_ctx(heartbeat_ctx_);
        if (snapshot_pump_thread_.joinable())
            snapshot_pump_thread_.join();
        // LIFETIME INVARIANT (Guardian lifecycle journal, item 7 PR-Ag): the heartbeat thread
        // (guardian_->journal_maintenance_tick / journal_stats) and the run-loop reconnect hook
        // (guardian_->page_journal) call INTO the engine, so neither may run after guardian_ is
        // destroyed (declared later, destroyed earlier). They stay safe ONLY because these
        // threads are joined HERE, first. Do NOT reorder a guardian_ teardown ahead of these
        // joins, and keep new guardian_-touching threads joined in this block. (Since C0 #2298
        // neither call carries a raw journal pointer off-lock any more - prune/page moved onto
        // the engine's own drain worker, which the engine itself joins - but the join order is
        // unchanged: page_journal still takes the engine mtx_ and wakes that worker.)
        if (heartbeat_thread_.joinable())
            heartbeat_thread_.join();
        // Concurrency-claim keepalive thread (CHAOS-TTL-1): stop_requested_
        // above already unblocks its should_stop() poll. Both callers of
        // quiesce_run_workers() (the reconnect-loop teardown and the Run()-
        // exit ScopeExit) are reached only after the read loop's
        // `stream->Read()` has already returned false — the connection is
        // already known dead, not merely stalled, so a Write() on it fails
        // fast rather than blocking (see the reconnect-teardown site's own
        // comment for the fuller version of this reasoning, and
        // `keepalive_unwind_guard` for the exception-escape path this
        // doesn't cover). Join is bounded by its own ≤5s sleep slice, same
        // shape as the snapshot pump above.
        keepalive_stop_.store(true, std::memory_order_release);
        if (keepalive_thread_.joinable())
            keepalive_thread_.join();
        sync_stop_.store(true, std::memory_order_release);
        cancel_ctx(sync_ctx_); // unblock an in-flight ReportInventory before joining
        if (sync_thread_.joinable())
            sync_thread_.join();
        if (update_thread_.joinable())
            update_thread_.join();
    }

    Config cfg_;
    PluginContextImpl plugin_ctx_;
    // Per-plugin contexts: each plugin gets its own PluginContextImpl with the
    // correct plugin_name for KV storage namespacing. Stored as unique_ptrs so
    // pointers remain stable after map insertions.
    std::unordered_map<std::string, std::unique_ptr<PluginContextImpl>> per_plugin_ctx_;
    std::unique_ptr<KvStore> kv_store_;
    // Drives interval / file-change / service-status triggers that plugins
    // register during init(). Owned here; a non-owning pointer is handed to
    // every per-plugin context so yuzu_register_trigger can reach it.
    // start() is called once plugins are loaded; stop() runs before plugin
    // shutdown so a trigger never fires into a half-torn-down plugin.
    TriggerEngine trigger_engine_;
    yuzu::MetricsRegistry metrics_;
    std::chrono::steady_clock::time_point start_time_;
    std::string session_id_;
    std::atomic<bool> stop_requested_{false};

    // #2233 item 3: serializes AgentImpl::stop()'s WHOLE body. Closes the one call site
    // with no external lock at all — the OTA self-stop thread (update_thread_ below calls
    // stop() on itself) can otherwise race the Windows console/SCM/POSIX-watcher stop
    // triggers with zero coordination, and (verified) dex_observer_'s own stop() is not
    // safe against concurrent entry (its Windows implementation touches poller_/subs_
    // outside state_->mu_; its Linux implementation can double-join the same std::thread).
    // Makes Agent::stop()'s own "Thread-safe" doc comment (agent.hpp) actually true.
    std::mutex stop_mu_;
    // A plain bool guarded by stop_mu_, not std::atomic<bool> like stop_requested_/
    // spark_boot_done_ above - deliberate, not a drift from that idiom: every read and write
    // of this flag already falls inside the same stop_mu_ critical section (it gates
    // whole-method mutual exclusion, not just a single flag check), so a bare atomic would
    // add nothing and would invite a future edit to check it outside the lock.
    // #2233 item 3: this stop_mu_/stop_completed_ pair itself has no direct test - AgentImpl
    // has no test seam (grep "_for_test\b" agent.cpp), so the concurrent-stop()-entry fix it
    // provides is verified by code review only, not exercised by any test in this repo today
    // (governance Gate 3 quality-engineer SHOULD-FIX; tracked, not blocking - a future test
    // seam for AgentImpl would close this).
    bool stop_completed_{false};
    // NOTE: an earlier revision of this PR also added teardown_mu_/guardian_stopped_/
    // spark_stopped_ to serialize guardian_->stop()/spark_engine_->stop() specifically
    // (the two calls duplicated between stop() and run()'s teardown ScopeExit). Removed
    // (adversarial review Kimi K1): SparkEngine::stop() already has its OWN internal
    // completion-barrier mutex for exactly this concurrent-caller scenario
    // (lifecycle_mu_+teardown_complete_ — its own header comment names the stop()-vs-
    // ScopeExit race explicitly as the reason that barrier exists); GuardianEngine::stop()
    // has no equivalent barrier but is safe on a repeat call because every step inside it is
    // independently idempotent (see the ScopeExit's own comment above for the verified list) -
    // so the extra AgentImpl-level layer was redundant for safety either way and, as
    // implemented, introduced a real regression: a stop() that raced spark_engine_'s boot
    // window would mark the flag done without ever having called spark_engine_->stop(),
    // permanently disabling the ScopeExit's retry. See stop()'s and the ScopeExit's own
    // call-site comments for the restored, deliberately-different-per-caller gating.

    std::atomic<bool> heartbeat_stop_{false};
    std::atomic<bool> sync_stop_{false}; // ADR-0016 daily-sync thread stop flag
    // Sync-on-demand (`__sync__.now`, ADR-0016 update): the command read loop
    // arms the scheduler through this handle and breaks the sync thread's sleep.
    // sync_scheduler_ is null under --inventory-disable and between connections
    // (published by the 4b-sync thread after its sources are registered, cleared
    // by that same thread on exit) — the intercept answers FAILURE, never blocks.
    std::atomic<bool> sync_wake_{false};
    std::mutex sync_sched_mu_;
    std::shared_ptr<SyncScheduler> sync_scheduler_;
    std::atomic<bool> keepalive_stop_{false}; // CHAOS-TTL-1 keepalive thread stop flag
    // Consecutive session-rejection-forced re-registrations (#1894). A successful
    // Register resets the normal reconnect backoff, so a server that reaps every
    // fresh session would otherwise drive a fleet-wide re-registration storm; the
    // heartbeat path applies its own escalating cooldown keyed on this counter,
    // which survives across re-registrations and resets on a healthy heartbeat.
    std::atomic<int> forced_rereg_streak_{0};
    // Set when run() returns due to a fatal STARTUP failure (the #1303 fail-closed
    // TLS posture refused to connect, or an unreadable cert/key) — not a normal
    // stop(). main() maps it to a non-zero exit. Single-threaded: written in run()
    // before the connect loop, read after run() returns; no atomic needed.
    /// Set on the run() thread, read by main()/service_win after run() returns. ATOMIC because it
    /// sits behind a PUBLIC VIRTUAL accessor: no race today, but the next cross-thread reader (a
    /// health probe, a log line in stop()) would silently create one. (governance: cpp-safety.)
    std::atomic<bool> startup_failed_{false};
    /// Serialises the three ClientContext pointers below against every cross-thread cancel.
    ///
    /// ALL THREE point at STACK objects — `&sub_ctx` in the reconnect-loop frame, `&ctx` in
    /// the per-iteration heartbeat frame, `&ctx` in the sync sender's frame — and they are
    /// TryCancel()'d from OTHER threads: the POSIX shutdown watcher, the Windows SCM control
    /// thread, and (for subscribe_ctx_) the heartbeat thread. Without this lock the owner can
    /// clear its pointer, leave the scope (destroying the ClientContext), and be joined, while
    /// a canceller sits between its load() and its TryCancel() — a use-after-free on a freed
    /// context, or a cancel against a DIFFERENT stream that reused the stack slot.
    ///
    /// It was survivable-by-luck before: the signal handler ran stop() inline on whichever
    /// thread took the signal, often the main thread, i.e. INSIDE run(). Moving the teardown
    /// onto a dedicated watcher thread (the B2 fix) makes stop() concurrent with run()'s exit
    /// on EVERY SIGTERM, so the race went from occasional to reliable.
    ///
    /// THE RULE, and why it is now STRUCTURAL rather than a convention. Every publish/retract
    /// goes through CtxSlot, and every cancel through cancel_ctx() — there are no bare
    /// store()/load()+TryCancel() sites left. The first attempt at this fix hand-rolled a
    /// lock_guard at each site and covered 3 of 7, leaving the identical UAF open on the
    /// reconnect path (which runs far more often than shutdown). Three reviewers found it
    /// independently. A rule you must remember at seven call sites is a rule that gets missed;
    /// the RAII owner cannot be. (governance Gate-8 round 7: cpp-safety, cpp-expert,
    /// security-guardian.)
    ///
    /// LOCK ORDER: ctx_mu_ is the OUTERMOST lock either of them takes. cancel_ctx() does hold
    /// it across TryCancel(), which takes gRPC's own internal ClientContext lock — so the order
    /// is strictly ctx_mu_ -> grpc-internal, and never the reverse (gRPC's sync API never calls
    /// back into our code, and grpc_call_cancel does not block). Never take ctx_mu_ while
    /// already holding it — a nested lock_guard on this NON-RECURSIVE mutex self-deadlocked
    /// Agent::stop() in an earlier round and the agent hung on every SIGTERM; note it would
    /// HANG, not throw, so a bad path is silent. And never hold it across a join(): the thread
    /// being joined needs it for its own ~CtxSlot.
    std::mutex ctx_mu_;
    std::atomic<grpc::ClientContext*> subscribe_ctx_{nullptr};
    std::atomic<grpc::ClientContext*> heartbeat_ctx_{nullptr};
    std::atomic<grpc::ClientContext*> sync_ctx_{nullptr}; // ADR-0016 daily-sync RPC (cancel on teardown)
    /// The Register RPC. Blocking, on the MAIN thread, and the only one of the four that runs
    /// BEFORE the others are published — so on a registration wedge it is the ONLY context
    /// stop() has to cancel. It carries a deadline too (kRegisterTimeout): the OTA self-stop
    /// path gets no signal at all, so cancellation alone would not bound it.
    std::atomic<grpc::ClientContext*> register_ctx_{nullptr};

    /// Publishes a STACK-owned ClientContext into one of the slots above for exactly the
    /// lifetime of the enclosing scope, and retracts it under ctx_mu_ on the way out —
    /// including on the exception and early-return paths a hand-written store(nullptr) misses.
    /// Because the retraction takes ctx_mu_, an in-flight cancel_ctx() holding the lock keeps
    /// the pointee alive until its TryCancel() returns.
    ///
    /// THE LOCK IS HELD ONLY MOMENTARILY — inside the ctor body and the dtor body, never for
    /// the slot's LIFETIME. That is load-bearing, not an implementation detail: `sub_slot`'s
    /// scope encloses `thread_pool_.reset()` and the heartbeat/sync/updater joins, and the
    /// heartbeat thread's own ~CtxSlot needs ctx_mu_ to exit. Hold the lock for the slot's
    /// lifetime (e.g. "optimise" these lock_guards into a unique_lock member) and run() would
    /// deadlock against the very thread it is joining, on every reconnect. Do not.
    class CtxSlot {
    public:
        CtxSlot(std::mutex& mu, std::atomic<grpc::ClientContext*>& slot,
                grpc::ClientContext* ctx) noexcept
            : mu_{mu}, slot_{slot} {
            std::lock_guard lk(mu_);
            slot_.store(ctx, std::memory_order_release);
        }
        ~CtxSlot() {
            std::lock_guard lk(mu_);
            slot_.store(nullptr, std::memory_order_release);
        }
        CtxSlot(const CtxSlot&) = delete;
        CtxSlot& operator=(const CtxSlot&) = delete;

    private:
        std::mutex& mu_;
        std::atomic<grpc::ClientContext*>& slot_;
    };

    /// The ONLY way to cancel one of the three contexts. Loads AND TryCancel()s under ctx_mu_
    /// so the owning frame's ~CtxSlot cannot retire the context in between. Safe on a slot
    /// that is already null (the common case — the RPC has finished).
    void cancel_ctx(std::atomic<grpc::ClientContext*>& slot) noexcept {
        std::lock_guard lk(ctx_mu_);
        if (auto* c = slot.load(std::memory_order_acquire))
            c->TryCancel();
    }
    std::vector<PluginHandle> plugins_;
    std::vector<std::string> plugin_names_;
    std::mutex stream_write_mu_;
    // Current Subscribe stream the Guardian event-sink writes through (H4 / #1209).
    // Guarded by stream_write_mu_. The sink must NOT capture a specific stream: it
    // reads this holder under the lock and drops the event if it is null (link down
    // between reconnects). Set on stream open, reset on read-loop exit BEFORE the
    // stream is torn down, so a writer firing mid-teardown can never write to a
    // cancelled stream. #4783: legacy guard worker threads no longer touch this at
    // all — they only enqueue onto GuardianEngine's legacy_sink_executor_, which
    // never captures a specific stream either. The things that CAN still write here
    // after this AgentImpl instance has moved on to a new stream (or is tearing
    // down) are (1) legacy_sink_executor_'s own detached worker — orphan-accounted
    // via active_io_workers()/hard_exit.hpp, same contract as (2) the DEX observer's
    // OS-callback threads, still synchronous and drained by dex_observer_->stop().
    std::shared_ptr<SubscribeStream> guardian_sink_stream_;
    // Fleet-wide DEX signal observer (multi-signal). Declared AFTER stream_write_mu_
    // + guardian_sink_stream_ (same reasoning as guardian_): its OS-callbacks emit
    // through emit_guardian_event(), so its dtor (which stop()s the subscriptions +
    // drains in-flight callbacks) must run while the mutex + sink-stream holder are
    // still alive. dex_seq_ disambiguates the at-least-once event_id for same-agent
    // bursts within one millisecond; agent_id (folded into the id) disambiguates
    // ACROSS agents so a fleet-wide signal wave doesn't collide on the global PK.
    std::atomic<std::uint64_t> dex_seq_{0};
    // Runtime arm/health of the DEX observer — flipped to false by the observer's
    // error callback on a runtime subscription failure on any channel (UP-1). A
    // shared_ptr<atomic> (not `this`) so a late OS-threadpool error callback stays
    // UAF-safe. Read by the heartbeat thread to drive the `yuzu.dex_observer_armed`
    // tag.
    std::shared_ptr<std::atomic<bool>> dex_health_;
    std::unique_ptr<ISignalObserver> dex_observer_;
    std::unique_ptr<ThreadPool> thread_pool_;
    // F3 orphan-exit accounting for mechanism-internal detached workers
    // (#2012/#3840 plan, "F3 orphan-exit accounting - Route A (corrected)").
    // A SparkDetachedLane (agents/core/src/spark_detached_call.hpp) inside a
    // Spark mechanism increments this counter at admission and decrements it
    // only once a detached worker's own closure is fully torn down - see that
    // header's own doc comment ("Ticketing"). Summed into
    // guardian_active_io_workers() below, additively with guardian_'s own
    // count. First consumer: the Windows Registry mechanism (PR-B1, handed in
    // via make_registry_mechanism(spark_detached_workers_) in the spark boot
    // block); File (PR-B2) and the Windows Service mechanism (PR-B3) both
    // followed the same shape.
    //
    // DEFAULT MEMBER INITIALIZER, DELIBERATELY - NOT declaration-order-
    // coupled to spark_engine_/guardian_ the way THEY are coupled to each
    // other (see spark_engine_'s own comment just below for that unrelated,
    // real dependency). This member's shared_ptr target must be constructed
    // before spark_engine_'s run()-time `= std::make_unique<SparkEngine>()`
    // (agent.cpp's spark boot block) - a default member initializer trivially
    // satisfies that: it exists from the moment AgentImpl itself finishes
    // constructing, which is unconditionally before run() is ever invoked,
    // covering every window the F3 sum must be correct in (pre-boot, mid-
    // boot, post-exception-reset, post-sticky-stop-skip-wiring - Astra's
    // round-3 finding, "F3 orphan-exit accounting - Route A (corrected)").
    // Never read through spark_engine_ or spark_boot_done_ (that IS the
    // point of Route A - see guardian_active_io_workers() below); its own
    // shared_ptr semantics keep the underlying atomic alive independent of
    // AgentImpl's member-destruction order, since any worker still holding a
    // copy (via CountGuard) keeps it alive regardless - so its declaration
    // POSITION here is for locality of reference (next to what it's summed
    // alongside), not because destruction order matters for it the way it
    // does for spark_engine_/guardian_ just below.
    std::shared_ptr<std::atomic<std::size_t>> spark_detached_workers_{
        std::make_shared<std::atomic<std::size_t>>(0)};
    // SparkEngine (ADR-0021 Stage-2, rung 1) — instantiated OBSERVE-ONLY with no
    // consumer, so (unlike guardian_/dex_observer_) it does NOT emit through
    // guardian_sink_stream_; ~SparkEngine only joins its own internal wheel/mechanism
    // threads. Read by the heartbeat thread (stats()/stats_by_type()), which is joined
    // in quiesce_run_workers() before member teardown. nullptr under --spark-disable,
    // and also nullptr if boot-time instantiation threw (degrade-to-no-spark).
    //
    // DECLARATION ORDER IS LOAD-BEARING — spark_engine_ MUST stay AFTER thread_pool_
    // AND BEFORE guardian_ below. Members destroy in REVERSE declaration order (the
    // LAST-declared member is destroyed FIRST): this position makes ~SparkEngine run
    // BEFORE ~ThreadPool (rung 1 does not borrow the pool, but rung 2's queued
    // Guardian consumer is expected to dispatch through it, #2037 - declared the
    // other way round, ~ThreadPool would run first and ~SparkEngine's join could
    // invoke a callback against a destroyed pool), AND makes ~SparkEngine run AFTER
    // ~GuardianEngine (ADR-0021 rung 7): GuardianSparkEngineBackend (rung 7.3) holds
    // a BORROWED, non-owning SparkEngine* threaded through guardian_'s
    // spark_runtime_/spark_backend_ once a future rung wires wire_spark_engine()
    // into this constructor - that pointer is only safe to hold if spark_engine_
    // outlives ~GuardianEngine, which requires spark_engine_ destroyed AFTER
    // guardian_, i.e. declared BEFORE it (verified with a standalone destructor-
    // order reproducer, not by re-reading this comment - an EARLIER version of this
    // fix, in this same PR, had guardian_ declared before spark_engine_, which is
    // BACKWARDS: that destroys spark_engine_ FIRST, still leaving the dangling-
    // pointer bug this comment describes fixing. Caught by governance Gate 8
    // independently re-reviewing this PR's own fix commit - cpp-safety and
    // security-guardian both re-derived the destruction order from source and
    // caught the inversion; empirically confirmed with g++ before landing this
    // correction). Free to fix now; a use-after-free class to find later otherwise
    // (governance Gate-3 architect, original finding).
    std::unique_ptr<SparkEngine> spark_engine_;
    // Declared AFTER stream_write_mu_/guardian_sink_stream_ (destroyed before both,
    // same reasoning as always: ~GuardianEngine joins the guard worker threads,
    // which must happen while the mutex + sink-stream holder those workers write
    // through are still alive, H4/#1209) AND, as of ADR-0021 rung 7, AFTER
    // spark_engine_ above - this is what makes guardian_ (the LAST-declared of the
    // two) destroy FIRST, while spark_engine_ is still alive, satisfying
    // GuardianSparkEngineBackend's borrowed-pointer requirement documented on
    // spark_engine_ above. Body-initialized in the ctor (after kv_store_), so this
    // declaration-order position does not itself require reordering any
    // constructor-body statement.
    std::unique_ptr<GuardianEngine> guardian_;
    /// TRUE once run()'s spark boot block has finished mutating spark_engine_ (set on
    /// every path: instantiated, --spark-disable, or degrade-to-no-spark). Agent::stop()
    /// — which runs on the watcher/SCM/console thread and is reachable from the moment
    /// g_agent is published, BEFORE run() — must acquire-load this latch before reading
    /// spark_engine_: the boot block both stores and (on the catch paths) FREES the
    /// pointer, and TSan caught the bare read racing that window for real (randomized-
    /// SIGTERM fuzz, 101 ms delay). Pre-latch, stop() skips spark; run()'s own ScopeExit
    /// covers teardown on that same thread. Post-latch, the slot is never written again
    /// until ~AgentImpl (after the watcher join / g_agent_mu barrier). The heartbeat
    /// thread needs no latch — it is spawned by run() AFTER the boot block, so its reads
    /// are sequenced by thread creation. (Gate-3 cpp-safety SAFE-1.)
    std::atomic<bool> spark_boot_done_{false};
    /// SHARED_PTR BEHIND A MUTEX, not a unique_ptr — and not a std::atomic<shared_ptr> either.
    ///
    /// WHY IT IS SHARED. run() REASSIGNS this on every reconnect (a fresh Updater per
    /// connection, so Updater::stop()'s latched stop_requested_ is cleared — reusing one would
    /// leave OTA dead after the first disconnect). Meanwhile Agent::stop() dereferences it from
    /// ANOTHER thread (the POSIX shutdown watcher, the Windows SCM/console thread). With a
    /// unique_ptr, run() could FREE the Updater while stop() was inside updater_->stop() — a
    /// use-after-free, and worse: since Updater gained a ctx_mu_ held across TryCancel(), a
    /// std::mutex DESTROYED WHILE LOCKED (UB; glibc tolerates it, MSVC and Apple Clang do not).
    ///
    /// WHY NOT std::atomic<std::shared_ptr<Updater>>, which is the obvious C++20 answer and was
    /// the first fix I wrote: **libc++ has never implemented P0718R2.** There is no
    /// atomic<shared_ptr> specialisation, so it instantiates the PRIMARY template over a
    /// non-trivially-copyable type and is ill-formed. It compiles on libstdc++ and MSVC STL and
    /// red-lines the macOS leg of Tier-1 CI. A green Linux build is not evidence of portability.
    /// (governance Gate-8 round 10 cpp-safety.)
    ///
    /// THE LOCK IS MOMENTARY — held only across the pointer copy in updater()/set_updater(),
    /// NEVER across u->stop() or a TryCancel(). Same discipline as CtxSlot. Hold it across the
    /// stop() and a wedged OTA drain would block run() and ~Agent behind it.
    ///
    /// Every reader takes a LOCAL shared_ptr copy first (via updater()), which keeps the object
    /// alive for the whole call even if run() swaps the slot underneath. There is no
    /// `updater_->x()` anywhere — grep for it across agents/ , not just this file.
    mutable std::mutex updater_mu_;
    std::shared_ptr<Updater> updater_;

    /// A LOCAL copy of the current Updater, or nullptr. The copy is what makes the caller safe.
    [[nodiscard]] std::shared_ptr<Updater> updater() const {
        std::lock_guard lk(updater_mu_);
        return updater_;
    }

    /// Publish a new Updater. The previous one is released OUTSIDE the lock: if this drops its
    /// last reference, ~Updater must not run while updater_mu_ is held.
    void set_updater(std::shared_ptr<Updater> u) {
        std::shared_ptr<Updater> old;
        {
            std::lock_guard lk(updater_mu_);
            old = std::move(updater_);
            updater_ = std::move(u);
        }
    }
    std::thread update_thread_;
    std::thread heartbeat_thread_;
    std::thread sync_thread_; // ADR-0016 daily-sync thread (per-connection)

    // PR 10 / UAT 2026-05-12 — Push-based fleet topology ingestion.
    //
    // `snapshot_pump_thread_` runs `tar.fleet_snapshot` locally on a
    // 30 s interval, captures the JSON, and stashes it under
    // `snapshot_mu_`. The heartbeat thread reads `latest_snapshot_`
    // each iteration; if `latest_snapshot_seq_` advanced since the
    // heartbeat's `last_attached_snapshot_seq_`, the snapshot rides
    // out on the next HeartbeatRequest.fleet_snapshot_json field.
    // Together they replace the previous dispatch-on-get path for
    // /api/v1/viz/fleet/topology, so the renderer reads from
    // per-agent slots that the agents themselves keep current.
    std::thread snapshot_pump_thread_;
    std::mutex snapshot_mu_;
    std::string latest_snapshot_;                  // last JSON produced by pump
    std::atomic<uint64_t> latest_snapshot_seq_{0}; // monotonically increases on each new snapshot

    // HA WS-0 (ADR-2002): durable command replay protection + terminal-outcome
    // replay. Replaces the former in-memory double-buffer dedup sets (cleared on
    // every reconnect, no outcome memory). Nullable — if the store fails to open
    // the agent runs with replay protection degraded (logged at boot). Set once
    // during startup and never reassigned, so the reader thread and the dispatch
    // workers read the pointer freely; the store serialises its own access.
    std::unique_ptr<CommandDedupStore> command_dedup_;

    // CHAOS-TTL-1 (PR #3784 fix round, governance ledger): a plugin-cooperation-
    // independent liveness signal for the server's per-device concurrency claim
    // TTL (ExecutionTracker::renew_concurrency_claim, ADR-1007). Neither a
    // plugin's own output volume nor its progress-reporting calls are a reliable
    // mid-execution signal — see the doc comment on keepalive thread spawn below
    // for the full rationale. `in_flight_ids_` is populated the instant a command
    // is accepted onto the thread pool (still covers queue-wait time, not just
    // execute()) and erased at the SAME chokepoint every terminal write already
    // goes through, `record_command_terminal` — so it can never diverge from the
    // set of commands this agent still owes a terminal response for.
    std::mutex in_flight_mu_;
    std::unordered_set<std::string> in_flight_ids_;
    std::thread keepalive_thread_;
};

// Factory

std::unique_ptr<Agent> Agent::create(Config config) {
    return std::make_unique<AgentImpl>(std::move(config));
}

} // namespace yuzu::agent
