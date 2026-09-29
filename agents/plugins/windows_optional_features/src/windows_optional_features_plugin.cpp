/**
 * windows_optional_features_plugin.cpp — Windows optional OS feature
 * (DISM) state plugin for Yuzu.
 *
 * Actions:
 *   "list" — Lists every optional feature and its state (optional `state`
 *            filter: enabled|disabled|pending).
 *   "info" — Detail for one feature (required `feature`).
 *
 * Windows: DISM API, DISM_ONLINE_IMAGE session. Per Architect ruling
 *   2026-09-08 (specs/P92-2.respec.md — binding, read it before touching
 *   this file), DismApi.dll is runtime-bound at LOAD_LIBRARY_SEARCH_SYSTEM32
 *   and NEVER `#include <dismapi.h>`/`DismApi.lib`/`find_library`: that
 *   header/import-lib pair ships only with the Windows ADK's "Deployment
 *   Tools" feature, absent from every self-hosted Windows CI runner (P92-1,
 *   tests/unit/fixtures/wave9/probes/the-rig-dism-findings.md). The eight
 *   resolved exports are the WHOLE DISM surface this plugin uses — no
 *   enable/disable/add/commit export is ever resolved (read-only by
 *   construction).
 * macOS / Linux: DISM has no equivalent — an honest unsupported row on
 *   every action, never a fabricated read.
 *
 * The actual DISM session lifecycle, the process-global single-flight
 * slot, and the bounded (timeout-protected) call around each DISM
 * invocation all live in agent-core's dism_bounded_call.{hpp,cpp} —
 * adversarial review C1 fix, Wave 9 PR9.2: a plugin-local detached worker
 * that outlives this plugin's own bounded shutdown quiesce would still be
 * executing plugin-resident code when the agent's teardown loop
 * FreeLibrary's this module at final agent shutdown (SIGTERM, service
 * stop, upgrade restart -- gated on stop_requested_, agent.cpp:3221; a
 * plain reconnect leaves the plugin loaded and never calls shutdown()).
 * See that file's header comment for the full rationale and the
 * agents/core/include/yuzu/agent/passwd_lookup.hpp (#3406) precedent it
 * mirrors. This file keeps only: parameter parsing/validation, the two
 * try_acquire_slot()/bounded-call entry-point calls, and turning the
 * returned Outcome into CommandContext output — none of which ever runs on
 * a thread that can outlive this plugin's own unload.
 *
 * Output is pipe-delimited via write_output():
 *   feature|<name>|<state>|<restart_required 1/0>
 *   feature_info|<name>|<display_name>|<state>|<restart_type>|<description>
 *   feature[_info]|unsupported|<os>:dism:unsupported
 *   feature[_info]|unavailable|<token>
 */

#include <yuzu/plugin.hpp>
#include <yuzu/string_utils.hpp>

#include <format>
#include <string>
#include <string_view>

#include "windows_optional_features_parsers.hpp" // agents/shared

#ifdef _WIN32

#include <yuzu/agent/dism_bounded_call.hpp>

#include <chrono>
#include <cstdio>
#include <optional>
#include <thread>
#include <unordered_set>

namespace wof_dism = yuzu::agent::dism;

#endif // _WIN32

namespace {

#ifdef _WIN32

int report_dism_outcome(yuzu::CommandContext& ctx, std::string_view action,
                        const wof_dism::Outcome& outcome) {
    switch (outcome.kind) {
    case wof_dism::Outcome::Kind::Ok:
        for (const auto& row : outcome.rows)
            ctx.write_output(row);
        return 0;
    case wof_dism::Outcome::Kind::ApiUnavailable:
        ctx.write_output(yuzu::wof::format_unavailable_row(action, "windows:dism:api_unavailable"));
        ctx.set_result_status(YUZU_RESULT_STATUS_UNAVAILABLE, YUZU_RESULT_COMPLETENESS_PARTIAL,
                              outcome.reason);
        return 0;
    case wof_dism::Outcome::Kind::InitializeFailed:
        ctx.write_output(yuzu::wof::format_unavailable_row(action, "windows:dism:initialize_failed"));
        ctx.set_result_status(YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL,
                              outcome.reason);
        return 0;
    case wof_dism::Outcome::Kind::OpenSessionFailed:
        ctx.write_output(
            yuzu::wof::format_unavailable_row(action, "windows:dism:open_session_failed"));
        ctx.set_result_status(YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL,
                              outcome.reason);
        return 0;
    case wof_dism::Outcome::Kind::GetFeaturesFailed:
        ctx.write_output(
            yuzu::wof::format_unavailable_row(action, "windows:dism:get_features_failed"));
        ctx.set_result_status(YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL,
                              outcome.reason);
        return 0;
    case wof_dism::Outcome::Kind::GetFeatureInfoFailed:
        ctx.write_output(
            yuzu::wof::format_unavailable_row(action, "windows:dism:get_feature_info_failed"));
        ctx.set_result_status(YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL,
                              outcome.reason);
        return 0;
    case wof_dism::Outcome::Kind::FeatureNotFound:
        ctx.write_output(yuzu::wof::format_unavailable_row(action, "windows:dism:feature_not_found"));
        ctx.set_result_status(YUZU_RESULT_STATUS_UNAVAILABLE, YUZU_RESULT_COMPLETENESS_FULL,
                              outcome.reason);
        return 0;
    case wof_dism::Outcome::Kind::AccessDenied:
        ctx.write_output(yuzu::wof::format_unavailable_row(action, "windows:dism:access_denied"));
        ctx.set_result_status(YUZU_RESULT_STATUS_PERMISSION_DENIED, YUZU_RESULT_COMPLETENESS_PARTIAL,
                              outcome.reason);
        return 0;
    case wof_dism::Outcome::Kind::Exception:
        ctx.write_output(yuzu::wof::format_unavailable_row(action, "windows:dism:exception"));
        ctx.set_result_status(YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL,
                              outcome.reason);
        return 0;
    }
    return 0;
}

/// SLOT PROTOCOL (peer H2, resolved): try_acquire_slot() runs BEFORE the
/// bounded call, on the DISPATCHING thread. busy/abandoned report and
/// return without ever calling DismInitialize. On `acquired`, the whole
/// DISM sequence runs -- bounded, in agent-core -- via run_list_bounded()/
/// run_info_bounded(); the Completed/TimedOut/Rejected dispatch below only
/// interprets their return value, never touches the slot itself (that
/// protocol now lives entirely in dism_bounded_call.cpp).
int do_windows_list(yuzu::CommandContext& ctx, yuzu::Params params) {
    if (!wof_dism::api_available()) {
        ctx.write_output(yuzu::wof::format_unavailable_row("list", "windows:dism:api_unavailable"));
        ctx.set_result_status(
            YUZU_RESULT_STATUS_UNAVAILABLE, YUZU_RESULT_COMPLETENESS_PARTIAL,
            "DismApi.dll or one of its eight required exports could not be resolved from System32");
        return 0;
    }

    const auto acquire = wof_dism::try_acquire_slot();
    if (acquire == yuzu::wof::DismSlot::Acquire::busy) {
        ctx.write_output(yuzu::wof::format_unavailable_row("list", "windows:dism:busy"));
        ctx.set_result_status(YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL,
                              "a DISM call is already in progress on this agent");
        return 0;
    }
    if (acquire == yuzu::wof::DismSlot::Acquire::abandoned) {
        ctx.write_output(yuzu::wof::format_unavailable_row("list", "windows:dism:abandoned"));
        ctx.set_result_status(
            YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL,
            "a previous DISM call timed out and its worker has not returned; the DISM API is "
            "still held by that worker; recovers when it returns, otherwise a service restart "
            "clears it");
        return 0;
    }

    std::optional<std::unordered_set<yuzu::wof::FeatureState>> filter;
    if (const auto state_param = params.get("state"); !state_param.empty())
        filter = yuzu::wof::parse_state_filter(state_param);

    const auto bounded = wof_dism::run_list_bounded(filter);

    if (bounded.status == wof_dism::BoundedStatus::TimedOut) {
        ctx.write_output(yuzu::wof::format_unavailable_row("list", "windows:dism:timeout"));
        ctx.set_result_status(YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL,
                              "DismGetFeatures did not return within the bounded timeout");
        return 0;
    }
    if (bounded.status == wof_dism::BoundedStatus::Rejected) {
        ctx.write_output(yuzu::wof::format_unavailable_row("list", "windows:dism:busy"));
        ctx.set_result_status(
            YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL,
            "the bounded-call outstanding-call ceiling rejected this DISM call before it started");
        return 0;
    }
    return report_dism_outcome(ctx, "list", bounded.outcome);
}

int do_windows_info(yuzu::CommandContext& ctx, const std::string& name) {
    if (!wof_dism::api_available()) {
        ctx.write_output(yuzu::wof::format_unavailable_row("info", "windows:dism:api_unavailable"));
        ctx.set_result_status(
            YUZU_RESULT_STATUS_UNAVAILABLE, YUZU_RESULT_COMPLETENESS_PARTIAL,
            "DismApi.dll or one of its eight required exports could not be resolved from System32");
        return 0;
    }

    const auto acquire = wof_dism::try_acquire_slot();
    if (acquire == yuzu::wof::DismSlot::Acquire::busy) {
        ctx.write_output(yuzu::wof::format_unavailable_row("info", "windows:dism:busy"));
        ctx.set_result_status(YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL,
                              "a DISM call is already in progress on this agent");
        return 0;
    }
    if (acquire == yuzu::wof::DismSlot::Acquire::abandoned) {
        ctx.write_output(yuzu::wof::format_unavailable_row("info", "windows:dism:abandoned"));
        ctx.set_result_status(
            YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL,
            "a previous DISM call timed out and its worker has not returned; the DISM API is "
            "still held by that worker; recovers when it returns, otherwise a service restart "
            "clears it");
        return 0;
    }

    const auto bounded = wof_dism::run_info_bounded(name);

    if (bounded.status == wof_dism::BoundedStatus::TimedOut) {
        ctx.write_output(yuzu::wof::format_unavailable_row("info", "windows:dism:timeout"));
        ctx.set_result_status(YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL,
                              "DismGetFeatureInfo did not return within the bounded timeout");
        return 0;
    }
    if (bounded.status == wof_dism::BoundedStatus::Rejected) {
        ctx.write_output(yuzu::wof::format_unavailable_row("info", "windows:dism:busy"));
        ctx.set_result_status(
            YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL,
            "the bounded-call outstanding-call ceiling rejected this DISM call before it started");
        return 0;
    }
    return report_dism_outcome(ctx, "info", bounded.outcome);
}

#else // !_WIN32

constexpr std::string_view kUnsupportedReason =
    "windows_optional_features is Windows-only (DISM); no Linux/macOS equivalent";

int mark_result_unsupported(yuzu::CommandContext& ctx, std::string_view action,
                            std::string_view token, std::string_view reason) {
    ctx.write_output(yuzu::wof::format_unsupported_row(action, token));
    ctx.set_result_status(YUZU_RESULT_STATUS_UNAVAILABLE, YUZU_RESULT_COMPLETENESS_PARTIAL, reason);
    return 0;
}

#endif // _WIN32

int do_list(yuzu::CommandContext& ctx, yuzu::Params params) {
#ifdef _WIN32
    return do_windows_list(ctx, params);
#elif defined(__APPLE__)
    (void)params;
    return mark_result_unsupported(ctx, "list", "macos:dism:unsupported", kUnsupportedReason);
#else
    (void)params;
    return mark_result_unsupported(ctx, "list", "linux:dism:unsupported", kUnsupportedReason);
#endif
}

int do_info(yuzu::CommandContext& ctx, yuzu::Params params) {
    // Validated identically on every OS, BEFORE any platform branch: an
    // invalid feature parameter never reaches DISM (or the unsupported-row
    // path) and always costs rc 1 with no downstream call, regardless of
    // whether this OS could ever have serviced the request.
    const auto raw_feature = params.get("feature");
    auto valid = yuzu::wof::validate_feature_name(raw_feature);
    if (!valid) {
        ctx.write_output(std::format("feature_info|invalid|invalid 'feature' parameter: '{}'",
                                     yuzu::util::safe_output_field(raw_feature)));
        return 1;
    }

#ifdef _WIN32
    return do_windows_info(ctx, *valid);
#elif defined(__APPLE__)
    return mark_result_unsupported(ctx, "info", "macos:dism:unsupported", kUnsupportedReason);
#else
    return mark_result_unsupported(ctx, "info", "linux:dism:unsupported", kUnsupportedReason);
#endif
}

// ── ABI4 capability declarations (#2204) ────────────────────────────────
//
// windows: DISM API via DismOpenSession(DISM_ONLINE_IMAGE) + DismGetFeatures/
// DismGetFeatureInfo, runtime-bound (never linked against DismApi.lib) --
// rung 1, native OS interface.
// linux/macos: DISM has no equivalent on either platform.
const YuzuActionDescriptor kActionDescriptors[] = {
    {"list",
     /* linux_leg   = */
     {YUZU_SUPPORT_UNSUPPORTED, 0, nullptr, "Windows-only: DISM has no Linux/macOS equivalent"},
     /* macos_leg   = */
     {YUZU_SUPPORT_UNSUPPORTED, 0, nullptr, "Windows-only: DISM has no Linux/macOS equivalent"},
     /* windows_leg = */
     {YUZU_SUPPORT_SUPPORTED, 1,
      "DISM API DismOpenSession(DISM_ONLINE_IMAGE) + DismGetFeatures/DismGetFeatureInfo",
      "verified live on the-rig under NT AUTHORITY\\SYSTEM, 2026-09-08"}},
    {"info",
     /* linux_leg   = */
     {YUZU_SUPPORT_UNSUPPORTED, 0, nullptr, "Windows-only: DISM has no Linux/macOS equivalent"},
     /* macos_leg   = */
     {YUZU_SUPPORT_UNSUPPORTED, 0, nullptr, "Windows-only: DISM has no Linux/macOS equivalent"},
     /* windows_leg = */
     {YUZU_SUPPORT_SUPPORTED, 1,
      "DISM API DismOpenSession(DISM_ONLINE_IMAGE) + DismGetFeatures/DismGetFeatureInfo",
      "verified live on the-rig under NT AUTHORITY\\SYSTEM, 2026-09-08"}},
};

} // namespace

class WindowsOptionalFeaturesPlugin final : public yuzu::Plugin {
public:
    std::string_view name() const noexcept override { return "windows_optional_features"; }
    std::string_view version() const noexcept override { return "1.0.0"; }
    std::string_view description() const noexcept override {
        return "Windows optional OS feature state (enabled/disabled/pending) via the DISM API";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {"list", "info", nullptr};
        return acts;
    }

    const YuzuActionDescriptor* action_descriptors() const noexcept override {
        return kActionDescriptors;
    }
    size_t action_descriptor_count() const noexcept override {
        return sizeof(kActionDescriptors) / sizeof(kActionDescriptors[0]);
    }

    yuzu::Result<void> init(yuzu::PluginContext& /*ctx*/) override { return {}; }

    /**
     * Short BOUNDED quiesce (plugin.hpp:245), mirroring power_health_plugin
     * .cpp's shutdown() pattern: wait up to 2x kTimeout for the DISM slot
     * to drain, then log the residue and return -- never an unbounded
     * join. Reads agent-core's slot_in_flight() rather than touching a
     * plugin-local slot: the slot itself lives in agent-core now (C1 fix,
     * Wave 9 PR9.2 -- see dism_bounded_call.hpp), so a worker still
     * draining past this quiesce is running agent-core code, never
     * this plugin's, regardless of how this loop resolves. On non-Windows
     * the slot doesn't exist and there is nothing to wait on.
     *
     * This 34s worst case sits inside agent.cpp's final-teardown block,
     * which neither shutdown watchdog (W1/W2, agent.cpp:~100-152) currently
     * covers -- a pre-existing gap tracked as #3756 item 5, not introduced
     * here, but this plugin is one of the larger named contributors to it
     * (governance Gate 6 sre review, Wave 9 PR9.2). On SERVICE_CONTROL_STOP
     * this only delays a clean exit (service_win.cpp reports one
     * SERVICE_STOP_PENDING with a 30s hint and no checkpoint-bumping
     * thread); on SERVICE_CONTROL_SHUTDOWN (reboot) the OS's own
     * WaitToKillServiceTimeout applies instead and is outside this
     * process's control.
     */
    void shutdown(yuzu::PluginContext& /*ctx*/) noexcept override {
#ifdef _WIN32
        const auto deadline = std::chrono::steady_clock::now() + 2 * wof_dism::kTimeout;
        while (wof_dism::slot_in_flight() && std::chrono::steady_clock::now() < deadline) {
            std::this_thread::sleep_for(std::chrono::milliseconds(20));
        }
        if (wof_dism::slot_in_flight()) {
            std::fprintf(stderr, "windows_optional_features: shutdown quiesce timed out with a "
                                 "DISM call still outstanding\n");
        }
#endif
    }

    // No exception may escape this function -- the extern "C" plugin-ABI
    // trampoline (sdk/include/yuzu/plugin.hpp's YUZU_PLUGIN_EXPORT) forwards
    // straight into this call with no catch of its own, and
    // .claude/routed-concerns.md's windows_optional_features row is
    // explicit: "never throws across the ABI". agent.cpp's remote
    // command-dispatch path independently wraps target->execute() as a
    // defence-in-depth backstop (added after a real 2026-05-12 incident:
    // agent_logging.get_log threw filesystem_error and brought the agent
    // down), but LocalDispatcher -- used by
    // tests/unit/test_windows_optional_features_local_dispatcher.cpp, and
    // by the daily-sync framework's other plugin consumers -- has no such
    // backstop, so this plugin owns its own containment rather than relying
    // on a caller. Precedent: autoruns_plugin.cpp's execute() wraps its
    // whole body the same way.
    int execute(yuzu::CommandContext& ctx, std::string_view action, yuzu::Params params) override {
        try {
            if (action == "list")
                return do_list(ctx, params);
            if (action == "info")
                return do_info(ctx, params);

            ctx.write_output(std::format("unknown action: {}", action));
            return 1;
        } catch (const std::exception& e) {
            ctx.write_output(yuzu::wof::format_unavailable_row(action, "windows:dism:exception"));
            ctx.set_result_status(YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL,
                                  std::string{"unhandled exception: "} +
                                      yuzu::util::safe_output_field(e.what()));
            return 1;
        } catch (...) {
            ctx.write_output(yuzu::wof::format_unavailable_row(action, "windows:dism:exception"));
            ctx.set_result_status(YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL,
                                  "unhandled exception of unknown type inside execute()");
            return 1;
        }
    }
};

YUZU_PLUGIN_EXPORT(WindowsOptionalFeaturesPlugin)
