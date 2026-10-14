#pragma once

/// @file executions_page_render.hpp
/// Pure renderers for the Executions page (`GET /fragments/executions?view=page` and
/// `GET /fragments/executions/{id}/detail?view=page`).
///
/// No store, no clock, no request, no gate: the route hands over rows that are ALREADY
/// projected for the caller (a confined caller's counters recomputed from in-scope devices,
/// scope and parameters replaced by the redaction constant), so nothing here can widen what
/// a caller sees -- the structs carry only what the route passed. Every value that reaches
/// the markup goes through `html_escape`.
///
/// Markup contract (O2 extends it, `yuzu-operate.js` reads it):
///   list:     <div class="ops-list" data-state="ok|empty" data-count="N" data-confined="0|1"
///                  data-truncated="0|1"> <div class="tw"><table class="ex"> ...
///               <tr class="row" data-execution-id data-execution-status data-def> ...
///   selected: <div data-slot="selected" data-execution-id data-execution-status
///                  data-confined="0|1"> <div class="hd">...</div><div class="kvl">...</div>
///
/// The detail panel fields (scope, parameters, ids) appear in full ONLY in the selected
/// panel; the list row carries the status, a clipped result preview and nothing else large.

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::server::operate_pages {

/// The pill a status renders as. `cls` is a `.pill` modifier (ok|warn|bad|info|idle).
struct ExecState {
    std::string cls;
    std::string label;
    std::string title; ///< hover text; always ends `status=<raw>`
};

/// running -> info "Running"; succeeded -> ok "Succeeded"; cancelled -> idle "Cancelled";
/// pending -> warn "Pending"; completed with failures -> bad when every responder failed,
/// else warn, label "<N> failed"; completed without -> ok "Completed"; anything this build
/// does not know -> idle with the raw status as the label (never a guessed colour).
[[nodiscard]] ExecState derive_state(std::string_view status, int agents_failure,
                                     int agents_responded);

struct ExecRow {
    std::string id;
    std::string definition_id;
    std::string definition_name; ///< display name, else the id (the route resolves it)
    std::string status;
    std::string dispatched_by;
    std::string last_error_detail;
    std::string rerun_of;
    int agents_targeted{0};
    int agents_responded{0};
    int agents_success{0};
    int agents_failure{0};
    int64_t dispatched_at{0}; ///< epoch seconds
};

struct ExecListView {
    std::vector<ExecRow> rows;
    bool confined{false};  ///< the caller's view is scope-limited
    bool truncated{false}; ///< older executions exist beyond the page cap
    bool filtered{false};  ///< a status or instruction filter is active
};

/// The list fragment (see the contract above).
[[nodiscard]] std::string render_exec_list(const ExecListView& v);

struct ExecSelectedView {
    ExecRow row;
    std::string scope_expression;  ///< already the redaction constant when confined
    std::string parameter_values;  ///< ditto
    int64_t completed_at{0};
    bool confined{false};
    int can_cancel{-1}; ///< -1 not probed (attribute omitted), 0 no grant, 1 holds Execute
};

/// The "Selected execution" panel body (see the contract above).
[[nodiscard]] std::string render_exec_selected(const ExecSelectedView& v);

/// One device's result row (agent_exec_status), already filtered to the caller's scope.
struct DeviceRow {
    std::string agent_id;
    std::string status; ///< wire vocabulary: success|failure|timeout|rejected|running|pending
    std::string error_detail;
    int exit_code{0};
    int64_t dispatched_at{0}; ///< epoch seconds
    int64_t completed_at{0};
};

/// One stored response row, already filtered to the caller's scope.
struct DeviceResponse {
    std::string agent_id;
    std::string output;
    std::string error_detail;
    int status{0};
    int64_t timestamp{0};   ///< epoch seconds
    int64_t received_ms{0}; ///< server receipt time; 0 for a legacy row
};

enum class ResponsesState { kOk, kDegraded, kUnavailable };

/// Page-view caps: the per-device table and the collapsed responses list stay bounded no
/// matter how many devices a run targets (every refresh re-sends the fragment). The agent
/// grid buckets into deciles above `kDeviceGridBucketThreshold`, as the drawer does.
inline constexpr std::size_t kDeviceTableCap = 500;
inline constexpr std::size_t kDeviceResponsesCap = 50;
inline constexpr std::size_t kDeviceGridBucketThreshold = 1024;

struct ExecDevicesView {
    std::string execution_id;
    std::string definition_name;
    std::vector<DeviceRow> rows;
    /// The run's dispatched-device count. Absent for a confined caller: it would subtract
    /// to an out-of-scope count, so the total is the visible rows and "not yet" is hidden.
    std::optional<int> targeted;
    std::vector<DeviceResponse> responses;
    std::size_t responses_total{0}; ///< before the cap
    ResponsesState responses_state{ResponsesState::kOk};
};

/// The "Device results" slot body of `GET /fragments/executions/{id}/detail?view=page`:
/// `<div data-slot="devices">` with the KPI strip (`#exec-kpi-{id}`), agent grid, per-device
/// table and collapsed responses. The live-update stamps of the ladder doc are kept
/// (`.exec-kpi-value`, `.agent-cell[data-agent-id][data-exec-id]`,
/// `#per-agent-row-{exec}-{agent}`, `.per-agent-status`, `.per-agent-exit-code`).
[[nodiscard]] std::string render_exec_devices(const ExecDevicesView& v);

inline constexpr std::string_view kExecutionsEmptyNote = "No executions yet.";
inline constexpr std::string_view kExecutionsFilteredEmptyNote =
    "No executions match these filters.";
inline constexpr std::string_view kExecutionsConfinedEmptyNote =
    "No executions visible in your scope.";
inline constexpr std::string_view kExecutionsUnknownFilterNote = "Unknown filter.";

} // namespace yuzu::server::operate_pages
