#pragma once

/// @file workflows_page_render.hpp
/// Pure renderers for the Workflows page (`GET /fragments/workflows` and
/// `GET /fragments/schedules?view=page`).
///
/// No store, no clock, no request, no gate: the route maps store rows into the view structs
/// below and decides, per row, what the caller may see. A field the caller may not see is
/// left at its default in the view and the renderer additionally refuses to print it unless
/// the row says `owner` -- so a route bug cannot widen a non-owner's schedule row. Every value
/// that reaches the markup goes through `html_escape`; no raw JSON is ever rendered.
///
/// Markup contract (`yuzu-operate.js` reads it):
///   definitions: <div class="ops-list" data-state="ok|empty" data-count="N" data-truncated="0|1">
///                  <div class="tw"><table class="wf">... <tr class="row" data-workflow-id
///                    data-workflow-name> ...</table></div>
///                  <div class="ops-steps-store" hidden>
///                    <div data-steps-for="<id>" data-name="<name>"><ol class="ops-steps">...
///                  [<div class="ops-foot hint">Showing the first 100 workflows.</div>]
///                </div>
///   schedules:   <div class="ops-list" data-state data-count data-truncated>
///                  [<div class="note warn">Showing a partial list ...</div>]
///                  <div class="tw"><table class="sc">... <tr class="row" data-schedule-id
///                    data-owner="0|1"> ...</table></div>
///
/// Runs (WF-2): `GET /fragments/workflow-runs` is a list of run rows (status pill, workflow,
/// started, duration) used for the newest-run-per-workflow patch of the definitions table and
/// for the "Recent runs" disclosure; `GET /fragments/workflow-runs/{id}` is one run's step
/// table. Both are metadata the caller may see: no agent id is ever printed, an error text only
/// when it is a plain string, and a confined caller's step pill reads "Dispatched (run-wide)".
///   runs:   <div class="ops-list" data-state data-count data-confined="0|1">
///             <div class="tw"><table class="runs">... <tr class="row" data-run-id
///               data-workflow-id data-status> <td data-c="status"> <td data-c="started"> ...
///   detail: <div data-slot="run" data-run-id data-run-status data-confined> <div class="kvl">
///             ...</div><ol class="ops-steps">...
///
/// The step list of every listed workflow rides in the definitions fragment itself (a hidden
/// store the controller clones from), so selecting a row needs no second request and no
/// second read of the definitions.

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::server::operate_pages {

struct WorkflowStepView {
    int index{0};
    std::string instruction_id;
    std::string label;
    std::string condition;
    std::string foreach_source;
    std::string on_failure; ///< "", "abort", "continue" or "skip_remaining"
    int retry_count{0};
    int retry_delay_seconds{0};
};

struct WorkflowRowView {
    std::string id;
    std::string name;
    std::string description;
    std::vector<WorkflowStepView> steps;
};

struct WorkflowListView {
    std::vector<WorkflowRowView> rows;
    bool truncated{false}; ///< more definitions exist than the page shows
    int page_cap{100};     ///< the number of rows the page shows at most
};

[[nodiscard]] std::string render_workflows_list(const WorkflowListView& v);

/// The step policy pill: abort (also the empty default), continue, skip_remaining; any other
/// value is shown verbatim on an idle pill, never guessed into one of the three.
struct StepPolicy {
    std::string cls;
    std::string label;
};
[[nodiscard]] StepPolicy step_policy(std::string_view on_failure);

struct ScheduleRowView {
    std::string id;
    std::string name;
    std::string definition_id;
    std::string frequency_type;
    bool enabled{false};
    int64_t next_execution_at{0};
    int64_t last_executed_at{0};
    int execution_count{0};
    bool owner{false}; ///< the viewing session created this schedule (computed by the route)
    bool targeted{false}; ///< scope_expression is non-empty; the only fact a non-owner sees
    // Owner rows only; the renderer prints none of these for a non-owner row.
    int interval_minutes{0};
    std::string scope_expression;
    bool requires_approval{false};
    int parameter_count{0};
};

struct ScheduleListView {
    std::vector<ScheduleRowView> rows;
    bool truncated{false}; ///< the store's list cap dropped schedules
};

/// "Once", "Every N minutes", "Daily (every 24 hours)", "Weekly (every 7 days)",
/// "Monthly (every 30 days)": the cadence the scheduler really applies (it ignores
/// time-of-day, weekday and day-of-month). `interval_minutes` <= 0 means the caller may not
/// see the interval, so an interval schedule reads "Repeats on an interval". An unknown
/// frequency is shown verbatim.
[[nodiscard]] std::string cadence_text(std::string_view frequency_type, int interval_minutes);

[[nodiscard]] std::string render_schedules_page(const ScheduleListView& v);

struct RunRowView {
    std::string id;
    std::string workflow_id;
    std::string workflow_name;
    bool workflow_deleted{false};
    std::string status;
    int64_t started_at{0};
    int64_t completed_at{0};
};

struct RunListView {
    std::vector<RunRowView> rows;
    bool confined{false}; ///< the caller's reads are narrowed to its device scope
    bool truncated{false}; ///< latest_per_workflow matched more workflows than the cap allowed
};

[[nodiscard]] std::string render_runs_list(const RunListView& v);

/// Run status pill: pending (idle) Pending, running (info) Running, completed (ok) Completed,
/// failed (bad) Failed, cancelled (idle) Cancelled; any other value verbatim on an idle pill.
[[nodiscard]] StepPolicy run_status_pill(std::string_view status);

/// Step state pill: pending Waiting, running Running, success Dispatched (the command was sent;
/// "Dispatched (run-wide)" for a confined caller, who cannot tell whether its own devices were
/// reached), failed Failed, skipped Skipped.
[[nodiscard]] StepPolicy run_step_pill(std::string_view status, bool confined);

/// "-" unless both instants are set and ordered; else "45s", "1m 12s" or "2h 3m".
[[nodiscard]] std::string duration_text(int64_t started_at, int64_t completed_at);

struct RunStepView {
    int index{0};
    std::string title; ///< the definition's label, else the instruction id
    std::string status;
    int64_t started_at{0};
    int64_t completed_at{0};
    /// The step result as the confined projection dumped it ("" when none). Only known shapes
    /// are read from it: `{"reason":<known text>}`, `{"error":<string>}`, `agents_reached`.
    std::string result_json;
};

struct RunDetailView {
    std::string id;
    std::string workflow_id;
    std::string workflow_name; ///< "" when the definition is gone: the id is shown
    std::string status;
    int64_t started_at{0};
    int64_t completed_at{0};
    bool confined{false};
    int device_count{-1}; ///< size of the (confined) agent id array; -1 = unknown
    std::vector<RunStepView> steps;
};

[[nodiscard]] std::string render_run_detail(const RunDetailView& v);

inline constexpr std::string_view kRunsEmptyNote = "No runs yet.";
inline constexpr std::string_view kRunsConfinedEmptyNote =
    "No runs include devices in your scope.";
inline constexpr std::string_view kRunsDeniedNote =
    "You do not have permission to view workflow runs.";
inline constexpr std::string_view kRunsDegradedNote = "Run history unavailable, retry shortly.";
inline constexpr std::string_view kRunsInvalidNote = "Unknown or invalid run filter.";

inline constexpr std::string_view kWorkflowsEmptyNote = "No workflows yet.";
inline constexpr std::string_view kWorkflowsEmptyHint = "Ask an administrator to add one.";
inline constexpr std::string_view kWorkflowsDeniedNote =
    "You do not have permission to view workflows.";
inline constexpr std::string_view kWorkflowsDegradedNote =
    "Workflow store unavailable, retry shortly. This is not an empty list.";
inline constexpr std::string_view kSchedulesEmptyNote = "No schedules configured.";
inline constexpr std::string_view kSchedulesDeniedNote =
    "You do not have permission to view schedules.";
inline constexpr std::string_view kSchedulesDegradedNote =
    "Schedule list temporarily unavailable - retry shortly.";
inline constexpr std::string_view kSchedulesPartialNote =
    "Showing a partial list - more schedules exist than can be displayed.";

} // namespace yuzu::server::operate_pages
