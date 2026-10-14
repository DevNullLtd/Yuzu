#include "workflow_execution_list_model.hpp"

#include <algorithm>
#include <array>
#include <limits>
#include <optional>
#include <ranges>

namespace yuzu::server {

namespace {

constexpr std::array<std::string_view, 5> kStatuses{"pending", "running", "completed", "failed",
                                                    "cancelled"};
constexpr std::array<std::string_view, 7> kKeys{"workflow_id", "status", "since", "until",
                                                "limit",       "cursor", "latest_per_workflow"};
constexpr std::string_view kAllowed =
    "allowed: workflow_id, status, since, until, limit, cursor, latest_per_workflow";

bool is_workflow_id(std::string_view v) {
    return !v.empty() && v.size() <= kWorkflowIdMaxLen &&
           std::ranges::all_of(v, [](char c) {
               return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') ||
                      c == '_' || c == '-';
           });
}

// What both transports hand over once each has read its own wire types. Everything is optional:
// absent means "not supplied", which is different from supplied-and-empty (refused).
struct Raw {
    std::optional<std::string> workflow_id, status, cursor;
    std::optional<std::int64_t> since, until, limit;
    std::optional<bool> latest;
};

// The one rule set both parsers share.
std::expected<WorkflowExecutionListQuery, std::string> finish(const Raw& r) {
    WorkflowExecutionListQuery q;
    if (r.workflow_id) {
        if (!is_workflow_id(*r.workflow_id))
            return std::unexpected("workflow_id must be 1-128 characters of A-Z a-z 0-9 _ -");
        q.workflow_id = *r.workflow_id;
    }
    if (r.status) {
        if (std::ranges::find(kStatuses, *r.status) == kStatuses.end())
            return std::unexpected(
                "status must be one of pending, running, completed, failed, cancelled");
        q.status = *r.status;
    }
    const auto in_range = [](const std::optional<std::int64_t>& v) {
        return !v || (*v >= 0 && *v <= kWorkflowExecutionTimeMax);
    };
    if (!in_range(r.since) || !in_range(r.until))
        return std::unexpected("since and until must be epoch seconds between 0 and 2^53");
    q.since = r.since;
    q.until = r.until;
    if (q.since && q.until && *q.since > *q.until)
        return std::unexpected("since must not be after until");
    if (r.limit) {
        if (*r.limit < 1)
            return std::unexpected("limit must be an integer of at least 1");
        q.limit = static_cast<int>(std::min<std::int64_t>(*r.limit, kWorkflowExecutionListMax));
    }
    q.latest_per_workflow = r.latest.value_or(false);
    if (r.cursor) {
        if (q.latest_per_workflow)
            return std::unexpected("cursor cannot be combined with latest_per_workflow");
        auto at = keyset::decode_cursor(kWorkflowExecutionCursorPrefix, *r.cursor);
        if (!at)
            return std::unexpected("invalid cursor");
        q.after = std::move(*at);
    }
    return q;
}

} // namespace

std::expected<WorkflowExecutionListQuery, std::string>
parse_workflow_execution_list_params(const std::vector<RawParam>& params) {
    Raw raw;
    // Refuse before reading any value: an unknown key must not be half-applied, and a repeated key
    // has no single meaning to pick.
    for (const auto& key : params | std::views::keys) {
        if (std::ranges::find(kKeys, key) == kKeys.end())
            return std::unexpected("unsupported query parameter (" + std::string(kAllowed) + ")");
        if (std::ranges::count(params, key, &RawParam::first) > 1)
            return std::unexpected("repeated query parameter: " + key);
    }
    for (const auto& [key, value] : params) {
        if (key == "workflow_id") {
            raw.workflow_id = value;
        } else if (key == "status") {
            raw.status = value;
        } else if (key == "cursor") {
            raw.cursor = value;
        } else if (key == "latest_per_workflow") {
            if (value != "true" && value != "false")
                return std::unexpected("latest_per_workflow must be true or false");
            raw.latest = value == "true";
        } else {
            // since / until / limit: a whole-string decimal; the range rules are `finish`'s.
            const auto n = keyset::parse_int(value, std::numeric_limits<std::int64_t>::min(),
                                             std::numeric_limits<std::int64_t>::max());
            if (!n)
                return std::unexpected(key + " must be an integer");
            (key == "since" ? raw.since : key == "until" ? raw.until : raw.limit) = *n;
        }
    }
    return finish(raw);
}

std::expected<WorkflowExecutionListQuery, std::string>
parse_workflow_execution_list_args(const nlohmann::json& args) {
    if (args.is_null())
        return WorkflowExecutionListQuery{};
    if (!args.is_object())
        return std::unexpected("arguments must be an object");
    Raw raw;
    for (const auto& [key, v] : args.items()) {
        const auto want_string = [&](std::optional<std::string>& dst) -> std::optional<std::string> {
            if (!v.is_string())
                return key + " must be a string";
            dst = v.get<std::string>();
            return std::nullopt;
        };
        const auto want_int = [&](std::optional<std::int64_t>& dst) -> std::optional<std::string> {
            // An unsigned above INT64_MAX is refused, never wrapped.
            if (!v.is_number_integer() ||
                (v.is_number_unsigned() &&
                 v.get<std::uint64_t>() >
                     static_cast<std::uint64_t>(std::numeric_limits<std::int64_t>::max())))
                return key + " must be an integer";
            dst = v.get<std::int64_t>();
            return std::nullopt;
        };
        std::optional<std::string> err;
        if (key == "workflow_id")
            err = want_string(raw.workflow_id);
        else if (key == "status")
            err = want_string(raw.status);
        else if (key == "cursor")
            err = want_string(raw.cursor);
        else if (key == "since")
            err = want_int(raw.since);
        else if (key == "until")
            err = want_int(raw.until);
        else if (key == "limit")
            err = want_int(raw.limit);
        else if (key == "latest_per_workflow") {
            if (!v.is_boolean())
                err = "latest_per_workflow must be a boolean";
            else
                raw.latest = v.get<bool>();
        } else
            err = "unsupported argument (" + std::string(kAllowed) + ")";
        if (err)
            return std::unexpected(*err);
    }
    return finish(raw);
}

nlohmann::json workflow_execution_summary_json(const WorkflowExecutionSummary& s) {
    return nlohmann::json{
        {"id", s.id},
        {"workflow_id", s.workflow_id},
        {"workflow_name", s.workflow_name},
        {"workflow_deleted", s.workflow_deleted},
        {"status", s.status},
        {"current_step", s.current_step},
        {"started_at", s.started_at},
        {"completed_at", s.completed_at},
    };
}

nlohmann::json workflow_execution_rows_json(const WorkflowExecutionPage& page) {
    nlohmann::json rows = nlohmann::json::array();
    for (const auto& s : page.rows)
        rows.push_back(workflow_execution_summary_json(s));
    return rows;
}

nlohmann::json workflow_execution_next_cursor_json(const WorkflowExecutionPage& page) {
    if (!page.next)
        return nullptr;
    return keyset::encode_cursor(kWorkflowExecutionCursorPrefix, *page.next);
}

} // namespace yuzu::server
