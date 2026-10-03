#include "result_set_routes.hpp"

#include "authz_model.hpp" // #4983 -- authz::in_scope
#include "http_route_sink.hpp"
#include "mcp_input_bounds.hpp" // #4983 Gate 3 SHOULD -- kResultSetDeviceIdMaxLen
#include "rest_audit.hpp" // detail::try_persist_audit (#5047 Gate 8 fix round, UP-10)
#include "result_set_store.hpp"
#include "result_sets_ui.hpp"

#include <nlohmann/json.hpp>
#include <spdlog/spdlog.h>

#include <cstddef>
#include <format>
#include <iterator>
#include <string>
#include <unordered_set>
#include <vector>

namespace yuzu::server::result_set {

void register_result_set_routes(HttpRouteSink& sink, Deps deps) {
    // -- Result Sets fragment API (scope walking, capability §30) -----------

    // Owner-checked read shared by every fragment mutation below: a DB
    // error is treated IDENTICALLY to "not found or not owned" — a
    // mutation (pin/unpin/delete) must never proceed on a degraded
    // ownership read (ADR-0036 fail-closed authoritative-read contract).
    // Collapses ResultSetStore::get's std::expected<optional<...>,...>
    // into a plain optional so every call site below is unchanged from its
    // pre-widening shape. Moved verbatim from server.cpp (#2542 PR-5) — a
    // local closure with no ServerImpl dependency beyond the store, never a
    // ServerImpl method, so no second-caller risk in this move.
    auto rs_get_owned = [deps](const std::string& id,
                               const std::string& owner) -> std::optional<ResultSet> {
        if (!deps.store)
            return std::nullopt;
        auto row = deps.store->get(id);
        if (!row || !row->has_value() || (*row)->owner_principal != owner)
            return std::nullopt;
        return **row;
    };

    // #5047: the C8 tier/approval belt, applied to the 4 mutating fragments
    // below (pin/unpin/delete/create) even though this whole module is
    // ownership-only by design (no `perm_fn`/RBAC gate) — these are plain
    // HTTP endpoints reachable with any Bearer token, not cookie-session-only,
    // so an MCP-tiered bearer could otherwise reach the identical mutation
    // its `/api/v1/result-sets` JSON twin now blocks. See
    // `Deps::TierPolicyFn`'s doc comment for the unwired-fn contract.
    auto tier_ok = [deps](const httplib::Request& req, httplib::Response& res,
                          const auth::Session& session, const std::string& securable_type,
                          const std::string& operation) -> bool {
        if (deps.tier_policy_fn)
            return deps.tier_policy_fn(req, res, session, securable_type, operation);
        if (!session.mcp_tier.empty()) {
            // Same rule as the REST twin (rest_api_v1.cpp): a degraded
            // security control must leave an evidence trail, not just a
            // test-covered response (#5047 governance fix round). Routed
            // through try_persist_audit (not a bare deps.audit_fn call, Gate 8
            // UP-10): this handler installs no exception_handler_, so an
            // audit sink that throws must not be allowed to replace the
            // intended 503 with httplib's bare, undetailed default 500.
            (void)detail::try_persist_audit(deps.audit_fn, req, "result_set.tier_policy_unavailable",
                                            "failure", "ResultSet", "",
                                            "tier-policy check misconfigured (unwired TierPolicyFn)");
            res.status = 503;
            res.set_content(
                R"({"error":{"code":503,"message":"tier-policy check misconfigured"}})",
                "application/json");
            return false;
        }
        return true;
    };

    // Owner-scoped sidebar list.
    //
    // guardian-confinement-2298 PR3 §3e: every result-set fragment here is
    // require_auth-only, keyed on `session->username` — but that username
    // is the MINTING principal's, not the individual token's own service
    // scope. A service-scoped token therefore reaches every result set the
    // minter (or any OTHER service token that same minter holds) has
    // created/pinned — cross-service reach beyond this token's own intended
    // cohort. Denied all six (one read here, detail below, plus
    // pin/unpin/delete/create).
    sink.Get(
        "/fragments/result-sets/sidebar",
        [deps](const httplib::Request& req, httplib::Response& res) {
            if (deps.deny_service_scoped_fn(
                    req, res, "result_set.sidebar.access_denied",
                    "service-scoped tokens may not read the result-set sidebar", "ResultSet", ""))
                return;
            auto session = deps.auth_fn(req, res);
            if (!session)
                return;
            if (!deps.store) {
                res.set_content("", "text/html; charset=utf-8");
                return;
            }
            std::string next;
            std::string selected =
                req.has_param("selected") ? req.get_param_value("selected") : "";
            auto sets = deps.store->list_by_owner(session->username, "", 200, next);
            res.set_content(render_result_sets_sidebar(sets, selected),
                            "text/html; charset=utf-8");
        });

    // Detail pane for one set (owner-checked).
    sink.Get(
        R"(/fragments/result-sets/(rs_[0-9a-f]+)/detail)",
        [deps, rs_get_owned](const httplib::Request& req, httplib::Response& res) {
            if (deps.deny_service_scoped_fn(
                    req, res, "result_set.detail.access_denied",
                    "service-scoped tokens may not read result-set detail", "ResultSet",
                    req.matches[1].str()))
                return;
            auto session = deps.auth_fn(req, res);
            if (!session)
                return;
            auto id = req.matches[1].str();
            auto row = rs_get_owned(id, session->username);
            if (!row) {
                res.set_content(render_result_set_detail_empty(),
                                "text/html; charset=utf-8");
                return;
            }
            auto chain = deps.store->lineage(id, session->username);
            res.set_content(render_result_set_detail(*row, chain), "text/html; charset=utf-8");
        });

    // Pin / unpin — return the refreshed detail and trigger a sidebar reload.
    auto rs_detail_after = [deps, rs_get_owned](const std::string& id, const std::string& owner,
                                                httplib::Response& res) {
        auto row = rs_get_owned(id, owner);
        if (!row) {
            res.set_content(render_result_set_detail_empty(), "text/html; charset=utf-8");
            return;
        }
        auto chain = deps.store->lineage(id, owner);
        res.set_header("HX-Trigger", "resultSetsChanged");
        res.set_content(render_result_set_detail(*row, chain), "text/html; charset=utf-8");
    };

    sink.Post(
        R"(/fragments/result-sets/(rs_[0-9a-f]+)/pin)",
        [deps, rs_detail_after, rs_get_owned, tier_ok](const httplib::Request& req,
                                              httplib::Response& res) {
            if (deps.deny_service_scoped_fn(req, res, "result_set.pin.access_denied",
                                            "service-scoped tokens may not pin result sets",
                                            "ResultSet", req.matches[1].str()))
                return;
            auto session = deps.auth_fn(req, res);
            if (!session)
                return;
            if (!tier_ok(req, res, *session, "Infrastructure", "Write"))
                return;
            if (!deps.store)
                return;
            auto id = req.matches[1].str();
            auto row = rs_get_owned(id, session->username);
            if (!row) {
                res.set_content(render_result_set_detail_empty(), "text/html; charset=utf-8");
                return;
            }
            auto pinned = deps.store->pin(id);
            if (!pinned) {
                // Don't audit a success that didn't happen, and tell the
                // operator why (review merged_bug_009). PinLimit is the
                // 50-pin cap; otherwise a transient store error.
                deps.audit_fn(req, "result_set.pin",
                              pinned.error() == ResultSetError::PinLimit ? "denied" : "failure",
                              "ResultSet", id, to_string(pinned.error()));
                res.set_header(
                    "HX-Trigger",
                    nlohmann::json{{"showToast",
                                    {{"level", "error"}, {"message", to_string(pinned.error())}}}}
                        .dump());
                auto chain = deps.store->lineage(id, session->username);
                res.set_content(render_result_set_detail(*row, chain),
                                "text/html; charset=utf-8");
                return;
            }
            deps.audit_fn(req, "result_set.pin", "success", "ResultSet", id, "");
            rs_detail_after(id, session->username, res);
        });

    sink.Post(
        R"(/fragments/result-sets/(rs_[0-9a-f]+)/unpin)",
        [deps, rs_detail_after, rs_get_owned, tier_ok](const httplib::Request& req,
                                              httplib::Response& res) {
            if (deps.deny_service_scoped_fn(req, res, "result_set.unpin.access_denied",
                                            "service-scoped tokens may not unpin result sets",
                                            "ResultSet", req.matches[1].str()))
                return;
            auto session = deps.auth_fn(req, res);
            if (!session)
                return;
            if (!tier_ok(req, res, *session, "Infrastructure", "Write"))
                return;
            if (!deps.store)
                return;
            auto id = req.matches[1].str();
            auto row = rs_get_owned(id, session->username);
            if (!row) {
                res.set_content(render_result_set_detail_empty(), "text/html; charset=utf-8");
                return;
            }
            auto unpinned = deps.store->unpin(id);
            if (!unpinned) {
                deps.audit_fn(req, "result_set.unpin", "failure", "ResultSet", id,
                              to_string(unpinned.error()));
                res.set_header("HX-Trigger",
                               nlohmann::json{{"showToast",
                                               {{"level", "error"},
                                                {"message", to_string(unpinned.error())}}}}
                                   .dump());
                auto chain = deps.store->lineage(id, session->username);
                res.set_content(render_result_set_detail(*row, chain),
                                "text/html; charset=utf-8");
                return;
            }
            deps.audit_fn(req, "result_set.unpin", "success", "ResultSet", id, "");
            rs_detail_after(id, session->username, res);
        });

    sink.Post(
        R"(/fragments/result-sets/(rs_[0-9a-f]+)/delete)",
        [deps, rs_get_owned, tier_ok](const httplib::Request& req, httplib::Response& res) {
            if (deps.deny_service_scoped_fn(req, res, "result_set.delete.access_denied",
                                            "service-scoped tokens may not delete result sets",
                                            "ResultSet", req.matches[1].str()))
                return;
            auto session = deps.auth_fn(req, res);
            if (!session)
                return;
            if (!tier_ok(req, res, *session, "Infrastructure", "Delete"))
                return;
            if (!deps.store)
                return;
            auto id = req.matches[1].str();
            auto row = rs_get_owned(id, session->username);
            if (!row) {
                res.set_content(render_result_set_detail_empty(), "text/html; charset=utf-8");
                return;
            }
            auto del = deps.store->delete_set(id);
            if (!del) {
                // Pinned sets must be unpinned first — re-render the detail
                // so the operator sees why nothing was deleted.
                auto chain = deps.store->lineage(id, session->username);
                res.set_content(render_result_set_detail(*row, chain),
                                "text/html; charset=utf-8");
                return;
            }
            deps.audit_fn(req, "result_set.delete", "success", "ResultSet", id, "");
            res.set_header("HX-Trigger", "resultSetsChanged");
            res.set_content(render_result_set_detail_empty(), "text/html; charset=utf-8");
        });

    // Create from pasted device IDs (CSV import) — returns refreshed sidebar.
    sink.Post(
        "/fragments/result-sets/create",
        [deps, tier_ok](const httplib::Request& req, httplib::Response& res) {
            if (deps.deny_service_scoped_fn(req, res, "result_set.create.access_denied",
                                            "service-scoped tokens may not create result sets",
                                            "ResultSet", ""))
                return;
            auto session = deps.auth_fn(req, res);
            if (!session)
                return;
            if (!tier_ok(req, res, *session, "Infrastructure", "Write"))
                return;
            if (!deps.store)
                return;
            CreateRequest cr;
            cr.owner_principal = session->username;
            cr.name = req.has_param("name") ? req.get_param_value("name") : "";
            cr.source_kind = std::string(source_kind::kManualCurate);
            cr.source_payload = R"({"note":"dashboard CSV import"})";

            std::vector<std::string> members;
            // Gate 3 SHOULD (cpp-expert, #4983 fix round): bound each pasted
            // entry to MCP's own kResultSetDeviceIdMaxLen. Unlike REST's JSON
            // body (harmless either way), up to kMaxCitedBadIds (20) of these
            // caller-supplied strings get echoed back into an HX-Trigger
            // response HEADER below on an unknown-device rejection -- header
            // size is a real protocol/proxy ceiling (most reverse proxies cap
            // a header line around 8-16 KB) that a JSON body doesn't share,
            // so an unbounded pasted entry is a header-size DoS specific to
            // this fragment. `device_id_too_long` rejects the WHOLE request
            // once tokenizing finishes, same shape as the kMaxMembersPerSet
            // array-size cap the store enforces below.
            bool device_id_too_long = false;
            if (req.has_param("device_ids")) {
                std::string raw = req.get_param_value("device_ids");
                std::string cur;
                auto flush = [&]() {
                    // trim whitespace
                    std::size_t a = cur.find_first_not_of(" \t\r\n");
                    std::size_t b = cur.find_last_not_of(" \t\r\n");
                    if (a != std::string::npos) {
                        std::string token = cur.substr(a, b - a + 1);
                        if (token.size() > yuzu::server::mcp::kResultSetDeviceIdMaxLen)
                            device_id_too_long = true;
                        else
                            members.push_back(std::move(token));
                    }
                    cur.clear();
                };
                for (char c : raw) {
                    if (c == '\n' || c == ',')
                        flush();
                    else
                        cur += c;
                }
                flush();
            }
            if (device_id_too_long) {
                // Gate 4 SHOULD (#4983 fix round): standardized on REST/MCP's
                // "reason=..." audit-detail convention rather than this
                // fragment's own bare-error-code shape -- see the
                // RESULT_SET_UNKNOWN_DEVICE_ID branch below for the full
                // rationale (both denials moved together).
                deps.audit_fn(req, "result_set.create", "denied", "ResultSet", "",
                              "reason=device_id_too_long");
                res.set_header(
                    "HX-Trigger",
                    nlohmann::json{
                        {"showToast",
                         {{"level", "error"},
                          {"message",
                           std::format("a device_ids entry exceeds {} bytes",
                                       yuzu::server::mcp::kResultSetDeviceIdMaxLen)}}}}
                        .dump());
                std::string next;
                auto sets = deps.store->list_by_owner(session->username, "", 200, next);
                res.set_content(render_result_sets_sidebar(sets, ""),
                                "text/html; charset=utf-8");
                return;
            }

            // Gate 4 NICE (#4983 fix round): bound the array size BEFORE the
            // O(n) existence-check loop below, mirroring REST's/MCP's
            // identical early reject (`rest_api_v1.cpp`/`mcp_server.cpp`,
            // both right after building `members`). Defense-in-depth only --
            // already bounded by the 4 MiB pre-routing body cap regardless,
            // and `create_materialized` below enforces the same cap itself,
            // so an oversized array was never actually persisted; this only
            // moves the rejection earlier and matches REST/MCP's shape
            // (including the absence of an audit call on this specific
            // branch -- neither of those two twins audits it either).
            if (members.size() > static_cast<size_t>(ResultSetStore::kMaxMembersPerSet)) {
                if (deps.metrics)
                    deps.metrics->counter("yuzu_result_set_quota_rejected").increment();
                res.set_header(
                    "HX-Trigger",
                    nlohmann::json{{"showToast",
                                    {{"level", "error"},
                                     {"message", to_string(ResultSetError::TooManyMembers)}}}}
                        .dump());
                std::string next;
                auto sets = deps.store->list_by_owner(session->username, "", 200, next);
                res.set_content(render_result_sets_sidebar(sets, ""),
                                "text/html; charset=utf-8");
                return;
            }

            // #4983: full existence + scope check on a non-empty device_ids,
            // mirroring the identical fix on POST /api/v1/result-sets (REST)
            // and MCP create_result_set (same PR) -- this fragment's
            // CSV-paste import had the identical gap: a caller-supplied
            // device_ids list with no lookup against the agent registry at
            // all. Scoped to fire ONLY when device_ids was actually supplied
            // and non-empty -- see this file's header comment ("#4983 (added
            // after the initial extraction)") for why the rejection shape
            // here is this file's own toast+sidebar idiom, not REST's
            // rs_err/A4-envelope or MCP's JSON-RPC error.
            if (!members.empty()) {
                // Checked SEPARATELY, in the same order as REST/MCP's fix --
                // fleet_read_fn unwired first, then (only once the gate has
                // actually run and admitted) all_agent_ids_fn -- rather than
                // one combined check, so a wired fleet_read_fn is always
                // consulted even when all_agent_ids_fn is the piece that's
                // missing (matters for RBAC-audit-of-the-attempt parity with
                // the other two surfaces).
                if (!deps.fleet_read_fn) {
                    spdlog::error("result_set.create (fragment): fleet_read_fn unwired -- "
                                  "misconfigured call site; failing closed");
                    // Gate 4 SHOULD (#4983 fix round): standardized on
                    // REST/MCP's "reason=..." audit-detail convention (see
                    // the RESULT_SET_UNKNOWN_DEVICE_ID branch below for the
                    // full rationale).
                    deps.audit_fn(req, "result_set.create", "denied", "ResultSet", "",
                                  "reason=fleet_read_fn_unwired");
                    res.set_header(
                        "HX-Trigger",
                        nlohmann::json{
                            {"showToast",
                             {{"level", "error"},
                              {"message", "RESULT_SET_STORE_UNAVAILABLE: device visibility "
                                          "check unavailable"}}}}
                            .dump());
                    std::string next;
                    auto sets = deps.store->list_by_owner(session->username, "", 200, next);
                    res.set_content(render_result_sets_sidebar(sets, ""),
                                    "text/html; charset=utf-8");
                    return;
                }
                auto gate = deps.fleet_read_fn(req, res, "Infrastructure", "Read");
                if (!gate.admitted)
                    return; // gate already wrote its own (JSON) 401/403/503 body -- the
                            // same accepted shape dashboard_routes.cpp's
                            // /fragments/results uses for an HTMX consumer.

                if (!deps.all_agent_ids_fn) {
                    spdlog::error("result_set.create (fragment): all_agent_ids_fn unwired -- "
                                  "misconfigured call site; failing closed");
                    deps.audit_fn(req, "result_set.create", "denied", "ResultSet", "",
                                  "reason=all_agent_ids_fn_unwired");
                    res.set_header(
                        "HX-Trigger",
                        nlohmann::json{
                            {"showToast",
                             {{"level", "error"},
                              {"message",
                               "RESULT_SET_STORE_UNAVAILABLE: device registry unavailable"}}}}
                            .dump());
                    std::string next;
                    auto sets = deps.store->list_by_owner(session->username, "", 200, next);
                    res.set_content(render_result_sets_sidebar(sets, ""),
                                    "text/html; charset=utf-8");
                    return;
                }

                // Called ONCE (not per-id) and cached in a set for O(1)
                // per-id membership checks -- same rationale as the REST/MCP
                // fix (see RestApiV1::AllAgentIdsFn's doc comment).
                // Presence-merged (AgentRegistry::all_ids()), NOT a
                // local-only snapshot.
                //
                // NICE (cpp-expert, #4983 fix round): `known` is never read
                // again after `known_set` is built, so move each string in
                // rather than copying it.
                std::vector<std::string> known = deps.all_agent_ids_fn();
                const std::unordered_set<std::string> known_set(
                    std::make_move_iterator(known.begin()), std::make_move_iterator(known.end()));

                // #3564-style oracle safety (see GET /api/v1/devices/{id}'s
                // identical rationale): a nonexistent id and a real-but-out-
                // of-scope id are indistinguishable here. Unlike that route,
                // these ids are the CALLER'S OWN submitted list, so citing
                // which one(s) failed back is not a disclosure of someone
                // else's device existence.
                //
                // NICE (cpp-expert, #4983 fix round): only the first
                // kMaxCitedBadIds are ever displayed (below) -- track the
                // total count separately instead of accumulating every bad
                // id into `bad_ids` when the caller's device_ids can run to
                // kMaxMembersPerSet (100000) entries.
                constexpr std::size_t kMaxCitedBadIds = 20;
                std::vector<std::string> bad_ids;
                std::size_t bad_id_count = 0;
                for (const auto& mid : members) {
                    if (!known_set.contains(mid) || !authz::in_scope(gate.scope, mid)) {
                        ++bad_id_count;
                        if (bad_ids.size() < kMaxCitedBadIds)
                            bad_ids.push_back(mid);
                    }
                }
                if (bad_id_count > 0) {
                    std::string cited;
                    for (std::size_t i = 0; i < bad_ids.size(); ++i) {
                        if (i)
                            cited += ", ";
                        cited += bad_ids[i];
                    }
                    if (bad_id_count > kMaxCitedBadIds)
                        cited += std::format(" (+{} more)", bad_id_count - kMaxCitedBadIds);
                    // Gate 4 SHOULD (#4983 fix round): standardized this
                    // fragment's audit-detail shape onto REST/MCP's
                    // "reason=..." convention (both already used it for this
                    // SAME rejection) rather than the bare
                    // RESULT_SET_UNKNOWN_DEVICE_ID this fragment used before
                    // -- the identical logical event should read identically
                    // in the audit log regardless of which of the three
                    // surfaces produced it. Applied to every #4983-added
                    // denial in this handler (device_id_too_long, both
                    // unwired-dependency branches above, and this one) for
                    // full consistency; this fragment's PRE-EXISTING
                    // pin/unpin/delete/quota audit calls (which audit a real
                    // ResultSetStore-level `ResultSetError`, a different kind
                    // of event) are left as their own established
                    // to_string(error)-code convention, unchanged.
                    deps.audit_fn(req, "result_set.create", "denied", "ResultSet", "",
                                  "reason=unknown_device_id");
                    // Gate 4 SHOULD (real bug, #4983 fix round): a caller-
                    // supplied (nonexistent) device_ids entry can carry
                    // invalid raw UTF-8 bytes reached via URL-decoded form
                    // data (httplib's query/form decoder does not validate
                    // UTF-8, unlike REST/MCP's JSON-body parsing, which
                    // structurally rejects invalid UTF-8 before device_ids is
                    // ever inspected) -- `cited` echoes those bytes verbatim,
                    // and nlohmann::json's default dump() throws
                    // `type_error.316` on invalid UTF-8, which propagates
                    // uncaught out of this handler (no exception_handler is
                    // installed on web_server_) into an opaque 500 instead of
                    // this route's own documented clean-400/toast contract.
                    // `error_handler_t::replace` substitutes U+FFFD instead
                    // of throwing -- the established idiom for exactly this
                    // "caller-controlled bytes reach a JSON dump()" class
                    // elsewhere in this codebase (`approval_routes.cpp`,
                    // `api_token_model.cpp`, `management_group_model.cpp`,
                    // `instruction_routes.cpp`, `bundle_service.cpp`).
                    res.set_header(
                        "HX-Trigger",
                        nlohmann::json{
                            {"showToast",
                             {{"level", "error"},
                              {"message",
                               "RESULT_SET_UNKNOWN_DEVICE_ID: device_ids contains an id "
                               "that does not exist or is not visible to you: " +
                                   cited}}}}
                            .dump(-1, ' ', false, nlohmann::json::error_handler_t::replace));
                    std::string next;
                    auto sets = deps.store->list_by_owner(session->username, "", 200, next);
                    res.set_content(render_result_sets_sidebar(sets, ""),
                                    "text/html; charset=utf-8");
                    return;
                }
            }

            auto created = deps.store->create_materialized(cr, members);
            if (!created) {
                // Surface quota / too-many-members / store errors instead of
                // silently re-rendering as if the create succeeded (review
                // merged_bug_009). The store enforces kMaxMembersPerSet, so
                // an oversized pasted CSV lands here as TooManyMembers (B4).
                if (created.error() == ResultSetError::QuotaExceeded ||
                    created.error() == ResultSetError::TooManyMembers) {
                    if (deps.metrics)
                        deps.metrics->counter("yuzu_result_set_quota_rejected").increment();
                }
                deps.audit_fn(req, "result_set.create", "denied", "ResultSet", "",
                              to_string(created.error()));
                res.set_header("HX-Trigger",
                               nlohmann::json{{"showToast",
                                               {{"level", "error"},
                                                {"message", to_string(created.error())}}}}
                                   .dump());
                std::string next;
                auto sets = deps.store->list_by_owner(session->username, "", 200, next);
                res.set_content(render_result_sets_sidebar(sets, ""),
                                "text/html; charset=utf-8");
                return;
            }
            deps.audit_fn(req, "result_set.create", "success", "ResultSet", created->id,
                          cr.source_kind);
            std::string next;
            auto sets = deps.store->list_by_owner(session->username, "", 200, next);
            res.set_header("HX-Trigger", "resultSetsChanged");
            res.set_content(render_result_sets_sidebar(sets, created->id),
                            "text/html; charset=utf-8");
        });
}

} // namespace yuzu::server::result_set
