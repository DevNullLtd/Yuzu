/// @file test_hardware_routes.cpp
/// Tests for /hardware — the CI list, the per-device CI record + lens tabs, and the
/// REST v1 twins (`GET /api/v1/hardware`, `GET /api/v1/hardware/{id}`,
/// `POST /api/v1/hardware/{id}/sync`) — driven in-process through TestRouteSink (no
/// httplib acceptor, #438), same discipline as test_inventory_routes.cpp's InvHarness.
/// Focus areas: results_only fragment scoping (#hw-results only, never the page
/// shell), the tag-filter validation + narrowing round-trip through
/// `normalise_hardware_query`/`hw_row_matches`, the "score only the rendered page"
/// DexScoreFn call-count discipline, the lens-bar OOB-swap/sync-poll interaction, the
/// scoped GuaranteedState:Read probe gating the DEX/Guardian lenses, the REST JSON
/// null-vs-value contract for the new fields, and the POST .../sync route matrix.

#include "hardware_routes.hpp"
#include "test_route_sink.hpp"

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <cstdio>
#include <expected>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

using namespace yuzu::server;

namespace {

bool contains(const std::string& hay, const std::string& needle) {
    return hay.find(needle) != std::string::npos;
}

InventoryDeviceRow make_row(std::string id, std::string host, std::string os, bool online,
                            std::vector<std::pair<std::string, std::string>> tags = {}) {
    InventoryDeviceRow r;
    r.agent_id = std::move(id);
    r.hostname = std::move(host);
    r.os = std::move(os);
    r.online = online;
    r.last_seen = online ? "now" : "1h ago";
    r.tags = std::move(tags);
    return r;
}

// ── HwHarness — HardwareRoutes::Deps wired as controllable fakes/lambdas ─────────
// Mirrors InvHarness (test_inventory_routes.cpp): every provider is a lambda
// capturing `this` so a test can flip a field and re-dispatch. Actions-lens-only
// deps (actions_fn/classify_fn/schema_fn/responses_fn/manifest_fn/
// action_descriptions) are left unwired — the Actions lens and its result poll are
// out of scope for this file (the CI list/record + REST twins are the named gap).
struct HwHarness {
    yuzu::server::test::TestRouteSink sink;
    HardwareRoutes routes;

    bool allow_fleet_read = true;
    bool allow_scoped_perm = true;      // per-device Inventory:Read (the CI record gate)
    bool allow_guaranteed_state = true; // scoped GuaranteedState:Read probe (DEX/Guardian/Live lenses)
    bool allow_execute = true;          // scoped Execution:Execute probe (sync affordance/actions)
    bool allow_tag_write = true;        // scoped Tag:Write probe (tag controls)

    std::vector<InventoryDeviceRow> roster_rows;
    bool roster_ci_degraded = false;
    bool roster_tags_degraded = false;

    HardwareCiDetail ci_detail; // configurable per test; default = degraded (the struct's own default)

    int dex_calls = 0;
    std::vector<std::string> dex_calls_for; // agent_ids scored, in call order
    std::unordered_map<std::string, int> dex_score_by_id; // per-id override; default 42

    HardwareRoutes::HwSyncDispatchResult sync_result{true, "cmd-sync-1"};
    bool unwire_sync_dispatch = false;
    std::optional<std::string> agent_version{std::string("0.13.1")}; // nullopt = no live session
    bool unwire_agent_version_fn = false;
    bool audit_should_fail = false; // simulates an audit-store degrade (AuditFn returns false)
    int sync_dispatch_calls = 0;

    std::vector<std::string> audits;        // "action|result"
    std::vector<std::string> audit_full;    // "action|result|target_type|target_id"
    std::vector<std::string> audit_details; // detail strings, parallel to `audits`

    // unwire_sync_dispatch/unwire_agent_version_fn decide, ONCE, which std::function
    // gets bound into deps below — an empty std::function (the "unwired" state) vs
    // the live reactive lambda. Unlike sync_result/agent_version (read fresh on
    // every call via `this`-capture, so mutating them AFTER construction still
    // works), that decision is baked in at construction time: a post-construction
    // `h.unwire_sync_dispatch = true` is silently a no-op — the route already holds
    // the real lambda. Pass either flag to the constructor, never assign it after.
    explicit HwHarness(bool unwire_sync_dispatch_ctor = false, bool unwire_agent_version_fn_ctor = false) {
        unwire_sync_dispatch = unwire_sync_dispatch_ctor;
        unwire_agent_version_fn = unwire_agent_version_fn_ctor;
        auto auth = [](const httplib::Request&, httplib::Response&) {
            return std::optional<auth::Session>(auth::Session{});
        };
        auto scoped_perm = [this](const httplib::Request&, httplib::Response& res, const std::string&,
                                  const std::string&, const std::string&) {
            if (!allow_scoped_perm)
                res.status = 403;
            return allow_scoped_perm;
        };
        HardwareRoutes::FleetReadFn fleet_read =
            [this](const httplib::Request&, httplib::Response& res, const std::string&,
                  const std::string&) -> authz::FleetReadGate {
            authz::FleetReadGate g;
            if (!allow_fleet_read) {
                res.status = 403;
                return g; // admitted=false, scope=deny_all() (unused — response already written)
            }
            g.admitted = true;
            g.scope = std::nullopt; // unfiltered — the only filter under test is the tag/os/status facet
            return g;
        };
        HardwareRoutes::RosterFn roster_fn = [this]() -> InventoryDevicesResult {
            InventoryDevicesResult out;
            out.rows = roster_rows;
            out.ci_degraded = roster_ci_degraded;
            out.tags_degraded = roster_tags_degraded;
            return out;
        };
        HardwareRoutes::CiDetailFn ci_fn = [this](const std::string&) { return ci_detail; };
        HardwareRoutes::ScopedProbeFn probe = [this](const httplib::Request&, const std::string& type,
                                                     const std::string& op, const std::string&) {
            if (type == "GuaranteedState" && op == "Read")
                return allow_guaranteed_state;
            if (type == "Execution" && op == "Execute")
                return allow_execute;
            if (type == "Tag" && op == "Write")
                return allow_tag_write;
            return true;
        };
        HardwareRoutes::AuditFn audit = [this](const httplib::Request&, const std::string& a,
                                               const std::string& r, const std::string& tt,
                                               const std::string& tid, const std::string& detail) {
            audits.push_back(a + "|" + r);
            audit_full.push_back(a + "|" + r + "|" + tt + "|" + tid);
            audit_details.push_back(detail);
            return !audit_should_fail;
        };
        HardwareRoutes::DexScoreFn dex_fn = [this](const std::string& id) {
            ++dex_calls;
            dex_calls_for.push_back(id);
            auto it = dex_score_by_id.find(id);
            return it != dex_score_by_id.end() ? it->second : 42;
        };
        HardwareRoutes::SyncDispatchFn sync_fn = [this](const std::string&, const std::string&) {
            ++sync_dispatch_calls;
            return sync_result;
        };
        HardwareRoutes::AgentVersionFn version_fn = [this](const std::string&) { return agent_version; };

        HardwareRoutes::Deps deps;
        deps.auth_fn = auth;
        deps.scoped_perm_fn = scoped_perm;
        deps.fleet_read_fn = fleet_read;
        deps.audit_fn = audit;
        deps.roster_fn = roster_fn;
        deps.ci_detail_fn = ci_fn;
        deps.scoped_probe_fn = probe;
        deps.dex_score_fn = dex_fn;
        deps.sync_dispatch_fn = unwire_sync_dispatch ? HardwareRoutes::SyncDispatchFn{} : sync_fn;
        deps.agent_version_fn = unwire_agent_version_fn ? HardwareRoutes::AgentVersionFn{} : version_fn;
        routes.register_routes(sink, deps);
    }
};

} // namespace

// ───────────────────────── CI list fragment ────────────────────────────────────

TEST_CASE("route: results_only returns ONLY the #hw-results region", "[hardware][route]") {
    HwHarness h;
    h.roster_rows = {make_row("agent-1", "HW-RESULTS-HOST", "windows", true)};

    auto results = h.sink.Get("/fragments/hardware/list?results_only=1");
    REQUIRE(results);
    REQUIRE(results->body.starts_with("<div id=\"hw-results\""));
    // The page shell/search box live OUTSIDE #hw-results by design — a results_only
    // response must not carry them, or a repeated htmx swap into #hw-results would
    // nest a second copy of the h1/search box inside itself on every filter click.
    REQUIRE_FALSE(contains(results->body, "<h1 class=\"hw-h1\">Hardware</h1>"));
    REQUIRE_FALSE(contains(results->body, "id=\"hw-q\""));
    REQUIRE(contains(results->body, "HW-RESULTS-HOST"));

    // Contrast: the full (non-results_only) render DOES carry both.
    auto full = h.sink.Get("/fragments/hardware/list");
    REQUIRE(full);
    REQUIRE(contains(full->body, "<h1 class=\"hw-h1\">Hardware</h1>"));
    REQUIRE(contains(full->body, "id=\"hw-q\""));
    REQUIRE(contains(full->body, "HW-RESULTS-HOST"));
}

TEST_CASE("route: list — invalid tag key is a 400 (normalise_hardware_query nullopt path)",
          "[hardware][route]") {
    HwHarness h;
    h.roster_rows = {make_row("agent-1", "HOST-1", "windows", true)};

    // '*' is outside TagStore::validate_key's charset (alnum + _-.: only).
    auto res = h.sink.Get("/fragments/hardware/list?tag=bad*key");
    REQUIRE(res);
    REQUIRE(res->status == 400);
    REQUIRE(contains(res->body, "Bad request"));
    REQUIRE_FALSE(contains(res->body, "HOST-1"));
}

TEST_CASE("route: list — tag facet narrows rendered rows (key-only and key=value)",
          "[hardware][route]") {
    HwHarness h;
    h.roster_rows = {
        make_row("a1", "hw-tag-alpha", "windows", true, {{"env", "prod"}}),
        make_row("a2", "hw-tag-bravo", "linux", true, {{"env", "trading"}}),
        make_row("a3", "hw-tag-charlie", "linux", true, {}), // untagged
    };

    {
        // key-only: any value of "env" matches — alpha + bravo, not charlie.
        auto res = h.sink.Get("/fragments/hardware/list?tag=env&results_only=1");
        REQUIRE(res);
        REQUIRE(contains(res->body, "hw-tag-alpha"));
        REQUIRE(contains(res->body, "hw-tag-bravo"));
        REQUIRE_FALSE(contains(res->body, "hw-tag-charlie"));
    }
    {
        // key=value: exact match only — bravo alone. httplib's query-pair parser
        // splits on the FIRST '=' only, so this reaches the handler as a single
        // `tag` param with value "env=trading", exactly like a real filter chip's
        // href.
        auto res = h.sink.Get("/fragments/hardware/list?tag=env=trading&results_only=1");
        REQUIRE(res);
        REQUIRE_FALSE(contains(res->body, "hw-tag-alpha"));
        REQUIRE(contains(res->body, "hw-tag-bravo"));
        REQUIRE_FALSE(contains(res->body, "hw-tag-charlie"));
    }
}

TEST_CASE("route: list — DexScoreFn is called EXACTLY page.rows.size() times, never the "
          "whole roster",
          "[hardware][route]") {
    HwHarness h;
    for (int i = 0; i < 10; ++i) {
        char buf[8];
        std::snprintf(buf, sizeof(buf), "H%02d", i);
        h.roster_rows.push_back(make_row("agent-" + std::string(buf), buf, "linux", true));
    }
    auto res = h.sink.Get("/fragments/hardware/list?limit=3&results_only=1");
    REQUIRE(res);
    // Sorted by name ascending (default) — the first page is H00,H01,H02.
    REQUIRE(contains(res->body, "H00"));
    REQUIRE(contains(res->body, "H01"));
    REQUIRE(contains(res->body, "H02"));
    REQUIRE_FALSE(contains(res->body, "H03"));
    REQUIRE(h.dex_calls == 3); // NOT 10 — scored only for the rendered page
    REQUIRE(h.dex_calls_for.size() == 3);
}

// ───────────────────────── CI record: lens-bar OOB swap ────────────────────────

TEST_CASE("route: ci lens_only — OOB lens-bar prepended normally, omitted on a sync poll",
          "[hardware][route]") {
    HwHarness h;
    h.ci_detail.identity = make_row("agent-1", "LENS-HOST", "windows", true);
    DeviceCiRecord rec;
    rec.last_seen = 5000;
    h.ci_detail.ci = std::expected<std::optional<DeviceCiRecord>, CiReadError>(
        std::optional<DeviceCiRecord>(rec));

    {
        // Normal lens-tab click: no await_since param at all.
        auto res = h.sink.Get("/fragments/hardware/ci?id=agent-1&lens=overview&lens_only=1");
        REQUIRE(res);
        REQUIRE(contains(res->body, "hx-swap-oob=\"true\""));
        REQUIRE(contains(res->body, "id=\"hw-lens-bar\""));
    }
    {
        // Sync-now poll: await_since present (server clock strictly before the
        // record's last_seen, so the route takes the "newer" branch straight into
        // the same lens_only render — the OOB bar must still be omitted here,
        // because the active tab hasn't changed on a poll tick).
        auto res =
            h.sink.Get("/fragments/hardware/ci?id=agent-1&lens=overview&lens_only=1&await_since=1000");
        REQUIRE(res);
        REQUIRE_FALSE(contains(res->body, "hx-swap-oob=\"true\""));
        REQUIRE_FALSE(contains(res->body, "id=\"hw-lens-bar\""));
    }
}

// ───────────────────────── CI record: GuaranteedState:Read probe ───────────────

TEST_CASE("route: dex/guardian lenses check scoped GuaranteedState:Read before rendering",
          "[hardware][route]") {
    for (const std::string lens : {"dex", "guardian"}) {
        HwHarness h;
        h.ci_detail.identity = make_row("agent-1", "GS-HOST", "windows", true);

        h.allow_guaranteed_state = true;
        auto ok = h.sink.Get("/fragments/hardware/ci?id=agent-1&lens=" + lens);
        REQUIRE(ok);
        REQUIRE(contains(ok->body, "/fragments/device/" + lens + "?id=agent-1"));
        REQUIRE_FALSE(contains(ok->body, "GuaranteedState:Read"));

        h.allow_guaranteed_state = false;
        auto denied = h.sink.Get("/fragments/hardware/ci?id=agent-1&lens=" + lens);
        REQUIRE(denied);
        REQUIRE(contains(denied->body, "GuaranteedState:Read"));
        REQUIRE_FALSE(contains(denied->body, "/fragments/device/" + lens + "?id=agent-1"));
    }
}

// ───────────────────────── REST v1: JSON null-vs-value contract ────────────────

TEST_CASE("route: GET /api/v1/hardware — new fields null-vs-value semantics",
          "[hardware][route][rest]") {
    HwHarness h;
    h.roster_rows = {
        make_row("agent-json-1", "JSON-HOST-1", "linux", true, {{"env", "prod"}}),
        make_row("agent-json-2", "JSON-HOST-2", "windows", false, {}),
    };
    h.roster_rows[0].agent_version = "0.14.2";
    h.roster_rows[0].arch = "x86_64";
    h.roster_rows[0].ips = {"10.0.0.5"};
    h.dex_score_by_id["agent-json-1"] = 88;
    h.dex_score_by_id["agent-json-2"] = -1; // "not scored" sentinel
    h.roster_tags_degraded = true;

    auto res = h.sink.Get("/api/v1/hardware");
    REQUIRE(res);
    REQUIRE(res->status == 200);
    auto body = nlohmann::json::parse(res->body, nullptr, false);
    REQUIRE_FALSE(body.is_discarded());
    REQUIRE(body["data"]["tags_degraded"].get<bool>() == true);

    const auto& devices = body["data"]["devices"];
    REQUIRE(devices.size() == 2);
    const auto& d1 = devices[0]["agent_id"] == "agent-json-1" ? devices[0] : devices[1];
    const auto& d2 = devices[0]["agent_id"] == "agent-json-2" ? devices[0] : devices[1];

    // Populated row: value, never a sentinel string.
    REQUIRE(d1["agent_version"].get<std::string>() == "0.14.2");
    REQUIRE(d1["arch"].get<std::string>() == "x86_64");
    REQUIRE(d1["ips"] == nlohmann::json::array({"10.0.0.5"}));
    nlohmann::json expected_tags = nlohmann::json::array();
    expected_tags.push_back({{"key", "env"}, {"value", "prod"}});
    REQUIRE(d1["tags"] == expected_tags);
    REQUIRE(d1["dex_score"].get<int>() == 88);

    // Empty row: agent_version/arch/ips/dex_score normalise to JSON null...
    REQUIRE(d2["agent_version"].is_null());
    REQUIRE(d2["arch"].is_null());
    REQUIRE(d2["ips"].is_null());
    REQUIRE(d2["dex_score"].is_null());
    // ...EXCEPT "tags", which is a plain (non-optional) vector on this row shape
    // (InventoryDeviceRow::tags) — an untagged device renders an EMPTY ARRAY, not
    // null; only the per-device CI-record twin's "tags" (HardwareCiDetail::tags,
    // an optional<vector<DeviceTag>>) uses null to mean "degraded/unwired". See
    // this file's final summary for why this diverges from a blanket
    // empty-means-null reading of hardware_list_model.hpp.
    REQUIRE(d2["tags"].is_array());
    REQUIRE(d2["tags"].empty());
}

TEST_CASE("route: GET /api/v1/hardware/{id} — CI-record tags/agent_version null-vs-value",
          "[hardware][route][rest]") {
    {
        // Degraded/unwired tag store -> nullopt -> JSON null.
        HwHarness h;
        h.ci_detail.identity = make_row("agent-ci-1", "CI-HOST-1", "linux", true);
        h.ci_detail.tags = std::nullopt;
        h.ci_detail.agent_version = std::nullopt;
        auto res = h.sink.Get("/api/v1/hardware/agent-ci-1");
        REQUIRE(res);
        REQUIRE(res->status == 200);
        auto body = nlohmann::json::parse(res->body, nullptr, false);
        REQUIRE_FALSE(body.is_discarded());
        REQUIRE(body["data"]["tags"].is_null());
        REQUIRE(body["data"]["agent_version"].is_null());
    }
    {
        // A genuinely tag-less device -> present-EMPTY vector -> JSON [], not null
        // (ADR-0016 §7: degraded and honestly-empty must never collapse to the
        // same wire value).
        HwHarness h;
        h.ci_detail.identity = make_row("agent-ci-2", "CI-HOST-2", "linux", true);
        h.ci_detail.tags = std::vector<DeviceTag>{};
        h.ci_detail.agent_version = std::string("0.13.5");
        auto res = h.sink.Get("/api/v1/hardware/agent-ci-2");
        REQUIRE(res);
        REQUIRE(res->status == 200);
        auto body = nlohmann::json::parse(res->body, nullptr, false);
        REQUIRE_FALSE(body.is_discarded());
        REQUIRE(body["data"]["tags"].is_array());
        REQUIRE(body["data"]["tags"].empty());
        REQUIRE(body["data"]["agent_version"].get<std::string>() == "0.13.5");
    }
}

// ───────────────────────── POST /api/v1/hardware/{id}/sync — route matrix ──────

TEST_CASE("route: POST .../sync — malformed JSON body is a 400, denied+audited "
          "(governance Gate 8)",
          "[hardware][route][rest]") {
    HwHarness h;
    auto res = h.sink.Post("/api/v1/hardware/agent-1/sync", "{not json");
    REQUIRE(res);
    REQUIRE(res->status == 400);
    REQUIRE(contains(res->body, "body must be a JSON object"));
    bool denied = false;
    for (const auto& a : h.audits)
        if (a == "inventory.sync.request|denied")
            denied = true;
    REQUIRE(denied);
}

TEST_CASE("route: POST .../sync — bad source is a 400, denied+audited, never dispatched",
          "[hardware][route][rest]") {
    HwHarness h;
    auto res = h.sink.Post("/api/v1/hardware/agent-1/sync", R"({"source":"not_a_real_source"})");
    REQUIRE(res);
    REQUIRE(res->status == 400);
    REQUIRE(contains(res->body, "source must be one of"));
    bool denied = false;
    for (const auto& a : h.audits)
        if (a == "inventory.sync.request|denied")
            denied = true;
    REQUIRE(denied);
}

TEST_CASE("route: POST .../sync — non-string source is a 400, not an uncaught throw "
          "(governance Gate 4)",
          "[hardware][route][rest]") {
    // {"source":123} used to reach nlohmann::json::value<string>(), which THROWS on
    // a type mismatch — an uncaught exception here degraded to a bare 500 with no
    // A4 envelope and no audit row at all (worse than the ordinary bad-source path).
    HwHarness h;
    auto res = h.sink.Post("/api/v1/hardware/agent-1/sync", R"({"source":123})");
    REQUIRE(res);
    REQUIRE(res->status == 400);
    REQUIRE(contains(res->body, "must be a string"));
    REQUIRE(h.sync_dispatch_calls == 0);
    bool denied = false;
    for (const auto& a : h.audits)
        if (a == "inventory.sync.request|denied")
            denied = true;
    REQUIRE(denied);
}

TEST_CASE("route: POST .../sync — agent below the sync-now version floor is 409",
          "[hardware][route][rest]") {
    // READ hardware_routes.cpp: this branch sets res.status = 409 (not the brief's
    // guessed "409-or-whatever" — confirmed against the actual code) and audits
    // "denied" (not "failure").
    HwHarness h;
    h.agent_version = std::string("0.12.9"); // predates kSyncNowMinAgentVersion {0,13,1}
    auto res = h.sink.Post("/api/v1/hardware/agent-1/sync", "");
    REQUIRE(res);
    REQUIRE(res->status == 409);
    REQUIRE(contains(res->body, "predates sync-on-demand"));
    bool denied = false;
    for (const auto& a : h.audits)
        if (a == "inventory.sync.request|denied")
            denied = true;
    REQUIRE(denied);
}

TEST_CASE("route: POST .../sync — offline agent or refused dispatch is a 503",
          "[hardware][route][rest]") {
    {
        // No live session: agent_version_fn returns nullopt.
        HwHarness h;
        h.agent_version = std::nullopt;
        auto res = h.sink.Post("/api/v1/hardware/agent-1/sync", "");
        REQUIRE(res);
        REQUIRE(res->status == 503);
        REQUIRE(contains(res->body, "not connected"));
        bool no_agents = false;
        for (const auto& a : h.audits)
            if (a == "inventory.sync.request|no_agents")
                no_agents = true;
        REQUIRE(no_agents);
    }
    {
        // Registry refuses the dispatch (sent=false) — a DIFFERENT branch from the
        // offline-version-fn case above: this one already passed the pre-dispatch
        // "requested" audit (audit-then-act), so there is no SECOND audit row for
        // the dispatch failure itself — the 503 response is the only signal for
        // "not reached" here, matching the /api/v1/dex/devices/{id}/live precedent
        // (governance Gate 4 consistency fix: this route used to double-audit).
        HwHarness h;
        h.sync_result = HardwareRoutes::HwSyncDispatchResult{false, ""};
        auto res = h.sink.Post("/api/v1/hardware/agent-1/sync", "");
        REQUIRE(res);
        REQUIRE(res->status == 503);
        REQUIRE(contains(res->body, "not reachable"));
        bool requested = false, no_agents = false;
        for (const auto& a : h.audits) {
            if (a == "inventory.sync.request|requested")
                requested = true;
            if (a == "inventory.sync.request|no_agents")
                no_agents = true;
        }
        REQUIRE(requested);
        REQUIRE_FALSE(no_agents);
    }
    {
        // sync-on-demand entirely unwired on this deployment -> 503, audited
        // "failure" (a DIFFERENT result string from the two "no_agents" cases
        // above — a config gap, not "the agent didn't answer").
        HwHarness h(/*unwire_sync_dispatch_ctor=*/true);
        auto res = h.sink.Post("/api/v1/hardware/agent-1/sync", "");
        REQUIRE(res);
        REQUIRE(res->status == 503);
        bool failed = false;
        for (const auto& a : h.audits)
            if (a == "inventory.sync.request|failure")
                failed = true;
        REQUIRE(failed);
    }
}

TEST_CASE("route: POST .../sync — successful dispatch is 202 with the documented shape, "
          "audited \"requested\" before dispatch",
          "[hardware][route][rest]") {
    HwHarness h;
    h.sync_result = HardwareRoutes::HwSyncDispatchResult{true, "__sync__-abc123"};
    auto res = h.sink.Post("/api/v1/hardware/agent-1/sync", R"({"source":"app_perf"})");
    REQUIRE(res);
    REQUIRE(res->status == 202);
    auto body = nlohmann::json::parse(res->body, nullptr, false);
    REQUIRE_FALSE(body.is_discarded());
    REQUIRE(body["data"]["command_id"].get<std::string>() == "__sync__-abc123");
    REQUIRE(body["data"]["source"].get<std::string>() == "app_perf");
    REQUIRE(body["data"]["agents_reached"].get<int>() == 1);
    REQUIRE(body["data"].contains("requested_at"));
    // The audit RESULT string is "requested", persisted BEFORE dispatch (governance
    // Gate 2 fix: the route used to audit "dispatched" AFTER the side effect and
    // discard the persist result — fail-open on an audit-store degrade). There is
    // no separate post-dispatch audit row; the command_id is returned to the caller
    // in the response body only.
    bool requested = false;
    for (const auto& a : h.audits)
        if (a == "inventory.sync.request|requested")
            requested = true;
    REQUIRE(requested);
}

TEST_CASE("route: POST .../sync — audit-store degrade fails CLOSED, no dispatch (governance Gate 2)",
          "[hardware][route][rest][security]") {
    HwHarness h;
    h.audit_should_fail = true;
    auto res = h.sink.Post("/api/v1/hardware/agent-1/sync", R"({"source":"app_perf"})");
    REQUIRE(res);
    REQUIRE(res->status == 503);
    REQUIRE(res->get_header_value("Sec-Audit-Failed") == "true");
    // The whole point of auditing BEFORE dispatch: a degraded audit store must
    // never let the side effect through.
    REQUIRE(h.sync_dispatch_calls == 0);
}
