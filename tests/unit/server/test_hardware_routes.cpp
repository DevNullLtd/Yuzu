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

#include <algorithm>
#include <cstdio>
#include <expected>
#include <optional>
#include <string>
#include <unordered_map>
#include <unordered_set>
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
    authz::VisibleSet scope;            // FleetReadGate scope; nullopt = unfiltered, set = confine to these ids
    bool allow_execute = true;          // scoped Execution:Execute probe (sync affordance/actions)
    bool allow_tag_write = true;        // scoped Tag:Write probe (tag controls)
    bool allow_tag_delete = true;       // scoped Tag:Delete probe (Remove control; Tags lens only)
    std::vector<std::string> probes;    // "Type:Op" for every scoped probe, in call order

    std::vector<InventoryDeviceRow> roster_rows;
    bool roster_ci_degraded = false;
    bool roster_tags_degraded = false;
    bool roster_degraded = false; // #5531: the durable roster read failed

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
            g.scope = scope; // default nullopt = unfiltered; a test sets it to exercise confinement
            return g;
        };
        HardwareRoutes::RosterFn roster_fn = [this]() -> InventoryDevicesResult {
            InventoryDevicesResult out;
            out.rows = roster_rows;
            out.ci_degraded = roster_ci_degraded;
            out.tags_degraded = roster_tags_degraded;
            out.roster_degraded = roster_degraded;
            return out;
        };
        HardwareRoutes::CiDetailFn ci_fn = [this](const std::string&) { return ci_detail; };
        HardwareRoutes::ScopedProbeFn probe = [this](const httplib::Request&, const std::string& type,
                                                     const std::string& op, const std::string&) {
            probes.push_back(type + ":" + op);
            if (type == "Tag" && op == "Delete")
                return allow_tag_delete;
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

// ───────────────────────── Page shell ──────────────────────────────────────────

// Kills: a wrong active_key literal in page_shell() — apply_shell lights nothing and says
// nothing for an unknown key, so only a test that fetches the page can see it.
TEST_CASE("route: /hardware lights the Hardware sidebar item and its breadcrumb leaf",
          "[hardware][route]") {
    HwHarness h;
    auto page = h.sink.Get("/hardware");
    REQUIRE(page);
    REQUIRE(page->status == 200);
    CHECK(contains(page->body, "/fragments/hardware/list"));
    CHECK(contains(page->body, "<a class=\"shell-nav on\" href=\"/hardware\" aria-current=\"page\">"));
    CHECK(contains(page->body, "<span class=\"shell-sep\">/</span><b>Hardware</b>"));
}

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

// Kills: the route dropping all.tags_degraded / all.ci_degraded on the results_only call, which
// every htmx control uses, so a degraded read would read as "no tags" / "no CI" after one click.
TEST_CASE("route: results_only list keeps the degrade banners", "[hardware][route]") {
    HwHarness h;
    h.roster_rows = {make_row("agent-1", "HW-DEGRADE-HOST", "windows", true)};

    auto healthy = h.sink.Get("/fragments/hardware/list?results_only=1");
    REQUIRE(healthy);
    REQUIRE_FALSE(contains(healthy->body, "Tags unavailable"));
    REQUIRE_FALSE(contains(healthy->body, "CI columns unavailable"));

    h.roster_tags_degraded = true;
    auto tags = h.sink.Get("/fragments/hardware/list?results_only=1");
    REQUIRE(tags);
    REQUIRE(tags->body.starts_with("<div id=\"hw-results\""));
    REQUIRE(contains(tags->body, "Tags unavailable"));

    h.roster_tags_degraded = false;
    h.roster_ci_degraded = true;
    auto ci = h.sink.Get("/fragments/hardware/list?results_only=1");
    REQUIRE(ci);
    REQUIRE(contains(ci->body, "CI columns unavailable"));
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

// ───────────────────────── Audit verbs: behavioural-PII tier ───────────────────

TEST_CASE("route: hardware list + CI record emit the inventory.* behavioural-PII verbs",
          "[hardware][route]") {
    HwHarness h;
    h.roster_rows = {make_row("agent-1", "AUDIT-HOST", "windows", true)};
    h.ci_detail.identity = make_row("agent-1", "AUDIT-HOST", "windows", true);
    auto has = [&](const std::string& row) {
        for (auto& a : h.audit_full)
            if (a == row)
                return true;
        return false;
    };

    REQUIRE(h.sink.Get("/fragments/hardware/list"));
    REQUIRE(has("inventory.devices|success|Inventory|fleet"));

    // The verb is inventory.device.ci for every lens EXCEPT software.
    REQUIRE(h.sink.Get("/fragments/hardware/ci?id=agent-1&lens=software"));
    REQUIRE(has("inventory.device.software|success|Agent|agent-1"));
    REQUIRE_FALSE(has("inventory.device.ci|success|Agent|agent-1"));

    REQUIRE(h.sink.Get("/fragments/hardware/ci?id=agent-1&lens=tags"));
    REQUIRE(has("inventory.device.ci|success|Agent|agent-1"));

    // The REST twins emit the same tuples. Clear the capture first so the fragment
    // calls above cannot satisfy these assertions.
    h.audit_full.clear();
    auto rest_list = h.sink.Get("/api/v1/hardware");
    REQUIRE(rest_list);
    REQUIRE(rest_list->status == 200);
    REQUIRE(has("inventory.devices|success|Inventory|fleet"));

    h.audit_full.clear();
    auto rest_ci = h.sink.Get("/api/v1/hardware/agent-1");
    REQUIRE(rest_ci);
    REQUIRE(rest_ci->status == 200);
    REQUIRE(has("inventory.device.ci|success|Agent|agent-1"));
}

TEST_CASE("route: hardware list + CI record audit-persist failure — fragments set "
          "Sec-Audit-Failed; REST fails closed",
          "[hardware][route]") {
    HwHarness h;
    h.roster_rows = {make_row("agent-1", "AUDIT-HOST", "windows", true)};
    h.ci_detail.identity = make_row("agent-1", "AUDIT-HOST", "windows", true);
    h.audit_should_fail = true;

    auto frag = h.sink.Get("/fragments/hardware/list");
    REQUIRE(frag);
    REQUIRE(frag->status == 200); // set-and-proceed
    REQUIRE(frag->get_header_value("Sec-Audit-Failed") == "true");

    auto rest = h.sink.Get("/api/v1/hardware");
    REQUIRE(rest);
    REQUIRE(rest->status == 503); // fail-closed
    CHECK(rest->get_header_value("Sec-Audit-Failed") == "true");
    CHECK_FALSE(contains(rest->body, "AUDIT-HOST")); // nothing served

    auto ci_frag = h.sink.Get("/fragments/hardware/ci?id=agent-1");
    REQUIRE(ci_frag);
    REQUIRE(ci_frag->status == 200); // set-and-proceed
    REQUIRE(ci_frag->get_header_value("Sec-Audit-Failed") == "true");

    auto ci_rest = h.sink.Get("/api/v1/hardware/agent-1");
    REQUIRE(ci_rest);
    REQUIRE(ci_rest->status == 503); // fail-closed
    CHECK(ci_rest->get_header_value("Sec-Audit-Failed") == "true");
    CHECK_FALSE(contains(ci_rest->body, "AUDIT-HOST")); // nothing served
}

// ───────────────────────── Gate denial + management-group confinement ──────────

TEST_CASE("route: fleet-read denied — 403; no roster body; no inventory.devices audit row",
          "[hardware][route]") {
    HwHarness h;
    h.roster_rows = {make_row("agent-1", "DENY-HOST", "windows", true)};
    h.allow_fleet_read = false;

    for (const char* url : {"/fragments/hardware/list", "/api/v1/hardware"}) {
        auto res = h.sink.Get(url);
        REQUIRE(res);
        CHECK(res->status == 403);
        CHECK_FALSE(contains(res->body, "DENY-HOST"));
    }
    for (auto& a : h.audit_full)
        CHECK_FALSE(a.starts_with("inventory.devices|"));
}

TEST_CASE("route: per-device Inventory:Read denied — CI record fragment is 403 and unaudited",
          "[hardware][route]") {
    HwHarness h;
    h.ci_detail.identity = make_row("agent-1", "DENY-CI-HOST", "windows", true);
    h.allow_scoped_perm = false;

    auto res = h.sink.Get("/fragments/hardware/ci?id=agent-1");
    REQUIRE(res);
    CHECK(res->status == 403);
    CHECK_FALSE(contains(res->body, "DENY-CI-HOST"));
    CHECK(h.audit_full.empty());
}

TEST_CASE("route: management-group scope drops out-of-scope rows (audited) and 404s the REST record",
          "[hardware][route]") {
    HwHarness h;
    h.roster_rows = {make_row("agent-in", "IN-SCOPE-HOST", "windows", true),
                     make_row("agent-out", "OUT-SCOPE-HOST", "windows", true)};
    h.ci_detail.identity = make_row("agent-out", "OUT-SCOPE-HOST", "windows", true);
    h.scope = authz::VisibleSet{std::unordered_set<std::string>{"agent-in"}};

    auto frag = h.sink.Get("/fragments/hardware/list");
    REQUIRE(frag);
    CHECK(frag->status == 200);
    CHECK(contains(frag->body, "IN-SCOPE-HOST"));
    CHECK_FALSE(contains(frag->body, "OUT-SCOPE-HOST"));

    auto rest = h.sink.Get("/api/v1/hardware");
    REQUIRE(rest);
    CHECK(rest->status == 200);
    CHECK(contains(rest->body, "agent-in"));
    CHECK_FALSE(contains(rest->body, "agent-out"));

    // Both list reads audit the drop count (one row dropped each).
    std::size_t omitted_rows = 0;
    for (auto& d : h.audit_details)
        if (contains(d, "omitted=1"))
            ++omitted_rows;
    CHECK(omitted_rows == 2);

    // Out-of-scope id collapses to the same 404 as a nonexistent one; nothing audited for it.
    h.audit_full.clear();
    auto out = h.sink.Get("/api/v1/hardware/agent-out");
    REQUIRE(out);
    CHECK(out->status == 404);
    CHECK_FALSE(contains(out->body, "OUT-SCOPE-HOST"));
    CHECK(h.audit_full.empty());
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

// ───────────────────────── #5531: failed roster read is never an empty fleet ───

namespace {
DeviceCiRecord make_ci_rec() {
    DeviceCiRecord rec;
    rec.model = "CI-MODEL-5531";
    rec.serial = "CI-SERIAL-5531";
    rec.last_seen = 5000;
    return rec;
}
HardwareCiDetail degraded_identity_detail(bool with_ci) {
    HardwareCiDetail d;
    d.identity = std::nullopt;
    d.identity_degraded = true;
    d.ci = with_ci ? std::expected<std::optional<DeviceCiRecord>, CiReadError>(
                         std::optional<DeviceCiRecord>(make_ci_rec()))
                   : std::expected<std::optional<DeviceCiRecord>, CiReadError>(
                         std::optional<DeviceCiRecord>{});
    d.software = std::nullopt;
    d.tags = std::nullopt;
    return d;
}
} // namespace

// Kills: dropping the roster_degraded guard in the list fragment (empty table, no failure audit).
TEST_CASE("route: list fragment — roster read failure renders the roster-unavailable banner; "
          "never an empty table; and audits failure",
          "[hardware][route]") {
    HwHarness h;
    h.roster_degraded = true;
    auto res = h.sink.Get("/fragments/hardware/list?q=abc");
    REQUIRE(res);
    REQUIRE(res->status == 200);
    REQUIRE(contains(res->body, "Hardware roster unavailable"));
    REQUIRE_FALSE(contains(res->body, "<table"));
    REQUIRE_FALSE(h.audits.empty());
    REQUIRE(h.audits.back() == "inventory.devices|failure");
    REQUIRE(contains(h.audit_details.back(), "roster read failed"));
    REQUIRE_FALSE(res->has_header("Sec-Audit-Failed")); // control: audit persisted

    auto ro = h.sink.Get("/fragments/hardware/list?results_only=1&q=abc");
    REQUIRE(ro);
    REQUIRE(ro->body.rfind("<div id=\"hw-results\" data-url=\"", 0) == 0);
    REQUIRE(contains(ro->body, "q=abc"));
    REQUIRE(contains(ro->body, "Hardware roster unavailable"));
    REQUIRE(contains(ro->body, "results_only=1")); // retry must not nest a full page in #hw-results

    // A bad request still precedes the degrade arm.
    auto bad = h.sink.Get("/fragments/hardware/list?sort=bogus");
    REQUIRE(bad);
    REQUIRE(bad->status == 400);
}

// Kills: reverting the list fragment's roster-failure audit to try_persist_audit (drops the
// Sec-Audit-Failed signal when the audit store is also degraded).
TEST_CASE("route: list fragment — roster failure with a degraded audit store keeps the banner and "
          "sets Sec-Audit-Failed",
          "[hardware][route][security]") {
    HwHarness h;
    h.roster_degraded = true;
    h.audit_should_fail = true;
    auto res = h.sink.Get("/fragments/hardware/list?q=abc");
    REQUIRE(res);
    REQUIRE(res->status == 200);
    REQUIRE(contains(res->body, "Hardware roster unavailable"));
    REQUIRE(res->get_header_value("Sec-Audit-Failed") == "true");
}

// Kills: dropping the roster_degraded guard in the REST list (200 with an empty data page).
TEST_CASE("route: GET /api/v1/hardware — roster read failure is 503 with retry_after_ms and no data",
          "[hardware][route][rest]") {
    {
        HwHarness h;
        h.roster_degraded = true;
        auto res = h.sink.Get("/api/v1/hardware");
        REQUIRE(res);
        REQUIRE(res->status == 503);
        auto body = nlohmann::json::parse(res->body, nullptr, false);
        REQUIRE_FALSE(body.is_discarded());
        REQUIRE(body["error"]["retry_after_ms"].get<int>() == 5000);
        REQUIRE_FALSE(body.contains("data"));
        REQUIRE_FALSE(h.audits.empty());
        REQUIRE(h.audits.back() == "inventory.devices|failure");
        REQUIRE_FALSE(res->has_header("Sec-Audit-Failed")); // control: audit persisted
    }
    {
        // Kills: reverting the swap to try_persist_audit — a degraded audit store must still
        // surface Sec-Audit-Failed on top of the unchanged 503.
        HwHarness h;
        h.roster_degraded = true;
        h.audit_should_fail = true;
        auto res = h.sink.Get("/api/v1/hardware");
        REQUIRE(res);
        REQUIRE(res->status == 503);
        auto body = nlohmann::json::parse(res->body, nullptr, false);
        REQUIRE_FALSE(body.is_discarded());
        REQUIRE(body["error"]["retry_after_ms"].get<int>() == 5000);
        REQUIRE(res->get_header_value("Sec-Audit-Failed") == "true");
    }
    {
        // Empty is not failed.
        HwHarness h;
        auto res = h.sink.Get("/api/v1/hardware");
        REQUIRE(res);
        REQUIRE(res->status == 200);
        auto body = nlohmann::json::parse(res->body);
        REQUIRE(body["pagination"]["total"].get<int>() == 0);
    }
}

// Kills: reverting the CI fragment's no_record arm to "Device not found".
TEST_CASE("route: CI fragment — identity_degraded with no readable record says roster unreadable "
          "and audits failure",
          "[hardware][route]") {
    HwHarness h;
    h.ci_detail = degraded_identity_detail(false);
    auto res = h.sink.Get("/fragments/hardware/ci?id=agent-x");
    REQUIRE(res);
    REQUIRE(contains(res->body, "roster unreadable"));
    REQUIRE_FALSE(contains(res->body, "Device not found"));
    REQUIRE_FALSE(h.audits.empty());
    REQUIRE(h.audits.back() == "inventory.device.ci|failure");
    REQUIRE(contains(h.audit_details.back(), "state=roster unreadable"));
}

// Kills: widening the degrade arm to a blanket "roster unreadable" (hides a readable CI record),
// and dropping the result=failure on a degraded identity.
TEST_CASE("route: CI fragment — identity_degraded with a readable CI record still renders it "
          "with the identity note",
          "[hardware][route]") {
    HwHarness h;
    h.ci_detail = degraded_identity_detail(true);
    auto res = h.sink.Get("/fragments/hardware/ci?id=agent-x");
    REQUIRE(res);
    REQUIRE(contains(res->body, "Device identity unavailable"));
    REQUIRE(contains(res->body, "CI-MODEL-5531"));
    REQUIRE_FALSE(contains(res->body, "roster unreadable"));
    REQUIRE_FALSE(contains(res->body, "Device not found"));
    REQUIRE_FALSE(h.audits.empty());
    REQUIRE(h.audits.back() == "inventory.device.ci|failure");
    REQUIRE(contains(h.audit_details.back(), "state=found identity=roster unreadable"));

    auto sw = h.sink.Get("/fragments/hardware/ci?id=agent-x&lens=software&lens_only=1");
    REQUIRE(sw);
    REQUIRE(h.audits.back() == "inventory.device.software|failure");
}

// Kills: letting truly_absent fall through to the existence 404 when identity_degraded.
TEST_CASE("route: GET /api/v1/hardware/{id} — identity_degraded with nothing else readable is 503 - "
          "never 404",
          "[hardware][route][rest]") {
    {
        HwHarness h;
        h.ci_detail = degraded_identity_detail(false);
        auto res = h.sink.Get("/api/v1/hardware/agent-x");
        REQUIRE(res);
        REQUIRE(res->status == 503);
        auto body = nlohmann::json::parse(res->body, nullptr, false);
        REQUIRE_FALSE(body.is_discarded());
        REQUIRE(body["error"]["retry_after_ms"].get<int>() == 5000);
        REQUIRE_FALSE(h.audits.empty());
        REQUIRE(h.audits.back() == "inventory.device.ci|failure");
        REQUIRE_FALSE(res->has_header("Sec-Audit-Failed")); // control: audit persisted
    }
    {
        // Kills: reverting the swap to try_persist_audit — a degraded audit store must still
        // surface Sec-Audit-Failed on top of the unchanged 503.
        HwHarness h;
        h.ci_detail = degraded_identity_detail(false);
        h.audit_should_fail = true;
        auto res = h.sink.Get("/api/v1/hardware/agent-x");
        REQUIRE(res);
        REQUIRE(res->status == 503);
        REQUIRE(res->get_header_value("Sec-Audit-Failed") == "true");
    }
    {
        HwHarness h;
        h.ci_detail = degraded_identity_detail(false);
        h.ci_detail.identity_degraded = false;
        auto res = h.sink.Get("/api/v1/hardware/agent-x");
        REQUIRE(res);
        REQUIRE(res->status == 404);
    }
}

// Kills: moving the scope check below the roster 503 arm (out-of-scope ids would answer
// 503-vs-404, an existence oracle).
TEST_CASE("route: GET /api/v1/hardware/{id} - scope 404 precedes the roster 503 arm",
          "[hardware][route][rest][security]") {
    HwHarness h;
    h.scope = authz::VisibleSet{std::unordered_set<std::string>{"agent-in"}};
    h.ci_detail = degraded_identity_detail(false);
    auto res = h.sink.Get("/api/v1/hardware/agent-out");
    REQUIRE(res);
    REQUIRE(res->status == 404);
    REQUIRE(h.audits.empty());
}

// Kills: dropping the audit-trail id floor - a CR/LF id would reach target_id on the
// roster-failure audit row.
TEST_CASE("route: hardware record id with control bytes is 400 and never audited",
          "[hardware][route][rest][security]") {
    HwHarness h;
    h.ci_detail = degraded_identity_detail(false);
    // TestRouteSink does not percent-decode, so pass the raw CR/LF a decoded request carries.
    const std::string bad_id = "a\r\nb";
    auto rest = h.sink.Get("/api/v1/hardware/" + bad_id);
    REQUIRE(rest);
    REQUIRE(rest->status == 400);
    auto frag = h.sink.Get("/fragments/hardware/ci?id=" + bad_id);
    REQUIRE(frag);
    REQUIRE(frag->status == 400);
    REQUIRE(h.audits.empty());
}

// Kills: dropping the LENGTH arm of the audit-trail id floor, or skipping the floor on either
// route - an over-long id would reach target_id on the audit rows. One byte over the limit.
TEST_CASE("route: hardware record id one byte over the length limit is 400 and never audited",
          "[hardware][route][rest][security]") {
    const std::string too_long(auth::kMaxAgentIdLength + 1, 'a');
    HwHarness h;
    h.ci_detail = degraded_identity_detail(false);
    auto rest = h.sink.Get("/api/v1/hardware/" + too_long);
    REQUIRE(rest);
    REQUIRE(rest->status == 400);
    REQUIRE(contains(rest->body, "invalid device id"));
    REQUIRE(h.audits.empty());
    auto frag = h.sink.Get("/fragments/hardware/ci?id=" + too_long);
    REQUIRE(frag);
    REQUIRE(frag->status == 400);
    REQUIRE(contains(frag->body, "Invalid device id."));
    REQUIRE(h.audits.empty());
}

// Kills: `<` for `<=` on the length arm - an id of exactly the limit is legal, so it must pass the
// floor on both routes and reach its normal audit row (any status but the floor's 400).
TEST_CASE("route: hardware record id of exactly the length limit passes the floor and is audited",
          "[hardware][route][rest][security]") {
    const std::string at_limit(auth::kMaxAgentIdLength, 'a');
    const std::string expected_row = "inventory.device.ci|success|Agent|" + at_limit;
    {
        HwHarness h;
        auto rest = h.sink.Get("/api/v1/hardware/" + at_limit);
        REQUIRE(rest);
        REQUIRE(rest->status != 400);
        REQUIRE_FALSE(h.audit_full.empty());
        REQUIRE(h.audit_full.back() == expected_row);
    }
    {
        HwHarness h;
        auto frag = h.sink.Get("/fragments/hardware/ci?id=" + at_limit);
        REQUIRE(frag);
        REQUIRE(frag->status != 400);
        REQUIRE_FALSE(h.audit_full.empty());
        REQUIRE(h.audit_full.back() == expected_row);
    }
}

// Kills: an over-strict floor on the accept side (`c <= 0x20` refusing a space, or a signed `char`
// refusing every byte >= 0x80) and an over-lax one (a threshold under 0x1f letting US through).
// Accept-side ids are legal on both routes and reach their normal audit row; the reject-side id
// is the floor's 400 with no audit row. (An embedded NUL is not tested: a std::string URL handed
// to the sink may truncate at it, which would turn the case into a vacuous accept.)
TEST_CASE("route: hardware record id floor accepts 0x20 and bytes over 0x7f and refuses 0x1f",
          "[hardware][route][rest][security]") {
    for (const auto& id : {std::string("agent 1"), std::string("a\xC3\xA9")}) {
        CAPTURE(id);
        const std::string expected_row = "inventory.device.ci|success|Agent|" + id;
        {
            HwHarness h;
            auto rest = h.sink.Get("/api/v1/hardware/" + id);
            REQUIRE(rest);
            REQUIRE(rest->status != 400);
            REQUIRE_FALSE(h.audit_full.empty());
            REQUIRE(h.audit_full.back() == expected_row);
        }
        {
            HwHarness h;
            auto frag = h.sink.Get("/fragments/hardware/ci?id=" + id);
            REQUIRE(frag);
            REQUIRE(frag->status != 400);
            REQUIRE_FALSE(h.audit_full.empty());
            REQUIRE(h.audit_full.back() == expected_row);
        }
    }
    const std::string us = "a\x1f" "b";
    HwHarness h;
    h.ci_detail = degraded_identity_detail(false);
    auto rest = h.sink.Get("/api/v1/hardware/" + us);
    REQUIRE(rest);
    REQUIRE(rest->status == 400);
    auto frag = h.sink.Get("/fragments/hardware/ci?id=" + us);
    REQUIRE(frag);
    REQUIRE(frag->status == 400);
    REQUIRE(h.audits.empty());
}

// Kills: moving the floor BELOW the scope gate on either route - an invalid id is refused before
// the scope check, so an out-of-scope (REST) or unpermitted (fragment) caller still sees the
// floor's 400, never the scope 404 / permission 403.
TEST_CASE("route: hardware record id floor is applied before the scope gate",
          "[hardware][route][rest][security]") {
    const std::string too_long(auth::kMaxAgentIdLength + 1, 'a');
    {
        HwHarness h;
        h.scope = authz::VisibleSet{std::unordered_set<std::string>{"agent-in"}};
        auto rest = h.sink.Get("/api/v1/hardware/" + too_long);
        REQUIRE(rest);
        REQUIRE(rest->status == 400);
        REQUIRE(h.audits.empty());
    }
    {
        HwHarness h;
        h.allow_scoped_perm = false;
        auto frag = h.sink.Get("/fragments/hardware/ci?id=" + too_long);
        REQUIRE(frag);
        REQUIRE(frag->status == 400);
        REQUIRE(h.audits.empty());
    }
}

// Kills: skipping the audit-trail id floor on any of the three routes that take a raw device id
// and audit it (REST sync, Actions lens, result poll) - an over-long or CR/LF id would reach
// target_id. Each refusal is the floor's own 400 (body-checked, so the pre-existing 400 arms
// cannot mask a missing floor), writes no audit row, and the sync dispatch is never reached.
// The scoped-permission gate is set to deny: the floor must run BEFORE it, because a denial
// audits the raw id (auth_routes.cpp require_scoped_permission). A floor placed after the gate
// answers 403 here and fails the 400 checks; the fragment responses are also pinned as HTML
// (text/html + the gp-placeholder div) so a JSON envelope repeating the sentence cannot pass.
TEST_CASE("route: sync and actions-lens ids are floored: over-length or control byte is 400 and unaudited",
          "[hardware][route][security]") {
    const std::string too_long(auth::kMaxAgentIdLength + 1, 'a');
    const std::string ctrl = "a\r\nb";
    for (const auto& bad_id : {too_long, ctrl}) {
        HwHarness h;
        h.allow_scoped_perm = false;
        auto sync = h.sink.Post("/api/v1/hardware/" + bad_id + "/sync", R"({"source":"all"})");
        REQUIRE(sync);
        REQUIRE(sync->status == 400);
        REQUIRE(contains(sync->body, "invalid device id"));
        REQUIRE(h.sync_dispatch_calls == 0);

        auto actions = h.sink.Get("/fragments/hardware/ci/actions?id=" + bad_id);
        REQUIRE(actions);
        REQUIRE(actions->status == 400);
        REQUIRE(contains(actions->body, "Invalid device id."));
        CHECK(actions->get_header_value("Content-Type").find("text/html") != std::string::npos);
        CHECK(contains(actions->body, "gp-placeholder"));

        auto result = h.sink.Get("/fragments/hardware/ci/result?id=" + bad_id +
                                 "&plugin=plug&command_id=plug-1");
        REQUIRE(result);
        REQUIRE(result->status == 400);
        REQUIRE(contains(result->body, "Invalid device id."));
        CHECK(result->get_header_value("Content-Type").find("text/html") != std::string::npos);
        CHECK(contains(result->body, "gp-placeholder"));

        REQUIRE(h.audits.empty());
    }
}

// Pins the documented dual-degraded shape: a degraded CI store alongside a degraded roster
// defeats truly_absent, so the record is served (200), not 503.
TEST_CASE("route: GET /api/v1/hardware/{id} — degraded roster AND degraded CI store is 200 with both "
          "states degraded",
          "[hardware][route][rest]") {
    HwHarness h;
    h.ci_detail = degraded_identity_detail(false);
    h.ci_detail.ci = std::expected<std::optional<DeviceCiRecord>, CiReadError>(
        std::unexpected(CiReadError::kDegraded));
    auto res = h.sink.Get("/api/v1/hardware/agent-x");
    REQUIRE(res);
    REQUIRE(res->status == 200);
    auto body = nlohmann::json::parse(res->body);
    REQUIRE(body["data"]["identity_state"].get<std::string>() == "degraded");
    REQUIRE(body["data"]["ci_state"].get<std::string>() == "degraded");
    REQUIRE_FALSE(h.audits.empty());
    REQUIRE(h.audits.back() == "inventory.device.ci|failure");
    REQUIRE(contains(h.audit_details.back(), "state=store degraded identity=roster unreadable"));
}

// Kills: dropping identity_state from hardware_ci_json / the failure audit on a served degraded record.
TEST_CASE("route: GET /api/v1/hardware/{id} — identity_degraded with a readable CI record is 200 "
          "with identity_state=degraded",
          "[hardware][route][rest]") {
    {
        HwHarness h;
        h.ci_detail = degraded_identity_detail(true);
        auto res = h.sink.Get("/api/v1/hardware/agent-x");
        REQUIRE(res);
        REQUIRE(res->status == 200);
        auto body = nlohmann::json::parse(res->body);
        REQUIRE(body["data"]["identity_state"].get<std::string>() == "degraded");
        REQUIRE(body["data"]["ci_state"].get<std::string>() == "found");
        REQUIRE(body["data"]["hostname"].is_null());
        REQUIRE_FALSE(h.audits.empty());
        REQUIRE(h.audits.back() == "inventory.device.ci|failure");
        REQUIRE(contains(h.audit_details.back(), "identity=roster unreadable"));
    }
    {
        HwHarness h;
        h.ci_detail.identity = make_row("agent-x", "HOST-X", "linux", true);
        auto res = h.sink.Get("/api/v1/hardware/agent-x");
        REQUIRE(res);
        REQUIRE(res->status == 200);
        auto body = nlohmann::json::parse(res->body);
        REQUIRE(body["data"]["identity_state"].get<std::string>() == "found");
        REQUIRE_FALSE(h.audits.empty());
        REQUIRE(h.audits.back() == "inventory.device.ci|success");
    }
}

// Remove needs Tag:Delete, which is not Tag:Write: a Write-only viewer is offered Add and no
// Remove (a control that can only 403). Kills: the Remove column keyed off can_write again.
TEST_CASE("route: Tags lens offers Remove only behind a Tag:Delete probe and hosts the "
          "properties fragment",
          "[hardware][route]") {
    HwHarness h;
    h.ci_detail.identity = make_row("agent-1", "TAG-HOST", "windows", true);
    h.ci_detail.tags = std::vector<DeviceTag>{{"agent-1", "owner", "ops", "api", 0}};

    auto full = h.sink.Get("/fragments/hardware/ci?id=agent-1&lens=tags");
    REQUIRE(full);
    CHECK(contains(full->body, "data-act=\"tag-add\""));
    CHECK(contains(full->body, "data-act=\"tag-del\""));
    CHECK(contains(full->body, "/fragments/hardware/ci/properties?id=agent-1"));
    CHECK(contains(full->body, ">Tags and properties<"));

    h.allow_tag_delete = false;
    auto write_only = h.sink.Get("/fragments/hardware/ci?id=agent-1&lens=tags&lens_only=1");
    REQUIRE(write_only);
    CHECK(contains(write_only->body, "data-act=\"tag-add\""));
    CHECK_FALSE(contains(write_only->body, "data-act=\"tag-del\""));

    h.allow_tag_write = false;
    h.allow_tag_delete = true;
    auto delete_only = h.sink.Get("/fragments/hardware/ci?id=agent-1&lens=tags&lens_only=1");
    REQUIRE(delete_only);
    CHECK_FALSE(contains(delete_only->body, "data-act=\"tag-add\""));
    CHECK(contains(delete_only->body, "data-act=\"tag-del\""));
}

// A record view on another lens must not pay a denied-probe audit row for a control it
// never renders. Kills: moving the Tag:Delete probe into affordances_for (every lens).
TEST_CASE("route: the Tag:Delete probe is taken only when the Tags lens is the active one",
          "[hardware][route]") {
    HwHarness h;
    h.ci_detail.identity = make_row("agent-1", "TAG-HOST", "windows", true);
    h.ci_detail.tags = std::vector<DeviceTag>{};

    REQUIRE(h.sink.Get("/fragments/hardware/ci?id=agent-1"));
    REQUIRE(h.sink.Get("/fragments/hardware/ci?id=agent-1&lens=software"));
    CHECK(std::count(h.probes.begin(), h.probes.end(), "Tag:Delete") == 0);

    REQUIRE(h.sink.Get("/fragments/hardware/ci?id=agent-1&lens=tags"));
    CHECK(std::count(h.probes.begin(), h.probes.end(), "Tag:Delete") == 1);
}

// The tags lens moved off the inline hwTagSet/hwTagDelete handlers onto data-act controls
// served by static/yuzu-device-data.js and the shared dialog (A8b: no window.confirm).
// Kills: restoring an inline onclick on Add or Remove.
TEST_CASE("tags lens: controls are data-act, carry no inline handler, and name the service "
          "sentences",
          "[hardware][tags][render]") {
    const std::vector<DeviceTag> tags{{"agent-1", "service", "web", "api", 0},
                                      {"agent-1", "owner", "ops", "api", 0}};
    const auto html = yuzu::server::render_hardware_tags_lens("agent-1", tags, true, true);
    CHECK_FALSE(contains(html, "onclick="));
    CHECK_FALSE(contains(html, "hwTag"));
    CHECK(contains(html, "data-act=\"tag-add\""));
    // The hint lists the real categories including the closed environment set.
    CHECK(contains(html, "environment (Dev, UAT or Production, exact case)"));
    CHECK(contains(html, "management group if it does not exist"));
    // The Remove sentence rides only on the service row.
    const auto svc = html.find("data-key=\"service\"");
    const auto own = html.find("data-key=\"owner\"");
    REQUIRE(svc != std::string::npos);
    REQUIRE(own != std::string::npos);
    CHECK(contains(html.substr(svc, own - svc), "data-service-note="));
    CHECK_FALSE(contains(html.substr(own), "data-service-note="));
}

TEST_CASE("hardware shell loads the dialog module before the device-data controls",
          "[hardware][route]") {
    HwHarness h;
    auto page = h.sink.Get("/hardware");
    REQUIRE(page);
    const auto dlg = page->body.find("src=\"/static/yuzu-dialog.js\" defer");
    const auto dd = page->body.find("src=\"/static/yuzu-device-data.js\" defer");
    REQUIRE(dlg != std::string::npos);
    REQUIRE(dd != std::string::npos);
    CHECK(dlg < dd);
    // The bulk bar's Apply buttons carry the service sentence hwBulkTag shows.
    auto list = h.sink.Get("/fragments/hardware/list");
    REQUIRE(list);
    CHECK(contains(list->body, "data-service-note="));
}

// ---- readouts over the scoped roster (median memory, manufacturer counts) -------------------

namespace {
yuzu::server::InventoryDeviceRow ci_row(const std::string& id, const std::string& ram,
                                        const std::string& vendor) {
    yuzu::server::InventoryDeviceRow r;
    r.agent_id = id;
    r.hostname = id;
    r.ci_ram_bytes = ram;
    r.ci_manufacturer = vendor;
    return r;
}
constexpr const char* kGiB8 = "8589934592";
constexpr const char* kGiB16 = "17179869184";
constexpr const char* kGiB64 = "68719476736";
} // namespace

TEST_CASE("readouts: median memory over rows with a synced figure, odd and even",
          "[hardware][readouts]") {
    using namespace yuzu::server;
    std::size_t n = 0;
    CHECK(*median_ram_gb({ci_row("a", kGiB8, ""), ci_row("b", kGiB16, ""), ci_row("c", kGiB64, "")},
                         &n) == 16.0);
    CHECK(n == 3);
    CHECK(*median_ram_gb({ci_row("a", kGiB8, ""), ci_row("b", kGiB16, "")}) == 12.0);
    // Unsynced, "unknown", zero and non-numeric are not devices with hardware synced.
    CHECK_FALSE(median_ram_gb({ci_row("a", "", ""), ci_row("b", "unknown", ""), ci_row("c", "0", ""),
                               ci_row("d", "12x", "")}, &n));
    CHECK(n == 0);
}

TEST_CASE("readouts: manufacturer counts fold case, sum the tail into Other and skip blanks",
          "[hardware][readouts]") {
    using namespace yuzu::server;
    std::vector<InventoryDeviceRow> rows{ci_row("1", "", "Dell"), ci_row("2", "", " dell "),
                                         ci_row("3", "", "HP"), ci_row("4", "", "unknown"),
                                         ci_row("5", "", "")};
    const auto c = count_by_manufacturer(rows);
    REQUIRE(c.size() == 2);
    CHECK(c[0].first == "Dell");
    CHECK(c[0].second == 2);
    CHECK(c[1].first == "HP");

    rows.clear();
    for (int i = 0; i < 10; ++i)
        rows.push_back(ci_row("d" + std::to_string(i), "", "V" + std::to_string(i)));
    const auto top = count_by_manufacturer(rows, 8);
    REQUIRE(top.size() == 9);
    CHECK(top.back().first == "Other");
    CHECK(top.back().second == 2);
    CHECK(count_by_manufacturer({}).empty());
}

TEST_CASE("readouts: list KPIs describe the scoped roster only and hide when nothing synced",
          "[hardware][readouts]") {
    using namespace yuzu::server;
    // H12: only the rows the confinement gate admitted reach hardware_kpis, so a
    // confined caller's figures cannot include an out-of-scope device.
    const auto admitted = hardware_kpis({ci_row("in-1", kGiB8, "Dell"), ci_row("in-2", kGiB8, "Dell")});
    CHECK(admitted.ram_devices == 2);
    REQUIRE(admitted.by_manufacturer.size() == 1);
    CHECK(admitted.by_manufacturer[0].second == 2);

    HardwareListPage page;
    page.kpis = admitted;
    const auto shown = render_hardware_list_fragment(page, false, false);
    CHECK(contains(shown, "Median memory, 2 devices with hardware synced"));
    CHECK(contains(shown, "By manufacturer: Dell 2"));
    // CI columns degraded: no readout (a blank would read as "none").
    const auto degraded = render_hardware_list_fragment(page, true, false);
    CHECK_FALSE(contains(degraded, "Median memory"));
    // Nothing synced: hidden.
    HardwareListPage bare;
    bare.kpis = hardware_kpis({ci_row("x", "", "")});
    const auto none = render_hardware_list_fragment(bare, false, false);
    CHECK_FALSE(contains(none, "Median memory"));
    CHECK_FALSE(contains(none, "By manufacturer"));
}

TEST_CASE("software lens header: count and last synced, never-synced told apart from degraded",
          "[hardware][readouts]") {
    using namespace yuzu::server;
    const std::vector<SoftwareEntry> sw{SoftwareEntry{}};
    HwSyncAffordance sync;
    const auto synced = render_hardware_software_lens("a", sw, false, true, sync, 1700000000);
    CHECK(contains(synced, "1 application, last synced 2023-11-14"));
    CHECK(contains(render_hardware_software_lens("a", sw, false, true, sync, 0), "never synced"));
    CHECK(contains(render_hardware_software_lens("a", sw, false, true, sync, std::nullopt),
                   "last synced time unavailable"));
    // Click-to-load hosts ride the same lens and nothing is fetched on render.
    CHECK(contains(synced, "hx-trigger=\"click\""));
}
