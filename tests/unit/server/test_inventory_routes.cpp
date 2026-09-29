/// @file test_inventory_routes.cpp
/// Tests for the /inventory dashboard — the PURE renderers (data-in / HTML-out) and
/// the route wiring driven in-process through TestRouteSink (no httplib acceptor,
/// #438). Focus areas: the authoritative-read DEGRADE-≠-EMPTY contract (a nullopt
/// data arg → an "unavailable" banner, never a silent empty table), the FIND per-row
/// management-group scope drop (+ omission audit, mirroring the REST sibling), the
/// per-device scoped-permission gate, and the truncated-cap signal.

#include "inventory_routes.hpp"
#include "test_route_sink.hpp"

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <algorithm>
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

SoftwareCatalogRow cat_row(std::string n, std::string pub, std::int64_t dev, std::int64_t vers) {
    SoftwareCatalogRow r;
    r.name = std::move(n);
    r.publisher = std::move(pub);
    r.device_count = dev;
    r.version_count = vers;
    return r;
}

SoftwareFleetRow fleet_row(std::string agent, std::string name, std::string ver) {
    SoftwareFleetRow r;
    r.agent_id = std::move(agent);
    r.entry.name = std::move(name);
    r.entry.version = std::move(ver);
    return r;
}

} // namespace

// ───────────────────────── PURE renderers ──────────────────────────────────────

TEST_CASE("software fragment: degrade is a banner, never an empty table", "[inventory][ui]") {
    // cat nullopt = rollup unreadable → degrade banner (meta irrelevant).
    const std::string degraded =
        render_inventory_software_fragment(std::nullopt, std::nullopt, "", std::nullopt, false, 2000);
    REQUIRE(contains(degraded, "unavailable"));
    REQUIRE(contains(degraded, "authoritative"));
    // A degrade must NOT masquerade as a genuine "nothing installed".
    REQUIRE_FALSE(contains(degraded, "No installed-software inventory has been reported"));
}

TEST_CASE("software fragment: building vs genuine empty are distinct", "[inventory][ui]") {
    // meta.refreshed_at == 0 → rollup never computed → "building", NOT a false empty.
    const std::string building = render_inventory_software_fragment(
        std::optional<std::vector<SoftwareCatalogRow>>(std::vector<SoftwareCatalogRow>{}),
        std::optional<CatalogRollupMeta>(CatalogRollupMeta{0, 0, 0}), "", std::int64_t{0}, false,
        2000);
    REQUIRE(contains(building, "building"));
    REQUIRE_FALSE(contains(building, "No installed-software inventory has been reported"));

    // meta.refreshed_at > 0 + empty rollup → honest "nothing installed", not building/degrade.
    const std::string empty = render_inventory_software_fragment(
        std::optional<std::vector<SoftwareCatalogRow>>(std::vector<SoftwareCatalogRow>{}),
        std::optional<CatalogRollupMeta>(CatalogRollupMeta{1000, 0, 0}), "", std::int64_t{0}, false,
        2000);
    REQUIRE(contains(empty, "No installed-software inventory has been reported"));
    REQUIRE_FALSE(contains(empty, "unavailable"));
    REQUIRE_FALSE(contains(empty, "building"));
}

TEST_CASE("software fragment: rows render with counts, KPIs from meta, drill link", "[inventory][ui]") {
    std::vector<SoftwareCatalogRow> rows{cat_row("Google Chrome", "Google LLC", 1180, 3),
                                         cat_row("7-Zip", "Igor Pavlov", 889, 1)};
    const std::string html = render_inventory_software_fragment(
        rows, std::optional<CatalogRollupMeta>(CatalogRollupMeta{1000, 2, 1284}), "",
        std::int64_t{37}, /*capped=*/false, /*now=*/2000);
    REQUIRE(contains(html, "Google Chrome"));
    REQUIRE(contains(html, "1180"));
    REQUIRE(contains(html, "Igor Pavlov"));
    // Each row drills into the version breakdown.
    REQUIRE(contains(html, "/fragments/inventory/software/versions?name=Google%20Chrome"));
    // KPIs come from the rollup meta: titles, devices-reporting, stale, and the "as of" line.
    REQUIRE(contains(html, "1284")); // devices reporting (meta.total_devices)
    REQUIRE(contains(html, "37"));   // stale count
    REQUIRE(contains(html, "updated")); // "updated 16m ago" (now-refreshed_at = 1000s)
    // Fleet-wide scope caveat is present (ADR-0017 honesty).
    REQUIRE(contains(html, "not yet effective"));
}

TEST_CASE("software fragment: capped shows the list-capped banner", "[inventory][ui]") {
    std::vector<SoftwareCatalogRow> rows{cat_row("A", "p", 1, 1)};
    const std::string html = render_inventory_software_fragment(
        rows, std::optional<CatalogRollupMeta>(CatalogRollupMeta{1000, 1, 1}), "", std::nullopt,
        /*capped=*/true, /*now=*/2000);
    REQUIRE(contains(html, "list capped"));
}

TEST_CASE("versions fragment: degrade banner vs empty vs share bars", "[inventory][ui]") {
    // nullopt = store degrade → banner.
    REQUIRE(contains(render_inventory_versions_fragment("Chrome", std::nullopt), "unavailable"));

    // Empty-non-null (a title since fully uninstalled) = honest empty, NOT a degrade (gov F2).
    const std::string empty = render_inventory_versions_fragment(
        "Chrome", std::optional<std::vector<SoftwareVersionCount>>(std::vector<SoftwareVersionCount>{}));
    REQUIRE(contains(empty, "No version data"));
    REQUIRE_FALSE(contains(empty, "unavailable"));

    // Empty name = precondition miss → "select a title" note, NOT the store-failed banner (gov happy-NICE).
    const std::string noname = render_inventory_versions_fragment("", std::nullopt);
    REQUIRE(contains(noname, "Select a title"));
    REQUIRE_FALSE(contains(noname, "unavailable"));

    std::vector<SoftwareVersionCount> vers{{"126.0", 742}, {"125.0", 301}};
    const std::string html = render_inventory_versions_fragment("Chrome", vers);
    REQUIRE(contains(html, "126.0"));
    REQUIRE(contains(html, "742"));
    REQUIRE(contains(html, "Installs per version"));
    REQUIRE(contains(html, "width:100%")); // the top version is the full-width bar
}

TEST_CASE("device-software fragment: degrade vs empty vs rows; offline note", "[inventory][ui]") {
    // Absent (a value holding std::nullopt) — CI is orthogonal to these assertions.
    const std::expected<std::optional<DeviceCiRecord>, CiReadError> ci_absent{std::nullopt};

    REQUIRE(contains(render_inventory_device_software_fragment("a1", "HOST", std::nullopt, true,
                                                               ci_absent, 2000),
                     "unavailable"));

    const std::string empty = render_inventory_device_software_fragment(
        "a1", "HOST", std::optional<std::vector<SoftwareEntry>>(std::vector<SoftwareEntry>{}), true,
        ci_absent, 2000);
    REQUIRE(contains(empty, "No installed software recorded"));
    REQUIRE_FALSE(contains(empty, "unavailable"));

    SoftwareEntry e;
    e.name = "Slack";
    e.version = "4.38";
    const std::string offline = render_inventory_device_software_fragment(
        "a1", "HOST", std::optional<std::vector<SoftwareEntry>>(std::vector<SoftwareEntry>{e}),
        /*online=*/false, ci_absent, 2000);
    REQUIRE(contains(offline, "Slack"));
    REQUIRE(contains(offline, "offline")); // the "last daily sync, not live" note
}

TEST_CASE("device-CI panel: degrade vs absent vs found; sentinel + humanized fields",
          "[inventory][ui]") {
    // std::unexpected(kDegraded) -> a degrade banner, distinct wording from "no CI record"
    // (ADR-0016 §7 authoritative-read honesty — never conflate the two).
    const std::expected<std::optional<DeviceCiRecord>, CiReadError> degraded =
        std::unexpected(CiReadError::kDegraded);
    const std::string deg = render_inventory_device_software_fragment(
        "a1", "HOST", std::optional<std::vector<SoftwareEntry>>(std::vector<SoftwareEntry>{}), true,
        degraded, 2000);
    REQUIRE(contains(deg, "CI record unavailable"));
    REQUIRE_FALSE(contains(deg, "No CI record synced"));

    // A value holding std::nullopt -> genuinely not synced yet, NOT a degrade.
    const std::expected<std::optional<DeviceCiRecord>, CiReadError> absent{std::nullopt};
    const std::string abs = render_inventory_device_software_fragment(
        "a1", "HOST", std::optional<std::vector<SoftwareEntry>>(std::vector<SoftwareEntry>{}), true,
        absent, 2000);
    REQUIRE(contains(abs, "No CI record synced"));
    REQUIRE_FALSE(contains(abs, "unavailable"));

    // A found record renders the grid; humanized CPU/RAM; the "unknown" sentinel (a
    // genuinely serial-less VM) renders as a placeholder, never the raw word.
    DeviceCiRecord rec;
    rec.manufacturer = "Dell Inc.";
    rec.model = "OptiPlex 7090";
    rec.serial = "unknown";
    rec.system_uuid = "ABC-123";
    rec.cpu_model = "Intel Core i7";
    rec.cpu_cores = "8";
    rec.cpu_threads = "16";
    rec.ram_bytes = "17179869184"; // 16 GiB
    rec.primary_mac = "AA:BB:CC:DD:EE:FF";
    rec.os_name = "Windows";
    rec.os_version = "11";
    rec.os_build = "22631";
    rec.arch = "x86_64";
    rec.first_seen = 1000;
    rec.last_seen = 1900;
    const std::expected<std::optional<DeviceCiRecord>, CiReadError> found{
        std::optional<DeviceCiRecord>(rec)};
    const std::string html = render_inventory_device_software_fragment(
        "a1", "HOST", std::optional<std::vector<SoftwareEntry>>(std::vector<SoftwareEntry>{}), true,
        found, 2000);
    REQUIRE(contains(html, "Dell Inc."));
    REQUIRE(contains(html, "OptiPlex 7090"));
    REQUIRE(contains(html, "ABC-123"));
    REQUIRE(contains(html, "8c/16t"));
    REQUIRE(contains(html, "16.0 GB"));
    REQUIRE(contains(html, "AA:BB:CC:DD:EE:FF"));
    REQUIRE(contains(html, "&mdash;"));      // the "unknown" serial's placeholder
    REQUIRE_FALSE(contains(html, ">unknown<")); // never rendered as raw text
}

TEST_CASE("devices fragment: real CI columns + offline-inclusive rows", "[inventory][ui]") {
    std::vector<InventoryDeviceRow> rows;
    InventoryDeviceRow on;
    on.agent_id = "a1";
    on.hostname = "WIN-1";
    on.os = "windows";
    on.online = true;
    on.last_seen = "now";
    // Device-CI enrichment (PR2) — as attach_device_ci would fill it in.
    on.ci_serial = "SN12345";
    on.ci_model = "OptiPlex 7090";
    on.ci_cpu_cores = "8";
    on.ci_cpu_threads = "16";
    on.ci_ram_bytes = "17179869184"; // 16 GiB
    InventoryDeviceRow off;
    off.agent_id = "a2";
    off.hostname = "UB-2";
    off.os = "linux";
    off.online = false;
    off.stale = true;
    off.last_seen = "3d ago";
    // off's ci_* fields are left default-empty — no CI synced yet for this agent.
    rows.push_back(on);
    rows.push_back(off);
    const std::string html = render_inventory_devices_fragment(rows, "", "", "");
    REQUIRE(contains(html, "WIN-1"));
    REQUIRE(contains(html, "UB-2"));      // offline device still appears
    REQUIRE(contains(html, "3d ago"));
    REQUIRE(contains(html, "stale"));
    // The per-device drill carries host + online into the URL.
    REQUIRE(contains(html, "/fragments/inventory/device?id=a1&host=WIN-1&online=1"));
    // Real CI columns for the enriched row.
    REQUIRE(contains(html, "SN12345"));
    REQUIRE(contains(html, "OptiPlex 7090"));
    REQUIRE(contains(html, "8c/16t"));
    REQUIRE(contains(html, "16.0 GB"));
    // The un-synced row's CI cells fall back to the placeholder, not a blank/garbage cell.
    REQUIRE(contains(html, "&mdash;"));
}

TEST_CASE("find results: truncated + omitted signals; degrade vs empty", "[inventory][ui]") {
    REQUIRE(contains(render_inventory_find_results_fragment("X", std::nullopt, false, 0),
                     "unavailable"));

    // Empty (non-null) → honest fleet-wide "no devices run X", not a degrade and not
    // implying scope-narrowing (Find is fleet-wide today; gov consistency/security).
    const std::string empty = render_inventory_find_results_fragment(
        "X", std::optional<std::vector<SoftwareFleetRow>>(std::vector<SoftwareFleetRow>{}), false, 0);
    REQUIRE(contains(empty, "No devices run"));
    REQUIRE_FALSE(contains(empty, "in your scope"));

    std::vector<SoftwareFleetRow> rows{fleet_row("a1", "X", "1.0")};
    const std::string html = render_inventory_find_results_fragment("X", rows, /*hit_cap=*/true,
                                                                    /*devices_omitted=*/2);
    REQUIRE(contains(html, "truncated at cap"));
    REQUIRE(contains(html, "2 device(s) outside your scope"));
    REQUIRE(contains(html, "a1"));
}

// ───────────────────────── route wiring ────────────────────────────────────────

namespace {

struct InvHarness {
    yuzu::server::test::TestRouteSink sink;
    InventoryRoutes routes;

    bool allow_perm = true;          // global Inventory:Read
    bool allow_scoped = true;        // per-device scoped Inventory:Read
    bool degrade = false;            // make every store provider return nullopt
    bool audit_should_fail = false;  // simulate an audit-persist failure (Sec-Audit-Failed)
    bool unwire_devices = false;     // register with an empty DevicesFn{} (unwired closure)
    bool service_scoped = false;     // simulate a service-scoped API token session
    std::optional<DeviceCiRecord> ci_record; // nullopt (default) = "absent, not yet synced"
    std::vector<SoftwareFleetRow> fleet_rows;
    std::vector<std::string> in_scope_agents; // FIND per-row scope predicate allow-list
    std::vector<std::string> audits;          // "action|result"
    std::vector<std::string> audit_full;      // "action|result|target_type|target_id" (parity check)
    std::vector<std::string> audit_details;   // detail strings, parallel to `audits`

    // Round-3 item 8 fixtures: agent_id -> hostname (HostnamesFn fake) for the
    // SOFTWARE "devices ›" expansion, and the last query object each fleet-wide
    // provider actually received (so a test can assert what the ROUTE forwarded,
    // not just what the fake chose to return).
    std::unordered_map<std::string, std::string> hostnames;
    std::optional<SoftwareCatalogQuery> last_catalog_query;
    std::optional<SoftwareFleetQuery> last_fleet_query; // shared by /find/results + /software/devices

    // `unwire_devices_` must be a constructor param, not a post-construction field write —
    // `register_routes` (below) runs once, here, so the DevicesFn choice is baked in at
    // construction time (unlike `degrade`, which every provider lambda re-checks per-call).
    explicit InvHarness(bool unwire_devices_ = false) : unwire_devices(unwire_devices_) {
        auto auth = [this](const httplib::Request&, httplib::Response&) {
            auth::Session s;
            if (service_scoped)
                s.token_scope_service = "printers";
            return std::optional<auth::Session>(s);
        };
        auto perm = [this](const httplib::Request&, httplib::Response& res, const std::string&,
                           const std::string&) {
            if (!allow_perm)
                res.status = 403;
            return allow_perm;
        };
        auto scoped = [this](const httplib::Request&, httplib::Response& res, const std::string&,
                             const std::string&, const std::string&) {
            if (!allow_scoped)
                res.status = 403;
            return allow_scoped;
        };
        auto catalog = [this](const SoftwareCatalogQuery& q)
            -> std::optional<std::vector<SoftwareCatalogRow>> {
            last_catalog_query = q;
            if (degrade)
                return std::nullopt;
            return std::vector<SoftwareCatalogRow>{cat_row("Chrome", "Google", 5, 2)};
        };
        auto catalog_meta = [this]() -> std::optional<CatalogRollupMeta> {
            if (degrade)
                return std::nullopt;
            return CatalogRollupMeta{1000, 1, 5}; // refreshed_at>0 → not "building"
        };
        auto versions = [this](const std::string&, int)
            -> std::optional<std::vector<SoftwareVersionCount>> {
            if (degrade)
                return std::nullopt;
            return std::vector<SoftwareVersionCount>{{"1.0", 5}};
        };
        auto fleet = [this](const SoftwareFleetQuery& q)
            -> std::optional<std::vector<SoftwareFleetRow>> {
            last_fleet_query = q;
            if (degrade)
                return std::nullopt;
            return fleet_rows;
        };
        auto agent_sw = [this](const std::string&) -> std::optional<std::vector<SoftwareEntry>> {
            if (degrade)
                return std::nullopt;
            SoftwareEntry e;
            e.name = "Slack";
            return std::vector<SoftwareEntry>{e};
        };
        auto devices = [this](const std::string&) -> InventoryDevicesResult {
            InventoryDeviceRow r;
            r.agent_id = "a1";
            r.hostname = "WIN-1";
            r.os = "windows";
            r.online = true;
            r.last_seen = "now";
            // Mirrors the real provider's contract: a CI-store degrade never blanks the
            // roster, it only means the CI columns (unmodeled in this harness fixture)
            // would be blank — `degrade` toggles JUST the ci_degraded signal here.
            InventoryDevicesResult result;
            result.rows = {r};
            result.ci_degraded = degrade;
            return result;
        };
        auto ci_fn = [this](const std::string&)
            -> std::expected<std::optional<DeviceCiRecord>, CiReadError> {
            if (degrade)
                return std::unexpected(CiReadError::kDegraded);
            return ci_record; // nullopt (default) = absent; set to a record = found
        };
        auto scope = [this](const std::string&, const std::string& agent_id) {
            for (const auto& a : in_scope_agents)
                if (a == agent_id)
                    return true;
            return false;
        };
        auto stale = [this]() -> std::optional<std::int64_t> {
            return degrade ? std::nullopt : std::optional<std::int64_t>(7);
        };
        auto audit = [this](const httplib::Request&, const std::string& a, const std::string& r,
                            const std::string& tt, const std::string& tid,
                            const std::string& detail) {
            audits.push_back(a + "|" + r);
            audit_full.push_back(a + "|" + r + "|" + tt + "|" + tid);
            audit_details.push_back(detail);
            return !audit_should_fail;
        };
        auto hostnames_fn = [this]() -> std::unordered_map<std::string, std::string> {
            return hostnames;
        };
        InventoryRoutes::DevicesFn devices_fn = devices;
        if (unwire_devices)
            devices_fn = InventoryRoutes::DevicesFn{}; // empty closure — route treats as degraded
        routes.register_routes(sink, auth, perm, scoped, catalog, catalog_meta, versions, fleet,
                               agent_sw, devices_fn, scope, stale, audit, ci_fn, hostnames_fn);
    }
};

} // namespace

TEST_CASE("route: software fragment denied without Inventory:Read", "[inventory][route]") {
    InvHarness h;
    h.allow_perm = false;
    auto res = h.sink.Get("/fragments/inventory/software");
    REQUIRE(res);
    REQUIRE(res->status == 403);
    REQUIRE_FALSE(contains(res->body, "Chrome"));
}

TEST_CASE("route: software fragment renders catalogue + audits", "[inventory][route]") {
    InvHarness h;
    auto res = h.sink.Get("/fragments/inventory/software");
    REQUIRE(res);
    REQUIRE(contains(res->body, "Chrome"));
    bool audited = false;
    for (const auto& a : h.audits)
        if (a == "inventory.software.catalog|success")
            audited = true;
    REQUIRE(audited);
    // Securable + target_id parity with audit-log.md (gov consistency NICE-1): a rename of
    // the securable or the target shape away from the doc must fail a test.
    bool target_ok = false;
    for (const auto& a : h.audit_full)
        if (a == "inventory.software.catalog|success|Inventory|fleet")
            target_ok = true;
    REQUIRE(target_ok);
}

TEST_CASE("route: software fragment degrade → banner, audited failure", "[inventory][route]") {
    InvHarness h;
    h.degrade = true;
    auto res = h.sink.Get("/fragments/inventory/software");
    REQUIRE(res);
    REQUIRE(contains(res->body, "unavailable"));
    bool failed = false;
    for (const auto& a : h.audits)
        if (a == "inventory.software.catalog|failure")
            failed = true;
    REQUIRE(failed);
}

TEST_CASE("route: per-device drill is scope-gated", "[inventory][route]") {
    InvHarness h;
    h.allow_scoped = false;
    auto denied = h.sink.Get("/fragments/inventory/device?id=a1&host=WIN-1&online=1");
    REQUIRE(denied);
    REQUIRE(denied->status == 403);
    REQUIRE_FALSE(contains(denied->body, "Slack"));

    h.allow_scoped = true;
    auto ok = h.sink.Get("/fragments/inventory/device?id=a1&host=WIN-1&online=1");
    REQUIRE(ok);
    REQUIRE(contains(ok->body, "Slack"));
}

TEST_CASE("route: inventory.devices + inventory.device.ci are the behavioural-PII audit "
          "tier (Sec-Audit-Failed on a persist failure)",
          "[inventory][route]") {
    // gov Gate 2 finding: both verbs carry a device-persistent identifier (serial) now,
    // so both were promoted from try_persist_audit to emit_behavioral_audit. Prove the
    // header actually appears on a persist failure — not just that the detail string
    // looks right (the prior tests already cover content; this locks in the tier).
    {
        InvHarness h;
        h.audit_should_fail = true;
        auto res = h.sink.Get("/fragments/inventory/devices");
        REQUIRE(res);
        REQUIRE(res->status != 403);
        REQUIRE(res->has_header("Sec-Audit-Failed"));
        // Set-and-proceed: the HTML fragment still renders despite the audit failure.
        REQUIRE(contains(res->body, "WIN-1"));
    }
    {
        InvHarness h;
        h.audit_should_fail = true;
        auto res = h.sink.Get("/fragments/inventory/device?id=a1&host=WIN-1&online=1");
        REQUIRE(res);
        REQUIRE(res->has_header("Sec-Audit-Failed"));
    }
}

TEST_CASE("route: per-device drill renders the CI panel + audits inventory.device.ci",
          "[inventory][route]") {
    {
        // Default ci_record (nullopt) = absent, not yet synced -> "success" audit (a
        // genuine absent read is not a failure), honest empty note in the body.
        InvHarness h;
        auto res = h.sink.Get("/fragments/inventory/device?id=a1&host=WIN-1&online=1");
        REQUIRE(res);
        REQUIRE(contains(res->body, "No CI record synced"));
        bool ok = false;
        for (const auto& a : h.audits)
            if (a == "inventory.device.ci|success")
                ok = true;
        REQUIRE(ok);
    }
    {
        // A found record -> the CI grid renders; audit is still "success".
        InvHarness h;
        DeviceCiRecord rec;
        rec.serial = "SN-ROUTE-1";
        h.ci_record = rec;
        auto res = h.sink.Get("/fragments/inventory/device?id=a1&host=WIN-1&online=1");
        REQUIRE(res);
        REQUIRE(contains(res->body, "SN-ROUTE-1"));
        bool ok = false;
        for (const auto& a : h.audits)
            if (a == "inventory.device.ci|success")
                ok = true;
        REQUIRE(ok);
    }
    {
        // Degrade -> "failure" audit + a degrade banner (distinct from "absent"). Note:
        // InvHarness's single `degrade` flag ALSO degrades agent_sw_fn_ in this same
        // request (gov Gate 3 quality-engineer finding — this is the first route-level
        // exercise of the software-degrade path on THIS endpoint, so assert on it too
        // rather than leaving it silently unchecked).
        InvHarness h;
        h.degrade = true;
        auto res = h.sink.Get("/fragments/inventory/device?id=a1&host=WIN-1&online=1");
        REQUIRE(res);
        REQUIRE(contains(res->body, "CI record unavailable"));
        bool ci_failed = false;
        for (const auto& a : h.audits)
            if (a == "inventory.device.ci|failure")
                ci_failed = true;
        REQUIRE(ci_failed);
        // The sibling software read is ALSO degraded by the same flag in this request —
        // assert its banner + audit too, so this test's coverage of the combined-degrade
        // path is actually cashed in, not just incidentally exercised.
        REQUIRE(contains(res->body, "Device software unavailable"));
        bool sw_failed = false;
        for (const auto& a : h.audits)
            if (a == "inventory.device.software|failure")
                sw_failed = true;
        REQUIRE(sw_failed);
    }
}

TEST_CASE("route: find results apply the per-row management-group drop filter", "[inventory][route]") {
    InvHarness h;
    // Unambiguous IDs (gov F5): a short literal like "a2" risks incidental HTML matches.
    h.fleet_rows = {fleet_row("agent-alpha", "Chrome", "1.0"),
                    fleet_row("agent-bravo", "Chrome", "2.0")};
    h.in_scope_agents = {"agent-alpha"}; // agent-bravo is out of the operator's scope

    auto res = h.sink.Get("/fragments/inventory/find/results?name=Chrome");
    REQUIRE(res);
    REQUIRE(contains(res->body, "agent-alpha"));
    REQUIRE_FALSE(contains(res->body, "agent-bravo"));   // dropped, not leaked
    REQUIRE(contains(res->body, "1 device(s) outside")); // omission surfaced
    bool denied = false, ok = false;
    for (const auto& a : h.audits) {
        denied = denied || a == "inventory.software.query|denied";
        ok = ok || a == "inventory.software.query|success";
    }
    REQUIRE(denied);
    REQUIRE(ok);
}

// Governance finding (guardian-confinement-2298 Gate 2/4/6): the per-row
// management-group drop filter above is the ONLY confinement this route had —
// it never checks token_scope_service, so a service-scoped token still saw
// every out-of-service device running the searched-for software fleet-wide
// (this file's own /fragments/inventory/devices sibling, two routes above,
// already closed this exact class). Blanket deny, matching that sibling.
TEST_CASE("route: find results — service-scoped token denied, no data leaked, denial audited",
          "[inventory][route][security]") {
    InvHarness h;
    h.service_scoped = true;
    h.fleet_rows = {fleet_row("agent-alpha", "Chrome", "1.0")};

    auto res = h.sink.Get("/fragments/inventory/find/results?name=Chrome");
    REQUIRE(res);
    REQUIRE(res->status == 403);
    REQUIRE_FALSE(contains(res->body, "agent-alpha"));
    // #3167: no `.permission` (no grant admits a service-scoped caller here —
    // naming one is a false self-remediation claim), and header/body
    // correlation-id parity.
    auto body = nlohmann::json::parse(res->body, nullptr, false);
    REQUIRE_FALSE(body.is_discarded());
    CHECK_FALSE(body["error"].contains("permission"));
    CHECK_FALSE(body["error"]["correlation_id"].get<std::string>().empty());
    CHECK(res->get_header_value("X-Correlation-Id") ==
         body["error"]["correlation_id"].get<std::string>());
    bool denied = false;
    for (const auto& a : h.audits) {
        if (a == "inventory.software.query|denied")
            denied = true;
        REQUIRE(a != "inventory.software.query|success");
    }
    REQUIRE(denied);
    // Gate 8: pin target_id="fleet" to match the REST/MCP siblings and
    // audit-log.md's documented uniform shape.
    REQUIRE(std::find(h.audit_full.begin(), h.audit_full.end(),
                      "inventory.software.query|denied|Inventory|fleet") != h.audit_full.end());
}

TEST_CASE("route: find results empty name short-circuits (no store read)", "[inventory][route]") {
    InvHarness h;
    auto res = h.sink.Get("/fragments/inventory/find/results?name=");
    REQUIRE(res);
    REQUIRE(contains(res->body, "Type an exact software name"));
    // No data read → no audit row (gov compliance NICE / F4 boundary).
    REQUIRE(h.audits.empty());
}

TEST_CASE("route: find results degrade → banner + audited failure", "[inventory][route]") {
    InvHarness h;
    h.degrade = true; // fleet_fn_ returns nullopt for a non-empty name
    auto res = h.sink.Get("/fragments/inventory/find/results?name=Chrome");
    REQUIRE(res);
    REQUIRE(contains(res->body, "unavailable"));
    bool failed = false;
    for (const auto& a : h.audits)
        if (a == "inventory.software.query|failure")
            failed = true;
    REQUIRE(failed);
}

TEST_CASE("route: version drill — deny, success+audit, degrade", "[inventory][route]") {
    {
        InvHarness h;
        h.allow_perm = false;
        auto res = h.sink.Get("/fragments/inventory/software/versions?name=Chrome");
        REQUIRE(res);
        REQUIRE(res->status == 403);
    }
    {
        InvHarness h;
        auto res = h.sink.Get("/fragments/inventory/software/versions?name=Chrome");
        REQUIRE(res);
        REQUIRE(contains(res->body, "Installs per version"));
        bool ok = false;
        for (const auto& a : h.audits)
            if (a == "inventory.software.versions|success")
                ok = true;
        REQUIRE(ok);
    }
    {
        InvHarness h;
        h.degrade = true;
        auto res = h.sink.Get("/fragments/inventory/software/versions?name=Chrome");
        REQUIRE(res);
        REQUIRE(contains(res->body, "unavailable"));
        bool failed = false;
        for (const auto& a : h.audits)
            if (a == "inventory.software.versions|failure")
                failed = true;
        REQUIRE(failed);
    }
}

TEST_CASE("route: devices list — deny vs success (offline-inclusive, audited)",
          "[inventory][route]") {
    {
        InvHarness h;
        h.allow_perm = false;
        auto res = h.sink.Get("/fragments/inventory/devices");
        REQUIRE(res);
        REQUIRE(res->status == 403);
        REQUIRE_FALSE(contains(res->body, "WIN-1"));
    }
    {
        InvHarness h;
        auto res = h.sink.Get("/fragments/inventory/devices");
        REQUIRE(res);
        REQUIRE(contains(res->body, "WIN-1"));
        // The identity-bearing roster read is audited (gov review #1759 — parity with the
        // other inventory surfaces).
        bool audited = false;
        for (const auto& a : h.audits)
            if (a == "inventory.devices|success")
                audited = true;
        REQUIRE(audited);
    }
}

// SEC-2/SEC-3 confinement-gap class (found during a docs sweep): devices_fn
// on /fragments/inventory/devices is username-keyed and does not confine a
// service-scoped API token whose principal resolves to an unscoped grant —
// the GDPR-personal-data roster (serial/system_uuid/primary_mac) would still
// be fleet-wide.
TEST_CASE("route: devices list — service-scoped token denied, denial audited",
          "[inventory][route][security]") {
    InvHarness h;
    h.service_scoped = true;
    auto res = h.sink.Get("/fragments/inventory/devices");
    REQUIRE(res);
    REQUIRE(res->status == 403);
    REQUIRE_FALSE(contains(res->body, "WIN-1"));
    // #3167: no `.permission` (no grant admits a service-scoped caller here —
    // naming one is a false self-remediation claim), and header/body
    // correlation-id parity.
    auto body = nlohmann::json::parse(res->body, nullptr, false);
    REQUIRE_FALSE(body.is_discarded());
    CHECK_FALSE(body["error"].contains("permission"));
    CHECK_FALSE(body["error"]["correlation_id"].get<std::string>().empty());
    CHECK(res->get_header_value("X-Correlation-Id") ==
         body["error"]["correlation_id"].get<std::string>());
    bool denied = false;
    for (const auto& a : h.audits) {
        if (a == "inventory.devices|denied")
            denied = true;
        REQUIRE(a != "inventory.devices|success");
    }
    REQUIRE(denied);
}

TEST_CASE("route: devices list — CI enrichment degrade audits failure, roster still renders",
          "[inventory][route]") {
    // #1785 review HIGH-1: a CI-store degrade must never masquerade as "success" in the
    // audit trail, even though the roster itself (offline-survivable, independent of the
    // CI-enrichment join) still renders — set-and-proceed for the HTML, honest for audit.
    InvHarness h;
    h.degrade = true;
    auto res = h.sink.Get("/fragments/inventory/devices");
    REQUIRE(res);
    REQUIRE(res->status != 403);
    REQUIRE(contains(res->body, "WIN-1")); // roster unaffected by the CI-join degrade
    bool failed = false, succeeded = false;
    for (const auto& a : h.audits) {
        failed = failed || a == "inventory.devices|failure";
        succeeded = succeeded || a == "inventory.devices|success";
    }
    REQUIRE(failed);
    REQUIRE_FALSE(succeeded);
}

TEST_CASE("route: devices list — unwired DevicesFn audits failure on an empty roster",
          "[inventory][route]") {
    // gov Gate 3 quality-engineer finding: the route's `else result.ci_degraded = true;`
    // branch (an unwired devices_fn_, production-unreachable but defensively handled —
    // mirrors agent_ci_fn_/agent_sw_fn_ elsewhere in this file) had no direct coverage.
    InvHarness h{/*unwire_devices_=*/true};
    auto res = h.sink.Get("/fragments/inventory/devices");
    REQUIRE(res);
    REQUIRE(res->status != 403);
    bool failed = false, succeeded = false;
    for (const auto& a : h.audits) {
        failed = failed || a == "inventory.devices|failure";
        succeeded = succeeded || a == "inventory.devices|success";
    }
    REQUIRE(failed);
    REQUIRE_FALSE(succeeded);
    // The empty-roster wording is distinct from the populated-roster degrade wording.
    bool honest_empty_detail = false;
    for (const auto& d : h.audit_details)
        if (contains(d, "device roster or CI store unavailable"))
            honest_empty_detail = true;
    REQUIRE(honest_empty_detail);
}

TEST_CASE("route: find shell gates on Inventory:Read", "[inventory][route]") {
    InvHarness h;
    h.allow_perm = false;
    auto res = h.sink.Get("/fragments/inventory/find");
    REQUIRE(res);
    REQUIRE(res->status == 403);
}

// ───────────────── Round-3 items 8/9: search, devices expansion, Find retired ──────

TEST_CASE("route: software fragment results_only=1 returns only the #sw-results region",
          "[inventory][route]") {
    // Mirrors hardware_ui.cpp's results_only fix for the identical class of bug: the
    // search box's own hx-get must swap ONLY #sw-results, never the full page (which
    // would re-include the triggering <input> and destroy it mid-keystroke).
    InvHarness h;
    auto res = h.sink.Get("/fragments/inventory/software?results_only=1");
    REQUIRE(res);
    REQUIRE(contains(res->body, "id=\"sw-results\""));
    REQUIRE(contains(res->body, "Chrome")); // the catalogue row itself still renders
    // The full-page chrome (KPI strip / search box / sub-nav / <h1>) is excluded.
    REQUIRE_FALSE(contains(res->body, "inv-kpis"));
    REQUIRE_FALSE(contains(res->body, "id=\"sw-q\""));
    REQUIRE_FALSE(contains(res->body, "inv-subnav"));
    REQUIRE_FALSE(contains(res->body, "inv-h1"));
}

TEST_CASE("route: software fragment forwards q into the store's name_filter",
          "[inventory][route]") {
    InvHarness h;
    auto res = h.sink.Get("/fragments/inventory/software?q=adobe");
    REQUIRE(res);
    REQUIRE(h.last_catalog_query.has_value());
    REQUIRE(h.last_catalog_query->name_filter == "adobe");
}

TEST_CASE("route: software devices — hostname resolution, columns, filter-group id",
          "[inventory][route]") {
    InvHarness h;
    h.in_scope_agents = {"agent-known", "agent-unknown"}; // else the scope filter drops both rows
    h.hostnames = {{"agent-known", "HOST-A"}}; // agent-unknown carries no mapping
    h.fleet_rows = {fleet_row("agent-known", "Chrome", "1.0"),
                    fleet_row("agent-unknown", "Chrome", "1.0")};
    auto res = h.sink.Get("/fragments/inventory/software/devices?name=Chrome");
    REQUIRE(res);
    REQUIRE(res->status == 200);

    // HostnamesFn resolution: a known mapping renders the HOSTNAME as the link
    // text; a miss falls back to the bare agent_id — both still link to the
    // per-device Hardware CI page (round-3 item 8).
    REQUIRE(contains(res->body, "<a href=\"/hardware/ci?id=agent-known\">HOST-A</a>"));
    REQUIRE(contains(res->body, "<a href=\"/hardware/ci?id=agent-unknown\">agent-unknown</a>"));

    // Columns: Version/Publisher/Install date/Signature/Ecosystem/Arch — Signature
    // and Ecosystem were previously unrendered anywhere (round-3 item 8 doc comment).
    REQUIRE(contains(res->body, "<th>Version</th>"));
    REQUIRE(contains(res->body, "<th>Publisher</th>"));
    REQUIRE(contains(res->body, "<th>Install date</th>"));
    REQUIRE(contains(res->body, "<th>Signature</th>"));
    REQUIRE(contains(res->body, "<th>Ecosystem</th>"));
    REQUIRE(contains(res->body, "<th>Arch</th>"));

    // Client filter-group: data-gpf is derived from the software name (id_safe),
    // matching the catalogue row's own hx-target for this expansion — the filter
    // input and every data row carry the SAME group.
    REQUIRE(contains(res->body, "data-gpf=\"swdev-nChrome-520456eb94564cdd\""));
}

TEST_CASE("route: software devices — service-scoped token denied, no data leaked, denial audited",
          "[inventory][route][security]") {
    InvHarness h;
    h.service_scoped = true;
    h.fleet_rows = {fleet_row("agent-alpha", "Chrome", "1.0")};

    auto res = h.sink.Get("/fragments/inventory/software/devices?name=Chrome");
    REQUIRE(res);
    REQUIRE(res->status == 403);
    REQUIRE_FALSE(contains(res->body, "agent-alpha"));
    auto body = nlohmann::json::parse(res->body, nullptr, false);
    REQUIRE_FALSE(body.is_discarded());
    CHECK_FALSE(body["error"].contains("permission"));
    CHECK_FALSE(body["error"]["correlation_id"].get<std::string>().empty());
    CHECK(res->get_header_value("X-Correlation-Id") ==
         body["error"]["correlation_id"].get<std::string>());
    bool denied = false;
    for (const auto& a : h.audits) {
        if (a == "inventory.software.query|denied")
            denied = true;
        REQUIRE(a != "inventory.software.query|success");
    }
    REQUIRE(denied);
}

TEST_CASE("route: software devices — per-row management-group drop count in pill and audit",
          "[inventory][route]") {
    InvHarness h;
    h.fleet_rows = {fleet_row("agent-alpha", "Chrome", "1.0"),
                    fleet_row("agent-bravo", "Chrome", "2.0")};
    h.in_scope_agents = {"agent-alpha"}; // agent-bravo is out of the operator's scope

    auto res = h.sink.Get("/fragments/inventory/software/devices?name=Chrome");
    REQUIRE(res);
    REQUIRE(contains(res->body, "agent-alpha"));
    REQUIRE_FALSE(contains(res->body, "agent-bravo")); // dropped, not leaked
    REQUIRE(contains(res->body, "1 device(s) outside your scope")); // the rendered pill
    bool denied = false, ok = false;
    for (const auto& a : h.audits) {
        denied = denied || a == "inventory.software.query|denied";
        ok = ok || a == "inventory.software.query|success";
    }
    REQUIRE(denied);
    REQUIRE(ok);
    bool detail_ok = false;
    for (const auto& d : h.audit_details)
        if (contains(d, "scope: filtered 1 out-of-management-group device(s)"))
            detail_ok = true;
    REQUIRE(detail_ok); // the same drop count also lands in the audit row's detail
}

TEST_CASE("route: software devices — degraded fleet store renders an honest banner, "
          "not an empty table",
          "[inventory][route]") {
    InvHarness h;
    h.degrade = true;
    auto res = h.sink.Get("/fragments/inventory/software/devices?name=Chrome");
    REQUIRE(res);
    REQUIRE(contains(res->body, "unavailable"));
    REQUIRE_FALSE(contains(res->body, "No devices run")); // never the "genuinely zero" wording
    bool failed = false;
    for (const auto& a : h.audits)
        if (a == "inventory.software.query|failure")
            failed = true;
    REQUIRE(failed);
}

TEST_CASE("route: software devices — empty name is a no-op: no data read, no audit",
          "[inventory][route]") {
    // Unreachable from the UI (the catalogue row's "devices ›" link always carries
    // ?name=); this is the renderer's precondition-miss short-circuit for a direct
    // fetch — NOT a "type a title" prompt (that wording belongs to the separate Find
    // results fragment). fleet_fn_ must never be called for an empty name.
    InvHarness h;
    auto res = h.sink.Get("/fragments/inventory/software/devices");
    REQUIRE(res);
    REQUIRE(res->status == 200);
    REQUIRE(res->body.empty());
    REQUIRE_FALSE(h.last_fleet_query.has_value()); // no data read
    REQUIRE(h.audits.empty());                     // → nothing to audit
}

TEST_CASE("route: software devices — fleet_fn_'s limit is clamped into the route's bound",
          "[inventory][route]") {
    InvHarness h;
    auto over = h.sink.Get("/fragments/inventory/software/devices?name=Chrome&limit=999999");
    REQUIRE(over);
    REQUIRE(h.last_fleet_query.has_value());
    REQUIRE(h.last_fleet_query->limit == 1000); // clamped down to the route's hard ceiling

    auto within = h.sink.Get("/fragments/inventory/software/devices?name=Chrome&limit=50");
    REQUIRE(within);
    REQUIRE(h.last_fleet_query.has_value());
    REQUIRE(h.last_fleet_query->limit == 50); // a value already inside the bound passes through
}

TEST_CASE("route: /fragments/inventory/find and /find/results stay registered for deep links",
          "[inventory][route]") {
    // Round-3 item 9 retired the Find TAB (inv_subnav no longer links here), but the
    // routes themselves stay registered by explicit design (existing deep links;
    // docs/user-manual/inventory.md's retirement follow-up) — a regression that
    // accidentally deleted either route must fail this, not silently 404.
    InvHarness h;
    auto shell = h.sink.Get("/fragments/inventory/find");
    REQUIRE(shell);
    REQUIRE(shell->status == 200);

    auto results = h.sink.Get("/fragments/inventory/find/results?name=Chrome");
    REQUIRE(results);
    REQUIRE(results->status == 200);
}
