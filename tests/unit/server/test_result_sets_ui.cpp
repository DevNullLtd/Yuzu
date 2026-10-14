/**
 * test_result_sets_ui.cpp — Render-function tests for the result-sets dashboard
 * surface. Pure rendering (no store I/O): asserts the scope token, lineage
 * breadcrumb, pin/unpin action selection, and — critically — that operator-
 * supplied names and device IDs are HTML-escaped (XSS).
 */

#include "result_set_extras_render.hpp"
#include "result_sets_ui.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <vector>

using namespace yuzu::server;

namespace {

ResultSet make(const std::string& id, const std::string& name, int64_t devices, bool pinned,
               ResultSetStatus status = ResultSetStatus::Materialized) {
    ResultSet r;
    r.id = id;
    r.name = name;
    r.owner_principal = "alice";
    r.device_count = devices;
    r.pinned = pinned;
    r.status = status;
    r.source_kind = std::string(source_kind::kInventoryQuery);
    return r;
}

} // namespace

TEST_CASE("result_sets_ui: sidebar lists sets with hx-get targets", "[result_set][ui]") {
    std::vector<ResultSet> sets = {make("rs_aaa", "win-fleet", 12, false),
                                   make("rs_bbb", "suspects", 3, true)};
    auto html = render_result_sets_sidebar(sets, "rs_bbb");

    CHECK(html.find("win-fleet") != std::string::npos);
    CHECK(html.find("suspects") != std::string::npos);
    CHECK(html.find("/fragments/result-sets/rs_aaa/detail") != std::string::npos);
    CHECK(html.find("12 devices") != std::string::npos);
    CHECK(html.find("3 devices") != std::string::npos);
    // Operate extras table: Source, Status, Captured, Expires columns.
    CHECK(html.find("<th>Source</th>") != std::string::npos);
    CHECK(html.find("Inventory query") != std::string::npos);
    CHECK(html.find("<th>Captured</th>") != std::string::npos);
    CHECK(html.find("Pinned</td>") != std::string::npos);
    // Selected set carries the active class; pinned set shows the star.
    CHECK(html.find("active") != std::string::npos);
    CHECK(html.find("★") != std::string::npos);
}

TEST_CASE("result_sets_ui: empty sidebar shows empty state", "[result_set][ui]") {
    auto html = render_result_sets_sidebar({}, "");
    CHECK(html.find("No result sets yet") != std::string::npos);
}

TEST_CASE("result_sets_ui: sidebar escapes a malicious name (XSS)", "[result_set][ui][security]") {
    std::vector<ResultSet> sets = {make("rs_xss", "<script>alert(1)</script>", 1, false)};
    auto html = render_result_sets_sidebar(sets, "");
    // The raw script tag must not appear; the escaped form must.
    CHECK(html.find("<script>alert(1)</script>") == std::string::npos);
    CHECK(html.find("&lt;script&gt;") != std::string::npos);
}

TEST_CASE("result_sets_ui: detail shows scope token + actions", "[result_set][ui]") {
    auto rs = make("rs_leaf", "compromised", 29, false);
    std::vector<LineageNode> chain = {{"rs_root", "all-windows", "inventory_query", 4011},
                                      {"rs_mid", "chrome", "inventory_query", 412},
                                      {"rs_leaf", "compromised", "instruction_result", 29}};
    auto html = render_result_set_detail(rs, chain);

    // Copyable scope token is present.
    CHECK(html.find("from_result_set:rs_leaf") != std::string::npos);
    // Breadcrumb renders all three nodes with the leaf marked current.
    CHECK(html.find("all-windows") != std::string::npos);
    CHECK(html.find("chrome") != std::string::npos);
    CHECK(html.find("current") != std::string::npos);
    // Unpinned set offers Pin (not Unpin) + Delete.
    CHECK(html.find("/fragments/result-sets/rs_leaf/pin") != std::string::npos);
    CHECK(html.find("/fragments/result-sets/rs_leaf/delete") != std::string::npos);
}

TEST_CASE("result_sets_ui: pinned set offers Unpin", "[result_set][ui]") {
    auto rs = make("rs_pin", "kept", 5, true);
    auto html = render_result_set_detail(rs, {});
    CHECK(html.find("/fragments/result-sets/rs_pin/unpin") != std::string::npos);
    CHECK(html.find("★ pinned") != std::string::npos);
}

TEST_CASE("result_sets_ui: detail empty state", "[result_set][ui]") {
    auto html = render_result_set_detail_empty();
    CHECK(html.find("Select a result set") != std::string::npos);
}

TEST_CASE("result_sets_ui: a degraded list never reads as empty; a full page says it is cut",
          "[result_set][ui]") {
    SidebarNotes degraded;
    degraded.degraded = true;
    auto d = render_result_sets_sidebar({}, "", degraded);
    CHECK(d.find("data-degraded=\"1\"") != std::string::npos);
    CHECK(d.find("This is not an empty list.") != std::string::npos);
    CHECK(d.find("No result sets yet") == std::string::npos);

    SidebarNotes cut;
    cut.truncated = true;
    cut.limit = 200;
    auto t = render_result_sets_sidebar({make("rs_a", "x", 1, false)}, "", cut);
    CHECK(t.find("data-truncated=\"1\"") != std::string::npos);
    CHECK(t.find("Showing the 200 most recent.") != std::string::npos);
}

TEST_CASE("result_sets_ui: pending polls itself, failed names the execution, copy has no "
          "inline handler", "[result_set][ui][security]") {
    auto pending = make("rs_p", "waiting", 0, false, ResultSetStatus::Pending);
    auto p = render_result_set_detail(pending, {});
    CHECK(p.find("hx-trigger=\"every 5s\"") != std::string::npos);
    CHECK(p.find("/fragments/result-sets/rs_p/detail") != std::string::npos);
    // A materialized set does not poll.
    CHECK(render_result_set_detail(make("rs_m", "ok", 1, false), {}).find("every 5s") ==
          std::string::npos);

    auto failed = make("rs_f", "bad", 0, false, ResultSetStatus::Failed);
    failed.source_execution_id = "exec-<b>1";
    auto f = render_result_set_detail(failed, {});
    CHECK(f.find("Failed to materialize.") != std::string::npos);
    CHECK(f.find("exec-&lt;b&gt;1") != std::string::npos);
    CHECK(f.find("exec-<b>1") == std::string::npos);

    auto full = render_result_set_detail(make("rs_c", "c", 1, false), {});
    CHECK(full.find("onclick") == std::string::npos);
    CHECK(full.find("data-ox-copy=\"from_result_set:rs_c\"") != std::string::npos);
}

TEST_CASE("result_sets_ui: Re-evaluate needs a supported kind, a verdict, and a settled set",
          "[result_set][ui]") {
    auto tar = make("rs_t", "tarset", 2, false);
    tar.source_kind = std::string(source_kind::kTarQuery);
    CHECK(render_result_set_detail(tar, {}).find("data-ox-reeval=\"rs_t\"") != std::string::npos);
    // The route's verdict (instruction no longer read-only / auto) hides it.
    CHECK(render_result_set_detail(tar, {}, {.reeval_allowed = false}).find("data-ox-reeval") ==
          std::string::npos);
    // The REST route answers 400 for these kinds, so the button is never drawn.
    auto inv = make("rs_i", "inv", 2, false); // inventory_query
    CHECK(render_result_set_detail(inv, {}).find("data-ox-reeval") == std::string::npos);
    auto manual = make("rs_m", "paste", 2, false);
    manual.source_kind = std::string(source_kind::kManualCurate);
    CHECK(render_result_set_detail(manual, {}).find("data-ox-reeval") == std::string::npos);
    // Pending: nothing to re-run yet.
    auto pend = make("rs_pp", "p", 0, false, ResultSetStatus::Pending);
    pend.source_kind = std::string(source_kind::kTarQuery);
    CHECK(render_result_set_detail(pend, {}).find("data-ox-reeval") == std::string::npos);
}

TEST_CASE("result_set_extras_render: members escape ids, page with a cursor, and a failed read "
          "is not an empty set", "[result_set][ui][security]") {
    auto m = render_result_set_members("rs_a", {"dev-1", "<img src=x onerror=1>"}, "cur&1", false);
    CHECK(m.find("<code>dev-1</code>") != std::string::npos);
    CHECK(m.find("&lt;img") != std::string::npos);
    CHECK(m.find("<img") == std::string::npos);
    CHECK(m.find("/fragments/result-sets/rs_a/members?cursor=cur&amp;1") != std::string::npos);

    CHECK(render_result_set_members("rs_a", {"dev-1"}, "", false).find("Show more") ==
          std::string::npos);
    auto empty = render_result_set_members("rs_a", {}, "", false);
    CHECK(empty.find("This set has no devices.") != std::string::npos);
    auto bad = render_result_set_members("rs_a", {}, "", true);
    CHECK(bad.find("data-degraded=\"1\"") != std::string::npos);
    CHECK(bad.find("no devices") == std::string::npos);
}

TEST_CASE("result_set_extras_render: producers escape names and always state that approval "
          "rules are not applied", "[result_set][ui][security]") {
    auto h = render_result_set_producers({{"def-1", "<b>Name</b>", "os_info", "os_version"}}, false);
    CHECK(h.find("&lt;b&gt;Name&lt;/b&gt;") != std::string::npos);
    CHECK(h.find("<b>Name") == std::string::npos);
    CHECK(h.find("value=\"def-1\"") != std::string::npos);
    CHECK(h.find("Approval rules are not applied") != std::string::npos);
    CHECK(h.find("data-truncated") == std::string::npos);

    auto empty = render_result_set_producers({}, false);
    CHECK(empty.find("data-empty=\"1\"") != std::string::npos);
    CHECK(empty.find("<option") == std::string::npos);

    CHECK(render_result_set_producers({{"d", "n", "p", "a"}}, true).find("data-truncated=\"1\"") !=
          std::string::npos);
    CHECK(render_result_set_producers_denied().find("data-denied=\"true\"") != std::string::npos);
    CHECK(render_result_set_producers_degraded().find("This is not an empty list.") !=
          std::string::npos);
}
