/**
 * test_approvals_page_render.cpp — the Approvals page's list renderer
 * (approvals_page_render.hpp). Pure string-in, string-out: no store, no clock (the
 * viewer's "now" is injected), so these run in the non-PG suite.
 *
 * What is pinned is the contract the page controller (yuzu-operate.js) reads, not the
 * whole markup: every `data-*` attribute, the container attributes, the exact notes and
 * the pill class per status. O2 re-edits this markup (buttons, slots); a full-markup
 * snapshot would only churn.
 */

#include "approvals_page_render.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstddef>
#include <expected>
#include <optional>
#include <string>
#include <vector>

using namespace yuzu::server::operate_pages;

namespace {

constexpr int64_t kNow = 2'000'000'000;

std::size_t count_of(const std::string& haystack, const std::string& needle) {
    std::size_t n = 0;
    for (auto at = haystack.find(needle); at != std::string::npos;
         at = haystack.find(needle, at + needle.size()))
        ++n;
    return n;
}

ApprovalRowView make_row(const std::string& id, const std::string& status) {
    ApprovalRowView r;
    r.id = id;
    r.definition_id = "def-" + id;
    r.name = "Name " + id;
    r.status = status;
    r.submitted_by = "alice";
    r.submitted_at = kNow - 360;
    return r;
}

ApprovalListView make_view(std::vector<ApprovalRowView> rows, const std::string& filter = "") {
    ApprovalListView v;
    v.rows = std::move(rows);
    v.status_filter = filter;
    v.now = kNow;
    return v;
}

} // namespace

TEST_CASE("approvals_page_render: a row carries every attribute the controller reads",
          "[ui][approvals][render]") {
    ApprovalRowView r;
    r.id = "7f3c2e90b14d4a68";
    r.definition_id = "crossplatform.service.set_start_mode";
    r.name = "Set Service Start Mode";
    r.status = "rejected";
    r.submitted_by = "a.operator";
    r.scope_expression = "group:3f9a1c0b7d2e";
    r.reviewed_by = "t.nakamura";
    r.review_comment = "Re-submit against the pilot group.";
    r.submitted_at = kNow - 3 * 3600 - 2 * 60;
    r.reviewed_at = kNow - 90;
    r.mine = true;
    r.mcp = false;

    const auto html = render_approvals_page(make_view({r}));

    CHECK(html.find("<tr class=\"row\" tabindex=\"0\" aria-selected=\"false\"") !=
          std::string::npos);
    CHECK(html.find(" data-id=\"7f3c2e90b14d4a68\"") != std::string::npos);
    CHECK(html.find(" data-def=\"crossplatform.service.set_start_mode\"") != std::string::npos);
    CHECK(html.find(" data-name=\"Set Service Start Mode\"") != std::string::npos);
    CHECK(html.find(" data-by=\"a.operator\"") != std::string::npos);
    CHECK(html.find(" data-scope=\"group:3f9a1c0b7d2e\"") != std::string::npos);
    CHECK(html.find(" data-at=\"" + std::to_string(r.submitted_at) + "\"") != std::string::npos);
    CHECK(html.find(" data-age=\"3h 2m ago\"") != std::string::npos);
    CHECK(html.find(" data-status=\"rejected\"") != std::string::npos);
    CHECK(html.find(" data-rev-by=\"t.nakamura\"") != std::string::npos);
    CHECK(html.find(" data-rev-at=\"" + std::to_string(r.reviewed_at) + "\"") !=
          std::string::npos);
    CHECK(html.find(" data-rev-age=\"1m ago\"") != std::string::npos);
    CHECK(html.find(" data-comment=\"Re-submit against the pilot group.\"") != std::string::npos);
    CHECK(html.find(" data-mine=\"1\"") != std::string::npos);
    CHECK(html.find(" data-mcp=\"0\"") != std::string::npos);
    // The ISO timestamp for hover is server-rendered UTC.
    CHECK(html.find("<td class=\"tm\" title=\"2033-05-18T") != std::string::npos);
}

TEST_CASE("approvals_page_render: each status gets its pill class", "[ui][approvals][render]") {
    const auto html = render_approvals_page(
        make_view({make_row("p", "pending"), make_row("a", "approved"),
                   make_row("r", "rejected"), make_row("e", "expired"),
                   make_row("x", "mystery")}));

    CHECK(html.find("<span class=\"pill warn\">pending</span>") != std::string::npos);
    CHECK(html.find("<span class=\"pill ok\">approved</span>") != std::string::npos);
    CHECK(html.find("<span class=\"pill bad\">rejected</span>") != std::string::npos);
    CHECK(html.find("<span class=\"pill idle\">expired</span>") != std::string::npos);
    // An unknown status is shown as-is, never as a healthy-looking pill.
    CHECK(html.find("<span class=\"pill idle\">mystery</span>") != std::string::npos);
}

TEST_CASE("approvals_page_render: relative ages use the injected clock",
          "[ui][approvals][render]") {
    auto row = [](const std::string& id, int64_t age) {
        auto r = make_row(id, "pending");
        r.submitted_at = kNow - age;
        return r;
    };
    const auto html = render_approvals_page(
        make_view({row("s", 45), row("m", 6 * 60), row("h", 3 * 3600 + 2 * 60),
                   row("d", 8 * 86400 + 3600)}));

    CHECK(html.find("data-age=\"45s ago\"") != std::string::npos);
    CHECK(html.find("data-age=\"6m ago\"") != std::string::npos);
    CHECK(html.find("data-age=\"3h 2m ago\"") != std::string::npos);
    CHECK(html.find("data-age=\"8d 1h ago\"") != std::string::npos);
}

TEST_CASE("approvals_page_render: the container reports state count and pending",
          "[ui][approvals][render]") {
    SECTION("populated") {
        const auto html = render_approvals_page(make_view(
            {make_row("1", "pending"), make_row("2", "approved"), make_row("3", "pending")}));
        CHECK(html.find("<div class=\"ops-list\" data-state=\"ok\" data-count=\"3\" "
                        "data-pending=\"2\" data-truncated=\"0\" data-can-decide=\"0\">") == 0);
        CHECK(html.find("data-can-decide=\"1\"") == std::string::npos);
        CHECK(count_of(html, "<tr class=\"row\"") == 3);
    }
    SECTION("truncated pending list is a lower bound") {
        auto v = make_view({make_row("1", "pending"), make_row("2", "pending")}, "pending");
        v.truncated = true;
        const auto html = render_approvals_page(v);
        CHECK(html.find("data-pending=\"2+\"") != std::string::npos);
        CHECK(html.find("data-truncated=\"1\"") != std::string::npos);
        CHECK(html.find("<div class=\"ops-foot hint\">Showing the 2 most recent. Older requests are "
                        "not listed.</div>") != std::string::npos);
    }
    SECTION("truncated all-status list is a lower bound too") {
        auto v = make_view({make_row("1", "pending"), make_row("2", "approved")}, "");
        v.truncated = true;
        CHECK(render_approvals_page(v).find("data-pending=\"1+\"") != std::string::npos);
    }
    SECTION("a decided-status filter never claims a pending bound") {
        auto v = make_view({make_row("1", "approved")}, "approved");
        v.truncated = true;
        const auto html = render_approvals_page(v);
        CHECK(html.find("data-pending=\"0\"") != std::string::npos);
        CHECK(html.find("data-pending=\"0+\"") == std::string::npos);
    }
}

TEST_CASE("approvals_page_render: the empty state is filter-aware and carries no table",
          "[ui][approvals][render]") {
    struct Case {
        const char* filter;
        const char* note;
    };
    for (const auto& c : {Case{"", "No approval requests."},
                          Case{"pending", "Nothing is waiting for a decision."},
                          Case{"approved", "No approved requests."},
                          Case{"rejected", "No rejected requests."},
                          Case{"expired", "No expired requests."}}) {
        INFO(c.filter);
        const auto html = render_approvals_page(make_view({}, c.filter));
        CHECK(html.find("data-state=\"empty\" data-count=\"0\"") != std::string::npos);
        CHECK(html.find(std::string("<div class=\"empty-state\">") + c.note + "</div>") !=
              std::string::npos);
        CHECK(html.find("<table") == std::string::npos);
    }
}

TEST_CASE("approvals_page_render: the MCP and You tags appear only where they are true",
          "[ui][approvals][render]") {
    auto plain = make_row("p", "pending");
    auto mcp = make_row("m", "pending");
    mcp.mcp = true;
    mcp.definition_id = "mcp.quarantine_device";
    mcp.name = "quarantine_device";
    auto mine = make_row("y", "pending");
    mine.mine = true;

    const auto only_plain = render_approvals_page(make_view({plain}));
    CHECK(only_plain.find("class=\"tag\"") == std::string::npos);

    const auto with_mcp = render_approvals_page(make_view({mcp}));
    CHECK(with_mcp.find("<span class=\"tag\">MCP</span>") != std::string::npos);
    CHECK(with_mcp.find("<span class=\"tag\">You</span>") == std::string::npos);
    CHECK(with_mcp.find("data-mcp=\"1\"") != std::string::npos);

    const auto with_mine = render_approvals_page(make_view({mine}));
    CHECK(with_mine.find("<span class=\"tag\">You</span>") != std::string::npos);
    CHECK(with_mine.find("<span class=\"tag\">MCP</span>") == std::string::npos);
    CHECK(with_mine.find("data-mine=\"1\"") != std::string::npos);
}

TEST_CASE("approvals_page_render: scope and comment appear in full once and the cell is "
          "clipped",
          "[ui][approvals][render]") {
    auto r = make_row("big", "rejected");
    r.scope_expression = std::string(10000, 'S');
    r.review_comment = std::string(5000, 'C');
    r.reviewed_by = "reviewer";
    r.reviewed_at = kNow - 60;

    const auto html = render_approvals_page(make_view({r}));
    CHECK(count_of(html, r.scope_expression) == 1);
    CHECK(count_of(html, r.review_comment) == 1);
    CHECK(html.find("<code class=\"clip scope\">" + std::string(120, 'S') + "\xE2\x80\xA6</code>") !=
          std::string::npos);
    // No title attribute duplicates the long values.
    CHECK(html.find("title=\"" + std::string(10, 'S')) == std::string::npos);
}

TEST_CASE("approvals_page_render: an empty scope is a dash and an empty data-scope",
          "[ui][approvals][render]") {
    const auto html = render_approvals_page(make_view({make_row("n", "pending")}));
    CHECK(html.find(" data-scope=\"\"") != std::string::npos);
    CHECK(html.find("<td><span class=\"faint\">&mdash;</span></td>") != std::string::npos);
    CHECK(html.find("<code class=\"clip scope\">") == std::string::npos);
}

TEST_CASE("approvals_page_render: every field is escaped on every sink",
          "[ui][approvals][render]") {
    const std::string evil = "\"><img src=x onerror=1>";
    ApprovalRowView r;
    r.id = evil;
    r.definition_id = evil;
    r.name = evil;
    r.status = evil;
    r.submitted_by = evil;
    r.scope_expression = evil;
    r.reviewed_by = evil;
    r.review_comment = evil;
    r.submitted_at = kNow - 10;
    r.reviewed_at = kNow - 5;
    auto v = make_view({r}, "");

    const auto html = render_approvals_page(v);
    CHECK(html.find("<img") == std::string::npos);
    CHECK(count_of(html, "&quot;&gt;&lt;img src=x onerror=1&gt;") >= 8);

    // The filter name reaches the empty note too.
    v.rows.clear();
    v.status_filter = evil;
    const auto empty = render_approvals_page(v);
    CHECK(empty.find("<img") == std::string::npos);
}

TEST_CASE("approvals_page_render: an mcp ticket is named after its tool without a lookup",
          "[ui][approvals][render]") {
    int calls = 0;
    NameLookupMemo memo(
        [&calls](const std::string&) -> std::expected<std::optional<std::string>, std::string> {
            ++calls;
            return std::optional<std::string>{"Resolved Name"};
        });

    CHECK(approval_display_name("mcp.quarantine_device", memo) == "quarantine_device");
    CHECK(calls == 0);
    CHECK(approval_display_name("def-42", memo) == "Resolved Name");
    CHECK(calls == 1);

    NameLookupMemo bare;
    CHECK(approval_display_name("def-42", bare) == "def-42");
}
