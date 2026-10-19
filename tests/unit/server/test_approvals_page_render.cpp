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

// -- Bound tickets (#6062): the reviewer reads the frozen request ------------------------

namespace {

constexpr const char* kDigest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

ApprovalRowView bound_row(const std::string& request_json) {
    auto r = make_row("b1", "pending");
    r.definition_id = "guardian.deploy.r1";
    r.request_json = request_json;
    r.request_digest = kDigest;
    return r;
}

} // namespace

TEST_CASE("summarize_bound_request: definition name+hash, targets and parameters, one fact per line",
          "[ui][approvals][render][bound]") {
    const auto text = summarize_bound_request(
        R"({"definition":{"name":"Block RDP","hash":"abc123"},"params":{"port":3389,"mode":"strict"},)"
        R"("targets":["host-1","host-2"]})",
        kDigest);
    CHECK(text.find("Definition: Block RDP (hash abc123)\n") != std::string::npos);
    CHECK(text.find("Targets (2): host-1, host-2\n") != std::string::npos);
    CHECK(text.find("Parameters:\n  mode: strict\n  port: 3389\n") != std::string::npos);
    CHECK(text.find(std::string("Digest: sha256:") + kDigest + "\n") != std::string::npos);
    // The raw document is never echoed.
    CHECK(text.find("{\"") == std::string::npos);
}

TEST_CASE("summarize_bound_request: every other top-level field is listed, nothing is hidden",
          "[ui][approvals][render][bound]") {
    const auto text = summarize_bound_request(
        R"({"definition":{"name":"n","hash":"h"},"targets":"group:servers","params":{},)"
        R"("rollout":{"waves":3},"dry_run":false})",
        "");
    CHECK(text.find("Targets: group:servers\n") != std::string::npos);
    CHECK(text.find("Parameters: none\n") != std::string::npos);
    CHECK(text.find("Other fields:\n  dry_run: false\n  rollout: {\"waves\":3}\n") !=
          std::string::npos);
    CHECK(text.find("Digest:") == std::string::npos); // none supplied
}

TEST_CASE("summarize_bound_request: a missing part reads as not stated, never as empty-and-fine",
          "[ui][approvals][render][bound]") {
    const auto text = summarize_bound_request(R"({"other":1})", kDigest);
    CHECK(text.find("Definition: (not stated in the request)\n") != std::string::npos);
    CHECK(text.find("Targets: (not stated in the request)\n") != std::string::npos);
    CHECK(text.find("Parameters: none stated\n") != std::string::npos);
}

TEST_CASE("summarize_bound_request: a value cannot forge a line of the summary",
          "[ui][approvals][render][bound]") {
    // A parameter value with a newline and a fake header, and a key doing the same.
    const auto text = summarize_bound_request(
        R"({"definition":{"name":"Safe","hash":"h"},"targets":["t"],)"
        R"j("params":{"note":"x\nDefinition: Evil (hash 000)","k\nTargets (0): ":"v"}})j",
        "");
    // Exactly one line starts with each header; the injected text stays on its own line,
    // escaped.
    std::size_t def_lines = 0, tgt_lines = 0;
    std::size_t pos = 0;
    while (pos < text.size()) {
        const auto eol = text.find('\n', pos);
        const auto line = text.substr(pos, eol - pos);
        if (line.rfind("Definition:", 0) == 0) ++def_lines;
        if (line.rfind("Targets", 0) == 0) ++tgt_lines;
        pos = eol == std::string::npos ? text.size() : eol + 1;
    }
    CHECK(def_lines == 1);
    CHECK(tgt_lines == 1);
    CHECK(text.find("x\\nDefinition: Evil") != std::string::npos);
}

TEST_CASE("summarize_bound_request: bounded per value, per section and in total",
          "[ui][approvals][render][bound]") {
    const std::string big(5000, 'a');
    const auto one = summarize_bound_request(
        std::string(R"({"definition":{"name":")") + big + R"(","hash":"h"},"targets":[],"params":{}})",
        "");
    CHECK(one.size() < 1000);
    CHECK(one.find("\xE2\x80\xA6") != std::string::npos); // truncated with an ellipsis

    std::string many = R"({"definition":{"name":"n","hash":"h"},"targets":["t"],"params":{)";
    for (int i = 0; i < 100; ++i)
        many += std::string(i ? "," : "") + "\"p" + std::to_string(1000 + i) + "\":1";
    many += "}}";
    const auto capped = summarize_bound_request(many, "");
    CHECK(capped.find("... and 60 more") != std::string::npos);
    CHECK(capped.size() <= 6100);
}

TEST_CASE("summarize_bound_request: unreadable input is a fixed notice, never a partial render",
          "[ui][approvals][render][bound]") {
    for (const char* bad : {"", "not json", "[1,2]", "\"str\"", "null", "{\"unterminated\":"}) {
        const auto text = summarize_bound_request(bad, kDigest);
        CHECK(text == "The stored request could not be read. Do not approve this request.");
    }
}

TEST_CASE("approvals_page_render: a bound row carries data-request/data-digest and a Bound tag; "
          "an unbound row carries neither",
          "[ui][approvals][render][bound]") {
    auto bound = bound_row(R"({"definition":{"name":"Block RDP","hash":"abc"},"targets":["h1"]})");
    auto plain = make_row("p1", "pending");
    const auto html = render_approvals_page(make_view({bound, plain}));
    REQUIRE(count_of(html, "<tr class=\"row\"") == 2);
    CHECK(count_of(html, " data-request=\"") == 1);
    CHECK(count_of(html, std::string(" data-digest=\"") + kDigest + "\"") == 1);
    CHECK(count_of(html, "<span class=\"tag\">Bound</span>") == 1);
    CHECK(html.find("Definition: Block RDP (hash abc)") != std::string::npos);
    // Neither the raw document nor its key syntax reaches the markup.
    CHECK(html.find("{&quot;definition") == std::string::npos);
    CHECK(html.find("{\"definition") == std::string::npos);
}

TEST_CASE("approvals_page_render: markup in the frozen request is escaped, in the attribute and "
          "everywhere else",
          "[ui][approvals][render][bound]") {
    auto r = bound_row(
        R"({"definition":{"name":"<script>alert(1)</script>","hash":"\" onmouseover=\"x"},)"
        R"("targets":["<img src=x onerror=y>"],"params":{"<b>k</b>":"v' onfocus='z"}})");
    const auto html = render_approvals_page(make_view({r}));
    CHECK(html.find("<script") == std::string::npos);
    CHECK(html.find("<img") == std::string::npos);
    CHECK(html.find("<b>k") == std::string::npos);
    CHECK(html.find("&lt;script&gt;") != std::string::npos);
    // A quote in a value cannot terminate the data-request attribute: the only
    // `onmouseover=` present is inside the escaped attribute value.
    CHECK(html.find("\" onmouseover=\"") == std::string::npos);
    CHECK(html.find("&quot;") != std::string::npos);
}

TEST_CASE("approvals_page_render: data-excluded marks a row the viewer may not approve",
          "[ui][approvals][render][bound]") {
    auto r = bound_row(R"({"definition":{"name":"n","hash":"h"}})");
    r.excluded = true;
    auto plain = make_row("p1", "pending");
    const auto html = render_approvals_page(make_view({r, plain}));
    CHECK(count_of(html, " data-excluded=\"1\"") == 1);
    CHECK(count_of(html, " data-excluded=\"0\"") == 1);
}
