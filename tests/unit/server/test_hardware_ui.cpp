/// @file test_hardware_ui.cpp
/// Unit tests for the /hardware PURE renderers (hardware_ui.cpp): the list
/// fragment (search box, sortable columns, OS/status chips, pagination,
/// checkbox/bulk-tag bar, per-row cells) and the CI record (lens tab bar,
/// lens-body permission gating, the Overview identity block, MAC chips).
/// Data in, HTML out — no store, no network, no httplib request/response.
///
/// Coverage, per the code review's own named gaps:
///  - the search input's exact htmx attributes, incl. a literal-`[`-absence
///    regression guard for the CSP-incompatible event-filter defect
///    (round-3 item 5 — `[key=='Enter']` compiles via `Function()`, which the
///    dashboard CSP silently refuses at runtime).
///  - #hw-results' `data-url` round-tripping the current query.
///  - every sortable `<th>`/filter chip/pager control carrying
///    `hx-include="#hw-q"` and never ALSO embedding its own `q=` — httplib
///    keeps only the first of two same-named query params, so a control
///    emitting both would silently clobber whatever the user typed.
///  - the checkbox column + sticky #hw-selbar bulk-tag bar markup.
///  - the DEX badge (scored vs the -1 sentinel), the IP cell (single / +N /
///    empty), and the Tags cell's one-chip-per-tag shape.
///  - MAC address chips: one `.hw-tag` span per address (round-3 item 12),
///    never one unbroken comma-joined blob.
///  - the lens tab bar: fixed 7-tab order, the active-tab class, and the OOB
///    swap attribute gated strictly on the `oob` parameter.
///  - the DEX/Guardian/Live lenses' `can_read_guaranteed_state` gate: an
///    honest permission note when false, the real bare=1 fragment hx-get
///    when true.
///  - the Overview "General" identity block's agent id/OS/version/arch.

#include "hardware_routes.hpp"

#include <catch2/catch_test_macros.hpp>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <utility>
#include <vector>

using namespace yuzu::server;

namespace {

/// Every occurrence of `open` in `html`, each expanded to the full opening
/// tag text (from `open` through the next `>`). Used to pull out every
/// `<th class="sortable" ...>`, `<a class="gp-chip...` or pager `<button
/// class="gp-btn" ...>` so each can be checked independently.
std::vector<std::string> all_opening_tags(const std::string& html, const std::string& open) {
    std::vector<std::string> out;
    std::size_t pos = 0;
    while ((pos = html.find(open, pos)) != std::string::npos) {
        const auto close = html.find('>', pos);
        REQUIRE(close != std::string::npos);
        out.push_back(html.substr(pos, close - pos + 1));
        pos = close + 1;
    }
    return out;
}

/// The value of attribute `attr="..."` inside one opening-tag string, or ""
/// if absent.
std::string attr_value(const std::string& tag, const std::string& attr) {
    const std::string needle = attr + "=\"";
    const auto p = tag.find(needle);
    if (p == std::string::npos) return {};
    const auto start = p + needle.size();
    const auto end = tag.find('"', start);
    return tag.substr(start, end - start);
}

/// The inner HTML of the (0-based) `index`-th `<td...>...</td>` cell in a
/// rendered `<tr>`. Every cell in row_html() is a self-closed span/anchor
/// with no nested `</td>`, so "up to the first </td>" is exact.
std::string nth_td(const std::string& row, int index) {
    std::size_t pos = 0;
    for (int i = 0; i <= index; ++i) {
        pos = row.find("<td", pos);
        REQUIRE(pos != std::string::npos);
        pos = row.find('>', pos);
        REQUIRE(pos != std::string::npos);
        ++pos;
    }
    const auto end = row.find("</td>", pos);
    REQUIRE(end != std::string::npos);
    return row.substr(pos, end - pos);
}

/// The first (and, in every test here, only) `<tr class="click" ...>...</tr>`
/// data row in a rendered results region.
std::string first_row(const std::string& html) {
    const auto start = html.find("<tr class=\"click\"");
    REQUIRE(start != std::string::npos);
    const auto end = html.find("</tr>", start);
    REQUIRE(end != std::string::npos);
    return html.substr(start, end + 5 - start);
}

std::size_t count_occurrences(const std::string& hay, const std::string& needle) {
    std::size_t count = 0;
    std::size_t pos = 0;
    while ((pos = hay.find(needle, pos)) != std::string::npos) {
        ++count;
        pos += needle.size();
    }
    return count;
}

/// Renders the results-only region for a single row — the shared shape every
/// per-cell test below needs.
std::string render_row(const InventoryDeviceRow& row) {
    HardwareListPage page;
    page.rows = {row};
    page.total_matching = 1;
    return render_hardware_list_fragment(page, /*ci_degraded=*/false, /*roster_unavailable=*/false,
                                         /*results_only=*/true);
}

} // namespace

// ── Search box (round-2/round-3 CSP-safety) ───────────────────────────────────

TEST_CASE("hardware list: search input is CSP-safe — plain trigger, no event filter",
          "[hardware][ui]") {
    HardwareListPage page; // default query, no rows
    const auto html = render_hardware_list_fragment(page, false, false, /*results_only=*/false);

    const auto open = html.find("<input id=\"hw-q\"");
    REQUIRE(open != std::string::npos);
    const auto close = html.find('>', open);
    REQUIRE(close != std::string::npos);
    const std::string tag = html.substr(open, close - open + 1);

    CHECK(tag.find("hx-target=\"#hw-results\"") != std::string::npos);
    CHECK(tag.find("hx-swap=\"outerHTML\"") != std::string::npos);
    CHECK(tag.find("hx-trigger=\"keyup changed delay:400ms, search\"") != std::string::npos);
    // Round-3 item 5 regression guard: an htmx `[key=='Enter']`-style event
    // filter compiles via `Function()`, which the dashboard's no-unsafe-eval
    // CSP silently refuses at runtime (htmx drops the filter and fires on
    // every keystroke instead) — the trigger value must never contain `[`.
    CHECK(tag.find('[') == std::string::npos);
}

// ── #hw-results data-url ──────────────────────────────────────────────────────

TEST_CASE("hardware results region: #hw-results data-url round-trips the current query",
          "[hardware][ui]") {
    HardwareListPage page;
    page.query.q = "chrome";
    page.query.os = "windows";
    page.query.status = "online";
    page.query.sort = "model";
    page.query.desc = true;
    page.query.offset = 50;
    page.query.limit = 25;

    const auto html = render_hardware_list_fragment(page, false, false, /*results_only=*/true);

    // list_url()'s own field order — os, status, sort, dir, offset, limit,
    // [q], [results_only] — each attribute value HTML-escaped, so "&" -> "&amp;".
    const std::string expected =
        "data-url=\"/fragments/hardware/list?os=windows&amp;status=online&amp;sort=model"
        "&amp;dir=desc&amp;offset=50&amp;limit=25&amp;q=chrome&amp;results_only=1\"";
    CHECK(html.find(expected) != std::string::npos);
}

// ── Sortable th / filter chip / pager: hx-include, never a duplicate q= ───────

TEST_CASE("hardware results region: sortable th / filter chip / pager always hx-include "
          "the search box and never duplicate its q= param",
          "[hardware][ui]") {
    HardwareListPage page;
    page.query.q = "chrome"; // a LIVE, non-empty search — the case that actually
                             // exercises httplib's duplicate-same-name-param hazard.
    page.query.offset = 10;
    page.query.limit = 5;
    page.total_matching = 100; // offset>0 -> Prev renders; offset+limit<total -> Next renders
    InventoryDeviceRow r1;
    r1.agent_id = "a1";
    r1.hostname = "WS-1";
    InventoryDeviceRow r2;
    r2.agent_id = "a2";
    r2.hostname = "WS-2";
    page.rows = {r1, r2};

    const auto html = render_hardware_list_fragment(page, false, false, /*results_only=*/true);

    auto assert_controls = [](const std::vector<std::string>& tags, std::size_t expected_count) {
        CHECK(tags.size() == expected_count);
        for (const auto& tag : tags) {
            CHECK(attr_value(tag, "hx-get").find("q=") == std::string::npos);
            CHECK(tag.find("hx-include=\"#hw-q\"") != std::string::npos);
        }
    };

    // 12 sortable columns: Name/IP/OS/Status/Version/Last seen/Manufacturer/
    // Model/Serial/CPU/RAM/OS version (DEX and Tags are NOT sortable).
    assert_controls(all_opening_tags(html, "<th class=\"sortable\""), 12);
    // 4 OS chips + 3 status chips.
    assert_controls(all_opening_tags(html, "<a class=\"gp-chip"), 7);

    const auto pagers = all_opening_tags(html, "<button class=\"gp-btn\" hx-get=\"");
    REQUIRE(pagers.size() == 2); // both Prev and Next are showing
    assert_controls(pagers, 2);
}

// ── Checkbox column + sticky bulk-tag bar ─────────────────────────────────────

TEST_CASE("hardware results region: checkbox column + sticky #hw-selbar bulk-tag bar",
          "[hardware][ui]") {
    InventoryDeviceRow row;
    row.agent_id = "agent-abc123";
    row.hostname = "WS-9";
    const auto html = render_row(row);

    // Select-all header checkbox + per-row checkbox.
    CHECK(html.find("<input type=\"checkbox\" onclick=\"hwSelAll(this)\"") != std::string::npos);
    CHECK(html.find("class=\"hw-sel\" value=\"agent-abc123\" onclick=\"hwSelToggle(this)\"") !=
          std::string::npos);

    // Sticky bulk-tag action bar and its real input ids / onclick handlers.
    CHECK(html.find("id=\"hw-selbar\" class=\"hw-selbar\"") != std::string::npos);
    CHECK(html.find("id=\"hw-bulk-key\"") != std::string::npos);
    CHECK(html.find("id=\"hw-bulk-value\"") != std::string::npos);
    CHECK(html.find("id=\"hw-bulk-rkey\"") != std::string::npos);
    CHECK(html.find("onclick=\"hwBulkTag(this,'set')\"") != std::string::npos);
    CHECK(html.find("onclick=\"hwBulkTag(this,'delete')\"") != std::string::npos);
    CHECK(html.find("onclick=\"hwSelClear()\"") != std::string::npos);
}

// ── DEX badge ──────────────────────────────────────────────────────────────────

TEST_CASE("hardware row: DEX badge for a scored row; honest dash for the -1 sentinel",
          "[hardware][ui]") {
    InventoryDeviceRow scored;
    scored.agent_id = "a1";
    scored.hostname = "WS-1";
    scored.dex_score = 82;
    CHECK(nth_td(first_row(render_row(scored)), 5).find(">82<") != std::string::npos);

    InventoryDeviceRow unscored;
    unscored.agent_id = "a2";
    unscored.hostname = "WS-2";
    unscored.dex_score = -1; // "not scored / no GuaranteedStateStore wired"
    CHECK(nth_td(first_row(render_row(unscored)), 5) == "<span class=\"hw-grey\">&mdash;</span>");
}

// ── IP cell ────────────────────────────────────────────────────────────────────

TEST_CASE("hardware row: IP cell — single IP, +N suffix for multiple, honest empty",
          "[hardware][ui]") {
    InventoryDeviceRow single;
    single.agent_id = "a1";
    single.hostname = "WS-1";
    single.ips = {"10.0.0.5"};
    CHECK(nth_td(first_row(render_row(single)), 2) == "<span title=\"10.0.0.5\">10.0.0.5</span>");

    InventoryDeviceRow many;
    many.agent_id = "a2";
    many.hostname = "WS-2";
    many.ips = {"10.0.0.5", "10.0.0.6", "10.0.0.7"};
    CHECK(nth_td(first_row(render_row(many)), 2) ==
          "<span title=\"10.0.0.5, 10.0.0.6, 10.0.0.7\">10.0.0.5 +2</span>");

    InventoryDeviceRow none;
    none.agent_id = "a3";
    none.hostname = "WS-3";
    CHECK(nth_td(first_row(render_row(none)), 2) == "<span class=\"hw-grey\">&mdash;</span>");
}

// ── Tags cell ──────────────────────────────────────────────────────────────────

TEST_CASE("hardware row: Tags cell renders one chip per tag, each targeting #hw-results",
          "[hardware][ui]") {
    InventoryDeviceRow none;
    none.agent_id = "a0";
    none.hostname = "WS-0";
    CHECK(nth_td(first_row(render_row(none)), 8) == "<span class=\"hw-grey\">&mdash;</span>");

    InventoryDeviceRow row;
    row.agent_id = "a1";
    row.hostname = "WS-1";
    row.tags = {{"env", "prod"}, {"role", ""}};
    const auto tags_cell = nth_td(first_row(render_row(row)), 8);

    // Visible label carries the full key[=value].
    CHECK(tags_cell.find(">env=prod<") != std::string::npos);
    CHECK(tags_cell.find(">role<") != std::string::npos);

    const auto chips = all_opening_tags(tags_cell, "<a class=\"hw-tag link\"");
    REQUIRE(chips.size() == 2);
    for (const auto& chip : chips) {
        CHECK(chip.find("hx-target=\"#hw-results\"") != std::string::npos);
        CHECK(chip.find("hx-swap=\"outerHTML\"") != std::string::npos);
        CHECK(chip.find("hx-include=\"#hw-q\"") != std::string::npos);
        // Same httplib duplicate-param hazard as every other list control.
        CHECK(attr_value(chip, "hx-get").find("q=") == std::string::npos);
    }

    // FLAGGED FOR THE ORCHESTRATOR (out of this file's scope to fix):
    // tag_chip()'s own doc comment promises "narrows the list to this exact
    // key[=value]", but hardware_ui.cpp's list_url() never serialises
    // HardwareListQuery::tag into the URL it builds (only os/status/sort/dir/
    // offset/limit/[q]/[results_only] — grep list_url() in hardware_ui.cpp).
    // So BOTH chips resolve to the byte-identical hx-get target today, and
    // clicking either one narrows nothing. This asserts the CURRENT behaviour
    // rather than silently encoding a stronger claim this test file has no
    // way to make true; the one-line fix is
    // `if (!q.tag.empty()) u += "&tag=" + url_encode(q.tag);` in list_url().
    // If that ships, THIS check starts failing — that failure is the signal
    // to replace it with a real key[=value]-differs-per-chip assertion.
    CHECK(attr_value(chips[0], "hx-get") == attr_value(chips[1], "hx-get"));
}

// ── MAC address chips (round-3 item 12) ───────────────────────────────────────

TEST_CASE("hardware CI overview lens: MAC chips render one span per address",
          "[hardware][ui]") {
    DeviceCiRecord rec;
    rec.macs_summary = "aa:bb:cc:dd:ee:01, aa:bb:cc:dd:ee:02, aa:bb:cc:dd:ee:03";
    HardwareCiDetail detail;
    detail.ci = std::optional<DeviceCiRecord>(rec);
    HwCiAffordances aff;

    const auto html = render_hardware_lens_body("a1", detail, /*lens=*/"", /*now_secs=*/0, aff);
    CHECK(count_occurrences(html, "<span class=\"hw-tag\">") == 3);
    CHECK(html.find(">aa:bb:cc:dd:ee:01<") != std::string::npos);
    CHECK(html.find(">aa:bb:cc:dd:ee:02<") != std::string::npos);
    CHECK(html.find(">aa:bb:cc:dd:ee:03<") != std::string::npos);
    // Never one unbroken comma-joined blob — the round-3-item-12 defect this
    // rendering exists to fix.
    CHECK(html.find("aa:bb:cc:dd:ee:01, aa:bb:cc:dd:ee:02") == std::string::npos);

    DeviceCiRecord empty_rec; // macs_summary defaults to ""
    HardwareCiDetail empty_detail;
    empty_detail.ci = std::optional<DeviceCiRecord>(empty_rec);
    const auto empty_html = render_hardware_lens_body("a1", empty_detail, "", 0, aff);
    CHECK(empty_html.find("<span class=\"inv-grey\">&mdash;</span>") != std::string::npos);
    CHECK(empty_html.find("<span class=\"hw-tag\">") == std::string::npos);
}

// ── Lens tab bar ───────────────────────────────────────────────────────────────

TEST_CASE("hardware lens bar: id, fixed 7-tab order, active class, oob gated on the parameter",
          "[hardware][ui]") {
    const auto html = render_hardware_lens_bar("a1", "dex", /*oob=*/false);
    REQUIRE(html.find("<div class=\"hw-lens\" id=\"hw-lens-bar\">") != std::string::npos);
    CHECK(html.find("hx-swap-oob") == std::string::npos);

    // Fixed order + exact labels.
    const std::vector<std::string> labels = {"Overview", "Installed software", "Tags",
                                              "DEX",      "Guardian",           "Live",
                                              "Actions"};
    std::size_t pos = 0;
    for (const auto& label : labels) {
        const auto found = html.find(">" + label + "<", pos);
        REQUIRE(found != std::string::npos);
        pos = found + 1;
    }

    // The active tab ("dex") carries the distinguishing "on" class; note
    // device_lens_tab()'s own hx-get is built by plain concatenation, not
    // list_url()/esc(), so "&" stays literal here (unlike the list controls).
    CHECK(html.find("<a class=\" on\" hx-get=\"/fragments/hardware/ci?id=a1&lens=dex"
                    "&lens_only=1\" hx-target=\"#hw-ci-lens\" hx-swap=\"innerHTML\">DEX</a>") !=
          std::string::npos);
    // A non-active tab carries no "on" class.
    CHECK(html.find("<a class=\"\" hx-get=\"/fragments/hardware/ci?id=a1&lens=overview") !=
          std::string::npos);

    const auto oob_html = render_hardware_lens_bar("a1", "overview", /*oob=*/true);
    CHECK(oob_html.find("hx-swap-oob=\"true\"") != std::string::npos);
}

// ── DEX/Guardian/Live lens gating on can_read_guaranteed_state ────────────────

TEST_CASE("hardware lens body: DEX/Guardian/Live honor the GuaranteedState:Read probe",
          "[hardware][ui]") {
    HardwareCiDetail detail; // identity/ci irrelevant to these three lenses

    HwCiAffordances denied;
    denied.can_read_guaranteed_state = false;
    for (const std::string& lens : {std::string("dex"), std::string("guardian"), std::string("live")}) {
        const auto html = render_hardware_lens_body("a1", detail, lens, 0, denied);
        CHECK(html.find("GuaranteedState:Read") != std::string::npos);
        CHECK(html.find("hx-get=\"/fragments/device/" + lens) == std::string::npos);
    }

    HwCiAffordances allowed;
    allowed.can_read_guaranteed_state = true;
    // Plain concatenation again (no esc()) — "&" stays literal.
    CHECK(render_hardware_lens_body("a1", detail, "dex", 0, allowed)
              .find("hx-get=\"/fragments/device/dex?id=a1&bare=1\"") != std::string::npos);
    CHECK(render_hardware_lens_body("a1", detail, "guardian", 0, allowed)
              .find("hx-get=\"/fragments/device/guardian?id=a1&bare=1\"") != std::string::npos);
    CHECK(render_hardware_lens_body("a1", detail, "live", 0, allowed)
              .find("hx-get=\"/fragments/device/live?id=a1\"") != std::string::npos);
}

// ── Overview "General" identity block ─────────────────────────────────────────

TEST_CASE("hardware lens body (overview): General block renders agent identity fields",
          "[hardware][ui]") {
    InventoryDeviceRow identity;
    identity.os = "linux";
    identity.arch = "x86_64";
    identity.agent_version = "0.14.2";
    HardwareCiDetail detail;
    detail.identity = identity;
    HwCiAffordances aff;

    const auto html = render_hardware_lens_body("agent-42", detail, /*lens=*/"", 0, aff);
    CHECK(html.find("<h4>General</h4>") != std::string::npos);
    CHECK(html.find("Agent id: </span>agent-42") != std::string::npos);
    CHECK(html.find("OS: </span>Linux") != std::string::npos); // os_label("linux")
    CHECK(html.find("Agent version: </span>0.14.2") != std::string::npos);
    CHECK(html.find("Architecture: </span>x86_64") != std::string::npos);
}
