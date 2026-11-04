/**
 * @file test_plugin_page_model.cpp
 * @brief Pure goldens for the System > Plugins and updates read panels
 *        (plugin_page_model.{hpp,cpp}): ready, empty, degraded, denied, truncated, XSS and
 *        long text for config, kill switch and product packs. No store, no Postgres.
 */

#include "plugin_page_model.hpp"

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>

#include <string>

using namespace yuzu::server::plugin_page;
using Catch::Matchers::ContainsSubstring;

namespace {

bool has(const std::string& h, const std::string& n) { return h.find(n) != std::string::npos; }

const char* kXss = "<img src=x onerror=1>";

SwitchLayer layer(const std::string& os, SwitchState st, const std::string& source = {}) {
    SwitchLayer l;
    l.os = os;
    l.state = st;
    l.source = source;
    if (!source.empty()) {
        l.reason = "maintenance";
        l.set_by = "alice";
        l.updated_at_ms = 1'800'000'000'000;
    }
    return l;
}

} // namespace

// ── Plugin configuration ──────────────────────────────────────────────────

TEST_CASE("config panel: empty is a sentence, never a bare table", "[plugin_page][plugins][ui]") {
    ConfigPanel p;
    const auto h = render_config_panel(p);
    CHECK_THAT(h, ContainsSubstring("No plugin settings stored."));
    // The honest note: nothing reads these values on an agent yet.
    CHECK_THAT(h, ContainsSubstring("Delivery to agents is not built yet"));
    CHECK_THAT(h, ContainsSubstring("cannot be listed or read back"));
}

TEST_CASE("config panel: rows show plugin, key, value, actor and time", "[plugin_page][plugins][ui]") {
    ConfigPanel p;
    p.rows.push_back({"email", "smtp.host", "mail.example.com", 1'800'000'000'000, "alice"});
    const auto h = render_config_panel(p);
    CHECK_THAT(h, ContainsSubstring("<code>email</code>"));
    CHECK_THAT(h, ContainsSubstring("<code>smtp.host</code>"));
    CHECK_THAT(h, ContainsSubstring("mail.example.com"));
    CHECK_THAT(h, ContainsSubstring("2027-01-15T08:00:00Z"));
    CHECK_FALSE(has(h, "No plugin settings stored."));
}

TEST_CASE("config panel: truncation names the row cap", "[plugin_page][plugins][ui]") {
    ConfigPanel p;
    p.truncated = true;
    p.row_cap = 5000;
    p.rows.push_back({"a", "b", "c", 0, "x"});
    CHECK_THAT(render_config_panel(p), ContainsSubstring("First 5000 shown."));
    p.truncated = false;
    CHECK_FALSE(has(render_config_panel(p), "First 5000 shown."));
}

TEST_CASE("config panel: degraded is not empty and denied names the grant", "[plugin_page][plugins][ui]") {
    ConfigPanel p;
    p.state = PanelState::Degraded;
    auto h = render_config_panel(p);
    CHECK_THAT(h, ContainsSubstring("could not be read"));
    CHECK_THAT(h, ContainsSubstring("not an empty list"));
    CHECK_FALSE(has(h, "No plugin settings stored."));
    p.state = PanelState::Denied;
    h = render_config_panel(p);
    CHECK_THAT(h, ContainsSubstring("PluginConfig:Read"));
    CHECK_THAT(h, ContainsSubstring("data-denied=\"1\""));
    CHECK_FALSE(has(h, "<table"));
}

TEST_CASE("config panel: every field is escaped and a long value is clipped but kept in the title",
          "[plugin_page][plugins][ui][security]") {
    ConfigPanel p;
    ConfigRow r{kXss, kXss, std::string(1000, 'v') + kXss, 1, kXss};
    p.rows.push_back(r);
    const auto h = render_config_panel(p);
    CHECK_FALSE(has(h, "<img"));
    CHECK_THAT(h, ContainsSubstring("&lt;img src=x onerror=1&gt;"));
    // 1000 'v' + payload: the cell shows the first 160 bytes plus an ellipsis; the tooltip
    // carries the first 512 bytes (escaped), so a page of 8 KiB values stays bounded.
    CHECK_THAT(h, ContainsSubstring(std::string(160, 'v') + "\xE2\x80\xA6"));
    CHECK_THAT(h, ContainsSubstring("title=\"" + std::string(512, 'v') + "\xE2\x80\xA6\""));
    CHECK_FALSE(has(h, std::string(513, 'v')));
}

TEST_CASE("clip_for_display never cuts a UTF-8 sequence", "[plugin_page][plugins][ui]") {
    const std::string s = std::string(159, 'a') + "\xC3\xA9\xC3\xA9"; // two 2-byte chars
    // A cut at 160 would land inside the first 2-byte char (bytes 159-160 end at 161): the
    // cut walks back to the previous boundary instead of emitting half a character.
    CHECK(clip_for_display(s, 160) == std::string(159, 'a') + "\xE2\x80\xA6");
    // On a boundary the character is kept whole.
    CHECK(clip_for_display(s, 161) == std::string(159, 'a') + "\xC3\xA9" + "\xE2\x80\xA6");
    CHECK(clip_for_display("short", 160) == "short");
}

// ── Kill switch ───────────────────────────────────────────────────────────

TEST_CASE("kill switch panel: no plugin entered is the lookup form and a hint", "[plugin_page][plugins][ui]") {
    KillSwitchPanel p;
    p.known_plugins = {"processes", "quarantine"};
    const auto h = render_kill_switch_panel(p);
    CHECK_THAT(h, ContainsSubstring("hx-get=\"/fragments/settings/kill-switch\""));
    CHECK_THAT(h, ContainsSubstring("<option value=\"processes\">"));
    CHECK_THAT(h, ContainsSubstring("A plugin with no switch set runs."));
    CHECK_FALSE(has(h, "<table"));
    // Mechanical wording: the server refuses to SEND; it does not stop the agent.
    CHECK_THAT(h, ContainsSubstring("refused by the server"));
    CHECK_THAT(h, ContainsSubstring("are not recalled"));
    CHECK_FALSE(has(h, "on every agent immediately"));
}

TEST_CASE("kill switch panel: four layers, deciding row named, per-OS state visible",
          "[plugin_page][plugins][ui]") {
    KillSwitchPanel p;
    p.plugin = "processes";
    p.layers = {layer("", SwitchState::Enabled),
                layer("windows", SwitchState::Disabled, "processes@windows"),
                layer("linux", SwitchState::Enabled), layer("darwin", SwitchState::Enabled)};
    const auto h = render_kill_switch_panel(p);
    CHECK_THAT(h, ContainsSubstring("All operating systems"));
    CHECK_THAT(h, ContainsSubstring("<td>Windows</td>"));
    CHECK_THAT(h, ContainsSubstring("<td>macOS</td>"));
    // The all-OS lookup alone would have said Enabled; the Windows row is the point.
    CHECK_THAT(h, ContainsSubstring(">Disabled</span>"));
    CHECK_THAT(h, ContainsSubstring("<code>processes@windows</code>"));
    CHECK_THAT(h, ContainsSubstring("maintenance"));
    CHECK_THAT(h, ContainsSubstring("No switch set"));
    CHECK_THAT(h, ContainsSubstring("A per-OS row only narrows."));
    CHECK_THAT(h, ContainsSubstring("not yet known are not covered by a per-OS switch"));
}

TEST_CASE("kill switch panel: an unreadable layer is Unknown, never Enabled", "[plugin_page][plugins][ui]") {
    KillSwitchPanel p;
    p.plugin = "processes";
    p.layers = {layer("", SwitchState::Unknown)};
    const auto h = render_kill_switch_panel(p);
    CHECK_THAT(h, ContainsSubstring(">Unknown</span>"));
    CHECK_FALSE(has(h, ">Enabled</span>"));
    // The deciding-row cell must not read as a definitive absence either.
    CHECK_THAT(h, ContainsSubstring("<td>Unknown</td></tr>"));
    CHECK_FALSE(has(h, "No switch set"));
}

TEST_CASE("kill switch panel: a blank action says action-level switches are not shown",
          "[plugin_page][plugins][ui]") {
    KillSwitchPanel p;
    p.plugin = "echo";
    p.layers = {layer("", SwitchState::Enabled)};
    CHECK_THAT(render_kill_switch_panel(p), ContainsSubstring("action-level switch is not shown"));
    p.action = "sql";
    CHECK_FALSE(has(render_kill_switch_panel(p), "action-level switch is not shown"));
    KillSwitchPanel empty;
    CHECK_THAT(render_kill_switch_panel(empty),
               ContainsSubstring("a switch on one action appears when you enter that action"));
}

TEST_CASE("kill switch panel: protective note and unseen-name warning", "[plugin_page][plugins][ui]") {
    KillSwitchPanel p;
    p.plugin = "quarantine";
    p.protective = true;
    p.layers = {layer("", SwitchState::Enabled)};
    CHECK_THAT(render_kill_switch_panel(p),
               ContainsSubstring("protective actions of this plugin are never refused"));

    KillSwitchPanel q;
    q.plugin = "procesess"; // typo
    q.catalogue_available = true;
    q.plugin_known = false;
    q.layers = {layer("", SwitchState::Enabled)};
    const auto h = render_kill_switch_panel(q);
    CHECK_THAT(h, ContainsSubstring("has not seen plugin 'procesess'"));
    CHECK_THAT(h, ContainsSubstring("stops nothing"));

    // Without a catalogue (denied or empty fleet) the page does not claim a name is unknown.
    q.catalogue_available = false;
    CHECK_FALSE(has(render_kill_switch_panel(q), "has not seen plugin"));

    // A known plugin with an unseen action names the action.
    KillSwitchPanel a;
    a.plugin = "processes";
    a.action = "lst";
    a.catalogue_available = true;
    a.plugin_known = true;
    a.action_known = false;
    a.layers = {layer("", SwitchState::Enabled)};
    CHECK_THAT(render_kill_switch_panel(a), ContainsSubstring("plugin 'processes' action 'lst'"));
}

TEST_CASE("kill switch panel: invalid input, degraded and denied", "[plugin_page][plugins][ui]") {
    KillSwitchPanel p;
    p.plugin = "Bad Name";
    p.input_error = "That plugin or action name is not valid.";
    auto h = render_kill_switch_panel(p);
    CHECK_THAT(h, ContainsSubstring("That plugin or action name is not valid."));
    CHECK_FALSE(has(h, "<table"));

    p = {};
    p.state = PanelState::Degraded;
    CHECK_THAT(render_kill_switch_panel(p), ContainsSubstring("not an empty list"));
    p.state = PanelState::Denied;
    CHECK_THAT(render_kill_switch_panel(p), ContainsSubstring("PluginConfig:Read"));
}

TEST_CASE("kill switch panel: names and reasons are escaped; the entered name stays in the form",
          "[plugin_page][plugins][ui][security]") {
    KillSwitchPanel p;
    p.plugin = kXss;
    p.action = "\"><script>1</script>";
    p.known_plugins = {kXss};
    p.layers = {layer("", SwitchState::Disabled, kXss)};
    p.layers[0].reason = kXss;
    p.layers[0].set_by = kXss;
    const auto h = render_kill_switch_panel(p);
    CHECK_FALSE(has(h, "<img"));
    CHECK_FALSE(has(h, "<script>1"));
    CHECK_FALSE(has(h, "hx-on"));
}

TEST_CASE("layer labels", "[plugin_page][plugins][ui]") {
    CHECK(layer_label("") == "All operating systems");
    CHECK(layer_label("windows") == "Windows");
    CHECK(layer_label("linux") == "Linux");
    CHECK(layer_label("darwin") == "macOS");
}

// ── Product packs ─────────────────────────────────────────────────────────

TEST_CASE("packs panel: empty, rows, items, signed pills", "[plugin_page][plugins][ui]") {
    PacksPanel p;
    CHECK_THAT(render_packs_panel(p), ContainsSubstring("No product packs installed."));

    PackRow a;
    a.id = "pack-1";
    a.name = "Windows hardening";
    a.version = "1.2.0";
    a.description = "CIS baseline";
    a.items = {{"InstructionDefinition", "Disable SMBv1", "i-1"}, {"Policy", "Baseline", "p-1"}};
    a.installed_at = 1'800'000'000;
    a.verified = true;
    PackRow b = a;
    b.id = "pack-2";
    b.verified = false;
    b.items = {{"Workflow", "Only one", "w-1"}};
    p.rows = {a, b};
    const auto h = render_packs_panel(p);
    CHECK_THAT(h, ContainsSubstring("Windows hardening"));
    CHECK_THAT(h, ContainsSubstring("2 items"));
    CHECK_THAT(h, ContainsSubstring("1 item<"));
    CHECK_THAT(h, ContainsSubstring("href=\"/api/v1/product-packs/pack-1\""));
    // "Signed" is valid-for-the-key-inside-the-pack: a neutral pill, not green OK.
    CHECK_THAT(h, ContainsSubstring("pill idle\" title=\"Valid for the key in the pack\">Signed"));
    CHECK_THAT(h, ContainsSubstring(">Unsigned</span>"));
    CHECK_FALSE(has(h, "pill ok"));
    CHECK_THAT(h, ContainsSubstring("2027-01-15T08:00:00Z"));
    // Items, not "Instructions": the column counts every kind.
    CHECK_THAT(h, ContainsSubstring("<th>Items</th>"));
}

TEST_CASE("packs panel: the first-N banner appears only when more exist", "[plugin_page][plugins][ui]") {
    PacksPanel p;
    p.shown_limit = 100;
    p.more = false;
    CHECK_FALSE(has(render_packs_panel(p), "First 100 shown."));
    p.more = true;
    CHECK_THAT(render_packs_panel(p), ContainsSubstring("First 100 shown."));
}

TEST_CASE("packs panel: degraded is not empty; denied names ProductPack:Read", "[plugin_page][plugins][ui]") {
    PacksPanel p;
    p.state = PanelState::Degraded;
    auto h = render_packs_panel(p);
    CHECK_THAT(h, ContainsSubstring("not an empty list"));
    CHECK_FALSE(has(h, "No product packs installed."));
    p.state = PanelState::Denied;
    CHECK_THAT(render_packs_panel(p), ContainsSubstring("ProductPack:Read"));
}

TEST_CASE("packs panel: pack and item text is escaped", "[plugin_page][plugins][ui][security]") {
    PacksPanel p;
    PackRow r;
    r.id = "\"><script>1</script>";
    r.name = kXss;
    r.version = kXss;
    r.description = kXss;
    r.items = {{kXss, kXss, kXss}};
    p.rows = {r};
    const auto h = render_packs_panel(p);
    CHECK_FALSE(has(h, "<img"));
    CHECK_FALSE(has(h, "<script>1"));
}
