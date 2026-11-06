/**
 * test_dex_score_policy_form.cpp -- the pure core of the DEX Scoring tab
 * (dex_score_policy_form.hpp): the urlencoded form <-> the version-2 score policy document, the
 * override row map, the section renderer and the tier-change preview. No store, no httplib, no
 * I/O; the route shell is in test_settings_routes_dex_scoring.cpp.
 */
#include "dex_score_policy_form.hpp"

#include <catch2/catch_test_macros.hpp>
#include <nlohmann/json.hpp>

#include <cstddef>
#include <string>
#include <vector>

using namespace yuzu::server;
using json = nlohmann::json;

namespace {

DexFormPairs pairs_of(const DexFormValues& v) { return {v.begin(), v.end()}; }

std::size_t count_of(const std::string& hay, const std::string& needle) {
    std::size_t n = 0;
    for (auto at = hay.find(needle); at != std::string::npos; at = hay.find(needle, at + 1))
        ++n;
    return n;
}
bool has(const std::string& hay, const std::string& needle) {
    return hay.find(needle) != std::string::npos;
}

void leaves(const json& j, const std::string& path, std::vector<std::string>& out) {
    if (j.is_object()) {
        for (const auto& [k, v] : j.items())
            leaves(v, path.empty() ? k : path + "." + k, out);
    } else if (j.is_array()) {
        for (std::size_t i = 0; i < j.size(); ++i)
            leaves(j[i], path + "[" + std::to_string(i) + "]", out);
    } else {
        out.push_back(path);
    }
}

DexScoreOverride override_named(const std::string& image) {
    DexScoreOverride o;
    o.image = image;
    return o;
}

/// A policy with every field of the document off its default, one override setting them all.
DexScorePolicy full_policy() {
    DexScorePolicy p;
    p.tiers.edges = {91.0, 81.0, 71.0};
    p.tiers.names = {"Great", "Okay", "Meh", "Bad"};
    p.weights = {20.0, 30.0, 25.0, 25.0};
    p.model = {7, 4.0, 1.5};
    p.interval_confidence = 0.9;
    DexScoreOverride o = override_named("full.exe");
    o.excellent = 95.0;
    o.good = 85.0;
    o.fair = 75.0;
    o.names = {std::optional<std::string>("A"), std::optional<std::string>("B"),
               std::optional<std::string>("C"), std::optional<std::string>("D")};
    o.breadth = 25.0;
    o.crashes = 25.0;
    o.hangs = 25.0;
    o.regression = 25.0;
    o.per_device_event_cap = 9;
    o.regression_full_ratio = 5.0;
    o.regression_start_ratio = 2.0;
    p.overrides.push_back(o);
    return p;
}

DexScoringView view_of(const DexScorePolicy& p, bool admin = true) {
    DexScoringView v;
    v.values = dex_form_values(p);
    v.admin = admin;
    return v;
}

/// Every `<input` or `<button` tag in `html` (up to its closing '>').
std::vector<std::string> control_tags(const std::string& html) {
    std::vector<std::string> out;
    for (const char* open : {"<input", "<button"})
        for (auto at = html.find(open); at != std::string::npos; at = html.find(open, at + 1))
            out.push_back(html.substr(at, html.find('>', at) - at + 1));
    return out;
}

DexAppStability app(const std::string& subject, std::optional<StabilityBand> band) {
    DexAppStability a;
    a.subject = subject;
    a.figures.score.band = band;
    return a;
}

} // namespace

TEST_CASE("form: the shipped defaults round-trip to the exact version-1 canonical text",
          "[server][dex][score_policy][form]") {
    const auto doc = dex_form_to_document(pairs_of(dex_form_values(dex_default_score_policy())));
    REQUIRE(doc);
    const auto v = dex_score_policy_validate_text(doc->text);
    REQUIRE(v);
    CHECK(dex_score_policy_canonical(*v) == dex_score_policy_canonical(dex_default_score_policy()));
    CHECK(json::parse(dex_score_policy_canonical(*v))["version"] == 1);
    CHECK_FALSE(json::parse(dex_score_policy_canonical(*v)).contains("model"));
    CHECK(doc->row_of_override.empty());
}

TEST_CASE("form: a non-default model and an override model field build a version-2 document",
          "[server][dex][score_policy][form]") {
    DexScorePolicy p;
    p.model.per_device_event_cap = 7;
    DexScoreOverride o = override_named("outlook.exe");
    o.regression_start_ratio = 2.0;
    p.overrides.push_back(o);
    const auto doc = dex_form_to_document(pairs_of(dex_form_values(p)));
    REQUIRE(doc);
    CHECK(json::parse(doc->text)["version"] == 2);
    const auto v = dex_score_policy_validate_text(doc->text);
    REQUIRE(v);
    CHECK(v->model.per_device_event_cap == 7);
    REQUIRE(v->overrides.size() == 1);
    CHECK(v->overrides[0].regression_start_ratio == 2.0);
    CHECK(json::parse(dex_score_policy_canonical(*v))["version"] == 2);
}

TEST_CASE("form: blank and removed rows are dropped, order is kept and unset fields inherit",
          "[server][dex][score_policy][form]") {
    auto v = dex_form_values(dex_default_score_policy());
    v["overrides[0].image"] = "a.exe";
    v["overrides[1].image"] = "b.exe";
    v["overrides[1].remove"] = "on";
    v["overrides[2].image"] = "c.exe";
    v["overrides[2].weights.hangs"] = "5";
    v["overrides[2].weights.crashes"] = ""; // blank: inherits, no key
    v["overrides[3].image"] = "d.exe";
    for (const char* f : {"image", "tiers.edges.excellent", "weights.breadth"})
        v[std::string("overrides[4].") + f] = ""; // the browser's blank trailing row
    const auto doc = dex_form_to_document(pairs_of(v));
    REQUIRE(doc);
    CHECK(doc->row_of_override == std::vector<int>{0, 2, 3});
    const auto j = json::parse(doc->text);
    REQUIRE(j["overrides"].size() == 3);
    CHECK(j["overrides"][0] == json{{"image", "a.exe"}});
    CHECK(j["overrides"][1] == json{{"image", "c.exe"}, {"weights", {{"hangs", 5}}}});
    CHECK(j["overrides"][2]["image"] == "d.exe");
}

TEST_CASE("form: a validator path is remapped to the submitted row and the renderer marks it",
          "[server][dex][score_policy][form]") {
    auto v = dex_form_values(dex_default_score_policy());
    v["overrides[0].image"] = "dup.exe";
    v["overrides[0].remove"] = "on";
    v["overrides[1].image"] = "dup.exe";
    v["overrides[2].image"] = "dup.exe";
    const auto doc = dex_form_to_document(pairs_of(v));
    REQUIRE(doc);
    CHECK(doc->row_of_override == std::vector<int>{1, 2});
    const auto bad = dex_score_policy_validate_text(doc->text);
    REQUIRE_FALSE(bad);
    CHECK(bad.error().field == "overrides[1].image"); // the JSON index
    const auto field = dex_form_remap_field(bad.error().field, doc->row_of_override);
    CHECK(field == "overrides[2].image"); // the submitted row

    DexScoringView view;
    view.values = dex_form_values(pairs_of(v));
    view.admin = true;
    view.error = DexFormError{field, "override_key_duplicate at " + field};
    const auto html = render_dex_scoring_section(view);
    CHECK(has(html, "<span class=\"err\" data-field=\"overrides[2].image\""));
    CHECK_FALSE(has(html, "<span class=\"err\" data-field=\"overrides[1].image\""));
    CHECK_FALSE(has(html, "<span class=\"err\" data-field=\"overrides[0].image\""));
    CHECK(dex_form_remap_field("overrides[9].image", doc->row_of_override) == "overrides");
    CHECK(dex_form_remap_field("weights", doc->row_of_override) == "weights");
}

TEST_CASE("form: a value that is not a number is refused by the parser at that exact field",
          "[server][dex][score_policy][form]") {
    auto v = dex_form_values(dex_default_score_policy());
    v["weights.hangs"] = "abc";
    const auto doc = dex_form_to_document(pairs_of(v));
    REQUIRE(doc);
    const auto bad = dex_score_policy_validate_text(doc->text);
    REQUIRE_FALSE(bad);
    CHECK(bad.error().field == "weights.hangs");
    CHECK(bad.error().message.starts_with("unparseable at weights.hangs: must be a number"));
    // A blank global field is carried too, so it is named rather than silently defaulted.
    v["weights.hangs"] = "";
    const auto blank = dex_score_policy_validate_text(dex_form_to_document(pairs_of(v))->text);
    REQUIRE_FALSE(blank);
    CHECK(blank.error().field == "weights.hangs");
}

TEST_CASE("form: an override index above the limit is refused before anything is built, and 201 "
          "real rows reach the validator's too_many_overrides",
          "[server][dex][score_policy][form]") {
    auto v = dex_form_values(dex_default_score_policy());
    v["overrides[300].image"] = "x.exe";
    const auto refused = dex_form_to_document(pairs_of(v));
    REQUIRE_FALSE(refused);
    CHECK(refused.error().field == "overrides");

    auto many = dex_form_values(dex_default_score_policy());
    for (int i = 0; i <= 200; ++i)
        many["overrides[" + std::to_string(i) + "].image"] = "app" + std::to_string(i) + ".exe";
    const auto doc = dex_form_to_document(pairs_of(many));
    REQUIRE(doc);
    const auto bad = dex_score_policy_validate_text(doc->text);
    REQUIRE_FALSE(bad);
    CHECK(bad.error().field == "overrides");
    CHECK(has(bad.error().message, "too_many_overrides"));

    DexFormPairs huge(kDexFormMaxPairs + 1, std::pair<std::string, std::string>{"x", "y"});
    CHECK_FALSE(dex_form_to_document(huge));
}

TEST_CASE("form: the image key folds to ASCII lower case so a case-only duplicate is refused on "
          "its row",
          "[server][dex][score_policy][form]") {
    auto v = dex_form_values(dex_default_score_policy());
    v["overrides[0].image"] = "Outlook.EXE";
    v["overrides[1].image"] = "outlook.exe";
    const auto doc = dex_form_to_document(pairs_of(v));
    REQUIRE(doc);
    const auto bad = dex_score_policy_validate_text(doc->text);
    REQUIRE_FALSE(bad);
    CHECK(bad.error().field == "overrides[1].image");
    DexScoringView view;
    view.values = v;
    view.admin = true;
    view.error = DexFormError{bad.error().field, bad.error().message};
    CHECK(has(render_dex_scoring_section(view), "<span class=\"err\" data-field=\"overrides[1].image\""));
}

TEST_CASE("form pairs: bodies decode, repeat last-wins and the cap is detectable",
          "[server][dex][score_policy][form]") {
    const auto p = dex_form_pairs("a=1&b=x%26y+z&c&=skip&a=2");
    REQUIRE(p.size() == 4);
    CHECK(p[1] == std::pair<std::string, std::string>{"b", "x&y z"});
    CHECK(p[2] == std::pair<std::string, std::string>{"c", ""});
    CHECK(dex_form_values(p).at("a") == "2");
}

TEST_CASE("render: an input named for every field of the typed document",
          "[server][dex][score_policy][form]") {
    const auto p = full_policy();
    REQUIRE_FALSE(dex_score_policy_fault(p));
    std::vector<std::string> paths;
    leaves(dex_score_policy_to_json(p), "", paths);
    REQUIRE(paths.size() > 20);
    DexScoringView view = view_of(p);
    view.revision = "0123456789abcdef";
    const auto html = render_dex_scoring_section(view);
    for (const auto& path : paths) {
        if (path == "version")
            continue; // stamped by the builder, not a field
        INFO(path);
        CHECK(has(html, "name=\"" + path + "\""));
    }
    CHECK(has(html, "<input type=\"hidden\" name=\"if_match\" value=\"0123456789abcdef\""));
    CHECK(has(html, "At most 200 overrides; 1 in use."));
    CHECK(has(html, "name=\"overrides[1].image\"")); // the blank trailing row
}

TEST_CASE("render: no blank row and the limit text at 200 overrides",
          "[server][dex][score_policy][form]") {
    DexScorePolicy p;
    for (std::size_t i = 0; i < kDexPolicyMaxOverrides; ++i)
        p.overrides.push_back(override_named("app" + std::to_string(i) + ".exe"));
    const auto html = render_dex_scoring_section(view_of(p));
    CHECK(has(html, "name=\"overrides[199].image\""));
    CHECK_FALSE(has(html, "name=\"overrides[200].image\""));
    CHECK(has(html, "data-limit=\"reached\""));
}

TEST_CASE("render: one form, three controls inside it, section body only",
          "[server][dex][score_policy][form]") {
    const auto html = render_dex_scoring_section(view_of(dex_default_score_policy()));
    CHECK(count_of(html, "<form") == 1);
    CHECK(count_of(html, "</form>") == 1);
    CHECK(count_of(html, "hx-post=\"/api/settings/dex-scoring/save\"") == 1);
    const auto close = html.find("</form>");
    for (const char* op : {"preview", "reset"}) {
        const auto at = html.find(std::string("hx-post=\"/api/settings/dex-scoring/") + op + "\"");
        REQUIRE(at != std::string::npos);
        CHECK(at < close);
    }
    CHECK(has(html, "hx-target=\"#dex-scoring-section\" hx-swap=\"innerHTML\" hx-confirm="));
    CHECK_FALSE(has(html, "id=\"dex-scoring-section\""));
}

TEST_CASE("render: tier names and image keys are HTML-escaped at every sink",
          "[server][dex][score_policy][form]") {
    DexScoringView view = view_of(dex_default_score_policy());
    view.values["tiers.names.good"] = "O'Brien's";
    view.values["overrides[0].image"] = "<img src=x>";
    view.suggestions = {"<img src=x>"};
    view.fault = "<b>fault</b>";
    DexTierPreview pv;
    pv.total = 1;
    pv.changed = 1;
    pv.rows.push_back({"<script>", "O'Brien's", "<i>"});
    view.preview = pv;
    const auto html = render_dex_scoring_section(view);
    CHECK(has(html, "value=\"O&#39;Brien&#39;s\""));
    CHECK(has(html, "&lt;img src=x&gt;"));
    CHECK(has(html, "&lt;script&gt;"));
    CHECK_FALSE(has(html, "<img"));
    CHECK_FALSE(has(html, "<script"));
    CHECK_FALSE(has(html, "<b>fault"));
}

TEST_CASE("render: the error mark lands on the input, the group or the document",
          "[server][dex][score_policy][form]") {
    DexScorePolicy p;
    for (int i = 0; i < 3; ++i)
        p.overrides.push_back(override_named("app" + std::to_string(i) + ".exe"));
    auto with_error = [&](const std::string& field) {
        DexScoringView v = view_of(p);
        v.error = DexFormError{field, "boom"};
        return render_dex_scoring_section(v);
    };
    auto group = with_error("tiers.edges");
    CHECK(has(group, "<fieldset class=\"grp\" data-field=\"tiers.edges\" data-invalid=\"1\">"));
    CHECK(has(group, "<span class=\"err\" data-field=\"tiers.edges\""));
    CHECK(count_of(group, "class=\"err\"") == 1);

    auto leaf = with_error("overrides[2].weights.breadth");
    CHECK(has(leaf, "<span class=\"err\" data-field=\"overrides[2].weights.breadth\""));
    CHECK(has(leaf, "aria-invalid=\"true\""));
    CHECK(count_of(leaf, "class=\"err\"") == 1);

    CHECK(has(with_error("document"), "<span class=\"err\" data-field=\"document\""));
    // A path the form has no element for marks the document.
    CHECK(has(with_error("overrides[2].weights.nope"),
              "<span class=\"err\" data-field=\"document\""));
    CHECK(has(with_error("version"), "<span class=\"err\" data-field=\"document\""));
}

TEST_CASE("render: a non-administrator sees every control disabled and the role note",
          "[server][dex][score_policy][form]") {
    const auto ro = render_dex_scoring_section(view_of(dex_default_score_policy(), false));
    CHECK(has(ro, "data-denied=\"admin\""));
    const auto tags = control_tags(ro);
    REQUIRE(tags.size() > 20);
    for (const auto& t : tags) {
        INFO(t);
        CHECK(has(t, " disabled"));
    }
    const auto rw = render_dex_scoring_section(view_of(dex_default_score_policy(), true));
    CHECK_FALSE(has(rw, "data-denied"));
    for (const auto& t : control_tags(rw)) {
        INFO(t);
        CHECK_FALSE(has(t, " disabled"));
    }
}

TEST_CASE("render: the application datalist exists only with suggestions",
          "[server][dex][score_policy][form]") {
    const auto none = render_dex_scoring_section(view_of(dex_default_score_policy()));
    CHECK_FALSE(has(none, "<datalist"));
    CHECK_FALSE(has(none, "list=\"dxs-apps\""));
    DexScoringView v = view_of(dex_default_score_policy());
    v.suggestions = {"a<b.exe", "c.exe"};
    const auto some = render_dex_scoring_section(v);
    CHECK(has(some, "<datalist id=\"dxs-apps\">"));
    CHECK(has(some, "<option value=\"a&lt;b.exe\">"));
    CHECK(has(some, "list=\"dxs-apps\""));
}

TEST_CASE("render: the refused token and the stale banner appear only when set",
          "[server][dex][score_policy][form]") {
    const auto plain = render_dex_scoring_section(view_of(dex_default_score_policy()));
    CHECK_FALSE(has(plain, "data-refused"));
    CHECK_FALSE(has(plain, "changed by someone else"));
    DexScoringView v = view_of(dex_default_score_policy());
    v.refused = "invalid";
    CHECK(has(render_dex_scoring_section(v), "data-refused=\"invalid\""));
    CHECK_FALSE(has(render_dex_scoring_section(v), "changed by someone else"));
    v.refused = "stale";
    const auto stale = render_dex_scoring_section(v);
    CHECK(has(stale, "changed by someone else"));
    CHECK(has(stale, "hx-get=\"/fragments/dex/scoring?window=7d\""));
    for (const auto& t : control_tags(stale)) {
        if (has(t, "hx-get="))
            continue; // the Reload button
        INFO(t);
        CHECK(has(t, " disabled"));
    }
}

TEST_CASE("preview: bands are diffed per shared subject with each model's own tier names",
          "[server][dex][score_policy][form]") {
    DexAppsModel now, next;
    now.apps = {app("a", StabilityBand::Excellent), app("b", StabilityBand::Good),
                app("c", StabilityBand::Fair), app("only-now", StabilityBand::Poor)};
    next.apps = {app("a", StabilityBand::Excellent), app("b", StabilityBand::Good),
                 app("c", StabilityBand::Poor)};
    next.policy.policy.tiers.names[3] = "Critical";
    const auto pv = dex_tier_preview(now, next);
    CHECK_FALSE(pv.degraded);
    CHECK(pv.total == 3);
    CHECK(pv.changed == 1);
    REQUIRE(pv.rows.size() == 1);
    CHECK(pv.rows[0].subject == "c");
    CHECK(pv.rows[0].from == "fair");
    CHECK(pv.rows[0].to == "Critical");

    DexAppsModel bad = now;
    bad.degraded = true;
    CHECK(dex_tier_preview(bad, next).degraded);
    CHECK(dex_tier_preview(now, bad).degraded);
}

TEST_CASE("preview: the table is capped and the summary is rendered",
          "[server][dex][score_policy][form]") {
    DexAppsModel now, next;
    for (int i = 0; i < 25; ++i) {
        now.apps.push_back(app("app" + std::to_string(i), StabilityBand::Good));
        next.apps.push_back(app("app" + std::to_string(i), StabilityBand::Fair));
    }
    const auto pv = dex_tier_preview(now, next);
    CHECK(pv.changed == 25);
    CHECK(pv.rows.size() == kDexPreviewMaxRows);
    DexScoringView v = view_of(dex_default_score_policy());
    v.preview = pv;
    const auto html = render_dex_scoring_section(v);
    CHECK(has(html, "25 of 25 applications change tier"));
    CHECK(has(html, "The first 20 are shown."));
    v.preview = DexTierPreview{.degraded = true};
    CHECK(has(render_dex_scoring_section(v), "Preview unavailable"));
}
