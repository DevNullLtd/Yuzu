#pragma once

/**
 * @file dex_score_policy_form.hpp
 * Pure core of the DEX Scoring tab: the urlencoded form <-> the typed score policy document,
 * the section renderer, and the tier-change preview diff. No I/O, no httplib, no store, no
 * clock; the route shell is SettingsRoutes (settings_routes.cpp).
 *
 * ONE VALIDATOR. The form states no range. It builds a version-2 JSON document whose field
 * names ARE the JSON paths (`tiers.edges.excellent`, `weights.hangs`,
 * `model.interval_confidence`, `overrides[3].tiers.names.good`, `overrides[3].image`), and the
 * strict parser and range validator of dex_score_policy_json.hpp refuse it exactly as they
 * refuse the REST body. A value that is not a number is emitted as a JSON string, so the
 * parser names that exact field ("must be a number"). The canonical dump demotes a document
 * with no model parameter to version 1, so the rolling-upgrade rule holds.
 *
 * OVERRIDE ROWS. A submitted row is dropped from the document when its image is blank or its
 * Remove box is ticked, so the JSON override index and the submitted form row index differ
 * after a drop. The document carries `row_of_override` (JSON index -> form row) and
 * dex_form_remap_field rewrites a validator path back to the form row that holds the fault,
 * so an error never lands on the wrong row.
 *
 * Every value that reaches markup passes html_escape (tier names allow an apostrophe; image
 * keys are customer text).
 */

#include "dex_read_model.hpp"
#include "dex_score_policy_json.hpp"
#include "web_utils.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <array>
#include <charconv>
#include <cctype>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <expected>
#include <format>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <unordered_map>
#include <utility>
#include <vector>

namespace yuzu::server {

/// Most name/value pairs one form body may carry; 200 override rows of 16 fields (image, Remove,
/// 3 edges, 4 names, 4 weights, 3 model) plus the globals is about 3,200. Above it the form
/// is refused whole (never silently truncated).
inline constexpr std::size_t kDexFormMaxPairs = 8192;
/// Highest override row index accepted from the wire.
inline constexpr int kDexFormMaxOverrideIndex = 255;
/// A value that is not a number is carried to the parser as a string, capped at this.
inline constexpr std::size_t kDexFormMaxBadNumberBytes = 64;
/// Rows of the tier-change table.
inline constexpr std::size_t kDexPreviewMaxRows = 20;

using DexFormPairs = std::vector<std::pair<std::string, std::string>>;
/// Field path -> submitted text. Sorted by path; the override row order comes from the index.
using DexFormValues = std::map<std::string, std::string>;

struct DexFormDocument {
    std::string text;                  ///< the version-2 JSON text handed to the writer
    std::vector<int> row_of_override;  ///< JSON override index -> submitted form row index
};

struct DexFormError {
    std::string field; ///< already remapped to the submitted form row
    std::string message;
};

namespace dex_form_detail {

inline constexpr std::array<std::string_view, 3> kEdgeKeys{"excellent", "good", "fair"};
inline constexpr std::array<std::string_view, 4> kNameKeys{"excellent", "good", "fair", "poor"};
inline constexpr std::array<std::string_view, 4> kWeightKeys{"breadth", "crashes", "hangs",
                                                             "regression"};
inline constexpr std::array<std::string_view, 4> kModelKeys{
    "per_device_event_cap", "regression_full_ratio", "regression_start_ratio",
    "interval_confidence"};
/// An override's model block has no interval_confidence (global only).
inline constexpr std::size_t kOverrideModelKeys = 3;

using json = nlohmann::json;

[[nodiscard]] inline std::string trim(std::string_view s) {
    constexpr std::string_view ws = " \t\r\n";
    const auto b = s.find_first_not_of(ws);
    if (b == std::string_view::npos)
        return {};
    return std::string(s.substr(b, s.find_last_not_of(ws) - b + 1));
}

/// A JSON number when `text` is wholly one (an integer stays an integer, so the event cap
/// parses), otherwise the raw text as a bounded JSON string for the parser to refuse by name.
/// strtod also reads hexadecimal ("0x10") and hex-float ("0x1p3") forms that a JSON body would
/// refuse, so a text holding x/X/p/P is never offered to it; from_chars<double> would need no
/// such guard but is not available on Apple Clang 15.
[[nodiscard]] inline json number_or_string(const std::string& raw) {
    const std::string t = trim(raw);
    if (!t.empty() && t.find_first_of("xXpP") == std::string::npos) {
        std::int64_t i = 0;
        const auto [p, ec] = std::from_chars(t.data(), t.data() + t.size(), i);
        if (ec == std::errc{} && p == t.data() + t.size())
            return i;
        char* end = nullptr;
        const double d = std::strtod(t.c_str(), &end);
        if (end == t.c_str() + t.size() && std::isfinite(d))
            return d;
    }
    return t.substr(0, kDexFormMaxBadNumberBytes);
}

/// `overrides[N].rest` -> {N, rest}. An index of five or more digits is no real row: it reads
/// as one past kDexFormMaxOverrideIndex, so the form is refused whole rather than the pair being
/// ignored. A leading zero ("007") is not the canonical spelling of any row (the form looks row 7
/// up as "overrides[7]."), so such a name is malformed and ignored like any other.
[[nodiscard]] inline std::optional<std::pair<int, std::string_view>>
split_override_key(std::string_view name) {
    constexpr std::string_view kPre = "overrides[";
    if (!name.starts_with(kPre))
        return std::nullopt;
    name.remove_prefix(kPre.size());
    const auto close = name.find("].");
    if (close == std::string_view::npos || close == 0)
        return std::nullopt;
    const std::string_view digits = name.substr(0, close);
    for (const char c : digits)
        if (c < '0' || c > '9')
            return std::nullopt;
    if (digits.size() > 1 && digits.front() == '0')
        return std::nullopt;
    int n = kDexFormMaxOverrideIndex + 1;
    if (digits.size() <= 4) {
        n = 0;
        for (const char c : digits)
            n = n * 10 + (c - '0');
    }
    return std::make_pair(n, name.substr(close + 2));
}

/// Sorted distinct override row indices present in `v`.
[[nodiscard]] inline std::vector<int> override_rows(const DexFormValues& v) {
    std::set<int> rows;
    for (const auto& kv : v)
        if (const auto k = split_override_key(kv.first))
            rows.insert(k->first);
    return {rows.begin(), rows.end()};
}

[[nodiscard]] inline std::string row_key(int row, std::string_view rest) {
    return "overrides[" + std::to_string(row) + "]." + std::string(rest);
}

[[nodiscard]] inline std::string num(double d) { return std::format("{}", d); }

[[nodiscard]] inline const std::string& value_of(const DexFormValues& v, const std::string& name) {
    static const std::string kEmpty;
    const auto it = v.find(name);
    return it == v.end() ? kEmpty : it->second;
}

/// {key: value} of the keys named in `v` under `base`; a blank value is skipped when
/// `skip_blank` (an override inherits), else carried so the validator names it. Blank is empty
/// for a name (a space is a valid name character the validator accepts, so it keeps its bytes)
/// and empty-after-trim for a number (a number cannot contain a space).
template <class Keys>
[[nodiscard]] inline json collect(const DexFormValues& v, const std::string& base,
                                  const Keys& keys, std::size_t count, bool numeric,
                                  bool skip_blank) {
    json out = json::object();
    for (std::size_t i = 0; i < count; ++i) {
        const auto it = v.find(base + "." + std::string(keys[i]));
        if (it == v.end())
            continue;
        if (skip_blank && (numeric ? trim(it->second).empty() : it->second.empty()))
            continue;
        out[std::string(keys[i])] = numeric ? number_or_string(it->second) : json(it->second);
    }
    return out;
}

inline void attach(json& obj, const char* key, json&& child) {
    if (!child.empty())
        obj[key] = std::move(child);
}

} // namespace dex_form_detail

/// Split an application/x-www-form-urlencoded body into decoded (name, value) pairs, in order.
/// Stops one past kDexFormMaxPairs so a caller can tell the form was over the cap.
[[nodiscard]] inline DexFormPairs dex_form_pairs(std::string_view body) {
    DexFormPairs out;
    std::size_t pos = 0;
    while (pos <= body.size() && out.size() <= kDexFormMaxPairs) {
        const auto amp = body.find('&', pos);
        const auto item = body.substr(pos, (amp == std::string_view::npos ? body.size() : amp) - pos);
        pos = amp == std::string_view::npos ? body.size() + 1 : amp + 1;
        if (item.empty())
            continue;
        const auto eq = item.find('=');
        std::string name = url_decode(std::string(item.substr(0, eq)));
        std::string value =
            eq == std::string_view::npos ? std::string() : url_decode(std::string(item.substr(eq + 1)));
        if (!name.empty())
            out.emplace_back(std::move(name), std::move(value));
    }
    return out;
}

/// The submitted values, later duplicates winning, with every override row that carries
/// nothing at all dropped (the blank trailing row a browser always submits: empty strings, never
/// whitespace, so a value of spaces is content and keeps its row).
[[nodiscard]] inline DexFormValues dex_form_values(const DexFormPairs& pairs) {
    using namespace dex_form_detail;
    DexFormValues v;
    for (const auto& [name, value] : pairs)
        v.insert_or_assign(name, value);
    for (const int row : override_rows(v)) {
        const std::string pre = row_key(row, "");
        bool blank = true;
        for (auto it = v.lower_bound(pre); it != v.end() && it->first.starts_with(pre); ++it)
            if (!it->second.empty())
                blank = false;
        if (blank)
            for (auto it = v.lower_bound(pre); it != v.end() && it->first.starts_with(pre);)
                it = v.erase(it);
    }
    return v;
}

/// The form values of a policy: every global field, and per override only the fields it sets.
[[nodiscard]] inline DexFormValues dex_form_values(const DexScorePolicy& p) {
    using namespace dex_form_detail;
    DexFormValues v;
    v["tiers.edges.excellent"] = num(p.tiers.edges.excellent);
    v["tiers.edges.good"] = num(p.tiers.edges.good);
    v["tiers.edges.fair"] = num(p.tiers.edges.fair);
    for (std::size_t i = 0; i < 4; ++i)
        v["tiers.names." + std::string(kNameKeys[i])] = p.tiers.names[i];
    v["weights.breadth"] = num(p.weights.breadth);
    v["weights.crashes"] = num(p.weights.crashes);
    v["weights.hangs"] = num(p.weights.hangs);
    v["weights.regression"] = num(p.weights.regression);
    v["model.per_device_event_cap"] = std::to_string(p.model.per_device_event_cap);
    v["model.regression_full_ratio"] = num(p.model.regression_full_ratio);
    v["model.regression_start_ratio"] = num(p.model.regression_start_ratio);
    v["model.interval_confidence"] = num(p.interval_confidence);
    for (std::size_t r = 0; r < p.overrides.size(); ++r) {
        const auto& o = p.overrides[r];
        const int row = static_cast<int>(r);
        v[row_key(row, "image")] = o.image;
        auto opt = [&](std::string_view rest, const std::optional<double>& x) {
            if (x)
                v[row_key(row, rest)] = num(*x);
        };
        opt("tiers.edges.excellent", o.excellent);
        opt("tiers.edges.good", o.good);
        opt("tiers.edges.fair", o.fair);
        for (std::size_t i = 0; i < 4; ++i)
            if (o.names[i])
                v[row_key(row, "tiers.names." + std::string(kNameKeys[i]))] = *o.names[i];
        opt("weights.breadth", o.breadth);
        opt("weights.crashes", o.crashes);
        opt("weights.hangs", o.hangs);
        opt("weights.regression", o.regression);
        if (o.per_device_event_cap)
            v[row_key(row, "model.per_device_event_cap")] = std::to_string(*o.per_device_event_cap);
        opt("model.regression_full_ratio", o.regression_full_ratio);
        opt("model.regression_start_ratio", o.regression_start_ratio);
    }
    return v;
}

/// Build the version-2 document the writer validates, plus the override row map. Refuses a
/// form over the pair cap or naming an override row above kDexFormMaxOverrideIndex, before
/// anything is built, and an override row that carries values but no image. Every range is
/// left to the validator.
[[nodiscard]] inline std::expected<DexFormDocument, DexFormError>
dex_form_to_document(const DexFormPairs& pairs) {
    using namespace dex_form_detail;
    if (pairs.size() > kDexFormMaxPairs)
        return std::unexpected(DexFormError{"document", "the form carries too many fields"});
    const DexFormValues v = dex_form_values(pairs);
    const auto rows = override_rows(v);
    if (!rows.empty() && rows.back() > kDexFormMaxOverrideIndex)
        return std::unexpected(DexFormError{"overrides", "too many override rows"});

    json doc{{"version", kDexScorePolicyVersion}};
    json tiers = json::object();
    attach(tiers, "edges", collect(v, "tiers.edges", kEdgeKeys, 3, true, false));
    attach(tiers, "names", collect(v, "tiers.names", kNameKeys, 4, false, false));
    attach(doc, "tiers", std::move(tiers));
    attach(doc, "weights", collect(v, "weights", kWeightKeys, 4, true, false));
    attach(doc, "model", collect(v, "model", kModelKeys, 4, true, false));

    DexFormDocument out;
    json arr = json::array();
    for (const int row : rows) {
        // The image key keeps its bytes: the validator accepts a space in a key, so trimming here
        // would re-address a stored override on an unrelated save.
        const std::string& image = value_of(v, row_key(row, "image"));
        if (value_of(v, row_key(row, "remove")) == "on")
            continue;
        // dex_form_values already dropped every all-blank row, so a row that reaches here with no
        // image carries typed input and is refused by name, never silently lost.
        if (image.empty())
            return std::unexpected(DexFormError{row_key(row, "image"),
                                                "an override needs an application image"});
        const auto at = [&](std::string_view rest) { return row_key(row, rest); };
        json ov{{"image", image}};
        json ot = json::object();
        attach(ot, "edges", collect(v, at("tiers.edges"), kEdgeKeys, 3, true, true));
        attach(ot, "names", collect(v, at("tiers.names"), kNameKeys, 4, false, true));
        attach(ov, "tiers", std::move(ot));
        attach(ov, "weights", collect(v, at("weights"), kWeightKeys, 4, true, true));
        attach(ov, "model", collect(v, at("model"), kModelKeys, kOverrideModelKeys, true, true));
        arr.push_back(std::move(ov));
        out.row_of_override.push_back(row);
    }
    if (!arr.empty())
        doc["overrides"] = std::move(arr);
    out.text = doc.dump(-1, ' ', false, json::error_handler_t::replace);
    return out;
}

/// Rewrite a leading `overrides[j].` of a validator path to the submitted form row that carries
/// it; a j outside the map (or an index that is not one) answers the bare `overrides` group.
[[nodiscard]] inline std::string dex_form_remap_field(std::string field,
                                                      const std::vector<int>& row_of_override) {
    using namespace dex_form_detail;
    if (const auto k = split_override_key(field))
        return static_cast<std::size_t>(k->first) < row_of_override.size()
                   ? row_key(row_of_override[static_cast<std::size_t>(k->first)], k->second)
                   : std::string("overrides");
    return field.starts_with("overrides[") ? std::string("overrides") : field;
}

// ── Tier-change preview ────────────────────────────────────────────────────────────────

struct DexTierChange {
    std::string subject, from, to;
};

struct DexTierPreview {
    bool degraded{false};     ///< either read could not be completed: no diff is shown
    std::int64_t total{0};    ///< applications scored under both policies
    std::int64_t changed{0};  ///< of those, how many land in a different tier
    std::int64_t apps_total{0};     ///< applications the current model could see (before its cap)
    bool apps_truncated{false};     ///< the current model scored only the top of them
    std::vector<DexTierChange> rows; ///< the first kDexPreviewMaxRows of them
};

/// Diff the tier of each application scored under both policies. Names come from each model's
/// own effective policy for that application, so a per-application override is honoured. A
/// rename that moves no application to another band is not a tier change and is not counted.
// ponytail: the two models are two store reads, so a signal landing between them can skew the
// count; acceptable for a preview, upgrade = score one row read twice.
[[nodiscard]] inline DexTierPreview dex_tier_preview(const DexAppsModel& current,
                                                     const DexAppsModel& proposed) {
    DexTierPreview out;
    if (current.degraded || proposed.degraded) {
        out.degraded = true;
        return out;
    }
    // The model is capped to the applications affecting most devices; the figures say so.
    out.apps_total = current.apps_total;
    out.apps_truncated = current.apps_truncated;
    std::unordered_map<std::string, const DexAppStability*> after;
    for (const auto& a : proposed.apps)
        after.emplace(a.subject, &a);
    const auto tier_name = [](const DexAppsModel& m, const DexAppStability& a) -> std::string {
        const auto& band = a.figures.score.band;
        if (!band)
            return "not scored";
        const auto eff = resolve_dex_score_policy(m.policy.policy, a.subject);
        return dex_tier_name(eff.tiers, *band);
    };
    for (const auto& a : current.apps) {
        const auto it = after.find(a.subject);
        if (it == after.end())
            continue;
        ++out.total;
        if (a.figures.score.band == it->second->figures.score.band)
            continue;
        ++out.changed;
        if (out.rows.size() < kDexPreviewMaxRows)
            out.rows.push_back({a.subject, tier_name(current, a), tier_name(proposed, *it->second)});
    }
    return out;
}

// ── Renderer ───────────────────────────────────────────────────────────────────────────

struct DexScoringView {
    DexFormValues values;
    std::string revision{"default"}; ///< of the policy in force
    std::string if_match;            ///< hidden precondition; empty = revision
    std::string source{"default"};   ///< default | custom
    std::string fault;               ///< a refused stored document, or empty
    bool editable{false}; ///< the caller holds Infrastructure:Write; false = every control disabled
    std::optional<DexFormError> error;
    std::vector<std::string> suggestions; ///< application names for the image datalist
    std::optional<DexTierPreview> preview;
    std::string refused; ///< data-refused token, or empty
};

namespace dex_form_detail {

[[nodiscard]] inline std::string esc(const std::string& s) { return html_escape(s); }

[[nodiscard]] inline std::string id_of(const std::string& path) {
    std::string id = "dxs-";
    for (const char c : path)
        id += std::isalnum(static_cast<unsigned char>(c)) ? c : '-';
    return id;
}

/// One pass of the markup. `target` is the element carrying the error (a leaf input name, a
/// group data-field, or "document").
class Renderer {
public:
    Renderer(const DexScoringView& v, std::string target)
        : v_(v), target_(std::move(target)), locked_(!v.editable || v.refused == "stale") {}

    [[nodiscard]] std::string run() {
        std::string o;
        if (v_.refused == "stale")
            o += "<div class=\"note warn\" data-stale=\"1\" role=\"alert\"><b>This policy was "
                 "changed by someone else.</b> Nothing was saved. Reload to see the current "
                 "version; reloading discards the edits on screen, so note them first. <button "
                 "type=\"button\" class=\"btn btn-secondary\" hx-get=\"/fragments/dex/scoring?window=7d\" "
                 "hx-target=\"#guardian-detail\" hx-swap=\"innerHTML\">Reload</button></div>";
        if (!v_.editable)
            o += "<div class=\"note\" data-denied=\"write\"><b>Editing the score policy needs "
                 "the Infrastructure:Write permission</b> (Administrator holds it by default), "
                 "the same grant as PUT /api/v1/dex/score-policy. You can see the policy in "
                 "force; ask someone who holds it to change it.</div>";
        o += in_force();
        o += "<form class=\"form dxs\" hx-post=\"/api/settings/dex-scoring/save\" "
             "hx-target=\"#dex-scoring-section\" hx-swap=\"innerHTML\" novalidate";
        if (!v_.refused.empty())
            o += " data-refused=\"" + esc(v_.refused) + "\"";
        o += ">";
        o += "<input type=\"hidden\" name=\"if_match\" value=\"" +
             esc(v_.if_match.empty() ? v_.revision : v_.if_match) + "\"" + dis() + ">";
        if (v_.error && target_ == "document")
            o += "<div class=\"note warn\" role=\"alert\"><span class=\"err\" "
                 "data-field=\"document\">" + esc(v_.error->message) + "</span></div>";
        o += tiers_panel();
        o += weights_panel();
        o += model_panel();
        o += overrides_panel();
        o += buttons();
        o += "</form>";
        o += preview();
        return o;
    }

private:
    const DexScoringView& v_;
    std::string target_;
    bool locked_;

    [[nodiscard]] const char* dis() const { return locked_ ? " disabled" : ""; }
    [[nodiscard]] const std::string& val(const std::string& name) const {
        return value_of(v_.values, name);
    }
    [[nodiscard]] std::string err(const std::string& field) const {
        if (!v_.error || field != target_)
            return {};
        return "<span class=\"err\" data-field=\"" + esc(field) + "\" role=\"alert\">" +
               esc(v_.error->message) + "</span>";
    }

    [[nodiscard]] std::string in_force() const {
        std::string o = "<section class=\"panel dxs\"><div class=\"hd\"><h2>Policy in force</h2>"
                        "<div class=\"end\"><span class=\"pill " +
                        std::string(v_.source == "custom" ? "warn" : "idle") + "\">" +
                        (v_.source == "custom" ? "Custom" : "Shipped defaults") +
                        "</span></div></div><div class=\"pb\"><p>Revision <code>" +
                        esc(v_.revision) + "</code>. Every application is scored and banded "
                        "under this policy; a change reaches every server within a few "
                        "seconds.</p>";
        if (!v_.fault.empty())
            o += "<div class=\"note warn\" data-fault=\"1\"><b>The stored policy was refused.</b> "
                 "The shipped defaults are in force until a valid policy is saved. Reason: "
                 "<code>" + esc(v_.fault) + "</code></div>";
        return o + "</div></section>";
    }

    [[nodiscard]] std::string group_open(const std::string& field, const char* legend,
                                         const std::string& hint = {}) const {
        std::string o = "<fieldset class=\"grp\" data-field=\"" + esc(field) + "\"";
        if (v_.error && field == target_)
            o += " data-invalid=\"1\"";
        o += "><legend>" + std::string(legend) + "</legend>";
        if (!hint.empty())
            o += "<p class=\"hint\">" + hint + "</p>";
        return o;
    }
    [[nodiscard]] std::string group_close(const std::string& field) const {
        return err(field) + "</fieldset>";
    }

    [[nodiscard]] std::string input(const std::string& path, const char* label, const char* type,
                                    const std::string& attrs, bool inherit = false) const {
        const bool bad = v_.error && path == target_;
        return "<div class=\"fld\"><label for=\"" + id_of(path) + "\">" + label +
               "</label><input class=\"in\" id=\"" + id_of(path) + "\" type=\"" + type +
               "\" name=\"" + esc(path) + "\" value=\"" + esc(val(path)) + "\"" +
               (inherit ? " placeholder=\"inherit\"" : "") + attrs +
               (bad ? " aria-invalid=\"true\"" : "") + dis() + ">" + err(path) + "</div>";
    }
    [[nodiscard]] std::string number(const std::string& path, const char* label, double lo,
                                     double hi, const char* step, bool inherit = false) const {
        return input(path, label, "number",
                     " min=\"" + num(lo) + "\" max=\"" + num(hi) + "\" step=\"" + step + "\"",
                     inherit);
    }
    [[nodiscard]] std::string name_input(const std::string& path, const char* label,
                                         bool inherit = false) const {
        return input(path, label, "text",
                     " maxlength=\"" + std::to_string(kDexPolicyMaxNameBytes) + "\"", inherit);
    }

    /// The edges, names, weights and (override or global) model fields under `base`.
    [[nodiscard]] std::string edges(const std::string& base, bool inherit) const {
        // The validator refuses 0 and 100 (0 < edge < 100) at one decimal, so the extremes a
        // number input may hold are the first tenth above 0 and the last below 100. The
        // attribute is a convenience; the validator decides.
        constexpr double kEdgeMin = 1.0 / kStabilityScoreScale;
        constexpr double kEdgeMax = 100.0 - 1.0 / kStabilityScoreScale;
        std::string o = group_open(base + "tiers.edges", "Score edges",
                                   "Lowest displayed score of each tier, above 0 and below "
                                   "100 at one decimal, strictly descending and at least " +
                                       num(static_cast<double>(kDexPolicyMinTierGapTenths) /
                                           kStabilityScoreScale) +
                                       " apart. Poor is everything below Fair.") +
                        "<div class=\"row2\">";
        o += number(base + "tiers.edges.excellent", "Excellent from", kEdgeMin, kEdgeMax, "0.1", inherit);
        o += number(base + "tiers.edges.good", "Good from", kEdgeMin, kEdgeMax, "0.1", inherit);
        o += number(base + "tiers.edges.fair", "Fair from", kEdgeMin, kEdgeMax, "0.1", inherit);
        return o + "</div>" + group_close(base + "tiers.edges");
    }
    [[nodiscard]] std::string names(const std::string& base, bool inherit) const {
        std::string o = group_open(base + "tiers.names", "Tier names",
                                   "1 to " + std::to_string(kDexPolicyMaxNameBytes) +
                                       " bytes of printable ASCII; none of &lt; &gt; &amp; "
                                       "&quot;.") +
                        "<div class=\"row2\">";
        o += name_input(base + "tiers.names.excellent", "Excellent", inherit);
        o += name_input(base + "tiers.names.good", "Good", inherit);
        o += name_input(base + "tiers.names.fair", "Fair", inherit);
        o += name_input(base + "tiers.names.poor", "Poor", inherit);
        return o + "</div>" + group_close(base + "tiers.names");
    }
    [[nodiscard]] std::string weights(const std::string& base, bool inherit) const {
        std::string o = group_open(base + "weights", "Weights",
                                   "Points deducted from 100 for each factor at its worst; "
                                   "the four sum to at most " + num(kDexPolicyWeightSumMax) +
                                       ".") +
                        "<div class=\"row2\">";
        constexpr double kMax = kDexPolicyWeightSumMax;
        o += number(base + "weights.breadth", "Breadth", 0.0, kMax, "any", inherit);
        o += number(base + "weights.crashes", "Crashes", 0.0, kMax, "any", inherit);
        o += number(base + "weights.hangs", "Hangs", 0.0, kMax, "any", inherit);
        o += number(base + "weights.regression", "Regression", 0.0, kMax, "any", inherit);
        return o + "</div>" + group_close(base + "weights");
    }
    [[nodiscard]] std::string model(const std::string& base, bool global) const {
        const bool inherit = !global;
        std::string o = group_open(base + "model", "Model",
                                   "Per-device event cap 1 to " +
                                       std::to_string(kStabilityMaxPerDeviceEventCap) +
                                       "; the regression ratios 1 to " +
                                       num(kStabilityMaxRegressionRatio) +
                                       " with start below full" +
                                       (global ? "; interval confidence " +
                                                     num(kDexStatsConfidenceMin) + " to " +
                                                     num(kDexStatsConfidenceMax)
                                               : std::string()) +
                                       ".") +
                        "<div class=\"row2\">";
        o += input(base + "model.per_device_event_cap", "Per-device event cap", "number",
                   " min=\"1\" max=\"" + std::to_string(kStabilityMaxPerDeviceEventCap) +
                       "\" step=\"1\"",
                   inherit);
        o += number(base + "model.regression_start_ratio", "Regression starts at ratio", 1.0,
                    kStabilityMaxRegressionRatio, "any", inherit);
        o += number(base + "model.regression_full_ratio", "Regression full at ratio", 1.0,
                    kStabilityMaxRegressionRatio, "any", inherit);
        if (global)
            o += number("model.interval_confidence", "Interval confidence",
                        kDexStatsConfidenceMin, kDexStatsConfidenceMax, "any");
        return o + "</div>" + group_close(base + "model");
    }

    [[nodiscard]] std::string tiers_panel() const {
        return "<section class=\"panel dxs\"><div class=\"hd\"><h2>Tiers</h2></div><div "
               "class=\"pb\">" + edges("", false) + names("", false) + "</div></section>";
    }
    [[nodiscard]] std::string weights_panel() const {
        return "<section class=\"panel dxs\"><div class=\"hd\"><h2>Weights</h2></div><div "
               "class=\"pb\">" + weights("", false) + "</div></section>";
    }
    [[nodiscard]] std::string model_panel() const {
        return "<section class=\"panel dxs\"><div class=\"hd\"><h2>Model</h2></div><div "
               "class=\"pb\">" + model("", true) + "</div></section>";
    }

    [[nodiscard]] std::string override_row(int row, bool blank) const {
        const std::string base = row_key(row, "");
        const std::string field = base.substr(0, base.size() - 1); // no trailing dot
        const std::string& image = val(base + "image");
        const bool open = v_.error && target_.starts_with(field);
        std::string o = "<details class=\"ovr\"" + std::string(open ? " open" : "") +
                        "><summary>" + (blank ? std::string("New application override")
                                              : esc(image)) + "</summary>";
        o += "<fieldset class=\"grp\" data-field=\"" + field + "\"";
        if (v_.error && field == target_)
            o += " data-invalid=\"1\"";
        o += ">";
        o += input(base + "image", "Application image name", "text",
                   " maxlength=\"" + std::to_string(kDexPolicyMaxKeyBytes) + "\"" +
                       (v_.suggestions.empty() ? std::string() : " list=\"dxs-apps\""));
        if (!blank)
            o += "<label class=\"chk\"><input type=\"checkbox\" name=\"" + base +
                 "remove\" value=\"on\"" + (val(base + "remove") == "on" ? " checked" : "") +
                 dis() + "> Remove this override</label>";
        o += "<p class=\"hint\">Leave a field blank to inherit the global value.</p>";
        o += edges(base, true) + names(base, true) + weights(base, true) + model(base, false);
        return o + err(field) + "</fieldset></details>";
    }

    [[nodiscard]] std::string overrides_panel() const {
        // A refusal re-renders the POSTED rows, and a hand-made body can name thousands of them
        // (each a collapsed section of ~40 controls). Only rows the form could ever accept are
        // drawn: an index within kDexFormMaxOverrideIndex and at most kDexPolicyMaxOverrides of
        // them. dex_form_to_document refuses a form with more, whole, so nothing drawn is lost.
        const auto posted = override_rows(v_.values);
        std::vector<int> rows;
        for (const int r : posted) {
            if (r > kDexFormMaxOverrideIndex || rows.size() >= kDexPolicyMaxOverrides)
                break;
            rows.push_back(r);
        }
        const std::size_t hidden = posted.size() - rows.size();
        std::string o = "<section class=\"panel dxs\"><div class=\"hd\"><h2>Application "
                        "overrides</h2></div><div class=\"pb\">" +
                        group_open("overrides", "Per-application policy",
                                   "An override is keyed by the exact image name (case is "
                                   "ignored) and replaces only the fields it sets. At most " +
                                       std::to_string(kDexPolicyMaxOverrides) + " overrides; " +
                                       std::to_string(rows.size()) + " in use.");
        if (!v_.suggestions.empty()) {
            o += "<datalist id=\"dxs-apps\">";
            for (const auto& s : v_.suggestions)
                o += "<option value=\"" + esc(s) + "\">";
            o += "</datalist>";
        }
        for (const int r : rows)
            o += override_row(r, false);
        if (hidden > 0)
            o += "<p class=\"hint\" data-hidden=\"" + std::to_string(hidden) + "\">" +
                 std::to_string(hidden) + " more submitted override rows are not shown: the "
                 "form carries more than " + std::to_string(kDexPolicyMaxOverrides) +
                 " rows or a row above " + std::to_string(kDexFormMaxOverrideIndex) +
                 ", and is refused until they are removed.</p>";
        const int next = rows.empty() ? 0 : rows.back() + 1;
        if (hidden == 0 && rows.size() < kDexPolicyMaxOverrides && next <= kDexFormMaxOverrideIndex)
            o += override_row(next, true);
        else if (rows.size() >= kDexPolicyMaxOverrides)
            o += "<p class=\"hint\" data-limit=\"reached\">The limit of " +
                 std::to_string(kDexPolicyMaxOverrides) +
                 " overrides is reached; remove one to add another.</p>";
        return o + group_close("overrides") + "</div></section>";
    }

    [[nodiscard]] std::string buttons() const {
        return std::string("<div class=\"btns\"><button type=\"submit\" class=\"btn\"") + dis() +
               ">Save</button><button type=\"button\" class=\"btn btn-secondary\" "
               "hx-post=\"/api/settings/dex-scoring/preview\" hx-target=\"#dex-scoring-section\" "
               "hx-swap=\"innerHTML\"" + dis() +
               ">Preview tier changes</button><button type=\"button\" class=\"btn "
               "btn-secondary\" hx-post=\"/api/settings/dex-scoring/reset\" "
               "hx-target=\"#dex-scoring-section\" hx-swap=\"innerHTML\" "
               "hx-confirm=\"Reset the score policy to the shipped defaults? Every override is "
               "removed.\"" + dis() + ">Reset to defaults</button></div>";
    }

    [[nodiscard]] std::string preview() const {
        if (!v_.preview)
            return {};
        const auto& p = *v_.preview;
        std::string o = "<section class=\"panel dxs\" data-preview=\"1\"><div class=\"hd\"><h2>"
                        "Tier changes</h2></div><div class=\"pb\">";
        if (p.degraded)
            return o + "<p>Preview unavailable: the applications could not be scored under both "
                       "policies right now. Nothing was saved.</p></div></section>";
        o += "<p>" + std::to_string(p.changed) + " of " + std::to_string(p.total) +
             " applications change tier. Preview only: nothing was saved.</p>";
        // The model holds only the applications affecting most devices, so say what this covers.
        o += "<p class=\"hint\" data-scope=\"1\">Based on the " + std::to_string(p.total) +
             " applications affecting most devices, last 7 days, all platforms.";
        if (p.apps_truncated && p.apps_total > p.total)
            o += " " + std::to_string(p.apps_total - p.total) + " more were not scored.";
        o += "</p>";
        if (!p.rows.empty()) {
            o += "<table class=\"tbl\"><thead><tr><th>Application</th><th>Now</th><th>Would "
                 "be</th></tr></thead><tbody>";
            for (const auto& r : p.rows)
                o += "<tr><td>" + esc(r.subject) + "</td><td>" + esc(r.from) + "</td><td>" +
                     esc(r.to) + "</td></tr>";
            o += "</tbody></table>";
            if (p.changed > static_cast<std::int64_t>(p.rows.size()))
                o += "<p class=\"hint\">The first " + std::to_string(p.rows.size()) +
                     " are shown.</p>";
        }
        return o + "</div></section>";
    }
};

} // namespace dex_form_detail

/// The Scoring tab's section BODY (no wrapper id: the GET handler adds
/// `<div id="dex-scoring-section">`, and every POST answers this body, swapped innerHTML).
/// The error mark lands on the input or group named by error->field; a field the form has no
/// element for marks the document, so a refusal is never silent.
[[nodiscard]] inline std::string render_dex_scoring_section(const DexScoringView& v) {
    using dex_form_detail::Renderer;
    std::string out = Renderer(v, v.error ? v.error->field : std::string()).run();
    if (v.error && out.find("class=\"err\"") == std::string::npos)
        out = Renderer(v, "document").run();
    return out;
}

} // namespace yuzu::server
