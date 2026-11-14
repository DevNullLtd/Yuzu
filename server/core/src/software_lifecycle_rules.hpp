#pragma once

/// @file software_lifecycle_rules.hpp
/// The pure model behind software lifecycle state (SAM-23): the rule and declared-fact types, the
/// strict CSV parser for rule files, and the evaluator that resolves one (product key, version)
/// to a lifecycle state with its source. No store, no libpq, no clock: the store
/// (`software_lifecycle_store.hpp`) supplies rows and the caller supplies `today` and `now`.
///
/// Keys: `product:<ProductRow::norm_key>` for a software title and `os:<distro_id>` (Linux,
/// version = the distro version) or `os:windows` / `os:macos` (version = the OS version) for an
/// operating system; see `product_lifecycle_key` and `os_lifecycle_key`.
///
/// Sources and precedence (highest first): `declared` (a fact a host reported about itself),
/// `external`, `imported`, `shipped` (the build-embedded seed). A declared fact counts in the top
/// tier only while some host repeated it inside the stale window; it is global, never one row per
/// host. Per event (`end_of_support`, `end_of_life`):
///   1. CURRENT declared facts (`last_seen >= now - stale_window`). The EARLIEST current date
///      wins. More than one current date is a disagreement between hosts right now: `conflict`.
///   2. Otherwise the best rule per source tier, `external` > `imported` > `shipped`. Inside a
///      tier the longest dot-component version prefix wins (`3.8` matches `3.8.10`, not `3.80`;
///      the empty prefix matches every version).
///   3. Otherwise the newest STALE declared fact (greatest `last_seen`, ties to the earliest
///      date): a declaration no host repeats sits below every rule and, with no rule, wins as
///      `unconfirmed`.
/// A corrected date therefore replaces the old one once the old one is stale: the store keeps
/// both rows and this evaluator decides. A lower tier that took part with a different date raises
/// `conflict` and is listed in `conflicting_sources`; a superseded stale fact never does.
///
/// State: `end_of_life` date <= today -> `end_of_life`; else `end_of_support` date <= today ->
/// `end_of_support`; else any resolved date -> `supported`; no date at all -> `unknown`, never
/// `supported`. Dates are `YYYY-MM-DD` text, compared lexicographically.

#include "model_param_helpers.hpp"
#include "utf8_sanitize.hpp"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <set>
#include <span>
#include <string>
#include <string_view>
#include <tuple>
#include <vector>

namespace yuzu::server {

enum class LifecycleEvent { end_of_support, end_of_life };

/// Declaration order IS the precedence (declared first). Do not reorder.
enum class LifecycleSource { declared, external, imported, shipped };

enum class LifecycleState { supported, end_of_support, end_of_life, unknown };

/// `unconfirmed` = the winning date is a declared fact no host has repeated inside the stale
/// window.
enum class LifecycleStatus { current, unconfirmed };

inline constexpr std::size_t kLifecycleCsvMaxBytes = 256 * 1024;
inline constexpr std::size_t kLifecycleCsvMaxRows = 5000;
inline constexpr std::size_t kLifecycleFieldMaxBytes = 256;
inline constexpr std::string_view kLifecycleCsvHeader =
    "product_key,version_prefix,event,date,source_reference";

/// Build-embedded seed (content/software-lifecycle/rules.csv), source `shipped`.
extern const std::string_view kSoftwareLifecycleSeed;

[[nodiscard]] constexpr std::string_view to_string(LifecycleEvent e) noexcept {
    return e == LifecycleEvent::end_of_support ? "end_of_support" : "end_of_life";
}
[[nodiscard]] constexpr std::string_view to_string(LifecycleSource s) noexcept {
    switch (s) {
    case LifecycleSource::declared:
        return "declared";
    case LifecycleSource::external:
        return "external";
    case LifecycleSource::imported:
        return "imported";
    case LifecycleSource::shipped:
        return "shipped";
    }
    return "shipped";
}
[[nodiscard]] constexpr std::string_view to_string(LifecycleState s) noexcept {
    switch (s) {
    case LifecycleState::supported:
        return "supported";
    case LifecycleState::end_of_support:
        return "end_of_support";
    case LifecycleState::end_of_life:
        return "end_of_life";
    case LifecycleState::unknown:
        return "unknown";
    }
    return "unknown";
}
[[nodiscard]] constexpr std::string_view to_string(LifecycleStatus s) noexcept {
    return s == LifecycleStatus::current ? "current" : "unconfirmed";
}

[[nodiscard]] inline std::optional<LifecycleEvent> parse_lifecycle_event(std::string_view s) {
    if (s == "end_of_support")
        return LifecycleEvent::end_of_support;
    if (s == "end_of_life")
        return LifecycleEvent::end_of_life;
    return std::nullopt;
}
[[nodiscard]] inline std::optional<LifecycleSource> parse_lifecycle_source(std::string_view s) {
    for (const auto v : {LifecycleSource::declared, LifecycleSource::external,
                         LifecycleSource::imported, LifecycleSource::shipped})
        if (s == to_string(v))
            return v;
    return std::nullopt;
}

/// A strict calendar date `YYYY-MM-DD`, year 1970..2999, real month and day (leap years honoured).
[[nodiscard]] inline bool is_lifecycle_date(std::string_view d) noexcept {
    if (d.size() != 10 || d[4] != '-' || d[7] != '-')
        return false;
    int v[3] = {0, 0, 0};
    constexpr std::array<std::pair<std::size_t, std::size_t>, 3> kParts{{{0, 4}, {5, 2}, {8, 2}}};
    for (std::size_t i = 0; i < kParts.size(); ++i)
        for (std::size_t k = 0; k < kParts[i].second; ++k) {
            const char c = d[kParts[i].first + k];
            if (c < '0' || c > '9')
                return false;
            v[i] = v[i] * 10 + (c - '0');
        }
    return v[0] >= 1970 && v[0] <= 2999 &&
           std::chrono::year_month_day{std::chrono::year{v[0]},
                                       std::chrono::month{static_cast<unsigned>(v[1])},
                                       std::chrono::day{static_cast<unsigned>(v[2])}}
               .ok();
}

/// One shipped, external or imported rule: from `date`, versions of `product_key` that start with
/// the dot-component `version_prefix` are past `event`. `source_ref` names the public policy.
struct LifecycleRule {
    std::string product_key;
    std::string version_prefix; ///< "" = every version
    LifecycleEvent event{LifecycleEvent::end_of_life};
    std::string date; ///< YYYY-MM-DD
    LifecycleSource source{LifecycleSource::shipped};
    std::string source_ref;
    std::int64_t loaded_at{0};
    bool operator==(const LifecycleRule&) const = default;
};

/// A date a host reported about one exact (product_key, version). Global, never per host.
struct DeclaredFact {
    std::string product_key;
    std::string version;
    LifecycleEvent event{LifecycleEvent::end_of_life};
    std::string date; ///< YYYY-MM-DD
    std::int64_t last_seen{0}; ///< epoch seconds a host last repeated it
    bool operator==(const DeclaredFact&) const = default;
};

namespace lifecycle_detail {

/// Printable text: no control byte (NUL, tab, CR, DEL included), valid UTF-8, within the field cap.
[[nodiscard]] inline bool text_ok(std::string_view s) noexcept {
    if (s.size() > kLifecycleFieldMaxBytes)
        return false;
    for (const char c : s)
        if (static_cast<unsigned char>(c) < 0x20 || c == 0x7f)
            return false;
    return sanitize_utf8_strict(s) == s;
}

} // namespace lifecycle_detail

/// First defect of a rule, or nullopt. The store and the CSV parser share this one check.
[[nodiscard]] inline std::optional<std::string> validate_lifecycle_rule(const LifecycleRule& r) {
    using lifecycle_detail::text_ok;
    if (r.product_key.empty() || !text_ok(r.product_key))
        return "product_key is empty, too long or not printable text";
    if (!text_ok(r.version_prefix) || r.version_prefix.starts_with('.') ||
        r.version_prefix.ends_with('.'))
        return "version_prefix is too long, not printable text, or starts or ends with a dot";
    if (!text_ok(r.source_ref))
        return "source_reference is too long or not printable text";
    if (!is_lifecycle_date(r.date))
        return "date is not a calendar date YYYY-MM-DD";
    if (r.source == LifecycleSource::declared)
        return "a rule cannot have the declared source";
    return std::nullopt;
}

[[nodiscard]] inline std::optional<std::string> validate_declared_fact(const DeclaredFact& f) {
    using lifecycle_detail::text_ok;
    if (f.product_key.empty() || !text_ok(f.product_key))
        return "product_key is empty, too long or not printable text";
    if (f.version.empty() || !text_ok(f.version))
        return "version is empty, too long or not printable text";
    if (!is_lifecycle_date(f.date))
        return "date is not a calendar date YYYY-MM-DD";
    if (f.last_seen < 0)
        return "last_seen is negative";
    return std::nullopt;
}

/// First defect of a lookup (product key and installed version), or nullopt. The version may be
/// empty: only a rule with an empty prefix matches it.
[[nodiscard]] inline std::optional<std::string>
validate_lifecycle_lookup(std::string_view product_key, std::string_view version) {
    using lifecycle_detail::text_ok;
    if (product_key.empty() || !text_ok(product_key))
        return "product_key is empty, too long or not printable text";
    if (!text_ok(version))
        return "version is too long or not printable text";
    return std::nullopt;
}

/// Parse a rule file. `#` lines and blank lines are skipped; the first other line must be
/// `kLifecycleCsvHeader`; fields are plain comma-separated text (no quoting, so no field holds a
/// comma). The whole file is refused on the first defect: over 256 KiB, over 5000 rows, a field
/// over 256 bytes, a control byte, invalid UTF-8, a non-calendar date, an event outside
/// {end_of_support,end_of_life}, a wrong column count, or a repeated
/// (product_key, version_prefix, event).
[[nodiscard]] inline std::expected<std::vector<LifecycleRule>, std::string>
parse_lifecycle_rules_csv(std::string_view text, LifecycleSource source) {
    if (text.size() > kLifecycleCsvMaxBytes)
        return std::unexpected("file exceeds " + std::to_string(kLifecycleCsvMaxBytes) + " bytes");
    std::vector<LifecycleRule> out;
    std::set<std::tuple<std::string, std::string, LifecycleEvent>> seen;
    bool header_seen = false;
    std::size_t line_no = 0;
    while (!text.empty()) {
        const auto nl = text.find('\n');
        std::string_view line = text.substr(0, nl);
        text = nl == std::string_view::npos ? std::string_view{} : text.substr(nl + 1);
        ++line_no;
        if (line.ends_with('\r'))
            line.remove_suffix(1);
        if (line.empty() || line.front() == '#')
            continue;
        const auto fail = [&](std::string_view why) {
            return std::unexpected("line " + std::to_string(line_no) + ": " + std::string{why});
        };
        if (!header_seen) {
            if (line != kLifecycleCsvHeader)
                return fail("header must be " + std::string{kLifecycleCsvHeader});
            header_seen = true;
            continue;
        }
        const auto f = model_detail::split(line, ',');
        if (f.size() != 5)
            return fail("expected 5 columns");
        const auto ev = parse_lifecycle_event(f[2]);
        if (!ev)
            return fail("event must be end_of_support or end_of_life");
        LifecycleRule r{std::string{f[0]}, std::string{f[1]}, *ev, std::string{f[3]}, source,
                        std::string{f[4]}, 0};
        if (const auto bad = validate_lifecycle_rule(r))
            return fail(*bad);
        if (out.size() >= kLifecycleCsvMaxRows)
            return fail("more than " + std::to_string(kLifecycleCsvMaxRows) + " rows");
        if (!seen.emplace(r.product_key, r.version_prefix, r.event).second)
            return fail("duplicate (product_key, version_prefix, event)");
        out.push_back(std::move(r));
    }
    if (!header_seen)
        return std::unexpected("no header line");
    return out;
}

/// `product:<norm_key>`; "" for an empty norm_key (no identity, no lifecycle lookup).
[[nodiscard]] inline std::string product_lifecycle_key(std::string_view norm_key) {
    return norm_key.empty() ? std::string{} : "product:" + std::string{norm_key};
}

/// The lifecycle key of an operating system: `os:<distro_id>` on Linux, `os:windows`,
/// `os:macos`; "" when the family or Linux distro id is unknown.
[[nodiscard]] inline std::string os_lifecycle_key(std::string_view os_family,
                                                  std::string_view distro_id) {
    const auto lower = [](std::string_view s) {
        std::string o{s};
        for (auto& c : o)
            c = static_cast<char>(c >= 'A' && c <= 'Z' ? c - 'A' + 'a' : c);
        return o;
    };
    const std::string fam = lower(os_family);
    if (fam == "windows" || fam == "macos")
        return "os:" + fam;
    if (fam == "linux" && !distro_id.empty())
        return "os:" + lower(distro_id);
    return {};
}

/// `prefix` is a dot-component prefix of `version`: "" matches all, "3.8" matches "3.8" and
/// "3.8.10" but not "3.80".
[[nodiscard]] inline bool lifecycle_prefix_matches(std::string_view prefix,
                                                   std::string_view version) noexcept {
    if (prefix.empty())
        return true;
    return version.starts_with(prefix) &&
           (version.size() == prefix.size() || version[prefix.size()] == '.');
}

/// The resolved date of one event and where it came from. `source_ref` is empty for `declared`.
struct LifecycleEventResult {
    std::string date;
    LifecycleSource source{LifecycleSource::shipped};
    std::string source_ref;
    bool operator==(const LifecycleEventResult&) const = default;
};

struct LifecycleEvaluation {
    LifecycleState state{LifecycleState::unknown};
    std::optional<LifecycleEventResult> end_of_support;
    std::optional<LifecycleEventResult> end_of_life;
    /// The reference of the event that set `state` (for `supported`: end_of_support if resolved,
    /// else end_of_life); empty for `unknown` and for a declared winner.
    std::string source_ref;
    bool conflict{false};
    /// Sources whose date differs from the winner's, in precedence order; `declared` also appears
    /// when current declared facts disagree among themselves.
    std::vector<LifecycleSource> conflicting_sources;
    LifecycleStatus status{LifecycleStatus::current};
    /// Always false until a collector reports host-declared dates (source (a) has none yet).
    bool declared_collected{false};
    bool operator==(const LifecycleEvaluation&) const = default;
};

namespace lifecycle_detail {

struct EventOutcome {
    std::optional<LifecycleEventResult> result;
    bool unconfirmed{false};
    bool conflict{false};
    std::set<LifecycleSource> losers;
};

[[nodiscard]] inline EventOutcome resolve_event(LifecycleEvent ev, std::string_view key,
                                                std::string_view version,
                                                std::span<const LifecycleRule> rules,
                                                std::span<const DeclaredFact> declared,
                                                std::int64_t now_secs,
                                                std::int64_t stale_window_secs) {
    const std::int64_t cutoff = now_secs - stale_window_secs;
    std::vector<const DeclaredFact*> current;
    const DeclaredFact* stale = nullptr;
    for (const auto& f : declared) {
        if (f.event != ev || f.product_key != key || f.version != version)
            continue;
        if (f.last_seen >= cutoff)
            current.push_back(&f);
        else if (!stale || f.last_seen > stale->last_seen ||
                 (f.last_seen == stale->last_seen && f.date < stale->date))
            stale = &f;
    }
    // Best rule per source tier: external, imported, shipped (index = source - 1).
    std::array<const LifecycleRule*, 3> best{};
    for (const auto& r : rules) {
        if (r.event != ev || r.source == LifecycleSource::declared || r.product_key != key ||
            !lifecycle_prefix_matches(r.version_prefix, version))
            continue;
        const LifecycleRule*& b = best[static_cast<std::size_t>(r.source) - 1];
        if (!b || r.version_prefix.size() > b->version_prefix.size() ||
            (r.version_prefix.size() == b->version_prefix.size() && r.date < b->date))
            b = &r;
    }

    EventOutcome out;
    const auto rule_result = [](const LifecycleRule& r) {
        return LifecycleEventResult{r.date, r.source, r.source_ref};
    };
    if (!current.empty()) {
        const auto earliest = *std::min_element(
            current.begin(), current.end(),
            [](const DeclaredFact* a, const DeclaredFact* b) { return a->date < b->date; });
        out.result = LifecycleEventResult{earliest->date, LifecycleSource::declared, {}};
        for (const auto* f : current)
            if (f->date != earliest->date)
                out.losers.insert(LifecycleSource::declared);
    } else if (const auto it = std::find_if(best.begin(), best.end(),
                                            [](const LifecycleRule* r) { return r != nullptr; });
               it != best.end()) {
        out.result = rule_result(**it);
    } else if (stale) {
        out.result = LifecycleEventResult{stale->date, LifecycleSource::declared, {}};
        out.unconfirmed = true;
        return out; // nothing else took part
    } else {
        return out;
    }
    for (const auto* r : best)
        if (r && r->date != out.result->date)
            out.losers.insert(r->source);
    out.conflict = !out.losers.empty();
    return out;
}

} // namespace lifecycle_detail

/// Resolve one (product_key, version) against the rules and declared facts the caller loaded.
/// `today` MUST be a valid `YYYY-MM-DD` (`is_lifecycle_date`); `now_secs` is the evaluation
/// instant and `stale_window_secs` the window a declared fact stays current after `last_seen`.
[[nodiscard]] inline LifecycleEvaluation
evaluate_lifecycle(std::string_view product_key, std::string_view version,
                   std::span<const LifecycleRule> rules, std::span<const DeclaredFact> declared,
                   std::string_view today, std::int64_t now_secs, std::int64_t stale_window_secs) {
    auto eos = lifecycle_detail::resolve_event(LifecycleEvent::end_of_support, product_key, version,
                                               rules, declared, now_secs, stale_window_secs);
    auto eol = lifecycle_detail::resolve_event(LifecycleEvent::end_of_life, product_key, version,
                                               rules, declared, now_secs, stale_window_secs);
    LifecycleEvaluation out;
    out.conflict = eos.conflict || eol.conflict;
    eos.losers.merge(eol.losers);
    out.conflicting_sources.assign(eos.losers.begin(), eos.losers.end());
    if (eos.unconfirmed || eol.unconfirmed)
        out.status = LifecycleStatus::unconfirmed;
    out.end_of_support = std::move(eos.result);
    out.end_of_life = std::move(eol.result);

    const LifecycleEventResult* set_by = nullptr;
    if (out.end_of_life && out.end_of_life->date <= today) {
        out.state = LifecycleState::end_of_life;
        set_by = &*out.end_of_life;
    } else if (out.end_of_support && out.end_of_support->date <= today) {
        out.state = LifecycleState::end_of_support;
        set_by = &*out.end_of_support;
    } else if (out.end_of_support || out.end_of_life) {
        out.state = LifecycleState::supported;
        set_by = out.end_of_support ? &*out.end_of_support : &*out.end_of_life;
    }
    if (set_by)
        out.source_ref = set_by->source_ref;
    return out;
}

} // namespace yuzu::server
