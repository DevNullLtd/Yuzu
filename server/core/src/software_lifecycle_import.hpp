#pragma once

/// @file software_lifecycle_import.hpp
/// The pure parsers behind the lifecycle rule import (SAM.7): a body in one of the supported
/// formats becomes a list of `LifecycleRule`s with source `imported`. No store, no HTTP, no clock.
/// The routes own the endpoint, the gate, the audit and the HTTP body cap; this file owns what a
/// body means.
///
/// FORMATS
///   csv      the rule-file grammar of `parse_lifecycle_rules_csv` (software_lifecycle_rules.hpp),
///            unchanged, with its own 256 KiB and 5,000-row limits. Each rule's `source_ref` is
///            overwritten with the caller's `source_reference`.
///   cle      Common Lifecycle Enumeration, ECMA-428 1st edition (December 2025), schema version
///            1.0.0. Schema: https://tc54.org/schemas/cle/cle-1.0.0.schema.json (retrieved
///            2026-11-16; Draft 2020-12). Specification source: https://github.com/Ecma-TC54/ECMA-428
///            (the `$schema` of a document is the pinned version; any other value is refused).
///
/// NOT A FORMAT: OpenEoX (OASIS). Its published core document holds dates only (no product,
/// vendor or version), so it cannot key a rule; the evidence and the follow-up are in #8000.
///
/// WHAT A CLE DOCUMENT BECOMES (the rule model matches by dot-component PREFIX, so an exact version
/// or a range cannot be stored without claiming other versions: `3.8` would also match `3.8.10`)
///   * Only `endOfSupport` and `endOfLife` events map (to `end_of_support` / `end_of_life`). Every
///     other event type is counted in `skipped` as `unmapped_event_type`.
///   * Each `versions[].range` is a `vers:` range (the grammar `vers_range.hpp` owns; the scheme is
///     irrelevant to the classification and is not checked). `vers:<scheme>/*` is the whole product:
///     one rule with the EMPTY version prefix. A range of only `=` constraints names exact versions
///     (`exact_version`); anything else is a `version_range`. Both are counted, never stored.
///   * The key is `product_lifecycle_key(norm_key(name, namespace))` of each PURL in `identifier`
///     (a string or an array of at most `kLifecycleCsvMaxRows` aliases); aliases that normalise to
///     the same key collapse, uncounted. A PURL whose name has no title token (`pkg:npm/2019`,
///     `pkg:generic/x64`) identifies nothing and yields no key. Every alias that yields no key is
///     counted as `empty_key`, once per mapped (endOfSupport / endOfLife) active event whatever its
///     versions; a distinct key the rule model refuses (too long, not printable) is counted as
///     `invalid_key` once per whole-product event. Each distinct key is judged once, where the keys
///     are built, so the parse stays linear in the body.
///   * `effective` gives the date: the `YYYY-MM-DD` part of the timestamp, validated by
///     `is_lifecycle_date`.
///   * `withdrawn` events are applied as the specification says (the referenced event is ignored as
///     if it never existed, and a withdrawn withdrawal restores it); neither is counted.
///
/// All-or-nothing refusals (no rules, a caller-facing reason): body over `kImportMaxBytes`, a
/// `source_reference` the rule model refuses, invalid UTF-8, JSON nesting or value count over the
/// budget, invalid JSON, a spec version other than the pinned one, a required field missing or of
/// the wrong type, a malformed `vers:` range, an `identifier` array of more than
/// `kLifecycleCsvMaxRows` aliases, two rules with the same (product_key, event), more than
/// `kLifecycleCsvMaxRows` rules, and any csv defect.

#include "json_value_budget.hpp"
#include "mcp_jsonrpc.hpp" // mcp::json_exceeds_depth / kMcpMaxJsonDepth: the shared depth guard
#include "product_normalize.hpp"
#include "software_lifecycle_rules.hpp"
#include "vers_range.hpp"

#include <nlohmann/json.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace yuzu::server::lifecycle_import {

inline constexpr std::size_t kImportMaxBytes = 4 * 1024 * 1024;

enum class Format { csv, cle };

struct ImportError {
    std::string reason;
};

struct Skipped {
    std::string reason;
    std::size_t count{0};
};

struct Parsed {
    std::vector<LifecycleRule> rules;
    std::vector<Skipped> skipped;
    std::string spec_version;
};

[[nodiscard]] inline std::optional<Format> parse_format(std::string_view token) {
    if (token == "csv")
        return Format::csv;
    if (token == "cle")
        return Format::cle;
    return std::nullopt;
}

namespace detail {

inline constexpr std::string_view kCleSchemaUri =
    "https://tc54.org/schemas/cle/cle-1.0.0.schema.json";
inline constexpr std::string_view kCleSpecVersion = "1.0.0";
/// Structural values (`[`, `{`, `,`) a JSON body may hold: about 20 MB of parse tree at the
/// measured 100 bytes a value, and ten times what 5,000 rules need.
inline constexpr std::size_t kJsonMaxValues = 200'000;

inline constexpr std::string_view kExactVersion = "exact_version";
inline constexpr std::string_view kVersionRange = "version_range";
inline constexpr std::string_view kUnmappedEventType = "unmapped_event_type";
inline constexpr std::string_view kEmptyKey = "empty_key";
inline constexpr std::string_view kInvalidKey = "invalid_key";

using Refusal = std::unexpected<ImportError>;

[[nodiscard]] inline Refusal refuse(std::string reason) {
    return std::unexpected(ImportError{std::move(reason)});
}

/// Skip counts grouped by reason, in order of first occurrence.
struct SkipTally {
    std::vector<Skipped> items;
    /// Count `n` skips of `reason`; `n == 0` records nothing (no empty row for the reason).
    void add(std::string_view reason, std::size_t n = 1) {
        if (n == 0)
            return;
        const auto it = std::ranges::find_if(items, [&](const Skipped& s) { return s.reason == reason; });
        if (it == items.end())
            items.push_back({std::string{reason}, n});
        else
            it->count += n;
    }
};

[[nodiscard]] inline std::optional<std::string> percent_decode(std::string_view in) {
    const auto hex = [](char c) -> int {
        if (c >= '0' && c <= '9')
            return c - '0';
        if (c >= 'a' && c <= 'f')
            return c - 'a' + 10;
        if (c >= 'A' && c <= 'F')
            return c - 'A' + 10;
        return -1;
    };
    std::string out;
    out.reserve(in.size());
    for (std::size_t i = 0; i < in.size(); ++i) {
        if (in[i] != '%') {
            out.push_back(in[i]);
            continue;
        }
        if (i + 2 >= in.size())
            return std::nullopt;
        const int hi = hex(in[i + 1]);
        const int lo = hex(in[i + 2]);
        if (hi < 0 || lo < 0)
            return std::nullopt;
        out.push_back(static_cast<char>(hi * 16 + lo));
        i += 2;
    }
    return out;
}

/// `pkg:<type>/<namespace...>/<name>[@version][?qualifiers][#subpath]` -> (name, namespace), both
/// percent-decoded; nullopt for anything that is not a PURL with a type and a name.
[[nodiscard]] inline std::optional<std::pair<std::string, std::string>>
purl_name_namespace(std::string_view purl) {
    if (!purl.starts_with("pkg:"))
        return std::nullopt;
    purl.remove_prefix(4);
    if (const auto h = purl.find('#'); h != std::string_view::npos)
        purl = purl.substr(0, h);
    if (const auto q = purl.find('?'); q != std::string_view::npos)
        purl = purl.substr(0, q);
    if (const auto at = purl.rfind('@'); at != std::string_view::npos)
        purl = purl.substr(0, at);
    std::vector<std::string_view> seg;
    while (!purl.empty()) {
        const auto s = purl.find('/');
        if (s != 0)
            seg.push_back(purl.substr(0, s));
        if (s == std::string_view::npos)
            break;
        purl.remove_prefix(s + 1);
    }
    if (seg.size() < 2) // a type and a name
        return std::nullopt;
    auto name = percent_decode(seg.back());
    if (!name || name->empty())
        return std::nullopt;
    std::string ns;
    for (std::size_t i = 1; i + 1 < seg.size(); ++i) {
        auto part = percent_decode(seg[i]);
        if (!part)
            return std::nullopt;
        ns += (ns.empty() ? "" : "/") + *part;
    }
    return std::pair{std::move(*name), std::move(ns)};
}

/// The lifecycle key of one PURL; empty when it is not a PURL or its name has no title token.
/// `norm_key` is never empty (it always carries the `:` separator), so the empty test has to be on
/// the title itself: a name such as "2019" or "x64" identifies nothing (the same rule as
/// `SoftwareTitleDimension`), and must not collapse unrelated PURLs onto the key `product::`.
[[nodiscard]] inline std::string purl_key(std::string_view purl) {
    const auto parts = purl_name_namespace(purl);
    if (!parts || normalize_title(parts->first).title.empty())
        return {};
    return product_lifecycle_key(norm_key(parts->first, parts->second));
}

enum class Span { whole_product, exact_versions, interval };

/// The scheme-neutral prefix a range is rebuilt with, and the constraint bytes that fit after it in
/// `vers::kMaxInputBytes`.
inline constexpr std::string_view kVersGenericPrefix = "vers:generic/";
inline constexpr std::size_t kMaxVersConstraintBytes =
    vers::kMaxInputBytes - kVersGenericPrefix.size();

/// Classify one `vers:<scheme>/<constraints>` text. The scheme does not change the answer, so it is
/// replaced with `generic` for the grammar check (`vers::parse` refuses deb, rpm and unknown
/// schemes by name, which would otherwise refuse a whole file for one such record). The rebuilt
/// text has to pass `vers::parse`'s own size bound, so the constraint text is bounded here by
/// `kMaxVersConstraintBytes`.
[[nodiscard]] inline std::optional<Span> classify_vers(std::string_view text) {
    constexpr std::string_view kPrefix = "vers:";
    if (text.size() > vers::kMaxInputBytes || !text.starts_with(kPrefix))
        return std::nullopt;
    const auto slash = text.find('/', kPrefix.size());
    if (slash == std::string_view::npos || slash == kPrefix.size())
        return std::nullopt;
    const auto scheme = text.substr(kPrefix.size(), slash - kPrefix.size());
    if (std::ranges::any_of(scheme, [](char c) {
            const auto u = static_cast<unsigned char>(c);
            return u <= 0x20 || u == 0x7f;
        }))
        return std::nullopt;
    const auto constraints = text.substr(slash + 1);
    if (constraints.size() > kMaxVersConstraintBytes)
        return std::nullopt;
    const auto range = vers::parse(std::string{kVersGenericPrefix} + std::string{constraints});
    if (!range)
        return std::nullopt;
    if (range->all)
        return Span::whole_product;
    const bool only_eq = std::ranges::all_of(
        range->constraints, [](const vers::Constraint& c) { return c.op == vers::Op::kEq; });
    return only_eq ? Span::exact_versions : Span::interval;
}

/// `YYYY-MM-DD` from an ISO 8601 date-time; nullopt when the date part is not a calendar date.
[[nodiscard]] inline std::optional<std::string> date_of(std::string_view timestamp) {
    if (timestamp.size() < 11 || (timestamp[10] != 'T' && timestamp[10] != 't'))
        return std::nullopt;
    std::string d{timestamp.substr(0, 10)};
    if (!is_lifecycle_date(d))
        return std::nullopt;
    return d;
}

/// A JSON integer >= 1.
[[nodiscard]] inline std::optional<std::uint64_t> positive_id(const nlohmann::json& v) {
    if (v.is_number_unsigned())
        return v.get<std::uint64_t>() >= 1 ? std::optional{v.get<std::uint64_t>()} : std::nullopt;
    if (v.is_number_integer() && v.get<std::int64_t>() >= 1)
        return static_cast<std::uint64_t>(v.get<std::int64_t>());
    return std::nullopt;
}

struct CleEvent {
    std::uint64_t id{0};
    const nlohmann::json* json{nullptr};
    std::string type;
};

[[nodiscard]] inline std::expected<Parsed, ImportError> parse_cle(std::string_view body,
                                                                  std::string_view source_ref) {
    using nlohmann::json;
    if (sanitize_utf8_strict(body) != body)
        return refuse("body is not valid UTF-8");
    if (mcp::json_exceeds_depth(body, mcp::kMcpMaxJsonDepth))
        return refuse("JSON nests deeper than " + std::to_string(mcp::kMcpMaxJsonDepth) +
                      " levels");
    if (json_exceeds_value_count(body, kJsonMaxValues))
        return refuse("JSON holds more than " + std::to_string(kJsonMaxValues) + " values");
    const json doc = json::parse(body, nullptr, /*allow_exceptions=*/false);
    if (doc.is_discarded())
        return refuse("body is not valid JSON");
    if (!doc.is_object())
        return refuse("CLE document must be a JSON object");

    const auto schema = doc.find("$schema");
    if (schema == doc.end() || !schema->is_string())
        return refuse("required field $schema is missing or not a string");
    if (schema->get<std::string>() != kCleSchemaUri)
        return refuse("unsupported CLE spec version: this server reads only " +
                      std::string{kCleSchemaUri});
    const auto updated = doc.find("updatedAt");
    if (updated == doc.end() || !updated->is_string())
        return refuse("required field updatedAt is missing or not a string");

    // identifier: a PURL string or a non-empty array of at most kLifecycleCsvMaxRows PURL strings.
    // Every alias is judged once, here, so the work per event below never grows with the alias
    // count: the rule model's verdict on a key depends on the key alone (the date comes from
    // date_of, the source_reference was checked by parse()).
    const auto ident = doc.find("identifier");
    if (ident == doc.end())
        return refuse("required field identifier is missing");
    std::vector<std::string> keys;    // accepted by the rule model, first-seen order
    std::size_t invalid_keys = 0;     // distinct keys the rule model refuses
    std::size_t unusable_aliases = 0; // aliases that yield no key at all
    {
        std::vector<std::string_view> purls;
        if (ident->is_string())
            purls.push_back(ident->get_ref<const std::string&>());
        else if (ident->is_array() && !ident->empty()) {
            if (ident->size() > kLifecycleCsvMaxRows)
                return refuse("identifier lists more than " + std::to_string(kLifecycleCsvMaxRows) +
                              " aliases");
            for (const auto& a : *ident) {
                if (!a.is_string())
                    return refuse("identifier must hold only strings");
                purls.push_back(a.get_ref<const std::string&>());
            }
        } else
            return refuse("identifier must be a string or a non-empty array of strings");
        LifecycleRule probe{std::string{}, "", LifecycleEvent::end_of_life, "2000-01-01",
                            LifecycleSource::imported, std::string{source_ref}, 0};
        std::set<std::string> seen_keys;
        for (const auto p : purls) {
            auto k = purl_key(p);
            if (k.empty()) {
                ++unusable_aliases;
                continue;
            }
            if (!seen_keys.insert(k).second)
                continue; // aliases that normalise to one key collapse
            probe.product_key = k;
            if (validate_lifecycle_rule(probe))
                ++invalid_keys;
            else
                keys.push_back(std::move(k));
        }
    }

    const auto events_it = doc.find("events");
    if (events_it == doc.end() || !events_it->is_array() || events_it->empty())
        return refuse("required field events is missing, empty or not an array");

    std::vector<CleEvent> events;
    std::set<std::uint64_t> ids;
    events.reserve(events_it->size());
    for (const auto& e : *events_it) {
        if (!e.is_object())
            return refuse("every event must be a JSON object");
        const auto id_it = e.find("id");
        const auto id = id_it == e.end() ? std::nullopt : positive_id(*id_it);
        if (!id)
            return refuse("event id is missing or not an integer of at least 1");
        const std::string at = "event " + std::to_string(*id) + ": ";
        if (!ids.insert(*id).second)
            return refuse(at + "duplicate event id");
        for (const char* f : {"type", "effective", "published"}) {
            const auto it = e.find(f);
            if (it == e.end() || !it->is_string())
                return refuse(at + "required field " + f + " is missing or not a string");
        }
        events.push_back({*id, &e, e.at("type").get<std::string>()});
        if (events.back().type == "withdrawn") {
            const auto w = e.find("eventId");
            const auto target = w == e.end() ? std::nullopt : positive_id(*w);
            if (!target)
                return refuse(at + "required field eventId is missing or not an integer of at least 1");
            if (*target >= *id)
                return refuse(at + "eventId must name an earlier event");
        }
    }

    // Newest first: a withdrawal that was itself withdrawn never existed, so it voids nothing.
    std::ranges::sort(events, [](const CleEvent& a, const CleEvent& b) { return a.id > b.id; });
    std::set<std::uint64_t> voided;
    std::vector<const CleEvent*> active;
    for (const auto& e : events) {
        if (voided.contains(e.id))
            continue;
        if (e.type == "withdrawn")
            voided.insert(positive_id(e.json->at("eventId")).value());
        else
            active.push_back(&e);
    }
    std::ranges::reverse(active); // oldest first: deterministic rule order

    Parsed out;
    out.spec_version = std::string{kCleSpecVersion};
    SkipTally skips;
    std::set<std::pair<std::string, LifecycleEvent>> seen; // the version prefix is always empty
    for (const CleEvent* ev : active) {
        LifecycleEvent kind{};
        if (ev->type == "endOfSupport")
            kind = LifecycleEvent::end_of_support;
        else if (ev->type == "endOfLife")
            kind = LifecycleEvent::end_of_life;
        else {
            skips.add(kUnmappedEventType);
            continue;
        }
        const std::string at = "event " + std::to_string(ev->id) + ": ";
        const auto date = date_of(ev->json->at("effective").get_ref<const std::string&>());
        if (!date)
            return refuse(at + "effective is not an ISO 8601 timestamp with a calendar date");
        const auto vs = ev->json->find("versions");
        if (vs == ev->json->end() || !vs->is_array() || vs->empty())
            return refuse(at + "required field versions is missing, empty or not an array");
        bool whole = false;
        std::size_t exact = 0;
        std::size_t interval = 0;
        for (const auto& v : *vs) {
            const auto r = v.is_object() ? v.find("range") : v.end();
            if (!v.is_object() || r == v.end() || !r->is_string())
                return refuse(at + "every versions entry needs a string range");
            const auto span = classify_vers(r->get_ref<const std::string&>());
            if (!span)
                return refuse(at + "versions range is not a valid vers range (at most " +
                              std::to_string(vers::kMaxConstraints) + " constraints and " +
                              std::to_string(kMaxVersConstraintBytes) + " constraint bytes)");
            switch (*span) {
            case Span::whole_product:
                whole = true;
                break;
            case Span::exact_versions:
                ++exact;
                break;
            case Span::interval:
                ++interval;
                break;
            }
        }
        skips.add(kEmptyKey, unusable_aliases);
        if (keys.empty() && invalid_keys == 0)
            continue; // every alias was unusable: the versions describe no product
        skips.add(kExactVersion, exact);
        skips.add(kVersionRange, interval);
        if (!whole)
            continue;
        skips.add(kInvalidKey, invalid_keys);
        // Each pass stores a rule or refuses the file, so the loop is bounded by the rule cap.
        for (const auto& key : keys) {
            if (!seen.emplace(key, kind).second)
                return refuse(at + "duplicate (product_key, version_prefix, event)");
            if (out.rules.size() >= kLifecycleCsvMaxRows)
                return refuse("more than " + std::to_string(kLifecycleCsvMaxRows) + " rules");
            out.rules.push_back(LifecycleRule{key, "", kind, *date, LifecycleSource::imported,
                                              std::string{source_ref}, 0});
        }
    }
    out.skipped = std::move(skips.items);
    return out;
}

} // namespace detail

/// Parse `body` as `format` into rules of source `imported`, each carrying `source_reference`.
/// All-or-nothing: on any refusal no rule is returned. See the file banner for the contract.
[[nodiscard]] inline std::expected<Parsed, ImportError>
parse(Format format, std::string_view body, std::string_view source_reference) {
    if (body.size() > kImportMaxBytes)
        return detail::refuse("body exceeds " + std::to_string(kImportMaxBytes) + " bytes");
    LifecycleRule probe{"product:x", "", LifecycleEvent::end_of_life, "2000-01-01",
                        LifecycleSource::imported, std::string{source_reference}, 0};
    if (const auto bad = validate_lifecycle_rule(probe))
        return detail::refuse(*bad);
    switch (format) {
    case Format::csv: {
        auto rules = parse_lifecycle_rules_csv(body, LifecycleSource::imported);
        if (!rules)
            return detail::refuse(std::move(rules.error()));
        for (auto& r : *rules)
            r.source_ref = std::string{source_reference};
        return Parsed{std::move(*rules), {}, {}};
    }
    case Format::cle:
        return detail::parse_cle(body, source_reference);
    }
    return detail::refuse("unknown format");
}

} // namespace yuzu::server::lifecycle_import
