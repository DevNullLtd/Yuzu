/**
 * browser_policy_parsers.hpp — the PURE policy-row model for browser_policy.
 *
 * Everything here is a free function over plain data: no OS calls, no file
 * or registry I/O, no logging. It compiles and is unit-tested on EVERY OS
 * (the Linux JSON-file leg feeds PolicyRow/format_policy_row today; the
 * planned Windows registry and macOS plist legs will feed the same model),
 * which is the repo's standing "pure core, thin shell" discipline
 * (peripherals_parsers.hpp is the sibling shape).
 *
 * WIRE ROW (one per configured policy, 9 pipe-delimited fields):
 *
 *   policy|<browser>|<level>|<scope>|<name>|<type>|<value>|<source>|<detail>
 *
 *   browser  chrome | chromium | edge                       (fixed vocabulary)
 *   level    mandatory | recommended                        (fixed vocabulary)
 *   scope    machine | user:<name>                          (<name> untrusted)
 *   name     the policy name exactly as the browser documents it
 *   type     bool | int | real | string | list | dict | null | unmodelled
 *   value    bool "true"/"false"; int/real as decimal text; string verbatim;
 *            list/dict as compact JSON text (see `json_escaped` below); null
 *            "null"; unmodelled "-"
 *   source   the LOGICAL absolute file (or registry key) the policy was read
 *            from, e.g. /etc/opt/chrome/policies/managed/corp.json — never an
 *            injected test root
 *   detail   "-" normally; `json_type` for an `unmodelled` value (the only
 *            unmodelled qualifier emitted today); `json_escaped` for a
 *            list/dict value whose JSON dump contains a backslash (a nested
 *            string held a `"`, `\` or control character) — `safe_output_field`
 *            below folds every literal backslash to `/` before the row is
 *            written, so an escaped list/dict value on the wire is lossy and
 *            not trustworthy as the original JSON (an escaped quote in
 *            particular can make it syntactically invalid, though not every
 *            fold does -- e.g. a folded `\n` still parses); the row still
 *            carries the best-effort (folded) text, never blanked, but
 *            `json_escaped` says not to trust it as JSON;
 *            and `nul_replaced` / `utf8_replaced` / `truncated` (appended,
 *            comma-joined) when any free-text field held an embedded NUL, a
 *            byte that is not valid UTF-8, or more than kMaxFieldBytes
 *
 * Every free-text field goes through yuzu::util::safe_output_field
 * (sdk/include/yuzu/string_utils.hpp): a value ending in a backslash or
 * containing a pipe can never shift the field count on the server decoder
 * (server/core/src/result_parsing.hpp find_unescaped_pipe). The escaper is
 * intentionally lossy (backslash folds to '/'), which is acceptable for an
 * inventory display value. An embedded NUL byte is replaced by U+FFFD and
 * flagged in `detail`: the plugin ABI passes rows as C strings
 * (CommandContext::write_output), so a NUL would otherwise truncate the row
 * before its source/detail fields while still reporting success.
 *
 * VALID UTF-8 ONLY. The command output travels in a protobuf `string` field,
 * and the receiver rejects the WHOLE response if any byte in it is not valid
 * UTF-8. JSON keys and values are validated by the parser, but a Linux file
 * name is arbitrary bytes and lands in `source`, so every free-text field is
 * repaired (repair_utf8: each offending byte becomes U+FFFD, flagged in
 * `detail`) before it is written. Every free-text field is also capped at
 * kMaxFieldBytes (cut on a UTF-8 boundary, BEFORE escaping so a cut can never
 * strand an escape, flagged `truncated`): one policy value can otherwise make a
 * row larger than the server's per-chunk ingest cap, which drops the row's
 * `source` and `detail` fields while the agent still reports a complete read.
 *
 * OUTCOME, IN BAND. A host with no managed policy (browser not installed, no
 * policy files) reports ZERO rows and a clean OK status — an absent policy set
 * is a complete answer, so no placeholder row is written for it. Every other
 * outcome is reported twice: through the typed result status (CC-07) AND as ONE
 * `status` row (format_status_row, written first by the legs.hpp seams): a read
 * that could not be completed is `constrained` with the failure tokens, a
 * PLANNED leg or a leg that threw is `unavailable`. The row exists because the
 * server's response queries (REST, MCP, the dashboard) do not return the typed
 * status today (tracked as #4865; that issue also decides whether these
 * in-band rows are then retired or kept, since the typed status carries no
 * reason tokens), so without it a host that was not inspected, or a read that
 * failed, is indistinguishable from "no policy configured". The outcomes are
 * never conflated: zero rows and no `status` row means the read completed.
 *
 *   status|-|-|-|policies|-|<constrained|unavailable>|-|<reason tokens>
 *
 * TYPE MAPPING. Every JSON value maps into PolicyType (the planned legs' native
 * registry/plist values will map into the same enum), and anything the mapper
 * does not model lands on the literal PolicyType::Unmodelled ("unmodelled") —
 * distinct from no data, so a consumer can tell "policy present, value not
 * representable" from "no such policy".
 *
 * JSON PARSING follows the asset_tags_plugin.cpp:87-109 nlohmann idiom
 * (parse guarded against throwing, `.is_*()` type checks before typed
 * reads) with ONE deliberate override: asset_tags' `catch (...) {}` silently
 * resets to an empty state, which here would make a corrupt policy file read
 * as "no policy configured". A parse failure instead returns a failure token
 * the caller records as CONSTRAINED (ConstraintAccumulator).
 */
#pragma once

#include <yuzu/string_utils.hpp>

#include <nlohmann/json.hpp>

#include <algorithm>
#include <cstddef>
#include <limits>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::browser_policy {

// ── bounds ───────────────────────────────────────────────────────────────

/// A policy file larger than this is a constraint ("oversized"), never a
/// silently truncated (and therefore unparseable) read.
inline constexpr std::size_t kMaxPolicyFileBytes = 1024 * 1024;
/// Total rows one leg emits per run; beyond it the leg records `row_cap`.
inline constexpr std::size_t kMaxPolicyRows = 8192;
/// Total bytes of policy-file content one leg PARSES per run; beyond it the leg
/// records `byte_cap`. The per-file, per-directory and row caps are independent
/// and their product is far too large to be a real bound (thousands of files at
/// the per-file cap), so this is the one that bounds the run's parser input.
/// The file that crosses it has been read (at most one extra file cap) but is
/// not parsed. It is an INPUT bound, not a memory bound: one file's parsed
/// document costs several times its text, and the appended, unescaped row text
/// costs several times that again (a float array dumps `1e14` as
/// `100000000000000.0`; `format_policy_row`'s `+=` chain does not reserve).
/// Measured worst case at this input cap: on the order of one hundred MiB
/// resident, well short of unbounded, but MUCH more than kMaxFieldBytes'
/// per-row cap alone would suggest -- the per-run input bound is what actually
/// keeps this finite. kMaxJsonContainers keeps a `{}`-heavy file, the single
/// most expensive shape, from costing still more per input byte.
inline constexpr std::size_t kMaxPolicyTotalBytes = 16 * 1024 * 1024;
/// Containers (`[` or `{`) one policy file may hold. A parsed container costs
/// roughly thirty times the three bytes of `{}` that describe it, so the file
/// cap alone allows a ~30 MiB document per megabyte of `{}`, on top of what its
/// scalars cost; real policy files hold a few hundred containers. Beyond it the
/// file is `json_too_complex`.
inline constexpr std::size_t kMaxJsonContainers = 65536;
/// Bytes of any one free-text field (name, value, source, detail) before it is
/// cut and flagged `truncated`; five such fields, each expanded at most three-
/// fold by escaping (an all-NUL field, U+FFFD per byte), still land a whole row
/// far below the server's 2 MiB per-chunk ingest cap.
inline constexpr std::size_t kMaxFieldBytes = 64 * 1024;
/// Directory entries examined per directory (walk_dir_capped cap).
inline constexpr std::size_t kMaxEntriesPerDir = 4096;
/// Container nesting the mapper will descend; deeper is a constraint
/// (bounds nlohmann's recursive dump() and the CF recursion alike). The root
/// object counts as the first container, so 32 nested containers parse and a
/// 33rd is `json_too_deep`.
inline constexpr int kMaxNestingDepth = 32;

/// The walk bounds as a parameter so the unit suite can prove the saturation
/// paths (`row_cap`, oversized) at small, machine-independent sizes instead of
/// materializing thousands of files. Production always passes the defaults.
struct WalkLimits {
    std::size_t max_rows = kMaxPolicyRows;
    std::size_t max_entries_per_dir = kMaxEntriesPerDir;
    std::size_t max_file_bytes = kMaxPolicyFileBytes;
    std::size_t max_total_bytes = kMaxPolicyTotalBytes;
};

// ── failure tokens (string literals: `<os>:<detail>`) ────────────────────

inline constexpr std::string_view kTokenJsonUnparseable = "linux:json_unparseable";
inline constexpr std::string_view kTokenJsonNotObject = "linux:json_not_object";
inline constexpr std::string_view kTokenJsonTooDeep = "linux:json_too_deep";
inline constexpr std::string_view kTokenJsonTooComplex = "linux:json_too_complex";

// ── fixed vocabularies ───────────────────────────────────────────────────

enum class Browser { chrome, chromium, edge };
enum class Level { mandatory, recommended };
enum class PolicyType { Bool, Int, Real, String, List, Dict, Null, Unmodelled };

[[nodiscard]] constexpr std::string_view browser_token(Browser b) noexcept {
    switch (b) {
    case Browser::chrome:   return "chrome";
    case Browser::chromium: return "chromium";
    case Browser::edge:     return "edge";
    }
    return "chrome";
}

[[nodiscard]] constexpr std::string_view level_token(Level l) noexcept {
    switch (l) {
    case Level::mandatory:   return "mandatory";
    case Level::recommended: return "recommended";
    }
    return "mandatory";
}

[[nodiscard]] constexpr std::string_view type_token(PolicyType t) noexcept {
    switch (t) {
    case PolicyType::Bool:       return "bool";
    case PolicyType::Int:        return "int";
    case PolicyType::Real:       return "real";
    case PolicyType::String:     return "string";
    case PolicyType::List:       return "list";
    case PolicyType::Dict:       return "dict";
    case PolicyType::Null:       return "null";
    case PolicyType::Unmodelled: return "unmodelled";
    }
    return "unmodelled";
}

// ── the row model ────────────────────────────────────────────────────────

struct PolicyValue {
    PolicyType type = PolicyType::Unmodelled;
    std::string value;  // see the wire-row legend above
    std::string detail; // empty -> "-" on the wire
};

struct PolicyRow {
    Browser browser = Browser::chrome;
    Level level = Level::mandatory;
    std::string scope; // "machine" | "user:<name>"
    std::string name;
    PolicyValue value;
    std::string source;
};

[[nodiscard]] inline std::string machine_scope() { return "machine"; }
[[nodiscard]] inline std::string user_scope(std::string_view user) {
    return "user:" + std::string{user};
}

/// The literal "policy present, value not representable" outcome.
[[nodiscard]] inline PolicyValue unmodelled_value(std::string_view detail) {
    return PolicyValue{PolicyType::Unmodelled, "-", std::string{detail}};
}

namespace detail {
/// Strict UTF-8 repair: copies every well-formed sequence (Unicode Table 3-7:
/// no overlong forms, no surrogates, nothing above U+10FFFF) and replaces each
/// byte that does not begin or continue one with U+FFFD, setting `replaced`.
/// yuzu::util::sanitize_utf8 is deliberately NOT used: it only catches lone and
/// truncated bytes and passes overlong, surrogate and out-of-range sequences,
/// all of which the protobuf transport rejects.
[[nodiscard]] inline std::string repair_utf8(std::string_view s, bool& replaced) {
    const auto in_range = [&s](std::size_t i, unsigned lo, unsigned hi) {
        return i < s.size() && static_cast<unsigned char>(s[i]) >= lo &&
               static_cast<unsigned char>(s[i]) <= hi;
    };
    const auto cont = [&in_range](std::size_t i) { return in_range(i, 0x80, 0xBF); };
    std::string out;
    out.reserve(s.size());
    for (std::size_t i = 0; i < s.size();) {
        const auto c = static_cast<unsigned char>(s[i]);
        std::size_t n = 0; // length of the well-formed sequence starting here; 0 = none
        if (c < 0x80) {
            n = 1;
        } else if (c >= 0xC2 && c <= 0xDF) {
            n = cont(i + 1) ? 2 : 0;
        } else if (c == 0xE0) {
            n = in_range(i + 1, 0xA0, 0xBF) && cont(i + 2) ? 3 : 0;
        } else if (c == 0xED) {
            n = in_range(i + 1, 0x80, 0x9F) && cont(i + 2) ? 3 : 0; // not a surrogate
        } else if (c >= 0xE1 && c <= 0xEF) {
            n = cont(i + 1) && cont(i + 2) ? 3 : 0;
        } else if (c == 0xF0) {
            n = in_range(i + 1, 0x90, 0xBF) && cont(i + 2) && cont(i + 3) ? 4 : 0;
        } else if (c >= 0xF1 && c <= 0xF3) {
            n = cont(i + 1) && cont(i + 2) && cont(i + 3) ? 4 : 0;
        } else if (c == 0xF4) {
            n = in_range(i + 1, 0x80, 0x8F) && cont(i + 2) && cont(i + 3) ? 4 : 0; // <= U+10FFFF
        }
        if (n == 0) {
            out += "\xEF\xBF\xBD";
            replaced = true;
            ++i;
        } else {
            out.append(s.substr(i, n));
            i += n;
        }
    }
    return out;
}

/// What `wire_field` had to change in a field; each becomes a `detail` token.
struct WireFlags {
    bool nul = false;       // an embedded NUL was replaced by U+FFFD
    bool utf8 = false;      // a byte that is not valid UTF-8 was replaced by U+FFFD
    bool truncated = false; // the field held more than kMaxFieldBytes and was cut
};

/// Appends the `detail` tokens for `f` to `det`, comma-joined, in a fixed order.
inline void append_wire_flag_tokens(std::string& det, const WireFlags& f) {
    const auto add = [&det](std::string_view token) {
        if (!det.empty())
            det += ',';
        det += token;
    };
    if (f.nul)
        add("nul_replaced");
    if (f.utf8)
        add("utf8_replaced");
    if (f.truncated)
        add("truncated");
}

/// safe_output_field plus the transport repairs, in this order: every byte that
/// is not valid UTF-8 becomes U+FFFD; a field longer than kMaxFieldBytes is cut
/// on a UTF-8 boundary BEFORE escaping (so a cut can never strand a backslash
/// or half an escape sequence in front of the field separator); the escaper
/// runs; every embedded NUL becomes U+FFFD (see the header notes).
[[nodiscard]] inline std::string wire_field(std::string_view value, WireFlags& flags) {
    std::string repaired = repair_utf8(value, flags.utf8);
    if (repaired.size() > kMaxFieldBytes) {
        std::size_t cut = kMaxFieldBytes;
        // repaired[cut] is the first byte dropped; if it continues a sequence, back up to that
        // sequence's lead byte so the field never ends in half a character.
        while (cut > 0 && (static_cast<unsigned char>(repaired[cut]) & 0xC0) == 0x80)
            --cut;
        repaired.resize(cut);
        flags.truncated = true;
    }
    std::string escaped = yuzu::util::safe_output_field(repaired);
    if (escaped.find('\0') == std::string::npos)
        return escaped;
    std::string out;
    out.reserve(escaped.size() + 8);
    for (char c : escaped) {
        if (c == '\0') {
            out += "\xEF\xBF\xBD";
            flags.nul = true;
        } else {
            out += c;
        }
    }
    return out;
}
} // namespace detail

/// Formats one row (no trailing newline: append_output() adds the separator).
/// The result never contains a NUL byte.
[[nodiscard]] inline std::string format_policy_row(const PolicyRow& r) {
    detail::WireFlags flags;
    std::string out = "policy|";
    out += browser_token(r.browser);
    out += '|';
    out += level_token(r.level);
    out += '|';
    out += detail::wire_field(r.scope, flags);
    out += '|';
    out += detail::wire_field(r.name, flags);
    out += '|';
    out += type_token(r.value.type);
    out += '|';
    out += detail::wire_field(r.value.value, flags);
    out += '|';
    out += detail::wire_field(r.source, flags);
    out += '|';
    std::string det =
        r.value.detail.empty() ? std::string{} : detail::wire_field(r.value.detail, flags);
    detail::append_wire_flag_tokens(det, flags);
    out += det.empty() ? std::string_view{"-"} : std::string_view{det};
    return out;
}

// ── the in-band outcome row ──────────────────────────────────────────────

/// Field 0 of the outcome row (a policy row's field 0 is the literal `policy`).
inline constexpr std::string_view kStatusRowTag = "status";
/// The only action this plugin serves; it is the outcome row's `name` field.
inline constexpr std::string_view kActionName = "policies";
/// `state` values: the typed result status the row repeats, lower-cased.
inline constexpr std::string_view kStateConstrained = "constrained";
inline constexpr std::string_view kStateUnavailable = "unavailable";

/// The ONE in-band outcome row, nine fields wide like a policy row so the
/// definition's columns line up:
///
///   status|-|-|-|policies|-|<state>|-|<reason>
///
/// `state` is `constrained` (a read that could not be completed) or
/// `unavailable` (a planned leg, or a leg that threw); `reason` is the same
/// comma-joined `<os>:<detail>` string the typed result status carries as its
/// provenance. Only ever written when the outcome is NOT a complete read (see
/// the header note). The result never contains a NUL byte.
[[nodiscard]] inline std::string format_status_row(std::string_view state,
                                                   std::string_view reason) {
    detail::WireFlags flags;
    std::string out{kStatusRowTag};
    out += "|-|-|-|";
    out += kActionName;
    out += "|-|";
    out += detail::wire_field(state, flags);
    out += "|-|";
    out += detail::wire_field(reason, flags);
    return out;
}

// ── JSON policy text (Linux managed/recommended files) ───────────────────

namespace detail {
/// Compact dump that can never throw on invalid UTF-8 inside a string value
/// (a hostile or mis-encoded policy file must not abort the leg).
[[nodiscard]] inline std::string dump_json(const nlohmann::json& j) {
    return j.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);
}

/// What one linear pass over a policy file's text finds out about its shape.
struct JsonShape {
    std::size_t depth = 0;      // deepest container nesting
    std::size_t containers = 0; // total `[` and `{`
};

/// The deepest container nesting and the container count in `text`, counted over
/// `[`/`{` outside string literals and outside the `//` and `/* */` comments the
/// parse tolerates. ONE linear pass with no allocation: it replaces nlohmann's
/// parser callback as the depth guard, because the callback parser is QUADRATIC
/// on a wide container of child containers (a 1 MiB `{"a":[{},{},...]}` takes
/// minutes), which is exactly the shape a hostile policy file would use. It must
/// never count LESS nesting than the parser builds (an undercount would let a deep
/// document reach the recursive dump()); the unit suite pins it against nlohmann's
/// own SAX depth. An unterminated string or comment simply ends the scan; the
/// parse that follows reports it as unparseable.
[[nodiscard]] inline JsonShape scan_json_shape(std::string_view text) noexcept {
    JsonShape shape;
    std::size_t depth = 0;
    for (std::size_t i = 0; i < text.size(); ++i) {
        const char c = text[i];
        if (c == '"') {
            for (++i; i < text.size() && text[i] != '"'; ++i) {
                if (text[i] == '\\')
                    ++i; // the escaped character, which may itself be a quote
            }
        } else if (c == '/' && i + 1 < text.size() && text[i + 1] == '/') {
            // nlohmann ends a line comment at LF, CR or NUL (lexer.hpp scan_comment); ending it
            // anywhere later would hide brackets the parser counts, so mirror it exactly.
            i = text.find_first_of(std::string_view{"\n\r\0", 3}, i + 2);
            if (i == std::string_view::npos)
                break;
        } else if (c == '/' && i + 1 < text.size() && text[i + 1] == '*') {
            const auto end = text.find("*/", i + 2);
            if (end == std::string_view::npos)
                break;
            i = end + 1;
        } else if (c == '[' || c == '{') {
            ++shape.containers;
            shape.depth = std::max(shape.depth, ++depth);
        } else if ((c == ']' || c == '}') && depth > 0) {
            --depth;
        }
    }
    return shape;
}

/// The deepest container nesting in `text` (see scan_json_shape).
[[nodiscard]] inline std::size_t max_nesting_depth(std::string_view text) noexcept {
    return scan_json_shape(text).depth;
}
} // namespace detail

/// Maps one parsed JSON value onto the type enum. Total: every nlohmann
/// value type lands on a PolicyType, with Unmodelled as the explicit
/// catch-all (only `binary`/`discarded` reach it — neither can come out of
/// a text parse, so the branch is defensive, not a data-loss path).
[[nodiscard]] inline PolicyValue json_to_policy_value(const nlohmann::json& j) {
    if (j.is_boolean())
        return {PolicyType::Bool, j.get<bool>() ? "true" : "false", {}};
    if (j.is_number_integer()) // signed and unsigned
        return {PolicyType::Int, detail::dump_json(j), {}};
    if (j.is_number_float())
        return {PolicyType::Real, detail::dump_json(j), {}};
    if (j.is_string())
        return {PolicyType::String, j.get<std::string>(), {}};
    if (j.is_array()) {
        std::string raw = detail::dump_json(j);
        const bool escaped = raw.find('\\') != std::string::npos;
        return {PolicyType::List, std::move(raw), escaped ? "json_escaped" : std::string{}};
    }
    if (j.is_object()) {
        std::string raw = detail::dump_json(j);
        const bool escaped = raw.find('\\') != std::string::npos;
        return {PolicyType::Dict, std::move(raw), escaped ? "json_escaped" : std::string{}};
    }
    if (j.is_null())
        return {PolicyType::Null, "null", {}};
    return unmodelled_value("json_type");
}

struct JsonPolicyParse {
    std::vector<PolicyRow> rows;
    /// Set (to one of the kToken* literals) when the text could not be read
    /// as a policy object; `rows` is then empty and the caller MUST record
    /// the failure — never treat it as "no policies".
    std::optional<std::string_view> failure;
};

/// Parses one policy JSON file's text into rows, one per top-level key,
/// sorted by name (nlohmann objects are key-ordered). `//` and block
/// comments are tolerated (Chromium's file policy loader accepts them).
/// Top-level must be an object; nesting deeper than kMaxNestingDepth, or more
/// than kMaxJsonContainers containers, is a constraint, decided by a linear
/// pre-scan BEFORE the parse so a deep or sprawling value is never materialised. At most `max_rows` rows are built (the leg passes the row
/// budget it has left plus one, so a file that would overrun the cap is noticed
/// without first turning every one of its keys into a row).
[[nodiscard]] inline JsonPolicyParse
rows_from_json_policy_text(std::string_view text, Browser browser, Level level,
                           std::string_view scope, std::string_view source,
                           std::size_t max_rows = std::numeric_limits<std::size_t>::max()) {
    JsonPolicyParse out;
    const detail::JsonShape shape = detail::scan_json_shape(text);
    if (shape.depth > static_cast<std::size_t>(kMaxNestingDepth)) {
        out.failure = kTokenJsonTooDeep;
        return out;
    }
    if (shape.containers > kMaxJsonContainers) {
        out.failure = kTokenJsonTooComplex;
        return out;
    }
    nlohmann::json doc;
    try {
        doc = nlohmann::json::parse(text.begin(), text.end(), /*cb=*/nullptr,
                                    /*allow_exceptions=*/false, /*ignore_comments=*/true);
    } catch (...) {
        out.failure = kTokenJsonUnparseable;
        return out;
    }
    if (doc.is_discarded()) {
        out.failure = kTokenJsonUnparseable;
        return out;
    }
    if (!doc.is_object()) {
        out.failure = kTokenJsonNotObject;
        return out;
    }
    try {
        for (const auto& [key, val] : doc.items()) {
            if (out.rows.size() >= max_rows)
                break;
            PolicyRow row;
            row.browser = browser;
            row.level = level;
            row.scope = std::string{scope};
            row.name = key;
            row.value = json_to_policy_value(val);
            row.source = std::string{source};
            out.rows.push_back(std::move(row));
        }
    } catch (...) {
        out.rows.clear();
        out.failure = kTokenJsonUnparseable;
    }
    return out;
}

} // namespace yuzu::browser_policy
