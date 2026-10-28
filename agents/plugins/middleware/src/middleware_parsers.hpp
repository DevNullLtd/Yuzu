/**
 * middleware_parsers.hpp -- the PURE parsing / token / row layer of the middleware plugin.
 *
 * Everything here is a free function over plain data: no OS call, no I/O, no logging, no platform
 * header, no filesystem library (the repo's pure-core / thin-shell discipline; sibling shape:
 * agents/plugins/runtimes/src/runtimes_parsers.hpp). It compiles and is unit-tested on EVERY OS
 * (tests/unit/test_middleware_parsers.cpp, unguarded). What the plugin reads and in which order is
 * the product table (agents/shared/middleware_products.hpp); the orchestration over that table is
 * middleware_runner.hpp; the OS reads are a thin Fs behind the runner.
 *
 * ZERO SUBPROCESS. The plugin never runs a product binary (dspmqver, dspmqinst, ...): every fact
 * comes from a metadata file the installer laid down. These parsers see only the bytes a leg read.
 *
 * WIRE GRAMMAR. Every product action emits, in this order:
 *
 *   status|<action>|<supported|constrained|unsupported>|<tokens, comma-joined, or ->
 *   <action>|<title>|<name>|<version or ->|<install_path>|<edition or ->        (zero or more)
 *
 * The status row ALWAYS comes first. `supported` with zero data rows means NONE FOUND at the places
 * the leg looks; `constrained` means some read failed or was skipped and the rows that follow may be
 * incomplete -- failure never reads as absent. The status row is written by
 * yuzu::shared::format_status_row.
 *
 * TWO VOCABULARIES, ONE CHANNEL EACH.
 *   Cause       enumeration-level failures. The only thing that becomes a status token, and only
 *               through make_token(): `<os>:middleware:<source>:<cause>`.
 *   ItemReason  per-item shortfalls (one installation's version unknown, one path refused). They go
 *               to the leg's LOG and degrade that one row's fields; they never constrain the whole
 *               host. make_token has no ItemReason overload, so a per-item reason cannot reach the
 *               accumulator by construction. The two enums share some spellings (malformed,
 *               unreadable, oversized, network_fs_skipped) because they name the same fact at two
 *               scopes; they never share a channel.
 *
 * BOUNDS. A parser fed more than its byte cap parses NOTHING and reports `truncated` (no partial
 * data from a clipped read); a list past its row cap is cut with `truncated` set, and a cap-sized
 * list is complete. Nothing here throws on garbage, CRLF, truncated or oversized input.
 *
 * Free-text fields (title, name, version, path, edition) are untrusted installer text and go through
 * field_or_dash (sanitize_utf8 then safe_output_field), so a value containing '|' or ending in a
 * backslash can never shift the field count on the server's escape-aware decoder.
 */
#pragma once

#include <constraint_accumulator.hpp> // yuzu::shared::ConstraintAccumulator (agents/shared)
#include <ini_parse.hpp>              // yuzu::shared::ini_trim (agents/shared)
#include <inventory_status_row.hpp>   // yuzu::shared::format_status_row (agents/shared)
#include <middleware_products.hpp>    // NameForm (agents/shared)

#include <yuzu/string_utils.hpp>

#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace yuzu::middleware {

// -- caps ---------------------------------------------------------------------------------------

inline constexpr std::size_t kMaxKvFileBytes = 64 * 1024;
/// The PRODUCTION CEILINGS of one leg's row budget: every limit a caller injects is clamped to these
/// (make_row_budget in middleware_runner.hpp), so a test can lower a cap but never raise one.
inline constexpr std::size_t kMaxRows = 256;
inline constexpr std::size_t kMaxRowBytes = 1024 * 1024;

// -- shared result shape ------------------------------------------------------------------------

/// What a parser saw, so the caller can choose a status token without re-reading the text.
///  seen       items examined (stanzas)
///  dropped    seen items unusable (missing a required key); the CALLER counts these, siblings are kept
///  truncated  the row cap or the byte cap cut the result (see BOUNDS)
///  malformed  structurally broken input (content but no stanza line at all)
struct ParseReport {
    std::size_t seen = 0;
    std::size_t dropped = 0;
    bool truncated = false;
    bool malformed = false;
};

namespace detail {

/// Iterates the lines of `text` (split on '\n'; a trailing '\r' is removed by ini_trim).
template <class Fn> void for_each_line(std::string_view text, Fn&& fn) {
    std::size_t pos = 0;
    while (pos <= text.size()) {
        auto nl = text.find('\n', pos);
        if (nl == std::string_view::npos)
            nl = text.size();
        fn(text.substr(pos, nl - pos));
        pos = nl + 1;
    }
}

[[nodiscard]] inline bool starts_with(std::string_view s, std::string_view p) noexcept {
    return s.size() >= p.size() && s.substr(0, p.size()) == p;
}

[[nodiscard]] inline bool ends_with(std::string_view s, std::string_view p) noexcept {
    return s.size() >= p.size() && s.substr(s.size() - p.size()) == p;
}

} // namespace detail

// -- key=value stanzas --------------------------------------------------------------------------

struct KvStanza {
    std::vector<std::pair<std::string, std::string>> kv;

    /// The value of the FIRST occurrence of `key`, nullptr when absent.
    [[nodiscard]] const std::string* get(std::string_view key) const noexcept {
        for (const auto& [k, v] : kv)
            if (k == key)
                return &v;
        return nullptr;
    }
};

/// Splits `text` into stanzas of `key=value` lines (keys and values trimmed by ini_trim; blank lines
/// and `#` / `;` comment lines skipped; CRLF tolerated).
///
///  stanza != nullptr  a line equal to `stanza` (after trimming) opens a NEW stanza -- never merged
///                     with an earlier one, which is why the shared INI model in ini_parse.hpp
///                     (it merges a re-opened section) is not used. Any other `Word:` line (ends
///                     in ':', no '=') closes the current stanza and opens none. A `key=value`
///                     line outside a stanza is ignored. Text with content but no stanza line
///                     sets `malformed`.
///  stanza == nullptr  the whole text is ONE stanza, kept when the text has any content line.
///
/// A stanza is kept even when empty: the caller drops candidates lacking the keys it needs and
/// counts them. Exactly kMaxRows stanzas complete; one more sets `truncated` and stops. Text over
/// kMaxKvFileBytes parses nothing and sets `truncated`.
[[nodiscard]] inline std::vector<KvStanza> parse_kv_stanzas(std::string_view text,
                                                            const char* stanza,
                                                            ParseReport& report) {
    std::vector<KvStanza> out;
    if (text.size() > kMaxKvFileBytes) {
        report.truncated = true;
        return out;
    }
    const std::string_view header = stanza != nullptr ? std::string_view{stanza} : std::string_view{};
    bool any_content = false;
    bool saw_stanza = false;
    bool in_stanza = false;
    bool stop = false;
    detail::for_each_line(text, [&](std::string_view raw) {
        if (stop)
            return;
        const std::string line = yuzu::shared::ini_trim(raw);
        if (line.empty() || line[0] == '#' || line[0] == ';')
            return;
        any_content = true;
        const auto eq = line.find('=');
        if (stanza == nullptr) { // whole text is one stanza
            if (out.empty()) {
                out.emplace_back();
                ++report.seen;
            }
            in_stanza = true;
        } else if (line == header) {
            saw_stanza = true;
            if (out.size() >= kMaxRows) {
                report.truncated = true;
                stop = true;
                return;
            }
            out.emplace_back();
            ++report.seen;
            in_stanza = true;
            return;
        } else if (eq == std::string::npos && line.back() == ':') {
            in_stanza = false;
            return;
        }
        if (!in_stanza || eq == std::string::npos)
            return;
        std::string key = yuzu::shared::ini_trim(std::string_view{line}.substr(0, eq));
        if (key.empty())
            return;
        out.back().kv.emplace_back(std::move(key),
                                   yuzu::shared::ini_trim(std::string_view{line}.substr(eq + 1)));
    });
    if (stanza != nullptr && any_content && !saw_stanza)
        report.malformed = true;
    return out;
}

// -- file-name versions -------------------------------------------------------------------------

/// `\d+(\.\d+){1,3}`: two to four dot-separated digit groups, nothing else.
[[nodiscard]] constexpr bool is_dotted_version(std::string_view v) noexcept {
    std::size_t groups = 1;
    bool digit_run = false;
    for (const char c : v) {
        if (c >= '0' && c <= '9')
            digit_run = true;
        else if (c == '.' && digit_run) {
            ++groups;
            digit_run = false;
        } else
            return false;
    }
    return digit_run && groups >= 2 && groups <= 4;
}

/// The version carried by a file NAME (no file content is read): name == prefix + rest + suffix with
/// `rest` non-empty, and
///  exact           rest is `-<version>`; anything else (a `_` component tag included) is nullopt
///  product_suffix  rest is `-<version>`, or `_<anything>-<version>` where <version> follows the
///                  LAST '-'; anything else is nullopt
/// in both forms <version> must satisfy is_dotted_version. Everything else is nullopt, so
/// `ibm.com_IBM_MQSeries-1.0.swidtag` (the product part is not a whole token) never yields a version
/// under prefix `ibm.com_IBM_MQ`.
[[nodiscard]] inline std::optional<std::string>
version_from_file_name(std::string_view name, std::string_view prefix, std::string_view suffix,
                       NameForm form) {
    if (name.size() <= prefix.size() + suffix.size() || !detail::starts_with(name, prefix) ||
        !detail::ends_with(name, suffix))
        return std::nullopt;
    const std::string_view rest =
        name.substr(prefix.size(), name.size() - prefix.size() - suffix.size());
    std::string_view version;
    if (rest.front() == '-')
        version = rest.substr(1);
    else if (form == NameForm::product_suffix && rest.front() == '_') {
        const auto dash = rest.rfind('-');
        if (dash == std::string_view::npos)
            return std::nullopt;
        version = rest.substr(dash + 1);
    } else
        return std::nullopt;
    if (!is_dotted_version(version))
        return std::nullopt;
    return std::string{version};
}

// -- tokens -------------------------------------------------------------------------------------

/// Enumeration-level failure causes: the only vocabulary that becomes a status token.
enum class Cause {
    permission_denied,
    unreadable,
    oversized,
    symlink_refused,
    malformed,
    network_fs_skipped,
    row_cap,
    internal_error,
};

[[nodiscard]] constexpr std::string_view cause_name(Cause c) noexcept {
    switch (c) {
    case Cause::permission_denied:  return "permission_denied";
    case Cause::unreadable:         return "unreadable";
    case Cause::oversized:          return "oversized";
    case Cause::symlink_refused:    return "symlink_refused";
    case Cause::malformed:          return "malformed";
    case Cause::network_fs_skipped: return "network_fs_skipped";
    case Cause::row_cap:            return "row_cap";
    case Cause::internal_error:     return "internal_error";
    }
    return "internal_error";
}

/// `<os>:middleware:<source>:<cause>`; `os` is windows|macos|linux, `source` a probe id or `walk`.
[[nodiscard]] inline std::string make_token(std::string_view os, std::string_view source,
                                            Cause cause) {
    std::string out;
    out.append(os);
    out += ":middleware:";
    out.append(source);
    out += ':';
    out.append(cause_name(cause));
    return out;
}

/// Per-item shortfalls: LOGGED by the leg, never a status token (no make_token overload takes one).
enum class ItemReason {
    path_refused,
    missing,
    unreadable,
    oversized,
    malformed,
    network_fs_skipped,
};

[[nodiscard]] constexpr std::string_view item_reason_name(ItemReason r) noexcept {
    switch (r) {
    case ItemReason::path_refused:       return "path_refused";
    case ItemReason::missing:            return "missing";
    case ItemReason::unreadable:         return "unreadable";
    case ItemReason::oversized:          return "oversized";
    case ItemReason::malformed:          return "malformed";
    case ItemReason::network_fs_skipped: return "network_fs_skipped";
    }
    return "unreadable";
}

// -- rows ---------------------------------------------------------------------------------------
//
// Formatters return the row WITHOUT a trailing newline (write_output/append_output insert the
// separator; a formatter-emitted '\n' yields blank rows under LocalDispatcher capture).

/// Untrusted installer text becomes one safe field: invalid UTF-8 bytes are replaced first (the
/// output crosses the wire as a proto3 `string`, and one invalid byte fails the parse of the whole
/// chunk), then the pipe-grammar escaper runs. Empty -> "-".
[[nodiscard]] inline std::string field_or_dash(std::string_view v) {
    return v.empty() ? std::string{"-"}
                     : yuzu::util::safe_output_field(yuzu::util::sanitize_utf8(std::string{v}));
}

/// <action>|<title>|<name>|<version or ->|<install_path>|<edition or ->
[[nodiscard]] inline std::string format_row(std::string_view action, std::string_view title,
                                            std::string_view name, std::string_view version,
                                            std::string_view install_path,
                                            std::string_view edition) {
    std::string out = yuzu::util::safe_output_field(action);
    for (const std::string_view f : {title, name, version, install_path, edition}) {
        out += '|';
        out += field_or_dash(f);
    }
    return out;
}

/// The full ordered output of one action: the status row first (`supported` with no failure, else
/// `constrained` + the accumulator's tokens, which it already deduplicates in first-seen order), then
/// every data row.
[[nodiscard]] inline std::vector<std::string>
compose_output(std::string_view action, const std::vector<std::string>& data_rows,
               const yuzu::shared::ConstraintAccumulator& acc) {
    const auto level = acc.any_failure() ? yuzu::shared::StatusLevel::constrained
                                         : yuzu::shared::StatusLevel::supported;
    std::vector<std::string> out;
    out.reserve(data_rows.size() + 1);
    out.push_back(yuzu::shared::format_status_row(action, level, acc.reason()));
    out.insert(out.end(), data_rows.begin(), data_rows.end());
    return out;
}

} // namespace yuzu::middleware
