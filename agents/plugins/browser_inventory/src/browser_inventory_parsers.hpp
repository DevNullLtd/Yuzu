/**
 * browser_inventory_parsers.hpp — pure, portable JSON parsers for the
 * Chromium-family profile file shape (Google Chrome / Microsoft Edge /
 * other Chromium forks all share the "Local State" file layout at the
 * browser root). No OS read, no filesystem access, no subprocess: every
 * function here takes an already-loaded file's text and returns a row
 * model. The per-OS leg TUs (browser_inventory_linux.cpp / _macos.cpp /
 * _win.cpp) own locating and reading those files; this header owns
 * interpreting their bytes.
 *
 * PRIVACY CONTRACT (binding for this whole plugin): a row built from this
 * header's parsers NEVER carries a browsing-account identifier -- no
 * gaia_id, no e-mail address, no Chromium info_cache user_name/gaia_name,
 * no browsing history, no cookies, no bookmarks. The dedicated-identifier
 * half of this (gaia_id/user_name/gaia_name) is enforced structurally --
 * BrowserProfileRow simply has no such field. The e-mail-address half is
 * enforced by VALUE, not by absence: `profile_dir` and `display_name` ARE
 * free-text fields Chromium populates from the account (a signed-in Edge
 * profile in particular is often keyed by its account e-mail), so
 * `looks_like_email_address` below redacts either field WHOLE to
 * `kRedactedEmailPlaceholder` when it CONTAINS an e-mail-shaped substring
 * before it ever reaches BrowserProfileRow (adversarial-review findings
 * 2026-09-22/2026-09-23 -- the original structural-only claim was
 * incomplete, and the first by-value fix under-matched every decorated
 * form: "Alice <alice@example.com>", "alice@example.com (Work)", an
 * embedded address, or several addresses in one field). See
 * test_browser_inventory_parsers.cpp for a fixture that carries those
 * keys, and an e-mail-shaped profile_dir/display_name, and asserts none of
 * them reach a row unredacted.
 * TWO EXCEPTIONS (decided 2026-09-22, not part of this contract): (1) the
 * Linux leg's wire-row builder (browser_inventory_linux_parsers.hpp)
 * prepends the LOCAL OS/home-directory username to disambiguate profiles
 * across users sharing a machine -- that value never passes through this
 * header or BrowserProfileRow, and is not a browsing-account identifier.
 * (2) BrowserProfileRow.display_name may still carry a personal (non-
 * e-mail) name -- Chromium-family browsers commonly auto-populate it from
 * the signed-in account's real name, and only the e-mail SHAPE is
 * filtered above; a bare name is an accepted residual risk (see
 * BrowserProfileRow's own doc comment and the plugin README's PRIVACY
 * CONTRACT), not something this header filters.
 * No file inside a profile directory ("Preferences", "Secure Preferences",
 * "History", "Cookies", ...) is read by any caller of this header in this
 * release; the per-profile `extensions` action follows as its own PR.
 *
 * JSON-parse idiom copied from agents/plugins/asset_tags/src/
 * asset_tags_plugin.cpp:87-109 (try/catch around nlohmann::json::parse, no
 * rethrow; `.contains()` guards before indexing; `.value("key", default)`
 * for optional fields) -- with one addition: this header's callers need to
 * tell a "found nothing" empty result apart from "the JSON didn't parse at
 * all", so parsing failure is surfaced as std::nullopt rather than swallowed
 * silently. See each function's doc comment for its exact nullopt contract.
 */
#pragma once

#include <nlohmann/json.hpp>

#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::browser_inventory {

/// One row of the "profiles" action. Deliberately has no gaia_id/e-mail/
/// info_cache user_name field -- see the file banner's PRIVACY CONTRACT.
/// (The Linux leg's wire row separately carries the LOCAL OS username --
/// added by browser_inventory_linux_parsers.hpp, never a field here.)
struct BrowserProfileRow {
    std::string profile_dir;  // the info_cache key, e.g. "Default", "Profile 1"
                               // -- Edge in particular sometimes uses the
                               // signed-in account's e-mail address as this
                               // key itself; see kRedactedEmailPlaceholder
                               // below.
    std::string display_name; // info_cache[dir].name -- a user-editable
                               // label. Often a generic default ("Profile 1",
                               // "Work"), but Chromium-family browsers
                               // commonly auto-populate it from the
                               // signed-in account's real name -- this CAN
                               // legitimately be a personal name (accepted
                               // exception, see the file banner's PRIVACY
                               // CONTRACT; a personal name is not filtered).
                               // "-" if absent.
    bool active{false};       // dir == profile.last_used
    bool ephemeral{false};    // info_cache[dir].is_ephemeral, default false
};

/// Substituted for `profile_dir`/`display_name` when the raw value
/// contains an e-mail address (see `looks_like_email_address` below).
/// Irreversible by construction -- unlike the accepted personal-name
/// residual risk on `display_name`, an e-mail address is a
/// browsing-account identifier and the PRIVACY CONTRACT above forbids it
/// unconditionally, so this is a filter, not a documented exception.
inline constexpr std::string_view kRedactedEmailPlaceholder = "[redacted-email]";

/// True when `value` CONTAINS an e-mail-shaped substring anywhere -- bare
/// (`account@example.com`), decorated (`Alice <alice@example.com>`,
/// `alice@example.com (Work)`), embedded (`x alice@example.com`),
/// several (`a@x.org,b@y.org`), quoted (`"alice.smith"@example.com`),
/// RFC 5322 comment-syntax (`alice(comment)@example.com`), or separated
/// from the domain by folding whitespace/control characters
/// (`alice\n@example.com`); coarse by design, over-match is the safe
/// direction. Round-2 governance finding G-1 (2026-09-23): the earlier
/// local-part exclusion list rejected exactly the whitespace/quote/
/// comment characters a decorated or folded address puts immediately
/// before '@', which is backwards for a filter whose stated principle is
/// over-match-is-safe -- the ONLY local-side condition is now that '@' is
/// not at position 0. The domain side still has to look email-shaped, but
/// CFWS (folding whitespace and/or a parenthesized comment, possibly
/// nested) is skipped both immediately after '@' and around each domain
/// dot before that check runs: a dotted label (label '.' label, non-empty
/// either side once CFWS is skipped; domain bytes are ASCII alnum/-/._ or
/// any byte >= 0x80, so a raw non-punycode IDN domain still matches), or a
/// non-empty bracketed domain literal (`@[203.0.113.5]`, itself reachable
/// through leading CFWS); any hit redacts the whole field. Round-2
/// adversarial finding 2026-09-23 (domain-side mirror of G-3): the earlier
/// domain scan started matching immediately at '@', so CFWS before the
/// domain or around a dot (`alice@ (comment)example.com`,
/// `alice@example . com`) produced an empty or truncated domain and
/// returned false. (An unterminated comment consumes the rest of `value`
/// and yields no match by the same pre-existing contract `skip_cfws`
/// documents below -- not something this finding changed.) Round-3
/// code-review finding F1 (2026-09-23): a backslash-escaped byte inside a
/// comment is consumed as one RFC 5322 quoted-pair and never changes depth,
/// so an escaped `(`/`)` (`alice@(a\(b)example.com`,
/// `alice@(escaped\)paren)example.com`) does not open/close the comment
/// early and truncate the domain scan that follows.
[[nodiscard]] inline bool looks_like_email_address(std::string_view value) {
    auto is_domain_char = [](char c) {
        return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
               c == '-' || c == '.' || c == '_' || static_cast<unsigned char>(c) >= 0x80;
    };
    // Skips a run of folding whitespace and/or a parenthesized comment
    // (nested comments tracked by depth) starting at `i`, repeating until
    // neither advances. An unterminated comment consumes the rest of
    // `value` (depth never returns to 0), which is intentional: the caller
    // then finds an empty domain and reports no match. Inside a comment, a
    // backslash and the byte immediately after it are consumed together as
    // one RFC 5322 quoted-pair -- that byte is never itself tested as a
    // depth-changing '(' or ')' (round-3 finding F1, 2026-09-23: an escaped
    // ')' inside a comment was closing the comment early, truncating the
    // domain scan that follows).
    auto skip_cfws = [value](std::size_t& i) {
        for (;;) {
            bool advanced = false;
            while (i < value.size()) {
                const char c = value[i];
                if (c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\f' || c == '\v') {
                    ++i;
                    advanced = true;
                } else {
                    break;
                }
            }
            if (i < value.size() && value[i] == '(') {
                std::size_t depth = 0;
                while (i < value.size()) {
                    if (value[i] == '\\') {
                        // Quoted-pair: consume the backslash and the next
                        // byte as one unit, never as a depth-changing
                        // paren. A trailing lone backslash must not step
                        // past the end -- it then reads as an unterminated
                        // comment (depth stays open), same as before.
                        i += (i + 1 < value.size()) ? 2 : 1;
                    } else if (value[i] == '(') {
                        ++depth;
                        ++i;
                    } else if (value[i] == ')') {
                        --depth;
                        ++i;
                        if (depth == 0) {
                            break;
                        }
                    } else {
                        ++i;
                    }
                }
                advanced = true;
            }
            if (!advanced) {
                break;
            }
        }
    };

    for (auto at = value.find('@'); at != std::string_view::npos; at = value.find('@', at + 1)) {
        if (at == 0) {
            continue;
        }
        std::size_t i = at + 1;
        skip_cfws(i);
        if (i < value.size() && value[i] == '[') {
            const auto close = value.find(']', i + 1);
            if (close != std::string_view::npos && close > i + 1) {
                return true;
            }
            continue;
        }
        std::size_t label_len = 0;
        bool pending_dot = false;
        while (i < value.size()) {
            skip_cfws(i);
            if (i >= value.size()) {
                break;
            }
            const char c = value[i];
            if (is_domain_char(c) && c != '.') {
                if (pending_dot) {
                    return true;
                }
                ++label_len;
                ++i;
            } else if (c == '.') {
                pending_dot = (label_len > 0);
                label_len = 0;
                ++i;
            } else {
                break;
            }
        }
    }
    return false;
}

namespace detail {

/// Parses `text` as JSON. Returns std::nullopt for an empty string (file
/// absent -- not a parse failure) as well as for genuinely malformed JSON,
/// but distinguishes the two via `out_malformed` so callers can tell
/// "absent" from "present but broken".
inline std::optional<nlohmann::json> try_parse(std::string_view text, bool& out_malformed) {
    out_malformed = false;
    if (text.empty())
        return std::nullopt;
    try {
        return nlohmann::json::parse(text);
    } catch (...) {
        out_malformed = true;
        return std::nullopt;
    }
}

} // namespace detail

/// Parses a Chromium/Edge "Local State" file and returns one row per
/// profile directory under profile.info_cache. `local_state_text` may be
/// empty (file absent) -- that yields an empty vector, not nullopt.
///
/// std::nullopt means the JSON did not parse at all (malformed input) --
/// the caller reports CONSTRAINED. An empty vector is a legitimate "valid
/// JSON, no profiles" or "file absent" result, never a failure.
[[nodiscard]] inline std::optional<std::vector<BrowserProfileRow>>
profiles_from_local_state(std::string_view local_state_text) {
    bool malformed = false;
    auto parsed = detail::try_parse(local_state_text, malformed);
    if (malformed)
        return std::nullopt;
    if (!parsed.has_value())
        return std::vector<BrowserProfileRow>{}; // absent file

    // Valid JSON with a schema-drifted type (e.g. a numeric "last_used" or
    // "name") makes nlohmann::json's typed .value<T>() throw type_error --
    // syntactically valid input the try_parse() step above cannot catch,
    // since it only guards the parse itself. Adversarial-review finding
    // (2026-09-22): this whole semantic-extraction pass is now wrapped so
    // a type-drifted field reports the SAME documented contract as
    // malformed JSON (CONSTRAINED/local_state_malformed at the caller),
    // never an uncaught exception across the plugin ABI (the daemon's own
    // outer catch, agent.cpp, would still stop it from crashing the
    // agent, but the operator would see a generic "plugin threw
    // exception" message instead of the typed status this plugin
    // otherwise always provides).
    try {
        std::vector<BrowserProfileRow> rows;
        const auto& root = *parsed;
        if (!root.is_object() || !root.contains("profile") || !root["profile"].is_object())
            return rows;
        const auto& profile = root["profile"];
        const std::string last_used = profile.value("last_used", std::string{});
        if (!profile.contains("info_cache") || !profile["info_cache"].is_object())
            return rows;

        // nlohmann::json's default object type is ordered by key
        // (std::map), so this iteration -- and therefore row order -- is
        // deterministic.
        for (const auto& [dir, info] : profile["info_cache"].items()) {
            if (!info.is_object())
                continue;
            BrowserProfileRow row;
            row.profile_dir = looks_like_email_address(dir) ? std::string{kRedactedEmailPlaceholder}
                                                              : dir;
            row.display_name = info.value("name", std::string{});
            if (row.display_name.empty())
                row.display_name = "-";
            else if (looks_like_email_address(row.display_name))
                row.display_name = std::string{kRedactedEmailPlaceholder};
            row.active = (dir == last_used);
            row.ephemeral = info.value("is_ephemeral", false);
            rows.push_back(std::move(row));
        }
        return rows;
    } catch (const nlohmann::json::exception&) {
        return std::nullopt; // type-drifted field -- same contract as malformed JSON
    }
}

} // namespace yuzu::browser_inventory
