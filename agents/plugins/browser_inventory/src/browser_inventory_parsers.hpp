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
 * `looks_like_email_address` (agents/shared/email_redaction.hpp) redacts either field WHOLE to
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

#include <email_redaction.hpp>

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

using yuzu::shared::kRedactedEmailPlaceholder;
using yuzu::shared::looks_like_email_address;

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
