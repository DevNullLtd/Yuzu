#pragma once

/**
 * asset_tags_parsers.hpp — pure core of the asset_tags plugin (#232).
 *
 * No I/O, no threads, no logging: value capping, change-log bounding, the
 * sync diff, the on-disk snapshot (de)serialisation, and every output-row
 * formatter live here so the agent unit suite can exercise them directly.
 * The plugin .cpp keeps only the mutex, spdlog and the ABI shell;
 * asset_tags_store.hpp holds the state-file I/O.
 *
 * Output policy (S20): synced values are stored raw (capped to
 * kMaxValueBytes on a UTF-8 codepoint boundary), and EVERY field emitted in a
 * pipe-delimited row — values, keys, and echoed caller text — goes through
 * yuzu::util::safe_output_field. Nothing is rejected or stripped at rest.
 * safe_output_field is lossy on a literal backslash on the wire (folded to
 * '/'); that is a documented limitation of the shared server decoder.
 *
 * Persistence is lossy in exactly one case: a stored value that is not valid
 * UTF-8 is written with U+FFFD in place of each bad byte (serialize_state),
 * so it differs after a restart. A value the server accepted is valid UTF-8
 * and round-trips byte-for-byte.
 */

#include <algorithm>
#include <array>
#include <charconv>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <unordered_map>
#include <utility>
#include <vector>

#include <nlohmann/json.hpp>

#include <yuzu/string_utils.hpp>

namespace yuzu::asset_tags {

// The 4 fixed structured tag categories.
inline constexpr std::array<std::string_view, 4> kCategoryKeys = {"role", "environment", "location",
                                                                  "service"};

/// Maximum entries kept in the change log, in memory and on disk (S19). A
/// round number, not derived from a byte/retention budget like
/// kMaxValueBytes below -- the log is a local diagnostic trail (`changes`
/// action), not the authoritative tag state (that's the server's TagStore),
/// so an exact figure isn't load-bearing; chosen to comfortably cover a
/// single sync's worth of category+key changes with headroom.
inline constexpr std::size_t kMaxChangeLog = 50;

/// Maximum bytes of a stored tag value. Matches the server's
/// TagStore::validate_value cap (server/core/src/tag_store.cpp), so a value
/// the server accepts is never truncated here.
inline constexpr std::size_t kMaxValueBytes = 448;

/// Floor for asset_tags.check_interval, in seconds.
inline constexpr int kMinCheckIntervalS = 30;

using CategoryValues = std::array<std::string, kCategoryKeys.size()>;

struct ChangeRecord {
    std::string key;
    std::string old_value;
    std::string new_value;
    int64_t timestamp{0}; // epoch seconds
};

struct AssetTagState {
    std::unordered_map<std::string, std::string> tags;
    int64_t last_sync_epoch{0};
    bool stale{true};
    std::vector<ChangeRecord> change_log;
};

/// Why a snapshot was rejected; `message` names the offending field.
struct ParseError {
    std::string message;
};

inline bool is_category_key(std::string_view key) {
    return std::find(kCategoryKeys.begin(), kCategoryKeys.end(), key) != kCategoryKeys.end();
}

/// Cap a value to kMaxValueBytes without tearing a UTF-8 codepoint: a
/// multi-byte sequence that straddles the limit is dropped whole. No
/// stripping, no escaping.
inline std::string cap_value(std::string_view raw) {
    if (raw.size() <= kMaxValueBytes)
        return std::string{raw};
    std::size_t cut = kMaxValueBytes;
    // raw[cut] is the first excluded byte; a continuation byte (10xxxxxx)
    // there means the cut is mid-codepoint.
    while (cut > 0 && (static_cast<unsigned char>(raw[cut]) & 0xC0U) == 0x80U)
        --cut;
    return std::string{raw.substr(0, cut)};
}

/// Evict the oldest entries so at most kMaxChangeLog remain.
inline void trim_change_log(std::vector<ChangeRecord>& log) {
    if (log.size() > kMaxChangeLog)
        log.erase(log.begin(), log.begin() + static_cast<std::ptrdiff_t>(log.size() - kMaxChangeLog));
}

inline void append_change(std::vector<ChangeRecord>& log, ChangeRecord cr) {
    log.push_back(std::move(cr));
    trim_change_log(log);
}

/// Apply a sync: per category (kCategoryKeys order), record a change when the
/// value differs, then store (or erase, when empty) the new value. Returns the
/// changes made by THIS sync (independent of the bounded log).
inline std::vector<ChangeRecord> apply_sync(AssetTagState& st, const CategoryValues& values,
                                            int64_t now) {
    std::vector<ChangeRecord> changes;
    for (std::size_t i = 0; i < kCategoryKeys.size(); ++i) {
        const std::string key{kCategoryKeys[i]};
        const std::string& new_value = values[i];

        auto it = st.tags.find(key);
        std::string old_value = (it != st.tags.end()) ? it->second : std::string{};

        if (new_value != old_value) {
            ChangeRecord cr{key, old_value, new_value, now};
            changes.push_back(cr);
            append_change(st.change_log, std::move(cr));
        }

        if (new_value.empty())
            st.tags.erase(key);
        else
            st.tags[key] = new_value;
    }
    st.last_sync_epoch = now;
    st.stale = false;
    return changes;
}

inline std::string serialize_state(const AssetTagState& st) {
    nlohmann::json j;
    j["tags"] = st.tags;
    j["last_sync_epoch"] = st.last_sync_epoch;
    j["stale"] = st.stale;

    nlohmann::json log_arr = nlohmann::json::array();
    for (const auto& cr : st.change_log) {
        log_arr.push_back({{"key", cr.key},
                           {"old_value", cr.old_value},
                           {"new_value", cr.new_value},
                           {"timestamp", cr.timestamp}});
    }
    j["change_log"] = std::move(log_arr);
    // Raw stored values may carry invalid UTF-8; replace rather than throw
    // (dump()'s default would raise type_error 316 inside the sync lock).
    // This is the one lossy case — see the file header.
    return j.dump(2, ' ', false, nlohmann::json::error_handler_t::replace);
}

namespace detail {

/// Look up an optional field and check its type. Returns nullptr when the
/// field is absent, the field when present and of the expected type, and a
/// ParseError naming `where + name` when present but of another type.
template <class IsType>
[[nodiscard]] inline std::expected<const nlohmann::json*, ParseError>
optional_field(const nlohmann::json& obj, const char* name, const std::string& where,
               IsType&& is_type, const char* type_name) {
    auto it = obj.find(name);
    if (it == obj.end())
        return nullptr;
    if (!is_type(*it))
        return std::unexpected(ParseError{where + name + ": expected " + type_name});
    return &*it;
}

/// Optional capped string field: nullopt when absent.
[[nodiscard]] inline std::expected<std::optional<std::string>, ParseError>
optional_string(const nlohmann::json& obj, const char* name, const std::string& where) {
    auto f = optional_field(
        obj, name, where, [](const nlohmann::json& v) { return v.is_string(); }, "string");
    if (!f)
        return std::unexpected(f.error());
    if (!*f)
        return std::nullopt;
    return cap_value((*f)->get_ref<const std::string&>());
}

} // namespace detail

/// Parse an on-disk snapshot. ONE recovery policy: any schema violation
/// rejects the WHOLE snapshot (a ParseError naming the offending field); no
/// partial state is ever returned. Unknown top-level keys are ignored
/// (forward compatibility); missing known top-level fields keep their
/// defaults. A change-log entry must carry a category `key`. Never throws.
/// Loaded values are capped (an older plugin stored them uncapped) and an
/// oversized change log is trimmed to the newest kMaxChangeLog.
[[nodiscard]] inline std::expected<AssetTagState, ParseError> parse_state(std::string_view text) {
    using nlohmann::json;
    auto j = json::parse(text.begin(), text.end(), nullptr, false);
    if (j.is_discarded())
        return std::unexpected(ParseError{"not valid JSON"});
    if (!j.is_object())
        return std::unexpected(ParseError{"root: expected object"});

    AssetTagState st;

    auto tags = detail::optional_field(
        j, "tags", "", [](const json& v) { return v.is_object(); }, "object");
    if (!tags)
        return std::unexpected(tags.error());
    if (*tags) {
        for (const auto& [key, val] : (*tags)->items()) {
            if (!is_category_key(key))
                return std::unexpected(ParseError{"tags." + key + ": unknown category"});
            if (!val.is_string())
                return std::unexpected(ParseError{"tags." + key + ": expected string"});
            st.tags[key] = cap_value(val.get_ref<const std::string&>());
        }
    }

    auto epoch = detail::optional_field(
        j, "last_sync_epoch", "", [](const json& v) { return v.is_number_integer(); }, "integer");
    if (!epoch)
        return std::unexpected(epoch.error());
    if (*epoch)
        st.last_sync_epoch = (*epoch)->get<int64_t>();

    auto stale = detail::optional_field(
        j, "stale", "", [](const json& v) { return v.is_boolean(); }, "boolean");
    if (!stale)
        return std::unexpected(stale.error());
    if (*stale)
        st.stale = (*stale)->get<bool>();

    auto log = detail::optional_field(
        j, "change_log", "", [](const json& v) { return v.is_array(); }, "array");
    if (!log)
        return std::unexpected(log.error());
    if (*log) {
        std::size_t idx = 0;
        for (const auto& entry : **log) {
            const std::string where = "change_log[" + std::to_string(idx) + "].";
            if (!entry.is_object())
                return std::unexpected(
                    ParseError{"change_log[" + std::to_string(idx) + "]: expected object"});

            ChangeRecord cr;
            auto key = detail::optional_string(entry, "key", where);
            if (!key)
                return std::unexpected(key.error());
            if (!*key)
                return std::unexpected(ParseError{where + "key: missing"});
            if (!is_category_key(**key))
                return std::unexpected(ParseError{where + "key: unknown category"});
            cr.key = std::move(**key);

            auto old_value = detail::optional_string(entry, "old_value", where);
            if (!old_value)
                return std::unexpected(old_value.error());
            if (*old_value)
                cr.old_value = std::move(**old_value);

            auto new_value = detail::optional_string(entry, "new_value", where);
            if (!new_value)
                return std::unexpected(new_value.error());
            if (*new_value)
                cr.new_value = std::move(**new_value);

            auto ts = detail::optional_field(
                entry, "timestamp", where, [](const json& v) { return v.is_number_integer(); },
                "integer");
            if (!ts)
                return std::unexpected(ts.error());
            if (*ts)
                cr.timestamp = (*ts)->get<int64_t>();

            st.change_log.push_back(std::move(cr));
            ++idx;
        }
    }
    trim_change_log(st.change_log);
    return st;
}

// ── Row formatters — every string field escaped ─────────────────────────────

inline std::string format_sync_event(const ChangeRecord& cr) {
    const auto key = yuzu::util::safe_output_field(cr.key);
    if (cr.old_value.empty())
        return "sync|tag_added|" + key + "|" + yuzu::util::safe_output_field(cr.new_value);
    if (cr.new_value.empty())
        return "sync|tag_removed|" + key + "|" + yuzu::util::safe_output_field(cr.old_value);
    return "sync|tag_changed|" + key + "|" + yuzu::util::safe_output_field(cr.old_value) + "|" +
           yuzu::util::safe_output_field(cr.new_value);
}

inline std::string format_tag_row(std::string_view key, std::string_view value) {
    return "tag|" + yuzu::util::safe_output_field(key) + "|" + yuzu::util::safe_output_field(value);
}

inline std::string format_change_row(const ChangeRecord& cr) {
    return "change|" + yuzu::util::safe_output_field(cr.key) + "|" +
           yuzu::util::safe_output_field(cr.old_value) + "|" +
           yuzu::util::safe_output_field(cr.new_value) + "|" + std::to_string(cr.timestamp);
}

/// `<prefix>: <echoed>` with the caller-supplied echo escaped. The prefix is
/// plugin-authored and emitted verbatim.
inline std::string format_error_row(std::string_view prefix, std::string_view echoed) {
    std::string out{prefix};
    out += ": ";
    out += yuzu::util::safe_output_field(echoed);
    return out;
}

/// Parse asset_tags.check_interval: the whole string must be a decimal
/// integer; the result is floored at kMinCheckIntervalS. nullopt on malformed
/// input (caller keeps its default and warns).
inline std::optional<int> parse_check_interval(std::string_view s) {
    int v = 0;
    const auto* first = s.data();
    const auto* last = s.data() + s.size();
    auto [ptr, ec] = std::from_chars(first, last, v);
    if (ec != std::errc{} || ptr != last)
        return std::nullopt;
    return std::max(v, kMinCheckIntervalS);
}

} // namespace yuzu::asset_tags
