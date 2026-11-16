#pragma once

/// @file collection_settings_agent.hpp
/// Agent side of the fleet collection settings: the `__sync__` action `settings`.
///
/// The server sends the settings its group tree resolves for this device as a text document plus
/// its SHA-256 (the document's version):
///
///   command plugin `__sync__`, action `settings`, parameters `version` and `document`
///   document = lines, each terminated by '\n', in exactly this order:
///       v1
///       interval=<seconds>
///       window=<start_min>-<end_min>     or    window=none
///       tz=<IANA name or empty>
///       plugin.<name>=0|1                one line per collector, ascending name order
///
/// This header is the whole decision: parse_settings_command() refuses anything that is not that
/// shape (a self-consistent hash over an incomplete document is never applied),
/// decide_sync_settings() persists and hands the result over through injected hooks,
/// load_stored_settings() re-validates the persisted pair at start-up and emit_settings_tags()
/// publishes what was applied. No gRPC, no store, no clock: agent.cpp supplies the hooks. The only
/// non-inline dependency is sha256_hex (sync_canonical.hpp), an exported agent-core symbol.
///
/// Every `plugin.<name>` value is applied as sent. The server alone keeps `installed_apps` on
/// unless that collector is kill-switched, and the agent adds no override: a kill switch must stop
/// collection on the machine while the agent reports the version it really applied.

#include "sync_canonical.hpp"
#include "sync_now_decision.hpp"
#include "sync_window.hpp"

#include <array>
#include <cstddef>
#include <expected>
#include <functional>
#include <map>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::agent {

/// The reserved-command action this header decides.
inline constexpr std::string_view kSettingsAction = "settings";
/// `__sync__` KV keys holding the applied pair. Written document first, version second: a crash
/// between the two writes leaves a hash that does not match, which start-up discards.
inline constexpr std::string_view kSettingsKvDocumentKey = "settings.document";
inline constexpr std::string_view kSettingsKvVersionKey = "settings.version";
/// The only sync source the settings steer.
inline constexpr std::string_view kSettingsSyncSource = "installed_software";

inline constexpr std::size_t kSettingsDocumentMaxBytes = 4096;
inline constexpr int kSettingsMinIntervalS = 3600;   // 1 h
inline constexpr int kSettingsMaxIntervalS = 604800; // 7 d
inline constexpr int kSettingsDayS = 86400;
inline constexpr int kSettingsMinutesPerDay = 1440;
inline constexpr std::size_t kSettingsMaxTimezoneBytes = 64;

/// Version tag value when nothing is applied (or the stored pair did not validate).
inline constexpr std::string_view kSettingsVersionNone = "none";
/// Reason load_stored_settings() gives when the KV holds no pair at all.
inline constexpr std::string_view kNoStoredSettings = "no stored settings";

/// The collectors a document must carry a switch for, sorted: the collector plugins of the
/// installed_software table (sync_source_installed_software.cpp) the server can switch, the same
/// six as the server's kCollectionPlugins. The `hardware` driver facet has no switch.
inline constexpr std::array<std::string_view, 6> kSettingsCollectors = {
    "installed_apps", "middleware", "msi_packages", "pkg_inventory", "runtimes",
    "windows_optional_features",
};

struct AgentCollectionSettings {
    std::string version; ///< 64 lower-case hex, == sha256_hex(the document it came from)
    int interval_s{kSettingsDayS};
    std::optional<SyncWindow> window; ///< minutes after local midnight; nullopt = `window=none`
    std::string timezone;             ///< stored and reported; the window runs in machine-local time
    std::map<std::string, bool> plugins; ///< includes names this agent does not know
};

namespace settings_detail {

inline bool is_hex64(std::string_view s) {
    if (s.size() != 64)
        return false;
    for (const char c : s) {
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
            return false;
    }
    return true;
}

/// A plain non-negative decimal (no sign, no space, no leading zero, at most 7 digits).
inline std::optional<int> parse_count(std::string_view s) {
    if (s.empty() || s.size() > 7 || (s.size() > 1 && s.front() == '0'))
        return std::nullopt;
    int v = 0;
    for (const char c : s) {
        if (c < '0' || c > '9')
            return std::nullopt;
        v = v * 10 + (c - '0');
    }
    return v;
}

/// Echo of an attacker-influenced line in a reason: printable ASCII only, bounded.
inline std::string quote(std::string_view s) {
    std::string out;
    for (const char c : s.substr(0, 40))
        out.push_back((c >= 0x20 && c < 0x7f) ? c : '?');
    if (s.size() > 40)
        out += "...";
    return out;
}

inline bool is_plugin_name(std::string_view n) {
    if (n.empty() || n.size() > 64)
        return false;
    for (const char c : n) {
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_'))
            return false;
    }
    return true;
}

inline bool is_timezone(std::string_view tz) {
    if (tz.size() > kSettingsMaxTimezoneBytes)
        return false;
    for (const char c : tz) {
        const bool ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                        (c >= '0' && c <= '9') || c == '_' || c == '/' || c == '+' || c == '-';
        if (!ok)
            return false;
    }
    return true;
}

} // namespace settings_detail

/// Parse and validate a `settings` command's parameters (any map with find()/end() over
/// string -> string: the protobuf parameter map, or a std::map in a test). Each refusal carries
/// its own reason; nothing is applied on any of them.
template <class Params>
[[nodiscard]] std::expected<AgentCollectionSettings, std::string>
parse_settings_command(const Params& params) {
    using std::unexpected;
    namespace d = settings_detail;

    const auto vit = params.find("version");
    if (vit == params.end())
        return unexpected("missing parameter: version");
    const auto dit = params.find("document");
    if (dit == params.end())
        return unexpected("missing parameter: document");
    const std::string version{vit->second};
    const std::string_view doc{dit->second};

    if (doc.size() > kSettingsDocumentMaxBytes)
        return unexpected("document exceeds " + std::to_string(kSettingsDocumentMaxBytes) +
                          " bytes");
    if (!d::is_hex64(version))
        return unexpected("version is not 64 lower-case hex characters");
    if (doc.empty() || doc.back() != '\n')
        return unexpected("document is empty or its last line is not newline-terminated");

    std::vector<std::string_view> lines;
    for (std::size_t pos = 0; pos < doc.size();) {
        const auto nl = doc.find('\n', pos);
        lines.push_back(doc.substr(pos, nl - pos));
        pos = nl + 1;
    }

    // Lines 1-4 are fixed in place: each must be present, and be the field it is the slot of.
    const auto fixed = [&](std::size_t i, std::string_view prefix) -> std::optional<std::string_view> {
        if (i >= lines.size() || !lines[i].starts_with(prefix))
            return std::nullopt;
        return lines[i].substr(prefix.size());
    };
    const auto refuse_field = [&](std::size_t i, std::string_view field) {
        return unexpected(
            i >= lines.size()
                ? "document is missing the " + std::string{field} + " line"
                : "line " + std::to_string(i + 1) + " must be " + std::string{field} + ", got '" +
                      d::quote(lines[i]) + "'");
    };

    if (lines.empty() || lines[0] != "v1")
        return refuse_field(0, "v1");

    AgentCollectionSettings out;
    out.version = version;

    const auto interval_text = fixed(1, "interval=");
    if (!interval_text)
        return refuse_field(1, "interval=<seconds>");
    const auto interval = d::parse_count(*interval_text);
    if (!interval)
        return unexpected("interval is not a plain integer: '" + d::quote(*interval_text) + "'");
    if (*interval < kSettingsMinIntervalS || *interval > kSettingsMaxIntervalS)
        return unexpected("interval must be between 3600 and 604800");
    out.interval_s = *interval;

    const auto window_text = fixed(2, "window=");
    if (!window_text)
        return refuse_field(2, "window=<start>-<end> or window=none");
    if (*window_text != "none") {
        const auto dash = window_text->find('-');
        std::optional<int> start;
        std::optional<int> end;
        if (dash != std::string_view::npos) {
            start = d::parse_count(window_text->substr(0, dash));
            end = d::parse_count(window_text->substr(dash + 1));
        }
        if (!start || !end)
            return unexpected("window is neither none nor <start>-<end>: '" +
                              d::quote(*window_text) + "'");
        if (*start < 0 || *start >= *end || *end > kSettingsMinutesPerDay)
            return unexpected("window needs 0 <= start < end <= 1440");
        if (out.interval_s % kSettingsDayS != 0)
            return unexpected("a window needs a whole-day interval (86400, 172800, ...)");
        out.window = SyncWindow{*start, *end};
    }

    const auto tz_text = fixed(3, "tz=");
    if (!tz_text)
        return refuse_field(3, "tz=<zone or empty>");
    if (!d::is_timezone(*tz_text))
        return unexpected("tz is longer than 64 bytes or has an invalid character");
    out.timezone = std::string{*tz_text};

    // Lines 5..: plugin.<name>=0|1 in strictly ascending name order, each name once.
    std::string previous;
    for (std::size_t i = 4; i < lines.size(); ++i) {
        const std::string_view line = lines[i];
        constexpr std::string_view kPrefix = "plugin.";
        const auto eq = line.find('=');
        if (!line.starts_with(kPrefix) || eq == std::string_view::npos || eq < kPrefix.size())
            return unexpected("line " + std::to_string(i + 1) +
                              " is not a plugin.<name>=0|1 line: '" + d::quote(line) + "'");
        const std::string name{line.substr(kPrefix.size(), eq - kPrefix.size())};
        const std::string_view value = line.substr(eq + 1);
        if (!d::is_plugin_name(name))
            return unexpected("line " + std::to_string(i + 1) + " has an invalid plugin name: '" +
                              d::quote(name) + "'");
        if (value != "0" && value != "1")
            return unexpected("plugin." + name + " must be 0 or 1");
        if (i > 4 && name == previous)
            return unexpected("plugin." + name + " is repeated");
        if (i > 4 && name < previous)
            return unexpected("plugin." + name + " is out of order (plugin lines are ascending)");
        previous = name;
        out.plugins.emplace(name, value == "1");
    }
    for (const auto required : kSettingsCollectors) {
        if (!out.plugins.contains(std::string{required}))
            return unexpected("document is missing the plugin." + std::string{required} + " line");
    }

    if (sha256_hex(std::string{doc}) != version)
        return unexpected("version does not match the document's SHA-256");
    return out;
}

/// The hooks decide_sync_settings() drives; agent.cpp binds them to the KV store, the scheduler
/// and the collector.
struct SettingsHooks {
    /// Write one KV value; false = the write failed.
    std::function<bool(std::string_view key, std::string_view value)> persist;
    /// Make the validated, persisted settings live (scheduler cadence, collector switches, the
    /// applied-state the heartbeat tag reads). Must not throw and must not force a sync.
    std::function<void(const AgentCollectionSettings&)> apply;
};

/// Decide the reply to a `__sync__` `settings` command.
///   parse failure           -> FAILURE exit 2, the reason, nothing changed
///   daily-sync not running  -> FAILURE exit 1, nothing changed
///   a KV write fails        -> FAILURE exit 1, the previous settings stay live
///   otherwise               -> SUCCESS `applied|<version>`
/// The document is written before the version, so a crash between them leaves a pair whose hash
/// does not match; load_stored_settings() discards it and the tag reads `none`.
template <class Params>
[[nodiscard]] SyncNowDecision decide_sync_settings(const Params& params, bool inventory_disable,
                                                   bool scheduler_running,
                                                   const SettingsHooks& hooks) {
    auto parsed = parse_settings_command(params);
    if (!parsed)
        return {SyncNowDecision::Status::Failure, 2, "invalid settings: " + parsed.error()};
    if (!scheduler_running) {
        return {SyncNowDecision::Status::Failure, 1,
                inventory_disable ? "daily-sync disabled (--inventory-disable)"
                                  : "daily-sync not running (not connected)"};
    }
    const std::string document{params.find("document")->second};
    if (!hooks.persist(kSettingsKvDocumentKey, document))
        return {SyncNowDecision::Status::Failure, 1, "could not persist settings.document"};
    if (!hooks.persist(kSettingsKvVersionKey, parsed->version))
        return {SyncNowDecision::Status::Failure, 1, "could not persist settings.version"};
    hooks.apply(*parsed);
    return {SyncNowDecision::Status::Success, 0, "applied|" + parsed->version};
}

/// Start-up: read the persisted pair and validate it exactly as a live command. `kv_get(key)`
/// returns std::optional<std::string>. An absent pair is kNoStoredSettings; a document that no
/// longer matches its version (an interrupted two-write persist, a hand edit) is the parse
/// error: the caller applies nothing and reports `none`, so the server re-sends.
template <class KvGet>
[[nodiscard]] std::expected<AgentCollectionSettings, std::string> load_stored_settings(KvGet&& kv_get) {
    const std::optional<std::string> document = kv_get(std::string{kSettingsKvDocumentKey});
    const std::optional<std::string> version = kv_get(std::string{kSettingsKvVersionKey});
    if (!document && !version)
        return std::unexpected(std::string{kNoStoredSettings});
    const std::map<std::string, std::string> params{{"version", version.value_or("")},
                                                    {"document", document.value_or("")}};
    return parse_settings_command(params);
}

/// Heartbeat tags: `yuzu.inv_settings_version` is always present (the applied version, or
/// `none`); `yuzu.inv_settings_tz=machine_local` when a time zone was sent, because the window
/// runs in machine-local time and the agent does no zone conversion.
template <class TagMap>
void emit_settings_tags(TagMap& tags, const std::optional<AgentCollectionSettings>& applied) {
    tags["yuzu.inv_settings_version"] = applied ? applied->version : std::string{kSettingsVersionNone};
    if (applied && !applied->timezone.empty())
        tags["yuzu.inv_settings_tz"] = "machine_local";
}

} // namespace yuzu::agent
