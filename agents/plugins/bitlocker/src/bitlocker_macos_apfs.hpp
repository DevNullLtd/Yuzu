/**
 * bitlocker_macos_apfs.hpp — pure parser for `diskutil apfs list` output.
 *
 * Turns the text output of `diskutil apfs list` (no sudo required) into
 * per-volume FileVault/encryption records. This header does NOT execute any
 * subprocess itself — callers capture the command output and pass it in, so
 * the parser is fixture-testable (feed it a captured `diskutil apfs list`
 * transcript and assert on the parsed records) without needing a live
 * diskutil binary or an APFS volume to point it at.
 *
 * PRIVACY NOTE: per-volume disk-encryption state is a works-council /
 * privacy-sensitive signal (it reports the device's disk-encryption
 * posture). This parser only classifies encrypted / not_encrypted /
 * unknown from diskutil's own status metadata — it never reads volume
 * contents.
 *
 * No sudo, no DiskArbitration, no IOKit, no Objective-C — plain text
 * parsing of `diskutil apfs list` / `diskutil info` style "Key: Value"
 * output.
 */
#pragma once

#include <cctype>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::bitlocker::macos {

/// One APFS volume's encryption posture, as reported by `diskutil apfs list`.
struct ApfsVolumeStatus {
    std::string disk_id;         // e.g. "disk3s1"
    std::string name;            // e.g. "Macintosh HD - Data" (may be empty)
    std::string mount_point;     // e.g. "/System/Volumes/Data", or "Not Mounted"
    std::string role;            // e.g. "Data", "System", "Preboot" (raw case)
    std::string encrypted_state; // "encrypted" | "not_encrypted" | "unknown"
};

namespace detail {

inline std::string trim(std::string_view sv) {
    size_t start = 0, end = sv.size();
    while (start < end && (sv[start] == ' ' || sv[start] == '\t' || sv[start] == '|' ||
                            sv[start] == '+' || sv[start] == '-' || sv[start] == '=' ||
                            sv[start] == '>' || sv[start] == '<')) {
        ++start;
    }
    while (end > start && (sv[end - 1] == ' ' || sv[end - 1] == '\t' || sv[end - 1] == '\r')) {
        --end;
    }
    return std::string(sv.substr(start, end - start));
}

inline std::string to_lower(std::string s) {
    for (auto& c : s)
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    return s;
}

/// Extract a "disk<N>s<M>" (or bare "disk<N>") token from a line, if present.
inline std::string extract_disk_id(std::string_view line) {
    size_t pos = line.find("disk");
    while (pos != std::string_view::npos) {
        size_t i = pos + 4;
        size_t digits_start = i;
        while (i < line.size() && std::isdigit(static_cast<unsigned char>(line[i])))
            ++i;
        if (i > digits_start) {
            size_t end = i;
            if (i < line.size() && line[i] == 's') {
                size_t j = i + 1;
                size_t s_digits_start = j;
                while (j < line.size() && std::isdigit(static_cast<unsigned char>(line[j])))
                    ++j;
                if (j > s_digits_start)
                    end = j;
            }
            return std::string(line.substr(pos, end - pos));
        }
        pos = line.find("disk", pos + 1);
    }
    return {};
}

/// Pull the last "(...)" parenthetical out of a string, if any.
inline std::string extract_parenthetical(std::string_view s) {
    auto open = s.rfind('(');
    auto close = s.rfind(')');
    if (open != std::string_view::npos && close != std::string_view::npos && close > open) {
        return std::string(s.substr(open + 1, close - open - 1));
    }
    return {};
}

/// Split "key: value" on the first colon, trimming both sides. Returns false
/// if the line has no colon (not a key/value line).
inline bool split_key_value(std::string_view line, std::string& key, std::string& value) {
    auto colon = line.find(':');
    if (colon == std::string_view::npos)
        return false;
    key = trim(line.substr(0, colon));
    value = trim(line.substr(colon + 1));
    return true;
}

/// Classify a "Yes"/"No" (optionally with trailing "(Unlocked)" etc.) field
/// value into our tri-state. Empty/unrecognized input stays unclassified
/// (caller leaves the field as-is so an earlier/later key can still win).
inline std::string classify_yes_no(const std::string& value) {
    std::string v = to_lower(value);
    if (v.rfind("yes", 0) == 0)
        return "encrypted";
    if (v.rfind("no", 0) == 0)
        return "not_encrypted";
    return {};
}

} // namespace detail

/// Parse the text output of `diskutil apfs list` into per-volume records.
/// Pure text parsing only — no subprocess execution, no filesystem access.
/// Unrecognized/garbled input yields an empty vector (never fabricated
/// records); a volume whose encryption state can't be determined from the
/// text is honestly reported as "unknown", never guessed.
inline std::vector<ApfsVolumeStatus> parse_diskutil_apfs_list(const std::string& output) {
    std::vector<ApfsVolumeStatus> volumes;
    ApfsVolumeStatus current;
    bool have_current = false;

    auto flush = [&]() {
        if (have_current && !current.disk_id.empty()) {
            volumes.push_back(current);
        }
        current = ApfsVolumeStatus{};
        have_current = false;
    };

    std::istringstream iss(output);
    std::string raw_line;
    while (std::getline(iss, raw_line)) {
        std::string trimmed = detail::trim(raw_line);
        if (trimmed.empty())
            continue;

        // A new volume record starts at a "Volume diskXsY <uuid> [(Role)]"
        // header line, e.g. "+-> Volume disk3s1 7263F4B6-... (Data)".
        if (trimmed.rfind("Volume ", 0) == 0) {
            flush();
            current.disk_id = detail::extract_disk_id(trimmed);
            have_current = true;
            // Some diskutil versions put the role inline on the header line.
            current.role = detail::extract_parenthetical(trimmed);
            continue;
        }

        if (!have_current)
            continue; // key/value lines before any volume header — ignore

        std::string key, value;
        if (!detail::split_key_value(trimmed, key, value))
            continue;

        if (key == "Name") {
            current.name = value;
        } else if (key == "Mount Point") {
            current.mount_point = value;
        } else if (key.find("Role") != std::string::npos) {
            // "APFS Volume Disk (Role):   disk3s1 (Data)" — pull the role.
            auto role = detail::extract_parenthetical(value);
            if (!role.empty())
                current.role = role;
        } else if (key == "FileVault") {
            auto state = detail::classify_yes_no(value);
            if (!state.empty())
                current.encrypted_state = state;
        } else if (key == "Encrypted" && current.encrypted_state.empty()) {
            auto state = detail::classify_yes_no(value);
            if (!state.empty())
                current.encrypted_state = state;
        }
    }
    flush();

    for (auto& vol : volumes) {
        if (vol.encrypted_state.empty())
            vol.encrypted_state = "unknown";
    }
    return volumes;
}

/// Best human-facing label for a volume: prefer its Name, then its mount
/// point (if actually mounted), then fall back to the disk id.
inline std::string volume_label(const ApfsVolumeStatus& vol) {
    if (!vol.name.empty())
        return vol.name;
    if (!vol.mount_point.empty() && vol.mount_point != "Not Mounted")
        return vol.mount_point;
    if (!vol.disk_id.empty())
        return vol.disk_id;
    return "unknown";
}

/// Lowercased role (e.g. "data", "system", "preboot"), or "unknown" if
/// diskutil didn't report one — never fabricated.
inline std::string volume_type(const ApfsVolumeStatus& vol) {
    if (vol.role.empty())
        return "unknown";
    return detail::to_lower(vol.role);
}

} // namespace yuzu::bitlocker::macos
