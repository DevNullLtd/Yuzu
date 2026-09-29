#pragma once

// tar_removable_parsers.hpp -- pure core for the `removable` cursor-model TAR
// source (tar_cursor.hpp). Everything here is a free function over strings/
// structs: no OS handle, no file I/O, no framework include -- so it compiles
// and unit-tests identically on every platform (tests/unit/
// test_tar_removable.cpp), and tar_removable_collector.cpp /
// tar_removable_diskarb.mm are the only places raw XML, sysfs text, or a
// DiskArbitration description dictionary is ever handed to real OS state.
//
// Five responsibilities, matching the acceptance criteria:
//  1. Windows Partition/Diagnostic event-XML field extraction + the
//     attach/detach payload-collapse classification (README.md's discriminator
//     table -- attach and detach share EventID 1006; the payload tells them
//     apart).
//  2. Device-identity normalization (P-011): device_key uses the serial only
//     when it is non-generic; otherwise a platform-stable instance id.
//  3. Per-channel cursor JSON encode/decode + wrap/gap decisions.
//  4. exec-from-removable path-prefix decision (P-004: exec_path only).
//  5. The macOS DiskArbitration session INTERFACE (no framework symbols --
//     implemented in tar_removable_diskarb.mm) so tar_removable_collector.cpp
//     can drive it without any Objective-C in a .cpp translation unit.

#include <nlohmann/json.hpp>

#include <yuzu/agent/process_enum.hpp> // yuzu::agent::ProcessInfo -- typed field only, no OS call

#include <cctype>
#include <cstdint>
#include <format>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <unordered_map>
#include <unordered_set>
#include <vector>

namespace yuzu::tar {

// ── Retrospective backfill default (tar_cursor.hpp rule 5) ─────────────────
// Same shape as netconn_lookback_seconds (ADR-0020): 7 days, 0 = forward-only.
inline constexpr std::int64_t kDefaultRemovableLookbackSeconds = 604800;

namespace removable_detail {

/// Text content of <Tag>...</Tag> (first occurrence only).
inline std::string_view xml_elem_text(std::string_view xml, std::string_view tag) {
    const std::string open = "<" + std::string(tag) + ">";
    const std::string close = "</" + std::string(tag) + ">";
    const auto opos = xml.find(open);
    if (opos == std::string_view::npos)
        return {};
    const auto start = opos + open.size();
    const auto end = xml.find(close, start);
    return end == std::string_view::npos ? std::string_view{} : xml.substr(start, end - start);
}

/// Value of attr='...' inside the first <Tag .../> or <Tag ...> occurrence.
inline std::string_view xml_elem_attr(std::string_view xml, std::string_view tag,
                                      std::string_view attr) {
    const std::string tag_open = "<" + std::string(tag) + " ";
    const auto tpos = xml.find(tag_open);
    if (tpos == std::string_view::npos)
        return {};
    const auto tag_end = xml.find('>', tpos);
    if (tag_end == std::string_view::npos)
        return {};
    const std::string_view tag_span = xml.substr(tpos, tag_end - tpos);
    const std::string needle = std::string(attr) + "='";
    const auto apos = tag_span.find(needle);
    if (apos == std::string_view::npos)
        return {};
    const auto start = apos + needle.size();
    const auto end = tag_span.find('\'', start);
    return end == std::string_view::npos ? std::string_view{} : tag_span.substr(start, end - start);
}

/// Text content of <Data Name='name'>...</Data> -- the EventData allow-list
/// gate, same shape as tar_netconn.hpp's xml_data_value.
inline std::string_view xml_data_value(std::string_view xml, std::string_view name) {
    const std::string open = "<Data Name='" + std::string(name) + "'>";
    const auto opos = xml.find(open);
    if (opos == std::string_view::npos)
        return {};
    const auto start = opos + open.size();
    const auto end = xml.find("</Data>", start);
    return end == std::string_view::npos ? std::string_view{} : xml.substr(start, end - start);
}

/// Decode the five XML 1.0 predefined entities in one left-to-right pass.
///
/// This is load-bearing, not cosmetic: EVERY Windows PnP device instance path
/// contains '&' (e.g. `USB\VID_0951&PID_1666\E0D55EA574A4E57049410200`), which
/// the event XML carries escaped as `&amp;`. A raw substring read therefore
/// stores a corrupted identifier — and ParentId is exactly the platform-stable
/// instance id device_key falls back to when a device reports no usable serial,
/// so an undecoded value silently splits or collides device identity. Caught by
/// the REAL the-rig capture; a hand-written fixture would have agreed with the
/// bug. One pass (rather than sequential replaces) so a literal `&amp;amp;` in
/// the source text decodes to `&amp;` and never to `&`.
inline std::string xml_unescape(std::string_view s) {
    std::string out;
    out.reserve(s.size());
    for (std::size_t i = 0; i < s.size();) {
        if (s[i] != '&') {
            out.push_back(s[i++]);
            continue;
        }
        const auto semi = s.find(';', i + 1);
        // Cap the scan: an unterminated '&' is literal text, not an entity.
        if (semi == std::string_view::npos || semi - i > 6) {
            out.push_back(s[i++]);
            continue;
        }
        const std::string_view ent = s.substr(i, semi - i + 1);
        if (ent == "&amp;")       out.push_back('&');
        else if (ent == "&lt;")   out.push_back('<');
        else if (ent == "&gt;")   out.push_back('>');
        else if (ent == "&quot;") out.push_back('"');
        else if (ent == "&apos;") out.push_back('\'');
        else { out.push_back(s[i++]); continue; }  // unknown entity: literal '&'
        i = semi + 1;
    }
    return out;
}

/// Text content of a <Data Name='...'> field with XML entities decoded — use
/// this for every field that can carry human/device text. Numeric and boolean
/// fields keep using xml_data_value's zero-copy view.
inline std::string xml_data_text(std::string_view xml, std::string_view name) {
    return xml_unescape(xml_data_value(xml, name));
}

inline std::int64_t to_i64(std::string_view s, std::int64_t fallback = 0) {
    if (s.empty())
        return fallback;
    std::int64_t v = fallback;
    bool neg = false;
    std::size_t i = 0;
    if (s[0] == '-') {
        neg = true;
        i = 1;
    }
    std::int64_t acc = 0;
    bool any = false;
    for (; i < s.size(); ++i) {
        if (s[i] < '0' || s[i] > '9')
            return fallback;
        acc = acc * 10 + (s[i] - '0');
        any = true;
    }
    if (!any)
        return fallback;
    v = neg ? -acc : acc;
    return v;
}

inline bool to_bool(std::string_view s) { return s == "true" || s == "1"; }

// Days-from-civil (Howard Hinnant's algorithm), matching tar_netconn.hpp's
// own copy -- duplicated here rather than included so this header stays
// dependency-free (P-006: no cross-package include beyond nlohmann/json).
inline std::int64_t days_from_civil(std::int64_t y, unsigned m, unsigned d) {
    y -= m <= 2;
    const std::int64_t era = (y >= 0 ? y : y - 399) / 400;
    const unsigned yoe = static_cast<unsigned>(y - era * 400);
    const unsigned doy = (153 * (m + (m > 2 ? -3 : 9)) + 2) / 5 + d - 1;
    const unsigned doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    return era * 146097 + static_cast<std::int64_t>(doe) - 719468;
}

} // namespace removable_detail

/// Parse an EvtRender/wevtutil ISO-8601 UTC timestamp
/// ('2026-09-04T10:06:24.2284397Z') into Unix epoch seconds. 0 on mismatch.
inline std::int64_t parse_removable_event_time(std::string_view s) {
    using removable_detail::to_i64;
    if (s.size() < 19 || s[4] != '-' || s[7] != '-' || s[10] != 'T' || s[13] != ':' ||
        s[16] != ':')
        return 0;
    const auto y = to_i64(s.substr(0, 4), -1);
    const auto mo = to_i64(s.substr(5, 2), -1);
    const auto d = to_i64(s.substr(8, 2), -1);
    const auto h = to_i64(s.substr(11, 2), -1);
    const auto mi = to_i64(s.substr(14, 2), -1);
    const auto sec = to_i64(s.substr(17, 2), -1);
    if (y < 1970 || mo < 1 || mo > 12 || d < 1 || d > 31 || h < 0 || h > 23 || mi < 0 ||
        mi > 59 || sec < 0 || sec > 60)
        return 0;
    return removable_detail::days_from_civil(y, static_cast<unsigned>(mo),
                                              static_cast<unsigned>(d)) *
               86400 +
           h * 3600 + mi * 60 + sec;
}

/// Format epoch seconds as the ISO-8601 UTC literal EvtQuery XPath compares
/// @SystemTime against, mirroring tar_netconn.hpp's format_event_systemtime.
inline std::string format_removable_event_time(std::int64_t epoch_s) {
    if (epoch_s < 0)
        epoch_s = 0;
    std::int64_t days = epoch_s / 86400;
    std::int64_t rem = epoch_s % 86400;
    days += 719468;
    const std::int64_t era = (days >= 0 ? days : days - 146096) / 146097;
    const unsigned doe = static_cast<unsigned>(days - era * 146097);
    const unsigned yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    const std::int64_t y = static_cast<std::int64_t>(yoe) + era * 400;
    const unsigned doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    const unsigned mp = (5 * doy + 2) / 153;
    const unsigned d = doy - (153 * mp + 2) / 5 + 1;
    const unsigned m = mp + (mp < 10 ? 3 : -9);
    // R-021: no printf-family calls (docs/cpp-conventions.md) — std::format.
    return std::format("{:04d}-{:02d}-{:02d}T{:02d}:{:02d}:{:02d}.000Z",
                       static_cast<long long>(y + (m <= 2)), m, d,
                       static_cast<long long>(rem / 3600), static_cast<long long>((rem % 3600) / 60),
                       static_cast<long long>(rem % 60));
}

// ── 1. Microsoft-Windows-Partition/Diagnostic (ID 1006) ────────────────────

/// One parsed Partition/Diagnostic 1006 record. Identity authority for
/// Windows removable-media capture (README.md's discriminator table).
struct PartitionDiagnosticRecord {
    std::int64_t event_record_id{0};
    std::int64_t ts{0};
    std::string bus_type; // "7"=USB, "17"=NVMe, ... raw as captured
    std::string manufacturer;
    std::string model;
    std::string revision;
    std::string serial_number;
    std::string parent_id; // Windows PnP device instance path
    std::string disk_id;   // stable GUID correlating attach+detach pair
    std::int64_t capacity{0};
    std::int64_t bytes_per_sector{0};
    std::int64_t partition_count{0};
    bool user_removal_policy{false};
};

/// PURE: one rendered Partition/Diagnostic event XML -> one record, or
/// nullopt if it isn't EventID 1006 / the timestamp doesn't parse.
inline std::optional<PartitionDiagnosticRecord> parse_partition_diagnostic_xml(std::string_view xml) {
    using namespace removable_detail;
    if (to_i64(xml_elem_text(xml, "EventID"), -1) != 1006)
        return std::nullopt;
    const auto ts = parse_removable_event_time(xml_elem_attr(xml, "TimeCreated", "SystemTime"));
    if (ts == 0)
        return std::nullopt;

    PartitionDiagnosticRecord r;
    r.event_record_id = to_i64(xml_elem_text(xml, "EventRecordID"), 0);
    r.ts = ts;
    r.bus_type = std::string(xml_data_value(xml, "BusType"));
    r.manufacturer = xml_data_text(xml, "Manufacturer");
    r.model = xml_data_text(xml, "Model");
    r.revision = xml_data_text(xml, "Revision");
    r.serial_number = xml_data_text(xml, "SerialNumber");
    r.parent_id = xml_data_text(xml, "ParentId");
    r.disk_id = xml_data_text(xml, "DiskId");
    r.capacity = to_i64(xml_data_value(xml, "Capacity"), 0);
    r.bytes_per_sector = to_i64(xml_data_value(xml, "BytesPerSector"), 0);
    r.partition_count = to_i64(xml_data_value(xml, "PartitionCount"), 0);
    r.user_removal_policy = to_bool(xml_data_value(xml, "UserRemovalPolicy"));
    return r;
}

/// USB = 7 (README.md discriminator #2). BusType 17 (NVMe) and every other
/// internal bus must be excluded before a record ever reaches the DB.
inline bool is_removable_bus_type(std::string_view bus_type) { return bus_type == "7"; }

enum class PartitionTransition { kAttach, kDetach };

/// PAYLOAD-COLLAPSE classification (README.md discriminator #1): attach and
/// detach share EventID 1006 and even SerialNumber/DiskId -- the transition
/// is told apart ONLY by the zeroed-out capacity/geometry/UserRemovalPolicy
/// on detach. Keying on event id alone misreads a detach as a second attach
/// of a zero-byte disk.
inline PartitionTransition classify_partition_transition(const PartitionDiagnosticRecord& r) {
    if (r.capacity == 0 && r.bytes_per_sector == 0 && r.partition_count == 0 &&
        !r.user_removal_policy)
        return PartitionTransition::kDetach;
    return PartitionTransition::kAttach;
}

/// Generic EventRecordID extraction, used for the corroboration channels
/// (Kernel-PnP/Configuration, Storsvc/Diagnostic) whose cursor still advances
/// per-channel even though they emit no RemovableEvent rows of their own.
inline std::optional<std::int64_t> extract_event_record_id(std::string_view xml) {
    const auto v = removable_detail::xml_elem_text(xml, "EventRecordID");
    if (v.empty())
        return std::nullopt;
    return removable_detail::to_i64(v, -1) >= 0
              ? std::optional<std::int64_t>(removable_detail::to_i64(v, -1))
              : std::nullopt;
}

// ── 2. Device identity (P-011) ──────────────────────────────────────────────

/// SCSI-INQUIRY fixed-width identity fields (VendorId/ProductId/
/// SerialNumber) are ASCII SPACE-padded to their declared width (SPC), not
/// NUL-padded — a driver that copies the raw INQUIRY bytes without its own
/// NUL-termination leaves that padding in place. Measured on real hardware
/// (PR #4023 review): Windows' STORAGE_DEVICE_DESCRIPTOR reported
/// `product="STORE N GO      "` (6 trailing spaces) for a device the
/// event-log leg's XML-sourced fields — which carry no such padding —
/// reported as `product="STORE N GO"`. Two representations of one string
/// split compute_device_key's cross-leg agreement (the very invariant
/// tar_removable_collector.cpp's C7 comment describes), because the two legs
/// then disagree on a byte a human would call the same device.
///
/// Trims trailing space ONLY. A vendor/product string can legitimately
/// contain internal spaces ("DataTraveler 3.0", "STORE N GO" itself) — the
/// padding is by construction only ever appended after the real content, so
/// anything but a trailing-only trim risks corrupting a genuine name.
inline std::string trim_trailing_scsi_padding(std::string s) {
    while (!s.empty() && s.back() == ' ')
        s.pop_back();
    return s;
}

/// A serial is "generic" (untrustworthy as identity) when empty, all
/// whitespace, or all-zero/all-'0' digits (some USB controllers report a
/// fixed placeholder like "000000000000" for every unit of a cheap model).
inline bool is_generic_serial(std::string_view serial) {
    if (serial.empty())
        return true;
    bool all_ws = true;
    bool all_zero_char = true;
    for (unsigned char c : serial) {
        if (!(c == ' ' || c == '\t' || c == '\r' || c == '\n'))
            all_ws = false;
        if (c != '0')
            all_zero_char = false;
    }
    return all_ws || all_zero_char;
}

inline std::uint64_t fnv1a64(std::string_view s) {
    std::uint64_t h = 14695981039346656037ull;
    for (unsigned char c : s) {
        h ^= c;
        h *= 1099511628211ull;
    }
    return h;
}

inline std::string hex64(std::uint64_t v) {
    return std::format("{:016x}", v); // R-021: no printf-family calls
}

struct DeviceKeyResult {
    std::string device_key;
    bool used_serial{false}; // false => anonymous-serial fallback was used
};

/// device_key = hash(vendor|product|serial) ONLY for a non-generic serial;
/// otherwise hash(vendor|product|<platform_instance_id>) -- Windows PnP
/// instance path / volume STORAGE_DEVICE_NUMBER path, macOS
/// kDADiskDescriptionMediaUUIDKey else BSD name, Linux sysfs device path (+
/// wwid where present). `used_serial=false` is the evidence-column marker
/// the acceptance criteria require: two identical anonymous devices with the
/// same platform_instance_id (e.g. re-enumerated at the same USB port after
/// the OS reuses the instance path) will collide under this fallback -- a
/// residual limitation documented in docs/user-manual/tar-removable.md, not
/// silently hidden.
inline DeviceKeyResult compute_device_key(std::string_view vendor, std::string_view product,
                                          std::string_view serial,
                                          std::string_view platform_instance_id) {
    DeviceKeyResult r;
    std::string basis;
    basis.reserve(vendor.size() + product.size() + serial.size() + platform_instance_id.size() + 2);
    basis.append(vendor).push_back('|');
    basis.append(product).push_back('|');
    if (!is_generic_serial(serial)) {
        basis.append(serial);
        r.used_serial = true;
    } else {
        basis.append(platform_instance_id);
        r.used_serial = false;
    }
    r.device_key = hex64(fnv1a64(basis));
    return r;
}

/// A serial reported by MORE THAN ONE distinct PnP ParentId within one
/// observation batch is a physically shared/placeholder serial, not a
/// trustworthy per-device identity — is_generic_serial() cannot catch this
/// because it looks at one serial string in isolation, and this one is not
/// empty/whitespace/all-zero. Measured on real hardware (PR #4023 review,
/// DGRHP): a multi-format card reader exposes two physically distinct
/// USBSTOR LUNs that both report the identical serial "000000002958", each
/// with its own ParentId. compute_device_key collapsed both onto one
/// device_key; the real 7-day lookback replay recorded three real
/// transitions as six rows — for the acceptance criteria's own "exactly ONE
/// attached row per physical stick" requirement.
///
/// Scoped to ONE batch (one collect() tick's channel read), not persisted
/// across restarts or ticks: the failure this closes is a multi-LUN reader
/// whose LUNs enumerate together on physical insertion and land in the SAME
/// batch — measured, both LUNs' attach records shared one timestamp. A LUN
/// that first appears in a batch well after its sibling (a much narrower
/// case) is a residual this does not close; matching the existing
/// anonymous-serial-fallback limitation's own "best-effort, not absolute"
/// posture (docs/user-manual/tar-removable.md) rather than adding new
/// cross-restart persisted state to chase it.
///
/// Returns the "vendor\x1fmodel\x1fserial" identities found shared. The
/// caller re-derives device_key for an affected record with an EMPTY serial
/// (the same anonymous-fallback path is_generic_serial's empty-string case
/// already takes) rather than this function mutating anything itself.
inline std::unordered_set<std::string>
shared_serials_in_batch(const std::vector<PartitionDiagnosticRecord>& records) {
    std::unordered_map<std::string, std::unordered_set<std::string>> parent_ids_by_identity;
    for (const auto& r : records) {
        if (r.serial_number.empty())
            continue; // is_generic_serial already refuses an empty serial on its own
        parent_ids_by_identity[r.manufacturer + "\x1f" + r.model + "\x1f" + r.serial_number]
           .insert(r.parent_id);
    }
    std::unordered_set<std::string> shared;
    for (const auto& [identity, parent_ids] : parent_ids_by_identity)
        if (parent_ids.size() > 1)
            shared.insert(identity);
    return shared;
}

// ── 3. Per-channel cursor JSON + wrap/gap decisions ─────────────────────────

struct RemovableChannelCursor {
    std::int64_t record_id{0};
};

/// cursor_json shape (tar_cursor.hpp rule 4): {"v":1,"channels":{"<channel>":
/// {"record_id":N}},"attach_set":{"<device_key>":true,...},"baseline_done":
/// true}. One row per source name ("removable"), never one per channel.
struct RemovableCursorState {
    int v{1};
    std::map<std::string, RemovableChannelCursor> channels;
    std::map<std::string, bool> attach_set;
    // K1: the (device_key, image_path) pairs already REPORTED as
    // exec_from_removable. The exec record_key is deliberately stable for a
    // pair -- one row per execution observed on a device, not one per tick --
    // so the emission must be gated on this set, or every later tick re-derives
    // the same key with a fresh ts, the seam's replay check sees a differing
    // payload, and the whole event+cursor transaction is refused. That refusal
    // repeats every tick for as long as the process runs, taking every other
    // event in the batch down with it. Persisted, so it survives a restart;
    // cleared per device on detach, so a re-attach reports afresh.
    std::set<std::string> exec_seen; // "<device_key>\x1f<image_path>"
    // C7: device_keys the Windows SNAPSHOT leg is able to express -- i.e. those
    // derived from a trusted serial, which is exactly when compute_device_key
    // ignores the platform instance id and the two legs agree by construction.
    // A key from the event leg for an ANONYMOUS device is keyed on the PnP
    // ParentId, which the snapshot cannot reproduce, so the snapshot must never
    // conclude that such a device has detached merely because it cannot see it.
    std::set<std::string> snapshot_keyed;
    // device_key -> the epoch second at which this attach session began. Scopes
    // the exec record_key (see removable_exec_record_key) so a re-attach is a
    // new session rather than a colliding replay of the old one.
    std::map<std::string, std::int64_t> attach_epoch;
    bool baseline_done{false};
    // R-005: distinguishes "never persisted" (nullopt/empty cursor_json --
    // a genuine first-ever run, tar_cursor.hpp rule 2's Baseline case) from
    // "was persisted but failed to parse" (rule 2's explicit CursorLost
    // case: "the cursor JSON fails to parse"). The collector uses this to
    // emit a capture_gap and report CursorOutcome::CursorLost instead of
    // silently reporting an ordinary Baseline/Advanced tick for a real loss.
    bool malformed{false};
};

/// PURE decode. nullopt/empty is "never persisted" (fresh
/// RemovableCursorState{}, malformed=false) -- an ordinary first run.
/// Unparseable JSON is a LOST cursor (tar_cursor.hpp rule 2): the returned
/// state is still a fresh RemovableCursorState{} (recoverable by
/// re-baselining, never a thrown error), but malformed=true so the caller
/// reports the loss via CursorOutcome::CursorLost + a capture_gap event
/// rather than silently treating it as an ordinary Baseline tick.
inline RemovableCursorState decode_removable_cursor(const std::optional<std::string>& cursor_json) {
    RemovableCursorState st;
    if (!cursor_json || cursor_json->empty())
        return st;
    try {
        const auto j = nlohmann::json::parse(*cursor_json);
        st.baseline_done = j.value("baseline_done", false);
        if (j.contains("channels") && j["channels"].is_object()) {
            for (auto it = j["channels"].begin(); it != j["channels"].end(); ++it)
                st.channels[it.key()].record_id = it.value().value("record_id", std::int64_t{0});
        }
        if (j.contains("attach_set") && j["attach_set"].is_object()) {
            for (auto it = j["attach_set"].begin(); it != j["attach_set"].end(); ++it)
                st.attach_set[it.key()] = it.value().is_boolean() ? it.value().get<bool>() : true;
        }
        if (j.contains("exec_seen") && j["exec_seen"].is_array()) {
            for (const auto& e : j["exec_seen"])
                if (e.is_string())
                    st.exec_seen.insert(e.get<std::string>());
        }
        if (j.contains("snapshot_keyed") && j["snapshot_keyed"].is_array()) {
            for (const auto& e : j["snapshot_keyed"])
                if (e.is_string())
                    st.snapshot_keyed.insert(e.get<std::string>());
        }
        if (j.contains("attach_epoch") && j["attach_epoch"].is_object()) {
            for (auto it = j["attach_epoch"].begin(); it != j["attach_epoch"].end(); ++it)
                if (it.value().is_number_integer())
                    st.attach_epoch[it.key()] = it.value().get<std::int64_t>();
        }
    } catch (const nlohmann::json::exception&) {
        RemovableCursorState lost;
        lost.malformed = true; // R-005: a persisted-but-unparseable cursor is CursorLost, not Baseline
        return lost;
    }
    return st;
}

inline std::string encode_removable_cursor(const RemovableCursorState& st) {
    nlohmann::json j;
    j["v"] = 1;
    j["baseline_done"] = st.baseline_done;
    nlohmann::json channels = nlohmann::json::object();
    for (const auto& [name, c] : st.channels)
        channels[name] = {{"record_id", c.record_id}};
    j["channels"] = channels;
    nlohmann::json attach_set = nlohmann::json::object();
    for (const auto& [key, present] : st.attach_set)
        attach_set[key] = present;
    j["attach_set"] = attach_set;
    j["exec_seen"] = nlohmann::json(st.exec_seen);
    j["snapshot_keyed"] = nlohmann::json(st.snapshot_keyed);
    nlohmann::json epochs = nlohmann::json::object();
    for (const auto& [k, e] : st.attach_epoch)
        epochs[k] = e;
    j["attach_epoch"] = epochs;
    // Never let a path decide whether the cursor can be written.
    //
    // exec_seen holds ProcessInfo::exec_path verbatim, and on Linux that is raw
    // bytes from /proc/<pid>/exe -- a binary on a FAT/exFAT stick can carry a
    // name that is not valid UTF-8. nlohmann's default dump() THROWS on that,
    // and the throw lands on collect()'s path: the tick is lost, and so is
    // every retry, for as long as that process runs. The contract also says
    // collect() throws only IncompleteCaptureError, which this would not be.
    // Replacing the invalid bytes keeps the cursor writable; the affected entry
    // is a dedupe key, not evidence, and the row itself carries the real path.
    return j.dump(-1, ' ', false, nlohmann::json::error_handler_t::replace);
}

/// A channel has WRAPPED (tar_cursor.hpp rule 2) when the stored cursor
/// position is older than the oldest record the channel currently retains --
/// the measured 1432->1352 Kernel-PnP/Configuration eviction in
/// runDir/fixtures is a real instance, not a hypothetical.
inline bool channel_cursor_wrapped(std::int64_t stored_record_id,
                                   std::int64_t oldest_retained_record_id) {
    // The boundary is the FIRST UNREAD record, not the stored one. The channel
    // is read with `EventRecordID > stored` (exclusive), so the next record we
    // owe is `stored + 1`; nothing is lost until the oldest retained record is
    // past it. Comparing against `stored` itself declared a wrap in the ordinary
    // healthy case -- retention had removed everything through the record we had
    // already committed, exactly as intended -- and the collector responded by
    // jumping the cursor to the head, skipping the very record it was about to
    // read. The false wrap thus CAUSED the loss it reported.
    // Written as a subtraction on the right so a stored id at the top of the
    // range cannot overflow.
    return oldest_retained_record_id > 0 && stored_record_id < oldest_retained_record_id - 1;
}

// ── record_key builders (replay idempotence, tar_cursor.hpp rule 3) ────────

inline std::string removable_baseline_record_key(std::string_view device_key) {
    return "baseline:" + std::string(device_key);
}

/// Scoped to the ATTACH SESSION, not just the device.
///
/// The key must be stable while a device stays attached -- one row per
/// execution observed, and a retry after a failed commit must dedupe. But it
/// must DIFFER across attach sessions: unplugging and replugging the stick and
/// running the same binary again is a genuinely new observation, and if it
/// re-derived the previous session's key with a new ts the store would read the
/// differing payload as a collision and refuse the batch on every tick -- the
/// same wedge the exec_seen gate exists to prevent, reached through the
/// detach-clears-exec_seen path instead.
inline std::string removable_exec_record_key(std::string_view device_key,
                                             std::int64_t attach_epoch,
                                             std::string_view image_path) {
    return "exec:" + std::string(device_key) + ":" + std::to_string(attach_epoch) + ":" +
           std::string(image_path);
}

inline std::string removable_channel_record_key(std::string_view channel,
                                                 std::int64_t event_record_id) {
    return "chan:" + std::string(channel) + ":" + std::to_string(event_record_id);
}

// ── 4. exec-from-removable path-prefix decision (P-004) ────────────────────

/// True iff `exec_path` resolves under `volume_root` (a currently-attached
/// removable volume's mount point). `exec_path` MUST already be
/// ProcessInfo::exec_path (never cmdline -- Linux NUL-flattens argv, making
/// cmdline unusable as a path). An empty exec_path always returns false, so
/// "process enumeration couldn't resolve the binary" never becomes a claim.
///
/// `case_insensitive` (R-016): Linux filesystems are case-sensitive by
/// default, so an exact byte comparison is correct there; Windows (NTFS) and
/// macOS (APFS's default case-insensitive-preserving mode) are not, and a
/// byte-exact comparison there produces ordinary false negatives whenever
/// the OS reports a path with different casing than the mount root string
/// this source captured. The caller selects the platform-appropriate value
/// (append_exec_from_removable in tar_removable_collector.cpp) -- this
/// function has no platform knowledge of its own.
/// `backslash_is_separator` MUST be false on POSIX. On Linux and macOS a
/// backslash is an ordinary filename character, so accepting it as a boundary
/// makes `/media/user/USB\decoy` -- a SIBLING file in `/media/user/`, not
/// anything under the mount -- match the root `/media/user/USB`. Where the
/// mount parent is writable that is a way to plant forensic evidence against a
/// device the binary never ran from. It defaults to the case-insensitivity
/// flag because the two travel together in practice (Windows paths are
/// case-insensitive AND backslash-separated), but it is a separate parameter so
/// a caller can never silently get one without meaning the other.
inline bool exec_path_under_removable_root(std::string_view exec_path, std::string_view volume_root,
                                           bool case_insensitive = false,
                                           bool backslash_is_separator = false) {
    if (exec_path.empty() || volume_root.empty())
        return false;
    std::string root(volume_root);
    while (!root.empty() && (root.back() == '/' || root.back() == '\\'))
        root.pop_back();
    if (root.empty() || exec_path.size() < root.size())
        return false;
    auto ascii_eq = [case_insensitive](char a, char b) {
        if (case_insensitive) {
            a = static_cast<char>(std::tolower(static_cast<unsigned char>(a)));
            b = static_cast<char>(std::tolower(static_cast<unsigned char>(b)));
        }
        return a == b;
    };
    for (std::size_t i = 0; i < root.size(); ++i) {
        if (!ascii_eq(exec_path[i], root[i]))
            return false;
    }
    if (exec_path.size() == root.size())
        return true;
    const char next = exec_path[root.size()];
    return next == '/' || (backslash_is_separator && next == '\\');
}

/// One exec-from-removable claim, already reduced to the typed fields
/// RemovableEvent needs (image_path, pid) plus the device it matched.
struct ExecFromRemovableMatch {
    std::string device_key;
    std::string image_path;
    std::int64_t pid{0};
};

/// PURE decision core for exec-from-removable (P-004, R-013): given
/// already-enumerated (pid, exec_path) pairs and the currently-attached
/// removable roots, returns one match per process whose exec_path resolves
/// under a root (first matching root wins -- one claim per process, mirrors
/// the collector's prior inline behaviour). The CALLER is responsible for
/// sourcing `exec_path` from ProcessInfo::exec_path ONLY, never cmdline --
/// pulling the matching decision out to a pure function here (rather than
/// leaving it embedded next to the live process_enum() call) makes it
/// testable without a live process enumeration, so a fixture-driven test can
/// assert an empty exec_path never matches and a populated one produces the
/// typed device_key/image_path/pid a future regression at the collector's
/// field-selection line (exec_path -> cmdline) would otherwise not be
/// caught by any test.
inline std::vector<ExecFromRemovableMatch>
select_exec_from_removable(const std::vector<std::pair<std::int64_t, std::string>>& pid_exec_paths,
                           const std::vector<std::pair<std::string, std::string>>& attached_roots,
                           bool case_insensitive = false) {
    std::vector<ExecFromRemovableMatch> out;
    if (attached_roots.empty())
        return out;
    for (const auto& [pid, exec_path] : pid_exec_paths) {
        if (exec_path.empty())
            continue; // P-004: no exec_path, no claim
        for (const auto& [device_key, root] : attached_roots) {
            if (!exec_path_under_removable_root(exec_path, root, case_insensitive,
                                                /*backslash_is_separator=*/case_insensitive))
                continue;
            out.push_back(ExecFromRemovableMatch{device_key, exec_path, pid});
            break; // one matching device is enough per process
        }
    }
    return out;
}

/// R-013 (fix round): the collector's own field-selection line -- reading
/// ProcessInfo::exec_path, NEVER ::cmdline (P-004) -- pulled out of
/// tar_removable_collector.cpp::append_exec_from_removable into this pure
/// function so a fixture-driven test can inject a
/// vector<yuzu::agent::ProcessInfo> directly (no live process_enum() call)
/// and catch a regression AT THE COLLECTOR BOUNDARY where that field is
/// chosen -- not just in select_exec_from_removable's already-reduced
/// (pid, exec_path) pairs, which can't see the selection mistake because the
/// wrong field was never fed to it. The collector's ONLY remaining job is
/// calling this with a live yuzu::agent::enumerate_processes() result and
/// the platform's case-sensitivity flag.
inline std::vector<ExecFromRemovableMatch>
select_exec_from_removable_processes(const std::vector<yuzu::agent::ProcessInfo>& processes,
                                     const std::vector<std::pair<std::string, std::string>>& attached_roots,
                                     bool case_insensitive = false) {
    std::vector<std::pair<std::int64_t, std::string>> pid_exec_paths;
    pid_exec_paths.reserve(processes.size());
    for (const auto& proc : processes)
        pid_exec_paths.emplace_back(static_cast<std::int64_t>(proc.pid),
                                    proc.exec_path); // P-004: exec_path only, never cmdline
    return select_exec_from_removable(pid_exec_paths, attached_roots, case_insensitive);
}

// ── Linux: udev/kobject netlink uevent parsing ──────────────────────────────
// Pure parse of one NETLINK_KOBJECT_UEVENT datagram body
// ("ACTION@/devpath\0KEY=VAL\0KEY=VAL\0...", NUL-separated, no trailing NUL
// guaranteed) -- kept here (not tar_removable_collector.cpp) because the wire
// format is exactly a string-splitting problem, unit-testable without a real
// netlink socket.
struct UeventRecord {
    std::string action; // "add" | "remove" | ... (whatever precedes '@')
    std::string devpath;
    std::map<std::string, std::string> kv; // SUBSYSTEM, DEVTYPE, DEVNAME, ...
};

inline std::optional<UeventRecord> parse_uevent_message(std::string_view raw) {
    if (raw.empty())
        return std::nullopt;
    // Split on NUL. The first token is "ACTION@/devpath"; the rest are
    // "KEY=VALUE" pairs (libudev's monitor also prepends a "libudev" tag
    // record on some kernels -- if the first token has no '@', treat as
    // unparseable rather than guess).
    std::vector<std::string_view> tokens;
    std::size_t start = 0;
    for (std::size_t i = 0; i <= raw.size(); ++i) {
        if (i == raw.size() || raw[i] == '\0') {
            if (i > start)
                tokens.push_back(raw.substr(start, i - start));
            start = i + 1;
        }
    }
    if (tokens.empty())
        return std::nullopt;
    const auto at = tokens[0].find('@');
    if (at == std::string_view::npos)
        return std::nullopt;

    UeventRecord rec;
    rec.action = std::string(tokens[0].substr(0, at));
    rec.devpath = std::string(tokens[0].substr(at + 1));
    for (std::size_t i = 1; i < tokens.size(); ++i) {
        const auto eq = tokens[i].find('=');
        if (eq == std::string_view::npos)
            continue;
        rec.kv.emplace(std::string(tokens[i].substr(0, eq)), std::string(tokens[i].substr(eq + 1)));
    }
    return rec;
}

/// True iff a parsed uevent is an add/remove of a whole block DISK (not a
/// partition, not a non-block subsystem) -- the only uevents this source
/// tracks. `DEVTYPE=disk` excludes partition sub-devices (`DEVTYPE=partition`)
/// the same way BusType==7 excludes non-USB on Windows.
inline bool is_block_disk_uevent(const UeventRecord& rec) {
    const auto sub = rec.kv.find("SUBSYSTEM");
    const auto devtype = rec.kv.find("DEVTYPE");
    if (sub == rec.kv.end() || sub->second != "block")
        return false;
    if (devtype == rec.kv.end() || devtype->second != "disk")
        return false;
    return rec.action == "add" || rec.action == "remove";
}

// ── Linux: /proc/mounts exec-from-removable correlation (respec amendment,
// 2026-09-04) ────────────────────────────────────────────────────────────
// Maps a partition devnode name to its parent whole-disk devnode name, so a
// `/proc/mounts` row mounting a removable device's partition can be matched
// against the disk-level identity this source already tracks
// (linux_known_devices_ in tar_removable_collector.cpp, disk name ->
// device_key). `devnode_name` is the bare name with no "/dev/" prefix.
inline std::string linux_parent_block_device(std::string_view devnode_name) {
    if (devnode_name.empty())
        return {};
    std::size_t digit_start = devnode_name.size();
    while (digit_start > 0 &&
          std::isdigit(static_cast<unsigned char>(devnode_name[digit_start - 1])))
        --digit_start;
    if (digit_start == devnode_name.size())
        return std::string(devnode_name); // no trailing digits -> maps to itself
    // nvme0n1p2 / mmcblk0p1: a trailing "p<digits>" whose preceding char is
    // itself a digit strips back to the whole-disk name (the base disk name
    // ends in a digit for both nvme and mmcblk naming schemes).
    if (digit_start >= 2 && devnode_name[digit_start - 1] == 'p' &&
        std::isdigit(static_cast<unsigned char>(devnode_name[digit_start - 2])))
        return std::string(devnode_name.substr(0, digit_start - 1));
    // sdb1 -> sdb: otherwise strip the trailing digit run only.
    return std::string(devnode_name.substr(0, digit_start));
}

/// (device_key, mount_root) pairs correlated from a /proc/mounts read, plus
/// whether any structurally short row was skipped (never a throw -- mirrors
/// tar_mapdrive_collector.cpp's parse_proc_mounts BR-mapdrive-001 policy).
struct RemovableMountCorrelation {
    std::vector<std::pair<std::string, std::string>> pairs;
    bool malformed{false};
};

namespace removable_detail {

/// Decode the kernel's octal escapes in a /proc/mounts field (space=\040,
/// tab=\011, newline=\012, backslash=\134) -- same decode contract as
/// tar_mapdrive_collector.cpp::decode_mount_escapes, reimplemented locally
/// per the owned-files boundary (do not include that file from here).
inline std::string decode_proc_mounts_field(std::string_view in) {
    std::string out;
    out.reserve(in.size());
    for (std::size_t i = 0; i < in.size(); ++i) {
        if (in[i] == '\\' && i + 3 < in.size() &&
            std::isdigit(static_cast<unsigned char>(in[i + 1])) &&
            std::isdigit(static_cast<unsigned char>(in[i + 2])) &&
            std::isdigit(static_cast<unsigned char>(in[i + 3]))) {
            const int v = (in[i + 1] - '0') * 64 + (in[i + 2] - '0') * 8 + (in[i + 3] - '0');
            out.push_back(static_cast<char>(v));
            i += 3;
        } else {
            out.push_back(in[i]);
        }
    }
    return out;
}

} // namespace removable_detail

/// PURE: correlate `/proc/mounts` content against the currently-known
/// removable whole-disk devices (name -> device_key). Only rows whose mount
/// source is `/dev/<name>` with a known-removable `linux_parent_block_device`
/// participate; a non-`/dev/` source (tmpfs, nfs, cgroup, ...) never matches.
/// One device mounted at multiple points yields multiple pairs.
inline RemovableMountCorrelation
correlate_removable_mounts(std::string_view proc_mounts_content,
                           const std::unordered_map<std::string, std::string>& known_removable_disks) {
    RemovableMountCorrelation result;
    constexpr std::string_view kDevPrefix = "/dev/";

    std::size_t pos = 0;
    while (pos <= proc_mounts_content.size()) {
        const auto nl = proc_mounts_content.find('\n', pos);
        const std::string_view line = nl == std::string_view::npos
           ? proc_mounts_content.substr(pos)
           : proc_mounts_content.substr(pos, nl - pos);
        pos = nl == std::string_view::npos ? proc_mounts_content.size() + 1 : nl + 1;
        if (line.empty()) {
            if (nl == std::string_view::npos)
                break;
            continue;
        }

        std::vector<std::string_view> fields;
        std::size_t i = 0;
        while (i < line.size()) {
            while (i < line.size() && (line[i] == ' ' || line[i] == '\t'))
                ++i;
            const std::size_t start = i;
            while (i < line.size() && line[i] != ' ' && line[i] != '\t')
                ++i;
            if (i > start)
                fields.push_back(line.substr(start, i - start));
        }
        if (fields.size() < 2) {
            result.malformed = true;
            continue;
        }

        const std::string_view source = fields[0];
        if (source.size() <= kDevPrefix.size() || source.substr(0, kDevPrefix.size()) != kDevPrefix)
            continue; // not a /dev/ source -- tmpfs, nfs, cgroup, ... never match

        const std::string devname(source.substr(kDevPrefix.size()));
        const std::string parent = linux_parent_block_device(devname);
        const auto known = known_removable_disks.find(parent);
        if (known == known_removable_disks.end())
            continue;

        result.pairs.emplace_back(known->second,
                                  removable_detail::decode_proc_mounts_field(fields[1]));
    }
    return result;
}

// ── 5. macOS DiskArbitration session interface ──────────────────────────────
// Declared here (framework-free -- Impl is opaque) so tar_removable_collector.
// cpp can drive a DASession without any Objective-C leaking into a .cpp TU.
// Implemented in tar_removable_diskarb.mm, which is the ONLY place CoreFoundation/
// DiskArbitration symbols appear (docs/native-objcpp-conventions.md; structure
// copied from wifi_corewlan.mm).

/// ── Baseline + reconciliation decision (pure) ─────────────────────────────
///
/// The live legs differ only in HOW they learn the currently-attached set
/// (DiskArbitration, udev, the event log); what they must DO with it is
/// identical, and it is the part that has been wrong twice. Extracted here so
/// it is reachable from the unit suites without a DiskArbitration session:
/// the collector owns the OS call and the device metadata, this owns the
/// decision.
///
/// Order is load-bearing and mirrors the collector's:
///   1. baseline (first tick only) — seed `attach_set` from what is attached
///      NOW, and name the devices that need a `present_at_baseline` row;
///   2. pending — apply the queued OS callbacks, so a real `detached` that
///      arrived during the baseline tick still wins;
///   3. reconcile (only once baseline has run) — recover from a callback the
///      OS never delivered, in both directions.
struct BaselineReconcileInputs {
    bool baseline_already_done{false};
    std::set<std::string> exec_seen;
    std::map<std::string, std::int64_t> attach_epoch;
    std::int64_t now{0}; // stamped as the session start for a newly-attached device
    std::unordered_set<std::string> current_keys;
    std::unordered_map<std::string, bool> prev_attach_set;
    // (action, device_key) of the retained pending queue, oldest first.
    std::vector<std::pair<std::string, std::string>> pending;
};

struct BaselineReconcileResult {
    std::unordered_map<std::string, bool> attach_set;
    std::map<std::string, std::int64_t> attach_epoch; // session start per device
    std::set<std::string> exec_seen; // carried through; detach clears a device's entries
    std::vector<std::string> baseline_keys;     // -> present_at_baseline
    std::vector<std::string> reconcile_added;   // -> attached  (missed appeared)
    std::vector<std::string> reconcile_removed; // -> detached  (missed disappeared)
};

inline BaselineReconcileResult decide_baseline_and_reconcile(const BaselineReconcileInputs& in) {
    BaselineReconcileResult out;
    out.attach_set = in.prev_attach_set;
    out.exec_seen = in.exec_seen;
    out.attach_epoch = in.attach_epoch;
    // A device that is newly present starts a session; one already tracked keeps
    // the session it had, so the exec key stays stable while it remains plugged.
    auto begin_session = [&out, now = in.now](const std::string& key) {
        out.attach_epoch.try_emplace(key, now);
    };

    if (!in.baseline_already_done) {
        for (const auto& key : in.current_keys) {
            // P2: seed UNCONDITIONALLY. Emitting the baseline rows without
            // recording them persisted `baseline_done = true` beside an empty
            // attach_set, so the very next tick's reconcile step re-reported
            // every already-attached device as an `attached` event whose
            // evidence claimed a missed OS callback that never happened.
            out.attach_set[key] = true;
            begin_session(key);
            if (!in.prev_attach_set.count(key))
                out.baseline_keys.push_back(key);
        }
    }

    // Every path that drops a device from attach_set must also forget its
    // exec observations (K1), or a device that is unplugged and plugged back in
    // is never re-reported as executing -- the stable exec key would still be
    // in exec_seen from the previous session.
    auto forget_execs = [&out](const std::string& device_key) {
        const std::string prefix = device_key + "\x1f";
        for (auto it = out.exec_seen.begin(); it != out.exec_seen.end();)
            it = it->starts_with(prefix) ? out.exec_seen.erase(it) : std::next(it);
    };

    for (const auto& [action, key] : in.pending) {
        if (action == "attached") {
            out.attach_set[key] = true;
            begin_session(key);
        } else if (action == "detached") {
            out.attach_set.erase(key);
            out.attach_epoch.erase(key); // the session ends with the device
            forget_execs(key);
        }
    }

    if (in.baseline_already_done) {
        // K3: reconciliation diffs the pending CALLBACKS against a SNAPSHOT of
        // the device set, and the two are not taken atomically. A device
        // unplugged mid-tick can therefore have a real `detached` callback in
        // `pending` while the snapshot, taken a moment earlier, still lists it.
        // Without this guard the pending loop above removes the key and the
        // loop below immediately re-adds it as a "missed appeared-callback" --
        // evidence for a callback that never went missing -- leaving it in
        // attach_set so a second, reconcile-derived `detached` follows next
        // tick: three rows for one removal, one of them false. A key the OS
        // has already spoken about this tick needs no reconciling in either
        // direction; the snapshot is the weaker witness and must not override
        // a callback that actually arrived.
        std::unordered_set<std::string> pending_keys;
        pending_keys.reserve(in.pending.size());
        for (const auto& [action, key] : in.pending)
            pending_keys.insert(key);

        for (const auto& key : in.current_keys) {
            if (out.attach_set.count(key) || pending_keys.count(key))
                continue; // already accounted for by a callback this tick
            out.reconcile_added.push_back(key);
            out.attach_set[key] = true;
            begin_session(key);
        }
        for (const auto& [key, present] : in.prev_attach_set) {
            if (!present || in.current_keys.count(key) || !out.attach_set.count(key) ||
                pending_keys.count(key))
                continue; // still attached, or already spoken for by a callback this tick
            out.reconcile_removed.push_back(key);
            out.attach_set.erase(key);
            out.attach_epoch.erase(key);
            forget_execs(key);
        }
    }
    return out;
}

#ifdef __APPLE__

/// One DiskArbitration appear/disappear callback, or one baseline-snapshot
/// row, already reduced to plain strings/ints -- no CF/DA type crosses this
/// boundary.
struct RemovableDiskArbEvent {
    std::string action; // "attached" | "detached" | "present_at_baseline"
    std::string bsd_name;    // e.g. "disk4s1" -- identity fallback when no MediaUUID
    std::string media_uuid;  // kDADiskDescriptionMediaUUIDKey, "" if absent
    std::string vendor;
    std::string product;
    std::string volume_path; // mount point, "" if not mounted
    std::int64_t size_bytes{0};
};

/// Owns a private dispatch queue + DASession (tar_removable_diskarb.mm).
/// start()/stop() are the ONLY methods that touch the session; callbacks
/// pushed via on_event run on the DA queue thread and must not block or
/// touch the TarDatabase directly (the caller marshals into
/// BoundedPendingQueue<RemovableEvent>). stop() unregisters callbacks,
/// unschedules the queue and blocks until no callback can fire again before
/// returning (tar_cursor.hpp's stop() contract).
class RemovableDiskArbSession {
public:
    RemovableDiskArbSession();
    ~RemovableDiskArbSession();
    RemovableDiskArbSession(const RemovableDiskArbSession&) = delete;
    RemovableDiskArbSession& operator=(const RemovableDiskArbSession&) = delete;

    void start(std::function<void(RemovableDiskArbEvent)> on_event);
    void stop() noexcept;

    /// getfsstat + DADiskCreateFromBSDName/DADiskCopyDescription snapshot of
    /// every currently-mounted removable volume -- used for baseline and for
    /// exec-from-removable's currently-attached-roots list. Safe to call from
    /// collect() (not the DA queue).
    /// nullopt means the SNAPSHOT FAILED -- distinct from an empty vector,
    /// which means the scan succeeded and nothing removable is attached.
    /// Collapsing the two let a transient getfsstat/DASession failure look
    /// like "every device just detached": the reconciler diffed the empty set
    /// against the persisted attach_set, committed a detach for every device
    /// and cleared the durable state, and the next healthy scan committed a
    /// false re-attach for each one (C6). Rule 1 governs a failed acquisition:
    /// retain the cursor and skip the tick.
    [[nodiscard]] std::optional<std::vector<RemovableDiskArbEvent>> snapshot_attached() const;

    // Opaque, defined only in tar_removable_diskarb.mm. Public (not private)
    // because the callback trampolines in that .mm need the type name to
    // cast the void* DiskArbitration hands back through on_disk_appeared/
    // Disappeared -- Impl itself is still un-constructible outside the .mm
    // (no public members declared), so this buys no real external access.
    struct Impl;

private:
    std::unique_ptr<Impl> impl_;
};

#endif // __APPLE__

} // namespace yuzu::tar
