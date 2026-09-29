/**
 * disk_actions_legs.hpp — shared seam between the disk_actions plugin TU and
 * its three per-OS leg TUs.
 *
 * Holds (a) the per-OS entry-point declarations, (b) the pure row formatters,
 * and (c) the degradation reporters. Modelled on
 * filesystem_posture_legs.hpp, which is the most recent plugin to establish
 * this shape.
 *
 * ROW SCHEMAS. Both are fixed-width: every row of a given kind carries the
 * same field count, with "-" where a value is inapplicable. A consumer keying
 * on position must never have to guess which shape it received.
 *
 *   smart|<device>|<model>|<bus>|<media>|<health>|<pct_used>|<spare_pct>|<detail>
 *   volume|<volume>|<mount_points>|<device>|<fstype>|<total_bytes>|<detail>
 *
 * `health`, `bus` and `media` are FIXED vocabularies emitted verbatim (they are
 * derived from enums, never from parsed text); every other field is untrusted
 * OS-supplied text and goes through yuzu::util::safe_output_field.
 *
 * THE EMPTY-RESULT PLACEHOLDER, and how a consumer tells it from a real row.
 * When a leg finds nothing it still emits one row rather than silence, so a
 * consumer never reads zero rows and infers "this host has no disks". A smart
 * placeholder is typed: `health` is `unsupported`, a value no real drive row
 * carries. A volume placeholder has NO such column, so it is identified by its
 * `volume` field being "-": a real volume always has a name, and "-" in that
 * position is reserved for the placeholder. Both are accompanied by an
 * UNAVAILABLE result status, which is the authoritative signal.
 */
#pragma once

#include <yuzu/plugin.hpp>
#include <yuzu/string_utils.hpp>

#include <spdlog/spdlog.h>

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace yuzu::disk_actions {

// ── per-OS entry points (defined by the leg TUs) ─────────────────────────
//
// Each is a READ. Each returns 0 unconditionally: a degraded read is not a
// failed command, and the degradation is reported through set_result_status
// instead (the same binding rule filesystem_posture follows).

int emit_smart(yuzu::CommandContext& ctx);
int emit_volumes(yuzu::CommandContext& ctx);

// ── fixed vocabularies ──────────────────────────────────────────────────

/// Drive health. Deliberately coarse and closed: a plugin reports facts, and a
/// threshold belongs to the caller. `unknown` is a real answer (the device did
/// not tell us), distinct from `unsupported` (this OS leg cannot ask).
enum class Health { Ok, Warning, Failing, Unknown, Unsupported };

constexpr std::string_view health_token(Health h) noexcept {
    switch (h) {
    case Health::Ok:          return "ok";
    case Health::Warning:     return "warning";
    case Health::Failing:     return "failing";
    case Health::Unknown:     return "unknown";
    case Health::Unsupported: return "unsupported";
    }
    return "unknown";
}

/// Transport. `unknown` rather than a guess when the OS does not say.
enum class Bus { Nvme, Sata, Usb, Sas, Virtual, Unknown };

constexpr std::string_view bus_token(Bus b) noexcept {
    switch (b) {
    case Bus::Nvme:    return "nvme";
    case Bus::Sata:    return "sata";
    case Bus::Usb:     return "usb";
    case Bus::Sas:     return "sas";
    case Bus::Virtual: return "virtual";
    case Bus::Unknown: return "unknown";
    }
    return "unknown";
}

enum class Media { Ssd, Hdd, Unknown };

constexpr std::string_view media_token(Media m) noexcept {
    switch (m) {
    case Media::Ssd:     return "ssd";
    case Media::Hdd:     return "hdd";
    case Media::Unknown: return "unknown";
    }
    return "unknown";
}

namespace detail {

/// A std::nullopt percentage renders as "-", never as 0 -- "we did not read
/// this" and "this is zero" are different facts and a consumer must be able to
/// tell them apart.
///
/// This formatter is for fields whose contract really is 0..100 -- today that
/// is NVMe `Available Spare` only. A value above 100 from such a field is
/// malformed, and is clamped rather than dropped so the row still appears.
inline std::string format_optional_pct(std::optional<std::uint8_t> pct) {
    if (!pct) return "-";
    return std::to_string(*pct > 100 ? 100 : *pct);
}

/// Wear (`Percentage Used`) is NOT a 0..100 field and must not be clamped like
/// one. The NVMe Base Specification defines it as permitted to EXCEED 100 --
/// a drive past its rated endurance reports 101..254 honestly, and 255 is the
/// defined saturation value for anything beyond that.
///
/// The original revision fed this through format_optional_pct, so every drive
/// from 101% to 255% wear reported exactly "100" and a fleet view could not
/// distinguish a drive at its rated limit from one far past it, nor trend
/// toward failure. Adversarial review (2026-09-04) caught it; the unit test
/// that pinned 255 -> 100 was pinning the defect.
inline std::string format_wear_pct(std::optional<std::uint8_t> pct) {
    if (!pct) return "-";
    return std::to_string(*pct); // full 0..255 range, reported as read
}

inline std::string format_optional_bytes(std::optional<std::uint64_t> bytes) {
    if (!bytes) return "-";
    return std::to_string(*bytes);
}

} // namespace detail

// ── pure row formatters ─────────────────────────────────────────────────
//
// Formatters take already-computed values, perform no OS calls and make no
// decisions, and return the row WITHOUT a trailing newline -- append_output()
// inserts the separator between successive writes, so a formatter-emitted '\n'
// produces blank rows under LocalDispatcher capture.

/// smart|<device>|<model>|<bus>|<media>|<health>|<pct_used>|<spare_pct>|<detail>
inline std::string format_smart_row(std::string_view device, std::string_view model, Bus bus,
                                    Media media, Health health,
                                    std::optional<std::uint8_t> pct_used,
                                    std::optional<std::uint8_t> spare_pct,
                                    std::string_view detail) {
    std::string out = "smart|";
    out += yuzu::util::safe_output_field(device);
    out += '|';
    out += yuzu::util::safe_output_field(model);
    out += '|';
    out.append(bus_token(bus));    // fixed vocabulary -- verbatim
    out += '|';
    out.append(media_token(media)); // fixed vocabulary -- verbatim
    out += '|';
    out.append(health_token(health)); // fixed vocabulary -- verbatim
    out += '|';
    out += detail::format_wear_pct(pct_used);   // 0..255 by NVMe spec, never clamped
    out += '|';
    out += detail::format_optional_pct(spare_pct); // genuinely 0..100
    out += '|';
    out += yuzu::util::safe_output_field(detail);
    return out;
}

/// volume|<volume>|<mount_points>|<device>|<fstype>|<total_bytes>|<detail>
///
/// `mount_points` is the PHYSICAL-to-LOGICAL join this action exists for: the
/// mount points (or drive letters) served by `device`, comma-separated, or "-"
/// when none are mapped. Neither hardware.disks (physical only) nor
/// filesystem_posture.mounts (logical only) answers "which drive backs C:".
inline std::string format_volume_row(std::string_view volume, std::string_view mount_points,
                                     std::string_view device, std::string_view fstype,
                                     std::optional<std::uint64_t> total_bytes,
                                     std::string_view detail) {
    std::string out = "volume|";
    out += yuzu::util::safe_output_field(volume);
    out += '|';
    out += yuzu::util::safe_output_field(mount_points);
    out += '|';
    out += yuzu::util::safe_output_field(device);
    out += '|';
    out += yuzu::util::safe_output_field(fstype);
    out += '|';
    out += detail::format_optional_bytes(total_bytes);
    out += '|';
    out += yuzu::util::safe_output_field(detail);
    return out;
}

// ── write wrappers ──────────────────────────────────────────────────────

inline void write_smart_row(yuzu::CommandContext& ctx, std::string_view device,
                            std::string_view model, Bus bus, Media media, Health health,
                            std::optional<std::uint8_t> pct_used,
                            std::optional<std::uint8_t> spare_pct, std::string_view detail) {
    ctx.write_output(
        format_smart_row(device, model, bus, media, health, pct_used, spare_pct, detail));
}

inline void write_volume_row(yuzu::CommandContext& ctx, std::string_view volume,
                             std::string_view mount_points, std::string_view device,
                             std::string_view fstype, std::optional<std::uint64_t> total_bytes,
                             std::string_view detail) {
    ctx.write_output(format_volume_row(volume, mount_points, device, fstype, total_bytes, detail));
}

// ── degradation reporting ───────────────────────────────────────────────
//
// set_result_status defaults to UNDECLARED, from which the agent derives a
// coarse SUCCESS -- so omitting these on a partial read silently reports a
// clean run. Both log a WARN as well as setting the seam, because the seam
// alone is invisible to log-based alerting. `set_result_status` ASSIGNS, so
// the LAST call wins: report a summary after a walk, never per-item, or a
// later generic degradation will overwrite a cause already established.

inline void mark_result_partial(yuzu::CommandContext& ctx, std::string_view provenance,
                                std::string_view reason = {}) {
    if (reason.empty())
        spdlog::warn("disk_actions: degraded read ({})", provenance);
    else
        spdlog::warn("disk_actions: degraded read ({}): {}", provenance, reason);
    ctx.set_result_status(YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL,
                          provenance);
}

/// Report a capability that is ABSENT on this platform, as distinct from a
/// read that partially degraded. Spec-axis review (F5) caught the Linux legs
/// reporting CONSTRAINED/PARTIAL — "partial data" — for actions that are not
/// implemented at all and produce no data whatsoever. The repo precedent for
/// "capability absent entirely" is UNAVAILABLE (antivirus_plugin.cpp:92,
/// network_config_plugin.cpp:1170), and a status-keyed consumer must be able
/// to tell "some of it failed" from "this platform cannot do this".
inline void mark_result_unavailable(yuzu::CommandContext& ctx, std::string_view provenance,
                                    std::string_view reason = {}) {
    if (reason.empty())
        spdlog::warn("disk_actions: capability unavailable ({})", provenance);
    else
        spdlog::warn("disk_actions: capability unavailable ({}): {}", provenance, reason);
    ctx.set_result_status(YUZU_RESULT_STATUS_UNAVAILABLE, YUZU_RESULT_COMPLETENESS_PARTIAL,
                          provenance);
}

/// A degradation whose cause is specifically a PRIVILEGE denial, so a
/// status-keyed consumer can tell "not allowed to read that" from every other
/// kind of degradation — the two need different remediation, and only this one
/// is fixed by granting the agent account a right. Precedent:
/// event_logs_plugin.cpp's access-denied mapping, and filesystem_posture's
/// mark_result_denied.
inline void mark_result_denied(yuzu::CommandContext& ctx, std::string_view provenance,
                               std::string_view reason = {}) {
    if (reason.empty())
        spdlog::warn("disk_actions: permission denied ({})", provenance);
    else
        spdlog::warn("disk_actions: permission denied ({}): {}", provenance, reason);
    ctx.set_result_status(YUZU_RESULT_STATUS_PERMISSION_DENIED, YUZU_RESULT_COMPLETENESS_PARTIAL,
                          provenance);
}

} // namespace yuzu::disk_actions
