/**
 * filesystem_posture_legs.hpp — the seam between filesystem_posture_plugin.cpp
 * and the three per-OS leg TUs (filesystem_posture_linux.cpp,
 * filesystem_posture_macos.cpp, filesystem_posture_win.cpp).
 *
 * PINNED CONTRACT (peer H1): the three format_*_row signatures below are
 * compiled against by three concurrent wave-2 packages. Do not change them,
 * the QuotaState enumerator set, the wire tokens, the flags vocabulary, or
 * the row field order once written -- see filesystem_posture_parsers.hpp for
 * the full pinned wire-format contract.
 *
 * This header DECLARES (never defines) the three per-OS entry points; each
 * leg TU defines exactly one. It DEFINES the pure row formatters, the ctx
 * wrappers around them (the only ROW writers in this plugin -- see the note
 * at the wrappers), and mark_result_partial().
 */
#pragma once

#include <yuzu/plugin.hpp>
#include <yuzu/string_utils.hpp>

#include "filesystem_posture_parsers.hpp"

#include <spdlog/spdlog.h>

#include <optional>
#include <string>
#include <string_view>

namespace yuzu::filesystem_posture {

// ── per-OS entry points (defined by the leg TUs) ────────────────────────
//
// Each is a read; each returns 0 always (ADR-style: a read never fails the
// call, degradation is reported via mark_result_partial/set_result_status).

int emit_mounts(yuzu::CommandContext& ctx);
int emit_quotas(yuzu::CommandContext& ctx);
int emit_snapshots(yuzu::CommandContext& ctx);

// ── pure row formatters ─────────────────────────────────────────────────
//
// Formatters take already-computed values; they perform no OS calls and no
// decisions. They return the row WITHOUT a trailing '\n' (peer H1/L5,
// verified at agents/core/src/agent.cpp:305-313): append_output() inserts
// the separator between successive writes in capture mode, so a
// formatter-emitted '\n' would produce blank rows under LocalDispatcher
// capture.
//
// A std::nullopt byte count renders as the literal "-". Escaping: fields
// that can carry arbitrary text (mount_point, device, fstype, options, name,
// detail) go through yuzu::util::safe_output_field -- the shared SDK
// escaper, never a private copy. Fields drawn from a fixed vocabulary or
// already-numeric (flags, the quota-state token, kind, the "volume" scope
// literal, byte counts) are emitted verbatim.

namespace detail {
inline std::string format_optional_bytes(std::optional<unsigned long long> v) {
    return v.has_value() ? std::to_string(*v) : std::string{"-"};
}
} // namespace detail

/// mount|<mount_point>|<device>|<fstype>|<options>|<total_bytes>|<free_bytes>|<available_bytes>|<flags>
inline std::string format_mount_row(std::string_view mount_point, std::string_view device,
                                    std::string_view fstype, std::string_view options,
                                    std::optional<unsigned long long> total_bytes,
                                    std::optional<unsigned long long> free_bytes,
                                    std::optional<unsigned long long> available_bytes,
                                    std::string_view flags) {
    std::string out = "mount|";
    out += yuzu::util::safe_output_field(mount_point);
    out += '|';
    out += yuzu::util::safe_output_field(device);
    out += '|';
    out += yuzu::util::safe_output_field(fstype);
    out += '|';
    out += yuzu::util::safe_output_field(options);
    out += '|';
    out += detail::format_optional_bytes(total_bytes);
    out += '|';
    out += detail::format_optional_bytes(free_bytes);
    out += '|';
    out += detail::format_optional_bytes(available_bytes);
    out += '|';
    out.append(flags); // fixed vocabulary -- emitted verbatim
    return out;
}

/// quota|<mount_point>|volume|<state>|<limit_bytes>|<reserved_bytes>|<detail>
///
/// The scope field is always the fixed literal "volume" (callers cannot vary
/// it in this PR); state is rendered via quota_state_token().
inline std::string format_quota_row(std::string_view mount_point, QuotaState state,
                                    std::optional<unsigned long long> limit_bytes,
                                    std::optional<unsigned long long> reserved_bytes,
                                    std::string_view detail) {
    std::string out = "quota|";
    out += yuzu::util::safe_output_field(mount_point);
    out += "|volume|";
    out.append(quota_state_token(state));
    out += '|';
    out += detail::format_optional_bytes(limit_bytes);
    out += '|';
    out += detail::format_optional_bytes(reserved_bytes);
    out += '|';
    out += yuzu::util::safe_output_field(detail);
    return out;
}

/// snapshot|<mount_point>|<name>|<kind>|<detail>
///
/// `kind` MUST be one of the five fixed literals apfs|btrfs_subvolume|
/// device_mapper|vss|none and is emitted verbatim. On a `none` row, `name`
/// is "-" (the CALLER'S responsibility; this formatter does not enforce it),
/// while `detail` survives verbatim (after escaping) -- every leg passes an
/// operator-actionable detail on a `none` row (e.g. "no btrfs or
/// device-mapper mount found"), and blanking it would let a Windows
/// DeviceIoControl failure masquerade as an empty, healthy snapshot set.
inline std::string format_snapshot_row(std::string_view mount_point, std::string_view name,
                                       std::string_view kind, std::string_view detail) {
    std::string out = "snapshot|";
    out += yuzu::util::safe_output_field(mount_point);
    out += '|';
    out += yuzu::util::safe_output_field(name);
    out += '|';
    out.append(kind); // fixed vocabulary -- emitted verbatim
    out += '|';
    out += yuzu::util::safe_output_field(detail);
    return out;
}

// ── ctx wrappers: the only ROW writers in this plugin ──
// Every pipe-delimited ROW is emitted here and nowhere else. One non-row
// ctx.write_output exists, for the unknown-action diagnostic in
// filesystem_posture_plugin.cpp; it emits no kind token and is separately
// escaped. Claiming these are the ONLY write_output sites was false (CDX-P2-08).

inline void write_mount_row(yuzu::CommandContext& ctx, std::string_view mount_point,
                            std::string_view device, std::string_view fstype,
                            std::string_view options, std::optional<unsigned long long> total_bytes,
                            std::optional<unsigned long long> free_bytes,
                            std::optional<unsigned long long> available_bytes,
                            std::string_view flags) {
    ctx.write_output(format_mount_row(mount_point, device, fstype, options, total_bytes, free_bytes,
                                      available_bytes, flags));
}

inline void write_quota_row(yuzu::CommandContext& ctx, std::string_view mount_point,
                            QuotaState state, std::optional<unsigned long long> limit_bytes,
                            std::optional<unsigned long long> reserved_bytes,
                            std::string_view detail) {
    ctx.write_output(format_quota_row(mount_point, state, limit_bytes, reserved_bytes, detail));
}

inline void write_snapshot_row(yuzu::CommandContext& ctx, std::string_view mount_point,
                               std::string_view name, std::string_view kind,
                               std::string_view detail) {
    ctx.write_output(format_snapshot_row(mount_point, name, kind, detail));
}

/**
 * Report a degraded-but-partial read (verbatim-shape copy of
 * certificates_plugin.cpp:207-215). Every degradation logs a WARN
 * regardless of how many times it's called in one execute(); `set_result_status`
 * itself ASSIGNS -- last writer wins (peer M3, verified at
 * agents/core/src/agent.cpp:553-555) -- so when multiple degradations occur
 * in one execute() call, the LAST mark_result_partial() call's provenance is
 * what the server ultimately sees. This is a stated decision, not an
 * accident: every degradation still reaches the agent log even though only
 * the final one reaches the typed result status.
 */
inline void mark_result_partial(yuzu::CommandContext& ctx, std::string_view provenance,
                                std::string_view reason = {}) {
    if (reason.empty())
        spdlog::warn("filesystem_posture: degraded read ({})", provenance);
    else
        spdlog::warn("filesystem_posture: degraded read ({}): {}", provenance, reason);
    ctx.set_result_status(YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL,
                          provenance);
}

/**
 * Report a degradation whose cause is specifically a PRIVILEGE denial.
 *
 * Same shape and same "last call wins" semantics as mark_result_partial, but
 * it sets YUZU_RESULT_STATUS_PERMISSION_DENIED rather than CONSTRAINED, so a
 * status-keyed consumer can tell "this agent is not allowed to read that" from
 * every other kind of degradation. The precedent is event_logs_plugin.cpp:136,
 * which maps its own access-denied outcome to exactly this pair.
 *
 * This exists because the descriptor and four operator-facing docs state that
 * a denied read "reports permission_denied". Before this helper that sentence
 * was false -- the leg set CONSTRAINED like any other degradation -- which is
 * a documented contract the code did not honour, not merely imprecise prose.
 */
inline void mark_result_denied(yuzu::CommandContext& ctx, std::string_view provenance,
                               std::string_view reason = {}) {
    if (reason.empty())
        spdlog::warn("filesystem_posture: permission denied ({})", provenance);
    else
        spdlog::warn("filesystem_posture: permission denied ({}): {}", provenance, reason);
    ctx.set_result_status(YUZU_RESULT_STATUS_PERMISSION_DENIED, YUZU_RESULT_COMPLETENESS_PARTIAL,
                          provenance);
}

} // namespace yuzu::filesystem_posture
