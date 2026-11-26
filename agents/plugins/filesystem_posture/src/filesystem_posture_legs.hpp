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
 * leg TU defines exactly one. It DEFINES the pure row formatters, the pure
 * plan of the Windows snapshots rows, the ctx wrappers around the formatters
 * (the only ROW writers in this plugin -- see the note at the wrappers), and
 * mark_result_partial().
 */
#pragma once

#include <yuzu/agent/win_vss_snapshots.hpp> // types only here: the pure snapshot plan
#include <yuzu/plugin.hpp>
#include <yuzu/string_utils.hpp>

#include "filesystem_posture_parsers.hpp"

#include <spdlog/spdlog.h>

#include <cstdint>
#include <format>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

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

// ── Windows snapshots plan ──────────────────────────────────────────────
//
// What one VSS read means as rows and degradation marks. Pure, so every arm
// runs in the unit suite on every OS; the Windows leg only reads, resolves
// mount points and writes.

/// The values of one snapshot row, unescaped.
struct SnapshotRow {
    std::string mount_point, name, kind, detail;
};

/// One degradation: PERMISSION_DENIED when `denied`, otherwise CONSTRAINED.
struct SnapshotMark {
    bool denied = false;
    std::string detail;
};

struct VssRowPlan {
    std::vector<SnapshotRow> rows;
    std::vector<SnapshotMark> marks; ///< applied in order; the last one is the one reported
};

/// E_ACCESSDENIED, spelled out because this header also builds off Windows.
inline constexpr std::uint32_t kVssAccessDenied = 0x80070005u;

/// Renders a VSS step failure for both the row `detail` and the
/// degradation mark. E_ACCESSDENIED is named explicitly: it is the one
/// failure here an operator can actually act on, and it is what #1442 will
/// turn this leg into fleet-wide.
inline std::string vss_failure_detail(std::string_view step, std::int32_t hr) {
    const auto code = static_cast<std::uint32_t>(hr);
    if (code == kVssAccessDenied) {
        // "commonly indicates", not "lacks": E_ACCESSDENIED from a COM call
        // can also arise from COM security negotiation or the VSS service's
        // own ACL. Administrative rights are the overwhelmingly likely cause
        // and the one an operator can act on, but asserting a single cause
        // from a generic HRESULT would be stating more than the code knows.
        return std::format("{} denied (0x{:08X}): VSS snapshot enumeration requires "
                           "administrative rights; this commonly indicates the agent service "
                           "account lacks them",
                           step, code);
    }
    return std::format("{} failed: 0x{:08X}", step, code);
}

namespace detail {
/// The call a failed step names. com_init has its own fixed text instead.
inline std::string_view vss_call_name(yuzu::agent::win::VssStep step) {
    using yuzu::agent::win::VssStep;
    switch (step) {
    case VssStep::create:
        return "CreateVssBackupComponents";
    case VssStep::initialize:
        return "InitializeForBackup";
    case VssStep::query:
        return "Query";
    case VssStep::none:
    case VssStep::com_init:
    case VssStep::next:
        break;
    }
    return "IVssEnumObject::Next";
}
} // namespace detail

/// `mount_point_of` maps a snapshot's non-empty originating volume path onto the
/// mount-point vocabulary the mounts action reports.
inline VssRowPlan
plan_vss_rows(const yuzu::agent::win::VssSnapshotsRead& read,
              const std::function<std::string(const std::string&)>& mount_point_of) {
    using yuzu::agent::win::VssStep;
    VssRowPlan plan;
    // A failure writes BOTH a `none` row and a degradation mark: it must stay
    // distinguishable from a genuinely empty snapshot set (peer H6).
    const auto none_row = [&plan](std::string why) {
        plan.rows.push_back({"-", "-", "none", std::move(why)});
    };

    if (read.status != yuzu::agent::BoundedStatus::Completed) {
        const std::string why = std::format("VSS enumeration did not answer: {}",
                                            yuzu::agent::bounded_cause(read.status));
        none_row(why);
        plan.marks.push_back({false, why});
        return plan;
    }
    if (!read.api_available) {
        none_row("built without the VSS SDK headers");
        plan.marks.push_back({false, "SDK header vsbackup.h not present at build time"});
        return plan;
    }

    for (const auto& s : read.snapshots) {
        plan.rows.push_back(
            {s.original_volume.empty() ? std::string{"-"} : mount_point_of(s.original_volume),
             s.snapshot_id, "vss", s.device_object});
    }

    if (read.failed_step != VssStep::none) {
        const std::string why =
            read.failed_step == VssStep::com_init
                ? std::string{"COM initialisation failed"}
                : vss_failure_detail(detail::vss_call_name(read.failed_step), read.hr);
        // Rows already read are real; only a read that produced nothing needs
        // the `none` sentinel to carry the failure.
        if (plan.rows.empty())
            none_row(why);
        // A privilege denial is PERMISSION_DENIED at every step, mid-walk
        // included, so a status-keyed consumer can tell "not allowed to read
        // this" from any other degradation.
        plan.marks.push_back({static_cast<std::uint32_t>(read.hr) == kVssAccessDenied, why});
        return plan;
    }

    // Only claim an empty machine when the walk was COMPLETE AND UNNARROWED: a
    // truncated list, a failed SetContext and a skipped non-snapshot object each
    // mean the walk did not see everything (Gate 3 cpp-safety F3, Gate 4 CA-3).
    if (plan.rows.empty()) {
        const bool complete =
            !read.truncated && !read.context_narrowed && !read.skipped_wrong_type;
        none_row(complete ? "no shadow copies present on any volume"
                          : "no shadow copies observed, but the enumeration was incomplete "
                            "-- see the degraded status for why");
    }
    // set_result_status ASSIGNS -- last writer wins -- so these run
    // least-material first, leaving the most material cause (an incomplete
    // list) as the one an operator sees.
    if (read.skipped_wrong_type) {
        plan.marks.push_back(
            {false, "the provider returned a non-snapshot object; it was skipped"});
    }
    if (read.context_narrowed) {
        plan.marks.push_back(
            {false,
             "SetContext(VSS_CTX_ALL) failed; only the default snapshot context was enumerated"});
    }
    if (read.truncated) {
        plan.marks.push_back({false, std::format("snapshot list truncated at the {}-entry cap",
                                                 yuzu::agent::win::kMaxVssSnapshots)});
    }
    return plan;
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
