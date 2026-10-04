/**
 * mgmt_posture_legs.hpp -- shared seam between the mgmt_posture plugin TU and its
 * three per-OS leg TUs (update_source_trust_legs.hpp shape).
 *
 * Holds (a) the per-OS entry-point declarations, (b) report_posture, the SINGLE owner
 * of the `status|posture|...` row (no leg and no parser writes one), pairing each
 * status with its result status/completeness, (c) execute_posture, the plugin's
 * whole execute() body (dispatch + ABI containment), and (d) the OS-free per-OS
 * DECISION logic, `posture_linux` / `posture_macos`, over injected boundaries (a file
 * reader, a conf.d lister, a keytab probe, a command runner) so the refused-vs-absent
 * rules are unit-tested with canned results and no disk, spawn or uid dependence
 * (local_security_policy_legs.hpp precedent). The leg TUs keep only the OS shell.
 *
 * Each entry point is a READ and returns 0: a degraded read is not a failed command.
 */
#pragma once

#include "mgmt_posture_parsers.hpp"

#include <constraint_accumulator.hpp>
#include <yuzu/agent/runner_status.hpp>
#include <yuzu/agent/subprocess_runner.hpp>
#include <yuzu/plugin.hpp>
#include <yuzu/string_utils.hpp>

#include <cerrno>
#include <chrono>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace yuzu::mgmt_posture {

int run_windows(yuzu::CommandContext& ctx);
int run_linux(yuzu::CommandContext& ctx);
int run_macos(yuzu::CommandContext& ctx);

enum class StatusState { supported, constrained, permission_denied, unsupported };

inline std::string_view status_token(StatusState s) {
    switch (s) {
    case StatusState::supported:
        return "supported";
    case StatusState::constrained:
        return "constrained";
    case StatusState::permission_denied:
        return "permission_denied";
    case StatusState::unsupported:
        return "unsupported";
    }
    return "unsupported";
}

inline std::string format_status_row(StatusState s, std::string_view reason) {
    std::string r = "status|posture|";
    r += status_token(s);
    r += '|';
    r += reason.empty() ? std::string{"-"} : yuzu::util::safe_output_field(reason);
    return r;
}

/// Writes the status row FIRST, then the data rows, then the paired result status.
/// `unsupported` (a leg that read nothing) pairs with UNAVAILABLE/UNKNOWN and takes no
/// data rows; every other state is a read that ran.
inline void report_posture(yuzu::CommandContext& ctx, const std::vector<std::string>& data_rows,
                           StatusState status, std::string_view reason) {
    ctx.write_output(format_status_row(status, reason));
    for (const auto& r : data_rows)
        ctx.write_output(r);
    switch (status) {
    case StatusState::permission_denied:
        ctx.set_result_status(YUZU_RESULT_STATUS_PERMISSION_DENIED, YUZU_RESULT_COMPLETENESS_PARTIAL,
                              std::string{reason});
        break;
    case StatusState::constrained:
        ctx.set_result_status(YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL,
                              std::string{reason});
        break;
    case StatusState::unsupported:
        ctx.set_result_status(YUZU_RESULT_STATUS_UNAVAILABLE, YUZU_RESULT_COMPLETENESS_UNKNOWN,
                              std::string{reason});
        break;
    case StatusState::supported:
        ctx.set_result_status(YUZU_RESULT_STATUS_OK, YUZU_RESULT_COMPLETENESS_FULL, "");
        break;
    }
}

inline constexpr const char* kWindowsPlannedToken = "windows:planned";

/// A leg that reads nothing: ONE `unsupported` status row and UNAVAILABLE/UNKNOWN
/// carrying the same token, routed through report_posture (the sole status-row owner).
/// Callers: the Windows placeholder and execute_posture's catch arm (`<os>:leg:exception`).
inline void report_unavailable(yuzu::CommandContext& ctx, std::string_view token) {
    report_posture(ctx, {}, StatusState::unsupported, token);
}

/// What a leg decided: the status, its reason token(s), and the data rows.
struct Posture {
    StatusState status = StatusState::supported;
    std::string reason;
    std::vector<std::string> rows;
};

inline void report_posture(yuzu::CommandContext& ctx, const Posture& p) {
    report_posture(ctx, p.rows, p.status, p.reason);
}

using LegFn = int (*)(yuzu::CommandContext&);

/// The WHOLE body of the plugin's execute(): dispatch and the single ABI containment.
/// Status-row contract: exactly one per dispatch on every path but one. A leg that throws
/// AFTER report_posture already wrote its row (allocation failure while emitting data rows)
/// gets the catch arm's `unsupported` row appended, so the LAST status row wins -- the same
/// documented behaviour as update_source_trust_legs.hpp. The recovery itself allocates, so
/// it is guarded too: if it throws as well, the dispatch returns 1 (a failed command)
/// rather than unwinding across the plugin ABI.
inline int execute_posture(yuzu::CommandContext& ctx, std::string_view action, LegFn leg,
                           std::string_view leg_exception_token) {
    try {
        if (action != "posture") {
            ctx.write_output(std::string{"unknown action: "} +
                             yuzu::util::safe_output_field(action));
            return 1;
        }
        return leg(ctx);
    } catch (...) {
        try {
            report_unavailable(ctx, leg_exception_token);
        } catch (...) {
            return 1;
        }
        return 0;
    }
}

// ---------------------------------------------------------------------------
// Linux decision logic (OS-free; the shell in mgmt_posture_linux.cpp injects the I/O)
// ---------------------------------------------------------------------------

inline constexpr int kErrNotRegular = -1; ///< ReadResult::err: target is not a regular file
inline constexpr int kErrOversized = -2;  ///< ReadResult::err: target exceeds the read cap

struct ReadResult {
    std::string data;
    int err = 0; ///< 0 ok, else errno or kErrNotRegular / kErrOversized
};

inline bool refused(int err) { return err == EACCES || err == EPERM; }

inline std::string errno_token(int err) {
    switch (err) {
    case kErrNotRegular:
        return "not_regular";
    case kErrOversized:
        return "oversized";
    case ENOENT:
        return "enoent";
    case EACCES:
    case EPERM:
        return "permission_denied";
    case EIO:
        return "eio";
    case ELOOP:
        return "eloop";
    case ENOTDIR:
        return "enotdir";
    case ENAMETOOLONG:
        return "enametoolong";
    default:
        return "errno_" + std::to_string(err);
    }
}

inline constexpr const char* kSssdConf = "/etc/sssd/sssd.conf";
inline constexpr const char* kSssdConfD = "/etc/sssd/conf.d";
inline constexpr const char* kIpaConf = "/etc/ipa/default.conf";
/// Handed to the keytab probe ONLY: the keytab holds key material and is never read.
inline constexpr const char* kKeytab = "/etc/krb5.keytab";

/// The three injected Linux boundaries.
struct LinuxFs {
    /// Small-file reader (symlinks followed, regular files only, capped).
    std::function<ReadResult(const std::string& path)> read;
    /// Lists conf.d `*.conf` names into `names` (sorted, already cut to the snippet cap)
    /// and sets `too_many`. Returns 0 or the errno of a failed opendir/readdir.
    std::function<int(std::vector<std::string>& names, bool& too_many)> list_conf_d;
    /// Keytab presence probe: 0 present, ENOENT absent, any other errno unknown.
    std::function<int()> keytab_errno;
};

inline Posture posture_linux(const LinuxFs& fs) {
    yuzu::shared::ConstraintAccumulator acc;
    std::vector<std::string> denied; // permission_denied reasons, in order

    // --- krb5.keytab: presence only, never opened ---
    Presence keytab = Presence::unknown;
    if (const int kerr = fs.keytab_errno(); kerr == 0)
        keytab = Presence::present;
    else if (kerr == ENOENT)
        keytab = Presence::absent;
    else
        acc.add_failure("linux:mgmt_posture:krb5_keytab:" + errno_token(kerr));

    // --- SSSD: sssd.conf then conf.d snippets, concatenated in precedence order ---
    std::string text;
    bool sssd_present = false;
    const auto note = [&](int err, const char* part) {
        const std::string base = std::string("linux:mgmt_posture:") + part;
        if (refused(err))
            denied.push_back(base + ":permission_denied");
        else
            acc.add_failure(base + ":" + errno_token(err));
    };

    if (auto r = fs.read(kSssdConf); r.err == 0) {
        text = std::move(r.data);
        sssd_present = true;
    } else if (r.err != ENOENT) {
        note(r.err, "sssd_conf");
    }

    std::vector<std::string> snippets;
    bool too_many = false;
    if (const int err = fs.list_conf_d(snippets, too_many); err != 0 && err != ENOENT)
        note(err, "sssd_conf_d");
    if (too_many)
        acc.add_failure("linux:mgmt_posture:sssd_conf_d:too_many");
    for (const auto& n : snippets) {
        auto r = fs.read(std::string(kSssdConfD) + "/" + n);
        if (r.err == 0) {
            text += '\n';
            text += r.data;
            sssd_present = true;
        } else if (r.err != ENOENT) {
            note(r.err, "sssd_conf_d");
        }
    }

    if (!denied.empty()) {
        std::string reason;
        for (const auto& t : denied) {
            if (!reason.empty())
                reason += ',';
            reason += t;
        }
        // Keep any constraint already accumulated (e.g. the keytab errno token): the
        // `krb5_keytab|-` row's provenance must survive the early return.
        if (acc.any_failure())
            reason += ',' + acc.reason();
        return {StatusState::permission_denied, std::move(reason),
                linux_rows(Plane::unknown, keytab)};
    }

    std::optional<SssdFacts> sssd;
    if (sssd_present) {
        sssd = sssd_facts(parse_ini(text));
        if (!sssd->domains_key_present)
            acc.add_failure("linux:mgmt_posture:sssd_conf:no_domains_key");
    }

    // --- IPA: a refusal here is only constrained (the realm is also visible in sssd.conf) ---
    bool ipa_present = false;
    if (const auto r = fs.read(kIpaConf); r.err == 0)
        ipa_present = parse_ipa_default_conf_has_realm(parse_ini(r.data));
    else if (r.err != ENOENT)
        acc.add_failure("linux:mgmt_posture:ipa_default_conf:" + errno_token(r.err));

    const auto plane = classify_linux(sssd, ipa_present);
    return {acc.any_failure() ? StatusState::constrained : StatusState::supported, acc.reason(),
            linux_rows(plane, keytab)};
}

// ---------------------------------------------------------------------------
// macOS decision logic (OS-free; the shell in mgmt_posture_macos.cpp injects the runner)
// ---------------------------------------------------------------------------

using RunFn = std::function<yuzu::agent::SubprocessResult(
    const std::vector<std::string>& argv, const yuzu::agent::SubprocessOptions&)>;

inline Posture posture_macos(const RunFn& run) {
    const std::vector<std::string> argv{"/usr/bin/profiles", "status", "-type", "enrollment"};
    yuzu::agent::SubprocessOptions opts;
    opts.deadline = std::chrono::milliseconds{5000};
    opts.max_lines = 16;
    opts.output_cap_bytes = 16 * 1024;
    opts.merge_stderr = false;
    const auto r = run(argv, opts);

    // Every constrained arm carries NO data rows: never an empty success.
    const auto constrained = [](std::string_view token) {
        yuzu::shared::ConstraintAccumulator acc;
        acc.add_failure(token);
        return Posture{StatusState::constrained, acc.reason(), {}};
    };

    // classify_runner_failure covers termination_reason only (spawn/deadline/cancel/
    // signal/line_limit); exit code and truncation are named here.
    if (const auto f = yuzu::agent::classify_runner_failure(r))
        return constrained(f->provenance);
    if (!r.tool_ran)
        return constrained("subprocess_runner:spawn_error");
    if (r.timed_out)
        return constrained("subprocess_runner:deadline");
    if (r.output_truncated)
        return constrained("macos:mgmt_posture:profiles:output_truncated");
    if (r.exit_code != 0)
        return constrained("macos:mgmt_posture:profiles:exit_nonzero");

    const auto parsed = parse_profiles_status(r.output);
    if (!parsed.recognised())
        return constrained("macos:mgmt_posture:profiles:unrecognised_output");
    return {StatusState::supported, {}, macos_rows(parsed)};
}

} // namespace yuzu::mgmt_posture
