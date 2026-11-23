/**
 * process_introspect_legs.hpp -- the seam between the plugin TU and the Linux shell TU.
 *
 * Holds the request grammar check (parse_request), the pure errno classification (the ONLY place
 * an errno is interpreted), the injected /proc boundary (ProcSource), the OS-free decision
 * (inspect_linux), report (the SINGLE writer of the `status|inspect|...` row) and execute_inspect
 * (the plugin's whole execute() body and its ONE try/catch). Everything here compiles on every
 * OS so the decisions are unit-tested on every OS over an in-memory fake ProcSource; the shell
 * (process_introspect_linux.cpp) only binds syscalls.
 *
 * What is read, in order (Linux): /proc/<pid> is opened ONCE as a directory descriptor; every
 * per-process read is openat on that descriptor, so a recycled pid cannot be read. The only
 * absolute-path reads are the host-wide boot_id and, on the not-found path only,
 * /proc/self/mountinfo. Identity first (`stat` start time +
 * boot id -> token `<boot_id[0:8]>.<starttime>`); a supplied start_time that differs refuses with
 * pid_reused and nothing else is read; then the facet's sources; then `stat` is re-read and any
 * change discards every row (torn_read).
 *
 * Invalid parameters return 1; every process-state outcome returns 0 with a typed status.
 */
#pragma once

#include "process_introspect_parsers.hpp"

#include <constraint_accumulator.hpp>
#include <wire_utf8.hpp>
#include <yuzu/plugin.hpp>
#include <yuzu/string_utils.hpp>

#include <array>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <expected>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace yuzu::process_introspect {

// ---------------------------------------------------------------------------
// Request
// ---------------------------------------------------------------------------

struct Request {
    std::uint32_t pid = 0;
    Facet facet = Facet::resource_limits;
    std::string start_time; ///< empty = no identity guard
};

/// The agent is the trust boundary: direct command dispatch bypasses the definition's schema,
/// so this runs on every OS before any leg. An empty start_time means no guard (Params::get
/// returns "" for a missing key).
[[nodiscard]] inline std::expected<Request, std::string_view>
parse_request(std::string_view pid, std::string_view facet, std::string_view start_time) {
    const auto p = parse_pid(pid);
    if (!p)
        return std::unexpected{std::string_view{"process_introspect:invalid_pid"}};
    const auto f = parse_facet(facet);
    if (!f)
        return std::unexpected{std::string_view{"process_introspect:invalid_facet"}};
    if (!start_time.empty() && !valid_start_time_token(start_time))
        return std::unexpected{std::string_view{"process_introspect:invalid_start_time"}};
    return Request{*p, *f, std::string{start_time}};
}

// ---------------------------------------------------------------------------
// Raw read results and the pure errno classification
// ---------------------------------------------------------------------------

enum class RawErr { none, symlink_refused, not_regular, oversized, io };

/// Local mirror of yuzu::shared::FileRead so this compiles on every OS.
struct RawRead {
    std::string data;
    RawErr error = RawErr::none;
    int err = 0; ///< errno when error == io
};

enum class ReadState { ok, not_found, denied, oversized, io };

/// A not-found open is NOT proof the process is gone; see inspect_linux.
[[nodiscard]] constexpr ReadState classify_open_errno(int err) noexcept {
    if (err == 0)
        return ReadState::ok;
    if (err == ENOENT || err == ESRCH)
        return ReadState::not_found;
    if (err == EACCES || err == EPERM)
        return ReadState::denied;
    return ReadState::io;
}

[[nodiscard]] constexpr ReadState classify_read(RawErr e, int err) noexcept {
    switch (e) {
    case RawErr::none:
        return ReadState::ok;
    case RawErr::oversized:
        return ReadState::oversized;
    case RawErr::io: {
        // Same errno ladder as the open; an io failure carrying errno 0 stays io, never ok.
        const ReadState s = classify_open_errno(err);
        return s == ReadState::ok ? ReadState::io : s;
    }
    case RawErr::symlink_refused:
    case RawErr::not_regular:
        return ReadState::io;
    }
    return ReadState::io;
}

inline constexpr std::size_t kMountinfoCap = 1024 * 1024;

/// The injected /proc boundary. `read` takes `const char*` because the shared reader does and
/// every name is a literal; boot_id and mountinfo are callables so inspect_linux, not the
/// shell, decides when each is read.
struct ProcSource {
    int open_errno = 0; ///< errno of the one /proc/<pid> directory open; 0 when it opened
    std::function<RawRead(const char* name, std::size_t cap)> read;
    std::function<RawRead()> boot_id;
    std::function<RawRead()> mountinfo;
};

// ---------------------------------------------------------------------------
// Inspection and report
// ---------------------------------------------------------------------------

enum class StatusState { supported, constrained, permission_denied, unavailable, unsupported };

struct Inspection {
    StatusState status = StatusState::supported;
    std::string reason;
    std::vector<std::string> rows;
};

/// The SINGLE writer of the `status|inspect|<state>|<reason or ->` row: status row first, then
/// the data rows, then the paired result status. permission_denied pairs with
/// PERMISSION_DENIED/PARTIAL (the pairing every other plugin uses); a refusal about the target
/// (unavailable) and a leg that read nothing (unsupported) pair with UNAVAILABLE/UNKNOWN.
inline void report(yuzu::CommandContext& ctx, const Inspection& r) {
    struct Pairing {
        std::string_view token;
        YuzuResultStatus status;
        YuzuResultCompleteness completeness;
    };
    // Indexed by StatusState.
    static constexpr std::array<Pairing, 5> kPairing{{
        {"supported", YUZU_RESULT_STATUS_OK, YUZU_RESULT_COMPLETENESS_FULL},
        {"constrained", YUZU_RESULT_STATUS_CONSTRAINED, YUZU_RESULT_COMPLETENESS_PARTIAL},
        {"permission_denied", YUZU_RESULT_STATUS_PERMISSION_DENIED,
         YUZU_RESULT_COMPLETENESS_PARTIAL},
        {"unavailable", YUZU_RESULT_STATUS_UNAVAILABLE, YUZU_RESULT_COMPLETENESS_UNKNOWN},
        {"unsupported", YUZU_RESULT_STATUS_UNAVAILABLE, YUZU_RESULT_COMPLETENESS_UNKNOWN},
    }};
    static_assert(kPairing.size() == static_cast<std::size_t>(StatusState::unsupported) + 1);
    const Pairing& p = kPairing[static_cast<std::size_t>(r.status)];
    ctx.write_output("status|inspect|" + std::string{p.token} + '|' +
                     (r.reason.empty() ? std::string{"-"}
                                       : yuzu::util::safe_output_field(r.reason)));
    for (const auto& row : r.rows)
        ctx.write_output(row);
    ctx.set_result_status(p.status, p.completeness,
                          r.status == StatusState::supported ? std::string{} : r.reason);
}

// ---------------------------------------------------------------------------
// The Linux decision (OS-free)
// ---------------------------------------------------------------------------

namespace detail {

inline constexpr std::string_view kTok = "linux:process_introspect:";

[[nodiscard]] inline Inspection refuse(StatusState s, std::string_view cause) {
    return Inspection{s, std::string{kTok} + std::string{cause}, {}};
}

[[nodiscard]] inline std::string facet_token(Facet f, std::string_view cause) {
    return std::string{kTok} + std::string{facet_name(f)} + ':' + std::string{cause};
}

} // namespace detail

/// Source caps (bytes).
inline constexpr std::size_t kStatCap = 4096;
inline constexpr std::size_t kBootIdCap = 64;
inline constexpr std::size_t kStatusCap = 16384;
inline constexpr std::size_t kLimitsCap = 8192;
inline constexpr std::size_t kOomCap = 64;

/// Every source result goes through classify_open_errno / classify_read, so a fake that returns
/// raw errnos drives the real errno arms. See the file header for the order.
[[nodiscard]] inline Inspection inspect_linux(const Request& req, const ProcSource& src) {
    using detail::refuse;
    // (a) the directory open.
    switch (classify_open_errno(src.open_errno)) {
    case ReadState::ok:
        break;
    case ReadState::not_found: {
        // A hidden process and a missing one are the same ENOENT on a /proc mounted with
        // hidepid 2 or above; never assert the process is gone on a host that hides other
        // accounts' processes. The mount table is read on this path only.
        // ponytail: gid= and CAP_SYS_PTRACE exemptions are not evaluated; an exempt agent gets
        // the weaker, still true answer. Evaluate them if operators ask.
        const RawRead m = src.mountinfo();
        const bool visible = classify_read(m.error, m.err) == ReadState::ok &&
                             proc_visibility(m.data) == ProcVisibility::visible;
        return refuse(StatusState::unavailable,
                      visible ? "no_such_process" : "no_such_process_or_hidden");
    }
    case ReadState::denied:
        return refuse(StatusState::permission_denied, "permission_denied");
    case ReadState::oversized:
    case ReadState::io:
        return refuse(StatusState::unavailable, "identity_unreadable");
    }

    // (b) identity: stat + boot id; nothing else is read until the guard passes.
    const RawRead st0 = src.read("stat", kStatCap);
    switch (classify_read(st0.error, st0.err)) {
    case ReadState::ok:
        break;
    case ReadState::not_found:
        // The directory opened, so the process was visible and has exited.
        return refuse(StatusState::unavailable, "no_such_process");
    case ReadState::denied:
        return refuse(StatusState::permission_denied, "permission_denied");
    case ReadState::oversized:
    case ReadState::io:
        return refuse(StatusState::unavailable, "identity_unreadable");
    }
    const auto stat0 = parse_stat(st0.data);
    if (!stat0)
        return refuse(StatusState::unavailable, "identity_unreadable");

    const RawRead bid = src.boot_id();
    switch (classify_read(bid.error, bid.err)) {
    case ReadState::ok:
        break;
    case ReadState::denied:
        return refuse(StatusState::permission_denied, "permission_denied");
    case ReadState::not_found:
    case ReadState::oversized:
    case ReadState::io:
        return refuse(StatusState::unavailable, "identity_unreadable");
    }
    const auto boot8 = boot_prefix(bid.data);
    if (!boot8)
        return refuse(StatusState::unavailable, "identity_unreadable");
    const std::string token = start_time_token(*boot8, stat0->starttime);

    // (c) the caller's guard.
    if (!req.start_time.empty() && req.start_time != token)
        return refuse(StatusState::unavailable, "pid_reused");

    // (d) the facet's sources.
    yuzu::shared::ConstraintAccumulator acc;
    bool all_denied = true; // every recorded token is a permission_denied one
    bool torn = false;
    std::vector<std::string> rows;
    const Facet f = req.facet;
    auto fail = [&](std::string_view cause) {
        acc.add_failure(detail::facet_token(f, cause));
        if (cause != "permission_denied")
            all_denied = false;
    };
    auto fetch = [&](const char* name, std::size_t cap, std::string& out) {
        const RawRead r = src.read(name, cap);
        switch (classify_read(r.error, r.err)) {
        case ReadState::ok:
            out = r.data;
            return true;
        case ReadState::not_found:
            torn = true; // the process exited after identity succeeded
            return false;
        case ReadState::denied:
            fail("permission_denied");
            return false;
        case ReadState::oversized:
            fail("oversized");
            return false;
        case ReadState::io:
            fail("read_failed");
            return false;
        }
        return false;
    };
    auto mask_row = [&](const TextField& tf, std::string_view kind, std::string_view which) {
        if (tf.presence == Presence::ok)
            rows.push_back(format_mask(kind, which, tf.value));
        else
            fail("malformed");
    };

    std::string text;
    switch (f) {
    case Facet::resource_limits:
        if (fetch("limits", kLimitsCap, text)) {
            const LimitsParse lp = parse_limits(text);
            if (!lp.header_seen || lp.rows.empty())
                fail("malformed");
            for (const auto& r : lp.rows)
                rows.push_back(format_limit(r));
            if (lp.unknown_rows > 0)
                fail("unknown_row");
        }
        break;
    case Facet::sigmasks:
        if (fetch("status", kStatusCap, text)) {
            const StatusFields s = parse_status(text);
            mask_row(s.sig_pnd, "sigmask", "pending");
            mask_row(s.shd_pnd, "sigmask", "shared_pending");
            mask_row(s.sig_blk, "sigmask", "blocked");
            mask_row(s.sig_ign, "sigmask", "ignored");
            mask_row(s.sig_cgt, "sigmask", "caught");
        }
        break;
    case Facet::caps:
        if (fetch("status", kStatusCap, text)) {
            const StatusFields s = parse_status(text);
            mask_row(s.cap_inh, "cap", "inheritable");
            mask_row(s.cap_prm, "cap", "permitted");
            mask_row(s.cap_eff, "cap", "effective");
            mask_row(s.cap_bnd, "cap", "bounding");
            mask_row(s.cap_amb, "cap", "ambient");
        }
        break;
    case Facet::seccomp:
        if (fetch("status", kStatusCap, text)) {
            const StatusFields s = parse_status(text);
            if (s.seccomp.presence != Presence::ok || s.no_new_privs.presence == Presence::invalid ||
                s.seccomp_filters.presence == Presence::invalid)
                fail("malformed");
            rows.push_back(format_seccomp(s));
        }
        break;
    case Facet::oom: {
        std::string score_text, adj_text;
        std::optional<std::int32_t> score, adj;
        if (fetch("oom_score", kOomCap, score_text)) {
            score = parse_oom_value(score_text);
            if (!score)
                fail("malformed");
        }
        if (fetch("oom_score_adj", kOomCap, adj_text)) {
            adj = parse_oom_value(adj_text);
            if (!adj)
                fail("malformed");
        }
        if (score || adj)
            rows.push_back(format_oom(score, adj));
        break;
    }
    case Facet::sched: {
        TextField cpus;
        if (fetch("status", kStatusCap, text)) {
            cpus = parse_status(text).cpus_allowed_list;
            if (cpus.presence != Presence::ok)
                fail("malformed");
        }
        rows.push_back(format_sched(*stat0, cpus));
        break;
    }
    }
    if (torn)
        return refuse(StatusState::unavailable, "torn_read");

    // (e) re-read stat: a process that exited, or a pid that was recycled, discards everything.
    const RawRead st1 = src.read("stat", kStatCap);
    if (classify_read(st1.error, st1.err) != ReadState::ok)
        return refuse(StatusState::unavailable, "torn_read");
    const auto stat1 = parse_stat(st1.data);
    if (!stat1 || stat1->starttime != stat0->starttime)
        return refuse(StatusState::unavailable, "torn_read");

    // (f) state.
    Inspection out;
    out.rows.reserve(rows.size() + 1);
    out.rows.push_back(format_target(req.pid, token, f));
    for (auto& r : rows)
        out.rows.push_back(std::move(r));
    if (!acc.any_failure()) {
        out.status = StatusState::supported;
    } else {
        out.reason = acc.reason();
        out.status = (rows.empty() && all_denied) ? StatusState::permission_denied
                                                  : StatusState::constrained;
    }
    return out;
}

// ---------------------------------------------------------------------------
// The plugin's execute() body
// ---------------------------------------------------------------------------

using LegFn = int (*)(yuzu::CommandContext&, const Request&);

/// Linux shell (process_introspect_linux.cpp).
int run_linux(yuzu::CommandContext& ctx, const Request& req);

/// Dispatch, validation and the single ABI containment. An unknown action writes one non-status
/// line and returns 1; an invalid parameter writes one `unavailable` status row and returns 1;
/// a leg that throws gets one `unsupported` row carrying `leg_exception_token` and returns 0
/// (1 if that recovery throws too, rather than unwind across the ABI). Validation runs before
/// the leg on every OS, planned legs included.
inline int execute_inspect(yuzu::CommandContext& ctx, std::string_view action, std::string_view pid,
                           std::string_view facet, std::string_view start_time, LegFn leg,
                           std::string_view leg_exception_token) {
    try {
        if (action != "inspect") {
            std::string a{action};
            yuzu::shared::scrub_wire_bytes(a);
            ctx.write_output("unknown action: " + yuzu::util::safe_output_field(a));
            return 1;
        }
        const auto req = parse_request(pid, facet, start_time);
        if (!req) {
            report(ctx, Inspection{StatusState::unavailable, std::string{req.error()}, {}});
            return 1;
        }
        return leg(ctx, *req);
    } catch (...) {
        try {
            report(ctx, Inspection{StatusState::unsupported, std::string{leg_exception_token}, {}});
        } catch (...) {
            return 1;
        }
        return 0;
    }
}

} // namespace yuzu::process_introspect
