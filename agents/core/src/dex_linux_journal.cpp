#include "dex_linux_journal.hpp"

#include "dex_linux_kmsg.hpp" // classify_kernel_message — all _TRANSPORT=kernel free-text markers

#include <nlohmann/json.hpp>

#include <charconv>
#include <cstdio>
#include <string>
#include <utility>
#include <vector>

namespace yuzu::agent::lnx {

namespace {

using nlohmann::json;

// `journalctl -o json` renders most fields as strings, but a field can be an array
// (a key that repeated in the entry) or an object (binary → a byte array). Take it
// only when it is a plain string; anything else reads as "" so the caller drops it
// rather than shipping binary/structured content.
std::string jstr(const json& j, const char* key) {
    if (!j.is_object())
        return {};
    const auto it = j.find(key);
    if (it != j.end() && it->is_string())
        return it->get<std::string>();
    return {};
}

// Parse a whole string_view as a signed int. nullopt on anything malformed —
// from_chars never throws (a bad COREDUMP_SIGNAL must not unwind the poll thread).
std::optional<int> to_int(std::string_view s) {
    int v = 0;
    const char* const end = s.data() + s.size();
    const auto [p, ec] = std::from_chars(s.data(), end, v);
    if (ec != std::errc{} || p != end)
        return std::nullopt;
    return v;
}

// WP13 / F58 (#3872). MESSAGE_ID, COREDUMP_*, UNIT and UNIT_RESULT are ordinary
// client-settable journal fields (sd_journal_send / `logger --journald`), so they prove
// nothing about who wrote the entry. The underscore-prefixed "trusted" fields are stamped by
// journald from the sender's socket credentials and cannot be set by the client. A MISSING or
// malformed trusted field is untrusted (fail closed): a forged record is dropped.
//
// System manager (PID 1, root): the genuine "<unit>: Failed with result" entries.
bool from_system_manager(const json& j) {
    return jstr(j, "_PID") == "1" && jstr(j, "_UID") == "0";
}

// systemd-coredump runs as root; its comm is the 15-char truncation "systemd-coredum" and its
// unit is systemd-coredump@<n>.service. Root is the load-bearing term (a non-root process
// cannot claim _UID=0); the name terms bind it to the coredump helper rather than any root
// sender. NOT yet confirmed against a live capture (none on the measuring host) - see
// docs/dex-signal-catalog.md.
bool from_coredump_helper(const json& j) {
    // Safe superset (WP13 governance S3): root is the load-bearing term; ONE name term binds it
    // to the helper. The comm is matched by prefix because the kernel truncates it to 15 chars
    // and a distro may suffix it; the unit form covers a service-launched helper. The identity
    // is derived from systemd documentation, not from a captured journal entry on every distro
    // family; a mismatch would silently drop process.crashed there, which is why a drop here is
    // counted and logged by the collector. One specimen per distro family is an open follow-up.
    if (jstr(j, "_UID") != "0")
        return false;
    if (jstr(j, "_COMM").starts_with("systemd-coredum"))
        return true;
    return jstr(j, "_SYSTEMD_UNIT").starts_with("systemd-coredump@");
}

// chronyd: `_COMM` is settable with prctl(PR_SET_NAME) (#3871), so it is NOT sufficient.
// `_SYSTEMD_UNIT` is derived from the sender's cgroup; only root can place a process in the
// chrony service's cgroup. Require both.
bool from_chronyd_service(const json& j) {
    if (jstr(j, "_COMM") != "chronyd")
        return false;
    const std::string unit = jstr(j, "_SYSTEMD_UNIT");
    return unit == "chronyd.service" || unit == "chrony.service";
}

} // namespace

std::string crash_signal_name(int signo) {
    switch (signo) {
    case 3:  return "SIGQUIT";
    case 4:  return "SIGILL";
    case 5:  return "SIGTRAP";
    case 6:  return "SIGABRT";
    case 7:  return "SIGBUS";
    case 8:  return "SIGFPE";
    case 11: return "SIGSEGV";
    case 24: return "SIGXCPU";
    case 25: return "SIGXFSZ";
    case 31: return "SIGSYS";
    default: return "signal " + std::to_string(signo);
    }
}

JournalLine parse_journal_line(std::string_view line) {
    JournalLine out;
    const json j = json::parse(line, nullptr, /*allow_exceptions=*/false);
    if (j.is_discarded() || !j.is_object())
        return out; // cursor "", obs nullopt
    out.cursor = jstr(j, "__CURSOR");

    const std::string mid = jstr(j, "MESSAGE_ID");

    // ── systemd-coredump entry → process.crashed ─────────────────────────────
    // Every coredump is a crash by definition (systemd-coredump only fires on a
    // core-generating signal), so no intentional-stop filtering is needed. Subject
    // is the comm only — COREDUMP_EXE (a full path) is never shipped.
    if (mid == kMsgIdCoredump) {
        if (!from_coredump_helper(j)) {
            out.untrusted_dropped = true;
            return out; // forged / untrusted sender: no observation
        }
        const std::string comm = jstr(j, "COREDUMP_COMM");
        if (comm.empty())
            return out; // no safe subject
        SignalObservation o;
        o.obs_type = "process.crashed";
        o.subject = comm;
        o.kind = "signal";
        if (const auto sig = to_int(jstr(j, "COREDUMP_SIGNAL")))
            o.reason = crash_signal_name(*sig);
        o.sentence = comm + " crashed" + (o.reason.empty() ? std::string{} : " (" + o.reason + ")");
        out.obs = std::move(o);
        return out;
    }

    // ── systemd unit failed → service.crashed ───────────────────────────────
    // EMPIRICAL (systemd 259, live capture): the "<unit>: Failed with result 'X'."
    // entry (kMsgIdUnitResult / d9b373ed) is the carrier — it fires for BOTH a
    // running service that dies AND a service that fails to start (bad ExecStart,
    // bad WorkingDirectory). SD_MESSAGE_UNIT_FAILED (be02) did NOT appear in any
    // tested crash/start-fail case, but it is kept in the match as defensive cover
    // for paths not exercised (oneshot units, start-limit-hit, dependency failure).
    //
    // Both map to service.crashed — NOT split into service.crashed vs
    // service.start_failed — because the two are indistinguishable by MESSAGE_ID
    // (d9b3 carries both), and the only start-fail discriminator (the "Failed at
    // step EXEC/CHDIR" SPAWN_FAILED entry) is a SEPARATE record that co-occurs with
    // d9b3, so mapping it too would emit two observations for one failure. Splitting
    // would need cross-entry correlation, which this stateless one-entry-per-failure
    // classifier deliberately avoids. UNIT_RESULT (exit-code / signal / core-dump /
    // timeout / oom-kill) is the reason when present; absent → empty reason.
    if (mid == kMsgIdUnitFailed || mid == kMsgIdUnitResult) {
        if (!from_system_manager(j)) {
            out.untrusted_dropped = true;
            return out; // forged / user-manager / untrusted sender: no observation
        }
        const std::string unit = jstr(j, "UNIT");
        if (unit.empty())
            return out;
        const std::string result = jstr(j, "UNIT_RESULT");
        SignalObservation o;
        o.subject = unit;
        o.kind = "unit";
        o.reason = result;
        // A WatchdogSec timeout (UNIT_RESULT="watchdog", live-verified) means the
        // service stopped pinging the watchdog and systemd killed it — that is a HANG,
        // not an ordinary crash, so it routes to service.hung. Every other result
        // (exit-code / signal / core-dump / timeout / oom-kill) stays service.crashed.
        // ONE entry, routed by result — no double-emit, no new MESSAGE_ID, no query change.
        if (result == "watchdog") {
            o.obs_type = "service.hung";
            o.kind = "hang";
            o.sentence = unit + " hung (watchdog timeout)";
        } else {
            o.obs_type = "service.crashed";
            o.sentence =
                unit + " failed" + (result.empty() ? std::string{} : " (result: " + result + ")");
        }
        out.obs = std::move(o);
        return out;
    }

    // ── kernel ring-buffer line → free-text marker classification ────────────
    // Kernel messages carry no stable MESSAGE_ID, so every _TRANSPORT=kernel line is
    // classified by anchored substring markers in dex_linux_kmsg (OOM-killer, fatal
    // panic, MCE, disk/fs errors, journal recovery, hung-task). A line matching no
    // marker advances the cursor with no observation.
    if (jstr(j, "_TRANSPORT") == "kernel") {
        out.obs = classify_kernel_message(jstr(j, "MESSAGE"));
        return out;
    }

    // ── chronyd clock-unsynchronised → os.time_unsynced ──────────────────────
    // chrony logs free text (no MESSAGE_ID); we classify ONLY the genuine "clock is not
    // synchronised" markers (live-captured: "Can't synchronise: no selectable sources";
    // plus chrony's large-step message). The frequent "Source … online/offline" lines
    // produce NO observation — the cursor still advances. The raw MESSAGE can carry NTP
    // source IPs, so it is NEVER shipped — a fixed sentence + subject "clock" only.
    //
    // INTEGRITY (#3871): `SYSLOG_IDENTIFIER` is client-set, and `_COMM` alone is also
    // forgeable (prctl(PR_SET_NAME), or an executable named chronyd). The decisive term is
    // `_SYSTEMD_UNIT` (chronyd.service / chrony.service), journald-derived from the sender's
    // cgroup, which an unprivileged process cannot join; `_COMM` stays as a second term.
    if (jstr(j, "_COMM") == "chronyd") {
        if (!from_chronyd_service(j)) {
            out.untrusted_dropped = true;
            return out; // right comm, wrong/absent service cgroup: forged
        }

        const std::string m = jstr(j, "MESSAGE");
        if (m.find("Can't synchronise: no selectable sources") != std::string::npos ||
            m.find("System clock wrong by") != std::string::npos) {
            SignalObservation o;
            o.obs_type = "os.time_unsynced";
            o.subject = "clock";
            o.reason = "unsynced";
            o.sentence = "System clock not synchronised";
            out.obs = std::move(o);
        }
        return out;
    }

    return out;
}

bool read_pipe_line(std::FILE* f, std::string& out) {
    out.clear();
    char buf[16384];
    while (std::fgets(buf, sizeof(buf), f)) {
        out += buf;
        if (!out.empty() && out.back() == '\n') {
            out.pop_back();
            if (!out.empty() && out.back() == '\r')
                out.pop_back();
            return true;
        }
    }
    return !out.empty(); // a final line with no trailing newline
}

std::string journald_baseline_query() {
    // `timeout` (coreutils) bounds a wedged journalctl so the baseline read cannot
    // hang the poll thread; on a host without `timeout` the shell reports not-found
    // and the source simply no-ops this tick (cursor stays empty, retried next poll).
    return "timeout 30 journalctl -o json -n 1 --no-pager 2>/dev/null";
}

std::optional<std::string> build_journald_after_cursor_query(std::string_view cursor) {
    if (cursor.find('\'') != std::string_view::npos)
        return std::nullopt; // a real __CURSOR never contains a quote → signal re-baseline
    std::string cmd;
    cmd.reserve(256);
    cmd += "timeout 30 journalctl --after-cursor='";
    cmd.append(cursor); // the ONLY external input, confined to this single-quoted slot
    // journalctl ANDs distinct fields, ORs repeats of one field, and `+` separates whole
    // disjuncts. WP13/F58: every reliability disjunct also carries the journald-stamped
    // sender terms (parse_journal_line re-checks them), so forged entries are never fetched
    // and cannot reach the rate limiter:
    //   (coredump id AND _UID=0)
    //   + (unit-failed/result ids AND _PID=1 AND _UID=0)
    //   + (kernel transport lines, classified in dex_linux_kmsg)
    //   + (chronyd comm AND the chrony service unit; only the clock-unsynchronised markers
    //      map to an observation, chronyd is low-volume).
    cmd += "' -o json --no-pager MESSAGE_ID=";
    cmd.append(kMsgIdCoredump);
    cmd += " _UID=0";
    cmd += " + MESSAGE_ID=";
    cmd.append(kMsgIdUnitFailed);
    cmd += " MESSAGE_ID=";
    cmd.append(kMsgIdUnitResult);
    cmd += " _PID=1 _UID=0";
    cmd += " + _TRANSPORT=kernel";
    cmd += " + _COMM=chronyd _SYSTEMD_UNIT=chronyd.service _SYSTEMD_UNIT=chrony.service";
    cmd += " 2>/dev/null";
    return cmd;
}

std::vector<SignalObservation> drain_journal_pipe(std::FILE* pipe, std::string& cursor,
                                                  std::size_t* untrusted_dropped) {
    std::vector<SignalObservation> out;
    std::string newest = cursor;
    std::string line;
    while (read_pipe_line(pipe, line)) {
        JournalLine jl = parse_journal_line(line);
        if (!jl.cursor.empty())
            newest = std::move(jl.cursor); // chronological → last non-empty wins
        if (jl.untrusted_dropped && untrusted_dropped)
            ++*untrusted_dropped;
        if (jl.obs)
            out.push_back(std::move(*jl.obs));
    }
    cursor = std::move(newest);
    return out;
}

bool JournalDebounce::should_emit(const std::string& obs_type, const std::string& subject,
                                  std::int64_t now_mono) {
    const std::string key = obs_type + "|" + subject;
    if (const auto it = seen_.find(key); it != seen_.end() && now_mono - it->second < window_)
        return false; // within the debounce window — collapse
    seen_[key] = now_mono;
    return true;
}

void JournalDebounce::evict_stale(std::int64_t now_mono) {
    std::erase_if(seen_, [&](const auto& kv) { return now_mono - kv.second >= window_; });
}

} // namespace yuzu::agent::lnx
