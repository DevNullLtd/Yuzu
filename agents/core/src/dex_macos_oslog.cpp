#include "dex_macos_oslog.hpp"

#include <nlohmann/json.hpp>

#include <array>
#include <cmath>
#include <string>
#include <string_view>

namespace yuzu::agent::macos {

namespace {

using nlohmann::json;

std::string jstr(const json& j, const char* key) {
    if (!j.is_object())
        return {};
    const auto it = j.find(key);
    if (it != j.end() && it->is_string())
        return it->get<std::string>();
    return {};
}

// The launchd job label out of a subsystem like "system/com.apple.threadradiod
// [2699]" → "com.apple.threadradiod" (strip the "<domain>/" prefix and " [pid]").
std::string launchd_label(const std::string& subsystem) {
    std::string s = subsystem;
    if (const std::size_t slash = s.find('/'); slash != std::string::npos)
        s = s.substr(slash + 1);
    if (const std::size_t br = s.find(" ["); br != std::string::npos)
        s = s.substr(0, br);
    return s;
}

// A signal name that means "intentional stop", not "crash" — dropped.
bool is_intentional_signal(std::string_view sig) {
    static constexpr std::array kIntentional{"SIGTERM", "SIGKILL", "SIGINT", "SIGHUP", "SIGSTOP"};
    for (const auto* s : kIntentional)
        if (sig == s)
            return true;
    return false;
}

// Non-finite guard: std::stod returns ±Inf/NaN for "inf"/"nan"/overflow WITHOUT
// throwing, so a non-finite literal would flow straight into o.metric and poison
// the gauge (governance B2 — the recurring std::stod lesson).
double finite_or_zero(double v) {
    return std::isfinite(v) ? v : 0.0;
}

double leading_ms(std::string_view s) {
    try {
        return finite_or_zero(std::stod(std::string(s))); // "2761ms" → 2761
    } catch (...) {
        return 0.0;
    }
}

std::string basename_of(const std::string& path) {
    const std::size_t s = path.rfind('/');
    return s == std::string::npos ? path : path.substr(s + 1);
}

long int_after(const std::string& msg, std::string_view key) {
    const std::size_t p = msg.find(key);
    if (p == std::string::npos)
        return 0;
    try {
        return std::stol(msg.substr(p + key.size()));
    } catch (...) {
        return 0;
    }
}

double double_after(const std::string& msg, std::string_view key) {
    const std::size_t p = msg.find(key);
    if (p == std::string::npos)
        return 0.0;
    try {
        return finite_or_zero(std::stod(msg.substr(p + key.size())));
    } catch (...) {
        return 0.0;
    }
}

} // namespace

std::optional<SignalObservation> parse_oslog_event(const std::string& line) {
    const json j = json::parse(line, nullptr, /*allow_exceptions=*/false);
    if (j.is_discarded() || !j.is_object())
        return std::nullopt;

    const std::string proc = jstr(j, "processImagePath");
    const std::string msg = jstr(j, "eventMessage");

    // ── launchd service exits → service.crashed (abnormal only) ──────────────
    // "exited due to exit(1), ran for 2761ms"  /  "exited due to signal SIGSEGV, …"
    if (proc == "/sbin/launchd" && msg.rfind("exited due to", 0) == 0) {
        SignalObservation o;
        o.obs_type = "service.crashed";
        o.subject = launchd_label(jstr(j, "subsystem"));

        if (const std::size_t p = msg.find("signal "); p != std::string::npos) {
            std::string sig = msg.substr(p + 7);
            if (const std::size_t e = sig.find_first_of(", "); e != std::string::npos)
                sig = sig.substr(0, e);
            // Privacy (UP-6): a signal token is a short "SIG*" name. If the format
            // is unexpected, DROP rather than ship the raw message tail as `reason`
            // — that tail can carry paths/usernames the happy path never emits.
            if (sig.rfind("SIG", 0) != 0 || sig.size() > 16)
                return std::nullopt;
            if (is_intentional_signal(sig))
                return std::nullopt; // a managed stop, not a crash
            o.reason = sig; // e.g. SIGSEGV
            o.kind = "signal";
        } else if (const std::size_t q = msg.find("exit("); q != std::string::npos) {
            std::string code = msg.substr(q + 5);
            const std::size_t e = code.find(')');
            if (e == std::string::npos)
                return std::nullopt; // unexpected format — don't ship a raw tail (UP-6)
            code = code.substr(0, e);
            // Exit codes are numeric; anything else is an unexpected format → drop.
            if (code.empty() || code.find_first_not_of("-0123456789") != std::string::npos)
                return std::nullopt;
            if (code == "0")
                return std::nullopt; // clean exit — not a failure
            o.reason = "exit(" + code + ")";
            o.kind = "exit";
        } else {
            return std::nullopt; // unrecognised termination form
        }

        if (const std::size_t r = msg.find("ran for "); r != std::string::npos)
            o.metric = leading_ms(std::string_view(msg).substr(r + 8)); // runtime ms

        o.sentence = (o.subject.empty() ? "A service" : o.subject) + " exited abnormally (" +
                     o.reason + ")";
        return o;
    }

    // ── symptomsd link-quality degradation → network.wifi_drop (Network) ─────
    // "Realtime LQM changed: new-lqm -2 old-lqm 0 data-stalls 33.00 ... interface-type 3".
    // Negative LQM and/or data-stalls = the user's connectivity is degrading.
    if (jstr(j, "subsystem") == "com.apple.symptomsd" && msg.find("LQM changed") != std::string::npos) {
        const long lqm = int_after(msg, "new-lqm ");
        const double stalls = double_after(msg, "data-stalls ");
        if (lqm >= 0 && stalls < 1.0)
            return std::nullopt; // a healthy transition, not a degradation
        SignalObservation o;
        o.obs_type = "network.wifi_drop";
        o.subject = "Wi-Fi";
        o.reason = "lqm=" + std::to_string(lqm);
        o.metric = stalls; // data-stall count
        o.sentence = "Wi-Fi link degraded (LQM " + std::to_string(lqm) +
                     (stalls >= 1.0 ? ", data stalls" : "") + ")";
        return o;
    }

    // ── Error/Fault-level events from known DEX-relevant system processes ─────
    // Maps a failing subsystem onto its heading signal. OCCURRENCE-based by
    // design: the raw eventMessage (which for opendirectoryd/MDM can carry
    // usernames or paths) is NEVER shipped — subject is the process basename and
    // the DEX fact is "this subsystem is failing on this device". These are
    // best-effort until a real failure specimen tunes them (the macOS analogue of
    // the Windows manifest-pinned fixtures); the predicate pre-filters to
    // error/fault level so the agent only sees the failure subset.
    const std::string mt = jstr(j, "messageType");
    if (mt == "Error" || mt == "Fault") {
        const std::string procname = basename_of(proc);
        const std::string subsystem = jstr(j, "subsystem");
        struct Map {
            const char* match;
            bool is_subsystem;
            const char* obs_type;
            const char* what;
        };
        static const Map kMap[] = {
            {"softwareupdated", false, "update.failed", "Software update error"},
            {"cupsd", false, "print.failed", "Print service error"},
            {"mdmclient", false, "mgmt.mdm_error", "MDM client error"},
            {"opendirectoryd", false, "logon.no_dc", "Directory service error"},
            {"com.apple.apfs", true, "fs.corruption", "Filesystem error"},
        };
        for (const auto& m : kMap) {
            const bool hit = m.is_subsystem ? (subsystem == m.match) : (procname == m.match);
            if (!hit)
                continue;
            SignalObservation o;
            o.obs_type = m.obs_type;
            o.subject = m.is_subsystem ? subsystem : procname;
            o.sentence = std::string(m.what) + " (" + o.subject + ")";
            return o;
        }
    }

    return std::nullopt;
}

std::string oslog_predicate() {
    // The union of every class parse_oslog_event understands. logd evaluates this
    // server-side so the agent never processes the full firehose (error/fault
    // pre-filter keeps the system-process clauses to the failure subset). Keep in
    // sync with the branches above when adding a signal class.
    // NOTE the casing asymmetry: NSPredicate messageType enum values are
    // lowercase ("error"/"fault") while the emitted JSON field is capitalized
    // ("Error"/"Fault", matched by parse_oslog_event) — do not "clean up" either
    // side to match the other; the predicate-parity unit test pins both.
    return R"((process == "launchd" AND eventMessage CONTAINS "exited due to"))"
           R"( OR (process == "symptomsd" AND eventMessage CONTAINS "LQM changed"))"
           R"( OR ((process == "softwareupdated" OR process == "cupsd" OR process == "mdmclient")"
           R"( OR process == "opendirectoryd") AND (messageType == "error" OR messageType == "fault")))"
           R"( OR (subsystem == "com.apple.apfs" AND (messageType == "error" OR messageType == "fault")))";
}

} // namespace yuzu::agent::macos
