#include "dex_macos_signals.hpp"

#include <nlohmann/json.hpp>

#include <yuzu/version_string.hpp>

#include <array>
#include <cctype>
#include <cmath>
#include <string>
#include <string_view>

namespace yuzu::agent::macos {

namespace {

using nlohmann::json;

// ── Defensive JSON accessors ─────────────────────────────────────────────────
// nlohmann's value()/operator[] throw on a type mismatch; these never throw, so
// a report with a missing/renamed/retyped field degrades to an empty field (a
// counted occurrence) instead of unwinding out of the OS watcher thread.

std::string jstr(const json& j, const char* key) {
    if (!j.is_object())
        return {};
    const auto it = j.find(key);
    if (it != j.end() && it->is_string())
        return it->get<std::string>();
    return {};
}

std::int64_t jint(const json& j, const char* key) {
    if (!j.is_object())
        return 0;
    const auto it = j.find(key);
    if (it != j.end() && it->is_number_integer())
        return it->get<std::int64_t>();
    return 0;
}

const json* jobj(const json& j, const char* key) {
    if (!j.is_object())
        return nullptr;
    const auto it = j.find(key);
    return (it != j.end()) ? &*it : nullptr;
}

// bug_type is a string in modern reports ("309") but tolerate a numeric form.
std::string bug_type_of(const json& header) {
    std::string bt = jstr(header, "bug_type");
    if (bt.empty()) {
        if (const auto it = header.is_object() ? header.find("bug_type") : header.end();
            it != header.end() && it->is_number_integer())
            bt = std::to_string(it->get<std::int64_t>());
    }
    return bt;
}

// The faulting image BASENAME (privacy: never the path). usedImages[ frames[0]
// .imageIndex ] for the faulting thread — that is the binary the crash blames.
std::string faulting_image(const json& body) {
    const json* threads = jobj(body, "threads");
    if (!threads || !threads->is_array())
        return {};
    const std::int64_t ft = jint(body, "faultingThread"); // 0-based index
    if (ft < 0 || ft >= static_cast<std::int64_t>(threads->size()))
        return {};
    const json& th = (*threads)[static_cast<std::size_t>(ft)];
    const json* frames = jobj(th, "frames");
    if (!frames || !frames->is_array() || frames->empty())
        return {};
    const std::int64_t img = jint((*frames)[0], "imageIndex");
    const json* images = jobj(body, "usedImages");
    if (!images || !images->is_array() || img < 0 ||
        img >= static_cast<std::int64_t>(images->size()))
        return {};
    return jstr((*images)[static_cast<std::size_t>(img)], "name"); // basename only
}

std::string non_empty(const std::string& a, const std::string& b) { return a.empty() ? b : a; }

// The app's marketing version (CFBundleShortVersionString), canonicalised to the
// shared 4-group quad so macOS crashes/hangs join the same per-(app,version)
// reliability identity the Windows path builds. Prefer the .ips HEADER's
// `app_version` (present for bundled/signed apps); fall back to the BODY's
// `bundleInfo.CFBundleShortVersionString`. A bare/unsigned CLI binary has
// neither, so this degrades to "" — the shared unknown bucket.
std::string ips_app_version(const json& header, const json& body) {
    std::string v = jstr(header, "app_version");
    if (v.empty()) {
        if (const json* bundle_info = jobj(body, "bundleInfo"))
            v = jstr(*bundle_info, "CFBundleShortVersionString");
    }
    return yuzu::util::canon_version(v);
}

// ── `.diag` plain-text helpers ───────────────────────────────────────────────

std::string trim(std::string_view s) {
    std::size_t b = 0, e = s.size();
    while (b < e && std::isspace(static_cast<unsigned char>(s[b])))
        ++b;
    while (e > b && std::isspace(static_cast<unsigned char>(s[e - 1])))
        --e;
    return std::string(s.substr(b, e - b));
}

// Value of the first line whose first non-space token is `key` ("Command:" ->
// "system_installd"). "" when absent.
std::string diag_value(const std::string& text, std::string_view key) {
    std::size_t pos = 0;
    while (pos <= text.size()) {
        const std::size_t eol = text.find('\n', pos);
        const std::string_view line(text.data() + pos,
                                    (eol == std::string::npos ? text.size() : eol) - pos);
        std::size_t s = 0;
        while (s < line.size() && std::isspace(static_cast<unsigned char>(line[s])))
            ++s;
        const std::string_view body = line.substr(s);
        if (body.size() >= key.size() && body.substr(0, key.size()) == key)
            return trim(body.substr(key.size()));
        if (eol == std::string::npos)
            break;
        pos = eol + 1;
    }
    return {};
}

// Leading number of a value like "90s" / "179.37s" -> 90 / 179.37 (0 on failure).
double leading_number(const std::string& s) {
    try {
        std::size_t used = 0;
        const double v = std::stod(s, &used);
        // std::stod returns ±Inf/NaN for "inf"/"nan"/overflow WITHOUT throwing, so
        // the catch never fires — guard explicitly or a non-finite value poisons
        // the metric gauge (governance B2; the prior Windows std::stod lesson).
        return (used > 0 && std::isfinite(v)) ? v : 0.0;
    } catch (...) {
        return 0.0;
    }
}

std::string humanize_uptime(std::int64_t secs) {
    const std::int64_t d = secs / 86400, h = (secs % 86400) / 3600, m = (secs % 3600) / 60;
    if (d > 0)
        return "System uptime " + std::to_string(d) + "d " + std::to_string(h) + "h";
    if (h > 0)
        return "System uptime " + std::to_string(h) + "h " + std::to_string(m) + "m";
    return "System uptime " + std::to_string(m) + "m";
}

} // namespace

std::optional<SignalObservation> parse_ips_report(const std::string& ips_content) {
    // A `.ips` is TWO concatenated JSON documents: a one-line header object, then
    // a separate body object. Parsing the whole file as one JSON throws on the
    // trailing document — split on the first newline and parse each half.
    const std::size_t nl = ips_content.find('\n');
    const std::string header_str = ips_content.substr(0, nl);
    const std::string body_str =
        (nl == std::string::npos) ? std::string{} : ips_content.substr(nl + 1);

    const json header = json::parse(header_str, nullptr, /*allow_exceptions=*/false);
    const json body = json::parse(body_str, nullptr, /*allow_exceptions=*/false);

    const std::string bug = bug_type_of(header.is_discarded() ? body : header);

    SignalObservation o;
    o.timestamp_unix = 0; // engine stamps delivery time

    // crash family (modern 309, legacy 109/385): unhandled exception / fatal signal
    if (bug == "309" || bug == "109" || bug == "385") {
        o.obs_type = "process.crashed";
        o.kind = "exception";
        o.subject = non_empty(jstr(body, "procName"),
                              non_empty(jstr(header, "name"), jstr(header, "app_name")));
        o.pid = static_cast<std::uint32_t>(jint(body, "pid"));
        if (const json* exc = jobj(body, "exception")) {
            o.reason = jstr(*exc, "signal");   // "SIGSEGV" — machine-ish token
            o.symbolic = jstr(*exc, "type");   // "EXC_BAD_ACCESS" — symbolic name
        }
        o.component = faulting_image(body);    // faulting binary basename
        o.sentence = non_empty(o.subject, "A process") + " crashed";
        if (!o.reason.empty())
            o.sentence +=
                " (" + o.reason + (o.symbolic.empty() ? "" : " / " + o.symbolic) + ")";
        o.version = ips_app_version(header, body);
        return o;
    }

    // spin / hang (app stopped responding — the macOS App-Hang equivalent)
    if (bug == "288" || bug == "388") {
        o.obs_type = "process.hung";
        o.kind = "hang";
        o.subject = non_empty(jstr(body, "procName"),
                              non_empty(jstr(header, "name"), jstr(header, "app_name")));
        o.pid = static_cast<std::uint32_t>(jint(body, "pid"));
        o.sentence = non_empty(o.subject, "A process") + " stopped responding";
        o.version = ips_app_version(header, body);
        return o;
    }

    // kernel panic (the BSOD equivalent). We deliberately do NOT ship the raw
    // panicString — it can be large and pointer-laden; the DEX-relevant fact is
    // simply that the machine panicked.
    if (bug == "210" || bug == "110") {
        o.obs_type = "os.bugcheck";
        o.subject = "kernel";
        o.sentence = "Kernel panic";
        return o;
    }

    // jetsam (memory pressure killed processes). largestProcess names the biggest
    // memory consumer at the time — the entity to attribute the pressure to.
    if (bug == "298") {
        o.obs_type = "memory.exhausted";
        o.subject = jstr(body, "largestProcess");
        o.reason = "memory_pressure";
        o.sentence = o.subject.empty()
                         ? "System memory pressure (process killed)"
                         : "Memory pressure — largest process " + o.subject;
        return o;
    }

    return std::nullopt; // not a DEX-mapped report type
}

std::optional<SignalObservation> parse_diag_report(const std::string& diag_content) {
    const std::string event = diag_value(diag_content, "Event:");
    const std::string command = diag_value(diag_content, "Command:");
    if (event.empty() && command.empty())
        return std::nullopt; // not a resource-style .diag (Microstackshots header)

    SignalObservation o;
    o.obs_type = "process.resource_limit";
    o.subject = command;
    // Normalise the macOS event phrase to a stable reason token.
    if (event.rfind("cpu", 0) == 0 || event.find("cpu") != std::string::npos)
        o.reason = "cpu";
    else if (event.find("wakeups") != std::string::npos)
        o.reason = "wakeups";
    else if (event.find("disk") != std::string::npos)
        o.reason = "disk_writes";
    else
        o.reason = trim(event);

    if (o.reason == "cpu")
        o.metric = leading_number(diag_value(diag_content, "CPU used:"));

    o.sentence = non_empty(command, "A process") + " exceeded its " +
                 (o.reason.empty() ? event : o.reason) + " budget";
    return o;
}

std::optional<SignalObservation> uptime_observation(std::int64_t boot_unix, std::int64_t now_unix) {
    if (boot_unix <= 0)
        return std::nullopt;
    std::int64_t up = now_unix - boot_unix;
    if (up < 0)
        up = 0;
    SignalObservation o;
    o.obs_type = "os.uptime_report";
    o.subject = "host";
    o.metric = static_cast<double>(up);
    o.sentence = humanize_uptime(up);
    return o;
}

} // namespace yuzu::agent::macos
