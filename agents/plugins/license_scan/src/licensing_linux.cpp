/**
 * licensing_linux.cpp — Linux detection surfaces for the license_scan plugin
 * (SLE roadmap §5 PR1 detection-surface table; ADR-0024 Decision 2).
 *
 * Surfaces (probe_status tokens):
 *   pkg_metadata      — rpm `%{LICENSE}` (probable) or dpkg DEP-5 copyright
 *                       headers (heuristic). Declared-licence CLASSIFICATION
 *                       only (license_type open_source|freeware|unknown) —
 *                       no lapse detection, a stated gap recorded in the
 *                       os-capability-matrix rows.
 *   entitlement_certs — RHEL entitlement certificates
 *                       (/etc/pki/entitlement/*.pem notAfter). Authoritative
 *                       subscription expiry. Uses `openssl x509` via
 *                       subprocess, matching the certificates plugin's
 *                       established agent crypto usage — the agent has no
 *                       shared in-process X509 helper.
 *   flexlm_lic        — FlexLM `.lic` files under conventional dirs, via the
 *                       ProbeSpec table rows (pure INCREMENT parser;
 *                       authoritative expiry).
 *
 * Primary-surface honesty (ADR-0024 D3): "success" is structural — the
 * enumeration completed (a query returning zero rows is success;
 * a failed subprocess is error).
 */

#ifdef __linux__

#include <yuzu/agent/subprocess_runner.hpp> // yuzu::agent::run_bounded_subprocess / probe_tool_path (ADR-3002 rung 2)

#include <chrono>
#include <cstdlib>
#include <string>
#include <utility>
#include <vector>

#include "licensing_parsers.hpp"
#include "licensing_probes.hpp"
#include "licensing_record.hpp"

namespace yuzu::license_scan {

namespace {

// ── subprocess helpers (ADR-3002 rung-2 migration, Wave 4 PR4.3b) ──────────
//
// Replaces the prior run_command_rc() (popen -> /bin/sh -c) + command_exists()
// (std::system) pair. argv elements are injection-proof by construction (no
// shell in between), so the shell_single_quote() escaping this replaces is
// gone outright -- there is no shell metacharacter surface left to escape
// against once a value is just another argv element.

struct CommandResult {
    std::string output;
    bool ok = false;        // tool_ran && exit_code==0 && !timed_out
    bool truncated = false; // output_truncated -- caller must treat this as a
                             // distinct, honest failure mode: capture stopped
                             // early, so `output` (and hence anything parsed
                             // from it) may be incomplete even when `ok` is
                             // otherwise true. A truncated rpm -qa in
                             // particular is a false-negative surface (some
                             // installed packages silently missing from the
                             // result) -- never treated as a quiet partial
                             // success.
};

CommandResult run_argv(const std::vector<std::string>& argv) {
    CommandResult result;
    if (argv.empty() || argv.front().empty())
        return result; // probe miss: honest "tool not found", no OS call attempted
    const auto res = yuzu::agent::run_bounded_subprocess(
        argv, yuzu::agent::SubprocessOptions{.deadline = std::chrono::seconds{20}});
    result.output = res.output;
    result.ok = res.tool_ran && res.exit_code == 0 && !res.timed_out;
    result.truncated = res.output_truncated;
    return result;
}

std::vector<std::string> split_lines(const std::string& text) {
    std::vector<std::string> lines;
    std::size_t pos = 0;
    while (pos < text.size()) {
        std::size_t eol = text.find('\n', pos);
        if (eol == std::string::npos)
            eol = text.size();
        if (eol > pos)
            lines.emplace_back(text.substr(pos, eol - pos));
        pos = eol + 1;
    }
    return lines;
}

std::vector<std::string> split_tabs(const std::string& line) {
    std::vector<std::string> fields;
    std::size_t pos = 0;
    while (pos <= line.size()) {
        std::size_t tab = line.find('\t', pos);
        if (tab == std::string::npos)
            tab = line.size();
        fields.emplace_back(line.substr(pos, tab - pos));
        if (tab == line.size())
            break;
        pos = tab + 1;
    }
    return fields;
}

// ── pkg_metadata (surface table Linux row 1) ───────────────────────────────

void run_pkg_metadata_surface(ProbeHost& host, std::vector<LicRecord>& records,
                              std::vector<ProbeOutcome>& outcomes) {
    std::size_t emitted = 0;

    auto rpm = yuzu::agent::probe_tool_path({"/usr/bin/rpm", "/bin/rpm"});
    if (!rpm.empty()) {
        // license_scan/run_pkg_metadata_surface_linux#1 (docs/agent-spawn-sink-manifest.md)
        // Queryformat string kept byte-identical to the pre-migration shell
        // form -- the literal backslash-t/backslash-n escapes are interpreted
        // by rpm's own queryformat engine (not a shell), producing real
        // tab/newline bytes in the output that split_lines/split_tabs below
        // still parse unchanged.
        const auto res =
            run_argv({rpm, "-qa", "--queryformat",
                     "%{NAME}\\t%{VERSION}-%{RELEASE}\\t%{VENDOR}\\t%{LICENSE}\\n"});
        if (res.truncated) {
            // A truncated rpm -qa is a false-negative surface (some installed
            // packages silently missing) -- a distinct, honest outcome, never
            // folded into "query failed" or a silent partial success. rpm DID
            // run and IS the real tool here, so this stays terminal rather
            // than falling through to a second tool that would just re-run
            // the whole enumeration and produce a different partial result.
            outcomes.push_back({"pkg_metadata", false, 0, "output_truncated"});
            return;
        }
        if (res.ok) {
            for (const auto& line : split_lines(res.output)) {
                const auto fields = split_tabs(line);
                if (fields.size() < 4 || fields[0].empty())
                    continue;
                LicRecord r;
                r.product = fields[0];
                r.version = fields[1];
                r.vendor = fields[2] == "(none)" ? "" : fields[2];
                r.license_type = classify_license_string(fields[3]); // open_source|freeware|unknown
                r.status = "unknown"; // classification only — no lapse (stated gap)
                r.source = "package_metadata";
                r.confidence = "probable"; // declared by the packager
                records.push_back(std::move(r));
                ++emitted;
            }
            outcomes.push_back({"pkg_metadata", true, emitted, {}});
            return;
        }
        // rpm's PRESENCE on the host is not proof it is the host's real
        // package manager -- a Debian/Ubuntu box can carry a stray/leftover
        // `rpm` binary (pulled in transitively, e.g. by packaging tooling)
        // whose database was never initialized for real package management
        // and errors on every query, while dpkg-query works fine as the
        // host's actual manager. Found live: a shared self-hosted Linux CI
        // runner reported `rpm_query_failed` on every run despite
        // dpkg-query succeeding immediately after. So an rpm EXECUTION
        // failure (as opposed to rpm being simply absent) falls through to
        // try dpkg-query rather than reporting a terminal error.
    }

    auto dpkg_query = yuzu::agent::probe_tool_path({"/usr/bin/dpkg-query", "/bin/dpkg-query"});
    if (!dpkg_query.empty()) {
        // license_scan/run_pkg_metadata_surface_linux#2 (docs/agent-spawn-sink-manifest.md)
        // Same byte-identical-queryformat reasoning as the rpm branch above.
        // Format string is its OWN argv element (never "-f=<value>"): unlike a
        // GNU long option, dpkg-query's short "-f" does not strip a joined
        // "=" -- it is taken as a literal leading character of the format
        // string, so every emitted row silently gained a stray "=" prefix on
        // its first (package-name) field, which then broke the
        // "/usr/share/doc/<pkg>/copyright" lookup below for every package
        // (verified empirically against real dpkg-query on Ubuntu 20.04/
        // 22.04/24.04 and Debian 11 -- exit 0 in all four, but every line
        // prefixed with "=").
        const auto res = run_argv(
            {dpkg_query, "-W", "-f", "${Package}\\t${Version}\\t${db:Status-Abbrev}\\n"});
        if (res.truncated) {
            outcomes.push_back({"pkg_metadata", false, 0, "output_truncated"});
            return;
        }
        if (!res.ok) {
            outcomes.push_back({"pkg_metadata", false, 0, "dpkg_query_failed"});
            return;
        }
        for (const auto& line : split_lines(res.output)) {
            const auto fields = split_tabs(line);
            if (fields.size() < 3 || fields[0].empty())
                continue;
            // Installed or held (2nd status char 'i') — matches the
            // installed_apps/vuln_scan presence filter.
            if (fields[2].size() < 2 || fields[2][1] != 'i')
                continue;
            const std::string copyright_path = "/usr/share/doc/" + fields[0] + "/copyright";
            const auto content = host.read_file_prefix(copyright_path, 4096);
            if (!content || !is_dep5_copyright(*content))
                continue; // only machine-readable DEP-5 headers classify
            LicRecord r;
            r.product = fields[0];
            r.version = fields[1];
            r.license_type = classify_license_string(dep5_first_license(*content));
            r.status = "unknown";
            r.source = "package_metadata";
            r.confidence = "heuristic"; // header parse, not a packager field
            records.push_back(std::move(r));
            ++emitted;
        }
        outcomes.push_back({"pkg_metadata", true, emitted, {}});
        return;
    }

    // No supported package manager: structurally a successful probe of an
    // empty surface, not an error (nothing to enumerate).
    outcomes.push_back({"pkg_metadata", true, 0, {}});
}

// ── entitlement_certs (surface table Linux row 2; authoritative) ───────────

// Aggregate wall-clock budget for the WHOLE per-cert loop below, not the
// per-openssl-run deadline (20s, unnamed at each run_argv call). This is a
// START-GATE checked before each iteration, not a hard cap on the loop's
// total cost: an iteration already admitted can still run up to two 20s
// openssl runs (the -dateopt fallback) before the NEXT admission check, so
// the loop's real worst case is this budget plus one cert's cost -- up to
// ~100s, not 60s. Still bounds what would otherwise be unbounded: a
// directory with many certs -- 512 x 2 x 20s is several hours -- could pin
// the instruction worker on a single entitlement_certs call without it.
// Strictly better than the pre-migration unbounded popen this replaced (no
// budget at all), but cheap enough to add here too.
constexpr std::chrono::seconds kEntitlementCertsScanBudget{60};

void run_entitlement_certs_surface(ProbeHost& host, std::vector<LicRecord>& records,
                                   std::vector<ProbeOutcome>& outcomes) {
    auto pems = host.glob("/etc/pki/entitlement/*.pem");
    // Entitlement key pairs live beside the certs as <serial>-key.pem — skip.
    std::vector<std::string> certs;
    for (auto& p : pems) {
        if (p.size() >= 8 && p.compare(p.size() - 8, 8, "-key.pem") == 0)
            continue;
        certs.push_back(std::move(p));
    }
    if (certs.empty()) {
        outcomes.push_back({"entitlement_certs", true, 0, {}});
        return;
    }
    auto openssl = yuzu::agent::probe_tool_path({"/usr/bin/openssl", "/bin/openssl"});
    if (openssl.empty()) {
        // Certs exist but cannot be parsed — a real failure, not empty.
        outcomes.push_back({"entitlement_certs", false, 0, "openssl_unavailable"});
        return;
    }

    const long long now = host.now_epoch();
    std::size_t emitted = 0;
    bool any_parse_failure = false;
    bool budget_exhausted = false;
    const auto scan_deadline = std::chrono::steady_clock::now() + kEntitlementCertsScanBudget;
    for (const auto& cert : certs) {
        if (std::chrono::steady_clock::now() >= scan_deadline) {
            // Whatever was already parsed is real data, kept -- only the
            // remaining certs are unaccounted for, reported below via the
            // degraded outcome rather than silently truncating the scan.
            budget_exhausted = true;
            break;
        }
        // -dateopt iso_8601 where supported; parse_openssl_enddate also
        // accepts the older default date format. The cert path is globbed from
        // /etc/pki/entitlement (attacker-influenceable filenames) -- as a
        // plain argv element it is injection-proof by construction, no
        // shell-quoting needed (shell_single_quote is gone: there is no
        // shell left to escape against).
        // license_scan/run_entitlement_certs_surface_linux#1 (docs/agent-spawn-sink-manifest.md)
        auto res = run_argv(
            {openssl, "x509", "-noout", "-enddate", "-dateopt", "iso_8601", "-in", cert});
        if (!res.ok || res.truncated) {
            // license_scan/run_entitlement_certs_surface_linux#2 (docs/agent-spawn-sink-manifest.md)
            res = run_argv({openssl, "x509", "-noout", "-enddate", "-in", cert});
        }
        const std::string not_after =
            (res.ok && !res.truncated) ? parse_openssl_enddate(res.output) : std::string{};
        if (not_after.empty()) {
            any_parse_failure = true;
            continue;
        }
        LicRecord r;
        r.product = "Red Hat subscription entitlement";
        r.vendor = "Red Hat";
        r.license_type = "subscription";
        r.expires_at = not_after;
        // not_after is a UTC-midnight epoch string; compare it numerically to
        // the collection day (whole-day granularity — epoch decimal strings do
        // not lexicographically sort across widths). The server-side evaluator
        // re-derives lapse against its own clock — this is the agent-observed
        // state.
        const long long expiry_epoch = std::strtoll(not_after.c_str(), nullptr, 10);
        const long long today_epoch = now - (now % 86400);
        r.status = (expiry_epoch > 0 && expiry_epoch < today_epoch) ? "expired"
                                                                    : "subscription_active";
        r.source = "entitlement_cert";
        r.confidence = "authoritative";
        records.push_back(std::move(r));
        ++emitted;
    }

    // See entitlement_certs_outcome()'s doc comment (licensing_parsers.hpp)
    // for the honest-degrade invariants this classification encodes.
    outcomes.push_back(entitlement_certs_outcome(budget_exhausted, emitted, any_parse_failure));
}

} // namespace

// ── the Linux run ───────────────────────────────────────────────────────────

SurfaceRun run_platform_surfaces() {
    SurfaceRun run;
    ProbeHost host; // filesystem defaults; no registry on Linux

    run_pkg_metadata_surface(host, run.records, run.outcomes);
    run_entitlement_certs_surface(host, run.records, run.outcomes);

    // FlexLM conventional-dir rows ride the ProbeSpec table (flexlm_lic).
    run_probe_specs(host, Platform::linux_os, Scope::machine, run.records, run.outcomes);

    return run;
}

} // namespace yuzu::license_scan

#endif // __linux__
