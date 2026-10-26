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
 *                       subscription expiry, read in-process via libcrypto
 *                       (licensing_x509.hpp, rung 1; no subprocess). A
 *                       directory or certificate the agent may not read is
 *                       `cert_permission_denied`, never an empty or clean
 *                       surface.
 *   flexlm_lic        — FlexLM `.lic` files under conventional dirs, via the
 *                       ProbeSpec table rows (pure INCREMENT parser;
 *                       authoritative expiry).
 *
 * Primary-surface honesty (ADR-0024 D3): "success" is structural — the
 * enumeration completed (a query returning zero rows is success;
 * a failed subprocess is error).
 */

#ifdef __linux__

#include <yuzu/agent/subprocess_runner.hpp> // yuzu::agent::run_bounded_subprocess / probe_tool_path (ADR-3002 rung 2; pkg_metadata only)

#include <algorithm>
#include <cerrno>
#include <chrono>
#include <cstdlib>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "licensing_parsers.hpp"
#include "licensing_probes.hpp"
#include "licensing_record.hpp"
#include "licensing_x509.hpp"

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

constexpr std::string_view kEntitlementDir = "/etc/pki/entitlement";
constexpr std::size_t kMaxDirEntries = 4096;         // more entries = truncated listing
constexpr std::size_t kPemFileCapBytes = 64 * 1024;  // larger file = parse failure, never a partial parse
constexpr std::size_t kMaxCertFiles = 64;            // more candidate files = budget exhausted
constexpr std::size_t kMaxCertsPerFile = 16;         // a 17th cert in one file = budget exhausted

// START GATE checked before each certificate file is read -- cooperative, NOT a
// hard deadline. The directory listing precedes the gate and a single blocking
// read (e.g. a cert reached through a followed link onto a dead network mount;
// open/read carry no deadline, O_NONBLOCK is inert on regular files) can
// overrun it. /etc/pki/entitlement is a fixed root-owned path on the root
// filesystem by subscription-manager's contract, so no mount-table guard here
// (the README names this residual, same shape as runtimes/#4875). With the
// in-process reads below the budget only bounds a slow filesystem, not a
// subprocess; it replaces the 60 s gate the openssl runs needed.
constexpr std::chrono::seconds kEntitlementCertsScanBudget{10};

bool is_refusal(int err) {
    return err == EACCES || err == EPERM;
}

} // namespace

// Exported (licensing_probes.hpp) so tests/unit/test_license_scan_surfaces.cpp can
// drive this shell through a controlled ProbeHost.
void run_entitlement_certs_surface(ProbeHost& host, std::vector<LicRecord>& records,
                                   std::vector<ProbeOutcome>& outcomes) {
    const auto dir = host.list_dir(kEntitlementDir, kMaxDirEntries);
    if (dir.err == ENOENT || dir.err == ENOTDIR) {
        // Not a RHEL-family host (or no subscription): a probe that ran and
        // found nothing is a structural success (ADR-0024 D3).
        outcomes.push_back({"entitlement_certs", true, 0, {}});
        return;
    }
    if (is_refusal(dir.err)) {
        // The agent may not list the directory: a refusal, NEVER ok|0 -- on this
        // authoritative surface the sync would otherwise full-replace the
        // host's stored entitlement records to empty.
        outcomes.push_back(entitlement_certs_outcome(true, false, 0, false));
        return;
    }
    if (dir.err != 0) {
        // Any other open/read failure: an unlistable directory is a failed
        // surface, never an empty one.
        outcomes.push_back(entitlement_certs_outcome(false, false, 0, true));
        return;
    }

    bool budget_exhausted = dir.truncated; // entries beyond the listing cap were never seen
    // Entitlement key pairs live beside the certs as <serial>-key.pem -- skip.
    // Filter the WHOLE listing first, then sort (deterministic row order for
    // the daily-sync hash), then cap the file count.
    std::vector<std::string> certs;
    for (const auto& name : dir.names) {
        if (name.ends_with(".pem") && !name.ends_with("-key.pem"))
            certs.push_back(name);
    }
    std::sort(certs.begin(), certs.end());
    if (certs.size() > kMaxCertFiles) {
        budget_exhausted = true;
        certs.resize(kMaxCertFiles);
    }
    if (certs.empty() && !budget_exhausted) {
        outcomes.push_back({"entitlement_certs", true, 0, {}});
        return;
    }

    const long long now = host.now_epoch();
    std::size_t emitted = 0;
    bool permission_denied = false;
    bool any_parse_failure = false;
    const auto scan_deadline = host.now_steady() + kEntitlementCertsScanBudget;
    for (const auto& name : certs) {
        if (host.now_steady() >= scan_deadline) {
            // Whatever was already parsed is real data, kept -- only the
            // remaining certs are unaccounted for, reported below via the
            // degraded outcome rather than silently truncating the scan.
            budget_exhausted = true;
            break;
        }
        const auto file =
            host.read_file_capped(std::string(kEntitlementDir) + "/" + name, kPemFileCapBytes);
        if (!file.data) {
            // oversized (never a truncated parse) and every non-refusal failure
            // are parse failures; a refusal is its own, higher-precedence token.
            if (!file.oversized && is_refusal(file.err))
                permission_denied = true;
            else
                any_parse_failure = true;
            continue;
        }
        const auto parsed = parse_pem_not_after(*file.data, kMaxCertsPerFile);
        if (parsed.parse_failure)
            any_parse_failure = true;
        if (parsed.cert_cap_hit)
            budget_exhausted = true;
        for (const auto& not_after : parsed.expires_wire) {
            LicRecord r;
            r.product = "Red Hat subscription entitlement";
            r.vendor = "Red Hat";
            r.license_type = "subscription";
            r.expires_at = not_after;
            // not_after is a UTC-midnight epoch string; compare it numerically
            // to the collection day (whole-day granularity -- epoch decimal
            // strings do not lexicographically sort across widths). The
            // server-side evaluator re-derives lapse against its own clock --
            // this is the agent-observed state.
            const long long expiry_epoch = std::strtoll(not_after.c_str(), nullptr, 10);
            const long long today_epoch = now - (now % 86400);
            r.status = (expiry_epoch > 0 && expiry_epoch < today_epoch) ? "expired"
                                                                        : "subscription_active";
            r.source = "entitlement_cert";
            r.confidence = "authoritative";
            records.push_back(std::move(r));
            ++emitted;
        }
    }

    // See entitlement_certs_outcome()'s doc comment (licensing_parsers.hpp)
    // for the honest-degrade invariants this classification encodes.
    outcomes.push_back(
        entitlement_certs_outcome(permission_denied, budget_exhausted, emitted, any_parse_failure));
}

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
