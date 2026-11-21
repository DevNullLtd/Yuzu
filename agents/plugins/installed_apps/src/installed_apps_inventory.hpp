#pragma once

// installed_apps_inventory.hpp -- pure parsing/formatting helpers for the
// `list_inventory` action (software-inventory blob contract v3, ADR-0016).
//
// The contract: fields an ecosystem does not store stay EMPTY, never
// synthesised. Every function here is a pure string operation -- no popen, no
// platform #ifdefs -- so the unit test (test_installed_apps_inventory.cpp)
// exercises the exact code the plugin runs against per-ecosystem fixture
// vectors, without needing dpkg/rpm/pacman/apk on the test host (same
// header-for-testability pattern as installed_apps_registry_utf8.hpp, #1662).
//
// SAM-45: the Linux dpkg and rpm rows are mapped from the in-process database readers' records
// (inv_record_from_dpkg / inv_record_from_rpm below). The CLI-output line parsers that used to
// build them (parse_dpkg_inv_line, parse_rpm_inv_line and their helpers) are no longer product
// code; they live on, verbatim, in tests/unit/installed_apps_old_path_oracle.hpp as the test-only
// interpreter of the old path's captured output.
//
// Publisher derivation per leg (empty here = the agent core labels the row `via:<ecosystem>`):
//   rpm      VENDOR, else PACKAGER (a person), else empty      deb   Maintainer (empty -> via:deb)
//   pacman   empty (no vendor field without a second subprocess) -> via:pacman
//   apk      empty (same reason)                                 -> via:apk
//   windows  Uninstall-hive Publisher, else empty               -> via:windows
//   macos    signing leaf CN, else empty                        -> via:macos
//   macos_pkgutil  empty always (a reverse-domain id is an identifier, not a vendor)
//                                                              -> via:macos_pkgutil

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <ctime>
#include <functional>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include <dpkg_status_parsers.hpp> // yuzu::shared::DpkgPackage
#include <rpmdb_parsers.hpp>       // yuzu::shared::RpmPackage, rpm_date_c_locale

namespace yuzu::installed_apps::inventory {

// One `inv|` row. Member order == wire order after the prefix -- the blob
// contract v3 field order the agent core hashes and the server re-parses:
//   name, version, publisher, install_date, kind, ecosystem, epoch, release,
//   arch, signature_status, distro_id, distro_version, install_location
struct InvRecord {
    std::string name;
    std::string version;      // upstream version, release/revision stripped
    std::string publisher;    // rpm VENDOR>PACKAGER / deb Maintainer / Windows Publisher /
                              // macOS signer; empty = unlabelled (see the table above)
    std::string install_date; // human-readable per ecosystem, EXCEPT macos_pkgutil,
                              // whose receipts store only a UNIX epoch-seconds
                              // integer -- carried through verbatim rather than
                              // reformatted into a shape the receipt never had
    std::string kind;         // "package" | "app" | "pkg" (macOS pkgutil receipt)
    std::string ecosystem;    // rpm|deb|apk|pacman|windows|macos|macos_pkgutil
    std::string epoch;
    std::string release;      // rpm RELEASE / deb revision / apk pkgrel
    std::string arch;
    std::string signature_status; // "signed"|"unsigned"; empty where unknown.
                                  // PRESENCE of a signature, never its validity:
                                  // rpm's STORED header tags, and (macOS `app`
                                  // rows) the presence of SecStaticCode signing
                                  // metadata. A bundle whose signature has been
                                  // broken still reads "signed" -- and its
                                  // `publisher` is then the ORIGINAL vendor's CN,
                                  // so publisher is unverified attribution. Not a
                                  // Gatekeeper/notarization verdict, and not
                                  // tamper detection.
    std::string distro_id;        // /etc/os-release ID (Linux rows only)
    std::string distro_version;   // /etc/os-release VERSION_ID (Linux rows only)
    std::string install_location; // Windows InstallLocation, macOS the .app path, Linux empty (no
                                  // single prefix). Wire token 14 (blob v3 slot 13). The agent
                                  // core keeps it only under a known machine root, blanking any
                                  // other value (installed_software_v3.hpp machine_install_location).
};

// Epoch/version/release triple shared by the deb and pacman splitters.
struct EvrParts {
    std::string epoch;
    std::string version;
    std::string release;
};

// apk info -v lines carry the package name fused with the version.
struct ApkParts {
    std::string name;
    std::string version;
    std::string release;
};

namespace detail {

inline bool all_digits(std::string_view s) {
    return !s.empty() && std::all_of(s.begin(), s.end(), [](unsigned char c) {
        return std::isdigit(c) != 0;
    });
}

// [epoch:]version[-release] -- the shape shared by deb `${Version}` and pacman
// `-Q` version strings. Epoch is a strictly numeric prefix (Debian policy;
// pacman likewise) -- a non-numeric prefix before ':' is part of the version,
// not an epoch. Release is everything after the LAST '-': both formats permit
// '-' inside the upstream version only when a release/revision is present, so
// the last dash is the unambiguous split point. No dash at all means a native
// package -- release stays empty; never synthesise "-0".
inline EvrParts split_evr(std::string_view v) {
    EvrParts out;
    const std::size_t colon = v.find(':');
    if (colon != std::string_view::npos && colon > 0 && all_digits(v.substr(0, colon))) {
        out.epoch = std::string(v.substr(0, colon));
        v.remove_prefix(colon + 1);
    }
    const std::size_t dash = v.rfind('-');
    if (dash != std::string_view::npos) {
        out.version = std::string(v.substr(0, dash));
        out.release = std::string(v.substr(dash + 1));
    } else {
        out.version = std::string(v);
    }
    return out;
}

} // namespace detail

// deb `${Version}` = [epoch:]upstream[-revision].
inline EvrParts split_deb_version(std::string_view v) {
    return detail::split_evr(v);
}

// pacman `-Q` version = [epoch:]pkgver-pkgrel (pkgver cannot contain '-';
// tolerate a missing pkgrel -> release empty).
inline EvrParts split_pacman_version(std::string_view v) {
    return detail::split_evr(v);
}

// `apk info -v` line = name-pkgver-rN. pkgver/pkgrel never contain '-', so the
// last two dash-separated segments are the version and the release (the same
// split the vuln_scan plugin has proven in the field). The trailing segment's
// 'r' is apk's display decoration, not part of pkgrel -- strip it iff the
// segment matches r[0-9]+; otherwise there is no pkgrel and the tail is the
// version (tolerance for a malformed/foreign line, release stays empty).
inline ApkParts split_apk_line(std::string_view line) {
    ApkParts out;
    const std::size_t last = line.rfind('-');
    if (last == std::string_view::npos) {
        out.name = std::string(line);
        return out;
    }
    const std::string_view tail = line.substr(last + 1);
    if (tail.size() >= 2 && tail[0] == 'r' && detail::all_digits(tail.substr(1))) {
        const std::size_t prev = line.rfind('-', last - 1);
        if (prev == std::string_view::npos) {
            // No name segment left; caller drops empty-name rows.
            out.version = std::string(line.substr(0, last));
        } else {
            out.name = std::string(line.substr(0, prev));
            out.version = std::string(line.substr(prev + 1, last - prev - 1));
        }
        out.release = std::string(tail.substr(1));
        return out;
    }
    out.name = std::string(line.substr(0, last));
    out.version = std::string(tail);
    return out;
}

// Extract one key's value from /etc/os-release content. Handles double- and
// single-quoted values, comment lines, CRLF, and a missing key (-> empty).
// Takes the file CONTENT (not a path) so the parse is testable without a
// filesystem; the plugin owns the single read per invocation.
inline std::string parse_os_release(std::string_view content, std::string_view key) {
    std::size_t pos = 0;
    while (pos <= content.size()) {
        std::size_t eol = content.find('\n', pos);
        if (eol == std::string_view::npos)
            eol = content.size();
        std::string_view line = content.substr(pos, eol - pos);
        pos = eol + 1;
        if (!line.empty() && line.back() == '\r')
            line.remove_suffix(1);
        while (!line.empty() && (line.front() == ' ' || line.front() == '\t'))
            line.remove_prefix(1);
        if (line.empty() || line.front() == '#')
            continue;
        const std::size_t eq = line.find('=');
        if (eq == std::string_view::npos || line.substr(0, eq) != key)
            continue;
        std::string_view val = line.substr(eq + 1);
        if (val.size() >= 2 && (val.front() == '"' || val.front() == '\'') &&
            val.back() == val.front()) {
            val = val.substr(1, val.size() - 2);
        }
        return std::string(val);
    }
    return {};
}



// ── dpkg / rpm: records from the in-process database readers ─────────────────

// One installed dpkg package -> its `inv|` record, or nullopt when the package is not installed.
// dpkg-query's `${db:Status-Abbrev}` second character was 'i' exactly when the state word is
// `installed`, whatever the want (install, hold, deinstall, purge) and the error flag
// (ok, reinstreq ...): the OLD rule, kept, so a held package is present and scannable while "rc"
// (removed, config-files) and "un" are not. Matches vuln_identity.hpp::parse_dpkg_line (PR #1804).
[[nodiscard]] inline std::optional<InvRecord> inv_record_from_dpkg(const yuzu::shared::DpkgPackage& p) {
    if (p.status != "installed")
        return std::nullopt;
    InvRecord r;
    r.name = p.name;
    const EvrParts evr = split_deb_version(p.version);
    r.epoch = evr.epoch;
    r.version = evr.version;
    r.release = evr.release;
    r.arch = p.architecture;
    r.publisher = p.maintainer;
    r.kind = "package";
    r.ecosystem = "deb";
    return r;
}

// One installed rpm package -> its `inv|` record. `to_local_tm` turns the stored INSTALLTIME into a
// broken-down local time (localtime_r in the plugin, gmtime in a test), so the date renders exactly as
// rpm's `%{INSTALLTIME:date}` did in the C locale and the formatter owns no timezone.
//
//   epoch     the decimal EPOCH, or empty when the tag is absent (rpm printed "(none)")
//   publisher the declared VENDOR, else PACKAGER (a person, kept only as the fallback), else empty
//   signature "signed" when SIGPGP (payload) or RSAHEADER (header) holds bytes, else "unsigned" --
//             the STORED tags only, never a live verification (modern RHEL/Fedora/SUSE packages are
//             frequently header-signed only, so SIGPGP alone would mislabel them; PR #1804 parity)
[[nodiscard]] inline InvRecord inv_record_from_rpm(const yuzu::shared::RpmPackage& p,
                                     const std::function<std::tm(std::int64_t)>& to_local_tm) {
    InvRecord r;
    r.name = p.name;
    if (p.epoch)
        r.epoch = std::to_string(*p.epoch);
    r.version = p.version;
    r.release = p.release;
    r.arch = p.arch;
    r.publisher = !p.vendor.empty() ? p.vendor : p.packager;
    if (p.install_time)
        r.install_date = yuzu::shared::rpm_date_c_locale(to_local_tm(static_cast<std::int64_t>(*p.install_time)));
    r.signature_status = (p.sigpgp || p.rsaheader) ? "signed" : "unsigned";
    r.kind = "package";
    r.ecosystem = "rpm";
    return r;
}

// One `pacman -Q` line: "name [epoch:]pkgver-pkgrel".
inline std::optional<InvRecord> parse_pacman_inv_line(std::string_view line) {
    const std::size_t sp = line.find(' ');
    if (sp == std::string_view::npos || sp == 0)
        return std::nullopt;
    InvRecord r;
    r.name = std::string(line.substr(0, sp));
    const EvrParts evr = split_pacman_version(line.substr(sp + 1));
    r.epoch = evr.epoch;
    r.version = evr.version;
    r.release = evr.release;
    r.kind = "package";
    r.ecosystem = "pacman";
    return r;
}

// One `apk info -v` line: "name-pkgver-rN".
inline std::optional<InvRecord> parse_apk_inv_line(std::string_view line) {
    if (line.empty())
        return std::nullopt;
    const ApkParts p = split_apk_line(line);
    if (p.name.empty())
        return std::nullopt;
    InvRecord r;
    r.name = p.name;
    r.version = p.version;
    r.release = p.release;
    r.kind = "package";
    r.ecosystem = "apk";
    return r;
}

// Field values must never corrupt the row framing ('|') nor carry the internal
// query separator or line breaks. Package fields are single-line tokens, so
// deletion (matching the agent core's clamp_field philosophy for 0x1F/0x1E) is
// honest -- also retro-fixes the latent field-shift when a Windows DisplayName
// or a deb Maintainer legally contains '|'.
inline std::string pipe_safe(std::string_view v) {
    std::string out;
    out.reserve(v.size());
    for (char c : v) {
        if (c == '|' || c == '\t' || c == '\r' || c == '\n')
            continue;
        out.push_back(c);
    }
    return out;
}

// A path that holds '|' keeps its place in the row: the bar becomes U+FFFD (a visibly altered
// path) rather than being deleted (which would silently merge two different directories);
// tab, CR and LF are deleted as pipe_safe does.
inline std::string install_location_safe(std::string_view v) {
    std::string out;
    out.reserve(v.size());
    for (char c : v) {
        if (c == '|')
            out += "\xEF\xBF\xBD";
        else if (c != '\t' && c != '\r' && c != '\n')
            out.push_back(c);
    }
    return out;
}

// The one place that knows the 14-token `inv|` row layout. Keep in lockstep
// with parse_installed_apps_output (agents/core/src/sync_source_installed_software.cpp).
inline std::string format_inv_row(const InvRecord& r) {
    std::string out = "inv";
    const std::string_view fields[12] = {r.name,  r.version,   r.publisher,
                                         r.install_date, r.kind, r.ecosystem,
                                         r.epoch, r.release,   r.arch,
                                         r.signature_status, r.distro_id, r.distro_version};
    for (const auto& f : fields) {
        out.push_back('|');
        out += pipe_safe(f);
    }
    out.push_back('|');
    out += install_location_safe(r.install_location);
    return out;
}

} // namespace yuzu::installed_apps::inventory
