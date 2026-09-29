#pragma once

// installed_apps_inventory.hpp -- pure parsing/formatting helpers for the
// `list_inventory` action (software-inventory blob contract v2, ADR-0016).
//
// The v2 contract: fields an ecosystem does not store stay EMPTY, never
// synthesised. Every function here is a pure string operation -- no popen, no
// platform #ifdefs -- so the unit test (test_installed_apps_inventory.cpp)
// exercises the exact code the plugin runs against per-ecosystem fixture
// vectors, without needing dpkg/rpm/pacman/apk on the test host (same
// header-for-testability pattern as installed_apps_registry_utf8.hpp, #1662).

#include <algorithm>
#include <cctype>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::installed_apps::inventory {

// One `inv|` row. Member order == wire order after the prefix -- the blob
// contract v2 field order the agent core hashes and the server re-parses:
//   name, version, publisher, install_date, kind, ecosystem, epoch, release,
//   arch, signature_status, distro_id, distro_version
struct InvRecord {
    std::string name;
    std::string version;      // upstream version, release/revision stripped
    std::string publisher;    // rpm PACKAGER / deb Maintainer / Windows Publisher
    std::string install_date; // human-readable per ecosystem, EXCEPT macos_pkgutil,
                              // whose receipts store only a UNIX epoch-seconds
                              // integer -- carried through verbatim rather than
                              // reformatted into a shape the receipt never had
    std::string kind;         // "package" | "app" | "pkg" (macOS pkgutil receipt)
    std::string ecosystem;    // rpm|deb|apk|pacman|windows|macos|macos_pkgutil|homebrew
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

// Split a query-output line on '\t'. Tab is the internal separator for the
// format strings we control (rpm --queryformat, dpkg-query -f): rpm's own
// conditional syntax uses '|', and Maintainer/PACKAGER free text may legally
// contain '|', so pipe-separated internal formats would be ambiguous.
inline std::vector<std::string_view> split_tabs(std::string_view line) {
    std::vector<std::string_view> out;
    std::size_t p = 0;
    while (true) {
        const std::size_t t = line.find('\t', p);
        if (t == std::string_view::npos) {
            out.push_back(line.substr(p));
            break;
        }
        out.push_back(line.substr(p, t - p));
        p = t + 1;
    }
    return out;
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

// rpm --queryformat prints the literal "(none)" for an unset tag (EPOCH,
// PACKAGER, ARCH on gpg-pubkey pseudo-packages). Map it to honest-empty.
inline std::string map_rpm_none(std::string_view v) {
    return v == "(none)" ? std::string{} : std::string{v};
}

// A signature tag counts as present only if it holds a real value -- not
// empty, not "(none)", and not an unexpanded literal "%{...}" (an rpm too
// old to know the tag echoes the format string back, which must NOT read as
// "signed"). Mirrors vuln_identity.hpp::rpm_sig_present (PR #1804) exactly --
// the two agent-side collectors emit the same PackageRecord shape for the
// same rpm and must agree on this security-posture-relevant field, or an
// operator/matcher sees a different signed/unsigned answer depending on
// which collector happened to report the device.
//
// Assumes rpm's default formatting of an RPM_BIN_TYPE tag (SIGPGP/RSAHEADER,
// absent an explicit :base64/:pgpsig format extension) is a tab/newline-free
// hex string -- undocumented empirically (no rpm host was reachable to
// verify against a live package), but consistent with rpm's documented
// BIN-tag default and with PR #1804 shipping the identical assumption.
inline bool rpm_sig_present(std::string_view raw) {
    const std::string v = map_rpm_none(raw);
    return !v.empty() && v.rfind("%{", 0) != 0;
}

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

// One dpkg-query line:
//   ${Package}\t${db:Status-Abbrev}\t${Version}\t${Architecture}\t${Maintainer}
// Status-Abbrev is <want><status><eflag> (3 chars -- dpkg emits a trailing
// space for the usual empty eflag, e.g. "ii "); the 2nd char 'i' == installed --
// matches vuln_identity.hpp::parse_dpkg_line (PR #1804) exactly. Covers "ii"
// (want=install) AND "hi" (want=hold: apt-mark hold / kernel pin), so a
// held-but-installed package is present and scannable -- the legacy `list`
// action's "install ok installed" substring filter excludes held, this does
// not. "rc" (removed, config-files) and "un" (unknown) are correctly
// excluded. nullopt for a structurally wrong or not-installed line.
inline std::optional<InvRecord> parse_dpkg_inv_line(std::string_view line) {
    const auto tok = detail::split_tabs(line);
    if (tok.size() != 5 || tok[1].size() < 2 || tok[1][1] != 'i')
        return std::nullopt;
    InvRecord r;
    r.name = std::string(tok[0]);
    const EvrParts evr = split_deb_version(tok[2]);
    r.epoch = evr.epoch;
    r.version = evr.version;
    r.release = evr.release;
    r.arch = std::string(tok[3]);
    r.publisher = std::string(tok[4]); // Maintainer
    r.kind = "package";
    r.ecosystem = "deb";
    return r;
}

// One rpm line (9 tab-separated tokens):
//   NAME EPOCH VERSION RELEASE ARCH PACKAGER INSTALLTIME:date SIGPGP RSAHEADER
// SIGPGP is the payload (v3 OpenPGP) signature tag; RSAHEADER is the header
// signature tag. Both are checked (via rpm_sig_present) because modern
// RHEL/Fedora packages are frequently header-signed only -- SIGPGP alone
// would mislabel a validly-signed package as unsigned. Signature is read
// from these STORED rpmdb tags only, never a live `rpm -K` verification.
//
// Two deliberate behavior shifts vs. this file's prior (pre-PR-#1804-parity)
// scheme, both adopted for cross-collector agreement with vuln_identity.hpp:
//   1. signature_status is now ALWAYS "signed" or "unsigned" -- never empty.
//      The prior scheme left it honest-empty when the queryformat produced
//      an unrecognized token (e.g. an rpm too old to expand the conditional
//      syntax at all). That "indeterminate" case is now folded into an
//      AFFIRMATIVE "unsigned" (rpm_sig_present's %{...}-literal-echo guard).
//      This is a stronger negative claim on a security-posture-relevant
//      field than "unrecorded" -- deliberate, not an oversight.
//   2. The tag set checked narrows from four (DSAHEADER/RSAHEADER/SIGGPG/
//      SIGPGP) to two (SIGPGP/RSAHEADER). A DSA-header-only- or GPG-payload-
//      only-signed package -- legacy, uncommon on a modern RHEL/Fedora/SUSE
//      fleet -- now reads "unsigned" where the old scheme read "signed".
inline std::optional<InvRecord> parse_rpm_inv_line(std::string_view line) {
    const auto tok = detail::split_tabs(line);
    if (tok.size() != 9)
        return std::nullopt;
    InvRecord r;
    r.name = std::string(tok[0]);
    r.epoch = map_rpm_none(tok[1]);
    r.version = std::string(tok[2]);
    r.release = map_rpm_none(tok[3]);
    r.arch = map_rpm_none(tok[4]); // gpg-pubkey pseudo-packages have (none) arch
    r.publisher = map_rpm_none(tok[5]); // PACKAGER (the v2 spec; `list` keeps VENDOR)
    r.install_date = map_rpm_none(tok[6]);
    r.signature_status =
        (rpm_sig_present(tok[7]) || rpm_sig_present(tok[8])) ? "signed" : "unsigned";
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

// The one place that knows the 13-token `inv|` row layout. Keep in lockstep
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
    return out;
}

} // namespace yuzu::installed_apps::inventory
