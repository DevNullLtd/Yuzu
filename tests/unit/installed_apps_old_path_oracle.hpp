#pragma once

// installed_apps_old_path_oracle.hpp -- TEST ONLY. The CLI-output line parsers the installed_apps
// plugin used before SAM-45, moved here VERBATIM (same namespaces, same bodies) when the plugin
// stopped running `dpkg-query` and `rpm -qa`.
//
// They are no longer product code. Their one remaining job is to be the independent interpreter of
// the OLD path's captured output: the parity cases read a capture's `inventory.tsv` / `list.txt`
// (the exact bytes `dpkg-query -W` and `rpm -qa --queryformat` printed), run these parsers over
// them, and require the in-process readers to produce the same rows. Nothing here may be "improved":
// a change to this file changes what "the old path" means.
//
//   inventory (list_inventory) : parse_dpkg_inv_line, parse_rpm_inv_line, kRpmInvQueryFormat,
//                                map_rpm_none, rpm_sig_present, rpm_text_value
//   list / query               : parse_dpkg_list, parse_rpm_list

#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

#include "installed_apps_inventory.hpp"
#include "installed_apps_parsers.hpp"

namespace yuzu::installed_apps::inventory {

namespace detail {

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

// A free-text rpm tag (VENDOR, PACKAGER) as honest-empty: "(none)" and an
// unexpanded literal "%{...}" echo (an rpm too old to know the tag) both read
// as empty, so the publisher falls through to the next source instead of
// carrying the format string. Same guard as rpm_sig_present.
inline std::string rpm_text_value(std::string_view raw) {
    return rpm_sig_present(raw) ? std::string{raw} : std::string{};
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
//
// Maintainer is free text and the LAST field, so a tab inside it never drops the
// row: the publisher is its head segment (the text before the first tab). The
// first four fields are tab/newline-free by the dpkg grammar.
inline std::optional<InvRecord> parse_dpkg_inv_line(std::string_view line) {
    const auto tok = detail::split_tabs(line);
    if (tok.size() < 5 || tok[1].size() < 2 || tok[1][1] != 'i')
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

// The rpm `--queryformat` whose output parse_rpm_inv_line reads: ONE copy, passed to rpm by the
// plugin and fed back through the parser by the unit test, so the producer and the parser cannot
// drift apart. The two free-text tags (VENDOR, PACKAGER) stay last (see below).
inline constexpr std::string_view kRpmInvQueryFormat =
    "%{NAME}\t%{EPOCH}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\t"
    "%{INSTALLTIME:date}\t%{SIGPGP}\t%{RSAHEADER}\t%{VENDOR}\t%{PACKAGER}\n";

// One rpm line (at least 9 tab-separated tokens):
//   NAME EPOCH VERSION RELEASE ARCH INSTALLTIME:date SIGPGP RSAHEADER VENDOR PACKAGER
// The publisher is the declared VENDOR when set, else PACKAGER (a person, kept only as the
// fallback), else empty (the agent core then labels the row `via:rpm`). `(none)` = unset.
//
// The two free-text tags (VENDOR, PACKAGER) are LAST so a tab inside either never drops the
// row: the first eight tags are fixed by position and the publisher is the head segment of
// VENDOR, else of PACKAGER (a tab inside VENDOR shifts PACKAGER right; only its head is read
// as a fallback when VENDOR is empty or its first byte is the tab). The first eight tags are
// tab/newline-free because rpmbuild enforces it at build time; the rpmdb does not, so a
// hand-built header with a tab in one of them can still shift a field (disclosed residual,
// as is a newline inside a free-text tag, which rpm prints as a second line).
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
    if (tok.size() < 9)
        return std::nullopt;
    InvRecord r;
    r.name = std::string(tok[0]);
    r.epoch = map_rpm_none(tok[1]);
    r.version = std::string(tok[2]);
    r.release = map_rpm_none(tok[3]);
    r.arch = map_rpm_none(tok[4]); // gpg-pubkey pseudo-packages have (none) arch
    r.publisher = rpm_text_value(tok[8]); // VENDOR: the declared vendor (head segment)
    if (r.publisher.empty() && tok.size() >= 10)
        r.publisher = rpm_text_value(tok[9]); // PACKAGER: a person, fallback only
    r.install_date = map_rpm_none(tok[5]);
    r.signature_status =
        (rpm_sig_present(tok[6]) || rpm_sig_present(tok[7])) ? "signed" : "unsigned";
    r.kind = "package";
    r.ecosystem = "rpm";
    return r;
}

} // namespace yuzu::installed_apps::inventory

namespace yuzu::installed_apps::parsers {

// ── Linux: dpkg-query ───────────────────────────────────────────────────────

// One line of `dpkg-query -W -f='${Package}|${Version}|${Maintainer}|${Status}\n'`
// (the `\n` here is the LITERAL two-byte escape dpkg-query's own format-string
// interpreter expands -- see the plugin's argv construction comment). Only
// fully-installed packages are kept ("install ok installed"), matching the
// legacy shell-out this replaces exactly.
[[nodiscard]] inline std::vector<AppRecord> parse_dpkg_list(std::string_view output) {
    std::vector<AppRecord> apps;
    std::string buf(output);
    std::istringstream ss(buf);
    std::string line;
    while (std::getline(ss, line)) {
        detail::strip_trailing_cr(line);
        if (line.find("install ok installed") == std::string::npos)
            continue;
        std::istringstream ls(line);
        std::string name, version, publisher;
        std::getline(ls, name, '|');
        std::getline(ls, version, '|');
        std::getline(ls, publisher, '|');
        apps.push_back(AppRecord{std::move(name), std::move(version), std::move(publisher),
                                 "-", {}});
    }
    return apps;
}

// ── Linux: rpm ───────────────────────────────────────────────────────────

// One line of `rpm -qa --queryformat '%{NAME}|%{VERSION}-%{RELEASE}|%{VENDOR}|%{INSTALLTIME:date}\n'`.
[[nodiscard]] inline std::vector<AppRecord> parse_rpm_list(std::string_view output) {
    std::vector<AppRecord> apps;
    std::string buf(output);
    std::istringstream ss(buf);
    std::string line;
    while (std::getline(ss, line)) {
        detail::strip_trailing_cr(line);
        std::istringstream ls(line);
        std::string name, version, publisher, date;
        std::getline(ls, name, '|');
        std::getline(ls, version, '|');
        std::getline(ls, publisher, '|');
        std::getline(ls, date, '|');
        if (publisher == "(none)")
            publisher = "-";
        apps.push_back(AppRecord{std::move(name), std::move(version), std::move(publisher),
                                 std::move(date), {}});
    }
    return apps;
}

} // namespace yuzu::installed_apps::parsers
