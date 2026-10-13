#pragma once

/// @file cpe_normalize.hpp
/// PURE, header-only CPE lane-routing + product-normalization primitives
/// (PR 3, ADR-0018 server-authoritative vulnerability matching). No store, no
/// NVD, no engine, no Postgres — every function here is a deterministic pure
/// helper that is fully testable without the resolver class or the
/// build-embedded curated map.
///
/// Two responsibilities:
///   * Lane routing (`is_lane1` / `is_os_native`) — ADR-0018 §"three lanes".
///     Lane 1 = distro package managers (rpm/deb/apk/pacman) that we resolve to
///     a CPE identity. OS-native software (Windows/macOS apps, macOS pkgutil receipts, Homebrew
///     formulae/casks, Windows optional features) are Lane 3:
///     identified but NOT assessed in v1 (zero guessing, zero false positives).
///   * Product normalization + the curated-map CSV parse. `normalize_product`
///     is the LOW-confidence fallback (a best-effort prefix token); the curated
///     map is the HIGH-confidence override.
///
/// **Curated-map-shields-suffix-collisions invariant.** `normalize_product`
/// only strips packaging suffixes from a deliberately SAFE closed allowlist
/// (`-dev`, `-devel`, `-headers`, `-dbg`, `-dbgsym`, `-doc`, `-docs`,
/// `-common`). Ambiguous suffixes that are real product stems in their own
/// right (`-server`, `-data`, `-utils`, `-bin`) are NOT stripped — the curated
/// map is the mechanism for those, so normalization can never silently collapse
/// two distinct products into one.

#include "peer_ip.hpp"                  // detail::to_lower_ascii
#include "software_inventory_store.hpp" // SoftwareEntry

#include <cstddef>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace yuzu::server {

// ---------------------------------------------------------------------------
// small pure string helpers
// ---------------------------------------------------------------------------

inline std::string_view cpe_trim_view(std::string_view s) {
    auto is_ws = [](char c) {
        return c == ' ' || c == '\t' || c == '\r' || c == '\n' || c == '\f' || c == '\v';
    };
    std::size_t b = 0;
    std::size_t e = s.size();
    while (b < e && is_ws(s[b]))
        ++b;
    while (e > b && is_ws(s[e - 1]))
        --e;
    return s.substr(b, e - b);
}

inline std::string cpe_trim(std::string_view s) { return std::string(cpe_trim_view(s)); }

// ---------------------------------------------------------------------------
// lane routing (ADR-0018)
// ---------------------------------------------------------------------------

/// Lane 1 — distro package-managed ecosystems we resolve to a CPE identity.
inline bool is_lane1(std::string_view eco) {
    // Lowercase before comparing — curated_key()/normalize also lowercase, and a
    // producer that emits "RPM" must not fall through to unsupported-ecosystem.
    //
    // pacman is INCLUDED here as NVD-assessable at M1a (NVD version-range matching
    // needs no distro OVAL stream). ADR-0018's Lane-1 enumeration currently lists
    // only deb/rpm/apk (Arch has no OVAL stream) — that list should be amended to
    // sanction pacman as an OVAL-less Lane-1 member; OVAL only matters at M1b.
    const std::string e = yuzu::server::detail::to_lower_ascii(cpe_trim_view(eco));
    return e == "rpm" || e == "deb" || e == "apk" || e == "pacman";
}

/// Lane 3 — OS-native software (GUI apps, non-distro package managers, Windows
/// optional features) that v1 identifies but does NOT assess: `kind` app/feat OR
/// an OS-native ecosystem. `pkg` is routed by its ecosystem, not as a kind-level
/// trigger. See ADR-0023 §2 (update 2026-10-04).
inline bool is_os_native(const SoftwareEntry& e) {
    const std::string kind = yuzu::server::detail::to_lower_ascii(cpe_trim_view(e.kind));
    const std::string eco = yuzu::server::detail::to_lower_ascii(cpe_trim_view(e.ecosystem));
    return kind == "app" || kind == "feat" || eco == "windows" || eco == "macos" ||
           eco == "macos_pkgutil" || eco == "brew" || eco == "optional_feature";
}

// ---------------------------------------------------------------------------
// low-confidence normalization (single-pass, fixed order — NOT loop-to-fixpoint)
// ---------------------------------------------------------------------------

/// Best-effort product token for the LOW-confidence lane. Single pass, each
/// step fires at most once, in this fixed order:
///   1. lowercase + trim.
///   2. strip ONE leading interpreter prefix (closed allowlist).
///   3. strip ONE trailing packaging suffix (longest match, SAFE allowlist).
///   4. if `^lib.+`: strip a trailing run of version chars `[0-9.]` (keep `lib`);
///      else: strip ONE trailing `-[0-9][0-9.]*` (a dash-separated version
///      tail) — digits glued without a separator (`sqlite3`) are kept.
///
/// Order matters and is deliberate — see `test_cpe_identity_resolver.cpp`
/// order-dependence cases (`foo-dev-12` -> `foo-dev`, not `foo`).
inline std::string normalize_product(std::string_view name) {
    std::string s = yuzu::server::detail::to_lower_ascii(cpe_trim_view(name));

    // 2. leading interpreter prefix — longest first so `python3-` wins over
    //    `python-` and `nodejs-` over `node-`.
    static constexpr std::string_view kInterpPrefixes[] = {
        "python3-", "nodejs-", "python-", "ruby-", "perl-", "node-"};
    for (std::string_view p : kInterpPrefixes) {
        if (s.size() > p.size() && s.compare(0, p.size(), p) == 0) {
            s.erase(0, p.size());
            break;
        }
    }

    // 3. trailing packaging suffix — longest match first. SAFE allowlist only;
    //    `-server`/`-data`/`-utils`/`-bin` are intentionally excluded.
    static constexpr std::string_view kSafeSuffixes[] = {
        "-headers", "-dbgsym", "-common", "-devel", "-docs", "-dev", "-dbg", "-doc"};
    for (std::string_view suf : kSafeSuffixes) {
        if (s.size() >= suf.size() && s.compare(s.size() - suf.size(), suf.size(), suf) == 0) {
            s.erase(s.size() - suf.size());
            break;
        }
    }

    // 4. version-tail strip.
    if (s.size() > 3 && s.compare(0, 3, "lib") == 0) {
        // `libfoo5` -> `libfoo`, `libssl1.1` -> `libssl`: drop a trailing run of
        // version chars `[0-9.]` (a dotted soname like `1.1` is a version tail,
        // not part of the stem), never below `lib`. Consuming `.` here is what
        // keeps a dotted-soname lib name from leaving a dead trailing-dot token.
        std::size_t e = s.size();
        while (e > 3 && ((s[e - 1] >= '0' && s[e - 1] <= '9') || s[e - 1] == '.'))
            --e;
        s.erase(e);
    } else {
        // `gcc-12` -> `gcc`: drop ONE trailing `-[0-9][0-9.]*`; keep `sqlite3`.
        std::size_t dash = s.rfind('-');
        if (dash != std::string::npos && dash + 1 < s.size() && s[dash + 1] >= '0' &&
            s[dash + 1] <= '9') {
            bool all_ver = true;
            for (std::size_t i = dash + 1; i < s.size(); ++i) {
                const char c = s[i];
                if (!((c >= '0' && c <= '9') || c == '.')) {
                    all_ver = false;
                    break;
                }
            }
            if (all_ver)
                s.erase(dash);
        }
    }
    return s;
}

// ---------------------------------------------------------------------------
// curated map: key + CSV parse
// ---------------------------------------------------------------------------

/// Lookup key for the curated map: `lower(eco) \x1f lower(distro_id) \x1f
/// lower(name)`. Empty eco/distro_id are legitimate (wildcard) key segments.
inline std::string curated_key(std::string_view eco, std::string_view distro_id,
                               std::string_view name) {
    std::string k = yuzu::server::detail::to_lower_ascii(cpe_trim_view(eco));
    k.push_back('\x1f');
    k += yuzu::server::detail::to_lower_ascii(cpe_trim_view(distro_id));
    k.push_back('\x1f');
    k += yuzu::server::detail::to_lower_ascii(cpe_trim_view(name));
    return k;
}

/// One parsed curated row. All fields lowercased + trimmed.
struct CuratedRow {
    std::string eco;
    std::string distro_id;
    std::string name;
    std::string vendor;
    std::string product;
};

/// Parse the curated CSV. Skips blank lines and `#` comments; splits each
/// remaining line into exactly 5 comma fields (`ecosystem,distro_id,name,
/// cpe_vendor,cpe_product`) and DROPS any line whose field count is not 5
/// (defensive against a malformed embed). Each field is trimmed + lowercased.
inline std::vector<CuratedRow> parse_curated_csv(std::string_view csv) {
    std::vector<CuratedRow> rows;
    std::size_t pos = 0;
    while (pos <= csv.size()) {
        std::size_t nl = csv.find('\n', pos);
        std::string_view line =
            (nl == std::string_view::npos) ? csv.substr(pos) : csv.substr(pos, nl - pos);
        pos = (nl == std::string_view::npos) ? csv.size() + 1 : nl + 1;

        if (!line.empty() && line.back() == '\r')
            line.remove_suffix(1);

        std::string_view t = cpe_trim_view(line);
        if (t.empty() || t.front() == '#')
            continue;

        // Split the raw line on ',' preserving empty leading/trailing fields
        // (`,,openssl,openssl,openssl` -> 5 fields, first two empty).
        std::string_view fields[6];
        std::size_t nfields = 0;
        std::size_t start = 0;
        bool overflow = false;
        while (true) {
            std::size_t comma = line.find(',', start);
            std::string_view field =
                (comma == std::string_view::npos) ? line.substr(start) : line.substr(start, comma - start);
            if (nfields >= 6) { // too many fields — will be dropped
                overflow = true;
                break;
            }
            fields[nfields++] = field;
            if (comma == std::string_view::npos)
                break;
            start = comma + 1;
        }
        if (overflow || nfields != 5)
            continue;

        CuratedRow r;
        r.eco = yuzu::server::detail::to_lower_ascii(cpe_trim_view(fields[0]));
        r.distro_id = yuzu::server::detail::to_lower_ascii(cpe_trim_view(fields[1]));
        r.name = yuzu::server::detail::to_lower_ascii(cpe_trim_view(fields[2]));
        r.vendor = yuzu::server::detail::to_lower_ascii(cpe_trim_view(fields[3]));
        r.product = yuzu::server::detail::to_lower_ascii(cpe_trim_view(fields[4]));
        // Drop a structurally-complete-but-useless row: an empty `name` (nothing
        // to key on) or empty `cpe_product` (a High-confidence hit that carries
        // no token to match downstream). An authoring slip — a trailing comma or
        // a column shifted left — must fail like a malformed row, not ship a
        // silent empty-product High hit.
        if (r.name.empty() || r.product.empty())
            continue;
        rows.push_back(std::move(r));
    }
    return rows;
}

} // namespace yuzu::server
