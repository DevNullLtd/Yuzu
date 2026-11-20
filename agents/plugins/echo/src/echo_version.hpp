#pragma once

#include <string_view>

namespace yuzu::echo {

// ── Numeric-segment version comparison ──────────────────────────────────────
// Returns <0 if a<b, 0 if a==b, >0 if a>b. Splits on '.' and '-' and compares
// segment by segment, so "10.0" > "9.0" (a plain std::string `operator>` gets
// this lexicographically wrong and would suppress real upgrade events — #1620).
// A missing segment counts as numeric 0.
//
// This is a strict weak order over ARBITRARY strings (#7482): std::sort in
// dedup() is undefined on a comparator that is not one, and the version strings
// come from the registry, so they are attacker-influenced. The per-segment order
// is total: an all-digit segment (empty counts as 0) sorts before any other
// segment; two numeric segments compare by value; two non-numeric segments
// compare as bytes. The old rule fell back to a lexicographic compare whenever
// EITHER side was non-numeric, which made 9 < 10 < 1a < 9 a cycle. Numeric
// values are compared as digit strings (leading zeros stripped, then length,
// then bytes), never converted, so a 30-digit segment cannot overflow. Known
// behaviour change: "1a" now ranks above "9".
//
// Mirrors the comparator in agents/plugins/vuln_scan/src/cve_rules.hpp; kept as
// a self-contained agent-side copy rather than a shared dependency, the same
// deliberate duplication documented in server/core/src/nvd_db.cpp.
inline int compare_versions(std::string_view a, std::string_view b) {
    auto next_segment = [](std::string_view& s) -> std::string_view {
        if (s.empty()) {
            return {};
        }
        auto pos = s.find_first_of(".-");
        std::string_view seg;
        if (pos == std::string_view::npos) {
            seg = s;
            s = {};
        } else {
            seg = s.substr(0, pos);
            s = s.substr(pos + 1);
        }
        return seg;
    };

    auto all_digits = [](std::string_view seg) {
        for (char c : seg) {
            if (c < '0' || c > '9') {
                return false;
            }
        }
        return true; // an empty segment is numeric 0
    };

    auto cmp_segment = [&](std::string_view sa, std::string_view sb) -> int {
        const bool a_num = all_digits(sa);
        const bool b_num = all_digits(sb);
        if (a_num != b_num) {
            return a_num ? -1 : 1;
        }
        if (!a_num) {
            return sa.compare(sb);
        }
        auto strip = [](std::string_view d) {
            auto nz = d.find_first_not_of('0');
            return nz == std::string_view::npos ? std::string_view{} : d.substr(nz);
        };
        sa = strip(sa);
        sb = strip(sb);
        if (sa.size() != sb.size()) {
            return sa.size() < sb.size() ? -1 : 1;
        }
        return sa.compare(sb);
    };

    std::string_view ra = a, rb = b;
    while (!ra.empty() || !rb.empty()) {
        if (int c = cmp_segment(next_segment(ra), next_segment(rb)); c != 0) {
            return c;
        }
    }
    return 0;
}

} // namespace yuzu::echo
