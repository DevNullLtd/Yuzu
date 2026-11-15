#pragma once

#include <string_view>
#include <utility>

namespace yuzu::echo {

// ── Numeric-segment version comparison ──────────────────────────────────────
// Returns <0 if a<b, 0 if a==b, >0 if a>b. Splits on '.' and '-' and compares
// each segment numerically where possible, so "10.0" > "9.0" (a plain
// std::string `operator>` gets this lexicographically wrong and would suppress
// real upgrade events — #1620). Non-numeric segments (e.g. "1.9.5p2") fall back
// to a lexicographic compare of that segment. This mirrors the proven, unit-
// tested comparator in agents/plugins/vuln_scan/src/cve_rules.hpp; kept as a
// self-contained agent-side copy rather than a shared dependency, the same
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

    auto to_num = [](std::string_view seg) -> std::pair<bool, long long> {
        if (seg.empty()) {
            return {true, 0};
        }
        long long val = 0;
        for (char c : seg) {
            if (c < '0' || c > '9') {
                return {false, 0};
            }
            val = val * 10 + (c - '0');
        }
        return {true, val};
    };

    std::string_view ra = a, rb = b;
    while (!ra.empty() || !rb.empty()) {
        auto sa = next_segment(ra);
        auto sb = next_segment(rb);

        auto [a_num, a_val] = to_num(sa);
        auto [b_num, b_val] = to_num(sb);

        if (a_num && b_num) {
            if (a_val != b_val) {
                return (a_val < b_val) ? -1 : 1;
            }
        } else {
            int cmp = sa.compare(sb);
            if (cmp != 0) {
                return cmp;
            }
        }
    }
    return 0;
}

} // namespace yuzu::echo
