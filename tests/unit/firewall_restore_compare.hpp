#pragma once

/**
 * firewall_restore_compare.hpp -- decides whether a host's firewall came back as it was, from two
 * sectioned text snapshots. Test-only and pure (no process, file or socket), so the live
 * containment harness (test_firewall_quarantine_live.cpp) and the unit suite
 * (test_firewall_restore_compare.cpp, fed sanitised lab excerpts) run the SAME decision.
 *
 * A snapshot is the text the harness reads before a case and after it:
 *
 *     == <section>
 *     <the tool's output, or [absent] when the tool is not installed, or [tables] and the kernel's
 *      own list of a legacy family's tables when it has no legacy save tool, or [failed]>
 *     == <section>
 *     ...
 *     == end
 *
 * Whoever read a section writes it with write_section(): a read that did not run, timed out, was
 * clipped or exited non-zero is `[failed]` and the partial text is never kept as the section's
 * content, so an unreadable snapshot can never compare equal to itself and a case cannot pass on
 * two failed reads. A root-owned helper (`yuzu-fw-helper snapshot`) writes the same format for the
 * Linux agent account; for a tool that exits non-zero it prints what the tool wrote and then the
 * `[failed]` marker, and a section that carries the marker is unreadable whatever precedes it. For a
 * legacy family with no save tool it prints `[tables]` and then the family's table names, which are
 * kept like any other line: a snapshot of a host with no table is readable and equal to itself, and
 * a table that appears between two reads is a difference, not a pass.
 *
 * Per OS (the sections are the names in `label`):
 *   Windows  `profiles` (one line per profile: name and its defaults) and `rules` (one line per
 *            rule, the key is the text before the first `|`). A key that matches the Store
 *            app-package pattern is counted and reported but never fails the comparison, because
 *            those rules churn by themselves; a package rule that was enabled and is now disabled
 *            is the exception, which is a failure whatever its name.
 *   Linux    `nft -a list ruleset` and a pair of iptables sections, in one of two forms: the
 *            broker's and the helper's (`iptables-legacy-save`, `ip6tables-legacy-save`: every
 *            instantiated table, as the save tools print it) or the root harness's own mirror of the
 *            direct legs (`iptables -S`, `ip6tables -S`: the filter table). Counters, a named counter
 *            object's values, a timed set element's countdown and rule handles are normalised
 *            away, and in a save listing the `#` lines (a date) go and a chain line's packet and byte
 *            counters go; `-P` lines and a save listing's `:<chain> <policy>` lines are defaults;
 *            every other line is a multiset.
 *   macOS    `pf rules`, `pf status` (the `Status:` line, compared by its state word only because
 *            the line also carries the uptime), `pf references` (the line count) and `yuzu anchor`
 *            (anything in it after the noise is residue; an anchor that is not loaded is written
 *            empty by the caller, see pf_anchor_absent).
 *
 * restored = both snapshots readable and nothing changed, went missing, appeared, was left
 * disabled, had a default changed or left a Yuzu residue.
 */

#include "firewall_quarantine_parsers.hpp"

#include <base64.hpp>

#include <algorithm>
#include <cstddef>
#include <format>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace yuzu::test::fwrestore {

namespace fq = yuzu::firewall::quarantine;

enum class Os { win, lin, mac };

inline constexpr std::string_view kEndLine = "== end";
inline constexpr std::string_view kFailedMarker = "[failed]";
inline constexpr std::string_view kAbsentMarker = "[absent]";

/// The section names, in the order a snapshot lists them. The Linux ones are the labels the
/// helper's `snapshot` prints.
namespace label {
inline constexpr std::string_view kProfiles = "profiles";
inline constexpr std::string_view kRules = "rules";
inline constexpr std::string_view kNft = "nft -a list ruleset";
// the root harness's mirror of the direct legs (`-S`, the filter table), and the save-tool sections
// the broker and the helper print: both forms exist because the baseline of a root run is the mirror
inline constexpr std::string_view kIptables = "iptables -S";
inline constexpr std::string_view kIp6tables = "ip6tables -S";
inline constexpr std::string_view kIptablesSave = "iptables-legacy-save";
inline constexpr std::string_view kIp6tablesSave = "ip6tables-legacy-save";
inline constexpr std::string_view kPfRules = "pf rules";
inline constexpr std::string_view kPfStatus = "pf status";
inline constexpr std::string_view kPfReferences = "pf references";
inline constexpr std::string_view kYuzuAnchor = "yuzu anchor";
} // namespace label

struct Verdict {
    bool readable = false;      // BOTH snapshots can be trusted
    bool restored = false;      // readable and every count below that matters is zero
    int changed = 0;            // a rule present on both sides whose line differs (not a package rule)
    int gone = 0;               // a line that was there and is not (not a package rule)
    int added = 0;              // a line that is there and was not (not a package rule)
    int package_churn = 0;      // a Store app-package rule renamed, added or lost: reported, never fails
    int yuzu_residue = 0;       // something of ours left behind
    int defaults_changed = 0;   // a profile default, a policy line, pf on/off, the pf reference count
    int left_disabled = 0;      // a rule that was enabled and now is not
    std::string detail;         // readable reason, or the first few differing lines
};

// ── writing a snapshot ──────────────────────────────────────────────────────

// write_section, write_absent and finish append to the snapshot text the caller is building: `out`
// is that text, not a result or an error channel. This is a deliberate exception to the
// output-parameter rule in docs/cpp-conventions.md, for a test-only builder.

/// One section: its header, then the tool's output when the read COMPLETED, else `[failed]`.
/// `complete` is yuzu::firewall::subprocess_complete(result) for a subprocess read, whoever ran
/// it: a read that did not run, timed out, was clipped or exited non-zero is never recorded as
/// the partial text it left behind.
inline void write_section(std::string& out, std::string_view label, bool complete,
                          std::string_view output) {
    out += "== ";
    out += label;
    out += '\n';
    if (!complete) {
        out += kFailedMarker;
        out += '\n';
        return;
    }
    out += output;
    if (!output.empty() && output.back() != '\n')
        out += '\n';
}

/// A section for a tool that is not installed on this host.
inline void write_absent(std::string& out, std::string_view label) {
    out += "== ";
    out += label;
    out += '\n';
    out += kAbsentMarker;
    out += '\n';
}

/// The closing line. A snapshot that was cut short has none and is unreadable.
inline void finish(std::string& out) {
    out += kEndLine;
    out += '\n';
}

// ── reading a snapshot ──────────────────────────────────────────────────────

namespace detail {

using fq::detail::trim;

struct Section {
    std::string name;
    std::vector<std::string> lines; // as printed, a trailing CR dropped
};

struct Parsed {
    std::vector<Section> sections;
    bool has_end = false;           // the last non-empty line is `== end`
    bool stray_before_header = false; // text ahead of the first `== ` header
};

[[nodiscard]] inline Parsed parse(std::string_view text) {
    Parsed p;
    bool ended = false;
    for (std::string_view line : fq::detail::split(text, '\n')) {
        while (!line.empty() && line.back() == '\r')
            line.remove_suffix(1);
        if (ended) {
            if (!trim(line).empty())
                p.has_end = false; // something after the closing line: not a snapshot
            continue;
        }
        if (line == kEndLine) {
            ended = true;
            p.has_end = true;
            continue;
        }
        if (line.starts_with("== ")) {
            p.sections.push_back(Section{std::string{line.substr(3)}, {}});
            continue;
        }
        if (p.sections.empty()) {
            if (!trim(line).empty())
                p.stray_before_header = true;
            continue;
        }
        p.sections.back().lines.emplace_back(line);
    }
    return p;
}

[[nodiscard]] inline const Section* find_section(const Parsed& p, std::string_view name) {
    for (const auto& s : p.sections)
        if (s.name == name)
            return &s;
    return nullptr;
}

[[nodiscard]] inline bool is_failed(const Section& s) {
    return std::any_of(s.lines.begin(), s.lines.end(),
                       [](const std::string& l) { return trim(l) == kFailedMarker; });
}

[[nodiscard]] inline bool is_absent(const Section& s) {
    std::size_t content = 0;
    bool marker = false;
    for (const auto& l : s.lines) {
        const auto t = trim(l);
        if (t.empty())
            continue;
        ++content;
        marker = t == kAbsentMarker;
    }
    return content == 1 && marker;
}

/// The non-empty lines of a section.
[[nodiscard]] inline std::vector<std::string> content_lines(const Section& s) {
    std::vector<std::string> out;
    for (const auto& l : s.lines)
        if (!trim(l).empty())
            out.push_back(l);
    return out;
}

[[nodiscard]] inline std::string_view field(std::string_view line, std::size_t index) {
    for (std::size_t i = 0; i < index; ++i) {
        const auto bar = line.find('|');
        if (bar == std::string_view::npos)
            return {};
        line.remove_prefix(bar + 1);
    }
    return line.substr(0, line.find('|'));
}

/// A Store app-package rule: `<package name>_<13 chars>S-1-5-...`. They churn by themselves (the
/// name carries the package version and the user's SID), so a change to one is reported, not failed.
[[nodiscard]] inline bool is_package_rule_key(std::string_view key) {
    const auto us = key.find('_');
    if (us == std::string_view::npos || us == 0)
        return false;
    for (const char c : key.substr(0, us))
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' ||
              c == '-'))
            return false;
    const auto rest = key.substr(us + 1);
    if (rest.size() < 13)
        return false;
    for (const char c : rest.substr(0, 13))
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')))
            return false;
    return rest.substr(13).starts_with("S-1-5-");
}

/// A first-line-of-detail for the first few lines that differ.
/// `detail` is read as well as written: the cap counts the notes already in it.
inline void note(std::string& detail, std::string_view kind, std::string_view line) {
    constexpr std::size_t kMaxNotes = 12;
    if (std::count(detail.begin(), detail.end(), '\n') >= static_cast<std::ptrdiff_t>(kMaxNotes))
        return;
    detail += std::format("{} {}\n", kind, line.substr(0, 200));
}

// ── Linux normalisation ─────────────────────────────────────────────────────

/// The end of `<digits> bytes <digits>` that starts at `from` (the two values of a counter), or npos.
[[nodiscard]] inline std::size_t counter_values_end(std::string_view s, std::size_t from) {
    const auto digits_end = [&](std::size_t q) {
        return std::min(s.find_first_not_of("0123456789", q), s.size());
    };
    const auto packets_end = digits_end(from);
    if (packets_end == from || s.compare(packets_end, 7, " bytes ") != 0)
        return std::string_view::npos;
    const auto bytes_start = packets_end + 7;
    const auto bytes_end = digits_end(bytes_start);
    return bytes_end == bytes_start ? std::string_view::npos : bytes_end;
}

/// The end of a duration as nft prints it (`29m22s440ms`: a digit, then digits and the letters d, h,
/// m and s) that starts at `from` and ends at a comma, a blank, a closing brace or the end, or npos.
[[nodiscard]] inline std::size_t nft_duration_end(std::string_view s, std::size_t from) {
    if (from >= s.size() || s[from] < '0' || s[from] > '9')
        return std::string_view::npos;
    const auto end = std::min(s.find_first_not_of("0123456789dhms", from), s.size());
    return end == s.size() || std::string_view{",} \t\r"}.find(s[end]) != std::string_view::npos
               ? end
               : std::string_view::npos;
}

/// Removes what changes by itself between two reads of the same ruleset: ` counter packets N bytes
/// N` becomes ` counter`, a timed set element's ` expires <duration>` goes (its own `timeout` is
/// configuration and stays), a named counter object's line `packets N bytes N` becomes `packets
/// bytes`, the trailing ` # handle N` goes, and trailing blanks go.
[[nodiscard]] inline std::string normalise_linux_line(std::string_view line) {
    std::string s{line};
    constexpr std::string_view kCounter = " counter packets ";
    for (std::size_t at = s.find(kCounter); at != std::string::npos; at = s.find(kCounter, at + 8)) {
        const auto end = counter_values_end(s, at + kCounter.size());
        if (end == std::string_view::npos)
            continue;
        s.replace(at, end - at, " counter");
    }
    constexpr std::string_view kExpires = " expires ";
    std::size_t from = 0;
    for (auto at = s.find(kExpires); at != std::string::npos; at = s.find(kExpires, from)) {
        const auto end = nft_duration_end(s, at + kExpires.size());
        if (end != std::string_view::npos)
            s.erase(at, end - at);
        from = end == std::string_view::npos ? at + kExpires.size() : at;
    }
    constexpr std::string_view kHandle = " # handle ";
    if (const auto at = s.rfind(kHandle); at != std::string::npos) {
        const auto tail = std::string_view{s}.substr(at + kHandle.size());
        if (!tail.empty() && std::all_of(tail.begin(), tail.end(), [](char c) { return c >= '0' && c <= '9'; }))
            s.erase(at);
    }
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t' || s.back() == '\r'))
        s.pop_back();
    constexpr std::string_view kValues = "packets ";
    const auto first = s.find_first_not_of(" \t");
    if (first != std::string::npos && std::string_view{s}.substr(first).starts_with(kValues) &&
        counter_values_end(s, first + kValues.size()) == s.size())
        s.replace(first, std::string::npos, "packets bytes");
    return s;
}

[[nodiscard]] inline bool is_pf_noise(std::string_view line) {
    const auto t = trim(line);
    return t.empty() || t.starts_with("No ALTQ") || t.starts_with("ALTQ related");
}

/// The state word of a pf `Status:` line (`Enabled`, `Disabled`), or empty.
[[nodiscard]] inline std::string_view pf_state_word(const Section& s) {
    for (const auto& l : s.lines) {
        const auto t = trim(l);
        if (!t.starts_with("Status:"))
            continue;
        auto rest = trim(t.substr(7));
        return rest.substr(0, rest.find_first_of(" \t"));
    }
    return {};
}

using Counts = std::map<std::string, int>;

inline void diff_multiset(const std::vector<std::string>& before, const std::vector<std::string>& after,
                          Verdict& v, std::string_view where) {
    Counts a, b;
    for (const auto& l : before)
        ++a[l];
    for (const auto& l : after)
        ++b[l];
    for (const auto& [line, n] : a) {
        const int other = b.count(line) ? b.at(line) : 0;
        if (n > other) {
            v.gone += n - other;
            note(v.detail, std::string{where} + " gone", line);
        }
    }
    for (const auto& [line, n] : b) {
        const int other = a.count(line) ? a.at(line) : 0;
        if (n > other) {
            v.added += n - other;
            note(v.detail, std::string{where} + " added", line);
        }
    }
}

[[nodiscard]] inline std::vector<std::string> required_sections(Os os) {
    switch (os) {
    case Os::win:
        return {std::string{label::kProfiles}, std::string{label::kRules}};
    case Os::lin:
        return {std::string{label::kNft}}; // the iptables pair is checked by linux_pair_present()
    case Os::mac:
        return {std::string{label::kPfRules}, std::string{label::kPfStatus},
                std::string{label::kPfReferences}, std::string{label::kYuzuAnchor}};
    }
    return {};
}

/// The Linux section of one iptables family: the save-tool section when the snapshot has it, else the
/// root harness's `-S` mirror, else null. A snapshot is one form or the other, never a mix.
[[nodiscard]] inline const Section* linux_family(const Parsed& p, std::string_view save, std::string_view direct) {
    if (const auto* s = find_section(p, save))
        return s;
    return find_section(p, direct);
}

/// Whether a Linux snapshot has both iptables families, in one form: `iptables-legacy-save` and
/// `ip6tables-legacy-save`, or `iptables -S` and `ip6tables -S`.
[[nodiscard]] inline bool linux_pair_present(const Parsed& p) {
    return (find_section(p, label::kIptablesSave) && find_section(p, label::kIp6tablesSave)) ||
           (find_section(p, label::kIptables) && find_section(p, label::kIp6tables));
}

/// Why a snapshot cannot be trusted, or empty when it can.
[[nodiscard]] inline std::string unreadable_reason(Os os, std::string_view text) {
    if (trim(text).empty())
        return "empty snapshot";
    const auto p = parse(text);
    if (!p.has_end)
        return "no == end trailer (cut short, or not a snapshot)";
    if (p.stray_before_header)
        return "text ahead of the first section";
    for (const auto& name : required_sections(os))
        if (!find_section(p, name))
            return "section missing: " + name;
    if (os == Os::lin && !linux_pair_present(p))
        return "section missing: the iptables and ip6tables pair";
    bool any_readable = false;
    for (const auto& s : p.sections) {
        if (is_failed(s))
            return "a read failed: " + s.name;
        for (const auto& l : s.lines)
            if (trim(l).starts_with("sudo:") || trim(l).starts_with("sudo-rs:"))
                return "sudo refused: " + s.name;
        if (!is_absent(s))
            any_readable = true;
    }
    if (!any_readable)
        return "every section is absent";
    if (os == Os::mac) {
        const auto* st = find_section(p, label::kPfStatus);
        const auto word = pf_state_word(*st);
        if (word.empty())
            return "pf status has no Status line";
        if (word != "Enabled" && word != "Disabled")
            return "pf status has an unknown state word";
    }
    if (os == Os::win) {
        if (content_lines(*find_section(p, label::kRules)).empty())
            return "no rule lines";
        if (content_lines(*find_section(p, label::kProfiles)).empty())
            return "no profile lines";
    }
    return {};
}

inline void compare_windows(const Parsed& a, const Parsed& b, Verdict& v) {
    // profile defaults: a profile whose line differs, or that is on one side only
    const auto keyed = [](const Parsed& p, std::string_view label) {
        std::map<std::string, std::string> m;
        for (const auto& l : content_lines(*find_section(p, label)))
            m[std::string{field(l, 0)}] = l;
        return m;
    };
    const auto pa = keyed(a, label::kProfiles);
    const auto pb = keyed(b, label::kProfiles);
    for (const auto& [name, line] : pa) {
        if (!pb.count(name) || pb.at(name) != line) {
            ++v.defaults_changed;
            note(v.detail, "profile changed", line + (pb.count(name) ? " => " + pb.at(name) : " => (gone)"));
        }
    }
    for (const auto& [name, line] : pb)
        if (!pa.count(name)) {
            ++v.defaults_changed;
            note(v.detail, "profile added", line);
        }

    const auto ra = keyed(a, label::kRules);
    const auto rb = keyed(b, label::kRules);
    const auto was_enabled = [](const std::string& line) { return line.find("|en=True|") != std::string::npos; };
    const auto now_disabled = [](const std::string& line) { return line.find("|en=False|") != std::string::npos; };
    for (const auto& [key, line] : ra) {
        const bool package = is_package_rule_key(key);
        if (!rb.count(key)) {
            if (package) {
                ++v.package_churn;
            } else {
                ++v.gone;
                note(v.detail, "rule gone", line);
            }
            continue;
        }
        const auto& now = rb.at(key);
        if (now == line)
            continue;
        const bool left = was_enabled(line) && now_disabled(now);
        if (left) {
            ++v.left_disabled;
            note(v.detail, "rule left disabled", line + " => " + now);
        }
        if (package) {
            if (!left)
                ++v.package_churn;
        } else {
            ++v.changed;
            note(v.detail, "rule changed", line + " => " + now);
        }
    }
    for (const auto& [key, line] : rb) {
        if (ra.count(key))
            continue;
        if (is_package_rule_key(key)) {
            ++v.package_churn;
        } else {
            ++v.added;
            note(v.detail, "rule added", line);
        }
    }
    // Whatever of ours is still there, new or not.
    for (const auto& [key, line] : rb) {
        const auto display = field(line, 1);
        if (line.find("|grp=" + std::string{fq::kWinGroup} + "|") != std::string::npos ||
            key.starts_with(fq::kWinRulePrefix) || display.starts_with(fq::kWinRulePrefix)) {
            ++v.yuzu_residue;
            note(v.detail, "yuzu residue", line);
        }
    }
}

/// A save listing's chain line, `:<chain> <policy> [<packets>:<bytes>]`, without its counters. A line
/// that is not one is returned unchanged.
[[nodiscard]] inline std::string without_chain_counters(const std::string& line) {
    if (!line.starts_with(':'))
        return line;
    const auto bracket = line.rfind(" [");
    if (bracket == std::string::npos || line.back() != ']')
        return line;
    return line.substr(0, bracket);
}

inline void compare_linux(const Parsed& a, const Parsed& b, Verdict& v) {
    // nft is a section of its own; each iptables family is read from whichever form the snapshot has
    const Section* nft_a = find_section(a, label::kNft);
    const Section* nft_b = find_section(b, label::kNft);
    const std::pair<std::string_view, std::pair<const Section*, const Section*>> sections[] = {
        {label::kNft, {nft_a, nft_b}},
        {label::kIptables, {linux_family(a, label::kIptablesSave, label::kIptables),
                            linux_family(b, label::kIptablesSave, label::kIptables)}},
        {label::kIp6tables, {linux_family(a, label::kIp6tablesSave, label::kIp6tables),
                             linux_family(b, label::kIp6tablesSave, label::kIp6tables)}}};
    for (const auto& [name, pair] : sections) {
        const auto* sa = pair.first;
        const auto* sb = pair.second;
        const bool nft = name == label::kNft;
        std::vector<std::string> before, after;
        std::set<std::string> policy_a, policy_b;
        const auto fill = [&](const Section& s, std::vector<std::string>& rest, std::set<std::string>& policies) {
            for (const auto& raw : content_lines(s)) {
                auto line = normalise_linux_line(raw);
                if (line.empty())
                    continue;
                // a save listing's comment lines carry the date it was made on: never a difference
                if (!nft && line.starts_with('#'))
                    continue;
                line = without_chain_counters(line);
                // `-P <chain> <policy>` (the `-S` form) and `:<chain> <policy>` (a save listing; a
                // policy of `-` is a user-defined chain, which is a rule like any other) are defaults
                const bool policy_line =
                    line.starts_with("-P ") || (line.starts_with(':') && line.size() > 2 && !line.ends_with(" -"));
                if (policy_line)
                    policies.insert(line);
                else
                    rest.push_back(std::move(line));
            }
        };
        fill(*sa, before, policy_a);
        fill(*sb, after, policy_b);
        if (policy_a != policy_b) {
            v.defaults_changed += static_cast<int>(
                std::count_if(policy_a.begin(), policy_a.end(), [&](const auto& l) { return !policy_b.count(l); }) +
                std::count_if(policy_b.begin(), policy_b.end(), [&](const auto& l) { return !policy_a.count(l); }));
            note(v.detail, std::string{name} + " policy differs", "");
        }
        diff_multiset(before, after, v, name);
        for (const auto& l : after)
            if (l.find("table inet " + std::string{fq::kNftTable}) != std::string::npos ||
                l.find(fq::kIptablesChainPrefix) != std::string::npos) {
                ++v.yuzu_residue;
                note(v.detail, "yuzu residue", l);
            }
    }
}

inline void compare_macos(const Parsed& a, const Parsed& b, Verdict& v) {
    const auto noise_free = [](const Section& s) {
        std::vector<std::string> out;
        for (const auto& l : s.lines)
            if (!is_pf_noise(l))
                out.push_back(std::string{trim(l)});
        return out;
    };
    diff_multiset(noise_free(*find_section(a, label::kPfRules)),
                  noise_free(*find_section(b, label::kPfRules)), v, "pf rules");
    if (pf_state_word(*find_section(a, label::kPfStatus)) != pf_state_word(*find_section(b, label::kPfStatus))) {
        ++v.defaults_changed;
        note(v.detail, "pf state changed",
             std::string{pf_state_word(*find_section(a, label::kPfStatus))} + " => " +
                 std::string{pf_state_word(*find_section(b, label::kPfStatus))});
    }
    const auto refs_a = noise_free(*find_section(a, label::kPfReferences)).size();
    const auto refs_b = noise_free(*find_section(b, label::kPfReferences)).size();
    if (refs_a != refs_b) {
        ++v.defaults_changed;
        note(v.detail, "pf reference lines", std::format("{} => {}", refs_a, refs_b));
    }
    for (const auto& l : noise_free(*find_section(b, label::kYuzuAnchor))) {
        ++v.yuzu_residue;
        note(v.detail, "yuzu residue", l);
    }
}

} // namespace detail

/// True when the snapshot can be trusted: complete, every expected section present, no failed or
/// sudo-refused read, not every section absent, and for macOS a pf state word that is Enabled or
/// Disabled, for Windows at least one profile and one rule line. An empty snapshot is never
/// readable: comparing two empty snapshots proves nothing.
[[nodiscard]] inline bool readable(Os os, std::string_view text) {
    return detail::unreadable_reason(os, text).empty();
}

/// The named section's lines as text, or nullopt when the snapshot has no such section.
[[nodiscard]] inline std::optional<std::string> section(std::string_view text, std::string_view name) {
    const auto p = detail::parse(text);
    const auto* s = detail::find_section(p, name);
    if (!s)
        return std::nullopt;
    std::string out;
    for (const auto& l : s->lines) {
        out += l;
        out += '\n';
    }
    return out;
}

/// Compares two snapshots (see the file comment for what each OS compares).
[[nodiscard]] inline Verdict compare(Os os, std::string_view baseline, std::string_view after) {
    Verdict v;
    const auto bad_a = detail::unreadable_reason(os, baseline);
    const auto bad_b = detail::unreadable_reason(os, after);
    if (!bad_a.empty() || !bad_b.empty()) {
        v.detail = (bad_a.empty() ? std::string{} : "baseline unreadable: " + bad_a + "\n") +
                   (bad_b.empty() ? std::string{} : "after unreadable: " + bad_b + "\n");
        return v;
    }
    v.readable = true;
    const auto a = detail::parse(baseline);
    const auto b = detail::parse(after);
    switch (os) {
    case Os::win:
        detail::compare_windows(a, b, v);
        break;
    case Os::lin:
        detail::compare_linux(a, b, v);
        break;
    case Os::mac:
        detail::compare_macos(a, b, v);
        break;
    }
    v.restored = v.changed == 0 && v.gone == 0 && v.added == 0 && v.yuzu_residue == 0 &&
                 v.defaults_changed == 0 && v.left_disabled == 0;
    return v;
}

/// One line for a log, then the first differing lines.
[[nodiscard]] inline std::string describe(const Verdict& v) {
    return std::format("readable={} restored={} changed={} gone={} added={} left_disabled={} "
                       "defaults_changed={} yuzu_residue={} package_churn={} (not counted)\n{}",
                       v.readable, v.restored, v.changed, v.gone, v.added, v.left_disabled,
                       v.defaults_changed, v.yuzu_residue, v.package_churn, v.detail);
}

/// The `Status:` line of `pfctl -s info` (the first one), or empty. The rest of `-s info` carries
/// counters and an uptime that are never equal between two reads, so only this line is recorded.
[[nodiscard]] inline std::string pf_status_line(std::string_view info_text) {
    for (const auto raw : fq::detail::split(info_text, '\n')) {
        const auto line = detail::trim(raw);
        if (line.starts_with("Status:"))
            return std::string{line};
    }
    return {};
}

/// The number of rule lines in a pf rules section's text: every line except blanks and the ALTQ
/// notices `pfctl -s rules` prints on stderr (`No ALTQ support in kernel`, `ALTQ related functions
/// disabled`). The snapshot merges stderr, the plugin counts stdout only, so the two counts are the
/// same only with those lines left out.
[[nodiscard]] inline std::size_t count_pf_rule_lines(std::string_view pf_rules_text) {
    std::size_t count = 0;
    for (const auto line : fq::detail::split(pf_rules_text, '\n'))
        if (!detail::is_pf_noise(line))
            ++count;
    return count;
}

/// Is the yuzu pf anchor simply not loaded? Measured on macOS 26.6.2 (lab VM, 2026-11-22):
/// `pfctl -a <anchor> -s rules` for an anchor that is not loaded exits 0 and prints `pfctl:
/// DIOCGETRULES: Invalid argument` on stderr, which pf_anchor_section reads as an empty section by
/// keeping stderr out. A non-zero exit for an absent anchor was not seen there; it stays handled
/// here for a host that does, because it is not an unreadable host either: the plugin itself reads
/// it as "no anchor" after two good main reads (PfLeg::read_status).
/// True only when BOTH main pf reads completed, the anchor call ran to a non-zero exit (it did
/// start, was not killed by a signal or the deadline and was not clipped: `ran_to_exit`, with
/// `exit_code` > 0) and no output line is a sudo refusal. The caller then records the anchor
/// section EMPTY; in every other case a read that did not complete is `[failed]`. The pfctl wording
/// is deliberately not keyed on: only the exit status and the sudo prefixes are.
[[nodiscard]] inline bool pf_anchor_absent(bool main_reads_complete, bool ran_to_exit, int exit_code,
                                           std::string_view output) {
    if (!main_reads_complete || !ran_to_exit || exit_code <= 0)
        return false;
    for (const auto raw : fq::detail::split(output, '\n')) {
        const auto line = detail::trim(raw);
        if (line.starts_with("sudo:") || line.starts_with("sudo-rs:"))
            return false;
    }
    return true;
}

/// One run of the anchor read, reduced to what the section decision needs.
struct PfAnchorRead {
    bool complete = false;    // it ran to an exit of 0 and was not clipped (subprocess_complete)
    bool ran_to_exit = false; // it started and was neither killed, timed out nor clipped
    int exit_code = 0;
    std::string output;
};

/// The text of the pf anchor section, or nullopt for `[failed]`. `first` is the read with stderr NOT
/// merged: when it completed (exit 0) its stdout is the section, so an error line pfctl prints on
/// stderr for an anchor that is not loaded (macOS 26.6.2: exit 0 and `DIOCGETRULES: Invalid
/// argument`) is never read as a rule left behind. Only a read that did not complete is read again,
/// by `reread_merged`, with stderr merged, because pf_anchor_absent needs sudo's own message to tell
/// a refused grant from an absent anchor: absent is an empty section, anything else is `[failed]`.
template <class RereadMerged>
[[nodiscard]] inline std::optional<std::string> pf_anchor_section(bool main_reads_complete, const PfAnchorRead& first,
                                                                  RereadMerged&& reread_merged) {
    if (first.complete)
        return first.output;
    const PfAnchorRead merged = reread_merged();
    if (pf_anchor_absent(main_reads_complete, merged.ran_to_exit, merged.exit_code, merged.output))
        return std::string{};
    return std::nullopt;
}

/// The number of rules in the raw `nft -a list ruleset` text: the lines that end in a rule handle
/// (`# handle <digits>`) and whose text before that marker does not end in `{`. A table, chain,
/// set, map or flowtable header carries a handle too and ends in `{`; a set's element lines, its
/// type and policy lines and comments carry none; a rule printed over several lines carries the
/// handle on its last line only, so it counts once.
[[nodiscard]] inline std::size_t count_nft_rules(std::string_view nft_text) {
    std::size_t count = 0;
    constexpr std::string_view kHandle = "# handle ";
    for (const auto raw : fq::detail::split(nft_text, '\n')) {
        const auto line = detail::trim(raw);
        const auto at = line.rfind(kHandle);
        if (at == std::string_view::npos)
            continue;
        const auto digits = line.substr(at + kHandle.size());
        if (digits.empty() || !std::all_of(digits.begin(), digits.end(), [](char c) { return c >= '0' && c <= '9'; }))
            continue;
        if (at == 0)
            continue; // a bare "# handle N" comment, nothing before it
        const auto before = detail::trim(line.substr(0, at));
        if (before.empty() || before.back() == '{')
            continue;
        ++count;
    }
    return count;
}

/// The PowerShell the Windows snapshot runs: one script, ASCII only, UTF-8 output, and
/// `$ErrorActionPreference = 'Stop'` first so a failing cmdlet exits non-zero and the whole read
/// is recorded as failed instead of as a shorter list. The line format is the lab collector's
/// (the rule key is the internal name; the app path is environment-expanded because a COM
/// round trip rewrites `%SystemRoot%` into the same path with different text).
[[nodiscard]] inline std::string windows_snapshot_script() {
    return "$ErrorActionPreference = 'Stop'\n"
           "$ProgressPreference = 'SilentlyContinue'\n"
           "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8\n"
           "$apps = @{}; Get-NetFirewallApplicationFilter | ForEach-Object { $apps[$_.InstanceID] = "
           "[Environment]::ExpandEnvironmentVariables([string]$_.Program) }\n"
           "$ports = @{}; Get-NetFirewallPortFilter | ForEach-Object { $ports[$_.InstanceID] = "
           "('{0}:{1}>{2}' -f $_.Protocol, $_.LocalPort, $_.RemotePort) }\n"
           "$addrs = @{}; Get-NetFirewallAddressFilter | ForEach-Object { $addrs[$_.InstanceID] = "
           "('{0}>{1}' -f ($_.LocalAddress -join ','), ($_.RemoteAddress -join ',')) }\n"
           "'== profiles'\n"
           "Get-NetFirewallProfile | Sort-Object Name | ForEach-Object { "
           "'{0}|enabled={1}|in={2}|out={3}|allowLocalRules={4}' -f $_.Name, $_.Enabled, "
           "$_.DefaultInboundAction, $_.DefaultOutboundAction, $_.AllowLocalFirewallRules }\n"
           "'== rules'\n"
           "Get-NetFirewallRule | Sort-Object Name | ForEach-Object { "
           "'{0}|{1}|en={2}|{3}|{4}|prof={5}|grp={6}|app={7}|port={8}|addr={9}' -f $_.Name, "
           "$_.DisplayName, $_.Enabled, $_.Direction, $_.Action, $_.Profile, $_.DisplayGroup, "
           "$apps[$_.InstanceID], $ports[$_.InstanceID], $addrs[$_.InstanceID] }\n"
           "'== end'\n";
}

/// The script as `powershell.exe -EncodedCommand` wants it: base64 of its UTF-16LE bytes. The
/// argument is plain ASCII, so no quoting rule of any shell or command line can change it.
/// `ascii` must be ASCII.
[[nodiscard]] inline std::string utf16le_base64(std::string_view ascii) {
    std::string wide;
    wide.reserve(ascii.size() * 2);
    for (const char c : ascii) {
        wide += c;
        wide += '\0';
    }
    return yuzu::shared::base64_encode(wide);
}

} // namespace yuzu::test::fwrestore
