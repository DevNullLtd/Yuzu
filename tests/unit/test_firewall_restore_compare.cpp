/**
 * test_firewall_restore_compare.cpp -- the pure restore comparison the live containment harness
 * decides with (firewall_restore_compare.hpp). Runs on every host with no process, file or
 * socket: the snapshots are built here from sanitised excerpts of the lab collectors' output
 * (the Windows rule and profile line format, `nft -a list ruleset`, `iptables -S`, `pfctl`), with
 * no host name, user name, machine id or real SID (the SID below is a documentation value).
 */

#include "firewall_restore_compare.hpp"

#include <catch2/catch_test_macros.hpp>

#include <string>
#include <string_view>
#include <vector>

using namespace yuzu::test::fwrestore;

namespace {

// ── Windows ──────────────────────────────────────────────────────────────────

constexpr std::string_view kSid = "S-1-5-21-1111111111-2222222222-3333333333-1001";

const std::vector<std::string> kProfiles = {
    "Domain|enabled=True|in=NotConfigured|out=NotConfigured|allowLocalRules=NotConfigured",
    "Private|enabled=True|in=NotConfigured|out=NotConfigured|allowLocalRules=NotConfigured",
    "Public|enabled=True|in=NotConfigured|out=NotConfigured|allowLocalRules=NotConfigured",
};

const std::string kDnsRule =
    "CoreNet-DNS-Out-UDP|Core Networking - DNS (UDP-Out)|en=True|Outbound|Allow|prof=Any|"
    "grp=Core Networking|app=C:\\Windows\\system32\\svchost.exe|port=UDP:Any>53|addr=Any>Any";
const std::string kSshRule =
    "OpenSSH-Server-In-TCP|OpenSSH SSH Server (sshd)|en=True|Inbound|Allow|prof=Any|"
    "grp=OpenSSH Server|app=C:\\Windows\\System32\\OpenSSH\\sshd.exe|port=TCP:22>Any|addr=Any>Any";
const std::string kDisabledRule =
    "FPS-SMB-In-TCP|File and Printer Sharing (SMB-In)|en=False|Inbound|Allow|prof=Private, Public|"
    "grp=File and Printer Sharing|app=System|port=TCP:445>Any|addr=Any>Any";

std::string package_rule(std::string_view package, std::string_view enabled = "True",
                         std::string_view display = "") {
    // <package>_<publisher id, 13 chars>S-1-5-...: the key the Store gives an app's rule
    return std::string{package} + "_8wekyb3d8bbwe" + std::string{kSid} + "|" +
           std::string{display.empty() ? package : display} + "|en=" + std::string{enabled} +
           "|Inbound|Allow|prof=Any|grp=" + std::string{package} + "|app=Any|port=Any:Any>Any|addr=Any>Any";
}

std::string lines(const std::vector<std::string>& v) {
    std::string out;
    for (const auto& l : v)
        out += l + "\n";
    return out;
}

std::string win_snapshot(const std::vector<std::string>& rules,
                         const std::vector<std::string>& profiles = kProfiles) {
    std::string out;
    write_section(out, label::kProfiles, true, lines(profiles));
    write_section(out, label::kRules, true, lines(rules));
    finish(out);
    return out;
}

const std::vector<std::string> kWinBase = {kDnsRule, kSshRule, kDisabledRule,
                                           package_rule("Microsoft.WindowsStore"),
                                           package_rule("Microsoft.Windows.Search")};

Verdict win(const std::vector<std::string>& before, const std::vector<std::string>& after) {
    return compare(Os::win, win_snapshot(before), win_snapshot(after));
}

// ── Linux ────────────────────────────────────────────────────────────────────

const std::string kNftRuleset =
    "table inet filter { # handle 1\n"
    "\tchain input { # handle 1\n"
    "\t\ttype filter hook input priority filter; policy accept;\n"
    "\t\ttcp dport 22 counter packets 41 bytes 3120 accept # handle 4\n"
    "\t\tct state established,related accept # handle 5\n"
    "\t}\n"
    "}\n";

std::string lin_snapshot(std::string_view nft, std::string_view ipt, std::string_view ip6t) {
    std::string out;
    write_section(out, label::kNft, true, nft);
    write_section(out, label::kIptables, true, ipt);
    write_section(out, label::kIp6tables, true, ip6t);
    finish(out);
    return out;
}

constexpr std::string_view kIpt = "-P INPUT ACCEPT\n-P FORWARD ACCEPT\n-P OUTPUT ACCEPT\n";

// ── macOS ────────────────────────────────────────────────────────────────────

std::string mac_snapshot(std::string_view rules, std::string_view status, std::string_view refs,
                         std::string_view anchor) {
    std::string out;
    write_section(out, label::kPfRules, true, rules);
    write_section(out, label::kPfStatus, true, status);
    write_section(out, label::kPfReferences, true, refs);
    write_section(out, label::kYuzuAnchor, true, anchor);
    finish(out);
    return out;
}

constexpr std::string_view kPfRulesMain =
    "scrub-anchor \"com.apple/*\" all fragment reassemble\nanchor \"com.apple/*\" all\n";
constexpr std::string_view kPfOn = "Status: Enabled for 0 days 00:03:12            Debug: Urgent\n";
constexpr std::string_view kPfOff = "Status: Disabled for 0 days 00:00:09           Debug: Urgent\n";
constexpr std::string_view kPfRefs = "TOKEN       DURATION    PROCESS\n12345678901  0d 00:05:11  com.apple.example\n";

} // namespace

// ── write_section ────────────────────────────────────────────────────────────

TEST_CASE("write_section: a complete read writes its output, an incomplete one writes [failed]",
          "[firewall]") {
    std::string out;
    write_section(out, "iptables -S", true, "-P INPUT ACCEPT\n");
    write_section(out, "nft", true, "no trailing newline");
    write_section(out, "empty", true, "");
    write_section(out, "ip6tables -S", false, "-P INPUT DROP\npartial text that must not survive\n");
    write_absent(out, "pf");
    finish(out);
    CHECK(out == "== iptables -S\n-P INPUT ACCEPT\n== nft\nno trailing newline\n== empty\n"
                 "== ip6tables -S\n[failed]\n== pf\n[absent]\n== end\n");
    CHECK(out.find("partial text") == std::string::npos);
    CHECK(section(out, "iptables -S") == std::optional<std::string>{"-P INPUT ACCEPT\n"});
    CHECK(section(out, "empty") == std::optional<std::string>{""});
    CHECK(section(out, "ip6tables -S") == std::optional<std::string>{"[failed]\n"});
    CHECK_FALSE(section(out, "no such section").has_value());
}

// ── Windows ──────────────────────────────────────────────────────────────────

TEST_CASE("Windows: identical snapshots are readable and restored", "[firewall]") {
    const auto text = win_snapshot(kWinBase);
    CHECK(readable(Os::win, text));
    const auto v = compare(Os::win, text, text);
    INFO(describe(v));
    CHECK(v.readable);
    CHECK(v.restored);
    CHECK(v.changed == 0);
    CHECK(v.gone == 0);
    CHECK(v.added == 0);
    CHECK(v.package_churn == 0);
}

TEST_CASE("Windows: Store package rules renamed and added are counted and never fail", "[firewall]") {
    auto after = kWinBase;
    // a package rule whose display text moved with the package version, and a new one
    after[3] = package_rule("Microsoft.WindowsStore", "True", "Microsoft Store 22610.1401.3.0");
    after.push_back(package_rule("Microsoft.XboxGamingOverlay"));
    // a package rule that went away
    after.erase(after.begin() + 4);
    const auto v = win(kWinBase, after);
    INFO(describe(v));
    CHECK(v.readable);
    CHECK(v.restored);
    CHECK(v.package_churn == 3);
    CHECK(v.changed == 0);
    CHECK(v.gone == 0);
    CHECK(v.added == 0);
}

TEST_CASE("Windows: a non-package rule changed, gone or added fails, each alone", "[firewall]") {
    {
        auto after = kWinBase;
        after[1] = kSshRule + "X"; // the app column changed
        const auto v = win(kWinBase, after);
        CHECK_FALSE(v.restored);
        CHECK(v.changed == 1);
        CHECK(v.gone == 0);
        CHECK(v.added == 0);
    }
    {
        auto after = kWinBase;
        after.erase(after.begin() + 1);
        const auto v = win(kWinBase, after);
        CHECK_FALSE(v.restored);
        CHECK(v.gone == 1);
        CHECK(v.changed == 0);
        CHECK(v.added == 0);
    }
    {
        auto after = kWinBase;
        after.push_back("Custom-Allow-8080|Custom allow 8080|en=True|Inbound|Allow|prof=Any|grp=|"
                        "app=Any|port=TCP:8080>Any|addr=Any>Any");
        const auto v = win(kWinBase, after);
        CHECK_FALSE(v.restored);
        CHECK(v.added == 1);
        CHECK(v.changed == 0);
        CHECK(v.gone == 0);
    }
}

TEST_CASE("Windows: a rule of ours left behind fails, by group, by key and by display name",
          "[firewall]") {
    const std::string by_group =
        "ZZ-unrelated|Something|en=True|Outbound|Allow|prof=Any|grp=Yuzu Firewall Quarantine|app=Any|"
        "port=TCP:Any>50051|addr=Any>198.51.100.7";
    const std::string by_key =
        "YuzuFirewall_Quarantine_3_0|Whatever|en=True|Outbound|Allow|prof=Any|grp=|app=Any|port=Any|addr=Any";
    const std::string by_display =
        "ZZ-other|YuzuFirewall_Quarantine_3_1|en=True|Outbound|Allow|prof=Any|grp=|app=Any|port=Any|addr=Any";
    for (const auto& leftover : {by_group, by_key, by_display}) {
        auto after = kWinBase;
        after.push_back(leftover);
        const auto v = win(kWinBase, after);
        INFO(leftover);
        CHECK_FALSE(v.restored);
        CHECK(v.yuzu_residue == 1);
    }
    // residue that was already there before the case is still residue after it
    auto dirty = kWinBase;
    dirty.push_back(by_group);
    const auto v = win(dirty, dirty);
    CHECK_FALSE(v.restored);
    CHECK(v.yuzu_residue == 1);
}

TEST_CASE("Windows: a profile default changed fails", "[firewall]") {
    auto profiles = kProfiles;
    profiles[2] = "Public|enabled=True|in=Block|out=Block|allowLocalRules=NotConfigured";
    const auto v = compare(Os::win, win_snapshot(kWinBase), win_snapshot(kWinBase, profiles));
    INFO(describe(v));
    CHECK(v.readable);
    CHECK_FALSE(v.restored);
    CHECK(v.defaults_changed == 1);
    CHECK(v.changed == 0);

    // a profile that disappeared, and one that appeared
    auto fewer = kProfiles;
    fewer.pop_back();
    CHECK_FALSE(compare(Os::win, win_snapshot(kWinBase), win_snapshot(kWinBase, fewer)).restored);
    CHECK_FALSE(compare(Os::win, win_snapshot(kWinBase, fewer), win_snapshot(kWinBase)).restored);
}

TEST_CASE("Windows: a baseline-enabled rule now disabled fails, a package rule included", "[firewall]") {
    auto after = kWinBase;
    after[0] = kDnsRule;
    after[0].replace(after[0].find("|en=True|"), 9, "|en=False|");
    const auto plain = win(kWinBase, after);
    CHECK_FALSE(plain.restored);
    CHECK(plain.left_disabled == 1);

    // a Store package rule left switched off is the failure the comparison exists to catch
    auto pkg_after = kWinBase;
    pkg_after[3] = package_rule("Microsoft.WindowsStore", "False");
    const auto pkg = win(kWinBase, pkg_after);
    INFO(describe(pkg));
    CHECK_FALSE(pkg.restored);
    CHECK(pkg.left_disabled == 1);
    CHECK(pkg.package_churn == 0); // not also churn: it is already a failure

    // a rule that was disabled before and is disabled after is nothing
    CHECK(win(kWinBase, kWinBase).restored);
    // and one that was disabled and is now enabled is a change, not a left-disabled
    auto enabled_now = kWinBase;
    enabled_now[2] = kDisabledRule;
    enabled_now[2].replace(enabled_now[2].find("|en=False|"), 10, "|en=True|");
    const auto up = win(kWinBase, enabled_now);
    CHECK_FALSE(up.restored);
    CHECK(up.left_disabled == 0);
    CHECK(up.changed == 1);
}

TEST_CASE("Windows: the same path as environment text and as expanded text is one rule when both "
          "sides are expanded",
          "[firewall]") {
    // the collector expands the app path on both sides, so equal text is equal rules
    const std::string expanded =
        "CoreNet-ICMP|Core Networking - ICMP|en=True|Inbound|Allow|prof=Any|grp=Core Networking|"
        "app=C:\\Windows\\system32\\svchost.exe|port=ICMPv4:Any>Any|addr=Any>Any";
    std::string unexpanded = expanded;
    unexpanded.replace(unexpanded.find("C:\\Windows"), 10, "%SystemRoot%");
    auto base = kWinBase;
    base.push_back(expanded);
    auto same = kWinBase;
    same.push_back(expanded);
    CHECK(win(base, same).restored);
    // a side that was not expanded reads as a change, which is why the snapshot expands it
    auto raw = kWinBase;
    raw.push_back(unexpanded);
    CHECK_FALSE(win(base, raw).restored);
}

TEST_CASE("Windows: package rule keys match the Store pattern and nothing looser", "[firewall]") {
    using detail::is_package_rule_key;
    CHECK(is_package_rule_key(std::string{"Microsoft.WindowsStore_8wekyb3d8bbwe"} + std::string{kSid}));
    CHECK(is_package_rule_key("Some-App.Name_cw5n1h2txyewyS-1-5-21-1-2-3-1001"));
    CHECK_FALSE(is_package_rule_key("CoreNet-DNS-Out-UDP"));
    CHECK_FALSE(is_package_rule_key("OpenSSH-Server-In-TCP"));
    CHECK_FALSE(is_package_rule_key("Name_8wekyb3d8bbwe"));                       // no SID
    CHECK_FALSE(is_package_rule_key("Name_8WEKYB3D8BBWES-1-5-21"));              // publisher id is lower case
    CHECK_FALSE(is_package_rule_key("Name_8wekyb3d8bbS-1-5-21"));                // 11 characters, not 13
    CHECK_FALSE(is_package_rule_key("_8wekyb3d8bbweS-1-5-21"));                   // no package name
    CHECK_FALSE(is_package_rule_key("Name With Space_8wekyb3d8bbweS-1-5-21-1"));  // a space is not in the class
}

// ── Linux ────────────────────────────────────────────────────────────────────

TEST_CASE("Linux: counters and handles are normalised away", "[firewall]") {
    CHECK(detail::normalise_linux_line("\t\ttcp dport 22 counter packets 41 bytes 3120 accept # handle 4") ==
          "\t\ttcp dport 22 counter accept");
    CHECK(detail::normalise_linux_line("ip saddr 1.2.3.4 counter packets 0 bytes 0 counter packets 7 bytes 9 drop # handle 12") ==
          "ip saddr 1.2.3.4 counter counter drop");
    CHECK(detail::normalise_linux_line("table inet filter { # handle 1") == "table inet filter {");
    CHECK(detail::normalise_linux_line("-A INPUT -j ACCEPT   ") == "-A INPUT -j ACCEPT");
    // text that merely looks like a counter or a handle stays
    CHECK(detail::normalise_linux_line("comment \"counter packets x bytes y\"") ==
          "comment \"counter packets x bytes y\"");
    CHECK(detail::normalise_linux_line("accept # handle x") == "accept # handle x");

    // two reads of the same ruleset taken at different moments are equal
    std::string later = kNftRuleset;
    later.replace(later.find("packets 41 bytes 3120"), 21, "packets 97 bytes 8800");
    later.replace(later.find("# handle 4"), 10, "# handle 9");
    const auto v = compare(Os::lin, lin_snapshot(kNftRuleset, kIpt, kIpt), lin_snapshot(later, kIpt, kIpt));
    INFO(describe(v));
    CHECK(v.readable);
    CHECK(v.restored);
}

TEST_CASE("Linux: an added or lost rule line fails, a changed -P policy fails", "[firewall]") {
    const auto base = lin_snapshot(kNftRuleset, kIpt, kIpt);

    std::string lost = kNftRuleset;
    lost.erase(lost.find("\t\tct state"), std::string_view{"\t\tct state established,related accept # handle 5\n"}.size());
    const auto gone = compare(Os::lin, base, lin_snapshot(lost, kIpt, kIpt));
    CHECK_FALSE(gone.restored);
    CHECK(gone.gone == 1);
    CHECK(gone.added == 0);

    const auto extra = compare(Os::lin, base,
                               lin_snapshot(kNftRuleset, std::string{kIpt} + "-A INPUT -p tcp --dport 8080 -j ACCEPT\n", kIpt));
    CHECK_FALSE(extra.restored);
    CHECK(extra.added == 1);

    const auto policy = compare(Os::lin, base,
                                lin_snapshot(kNftRuleset, "-P INPUT DROP\n-P FORWARD ACCEPT\n-P OUTPUT ACCEPT\n", kIpt));
    INFO(describe(policy));
    CHECK_FALSE(policy.restored);
    CHECK(policy.defaults_changed == 2); // the line that went and the line that came
    CHECK(policy.gone == 0);

    // the same chain count in another order is not a change
    const auto reorder = compare(Os::lin, lin_snapshot(kNftRuleset, "-P INPUT ACCEPT\n-N a\n-N b\n-P FORWARD ACCEPT\n-P OUTPUT ACCEPT\n", kIpt),
                                 lin_snapshot(kNftRuleset, "-P OUTPUT ACCEPT\n-N b\n-N a\n-P INPUT ACCEPT\n-P FORWARD ACCEPT\n", kIpt));
    CHECK(reorder.restored);
}

TEST_CASE("Linux: our table or a yuzu-fwq- chain left behind is residue", "[firewall]") {
    const auto base = lin_snapshot(kNftRuleset, kIpt, kIpt);
    const std::string with_table = kNftRuleset + "table inet yuzu_quarantine { # handle 7\n\tchain input { # handle 1\n"
                                                 "\t\ttype filter hook input priority filter; policy drop;\n\t}\n}\n";
    const auto t = compare(Os::lin, base, lin_snapshot(with_table, kIpt, kIpt));
    INFO(describe(t));
    CHECK_FALSE(t.restored);
    CHECK(t.yuzu_residue >= 1);

    const auto c = compare(Os::lin, base,
                           lin_snapshot(kNftRuleset, std::string{kIpt} + "-N yuzu-fwq-3\n-A INPUT -j yuzu-fwq-3\n", kIpt));
    CHECK_FALSE(c.restored);
    CHECK(c.yuzu_residue == 2);

    // residue that was there before the case is still residue after it
    const auto dirty = lin_snapshot(with_table, kIpt, kIpt);
    CHECK_FALSE(compare(Os::lin, dirty, dirty).restored);
}

TEST_CASE("Linux: an empty but readable ruleset (the lab guest) is readable and restored",
          "[firewall]") {
    // nft prints nothing for an empty ruleset and exits 0: a complete, empty section. iptables is
    // not installed on this guest.
    std::string guest;
    write_section(guest, label::kNft, true, "");
    write_absent(guest, label::kIptables);
    write_absent(guest, label::kIp6tables);
    finish(guest);
    CHECK(readable(Os::lin, guest));
    const auto v = compare(Os::lin, guest, guest);
    INFO(describe(v));
    CHECK(v.readable);
    CHECK(v.restored);

    // a rule that appears on that guest is an added line
    std::string dirty;
    write_section(dirty, label::kNft, true, "table inet t { # handle 1\n}\n");
    write_absent(dirty, label::kIptables);
    write_absent(dirty, label::kIp6tables);
    finish(dirty);
    CHECK_FALSE(compare(Os::lin, guest, dirty).restored);
}

// ── macOS ────────────────────────────────────────────────────────────────────

TEST_CASE("macOS: ALTQ noise is ignored and a Status line that differs only in uptime is equal",
          "[firewall]") {
    const auto noisy = std::string{"No ALTQ support in kernel\nALTQ related functions disabled\n"} + std::string{kPfRulesMain};
    const auto a = mac_snapshot(noisy, kPfOn, kPfRefs, "No ALTQ support in kernel\nALTQ related functions disabled\n");
    const auto b = mac_snapshot(kPfRulesMain, "Status: Enabled for 3 days 11:50:00            Debug: Urgent\n", kPfRefs, "");
    CHECK(readable(Os::mac, a));
    const auto v = compare(Os::mac, a, b);
    INFO(describe(v));
    CHECK(v.readable);
    CHECK(v.restored);
}

TEST_CASE("macOS: Enabled against Disabled, the reference count and the main rules are compared",
          "[firewall]") {
    const auto base = mac_snapshot(kPfRulesMain, kPfOn, kPfRefs, "");
    const auto off = compare(Os::mac, base, mac_snapshot(kPfRulesMain, kPfOff, kPfRefs, ""));
    CHECK_FALSE(off.restored);
    CHECK(off.defaults_changed == 1);

    const auto refs = compare(Os::mac, base,
                              mac_snapshot(kPfRulesMain, kPfOn, std::string{kPfRefs} + "98765432109  0d 00:00:01  com.example.other\n", ""));
    CHECK_FALSE(refs.restored);
    CHECK(refs.defaults_changed == 1);

    const auto rules = compare(Os::mac, base,
                               mac_snapshot(std::string{kPfRulesMain} + "block drop all\n", kPfOn, kPfRefs, ""));
    CHECK_FALSE(rules.restored);
    CHECK(rules.added == 1);
    const auto lost = compare(Os::mac, base, mac_snapshot("anchor \"com.apple/*\" all\n", kPfOn, kPfRefs, ""));
    CHECK_FALSE(lost.restored);
    CHECK(lost.gone == 1);
}

TEST_CASE("macOS: a non-empty yuzu anchor is residue", "[firewall]") {
    const auto base = mac_snapshot(kPfRulesMain, kPfOn, kPfRefs, "");
    const auto v = compare(Os::mac, base,
                           mac_snapshot(kPfRulesMain, kPfOn, kPfRefs, "no nat all\nno rdr all\nblock drop quick all\n"));
    INFO(describe(v));
    CHECK_FALSE(v.restored);
    CHECK(v.yuzu_residue == 3);
    // an anchor holding only the pf noise is empty
    CHECK(compare(Os::mac, base, mac_snapshot(kPfRulesMain, kPfOn, kPfRefs, "No ALTQ support in kernel\n")).restored);
}

// ── unreadable snapshots ─────────────────────────────────────────────────────

TEST_CASE("unreadable: empty text, a missing == end trailer, a [failed] section, every section "
          "absent, zero Windows rule lines",
          "[firewall]") {
    // empty text
    CHECK_FALSE(readable(Os::win, ""));
    CHECK_FALSE(readable(Os::lin, "\n\n"));
    CHECK_FALSE(readable(Os::mac, "   "));

    // a listing that was cut short has no trailer
    auto cut = lin_snapshot(kNftRuleset, kIpt, kIpt);
    cut.erase(cut.rfind("== end"));
    CHECK_FALSE(readable(Os::lin, cut));
    // text after the trailer is not a snapshot either
    CHECK_FALSE(readable(Os::lin, lin_snapshot(kNftRuleset, kIpt, kIpt) + "stray\n"));

    // a read that failed
    std::string failed;
    write_section(failed, label::kNft, true, kNftRuleset);
    write_section(failed, label::kIptables, false, "-P INPUT ACCEPT\n");
    write_section(failed, label::kIp6tables, true, kIpt);
    finish(failed);
    CHECK_FALSE(readable(Os::lin, failed));
    // the helper marks a tool that exited non-zero AFTER what it printed
    CHECK_FALSE(readable(Os::lin, lin_snapshot(kNftRuleset, std::string{kIpt} + "[failed]\n", kIpt)));

    // every section absent
    std::string absent;
    write_absent(absent, label::kNft);
    write_absent(absent, label::kIptables);
    write_absent(absent, label::kIp6tables);
    finish(absent);
    CHECK_FALSE(readable(Os::lin, absent));

    // a snapshot without a section the OS needs
    std::string partial;
    write_section(partial, label::kNft, true, kNftRuleset);
    finish(partial);
    CHECK_FALSE(readable(Os::lin, partial));

    // Windows: no rule lines (an empty enumeration) and no profile lines
    CHECK_FALSE(readable(Os::win, win_snapshot({})));
    CHECK_FALSE(readable(Os::win, win_snapshot(kWinBase, {})));
    CHECK(readable(Os::win, win_snapshot(kWinBase)));

    // comparing with either side unreadable is never "restored", even against itself
    const auto good = win_snapshot(kWinBase);
    for (const auto& bad : {std::string{}, win_snapshot({}), std::string{"== profiles\n"}}) {
        CHECK_FALSE(compare(Os::win, good, bad).restored);
        CHECK_FALSE(compare(Os::win, bad, good).restored);
        const auto self = compare(Os::win, bad, bad);
        CHECK_FALSE(self.restored);
        CHECK_FALSE(self.readable);
        CHECK_FALSE(self.detail.empty());
    }
}

TEST_CASE("unreadable (review P1): identical snapshots of sudo's refusal text, a failed or "
          "malformed pf status",
          "[firewall]") {
    // a non-root run whose every read was refused by sudo: the sections hold sudo's message, and
    // two such snapshots are textually identical
    const std::string refusal = "sudo: a password is required\n";
    std::string refused;
    write_section(refused, label::kNft, true, refusal);
    write_section(refused, label::kIptables, true, refusal);
    write_section(refused, label::kIp6tables, true, refusal);
    finish(refused);
    CHECK_FALSE(readable(Os::lin, refused));
    const auto v = compare(Os::lin, refused, refused);
    CHECK_FALSE(v.restored);
    CHECK_FALSE(v.readable);
    // a sudo-rs spelling and a single refusing section
    CHECK_FALSE(readable(Os::lin, lin_snapshot(kNftRuleset, kIpt, "sudo-rs: interactive authentication is required\n")));
    CHECK_FALSE(readable(Os::lin, lin_snapshot(kNftRuleset, "sudo: a terminal is required to read the password\n", kIpt)));

    // a failed pf status read
    std::string failed_status;
    write_section(failed_status, label::kPfRules, true, kPfRulesMain);
    write_section(failed_status, label::kPfStatus, false, kPfOn);
    write_section(failed_status, label::kPfReferences, true, kPfRefs);
    write_section(failed_status, label::kYuzuAnchor, true, "");
    finish(failed_status);
    CHECK_FALSE(readable(Os::mac, failed_status));
    CHECK_FALSE(compare(Os::mac, failed_status, failed_status).restored);

    // a pf status section with no Status line, and one with a state word that is neither
    CHECK_FALSE(readable(Os::mac, mac_snapshot(kPfRulesMain, "", kPfRefs, "")));
    CHECK_FALSE(readable(Os::mac, mac_snapshot(kPfRulesMain, "pfctl: /dev/pf: Permission denied\n", kPfRefs, "")));
    CHECK_FALSE(readable(Os::mac, mac_snapshot(kPfRulesMain, "Status: Unknown for 0 days\n", kPfRefs, "")));
    CHECK_FALSE(readable(Os::mac, mac_snapshot(kPfRulesMain, "Status: enabled\n", kPfRefs, ""))); // case matters
    CHECK(readable(Os::mac, mac_snapshot(kPfRulesMain, kPfOn, kPfRefs, "")));
    CHECK(readable(Os::mac, mac_snapshot(kPfRulesMain, kPfOff, kPfRefs, "")));
    const auto same = mac_snapshot(kPfRulesMain, "", kPfRefs, "");
    CHECK_FALSE(compare(Os::mac, same, same).restored);
}

// ── count_nft_rules ──────────────────────────────────────────────────────────

TEST_CASE("count_nft_rules: lines ending in a rule handle count, headers, sets, policies and "
          "comments do not, a rule over several lines counts once",
          "[firewall]") {
    const std::string text =
        "# Warning: table ip nat is managed by iptables-nft, do not touch!\n"
        "table inet filter { # handle 1\n"
        "\tset blocked { # handle 2\n"
        "\t\ttype ipv4_addr\n"
        "\t\tflags interval\n"
        "\t\telements = { 192.0.2.0/24, 198.51.100.0/24 }\n"
        "\t}\n"
        "\tmap m { # handle 3\n"
        "\t\ttype ipv4_addr : verdict\n"
        "\t}\n"
        "\tflowtable ft { # handle 4\n"
        "\t\thook ingress priority filter\n"
        "\t}\n"
        "\tchain input { # handle 5\n"
        "\t\ttype filter hook input priority filter; policy accept;\n"
        "\t\ttcp dport 22 accept # handle 6\n"
        "\t\tip saddr @blocked drop # handle 7\n"
        "\t\ttcp dport {\n"
        "\t\t\t80, 443\n"
        "\t\t} accept # handle 8\n"
        "\t\tcounter packets 4 bytes 8 # handle 9\n"
        "\t}\n"
        "\tchain forward { # handle 10\n"
        "\t\ttype filter hook forward priority filter; policy drop;\n"
        "\t}\n"
        "}\n"
        "table ip6 filter { # handle 2\n"
        "\tchain input { # handle 1\n"
        "\t\ticmpv6 type echo-request accept comment \"ping\" # handle 2\n"
        "\t}\n"
        "}\n";
    // rules: handles 6, 7, 8 (one rule over three lines), 9, and the ip6 rule
    CHECK(count_nft_rules(text) == 5);
    CHECK(count_nft_rules("") == 0);
    CHECK(count_nft_rules("table inet t { # handle 1\n}\n") == 0);
    CHECK(count_nft_rules("accept # handle 3\r\ndrop # handle 4\r\n") == 2);
    CHECK(count_nft_rules("accept # handle x\n") == 0);
    CHECK(count_nft_rules("accept # handle \n") == 0);
}

// ── the Windows snapshot script ──────────────────────────────────────────────

TEST_CASE("the Windows snapshot script is ASCII, fails on a failing cmdlet, and ends the snapshot",
          "[firewall]") {
    const auto script = windows_snapshot_script();
    for (const unsigned char c : script)
        CHECK(((c >= 0x20 && c < 0x7f) || c == '\n'));
    // a cmdlet that throws must exit non-zero, so the read is recorded as failed, not as shorter
    CHECK(script.starts_with("$ErrorActionPreference = 'Stop'\n"));
    // no progress stream: it would be written to standard error as XML
    CHECK(script.find("$ProgressPreference = 'SilentlyContinue'") != std::string::npos);
    CHECK(script.find("[System.Text.Encoding]::UTF8") != std::string::npos);
    const auto profiles = script.find("'== profiles'");
    const auto rules = script.find("'== rules'");
    const auto end = script.find("'== end'");
    REQUIRE(profiles != std::string::npos);
    REQUIRE(rules != std::string::npos);
    REQUIRE(end != std::string::npos);
    CHECK(profiles < rules);
    CHECK(rules < end);
    CHECK(script.find("ExpandEnvironmentVariables") != std::string::npos);
    CHECK(script.find("Get-NetFirewallRule") != std::string::npos);
    // the rule line keeps the key first and the enabled flag where the comparison looks for it
    CHECK(script.find("'{0}|{1}|en={2}|") != std::string::npos);
    // what the script prints is what the reader reads
    CHECK(label::kProfiles == "profiles");
    CHECK(label::kRules == "rules");
}

TEST_CASE("utf16le_base64 encodes the way powershell -EncodedCommand reads it", "[firewall]") {
    CHECK(utf16le_base64("") == "");
    // each character is two bytes, the character and a zero
    CHECK(utf16le_base64("a") == "YQA=");
    CHECK(utf16le_base64("ab") == "YQBiAA==");
    CHECK(utf16le_base64("abc") == "YQBiAGMA");
    CHECK(utf16le_base64("dir") == "ZABpAHIA");
    const auto encoded = utf16le_base64(windows_snapshot_script());
    for (const char c : encoded)
        CHECK(((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '+' ||
                c == '/' || c == '='));
    CHECK(encoded.size() % 4 == 0);
}

TEST_CASE("pf_status_line keeps the Status line and nothing the uptime or counters touch",
          "[firewall]") {
    const std::string info =
        "No ALTQ support in kernel\nALTQ related functions disabled\n"
        "Status: Enabled for 0 days 00:03:12            Debug: Urgent\n\n"
        "State Table                          Total             Rate\n"
        "  current entries                        0\n";
    CHECK(pf_status_line(info) == "Status: Enabled for 0 days 00:03:12            Debug: Urgent");
    CHECK(pf_status_line("") == "");
    CHECK(pf_status_line("pfctl: /dev/pf: Permission denied\n") == "");
    CHECK(pf_status_line("  Status: Disabled for 1 days\r\n") == "Status: Disabled for 1 days");
    // and it round-trips through a snapshot as a readable pf status section
    std::string out;
    write_section(out, label::kPfRules, true, "");
    write_section(out, label::kPfStatus, true, pf_status_line(info));
    write_section(out, label::kPfReferences, true, "TOKEN DURATION PROCESS\n");
    write_section(out, label::kYuzuAnchor, true, "");
    finish(out);
    CHECK(readable(Os::mac, out));
}
