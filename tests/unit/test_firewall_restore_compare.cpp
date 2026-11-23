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

// The two iptables sections carry `ipt_label` and `ip6t_label`: the root harness's `-S` mirror of the direct
// legs by default, or the save tools' own names as the broker and the helper print them.
std::string lin_snapshot(std::string_view nft, std::string_view ipt, std::string_view ip6t,
                         std::string_view ipt_label = label::kIptables,
                         std::string_view ip6t_label = label::kIp6tables) {
    std::string out;
    write_section(out, label::kNft, true, nft);
    write_section(out, ipt_label, true, ipt);
    write_section(out, ip6t_label, true, ip6t);
    finish(out);
    return out;
}

constexpr std::string_view kIpt = "-P INPUT ACCEPT\n-P FORWARD ACCEPT\n-P OUTPUT ACCEPT\n";

// The same three sections as the broker and the helper print them: the legacy save tools' own names, and in
// each of those two sections either a save listing or `[tables]` (and the kernel's table names).
std::string lin_snapshot_save(std::string_view nft, std::string_view ipt, std::string_view ip6t) {
    return lin_snapshot(nft, ipt, ip6t, label::kIptablesSave, label::kIp6tablesSave);
}

// A save listing as `iptables-save` prints it (counters read [0:0] without -c; the first and last lines are
// the only ones that carry a date). `date` makes two reads of one ruleset differ the way two real ones do.
std::string save_listing(std::string_view date, std::string_view input_policy = "ACCEPT",
                         std::string_view counters = "[0:0]", std::string_view extra = "") {
    return "# Generated by iptables-save v1.8.11 on " + std::string{date} +
           "\n*filter\n:INPUT " + std::string{input_policy} + " " + std::string{counters} +
           "\n:FORWARD ACCEPT [0:0]\n:OUTPUT ACCEPT [0:0]\n" + std::string{extra} +
           "COMMIT\n# Completed on " + std::string{date} + "\n";
}

// The real lines of a Rocky 9.9 firewalld host's ruleset that change by themselves between two reads: a
// named counter object's values, and the elements of a set with timers (nft prints the countdown after each
// element, and the two timer texts below are the ones two reads of that host measured, a moment apart).
std::string timed_ruleset(std::string_view first_timer, std::string_view second_timer,
                          std::string_view counter_values = "packets 0 bytes 0") {
    return "table ip labrich { # handle 18\n\tcounter lab_ctr { # handle 15\n\t\t" + std::string{counter_values} +
           "\n\t}\n\n\tset timedset { # handle 3\n\t\ttype ipv4_addr\n\t\tsize 1024\n\t\tcounter\n"
           "\t\ttimeout 1h\n\t\tcomment \"lab timed set\"\n"
           "\t\telements = { 192.0.2.50 counter packets 0 bytes 0 timeout 30m expires " +
           std::string{first_timer} + ",\n\t\t\t     192.0.2.51 counter packets 0 bytes 0 expires " +
           std::string{second_timer} + " }\n\t}\n}\n";
}

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

TEST_CASE("Linux: a snapshot with [tables] legacy sections is readable and equal to itself", "[firewall]") {
    // The helper's `snapshot` word and the broker print `[tables]` and the kernel's table names for a legacy
    // family with no save tool: `[tables]` alone is a family that holds no table. The live read cases take
    // their baseline from such a host, so it must be a readable snapshot and not a failed read.
    for (const auto& snap : {lin_snapshot_save(kNftRuleset, "[tables]\n", "[tables]\n"),
                             lin_snapshot_save(kNftRuleset, "[tables]\n", save_listing("a")),
                             lin_snapshot_save("", "[tables]\n", "[tables]\n")}) {
        INFO(snap);
        CHECK(readable(Os::lin, snap));
        const auto v = compare(Os::lin, snap, snap);
        INFO(describe(v));
        CHECK(v.readable);
        CHECK(v.restored);
    }
    // a table that appears between two reads is a difference, not a pass
    const auto loaded_later = compare(Os::lin, lin_snapshot_save(kNftRuleset, "[tables]\n", "[tables]\n"),
                                      lin_snapshot_save(kNftRuleset, save_listing("x"), "[tables]\n"));
    INFO(describe(loaded_later));
    CHECK(loaded_later.readable);
    CHECK_FALSE(loaded_later.restored);
    CHECK(loaded_later.added >= 1);
    // and it does not make a failed read readable
    CHECK_FALSE(readable(Os::lin, lin_snapshot_save(kNftRuleset, "[tables]\n\n[failed]\n", "[tables]\n")));
}

TEST_CASE("Linux: [tables] followed by a name is tables nothing listed, so the plugin reads it as unread and so "
          "does the harness",
          "[firewall]") {
    // `[tables]` alone is a family that holds no table (readable, above); with a name after it, tables exist
    // that nothing listed (read_legacy_section reads that as unread), so a restore proof that called it
    // restored would call restored what nobody listed
    for (const char* names : {"[tables]\nfilter\n", "[tables]\nnat\nfilter\n"}) {
        INFO(names);
        for (const auto& snap : {lin_snapshot_save(kNftRuleset, names, "[tables]\n"),
                                 lin_snapshot_save(kNftRuleset, "[tables]\n", names)}) {
            CHECK_FALSE(readable(Os::lin, snap));
            const auto v = compare(Os::lin, snap, snap);
            CHECK_FALSE(v.readable);
            CHECK_FALSE(v.restored); // an unreadable baseline never compares equal to itself
        }
    }
}

TEST_CASE("Linux: a policy or a rule that changes in one table cannot hide behind the same line in another",
          "[firewall]") {
    // raw OUTPUT is DROP, mangle OUTPUT is ACCEPT, and filter OUTPUT goes from ACCEPT to DROP: the set of
    // policy lines is the same before and after unless each line carries the table it belongs to
    const auto listing = [](std::string_view filter_output) {
        return "*raw\n:PREROUTING ACCEPT [0:0]\n:OUTPUT DROP [0:0]\nCOMMIT\n"
               "*mangle\n:OUTPUT ACCEPT [0:0]\nCOMMIT\n"
               "*filter\n:INPUT ACCEPT [0:0]\n:OUTPUT " + std::string{filter_output} + " [0:0]\nCOMMIT\n";
    };
    const auto same = compare(Os::lin, lin_snapshot_save(kNftRuleset, listing("ACCEPT"), "[tables]\n"),
                              lin_snapshot_save(kNftRuleset, listing("ACCEPT"), "[tables]\n"));
    CHECK(same.readable);
    CHECK(same.restored);
    const auto leak = compare(Os::lin, lin_snapshot_save(kNftRuleset, listing("ACCEPT"), "[tables]\n"),
                              lin_snapshot_save(kNftRuleset, listing("DROP"), "[tables]\n"));
    INFO(describe(leak));
    CHECK(leak.readable);
    CHECK_FALSE(leak.restored);
    CHECK(leak.defaults_changed == 2); // the filter policy that went and the one that came
    // a rule that moves from one table to another is a line gone and a line added, not a pass
    const auto in_filter = "*filter\n:INPUT ACCEPT [0:0]\n-A INPUT -p tcp -j ACCEPT\nCOMMIT\n*mangle\n:INPUT ACCEPT [0:0]\nCOMMIT\n";
    const auto in_mangle = "*filter\n:INPUT ACCEPT [0:0]\nCOMMIT\n*mangle\n:INPUT ACCEPT [0:0]\n-A INPUT -p tcp -j ACCEPT\nCOMMIT\n";
    const auto moved = compare(Os::lin, lin_snapshot_save(kNftRuleset, in_filter, "[tables]\n"),
                               lin_snapshot_save(kNftRuleset, in_mangle, "[tables]\n"));
    INFO(describe(moved));
    CHECK(moved.readable);
    CHECK_FALSE(moved.restored);
    CHECK(moved.gone == 1);
    CHECK(moved.added == 1);
    // the `-S` form lists the filter table alone and is compared as before
    CHECK_FALSE(compare(Os::lin, lin_snapshot(kNftRuleset, kIpt, kIpt),
                        lin_snapshot(kNftRuleset, "-P INPUT DROP\n-P FORWARD ACCEPT\n-P OUTPUT ACCEPT\n", kIpt))
                    .restored);
}

TEST_CASE("Linux: a save listing's dates and chain counters are normalised away, and nothing else", "[firewall]") {
    // two reads of one ruleset: the dates differ and a chain's packet and byte counters moved
    const auto first = lin_snapshot_save(kNftRuleset, save_listing("Mon Nov 23 04:00:00 2026"), "[tables]\n");
    const auto later = lin_snapshot_save(kNftRuleset, save_listing("Mon Nov 23 04:00:02 2026", "ACCEPT", "[41:3120]"),
                                         "[tables]\n");
    const auto same = compare(Os::lin, first, later);
    INFO(describe(same));
    CHECK(same.readable);
    CHECK(same.restored);
    // a changed policy is a changed default (the line that went and the line that came), counters or not
    const auto dropped = compare(Os::lin, first, lin_snapshot_save(kNftRuleset, save_listing("x", "DROP"), "[tables]\n"));
    INFO(describe(dropped));
    CHECK(dropped.readable);
    CHECK_FALSE(dropped.restored);
    CHECK(dropped.defaults_changed == 2);
    CHECK(dropped.gone == 0);
    CHECK(dropped.added == 0);
    // an added rule, in the filter table or in a table the `-S` read never showed, is one line added
    const auto extra = compare(Os::lin, first,
                               lin_snapshot_save(kNftRuleset, save_listing("x", "ACCEPT", "[0:0]", "-A INPUT -p tcp -j ACCEPT\n"),
                                                 "[tables]\n"));
    CHECK(extra.readable);
    CHECK_FALSE(extra.restored);
    CHECK(extra.added == 1);
    CHECK(extra.gone == 0);
    const auto raw = compare(Os::lin, first,
                             lin_snapshot_save(kNftRuleset, save_listing("x") + "*raw\n:PREROUTING DROP [0:0]\nCOMMIT\n",
                                               "[tables]\n"));
    CHECK(raw.readable);
    CHECK_FALSE(raw.restored);
    CHECK(raw.added == 2); // `*raw` and `COMMIT` are lines of their own
    CHECK(raw.defaults_changed == 1);
    // a user chain is a rule like any other (its `-` is no policy); a user chain of ours is residue
    const auto chain = compare(Os::lin, first,
                               lin_snapshot_save(kNftRuleset, save_listing("x", "ACCEPT", "[0:0]", ":yuzu-fwq-3 - [0:0]\n"),
                                                 "[tables]\n"));
    CHECK_FALSE(chain.restored);
    CHECK(chain.added == 1);
    CHECK(chain.yuzu_residue == 1);
    CHECK(chain.defaults_changed == 0);
    // the nft section keeps its comment lines: only the iptables sections drop `#` lines
    const auto warn = compare(Os::lin, lin_snapshot_save(kNftRuleset, "[tables]\n", "[tables]\n"),
                              lin_snapshot_save("# Warning: table ip nat is managed by iptables-nft, do not touch!\n" + kNftRuleset,
                                                "[tables]\n", "[tables]\n"));
    CHECK(warn.readable);
    CHECK_FALSE(warn.restored);
    CHECK(warn.added == 1);
    // the two forms are each readable, and a pair of one form with the other is not a snapshot
    CHECK(readable(Os::lin, lin_snapshot(kNftRuleset, kIpt, kIpt)));
    CHECK(readable(Os::lin, lin_snapshot_save(kNftRuleset, "[tables]\n", "[tables]\n")));
    std::string mixed;
    write_section(mixed, label::kNft, true, kNftRuleset);
    write_section(mixed, label::kIptablesSave, true, "[tables]\n");
    write_section(mixed, label::kIp6tables, true, kIpt);
    finish(mixed);
    CHECK_FALSE(readable(Os::lin, mixed));
}

TEST_CASE("Linux: a timed set element's countdown and a counter object's values are normalised away",
          "[firewall]") {
    using detail::normalise_linux_line;
    // the real lines, from the Rocky 9.9 rich ruleset
    CHECK(normalise_linux_line("\t\telements = { 192.0.2.50 counter packets 0 bytes 0 timeout 30m expires 29m22s440ms,") ==
          "\t\telements = { 192.0.2.50 counter timeout 30m,");
    CHECK(normalise_linux_line("\t\t\t     192.0.2.51 counter packets 0 bytes 0 expires 59m22s }") ==
          "\t\t\t     192.0.2.51 counter }");
    CHECK(normalise_linux_line("\t\tpackets 0 bytes 0") == "\t\tpackets bytes");
    CHECK(normalise_linux_line("\t\tpackets 4096 bytes 1234567") == "\t\tpackets bytes");
    // every duration shape nft prints, at the end of the line too
    CHECK(normalise_linux_line("192.0.2.1 expires 1d2h3m4s5ms") == "192.0.2.1");
    CHECK(normalise_linux_line("192.0.2.1 expires 7s, 192.0.2.2 expires 9m") == "192.0.2.1, 192.0.2.2");
    // the element's own timeout is configuration, and text that merely looks like these stays
    CHECK(normalise_linux_line("192.0.2.1 timeout 30m") == "192.0.2.1 timeout 30m");
    CHECK(normalise_linux_line("comment \"expires soon\"") == "comment \"expires soon\"");
    CHECK(normalise_linux_line("192.0.2.1 expires m5") == "192.0.2.1 expires m5");
    CHECK(normalise_linux_line("192.0.2.1 expires 5m!") == "192.0.2.1 expires 5m!");
    CHECK(normalise_linux_line("comment \"expires 5m\"") == "comment \"expires 5m\"");
    CHECK(normalise_linux_line("\t\tpackets 0 bytes 0 drop") == "\t\tpackets 0 bytes 0 drop");
    CHECK(normalise_linux_line("\t\tpackets x bytes 0") == "\t\tpackets x bytes 0");
    CHECK(normalise_linux_line("\t\tpackets 0 bytes") == "\t\tpackets 0 bytes");

    // two reads of the same ruleset: the timers ticked (and one lost its milliseconds, so the wrapped
    // line changed width) and traffic went through the named counter
    const auto before = lin_snapshot(timed_ruleset("29m22s440ms", "59m22s440ms"), kIpt, kIpt);
    const auto after = lin_snapshot(timed_ruleset("29m22s", "59m22s", "packets 12 bytes 1840"), kIpt, kIpt);
    const auto same = compare(Os::lin, before, after);
    INFO(describe(same));
    CHECK(same.readable);
    CHECK(same.restored);

    // a change that is not a tick is still a difference: the timeout, an element, a quoted comment
    const auto edited = [](std::string_view from, std::string_view to) {
        auto text = timed_ruleset("29m22s", "59m22s");
        const auto at = text.find(from);
        REQUIRE(at != std::string::npos);
        text.replace(at, from.size(), to);
        return lin_snapshot(text, kIpt, kIpt);
    };
    const auto base = edited("timeout 30m", "timeout 30m");
    for (const auto& changed : {edited("timeout 30m", "timeout 45m"), edited("192.0.2.51", "192.0.2.52")}) {
        const auto v = compare(Os::lin, base, changed);
        INFO(describe(v));
        CHECK(v.readable);
        CHECK_FALSE(v.restored);
        CHECK(v.gone == 1); // the line that held the old value
        CHECK(v.added == 1); // and the line that holds the new one
        CHECK(v.changed == 0);
    }
    const auto comment = compare(Os::lin, edited("lab timed set", "expires soon"), edited("lab timed set", "expires later"));
    INFO(describe(comment));
    CHECK(comment.readable);
    CHECK_FALSE(comment.restored);
    CHECK(comment.gone == 1);
    CHECK(comment.added == 1);
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

TEST_CASE("macOS: pf_anchor_absent reads an anchor that is not loaded as absent, and nothing else",
          "[firewall]") {
    // what pfctl answers for an anchor that is not loaded on macOS 26.6.2 is exit 0 with this line on
    // stderr (see pf_anchor_section below); an exit of 1 with it was not observed there, and is the
    // absent anchor of a host that does exit non-zero: it ran, exited non-zero and printed its error;
    // both main reads completed
    const std::string_view invalid = "pfctl: DIOCGETRULES: Invalid argument\n";
    CHECK(pf_anchor_absent(true, true, 1, invalid));
    // the exit status decides, not the wording: another pfctl text with the same exit is absent too
    CHECK(pf_anchor_absent(true, true, 1, "pfctl: some other wording\n"));
    CHECK(pf_anchor_absent(true, true, 1, ""));

    // an incomplete main read: nothing can be said about the anchor
    CHECK_FALSE(pf_anchor_absent(false, true, 1, invalid));
    // a read that did not run to an exit (timed out, clipped, never started)
    CHECK_FALSE(pf_anchor_absent(true, false, 1, invalid));
    // a clean exit is a completed read (the caller keeps its output), not an absence
    CHECK_FALSE(pf_anchor_absent(true, true, 0, ""));
    // death by signal has no exit status
    CHECK_FALSE(pf_anchor_absent(true, true, -1, invalid));
    // sudo refusing is never an absent anchor, whichever spelling and wherever the line sits
    CHECK_FALSE(pf_anchor_absent(true, true, 1, "sudo: a password is required\n"));
    CHECK_FALSE(pf_anchor_absent(true, true, 1, "sudo-rs: interactive authentication is required\n"));
    CHECK_FALSE(pf_anchor_absent(true, true, 1, std::string{invalid} + "  sudo: a terminal is required\n"));

    // composed the way the harness writes it: absent is an EMPTY section that reads and restores,
    // a failed anchor read is `[failed]` and the snapshot is unreadable
    std::string clean;
    write_section(clean, label::kPfRules, true, kPfRulesMain);
    write_section(clean, label::kPfStatus, true, kPfOn);
    write_section(clean, label::kPfReferences, true, kPfRefs);
    write_section(clean, label::kYuzuAnchor, true, ""); // the anchor is absent
    finish(clean);
    CHECK(readable(Os::mac, clean));
    CHECK(compare(Os::mac, clean, mac_snapshot(kPfRulesMain, kPfOn, kPfRefs, "")).restored);
    std::string broken;
    write_section(broken, label::kPfRules, true, kPfRulesMain);
    write_section(broken, label::kPfStatus, true, kPfOn);
    write_section(broken, label::kPfReferences, true, kPfRefs);
    write_section(broken, label::kYuzuAnchor, false, "");
    finish(broken);
    CHECK_FALSE(readable(Os::mac, broken));
}

TEST_CASE("macOS: the anchor section is the read's stdout, and stderr is asked for only when it did not "
          "complete",
          "[firewall]") {
    // measured on macOS 26.6.2: an anchor that is not loaded reads exit 0, nothing on stdout and this on stderr
    const std::string_view real_line = "pfctl: DIOCGETRULES: Invalid argument\n";
    int rereads = 0;
    const auto reread = [&](PfAnchorRead merged) {
        return [&rereads, merged = std::move(merged)] {
            ++rereads;
            return merged;
        };
    };
    const auto base = mac_snapshot(kPfRulesMain, kPfOn, kPfRefs, "");

    // exit 0 and empty stdout: an empty, readable section that restores, and no second read
    const auto empty = pf_anchor_section(true, PfAnchorRead{true, true, 0, ""}, reread({}));
    REQUIRE(empty.has_value());
    CHECK(empty->empty());
    CHECK(rereads == 0);
    const auto restored = compare(Os::mac, base, mac_snapshot(kPfRulesMain, kPfOn, kPfRefs, *empty));
    CHECK(restored.readable);
    CHECK(restored.restored);

    // exit 0 with rule lines: they are kept, and they are residue
    const auto loaded = pf_anchor_section(true, PfAnchorRead{true, true, 0, "no nat all\nno rdr all\nblock drop quick all\n"},
                                          reread({}));
    REQUIRE(loaded.has_value());
    const auto residue = compare(Os::mac, base, mac_snapshot(kPfRulesMain, kPfOn, kPfRefs, *loaded));
    CHECK(residue.yuzu_residue == 3);
    CHECK_FALSE(residue.restored);
    CHECK(rereads == 0);

    // why stderr must stay out of the section: the real line, were it in there, is read as a rule left behind
    const auto merged_in = compare(Os::mac, base, mac_snapshot(kPfRulesMain, kPfOn, kPfRefs, real_line));
    CHECK(merged_in.yuzu_residue == 1);
    CHECK_FALSE(merged_in.restored);

    // a read that did not complete is read again with stderr merged: a sudo refusal is never an absent anchor
    const auto refused = pf_anchor_section(true, PfAnchorRead{false, true, 1, ""},
                                           reread({false, true, 1, "sudo: a password is required\n"}));
    CHECK_FALSE(refused.has_value()); // `[failed]`
    CHECK(rereads == 1);
    // ... a non-zero exit with pfctl's own error is the absent anchor of a host that exits non-zero
    const auto absent = pf_anchor_section(true, PfAnchorRead{false, true, 1, ""}, reread({false, true, 1, std::string{real_line}}));
    REQUIRE(absent.has_value());
    CHECK(absent->empty());
    CHECK(rereads == 2);
    // ... but only after the two main reads completed, and never for a read that did not run to an exit
    CHECK_FALSE(pf_anchor_section(false, PfAnchorRead{false, true, 1, ""}, reread({false, true, 1, std::string{real_line}}))
                    .has_value());
    CHECK_FALSE(pf_anchor_section(true, PfAnchorRead{false, false, 0, ""}, reread({false, false, 0, ""})).has_value());
}

TEST_CASE("macOS: count_pf_rule_lines leaves the ALTQ notices and blank lines out",
          "[firewall]") {
    // stderr merged into the snapshot: two notices, then two rules
    const std::string merged =
        "No ALTQ support in kernel\nALTQ related functions disabled\n"
        "scrub-anchor \"com.apple/*\" all fragment reassemble\nanchor \"com.apple/*\" all\n";
    CHECK(count_pf_rule_lines(merged) == 2);
    CHECK(count_pf_rule_lines(std::string{kPfRulesMain}) == 2);
    CHECK(count_pf_rule_lines("") == 0);
    CHECK(count_pf_rule_lines("\n  \n") == 0);
    CHECK(count_pf_rule_lines("No ALTQ support in kernel\nALTQ related functions disabled\n") == 0);
    // a rule line that merely mentions the word is a rule
    CHECK(count_pf_rule_lines("block drop log all label \"ALTQ related\"\n") == 1);
    // and it reads the section the way the harness stores it
    const auto snap = mac_snapshot(merged, kPfOn, kPfRefs, "");
    CHECK(count_pf_rule_lines(section(snap, label::kPfRules).value_or("")) == 2);
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
    // and neither is text ahead of the first header (classic sudo's `unable to resolve host`
    // warning, were stderr merged): the reason names it
    const auto ahead = "sudo: unable to resolve host lab-guest\n" + lin_snapshot(kNftRuleset, kIpt, kIpt);
    CHECK_FALSE(readable(Os::lin, ahead));
    CHECK(detail::unreadable_reason(Os::lin, ahead) == "text ahead of the first section");
    CHECK(readable(Os::lin, "\n\n" + lin_snapshot(kNftRuleset, kIpt, kIpt))); // blank lines are not text

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
    // the display group sits in its field: the Yuzu-residue check reads `grp=`
    CHECK(script.find("|grp={6}|") != std::string::npos);
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
