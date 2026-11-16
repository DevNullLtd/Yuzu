/**
 * test_process_introspect_parsers.cpp -- the pure core of the process_introspect plugin: request
 * grammar, start-time token, /proc/<pid>/stat, the /proc mount-table hidepid check,
 * /proc/<pid>/status, /proc/<pid>/limits, the oom values and the row formatters.
 *
 * FIXTURES. Every fixture below is a LABELLED FIXTURE written to the documented kernel layout
 * (proc(5), kernel 6.x): none was captured from a host by this test. The real-host capture is the
 * plugin-capture sample (agents/plugins/process_introspect/docs/samples/linux.txt), taken on a
 * Linux lane. No host is read and nothing is spawned here.
 *
 * Tagged [process_introspect] ONLY: a carved tag would move a case to another shard.
 */
#include <catch2/catch_test_macros.hpp>

#include "process_introspect_parsers.hpp"

#include <algorithm>
#include <cstdint>
#include <initializer_list>
#include <regex>
#include <string>
#include <vector>

using namespace yuzu::process_introspect;

namespace {

std::string join_lines(std::initializer_list<const char*> lines) {
    std::string out;
    for (const char* l : lines) {
        out += l;
        out += '\n';
    }
    return out;
}

/// A /proc/<pid>/stat line in the kernel 6.x layout: "<pid> (<comm>) S" then 49 more fields.
/// Field numbers are proc(5)'s; the helper sets the four the parser reads.
std::string make_stat(const std::string& comm, int nice, std::uint64_t starttime,
                      unsigned rt_priority, unsigned policy, int field_count = 52,
                      const std::string& start_override = {}) {
    std::vector<std::string> f(static_cast<std::size_t>(std::max(field_count, 41) + 1), "0");
    f[3] = "S";
    f[19] = std::to_string(nice);
    f[22] = start_override.empty() ? std::to_string(starttime) : start_override;
    f[40] = std::to_string(rt_priority);
    f[41] = std::to_string(policy);
    std::string s = "4242 (" + comm + ")";
    for (int i = 3; i <= field_count; ++i)
        s += ' ' + f[static_cast<std::size_t>(i)];
    return s + '\n';
}

// LABELLED FIXTURE (kernel 6.x layout): /proc/<pid>/status of a quiet root-less process.
const std::string kStatus = join_lines({
    "Name:\tsleep",
    "Umask:\t0022",
    "State:\tS (sleeping)",
    "Tgid:\t4242",
    "Threads:\t1",
    "SigQ:\t0/62311",
    "SigPnd:\t0000000000000000",
    "ShdPnd:\t0000000000000001",
    "SigBlk:\t0000000000010000",
    "SigIgn:\t0000000000384004",
    "SigCgt:\t0000000180000000",
    "CapInh:\t0000000000000000",
    "CapPrm:\t000001ffffffffff",
    "CapEff:\t000001ffffffffff",
    "CapBnd:\t000001ffffffffff",
    "CapAmb:\t0000000000000000",
    "NoNewPrivs:\t1",
    "Seccomp:\t2",
    "Seccomp_filters:\t3",
    "Speculation_Store_Bypass:\tthread vulnerable",
    "Cpus_allowed:\tffff",
    "Cpus_allowed_list:\t0-15",
});

// LABELLED FIXTURE: /proc/<pid>/limits, 16 rows.
const std::string kLimits = join_lines({
    "Limit                     Soft Limit           Hard Limit           Units     ",
    "Max cpu time              unlimited            unlimited            seconds   ",
    "Max file size             unlimited            unlimited            bytes     ",
    "Max data size             unlimited            unlimited            bytes     ",
    "Max stack size            8388608              unlimited            bytes     ",
    "Max core file size        0                    unlimited            bytes     ",
    "Max resident set          unlimited            unlimited            bytes     ",
    "Max processes             62311                62311                processes ",
    "Max open files            1024                 1048576              files     ",
    "Max locked memory         8388608              8388608              bytes     ",
    "Max address space         unlimited            unlimited            bytes     ",
    "Max file locks            unlimited            unlimited            locks     ",
    "Max pending signals       62311                62311                signals   ",
    "Max msgqueue size         819200               819200               bytes     ",
    "Max nice priority         0                    0                    ",
    "Max realtime priority     0                    0                    ",
    "Max realtime timeout      unlimited            unlimited            us        ",
});

// LABELLED FIXTURE: the /proc line of /proc/self/mountinfo with no hidepid option.
const std::string kProcLine =
    "23 28 0:21 / /proc rw,nosuid,nodev,noexec,relatime shared:13 - proc proc rw\n";

std::string proc_line_with(const std::string& super_opts, const std::string& fstype = "proc",
                           const std::string& point = "/proc") {
    return "23 28 0:21 / " + point + " rw,nosuid,nodev,noexec,relatime shared:13 - " + fstype +
           " proc " + super_opts + "\n";
}

} // namespace

TEST_CASE("process_introspect parse_pid accepts the grammar and nothing else", "[process_introspect]") {
    CHECK(parse_pid("1") == 1u);
    CHECK(parse_pid("2147483647") == 2147483647u);
    for (const char* bad : {"", "0", "01", "+1", "-1", " 1", "1 ", "0x10", "2147483648",
                            "12345678901", "1a", "1\n", "abc"})
        CHECK_FALSE(parse_pid(bad).has_value());
}

TEST_CASE("process_introspect parse_facet round-trips the six names and nothing else",
          "[process_introspect]") {
    for (std::size_t i = 0; i < kFacetNames.size(); ++i) {
        const auto f = parse_facet(kFacetNames[i]);
        REQUIRE(f.has_value());
        CHECK(static_cast<std::size_t>(*f) == i);
        CHECK(facet_name(*f) == kFacetNames[i]);
    }
    for (const char* bad : {"", "unknown", "Caps", "CAPS", "all", "caps,oom", "caps ", "limits"})
        CHECK_FALSE(parse_facet(bad).has_value());
}

TEST_CASE("process_introspect start-time token grammar", "[process_introspect]") {
    CHECK(boot_prefix("0123abcd-0000-0000-0000-000000000000") == "0123abcd");
    CHECK_FALSE(boot_prefix("0123abc").has_value());
    CHECK_FALSE(boot_prefix("0123ABCD-").has_value());
    CHECK_FALSE(boot_prefix("0123abcg-").has_value());
    CHECK_FALSE(boot_prefix("").has_value());

    CHECK(start_time_token("0123abcd", 987654) == "0123abcd.987654");
    CHECK(valid_start_time_token("0123abcd.987654"));
    CHECK(valid_start_time_token("0123abcd.18446744073709551615"));
    CHECK_FALSE(valid_start_time_token("0123ABCD.1"));       // upper-case hex
    CHECK_FALSE(valid_start_time_token("0123abcd.1|x"));     // pipe
    CHECK_FALSE(valid_start_time_token("0123abcd.1\n"));     // newline
    CHECK_FALSE(valid_start_time_token("0123abcd1"));        // missing dot
    CHECK_FALSE(valid_start_time_token("0123abcd."));        // no digits
    CHECK_FALSE(valid_start_time_token("0123abcd.123456789012345678901")); // 21 digits
    CHECK_FALSE(valid_start_time_token("0123abc.1"));        // 7 hex
    CHECK_FALSE(valid_start_time_token(""));
}

TEST_CASE("process_introspect parse_stat reads the four fields", "[process_introspect]") {
    const auto st = parse_stat(make_stat("sleep", -5, 987654, 10, 2));
    REQUIRE(st.has_value());
    CHECK(st->starttime == 987654u);
    CHECK(st->nice == -5);
    CHECK(st->rt_priority == 10u);
    CHECK(st->policy == 2u);
}

TEST_CASE("process_introspect parse_stat survives a comm with spaces and parentheses",
          "[process_introspect]") {
    for (const char* comm : {"a b", "x) S 1 2 3", "(((", "))) (", "a (b) c"}) {
        INFO("comm: " << comm);
        const auto st = parse_stat(make_stat(comm, 3, 55, 0, 0));
        REQUIRE(st.has_value());
        CHECK(st->starttime == 55u);
        CHECK(st->nice == 3);
    }
}

TEST_CASE("process_introspect parse_stat refuses short, non-numeric and out-of-range input",
          "[process_introspect]") {
    // proc(5) field 41 (policy) is the 39th token after comm; one field fewer is short.
    CHECK_FALSE(parse_stat(make_stat("x", 0, 1, 0, 0, 40)).has_value());
    CHECK(parse_stat(make_stat("x", 0, 1, 0, 0, 41)).has_value());
    CHECK_FALSE(parse_stat(make_stat("x", 20, 1, 0, 0)).has_value());   // nice 20
    CHECK_FALSE(parse_stat(make_stat("x", -21, 1, 0, 0)).has_value());  // nice -21
    CHECK_FALSE(parse_stat(make_stat("x", 0, 1, 100, 0)).has_value());  // rt_priority 100
    CHECK_FALSE(parse_stat(make_stat("x", 0, 1, 0, 0, 52, "zz")).has_value()); // non-numeric starttime
    CHECK_FALSE(parse_stat("").has_value());
    CHECK_FALSE(parse_stat("no parentheses here").has_value());
    CHECK_FALSE(parse_stat(") (").has_value());
}

TEST_CASE("process_introspect policy_token", "[process_introspect]") {
    CHECK(policy_token(0) == "other");
    CHECK(policy_token(1) == "fifo");
    CHECK(policy_token(2) == "rr");
    CHECK(policy_token(3) == "batch");
    CHECK(policy_token(5) == "idle");
    CHECK(policy_token(6) == "deadline");
    CHECK(policy_token(7) == "ext");
    CHECK(policy_token(4) == "unknown");
    CHECK(policy_token(99) == "unknown");
}

TEST_CASE("process_introspect proc_visibility: no hidepid is visible", "[process_introspect]") {
    CHECK(proc_visibility(kProcLine) == ProcVisibility::visible); // LABELLED FIXTURE
    for (const char* v : {"rw,hidepid=0", "rw,hidepid=off", "rw,hidepid=1", "rw,hidepid=noaccess"})
        CHECK(proc_visibility(proc_line_with(v)) == ProcVisibility::visible);
}

TEST_CASE("process_introspect proc_visibility: hidepid 2 and above, and unknown values, hide",
          "[process_introspect]") {
    for (const char* v : {"rw,hidepid=2", "rw,hidepid=invisible", "rw,hidepid=4",
                          "rw,hidepid=ptraceable", "rw,hidepid=something_new", "rw,gid=1,hidepid=2",
                          "hidepid=2,rw"})
        CHECK(proc_visibility(proc_line_with(v)) == ProcVisibility::hidden);
}

TEST_CASE("process_introspect proc_visibility: only a proc filesystem at /proc counts",
          "[process_introspect]") {
    // A /proc mount point whose filesystem type is not proc is ignored.
    CHECK(proc_visibility(proc_line_with("rw,hidepid=2", "tmpfs")) == ProcVisibility::unknown);
    // binfmt_misc under /proc/sys is a different mount point.
    CHECK(proc_visibility("40 23 0:35 / /proc/sys/fs/binfmt_misc rw,relatime shared:14 - binfmt_misc "
                          "binfmt_misc rw,hidepid=2\n") == ProcVisibility::unknown);
    // The LAST counting line wins: a later mount covers an earlier one.
    CHECK(proc_visibility(proc_line_with("rw,hidepid=2") + kProcLine) == ProcVisibility::visible);
    CHECK(proc_visibility(kProcLine + proc_line_with("rw,hidepid=2")) == ProcVisibility::hidden);
    // A line without the " - " separator is ignored.
    CHECK(proc_visibility("23 28 0:21 / /proc rw proc proc rw,hidepid=2\n") == ProcVisibility::unknown);
    CHECK(proc_visibility("") == ProcVisibility::unknown);
    CHECK(proc_visibility("1 2 0:1 / /sys rw - sysfs sysfs rw\n") == ProcVisibility::unknown);
}

TEST_CASE("process_introspect parse_status reads every key", "[process_introspect]") {
    const auto s = parse_status(kStatus);
    CHECK(s.sig_pnd.presence == Presence::ok);
    CHECK(s.shd_pnd.value == "0000000000000001");
    CHECK(s.sig_blk.value == "0000000000010000");
    CHECK(s.sig_ign.value == "0000000000384004");
    CHECK(s.sig_cgt.value == "0000000180000000");
    CHECK(s.cap_inh.value == "0000000000000000");
    CHECK(s.cap_prm.value == "000001ffffffffff");
    CHECK(s.cap_eff.value == "000001ffffffffff");
    CHECK(s.cap_bnd.value == "000001ffffffffff");
    CHECK(s.cap_amb.value == "0000000000000000");
    CHECK(s.no_new_privs.presence == Presence::ok);
    CHECK(s.no_new_privs.value == 1u);
    CHECK(s.seccomp.value == 2u);
    CHECK(s.seccomp_filters.value == 3u);
    CHECK(s.cpus_allowed_list.value == "0-15");
}

TEST_CASE("process_introspect parse_status: masks are exactly 16 lower-case hex digits",
          "[process_introspect]") {
    for (const char* bad : {"000000000000000", "00000000000000000", "000001FFFFFFFFFF",
                            "00000000000000g0", "", "0x00000000000000"}) {
        const auto s = parse_status(std::string{"SigBlk:\t"} + bad + "\n");
        INFO("mask: " << bad);
        CHECK(s.sig_blk.presence == Presence::invalid);
        CHECK(s.sig_blk.value.empty());
    }
}

TEST_CASE("process_introspect parse_status reports absent and invalid separately",
          "[process_introspect]") {
    const auto none = parse_status("Name:\tx\n");
    for (const TextField* f : {&none.sig_pnd, &none.shd_pnd, &none.sig_blk, &none.sig_ign,
                               &none.sig_cgt, &none.cap_inh, &none.cap_prm, &none.cap_eff,
                               &none.cap_bnd, &none.cap_amb, &none.cpus_allowed_list})
        CHECK(f->presence == Presence::absent);
    CHECK(none.seccomp.presence == Presence::absent);
    CHECK(none.no_new_privs.presence == Presence::absent);
    CHECK(none.seccomp_filters.presence == Presence::absent);

    const auto bad = parse_status("Seccomp:\tx\nCpus_allowed_list:\t0-a\nNoNewPrivs:\t2\n");
    CHECK(bad.seccomp.presence == Presence::invalid);
    CHECK(bad.cpus_allowed_list.presence == Presence::invalid);
    CHECK(bad.no_new_privs.presence == Presence::invalid);
}

TEST_CASE("process_introspect parse_status Seccomp values", "[process_introspect]") {
    CHECK(parse_status("Seccomp:\t0\n").seccomp.value == 0u);
    CHECK(parse_status("Seccomp:\t1\n").seccomp.value == 1u);
    CHECK(parse_status("Seccomp:\t2\n").seccomp.value == 2u);
    CHECK(parse_status("Seccomp:\t3\n").seccomp.presence == Presence::invalid);
    CHECK(seccomp_token(0) == "disabled");
    CHECK(seccomp_token(1) == "strict");
    CHECK(seccomp_token(2) == "filter");
}

TEST_CASE("process_introspect parse_status Cpus_allowed_list bound", "[process_introspect]") {
    const auto at = [](std::size_t n) {
        return parse_status("Cpus_allowed_list:\t" + std::string(n, '1') + "\n").cpus_allowed_list;
    };
    CHECK(at(4096).presence == Presence::ok);
    CHECK(at(4097).presence == Presence::invalid);
    CHECK(at(1).presence == Presence::ok);
    CHECK(parse_status("Cpus_allowed_list:\t0-3,8,10-11\n").cpus_allowed_list.presence == Presence::ok);
}

TEST_CASE("process_introspect parse_status: the first occurrence wins", "[process_introspect]") {
    const auto s = parse_status("SigBlk:\t0000000000000001\nSigBlk:\tffffffffffffffff\n"
                                "Seccomp:\t0\nSeccomp:\t2\nSigIgn:\tbad\nSigIgn:\t0000000000000002\n");
    CHECK(s.sig_blk.value == "0000000000000001");
    CHECK(s.seccomp.value == 0u);
    CHECK(s.sig_ign.presence == Presence::invalid); // the first, invalid, line decides
}

TEST_CASE("process_introspect parse_limits reads the 16 rows with units from the table",
          "[process_introspect]") {
    const auto p = parse_limits(kLimits);
    REQUIRE(p.header_seen);
    CHECK(p.unknown_rows == 0);
    REQUIRE(p.rows.size() == 16);
    CHECK(p.rows[0].name == "cpu_time");
    CHECK(p.rows[0].soft == "unlimited");
    CHECK(p.rows[0].unit == "seconds");
    CHECK(p.rows[3].name == "stack_size");
    CHECK(p.rows[3].soft == "8388608");
    CHECK(p.rows[3].hard == "unlimited");
    CHECK(p.rows[6].unit == "count"); // the kernel says `processes`; the unit is OUR token
    CHECK(p.rows[7].soft == "1024");
    CHECK(p.rows[7].hard == "1048576");
    CHECK(p.rows[13].name == "nice_priority");
    CHECK(p.rows[13].unit == "none"); // the kernel prints no unit here
    CHECK(p.rows[15].unit == "microseconds");
}

TEST_CASE("process_introspect parse_limits counts what it cannot place and echoes none of it",
          "[process_introspect]") {
    const auto p = parse_limits(
        "Limit Soft Limit Hard Limit Units\n"
        "Max cpu time unlimited unlimited seconds\n"
        "Max invented thing 1 2 bytes\n"
        "Max open files notanumber 5 files\n"
        "Max processes 1\n");
    REQUIRE(p.header_seen);
    CHECK(p.rows.size() == 1);
    CHECK(p.unknown_rows == 3);
    for (const auto& r : p.rows)
        CHECK(format_limit(r).find("invented") == std::string::npos);
}

TEST_CASE("process_introspect parse_limits: no header means nothing is parsed", "[process_introspect]") {
    // The kernel returns an EMPTY file for a target being reaped.
    for (const char* in : {"", "\n", "Max cpu time unlimited unlimited seconds\n",
                           "garbage\nMax cpu time unlimited unlimited seconds\n"}) {
        const auto p = parse_limits(in);
        CHECK_FALSE(p.header_seen);
        CHECK(p.rows.empty());
    }
}

TEST_CASE("process_introspect parse_oom_value", "[process_introspect]") {
    CHECK(parse_oom_value("0\n") == 0);
    CHECK(parse_oom_value("-1000\n") == -1000);
    CHECK(parse_oom_value("1000") == 1000);
    for (const char* bad : {"", "\n", "abc", "99999999999\n", "1\n2\n", "1 \n", " 1"})
        CHECK_FALSE(parse_oom_value(bad).has_value());
}

TEST_CASE("process_introspect formatters emit only validated shapes", "[process_introspect]") {
    const auto st = parse_stat(make_stat("sleep", -5, 987654, 10, 2));
    const auto ss = parse_status(kStatus);
    const auto lp = parse_limits(kLimits);
    REQUIRE((st && lp.header_seen));

    std::vector<std::string> rows;
    rows.push_back(format_target(4242, "0123abcd.987654", Facet::caps));
    for (const auto& r : lp.rows)
        rows.push_back(format_limit(r));
    rows.push_back(format_sigmask("blocked", ss.sig_blk.value));
    rows.push_back(format_cap("effective", ss.cap_eff.value));
    rows.push_back(format_seccomp(ss));
    rows.push_back(format_seccomp(StatusFields{}));
    rows.push_back(format_oom(500, -1000));
    rows.push_back(format_oom(std::nullopt, std::nullopt));
    rows.push_back(format_sched(*st, ss.cpus_allowed_list));
    rows.push_back(format_sched(*st, TextField{}));

    // The no-free-text invariant: lower-case tokens, then `|`-separated numeric/hex/token fields.
    static const std::regex shape{R"(^[a-z_]+(\|[a-z0-9_.,-]+)*$)"};
    for (const auto& r : rows) {
        INFO("row: " << r);
        CHECK(std::regex_match(r, shape));
    }
    CHECK(rows.front() == "target|4242|0123abcd.987654|caps");
    CHECK(format_seccomp(ss) == "seccomp|filter|3|1");
    CHECK(format_seccomp(StatusFields{}) == "seccomp|-|-|-");
    CHECK(format_oom(500, -1000) == "oom|500|-1000");
    CHECK(format_oom(std::nullopt, 5) == "oom|-|5");
    CHECK(format_sched(*st, ss.cpus_allowed_list) == "sched|rr|-5|10|0-15");
    CHECK(format_sched(*st, TextField{}) == "sched|rr|-5|10|-");
    CHECK(format_sigmask("blocked", "0000000000010000") == "sigmask|blocked|0000000000010000");
    CHECK(format_cap("effective", "000001ffffffffff") == "cap|effective|000001ffffffffff");
}

TEST_CASE("process_introspect: a process name never reaches any row", "[process_introspect]") {
    const std::string comm = "SECRETNAME";
    const auto st = parse_stat(make_stat(comm, 0, 1, 0, 0));
    REQUIRE(st.has_value());
    const auto ss = parse_status("Name:\t" + comm + "\n" + kStatus);
    for (const auto& row : {format_sched(*st, ss.cpus_allowed_list), format_seccomp(ss),
                            format_oom(1, 2), format_target(1, "0123abcd.1", Facet::sched)})
        CHECK(row.find("SECRETNAME") == std::string::npos);
}
