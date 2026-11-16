/**
 * test_process_introspect_legs.cpp -- the OS-free decision seam of the process_introspect plugin:
 * the pure errno classifiers, inspect_linux over an in-memory fake /proc that returns RAW errnos
 * (so the real classification arms run), report's status/result pairing and execute_inspect's
 * validation and containment. Compiles and runs on every OS; no host file is read and nothing
 * is spawned.
 *
 * The fake is the injected boundary: it records every read name and whether boot_id and
 * mountinfo were called, so the read-order rules (identity first, stat last, mount table only on
 * the not-found open path) are asserted, not assumed.
 *
 * Tagged [process_introspect] ONLY: a carved tag would move a case to another shard.
 */
#include <catch2/catch_test_macros.hpp>

#include "local_dispatcher.hpp"

#include "process_introspect_legs.hpp"

#include <algorithm>
#include <cerrno>
#include <deque>
#include <map>
#include <set>
#include <stdexcept>
#include <string>
#include <vector>

using namespace yuzu::process_introspect;

namespace {

// ---- fixtures: LABELLED FIXTURES in the documented kernel layout (see the parsers test) -------

std::string make_stat(std::uint64_t starttime, int nice = 0, unsigned rt = 0, unsigned policy = 0) {
    std::vector<std::string> f(42, "0");
    f[3] = "S";
    f[19] = std::to_string(nice);
    f[22] = std::to_string(starttime);
    f[40] = std::to_string(rt);
    f[41] = std::to_string(policy);
    std::string s = "4242 (sleep)";
    for (int i = 3; i <= 52 && i <= 41; ++i)
        s += ' ' + f[static_cast<std::size_t>(i)];
    return s + '\n';
}

const std::string kBootId = "0123abcd-4567-89ab-cdef-0123456789ab\n";
const std::string kToken = "0123abcd.987654";

const std::string kStatus =
    "Name:\tsleep\nSigPnd:\t0000000000000000\nShdPnd:\t0000000000000001\n"
    "SigBlk:\t0000000000010000\nSigIgn:\t0000000000384004\nSigCgt:\t0000000180000000\n"
    "CapInh:\t0000000000000000\nCapPrm:\t000001ffffffffff\nCapEff:\t000001ffffffffff\n"
    "CapBnd:\t000001ffffffffff\nCapAmb:\t0000000000000000\nNoNewPrivs:\t1\nSeccomp:\t2\n"
    "Seccomp_filters:\t3\nCpus_allowed_list:\t0-15\n";

const std::string kLimits =
    "Limit                     Soft Limit           Hard Limit           Units     \n"
    "Max cpu time              unlimited            unlimited            seconds   \n"
    "Max open files            1024                 1048576              files     \n"
    "Max nice priority         0                    0                    \n";

const std::string kProcVisible =
    "23 28 0:21 / /proc rw,nosuid,nodev,noexec,relatime shared:13 - proc proc rw\n";
const std::string kProcHidden =
    "23 28 0:21 / /proc rw,nosuid,nodev,noexec,relatime shared:13 - proc proc rw,hidepid=invisible\n";

RawRead ok(std::string data) { return RawRead{std::move(data), RawErr::none, 0}; }
RawRead io(int err) { return RawRead{{}, RawErr::io, err}; }
RawRead raw(RawErr e) { return RawRead{{}, e, 0}; }

/// The fake /proc. Each name holds a queue of results consumed in order; the last repeats.
struct Fake {
    int open_errno = 0;
    std::map<std::string, std::deque<RawRead>> files;
    RawRead boot = ok(kBootId);
    RawRead mount = ok(kProcVisible);
    mutable std::vector<std::string> reads; ///< names read from the pid directory, in order
    mutable int boot_calls = 0;
    mutable int mount_calls = 0;

    Fake() {
        set("stat", ok(make_stat(987654)));
        set("status", ok(kStatus));
        set("limits", ok(kLimits));
        set("oom_score", ok("100\n"));
        set("oom_score_adj", ok("-5\n"));
    }
    void set(const std::string& name, RawRead r) {
        files[name].clear();
        files[name].push_back(std::move(r));
    }
    void then(const std::string& name, RawRead r) { files[name].push_back(std::move(r)); }

    ProcSource src() const {
        ProcSource s;
        s.open_errno = open_errno;
        s.read = [this](const char* name, std::size_t) {
            reads.emplace_back(name);
            auto it = files.find(name);
            if (it == files.end())
                return io(ENOENT);
            auto& q = const_cast<std::deque<RawRead>&>(it->second);
            RawRead r = q.front();
            if (q.size() > 1)
                q.pop_front();
            return r;
        };
        s.boot_id = [this] {
            ++boot_calls;
            return boot;
        };
        s.mountinfo = [this] {
            ++mount_calls;
            return mount;
        };
        return s;
    }
};

Request req(Facet f, const std::string& start_time = {}) { return Request{4242, f, start_time}; }

Inspection run(const Fake& fk, Facet f, const std::string& start_time = {}) {
    return inspect_linux(req(f, start_time), fk.src());
}

bool has_token(const Inspection& r, const std::string& t) {
    return r.reason.find(t) != std::string::npos;
}

std::vector<std::string> facet_rows(const Inspection& r) {
    return r.rows.size() > 1 ? std::vector<std::string>(r.rows.begin() + 1, r.rows.end())
                             : std::vector<std::string>{};
}

std::string tok(const std::string& s) { return "linux:process_introspect:" + s; }

constexpr Facet kAll[] = {Facet::resource_limits, Facet::sigmasks, Facet::caps,
                          Facet::seccomp,         Facet::oom,      Facet::sched};

// ---- the seam as the host sees it ---------------------------------------------------------

const Inspection* g_report_input = nullptr;
int report_exec(YuzuCommandContext* raw_ctx, const char*, const YuzuParam*, std::size_t) {
    yuzu::CommandContext ctx{raw_ctx};
    report(ctx, *g_report_input);
    return 0;
}

struct ExecArgs {
    const char* action = "inspect";
    const char* pid = "4242";
    const char* facet = "oom";
    const char* start_time = "";
    LegFn leg = nullptr;
    int leg_calls = 0;
} g_exec;

int counting_leg(yuzu::CommandContext& ctx, const Request&) {
    ++g_exec.leg_calls;
    report(ctx, Inspection{StatusState::supported, {}, {"target|4242|0123abcd.1|oom"}});
    return 0;
}
int throwing_leg(yuzu::CommandContext&, const Request&) { throw std::runtime_error("probe"); }

int exec_exec(YuzuCommandContext* raw_ctx, const char*, const YuzuParam*, std::size_t) {
    yuzu::CommandContext ctx{raw_ctx};
    return execute_inspect(ctx, g_exec.action, g_exec.pid, g_exec.facet, g_exec.start_time,
                           g_exec.leg, "linux:leg:exception");
}

yuzu::agent::LocalDispatcher::Result dispatch(YuzuPluginDescriptor& d) {
    yuzu::agent::LocalDispatcher dispatcher;
    return dispatcher.run(&d, "inspect");
}

std::vector<std::string> rows_of(const std::string& captured) {
    std::vector<std::string> out;
    std::size_t i = 0;
    while (i < captured.size()) {
        const std::size_t nl = captured.find('\n', i);
        const std::string line = captured.substr(i, nl - i);
        if (!line.empty())
            out.push_back(line);
        if (nl == std::string::npos)
            break;
        i = nl + 1;
    }
    return out;
}

} // namespace

TEST_CASE("process_introspect classify_open_errno covers every arm", "[process_introspect]") {
    static_assert(classify_open_errno(0) == ReadState::ok);
    CHECK(classify_open_errno(0) == ReadState::ok);
    CHECK(classify_open_errno(ENOENT) == ReadState::not_found);
    CHECK(classify_open_errno(ESRCH) == ReadState::not_found);
    CHECK(classify_open_errno(EACCES) == ReadState::denied);
    CHECK(classify_open_errno(EPERM) == ReadState::denied);
    CHECK(classify_open_errno(EIO) == ReadState::io);
    CHECK(classify_open_errno(ENOTDIR) == ReadState::io);
}

TEST_CASE("process_introspect classify_read covers every arm", "[process_introspect]") {
    CHECK(classify_read(RawErr::none, 0) == ReadState::ok);
    CHECK(classify_read(RawErr::none, EIO) == ReadState::ok); // errno is meaningful for io only
    CHECK(classify_read(RawErr::oversized, 0) == ReadState::oversized);
    CHECK(classify_read(RawErr::io, ENOENT) == ReadState::not_found);
    CHECK(classify_read(RawErr::io, ESRCH) == ReadState::not_found);
    CHECK(classify_read(RawErr::io, EACCES) == ReadState::denied);
    CHECK(classify_read(RawErr::io, EPERM) == ReadState::denied);
    CHECK(classify_read(RawErr::io, EIO) == ReadState::io);
    CHECK(classify_read(RawErr::io, 0) == ReadState::io);
    CHECK(classify_read(RawErr::symlink_refused, 0) == ReadState::io);
    CHECK(classify_read(RawErr::not_regular, 0) == ReadState::io);
}

TEST_CASE("process_introspect happy path per facet", "[process_introspect]") {
    const std::map<Facet, std::vector<std::string>> expected{
        {Facet::resource_limits,
         {"limit|cpu_time|unlimited|unlimited|seconds", "limit|open_files|1024|1048576|count",
          "limit|nice_priority|0|0|none"}},
        {Facet::sigmasks,
         {"sigmask|pending|0000000000000000", "sigmask|shared_pending|0000000000000001",
          "sigmask|blocked|0000000000010000", "sigmask|ignored|0000000000384004",
          "sigmask|caught|0000000180000000"}},
        {Facet::caps,
         {"cap|inheritable|0000000000000000", "cap|permitted|000001ffffffffff",
          "cap|effective|000001ffffffffff", "cap|bounding|000001ffffffffff",
          "cap|ambient|0000000000000000"}},
        {Facet::seccomp, {"seccomp|filter|3|1"}},
        {Facet::oom, {"oom|100|-5"}},
        {Facet::sched, {"sched|other|0|0|0-15"}},
    };
    for (Facet f : kAll) {
        INFO("facet: " << facet_name(f));
        const Fake fk;
        const auto r = run(fk, f);
        CHECK(r.status == StatusState::supported);
        CHECK(r.reason.empty());
        REQUIRE_FALSE(r.rows.empty());
        CHECK(r.rows.front() == "target|4242|" + kToken + "|" + std::string{facet_name(f)});
        CHECK(facet_rows(r) == expected.at(f));
        CHECK(fk.mount_calls == 0);
    }
}

TEST_CASE("process_introspect a not-found open reads the mount table once", "[process_introspect]") {
    for (int err : {ENOENT, ESRCH}) {
        Fake fk;
        fk.open_errno = err;
        const auto r = run(fk, Facet::oom);
        CHECK(r.status == StatusState::unavailable);
        CHECK(r.reason == tok("no_such_process"));
        CHECK(r.rows.empty());
        CHECK(fk.reads.empty());
        CHECK(fk.boot_calls == 0);
        CHECK(fk.mount_calls == 1);
    }
}

TEST_CASE("process_introspect a hidden /proc never asserts the process is gone",
          "[process_introspect]") {
    for (const char* opt : {"rw,hidepid=2", "rw,hidepid=invisible", "rw,hidepid=ptraceable"}) {
        Fake fk;
        fk.open_errno = ENOENT;
        fk.mount = ok("23 28 0:21 / /proc rw shared:13 - proc proc " + std::string{opt} + "\n");
        const auto r = run(fk, Facet::oom);
        INFO(opt);
        CHECK(r.status == StatusState::unavailable);
        CHECK(r.reason == tok("no_such_process_or_hidden"));
        CHECK(r.rows.empty());
        CHECK(fk.reads.empty());
    }
    // An unreadable, oversized or /proc-less mount table is the weaker answer, never a bare gone.
    for (const RawRead& m : {io(EACCES), io(EIO), raw(RawErr::oversized),
                             ok("1 2 0:1 / /sys rw - sysfs sysfs rw\n"), ok("")}) {
        Fake fk;
        fk.open_errno = ENOENT;
        fk.mount = m;
        const auto r = run(fk, Facet::oom);
        CHECK(r.reason == tok("no_such_process_or_hidden"));
    }
}

TEST_CASE("process_introspect a refused or failed open reads nothing and skips the mount table",
          "[process_introspect]") {
    for (int err : {EACCES, EPERM}) {
        Fake fk;
        fk.open_errno = err;
        const auto r = run(fk, Facet::caps);
        CHECK(r.status == StatusState::permission_denied);
        CHECK(r.reason == tok("permission_denied"));
        CHECK(r.rows.empty());
        CHECK(fk.reads.empty());
        CHECK(fk.mount_calls == 0);
    }
    Fake fk;
    fk.open_errno = EIO;
    const auto r = run(fk, Facet::caps);
    CHECK(r.status == StatusState::unavailable);
    CHECK(r.reason == tok("identity_unreadable"));
    CHECK(fk.reads.empty());
    CHECK(fk.mount_calls == 0);
}

TEST_CASE("process_introspect identity failures are mapped and nothing else is read",
          "[process_introspect]") {
    struct Case {
        RawRead stat;
        StatusState state;
        const char* reason;
    };
    const Case cases[] = {
        {io(ENOENT), StatusState::unavailable, "no_such_process"}, // opened, then exited
        {io(ESRCH), StatusState::unavailable, "no_such_process"},
        {io(EACCES), StatusState::permission_denied, "permission_denied"},
        {io(EIO), StatusState::unavailable, "identity_unreadable"},
        {raw(RawErr::oversized), StatusState::unavailable, "identity_unreadable"},
        {ok("garbage"), StatusState::unavailable, "identity_unreadable"},
        {ok(""), StatusState::unavailable, "identity_unreadable"},
    };
    for (const auto& c : cases) {
        Fake fk;
        fk.set("stat", c.stat);
        const auto r = run(fk, Facet::oom);
        CHECK(r.status == c.state);
        CHECK(r.reason == tok(c.reason));
        CHECK(r.rows.empty());
        CHECK(fk.reads == std::vector<std::string>{"stat"});
        CHECK(fk.mount_calls == 0); // the directory opened: never the mount table
    }
    for (const RawRead& b : {io(EIO), io(ENOENT), raw(RawErr::oversized), ok(""), ok("ZZZZZZZZ-")}) {
        Fake fk;
        fk.boot = b;
        const auto r = run(fk, Facet::oom);
        CHECK(r.status == StatusState::unavailable);
        CHECK(r.reason == tok("identity_unreadable"));
        CHECK(fk.reads == std::vector<std::string>{"stat"});
    }
}

TEST_CASE("process_introspect a start_time guard refuses a reused pid before reading anything else",
          "[process_introspect]") {
    {
        Fake fk;
        const auto r = run(fk, Facet::caps, "0123abcd.1");
        CHECK(r.status == StatusState::unavailable);
        CHECK(r.reason == tok("pid_reused"));
        CHECK(r.rows.empty());
        CHECK(fk.reads == std::vector<std::string>{"stat"});
    }
    {
        // A token from another boot is a different process as far as this boot is concerned.
        Fake fk;
        const auto r = run(fk, Facet::caps, "ffffffff.987654");
        CHECK(r.reason == tok("pid_reused"));
    }
    {
        Fake fk;
        CHECK(run(fk, Facet::caps, kToken).status == StatusState::supported);
        Fake fk2;
        CHECK(run(fk2, Facet::caps, "").status == StatusState::supported);
    }
}

TEST_CASE("process_introspect a torn read discards every row", "[process_introspect]") {
    {
        Fake fk; // the second stat fails
        fk.then("stat", io(ESRCH));
        const auto r = run(fk, Facet::oom);
        CHECK(r.status == StatusState::unavailable);
        CHECK(r.reason == tok("torn_read"));
        CHECK(r.rows.empty());
    }
    {
        Fake fk; // the second stat answers a different start time: the pid was recycled
        fk.then("stat", ok(make_stat(1)));
        const auto r = run(fk, Facet::oom);
        CHECK(r.reason == tok("torn_read"));
        CHECK(r.rows.empty());
    }
    {
        Fake fk; // the second stat is unparseable
        fk.then("stat", ok("garbage"));
        CHECK(run(fk, Facet::oom).reason == tok("torn_read"));
    }
    for (Facet f : kAll) { // a facet source vanishing after identity means the process exited
        Fake fk;
        for (const char* n : {"status", "limits", "oom_score", "oom_score_adj"})
            fk.set(n, io(ENOENT));
        const auto r = run(fk, f);
        INFO(facet_name(f));
        CHECK(r.status == StatusState::unavailable);
        CHECK(r.reason == tok("torn_read"));
        CHECK(r.rows.empty());
    }
}

TEST_CASE("process_introspect read order: stat first and last, a facet reads only its own sources",
          "[process_introspect]") {
    const std::map<Facet, std::vector<std::string>> expected{
        {Facet::resource_limits, {"stat", "limits", "stat"}},
        {Facet::sigmasks, {"stat", "status", "stat"}},
        {Facet::caps, {"stat", "status", "stat"}},
        {Facet::seccomp, {"stat", "status", "stat"}},
        {Facet::oom, {"stat", "oom_score", "oom_score_adj", "stat"}},
        {Facet::sched, {"stat", "status", "stat"}},
    };
    for (Facet f : kAll) {
        const Fake fk;
        (void)run(fk, f);
        INFO(facet_name(f));
        CHECK(fk.reads == expected.at(f));
        CHECK(fk.boot_calls == 1);
    }
}

TEST_CASE("process_introspect partial reads are constrained, all-denied is permission_denied",
          "[process_introspect]") {
    {
        Fake fk;
        fk.set("oom_score_adj", io(EACCES));
        const auto r = run(fk, Facet::oom);
        CHECK(r.status == StatusState::constrained);
        CHECK(facet_rows(r) == std::vector<std::string>{"oom|100|-"});
        CHECK(has_token(r, tok("oom:permission_denied")));
    }
    {
        Fake fk;
        fk.set("oom_score", io(EACCES));
        fk.set("oom_score_adj", io(EPERM));
        const auto r = run(fk, Facet::oom);
        CHECK(r.status == StatusState::permission_denied);
        CHECK(r.rows.size() == 1); // only the target row
    }
    {
        Fake fk; // one denied + one failed with zero rows is NOT permission_denied
        fk.set("oom_score", io(EACCES));
        fk.set("oom_score_adj", io(EIO));
        const auto r = run(fk, Facet::oom);
        CHECK(r.status == StatusState::constrained);
        CHECK(r.rows.size() == 1);
        CHECK(has_token(r, tok("oom:permission_denied")));
        CHECK(has_token(r, tok("oom:read_failed")));
    }
    {
        Fake fk;
        fk.set("limits", raw(RawErr::oversized));
        const auto r = run(fk, Facet::resource_limits);
        CHECK(r.status == StatusState::constrained);
        CHECK(has_token(r, tok("resource_limits:oversized")));
    }
    {
        Fake fk; // sched keeps its stat-derived fields when status cannot be read
        fk.set("status", io(EACCES));
        const auto r = run(fk, Facet::sched);
        CHECK(r.status == StatusState::constrained);
        CHECK(facet_rows(r) == std::vector<std::string>{"sched|other|0|0|-"});
        CHECK(has_token(r, tok("sched:permission_denied")));
    }
}

TEST_CASE("process_introspect every required key is required", "[process_introspect]") {
    {
        Fake fk; // Seccomp missing
        fk.set("status", ok("Cpus_allowed_list:\t0\nNoNewPrivs:\t0\n"));
        const auto r = run(fk, Facet::seccomp);
        CHECK(r.status == StatusState::constrained);
        CHECK(has_token(r, tok("seccomp:malformed")));
        CHECK(facet_rows(r) == std::vector<std::string>{"seccomp|-|-|0"});
    }
    {
        Fake fk; // CapAmb missing: four rows and a token
        std::string st = kStatus;
        st.erase(st.find("CapAmb:"), std::string{"CapAmb:\t0000000000000000\n"}.size());
        fk.set("status", ok(st));
        const auto r = run(fk, Facet::caps);
        CHECK(r.status == StatusState::constrained);
        CHECK(has_token(r, tok("caps:malformed")));
        CHECK(facet_rows(r).size() == 4);
    }
    {
        Fake fk; // the 128-signal shape: 32-digit masks
        std::string st;
        for (const char* k : {"SigPnd", "ShdPnd", "SigBlk", "SigIgn", "SigCgt"})
            st += std::string{k} + ":\t" + std::string(32, '0') + "\n";
        fk.set("status", ok(st));
        const auto r = run(fk, Facet::sigmasks);
        CHECK(r.status == StatusState::constrained);
        CHECK(has_token(r, tok("sigmasks:malformed")));
        CHECK(facet_rows(r).empty());
    }
    {
        Fake fk; // Cpus_allowed_list missing
        std::string st = kStatus;
        st.erase(st.find("Cpus_allowed_list:"));
        fk.set("status", ok(st));
        const auto r = run(fk, Facet::sched);
        CHECK(r.status == StatusState::constrained);
        CHECK(has_token(r, tok("sched:malformed")));
        CHECK(facet_rows(r) == std::vector<std::string>{"sched|other|0|0|-"});
    }
    {
        Fake fk; // optional keys missing: supported, dashes, no token
        fk.set("status", ok("Seccomp:\t0\nCpus_allowed_list:\t0\n"));
        const auto r = run(fk, Facet::seccomp);
        CHECK(r.status == StatusState::supported);
        CHECK(facet_rows(r) == std::vector<std::string>{"seccomp|disabled|-|-"});
    }
    {
        Fake fk; // an optional key present but invalid is malformed
        fk.set("status", ok("Seccomp:\t0\nNoNewPrivs:\t7\nCpus_allowed_list:\t0\n"));
        const auto r = run(fk, Facet::seccomp);
        CHECK(r.status == StatusState::constrained);
        CHECK(has_token(r, tok("seccomp:malformed")));
    }
    {
        Fake fk; // an unparseable oom value
        fk.set("oom_score", ok("abc\n"));
        const auto r = run(fk, Facet::oom);
        CHECK(r.status == StatusState::constrained);
        CHECK(has_token(r, tok("oom:malformed")));
        CHECK(facet_rows(r) == std::vector<std::string>{"oom|-|-5"});
    }
}

TEST_CASE("process_introspect limits: unknown row and empty file", "[process_introspect]") {
    {
        Fake fk;
        fk.set("limits", ok(kLimits + "Max invented 1 2 bytes\n"));
        const auto r = run(fk, Facet::resource_limits);
        CHECK(r.status == StatusState::constrained);
        CHECK(has_token(r, tok("resource_limits:unknown_row")));
        CHECK(facet_rows(r).size() == 3); // the known rows are kept
    }
    {
        Fake fk; // the kernel's answer for a target being reaped
        fk.set("limits", ok(""));
        const auto r = run(fk, Facet::resource_limits);
        CHECK(r.status == StatusState::constrained);
        CHECK(has_token(r, tok("resource_limits:malformed")));
        CHECK(facet_rows(r).empty());
    }
}

TEST_CASE("process_introspect null-delivery sweep: no facet is supported on zero bytes",
          "[process_introspect]") {
    for (Facet f : kAll) {
        Fake fk;
        for (const char* n : {"status", "limits", "oom_score", "oom_score_adj"})
            fk.set(n, ok(""));
        const auto r = run(fk, f);
        INFO(facet_name(f));
        CHECK(r.status == StatusState::constrained);
        CHECK(has_token(r, tok(std::string{facet_name(f)} + ":malformed")));
    }
}

TEST_CASE("process_introspect supported implies at least one facet row", "[process_introspect]") {
    // Sweep: every combination of one broken source per facet. Whatever the outcome, a supported
    // answer always carries a facet row.
    const std::vector<RawRead> breaks = {ok(""), ok("garbage\n"), io(EACCES), io(EIO),
                                         raw(RawErr::oversized), raw(RawErr::not_regular)};
    for (Facet f : kAll)
        for (const char* src : {"status", "limits", "oom_score", "oom_score_adj"})
            for (const auto& b : breaks) {
                Fake fk;
                fk.set(src, b);
                const auto r = run(fk, f);
                if (r.status == StatusState::supported)
                    CHECK(facet_rows(r).size() >= 1);
            }
}

TEST_CASE("process_introspect parse_request", "[process_introspect]") {
    CHECK(parse_request("4242", "caps", "").has_value());
    CHECK(parse_request("4242", "caps", kToken).has_value());
    CHECK(parse_request("4242", "caps", "")->start_time.empty());
    CHECK(parse_request("", "caps", "").error() == "process_introspect:invalid_pid");
    CHECK(parse_request("0", "caps", "").error() == "process_introspect:invalid_pid");
    CHECK(parse_request("4242", "", "").error() == "process_introspect:invalid_facet");
    CHECK(parse_request("4242", "all", "").error() == "process_introspect:invalid_facet");
    CHECK(parse_request("4242", "caps", "zz").error() == "process_introspect:invalid_start_time");
    CHECK(parse_request("4242", "caps", "0123ABCD.1").error() ==
          "process_introspect:invalid_start_time");
}

TEST_CASE("process_introspect execute_inspect: validation, dispatch and containment",
          "[process_introspect]") {
    YuzuPluginDescriptor d{};
    d.execute = &exec_exec;

    g_exec = ExecArgs{};
    g_exec.leg = &counting_leg;
    {
        g_exec.action = "other";
        const auto r = dispatch(d);
        CHECK(r.rc == 1);
        CHECK(rows_of(r.captured) == std::vector<std::string>{"unknown action: other"});
        CHECK(g_exec.leg_calls == 0);
    }
    for (const auto& bad : std::vector<std::pair<const char*, const char*>>{
             {"pid", "process_introspect:invalid_pid"},
             {"facet", "process_introspect:invalid_facet"},
             {"start_time", "process_introspect:invalid_start_time"}}) {
        g_exec = ExecArgs{};
        g_exec.leg = &counting_leg;
        if (std::string{bad.first} == "pid")
            g_exec.pid = "abc";
        else if (std::string{bad.first} == "facet")
            g_exec.facet = "all";
        else
            g_exec.start_time = "zz";
        const auto r = dispatch(d);
        CHECK(r.rc == 1);
        CHECK(rows_of(r.captured) == std::vector<std::string>{std::string{"status|inspect|unavailable|"} + bad.second});
        CHECK(r.result_status == YUZU_RESULT_STATUS_UNAVAILABLE);
        CHECK(g_exec.leg_calls == 0); // the leg never runs on invalid input
    }
    {
        g_exec = ExecArgs{};
        g_exec.leg = &throwing_leg;
        const auto r = dispatch(d);
        CHECK(r.rc == 0); // contained, never unwound
        CHECK(rows_of(r.captured) ==
              std::vector<std::string>{"status|inspect|unsupported|linux:leg:exception"});
        CHECK(r.result_status == YUZU_RESULT_STATUS_UNAVAILABLE);
        CHECK(r.result_completeness == YUZU_RESULT_COMPLETENESS_UNKNOWN);
        CHECK(r.result_provenance == "linux:leg:exception");
    }
    {
        g_exec = ExecArgs{};
        g_exec.leg = &counting_leg;
        const auto r = dispatch(d);
        CHECK(r.rc == 0);
        CHECK(g_exec.leg_calls == 1);
    }
}

TEST_CASE("process_introspect report pairs each state with its result status", "[process_introspect]") {
    struct Case {
        StatusState state;
        const char* token;
        YuzuResultStatus status;
        YuzuResultCompleteness completeness;
    };
    const Case cases[] = {
        {StatusState::supported, "supported", YUZU_RESULT_STATUS_OK, YUZU_RESULT_COMPLETENESS_FULL},
        {StatusState::constrained, "constrained", YUZU_RESULT_STATUS_CONSTRAINED,
         YUZU_RESULT_COMPLETENESS_PARTIAL},
        // Deliberate: the pairing every other plugin uses for a refused read.
        {StatusState::permission_denied, "permission_denied", YUZU_RESULT_STATUS_PERMISSION_DENIED,
         YUZU_RESULT_COMPLETENESS_PARTIAL},
        {StatusState::unavailable, "unavailable", YUZU_RESULT_STATUS_UNAVAILABLE,
         YUZU_RESULT_COMPLETENESS_UNKNOWN},
        {StatusState::unsupported, "unsupported", YUZU_RESULT_STATUS_UNAVAILABLE,
         YUZU_RESULT_COMPLETENESS_UNKNOWN},
    };
    YuzuPluginDescriptor d{};
    d.execute = &report_exec;
    for (const auto& c : cases) {
        const bool supported = c.state == StatusState::supported;
        const Inspection in{c.state, supported ? std::string{} : tok("x:y"), {"target|1|0123abcd.1|oom"}};
        g_report_input = &in;
        const auto r = dispatch(d);
        INFO(c.token);
        const auto rows = rows_of(r.captured);
        REQUIRE(rows.size() == 2);
        CHECK(rows[0] == std::string{"status|inspect|"} + c.token + "|" + (supported ? "-" : tok("x:y")));
        CHECK(rows[1] == "target|1|0123abcd.1|oom");
        CHECK(r.result_status == c.status);
        CHECK(r.result_completeness == c.completeness);
        CHECK(r.result_provenance == (supported ? std::string{} : tok("x:y")));
    }
}
