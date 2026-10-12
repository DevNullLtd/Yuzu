/**
 * test_shares_legs.cpp -- fault tests for the OS-free `list_linux` / `list_macos`: every
 * boundary is a canned fake (no disk, no spawn, no uid dependence).
 *
 * Provenance: the `sharing -l -f json` text is a REAL capture (macOS 26.6.2, 2026-10-12,
 * anonymised); every other specimen is a RECONSTRUCTION built from the documented layouts.
 */
#include <catch2/catch_test_macros.hpp>

#include "shares_legs.hpp"

#include <algorithm>
#include <map>
#include <set>
#include <string>
#include <vector>

using namespace yuzu::shares;
using namespace yuzu::agent;

namespace {

constexpr const char* kExports = "/etc/exports";
constexpr const char* kSmb = "/etc/samba/smb.conf";
constexpr const char* kUsershares = "/var/lib/samba/usershares";

FileReadLike ok(std::string text) { return {std::move(text), ReadErr::none, 0}; }
FileReadLike io(int err) { return {{}, ReadErr::io, err}; }
FileReadLike kind(ReadErr e) { return {{}, e, 0}; }

constexpr const char* kSharingJson =
    R"({"Shared Folder":{"path":"\/Users\/jsmith\/Public","smb_guest_access":1,)"
    R"("smb_name":"Shared Folder","smb_read_only":0,"smb_sealed":0,"smb_shared":1}})";

/// Canned Linux boundaries; an unlisted path reads as ENOENT and every path asked for is
/// recorded.
struct FakeFs {
    std::map<std::string, FileReadLike> files;
    int list_err = ENOENT;
    std::vector<std::string> names;
    bool too_many = false;
    std::map<std::string, FileReadLike> snippets;
    std::set<std::string> dirs;
    std::vector<std::string> reads, snippet_reads, dir_probes;

    Listing run() {
        LinuxFs fs;
        fs.exports_path = kExports;
        fs.smb_conf_path = kSmb;
        fs.usershares_default = kUsershares;
        fs.read = [this](const std::string& p) {
            reads.push_back(p);
            const auto it = files.find(p);
            return it == files.end() ? io(ENOENT) : it->second;
        };
        fs.list_exports_d = [this](std::vector<std::string>& n, bool& tm) {
            n = names;
            tm = too_many;
            return list_err;
        };
        fs.read_exports_d_file = [this](const std::string& n) {
            snippet_reads.push_back(n);
            const auto it = snippets.find(n);
            return it == snippets.end() ? io(ENOENT) : it->second;
        };
        fs.dir_exists = [this](const std::string& p) {
            dir_probes.push_back(p);
            return dirs.contains(p);
        };
        return list_linux(fs);
    }
};

bool has(const Listing& l, const std::string& row) {
    return std::ranges::find(l.rows, row) != l.rows.end();
}
std::size_t count_prefix(const Listing& l, std::string_view prefix) {
    return static_cast<std::size_t>(std::ranges::count_if(
        l.rows, [&](const std::string& r) { return r.starts_with(prefix); }));
}
bool reason_has(const Listing& l, std::string_view token) {
    return l.reason.find(token) != std::string::npos;
}

struct FakeRun { // records what list_macos asked for, returns a fixed result
    SubprocessResult res;
    std::map<std::string, FileReadLike> files;
    std::vector<std::string> argv, reads;
    SubprocessOptions opts;

    Listing run() {
        return list_macos(
            [this](const std::vector<std::string>& a, const SubprocessOptions& o) {
                argv = a;
                opts = o;
                return res;
            },
            [this](const std::string& p) {
                reads.push_back(p);
                const auto it = files.find(p);
                return it == files.end() ? io(ENOENT) : it->second;
            },
            kExports);
    }
};

FakeRun exited(int code, std::string out) {
    FakeRun f;
    f.res.tool_ran = true;
    f.res.exit_code = code;
    f.res.termination_reason = TerminationReason::exited;
    f.res.output = std::move(out);
    return f;
}

} // namespace

TEST_CASE("shares linux: every source absent is supported with three absent source rows",
          "[shares]") {
    FakeFs f;
    const auto l = f.run();
    CHECK(l.status == StatusState::supported);
    CHECK(l.reason.empty());
    REQUIRE(l.rows.size() == 3);
    CHECK(l.rows[0] == "source|exports|absent|-");
    CHECK(l.rows[1] == "source|exports_d|absent|-");
    CHECK(l.rows[2] == "source|smb_conf|absent|-");
    CHECK(count_prefix(l, "share|") == 0);
}

TEST_CASE("shares linux: refused sources", "[shares]") {
    FakeFs only;
    only.files[kExports] = io(EACCES);
    const auto d = only.run();
    CHECK(d.status == StatusState::permission_denied);
    CHECK(reason_has(d, "linux:shares:exports:permission_denied"));
    CHECK(has(d, "source|exports|refused|-"));
    CHECK(count_prefix(d, "source|") == 3);

    FakeFs mixed;
    mixed.files[kExports] = io(EPERM);
    mixed.files[kSmb] = ok("[a]\npath=/srv/a\n");
    const auto c = mixed.run();
    CHECK(c.status == StatusState::constrained); // something was read: not permission_denied
    CHECK(reason_has(c, "linux:shares:exports:permission_denied"));
    CHECK(has(c, "source|exports|refused|-"));
    CHECK(has(c, "source|smb_conf|read|1"));
}

TEST_CASE("shares linux: failed reads carry a token", "[shares]") {
    struct Case {
        FileReadLike r;
        const char* token;
    };
    const Case cases[] = {
        {io(EIO), "linux:shares:smb_conf:eio"},
        {kind(ReadErr::symlink_refused), "linux:shares:smb_conf:symlink_refused"},
        {kind(ReadErr::not_regular), "linux:shares:smb_conf:not_regular"},
        {kind(ReadErr::oversized), "linux:shares:smb_conf:oversized"},
    };
    for (const auto& c : cases) {
        FakeFs f;
        f.files[kSmb] = c.r;
        const auto l = f.run();
        CHECK(l.status == StatusState::constrained);
        CHECK(reason_has(l, c.token));
        CHECK(has(l, "source|smb_conf|failed|-"));
    }
    FakeFs nul;
    std::string with_nul = "[a]\npath=/x";
    with_nul += '\0';
    with_nul += "y\n";
    nul.files[kSmb] = ok(with_nul);
    const auto l = nul.run();
    CHECK(reason_has(l, "linux:shares:smb_conf:invalid_bytes"));
    CHECK(count_prefix(l, "share|") == 0); // a NUL file is not parsed
}

TEST_CASE("shares linux: exports.d listing and snippet faults", "[shares]") {
    FakeFs notdir;
    notdir.list_err = ENOTDIR;
    auto l = notdir.run();
    CHECK(l.status == StatusState::constrained);
    CHECK(reason_has(l, "linux:shares:exports_d:not_a_directory"));
    CHECK(has(l, "source|exports_d|failed|-")); // never absent

    FakeFs denied;
    denied.list_err = EACCES;
    l = denied.run();
    CHECK(has(l, "source|exports_d|refused|-"));
    CHECK(l.status == StatusState::permission_denied);

    FakeFs many;
    many.list_err = 0;
    many.too_many = true;
    l = many.run();
    CHECK(reason_has(l, "linux:shares:exports_d:too_many"));

    FakeFs snip;
    snip.list_err = 0;
    snip.names = {"a.exports", "b.exports"};
    snip.snippets["a.exports"] = io(EACCES);
    snip.snippets["b.exports"] = ok("/srv/b host(rw)\n");
    l = snip.run();
    CHECK(has(l, "source|exports_d|refused|-")); // worst of the snippets
    CHECK(has(l, "share|nfs|-|/srv/b|rw|false|clients_1|exports_d")); // still emitted
    CHECK(l.status == StatusState::constrained);

    FakeFs good;
    good.list_err = 0;
    good.names = {"a.exports"};
    good.snippets["a.exports"] = ok("/srv/a *(ro)\n");
    l = good.run();
    CHECK(l.status == StatusState::supported);
    CHECK(has(l, "source|exports_d|read|1"));

    FakeFs empty; // a readable directory with nothing in it is a read of zero, never ambiguous
    empty.list_err = 0;
    l = empty.run();
    CHECK(l.status == StatusState::supported);
    CHECK(has(l, "source|exports_d|read|0"));
}

TEST_CASE("shares linux: an oversized field is cut and reported", "[shares]") {
    FakeFs f;
    f.files[kExports] = ok("/" + std::string(10000, 'p') + " h(rw)\n");
    const auto l = f.run();
    CHECK(l.status == StatusState::constrained);
    CHECK(reason_has(l, "linux:shares:field_oversized"));
    CHECK(count_prefix(l, "share|") == 1);
}

TEST_CASE("shares linux: declared unreached scope tokens", "[shares]") {
    FakeFs reg;
    reg.files[kSmb] = ok("[global]\nconfig backend = registry\n");
    CHECK(reason_has(reg.run(), "linux:shares:smb_conf:registry_backend"));

    FakeFs inc;
    inc.files[kSmb] = ok("[global]\ninclude = /etc/samba/more.conf\n");
    CHECK(reason_has(inc.run(), "linux:shares:smb_conf:include_unresolved"));

    FakeFs copy;
    copy.files[kSmb] = ok("[a]\ncopy = nope\npath=/a\n");
    CHECK(reason_has(copy.run(), "linux:shares:smb_conf:copy_unresolved"));

    FakeFs us;
    us.files[kSmb] = ok("[global]\nusershare max shares = 100\n");
    CHECK(reason_has(us.run(), "linux:shares:smb_conf:usershares_not_read"));

    // The directory alone is evidence (a Debian build's compiled-in default is invisible).
    FakeFs dir;
    dir.files[kSmb] = ok("[a]\npath=/a\n");
    dir.dirs.insert(kUsershares);
    const auto l = dir.run();
    CHECK(reason_has(l, "linux:shares:smb_conf:usershares_not_read"));
    REQUIRE(dir.dir_probes.size() == 1);
    CHECK(dir.dir_probes[0] == kUsershares);

    FakeFs custom;
    custom.files[kSmb] = ok("[global]\nusershare path = /srv/us\n");
    custom.run();
    REQUIRE(custom.dir_probes.size() == 1);
    CHECK(custom.dir_probes[0] == "/srv/us");

    FakeFs absent; // no smb.conf: the usershares directory is not probed
    absent.dirs.insert(kUsershares);
    absent.run();
    CHECK(absent.dir_probes.empty());
}

TEST_CASE("shares linux: one budget spans every source", "[shares]") {
    std::string exp, conf;
    for (int i = 0; i < 300; ++i) {
        exp += "/e" + std::to_string(i) + " h(rw)\n";
        conf += "[s" + std::to_string(i) + "]\npath=/s" + std::to_string(i) + "\n";
    }
    FakeFs f;
    f.files[kExports] = ok(exp);
    f.files[kSmb] = ok(conf);
    const auto l = f.run();
    CHECK(count_prefix(l, "share|") == 512);
    CHECK(reason_has(l, "linux:shares:row_cap"));
    CHECK(l.status == StatusState::constrained);
    CHECK(has(l, "source|exports|read|300"));
    CHECK(has(l, "source|smb_conf|read|212"));
}

TEST_CASE("shares linux: only the expected paths are asked for", "[shares]") {
    FakeFs f;
    f.list_err = 0;
    f.names = {"x.exports"};
    f.snippets["x.exports"] = ok("/srv/x h\n");
    f.files[kSmb] = ok("[global]\n");
    f.run();
    CHECK(f.reads == std::vector<std::string>{kExports, kSmb});
    CHECK(f.snippet_reads == std::vector<std::string>{"x.exports"});
    CHECK(f.dir_probes == std::vector<std::string>{kUsershares});
}

TEST_CASE("shares linux: rows are source rows first, then shares, each pipe-clean", "[shares]") {
    FakeFs f;
    f.files[kExports] = ok("/srv/pub *(rw)\n");
    f.files[kSmb] = ok("[a]\npath=/srv/a\nread only = no\n");
    const auto l = f.run();
    REQUIRE(l.rows.size() == 5);
    CHECK(l.rows[0] == "source|exports|read|1");
    CHECK(l.rows[3] == "share|nfs|-|/srv/pub|rw|true|clients_1|exports");
    CHECK(l.rows[4] == "share|smb|a|/srv/a|rw|false|-|smb_conf");
}

TEST_CASE("shares macos: argv and bounds are pinned", "[shares]") {
    auto f = exited(0, "{}");
    f.run();
    CHECK(f.argv == std::vector<std::string>{"/usr/sbin/sharing", "-l", "-f", "json"});
    CHECK(f.opts.deadline == std::chrono::milliseconds{5000});
    CHECK(f.opts.max_lines == 8192);
    CHECK(f.opts.output_cap_bytes == 512 * 1024);
    CHECK_FALSE(f.opts.merge_stderr);
    CHECK(f.reads == std::vector<std::string>{kExports});
}

TEST_CASE("shares macos: a failed or unstartable tool still emits both source rows", "[shares]") {
    FakeRun spawn;
    spawn.res.termination_reason = TerminationReason::spawn_error;
    auto l = spawn.run();
    CHECK(l.status == StatusState::constrained);
    CHECK(l.reason == "subprocess_runner:spawn_error");
    CHECK(l.rows == std::vector<std::string>{"source|exports|absent|-", "source|sharing|failed|-"});
    CHECK(spawn.reads == std::vector<std::string>{kExports}); // the file read is independent of the tool

    SECTION("an unstartable tool still lets /etc/exports be read") {
        FakeRun both;
        both.res.termination_reason = TerminationReason::spawn_error;
        both.files[kExports] = ok("/srv/pub *(rw)\n");
        l = both.run();
        CHECK(l.status == StatusState::constrained);
        CHECK(has(l, "source|exports|read|1"));
        CHECK(has(l, "source|sharing|failed|-"));
        CHECK(count_prefix(l, "share|nfs|") == 1);
    }

    for (auto reason : {TerminationReason::deadline, TerminationReason::cancelled,
                        TerminationReason::signaled, TerminationReason::line_limit}) {
        FakeRun f;
        f.res.tool_ran = true;
        f.res.termination_reason = reason;
        l = f.run();
        CHECK(l.status == StatusState::constrained);
        CHECK(reason_has(l, "subprocess_runner:"));
        CHECK(has(l, "source|sharing|failed|-"));
        CHECK(has(l, "source|exports|absent|-"));
    }
}

TEST_CASE("shares macos: row cap and oversized field are reported", "[shares]") {
    auto f = exited(0, kSharingJson);
    std::string exp = "/" + std::string(10000, 'p') + " -ro\n"; // first, so the cap cannot hide it
    for (int i = 0; i < 600; ++i)
        exp += "/e" + std::to_string(i) + " -ro\n";
    f.files[kExports] = ok(exp);
    const auto l = f.run();
    CHECK(l.status == StatusState::constrained);
    CHECK(count_prefix(l, "share|") == 512);
    CHECK(reason_has(l, "macos:shares:row_cap"));
    CHECK(reason_has(l, "macos:shares:field_oversized"));
    CHECK(count_prefix(l, "source|exports|") == 1);
    CHECK(count_prefix(l, "source|sharing|") == 1);
}

TEST_CASE("shares macos: exit, truncation and unrecognised output", "[shares]") {
    auto nz = exited(1, "");
    auto l = nz.run();
    CHECK(l.status == StatusState::constrained);
    CHECK(reason_has(l, "macos:shares:sharing:exit_nonzero"));
    CHECK(has(l, "source|sharing|failed|-"));

    auto tr = exited(0, "{}");
    tr.res.output_truncated = true;
    l = tr.run();
    CHECK(reason_has(l, "macos:shares:sharing:output_truncated"));
    CHECK(has(l, "source|sharing|failed|-"));

    auto junk = exited(0, "List of Share Points\n");
    l = junk.run();
    CHECK(reason_has(l, "macos:shares:sharing:unrecognised_output"));
    CHECK(has(l, "source|sharing|failed|-"));
    CHECK(count_prefix(l, "share|") == 0);
}

TEST_CASE("shares macos: empty list, real capture and a malformed record", "[shares]") {
    auto empty = exited(0, "{}");
    auto l = empty.run();
    CHECK(l.status == StatusState::supported);
    CHECK(has(l, "source|sharing|read|0"));
    CHECK(has(l, "source|exports|absent|-"));
    CHECK(count_prefix(l, "share|") == 0);

    auto real = exited(0, kSharingJson);
    l = real.run();
    CHECK(l.status == StatusState::supported);
    CHECK(has(l, "source|sharing|read|1"));
    CHECK(has(l, "share|smb|Shared Folder|/Users/jsmith/Public|rw|true|-|sharing"));

    auto bad = exited(0, R"({"bad":{},"good":{"path":"/g"}})");
    l = bad.run();
    CHECK(l.status == StatusState::constrained);
    CHECK(reason_has(l, "macos:shares:sharing:malformed_records:1"));
    CHECK(has(l, "source|sharing|read|1")); // the valid sibling is still emitted
}

TEST_CASE("shares macos: /etc/exports states ride alongside the sharing row", "[shares]") {
    auto read = exited(0, "{}");
    read.files[kExports] = ok("/Users -alldirs -network 2.29.96.0 -mask 255.255.255.0\n");
    auto l = read.run();
    CHECK(l.status == StatusState::supported);
    CHECK(has(l, "source|exports|read|1"));
    CHECK(has(l, "share|nfs|-|/Users|rw|false|clients_1|exports"));

    auto zero = exited(0, "{}");
    zero.files[kExports] = ok("# nothing\n");
    l = zero.run();
    CHECK(has(l, "source|exports|read|0"));
    CHECK(has(l, "source|sharing|read|0"));

    auto denied = exited(0, kSharingJson);
    denied.files[kExports] = io(EACCES);
    l = denied.run();
    CHECK(l.status == StatusState::constrained); // sharing was read
    CHECK(reason_has(l, "macos:shares:exports:permission_denied"));
    CHECK(has(l, "source|exports|refused|-"));

    auto only = exited(1, "");
    only.files[kExports] = io(EACCES);
    l = only.run();
    CHECK(l.status == StatusState::permission_denied); // refused, and nothing was read
    CHECK(reason_has(l, "macos:shares:sharing:exit_nonzero"));

    auto failed = exited(0, "{}");
    failed.files[kExports] = kind(ReadErr::symlink_refused);
    l = failed.run();
    CHECK(reason_has(l, "macos:shares:exports:symlink_refused"));
    CHECK(has(l, "source|exports|failed|-"));
}
