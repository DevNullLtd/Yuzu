/**
 * test_shares_legs.cpp -- fault tests for the OS-free `list_linux` and `list_windows`: every
 * boundary is a canned fake (no disk, no uid dependence, no Windows API).
 *
 * Provenance: every specimen is a RECONSTRUCTION built from the documented layouts (the
 * Windows pages from the SHARE_INFO_1/2 and STYPE_* documentation). The native capture
 * agents/plugins/shares/docs/samples/windows.txt (kingsley, LocalSystem, 2026-10-27) has the
 * same row shapes: kind and special flags, '-' for the IPC$ path, backslash paths folded to '/'.
 * The SDK side is pinned by shares_win.cpp's static_asserts and the tripwire case below.
 */
#include <catch2/catch_test_macros.hpp>

#include "shares_legs.hpp"

#include <algorithm>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

using namespace yuzu::shares;

namespace {

constexpr const char* kExports = "/etc/exports";
constexpr const char* kSmb = "/etc/samba/smb.conf";
constexpr const char* kUsershares = "/var/lib/samba/usershares";

FileReadLike ok(std::string text) { return {std::move(text), ReadErr::none, 0}; }
FileReadLike io(int err) { return {{}, ReadErr::io, err}; }
FileReadLike kind(ReadErr e) { return {{}, e, 0}; }

/// Canned Linux boundaries; an unlisted path reads as ENOENT and every path asked for is
/// recorded.
struct FakeFs {
    std::map<std::string, FileReadLike> files;
    int list_err = ENOENT;
    std::vector<std::string> names;
    bool too_many = false;
    std::map<std::string, FileReadLike> snippets;
    std::map<std::string, int> dirs; ///< probe result per path (0 = a directory); default ENOENT
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
        fs.dir_probe = [this](const std::string& p) {
            dir_probes.push_back(p);
            const auto it = dirs.find(p);
            return it == dirs.end() ? ENOENT : it->second;
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

    FakeFs cfg; // configured in the file: a token, and the directory is never probed
    cfg.files[kSmb] = ok("[global]\nusershare path = /srv/us\n");
    CHECK(reason_has(cfg.run(), "linux:shares:smb_conf:usershares_not_read"));
    CHECK(cfg.dir_probes.empty());

    FakeFs absent; // no smb.conf: the usershares directory is not probed
    absent.dirs[kUsershares] = 0;
    absent.run();
    CHECK(absent.dir_probes.empty());
}

TEST_CASE("shares linux: usershares probe is tri-state and honours an explicit disable",
          "[shares]") {
    // The directory alone is evidence (a Debian build's compiled-in default is invisible).
    FakeFs dir;
    dir.files[kSmb] = ok("[a]\npath=/a\n");
    dir.dirs[kUsershares] = 0;
    auto l = dir.run();
    CHECK(reason_has(l, "linux:shares:smb_conf:usershares_not_read"));
    CHECK(dir.dir_probes == std::vector<std::string>{kUsershares}); // the default dir only

    FakeFs off; // `usershare max shares = 0` disables them: no token and no probe at all
    off.files[kSmb] = ok("[global]\nusershare max shares = 0\n");
    off.dirs[kUsershares] = 0;
    l = off.run();
    CHECK(l.status == StatusState::supported);
    CHECK(l.reason.empty());
    CHECK(off.dir_probes.empty());

    for (const int absent_err : {ENOENT, ENOTDIR}) { // not a directory (a symlink) is absent
        FakeFs none;
        none.files[kSmb] = ok("[a]\npath=/a\n");
        none.dirs[kUsershares] = absent_err;
        l = none.run();
        CHECK(l.status == StatusState::supported);
        CHECK(l.reason.empty());
    }

    FakeFs denied; // could not tell: constrained and named, never read as absent
    denied.files[kSmb] = ok("[a]\npath=/a\n");
    denied.dirs[kUsershares] = EACCES;
    l = denied.run();
    CHECK(l.status == StatusState::constrained);
    CHECK(reason_has(l, "linux:shares:smb_conf:usershares_unreadable"));
    CHECK_FALSE(reason_has(l, "usershares_not_read"));

    FakeFs io_err; // any errno other than ENOENT/ENOTDIR
    io_err.files[kSmb] = ok("[a]\npath=/a\n");
    io_err.dirs[kUsershares] = EIO;
    CHECK(reason_has(io_err.run(), "linux:shares:smb_conf:usershares_unreadable"));
}

TEST_CASE("shares linux: smb.conf preamble and config file redirect", "[shares]") {
    FakeFs reg; // lines before the first header are [global], as in Samba
    reg.files[kSmb] = ok("config backend = registry\n");
    CHECK(reason_has(reg.run(), "linux:shares:smb_conf:registry_backend"));

    FakeFs redirect;
    redirect.files[kSmb] = ok("[global]\nconfig file = /etc/samba/%m.conf\n");
    CHECK(reason_has(redirect.run(), "linux:shares:smb_conf:include_unresolved"));
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

// ---------------------------------------------------------------------------
// list_windows -- RECONSTRUCTED NetShareEnum pages (SHARE_INFO_2 / SHARE_INFO_1 layouts)
// ---------------------------------------------------------------------------

namespace {

WinShareRec rec(std::string name, std::string path, std::uint32_t type = 0) {
    return WinShareRec{std::move(name), std::move(path), type};
}

/// A drain that asks for more pages than this has not terminated: fail the test instead of
/// letting a loop-exit regression spin the shard until its timeout.
constexpr std::size_t kMaxPagerCalls = 64;

/// Canned pager: per level, pages served in order; the last page repeats if asked again.
/// Every call's level is recorded.
struct FakeWinPages {
    std::map<int, std::vector<WinPage>> pages;
    std::map<int, std::size_t> next;
    std::vector<int> calls;

    WinPageFn fn() {
        return [this](int level) {
            calls.push_back(level);
            if (calls.size() > kMaxPagerCalls)
                FAIL("the pager was asked for more than " << kMaxPagerCalls
                                                           << " pages: the drain does not terminate");
            auto& v = pages[level];
            if (v.empty())
                return WinPage{};
            auto& i = next[level];
            const WinPage& p = v[std::min(i, v.size() - 1)];
            ++i;
            return p;
        };
    }
    Listing run() { return list_windows(fn()); }
    std::size_t calls_at(int level) const {
        return static_cast<std::size_t>(std::ranges::count(calls, level));
    }
};

/// `total` is NetShareEnum's totalentries for the call; list_windows reads it from the first page
/// of a multi-page drain only.
WinPage page_of(std::uint32_t status, std::vector<WinShareRec> shares = {},
                std::uint32_t total = 0) {
    return WinPage{status, std::move(shares), total};
}

std::vector<WinShareRec> disks(const std::string& prefix, std::size_t n) {
    std::vector<WinShareRec> v;
    for (std::size_t i = 0; i < n; ++i)
        v.push_back(rec(prefix + std::to_string(i), "C:/d" + std::to_string(i)));
    return v;
}

} // namespace

TEST_CASE("shares windows: one page of every kind is typed and special is flagged not hidden",
          "[shares]") {
    FakeWinPages f;
    // NetShareEnum returns backslash paths; the row grammar folds them to '/'. 3 is STYPE_IPC.
    f.pages[2] = {page_of(0, {rec("C$", "C:\\", kStypeSpecial), rec("ADMIN$", "C:\\Windows", kStypeSpecial),
                              rec("IPC$", "", kStypeSpecial | 3u), rec("Users", "C:\\Users", 0),
                              rec("HP", "", 1), rec("COM1", "", 2), rec("tmp", "C:\\t", kStypeTemporary),
                              rec("exfil$", "D:\\exfil", 0)})};
    const auto l = f.run();
    CHECK(l.status == StatusState::supported);
    CHECK(l.reason.empty());
    REQUIRE(l.rows.size() == 9);
    CHECK(l.rows[0] == "source|netshareenum|read|8");
    CHECK(l.rows[1] == "share|smb|C$|C:/|-|-|disk,special|netshareenum");
    CHECK(l.rows[2] == "share|smb|ADMIN$|C:/Windows|-|-|disk,special|netshareenum");
    CHECK(l.rows[3] == "share|smb|IPC$|-|-|-|ipc,special|netshareenum");
    CHECK(l.rows[4] == "share|smb|Users|C:/Users|-|-|disk|netshareenum");
    CHECK(l.rows[5] == "share|smb|HP|-|-|-|print|netshareenum");
    CHECK(l.rows[6] == "share|smb|COM1|-|-|-|device|netshareenum");
    CHECK(l.rows[7] == "share|smb|tmp|C:/t|-|-|disk,temporary|netshareenum");
    // A trailing '$' on a share that is not STYPE_SPECIAL is the browse-hiding convention.
    CHECK(l.rows[8] == "share|smb|exfil$|D:/exfil|-|-|disk,hidden|netshareenum");
    CHECK(f.calls == std::vector<int>{2});
}

TEST_CASE("shares windows: an unknown kind is other and the temporary bit alone is disk then "
          "temporary",
          "[shares]") {
    FakeWinPages f;
    f.pages[2] = {page_of(0, {rec("x", "C:/x", 7), rec("t", "C:/t", kStypeTemporary),
                              rec("h$", "C:/h", 2u | kStypeTemporary)})};
    const auto l = f.run();
    CHECK(has(l, "share|smb|x|C:/x|-|-|other|netshareenum"));
    CHECK(has(l, "share|smb|t|C:/t|-|-|disk,temporary|netshareenum"));
    // kind, then hidden, then temporary
    CHECK(has(l, "share|smb|h$|C:/h|-|-|device,hidden,temporary|netshareenum"));
}

TEST_CASE("shares windows: an advancing pager is drained in page order", "[shares]") {
    FakeWinPages f;
    f.pages[2] = {page_of(kWinMoreData, disks("a", 2), 6), page_of(kWinMoreData, disks("b", 2), 6),
                  page_of(0, disks("c", 2), 6)};
    const auto l = f.run();
    CHECK(l.status == StatusState::supported);
    CHECK(l.reason.empty());
    CHECK(count_prefix(l, "share|") == 6);
    CHECK(has(l, "source|netshareenum|read|6"));
    CHECK(l.rows[1].starts_with("share|smb|a0|"));
    CHECK(l.rows[6].starts_with("share|smb|c1|"));
    CHECK(f.calls_at(2) == 3);
}

TEST_CASE("shares windows: a terminal page that keeps nothing ends the drain cleanly, not as "
          "no_progress",
          "[shares]") {
    // The status==0 check must precede the kept==0 check: an empty last page, or one that only
    // repeats a name already seen, is the end of a clean drain and every earlier row survives.
    FakeWinPages f;
    f.pages[2] = {page_of(kWinMoreData, disks("a", 2), 2), page_of(0, {}, 2)};
    FakeWinPages g;
    g.pages[2] = {page_of(kWinMoreData, disks("a", 2), 2), page_of(0, disks("a", 1), 2)};
    for (auto* p : {&f, &g}) {
        const auto l = p->run();
        CHECK(l.status == StatusState::supported);
        CHECK(l.reason.empty());
        CHECK_FALSE(reason_has(l, "no_progress"));
        CHECK_FALSE(reason_has(l, "inconsistent_drain"));
        CHECK(count_prefix(l, "share|") == 2);
        CHECK(has(l, "source|netshareenum|read|2"));
        CHECK(p->calls_at(2) == 2);
    }
}

TEST_CASE("shares windows: a stalled pager is no_progress and reports no rows", "[shares]") {
    FakeWinPages f;
    f.pages[2] = {page_of(kWinMoreData, disks("a", 2)), page_of(kWinMoreData)};
    const auto l = f.run();
    CHECK(l.status == StatusState::constrained);
    CHECK(reason_has(l, "windows:shares:netshareenum:no_progress"));
    CHECK(l.rows == std::vector<std::string>{"source|netshareenum|failed|-"});
}

TEST_CASE("shares windows: a cyclic pager is no_progress on its second page and reports no rows",
          "[shares]") {
    FakeWinPages f;
    f.pages[2] = {page_of(kWinMoreData, disks("c", 100))}; // the same page, forever
    const auto l = f.run();
    CHECK(l.status == StatusState::constrained);
    CHECK(reason_has(l, "windows:shares:netshareenum:no_progress"));
    CHECK(l.rows == std::vector<std::string>{"source|netshareenum|failed|-"});
    CHECK(f.calls_at(2) == 2); // the repeat kept nothing new, so no third page was asked for
}

TEST_CASE("shares windows: a share returned twice is kept once and costs no budget", "[shares]") {
    FakeWinPages f;
    // Cursor drift repeats a share (names compare without regard to ASCII case).
    f.pages[2] = {page_of(kWinMoreData, {rec("a", "C:/a"), rec("b", "C:/b"), rec("c", "C:/c")}, 5),
                  page_of(0, {rec("B", "C:/other"), rec("c", "C:/c"), rec("d", "C:/d"), rec("e", "C:/e")}, 5)};
    const auto l = f.run();
    CHECK(l.status == StatusState::supported);
    CHECK(l.reason.empty());
    CHECK(count_prefix(l, "share|") == 5);
    CHECK(has(l, "source|netshareenum|read|5"));
    CHECK(has(l, "share|smb|b|C:/b|-|-|disk|netshareenum")); // the first occurrence wins
    CHECK_FALSE(has(l, "share|smb|B|C:/other|-|-|disk|netshareenum"));

    // 400 distinct names, then a page that repeats all 400 and adds 112: 512 distinct fit the row
    // cap exactly only if the 400 repeats were not charged.
    FakeWinPages g;
    g.pages[2] = {page_of(kWinMoreData, disks("d", 400), 512), page_of(0, [] {
                      auto v = disks("d", 400);
                      auto n = disks("n", 112);
                      v.insert(v.end(), n.begin(), n.end());
                      return v;
                  }(), 512)};
    const auto o = g.run();
    CHECK(count_prefix(o, "share|") == kMaxShareRows);
    CHECK(o.status == StatusState::supported);
    CHECK_FALSE(reason_has(o, "windows:shares:row_cap"));
}

TEST_CASE("shares windows: a multi-page drain whose count differs from the first page's total is "
          "inconsistent_drain with the rows kept",
          "[shares]") {
    // A share created while paging: 4 read, 3 announced.
    FakeWinPages f;
    f.pages[2] = {page_of(kWinMoreData, disks("a", 2), 3), page_of(0, disks("b", 2), 4)};
    const auto l = f.run();
    CHECK(l.status == StatusState::constrained);
    CHECK(reason_has(l, "windows:shares:netshareenum:inconsistent_drain"));
    CHECK(count_prefix(l, "share|") == 4);
    CHECK(has(l, "source|netshareenum|read|4"));

    // A share deleted while paging: 4 read, 5 announced.
    FakeWinPages g;
    g.pages[2] = {page_of(kWinMoreData, disks("a", 2), 5), page_of(0, disks("b", 2), 4)};
    const auto o = g.run();
    CHECK(o.status == StatusState::constrained);
    CHECK(reason_has(o, "windows:shares:netshareenum:inconsistent_drain"));
    CHECK(count_prefix(o, "share|") == 4);

    // A single page is read == total trivially and is never judged against it.
    FakeWinPages h;
    h.pages[2] = {page_of(0, disks("a", 2), 7)};
    const auto s1 = h.run();
    CHECK(s1.status == StatusState::supported);
    CHECK_FALSE(reason_has(s1, "inconsistent_drain"));
}

TEST_CASE("shares windows: one budget spans every page and refusal stops fetching", "[shares]") {
    FakeWinPages f;
    for (int i = 0; i < 6; ++i)
        f.pages[2].push_back(page_of(kWinMoreData, disks("p" + std::to_string(i) + "_", 100)));
    const auto l = f.run();
    CHECK(count_prefix(l, "share|") == kMaxShareRows);
    CHECK(reason_has(l, "windows:shares:row_cap"));
    CHECK(has(l, "source|netshareenum|read|512"));
    CHECK_FALSE(reason_has(l, "inconsistent_drain")); // a truncated drain is row_cap, not drift
    CHECK(f.calls_at(2) == 6); // page 7 was never asked for

    FakeWinPages g;
    g.pages[2] = {page_of(0, {rec(std::string(5000, 'n'), "C:/x")})};
    const auto o = g.run();
    CHECK(reason_has(o, "windows:shares:field_oversized"));
    REQUIRE(o.rows.size() == 2);
    CHECK(o.rows[1].size() < 4200);
}

TEST_CASE("shares windows: the byte budget cuts the listing before the row cap at the first "
          "refusal",
          "[shares]") {
    // Large entries exhaust 1 MiB long before 512 rows. Name, path, flags and the fixed per-row
    // overhead are all charged ("disk" plus its separator is 5 flag bytes), and a small entry
    // behind the refused one is never looked at.
    const std::size_t per_row = 4000 + 4000 + 5 + kRowOverhead;
    const std::size_t fit = kMaxShareBytes / per_row;
    REQUIRE(fit < kMaxShareRows);
    std::vector<WinShareRec> big;
    for (std::size_t i = 0; i <= fit + 10; ++i) {
        std::string name = "L" + std::to_string(i);
        name.resize(4000, 'n');
        big.push_back(rec(std::move(name), std::string(4000, 'p')));
    }
    big.push_back(rec("small", "C:/s"));
    FakeWinPages f;
    f.pages[2] = {page_of(0, std::move(big))};
    const auto l = f.run();
    CHECK(l.status == StatusState::constrained);
    CHECK(reason_has(l, "windows:shares:row_cap"));
    CHECK_FALSE(reason_has(l, "windows:shares:field_oversized")); // 4000 bytes is under the cut
    CHECK(count_prefix(l, "share|") == fit);
    CHECK(has(l, "source|netshareenum|read|" + std::to_string(fit)));
    CHECK(count_prefix(l, "share|smb|small|") == 0);
}

TEST_CASE("shares windows: the level-1 fallback does not inherit level-2 state", "[shares]") {
    // An oversized name read at level 2 is discarded with its page: the level-1 answer is judged
    // on its own rows, so it carries no field_oversized, and the names the discarded level-2 rows
    // used are free to appear again.
    FakeWinPages f;
    f.pages[2] = {page_of(kWinMoreData, {rec(std::string(5000, 'n'), "C:/x"), rec("Users", "C:/u")}, 800),
                  page_of(kWinAccessDenied)};
    f.pages[1] = {page_of(0, {rec("Users", ""), rec("Data", "")})};
    const auto l = f.run();
    CHECK(f.calls == std::vector<int>{2, 2, 1});
    CHECK(l.status == StatusState::constrained);
    CHECK(reason_has(l, "windows:shares:netshareenum:level2_permission_denied"));
    CHECK_FALSE(reason_has(l, "windows:shares:field_oversized"));
    CHECK(has(l, "source|netshareenum|read|2"));
    CHECK(has(l, "share|smb|Users|-|-|-|disk|netshareenum"));

    // A multi-page level-1 drain is judged against ITS first page's total, not level 2's (800).
    FakeWinPages g;
    g.pages[2] = {page_of(kWinMoreData, disks("a", 2), 800), page_of(kWinAccessDenied)};
    g.pages[1] = {page_of(kWinMoreData, {rec("a0", ""), rec("a1", "")}, 3), page_of(0, {rec("a2", "")}, 3)};
    const auto o = g.run();
    CHECK(o.status == StatusState::constrained);
    CHECK_FALSE(reason_has(o, "inconsistent_drain"));
    CHECK(has(o, "source|netshareenum|read|3"));
}

TEST_CASE("shares windows: a failing later page discards every earlier row", "[shares]") {
    FakeWinPages f;
    f.pages[2] = {page_of(kWinMoreData, disks("a", 3)), page_of(8)};
    const auto l = f.run();
    CHECK(l.status == StatusState::constrained);
    CHECK(reason_has(l, "windows:shares:netshareenum:status_8"));
    CHECK(l.rows == std::vector<std::string>{"source|netshareenum|failed|-"});
}

TEST_CASE("shares windows: level 2 refused falls back to level 1 names without paths", "[shares]") {
    FakeWinPages f;
    f.pages[2] = {page_of(kWinAccessDenied)};
    f.pages[1] = {page_of(0, {rec("Users", "", 0), rec("IPC$", "", kStypeSpecial | 3u)})};
    const auto l = f.run();
    CHECK(f.calls == std::vector<int>{2, 1});
    CHECK(l.status == StatusState::constrained);
    CHECK(reason_has(l, "windows:shares:netshareenum:level2_permission_denied"));
    CHECK(has(l, "source|netshareenum|read|2"));
    CHECK(has(l, "share|smb|Users|-|-|-|disk|netshareenum"));
    CHECK(has(l, "share|smb|IPC$|-|-|-|ipc,special|netshareenum"));
}

TEST_CASE("shares windows: the level-1 fallback that then fails reports no shares and both tokens",
          "[shares]") {
    // The fallback token says the retry was attempted, not that it succeeded: a level-1 drain
    // that fails leaves ONE failed source row (two wire rows with the status row) and no share.
    for (const std::uint32_t st : {8u, kWinMoreData}) { // status_8 / no_progress (empty page)
        FakeWinPages f;
        f.pages[2] = {page_of(kWinAccessDenied)};
        f.pages[1] = {page_of(st)};
        const auto l = f.run();
        INFO("level-1 status " << st);
        CHECK(f.calls == std::vector<int>{2, 1});
        CHECK(l.status == StatusState::constrained);
        CHECK(reason_has(l, "windows:shares:netshareenum:level2_permission_denied"));
        CHECK(reason_has(l, st == 8u ? "windows:shares:netshareenum:status_8"
                                     : "windows:shares:netshareenum:no_progress"));
        CHECK(l.rows == std::vector<std::string>{"source|netshareenum|failed|-"});
    }
}

TEST_CASE("shares windows: the level-1 fallback that answers empty is read|0 and still constrained",
          "[shares]") {
    FakeWinPages f;
    f.pages[2] = {page_of(kWinAccessDenied)};
    f.pages[1] = {page_of(0)};
    const auto l = f.run();
    CHECK(f.calls == std::vector<int>{2, 1});
    CHECK(l.status == StatusState::constrained);
    CHECK(reason_has(l, "windows:shares:netshareenum:level2_permission_denied"));
    CHECK(l.rows == std::vector<std::string>{"source|netshareenum|read|0"});
}

TEST_CASE("shares windows: the fallback restarts the budget and drops level-2 rows", "[shares]") {
    FakeWinPages f;
    f.pages[2] = {page_of(kWinMoreData, disks("a", 400)), page_of(kWinAccessDenied)}; // denied after rows were gathered
    f.pages[1] = {page_of(0, disks("a", 400))}; // the same names: the discarded rows are forgotten
    const auto l = f.run();
    CHECK(count_prefix(l, "share|") == 400);
    CHECK_FALSE(reason_has(l, "windows:shares:row_cap"));
    CHECK(has(l, "source|netshareenum|read|400"));
    REQUIRE(l.rows.size() > 1);
    CHECK(l.rows[1].starts_with("share|smb|a0|"));
}

TEST_CASE("shares windows: refused at both levels is permission_denied", "[shares]") {
    FakeWinPages f;
    f.pages[2] = {page_of(kWinAccessDenied)};
    f.pages[1] = {page_of(kWinAccessDenied)};
    const auto l = f.run();
    CHECK(l.status == StatusState::permission_denied);
    CHECK(l.reason == "windows:shares:netshareenum:permission_denied");
    CHECK(l.rows == std::vector<std::string>{"source|netshareenum|refused|-"});
}

TEST_CASE("shares windows: a stopped Server service is typed unsupported and level 1 is not tried",
          "[shares]") {
    for (const std::uint32_t st : {kNerrServerNotStarted, kRpcServerUnavailable, kRpcUnknownIf}) {
        FakeWinPages f;
        f.pages[2] = {page_of(st)};
        const auto l = f.run();
        INFO("status " << st);
        CHECK(l.status == StatusState::unsupported);
        CHECK(l.reason == (st == kNerrServerNotStarted ? "windows:shares:netshareenum:server_not_started"
                                       : "windows:shares:netshareenum:server_unavailable"));
        CHECK(l.rows == std::vector<std::string>{"source|netshareenum|failed|-"});
        CHECK(f.calls == std::vector<int>{2});
    }
}

TEST_CASE("shares windows: hostile bytes in a name stay inside one escaped field", "[shares]") {
    FakeWinPages f;
    f.pages[2] = {page_of(0, {rec(std::string("a|b\xff") + "c", "C:/x")})};
    const auto l = f.run();
    REQUIRE(l.rows.size() == 2);
    std::size_t pipes = 0;
    for (std::size_t i = 0; i < l.rows[1].size(); ++i)
        if (l.rows[1][i] == '|' && l.rows[1][i - 1] != '\\')
            ++pipes;
    CHECK(pipes == 7);
    CHECK(l.rows[1].find('\xff') == std::string::npos);
}

TEST_CASE("shares windows: the shell's SDK constants are pinned (portable tripwire)", "[shares]") {
    CHECK(kStypeSpecial == 0x80000000u);
    CHECK(kStypeTemporary == 0x40000000u);
    CHECK(kStypeMask == 0xFFu);
    CHECK(kWinAccessDenied == 5);
    CHECK(kWinMoreData == 234);
    CHECK(kNerrServerNotStarted == 2114);
    CHECK(kRpcServerUnavailable == 1722);
    CHECK(kRpcUnknownIf == 1717);
}
