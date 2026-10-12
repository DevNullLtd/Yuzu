/**
 * test_shares_legs.cpp -- fault tests for the OS-free `list_linux`: every boundary is a
 * canned fake (no disk, no uid dependence).
 *
 * Provenance: every specimen is a RECONSTRUCTION built from the documented layouts.
 */
#include <catch2/catch_test_macros.hpp>

#include "shares_legs.hpp"

#include <algorithm>
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
