/**
 * test_installed_apps_pkgdb.cpp -- the installed_apps Linux package-database shell
 * (installed_apps_pkgdb_read.hpp) and the record mapping it feeds (SAM-45).
 *
 * What this pins, case by case:
 *   - ROW-SET PARITY: for every fixture directory the rows the in-process readers produce equal,
 *     as a sorted set, the rows the OLD path produced from the capture's own `dpkg-query` / `rpm
 *     -qa` output (inventory.tsv and list.txt, interpreted by the old line parsers, kept verbatim
 *     in installed_apps_old_path_oracle.hpp). That is the PR's "no row, wire or hash changes"
 *     claim, measured.
 *   - the sqlite leg through a REAL connection, the format detection order, the no-follow
 *     refusals, the limits, the status.d directory, and the degraded contract.
 *
 * Fixture provenance: tests/unit/fixtures/software-estate/pkgdb/provenance.txt. "Real" means taken
 * from the S-7 captures, or from the debian12-statusd capture of a real status.d; every hostile or
 * edited input is built in memory or in a yuzu_test_ temporary directory from real fixture bytes and
 * says so. No test spawns a process, sleeps or touches the network; the sqlite cases copy the
 * fixture into a TempDir first so no sidecar is ever created in the source tree.
 *
 * YUZU_TEST_PKGDB_FIXTURE_ROOT replaces the fixture root so the SAME parity case runs over the
 * full, untrimmed S-7 captures: a tree of <capture>/{status|rpmdb.sqlite|Packages.db|Packages} +
 * inventory.tsv + list.txt in the old formats. It then prints one package count per capture.
 *
 * The bounded form (read_host_packages_bounded) is exercised through an injected reader: a reader parked on
 * a latch stands in for a wedged volume, so no timing is assumed beyond "a reader that never returns is
 * given up on at the wall". The Linux-only plugin wiring around it (the tracked-call guard, the shutdown
 * quiesce) is pinned by tests/test_installed_apps_pkgdb_wiring_lexical.py.
 *
 * POSIX only: the shell compiles out on Windows (the plugin walks the registry there). The cases that
 * HOLD rpm's transaction lock use an open-file-description lock (F_OFD_SETLK) and run on Linux only,
 * the one `#ifdef __linux__` part of this file; the unlocked, symlinked and directory lock-file cases
 * run everywhere. One case (the stamp's ctime variant) reads a kernel timestamp: its comment says why.
 */

#ifndef _WIN32

#include <catch2/catch_test_macros.hpp>

#include "installed_apps_inventory.hpp"
#include "installed_apps_old_path_oracle.hpp"
#include "installed_apps_parsers.hpp"
#include "installed_apps_pkgdb_read.hpp"
#include "test_helpers.hpp"

#include <sqlite3.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iterator>
#include <memory>
#include <mutex>
#include <new>
#include <optional>
#include <set>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace fs = std::filesystem;
namespace pkgdb = yuzu::installed_apps::pkgdb;
namespace inv = yuzu::installed_apps::inventory;
namespace parsers = yuzu::installed_apps::parsers;
using yuzu::shared::DpkgPackage;
using yuzu::shared::RpmPackage;
using Eco = pkgdb::HostPackages::Ecosystem;

namespace {

fs::path default_fixture_root() {
    return fs::path{YUZU_TEST_FIXTURE_DIR} / "software-estate" / "pkgdb";
}

fs::path fixture_root(bool* overridden = nullptr) {
    if (const char* env = std::getenv("YUZU_TEST_PKGDB_FIXTURE_ROOT"); env != nullptr && *env != '\0') {
        if (overridden)
            *overridden = true;
        return fs::path{env};
    }
    if (overridden)
        *overridden = false;
    return default_fixture_root();
}

std::string read_text(const fs::path& p) {
    std::ifstream f(p, std::ios::binary);
    REQUIRE(f.is_open());
    return std::string(std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>());
}

std::tm utc_tm(std::int64_t t) {
    std::tm out{};
    const std::time_t tt = static_cast<std::time_t>(t);
    gmtime_r(&tt, &out);
    return out;
}

// A scratch filesystem root under a yuzu_test_ temp dir (the Defender-exclusion prefix).
struct Root {
    yuzu::test::TempDir dir{"yuzu_test_pkgdb_"};
    Root() { fs::create_directories(dir.path); }
    [[nodiscard]] fs::path at(std::string_view rel) const { return dir.path / std::string{rel}; }
    [[nodiscard]] std::string str() const { return dir.path.string(); }
    fs::path put(std::string_view rel, const fs::path& src) const {
        fs::create_directories(at(rel).parent_path());
        fs::copy_file(src, at(rel), fs::copy_options::overwrite_existing);
        return at(rel);
    }
    fs::path put_text(std::string_view rel, const std::string& text) const {
        fs::create_directories(at(rel).parent_path());
        std::ofstream f(at(rel), std::ios::binary);
        f << text;
        return at(rel);
    }
};

// A sqlite handle that is closed even when a REQUIRE below throws (a raw handle would leak, and on a
// rollback-journal copy keep its lock for the rest of the run).
using SqliteDb = std::unique_ptr<sqlite3, pkgdb::detail::SqliteCloser>;
using SqliteStmt = std::unique_ptr<sqlite3_stmt, pkgdb::detail::StmtFinalizer>;

SqliteDb open_sqlite(const fs::path& path) {
    sqlite3* raw = nullptr;
    const int rc = sqlite3_open(path.string().c_str(), &raw);
    SqliteDb db{raw}; // owns the handle even on a failed open
    REQUIRE(rc == SQLITE_OK);
    return db;
}

void exec_sql(sqlite3* db, const char* sql) {
    char* err = nullptr;
    const int rc = sqlite3_exec(db, sql, nullptr, nullptr, &err);
    INFO(sql << " -> " << (err ? err : "ok"));
    sqlite3_free(err);
    REQUIRE(rc == SQLITE_OK);
}

// EDITED copy: switched from WAL to the rollback journal, the mode in which a reader takes a SHARED
// lock (exactly what `rpm -qa` took). A WAL-mode copy is never locked this way.
void switch_to_rollback_journal(const fs::path& db_path) {
    const auto db = open_sqlite(db_path);
    exec_sql(db.get(), "PRAGMA journal_mode=DELETE");
}

// The kind of database a fixture directory holds, by which file is in it.
struct DbFile {
    std::string name;     // status | rpmdb.sqlite | Packages.db | Packages
    std::string rel_dir;  // where it lives in a scratch root
    bool dpkg = false;
};
std::optional<DbFile> db_file_of(const fs::path& capture_dir) {
    if (fs::exists(capture_dir / "status"))
        return DbFile{"status", "var/lib/dpkg", true};
    if (fs::exists(capture_dir / "rpmdb.sqlite"))
        return DbFile{"rpmdb.sqlite", "var/lib/rpm", false};
    if (fs::exists(capture_dir / "Packages.db"))
        return DbFile{"Packages.db", "usr/lib/sysimage/rpm", false};
    if (fs::exists(capture_dir / "Packages"))
        return DbFile{"Packages", "var/lib/rpm", false};
    return std::nullopt;
}

pkgdb::Limits default_limits() { return pkgdb::Limits{}; }

pkgdb::HostPackages read_root(const Root& root, const pkgdb::Limits& lim = default_limits(),
                              std::function<bool()> expired = {}) {
    return pkgdb::read_host_packages(root.str(), lim, expired);
}

// ── new-path rows (in-process readers + mapping) ────────────────────────────

std::vector<std::string> new_inv_rows(const pkgdb::HostPackages& h) {
    std::vector<std::string> out;
    for (const auto& p : h.dpkg)
        if (auto r = inv::inv_record_from_dpkg(p))
            out.push_back(inv::format_inv_row(*r));
    for (const auto& p : h.rpm)
        out.push_back(inv::format_inv_row(inv::inv_record_from_rpm(p, utc_tm)));
    std::sort(out.begin(), out.end());
    return out;
}

std::vector<std::string> new_list_rows(const pkgdb::HostPackages& h) {
    std::vector<std::string> out;
    for (const auto& p : h.dpkg)
        if (auto r = parsers::app_record_from_dpkg(p))
            out.push_back(parsers::format_app_row({r->name, r->version, r->publisher, r->install_date, {}, {}}));
    for (const auto& p : h.rpm) {
        const auto r = parsers::app_record_from_rpm(p, utc_tm);
        out.push_back(parsers::format_app_row({r.name, r.version, r.publisher, r.install_date, {}, {}}));
    }
    std::sort(out.begin(), out.end());
    return out;
}

// ── old-path rows (the verbatim CLI parsers over the capture's own output) ──────

std::vector<std::string> old_inv_rows(const fs::path& capture_dir, bool dpkg) {
    std::vector<std::string> out;
    std::istringstream ss(read_text(capture_dir / "inventory.tsv"));
    std::string line;
    while (std::getline(ss, line)) {
        const auto r = dpkg ? inv::parse_dpkg_inv_line(line) : inv::parse_rpm_inv_line(line);
        if (r)
            out.push_back(inv::format_inv_row(*r));
    }
    std::sort(out.begin(), out.end());
    return out;
}

std::vector<std::string> old_list_rows(const fs::path& capture_dir, bool dpkg) {
    const std::string text = read_text(capture_dir / "list.txt");
    std::vector<std::string> out;
    for (const auto& r : dpkg ? parsers::parse_dpkg_list(text) : parsers::parse_rpm_list(text))
        out.push_back(parsers::format_app_row({r.name, r.version, r.publisher, r.install_date, {}, {}}));
    std::sort(out.begin(), out.end());
    return out;
}

std::set<std::string> names_of(const pkgdb::HostPackages& h) {
    std::set<std::string> out;
    for (const auto& p : h.dpkg)
        out.insert(p.name);
    for (const auto& p : h.rpm)
        out.insert(p.name);
    return out;
}

// A recording stand-in for yuzu::CommandContext (the degraded-acquisition helpers are templated on it).
struct RecCtx {
    std::vector<std::string> lines;
    int status_calls = 0;
    YuzuResultStatus status = YUZU_RESULT_STATUS_UNDECLARED;
    YuzuResultCompleteness completeness = YUZU_RESULT_COMPLETENESS_UNKNOWN;
    std::string provenance;
    void write_output(std::string_view l) { lines.emplace_back(l); }
    void set_result_status(YuzuResultStatus s, YuzuResultCompleteness c, std::string_view p = {}) {
        ++status_calls;
        status = s;
        completeness = c;
        provenance = std::string{p};
    }
};

} // namespace

// ── parity ──────────────────────────────────────────────────────────────────

TEST_CASE("pkgdb: row-set parity with the old path on every fixture directory", "[installed_apps][pkgdb]") {
    bool overridden = false;
    const fs::path root_dir = fixture_root(&overridden);
    REQUIRE(fs::is_directory(root_dir));

    std::vector<fs::path> captures;
    for (const auto& e : fs::directory_iterator(root_dir))
        if (e.is_directory())
            captures.push_back(e.path());
    std::sort(captures.begin(), captures.end());
    REQUIRE_FALSE(captures.empty());

    std::size_t checked = 0;
    for (const auto& dir : captures) {
        const auto db = db_file_of(dir);
        if (!db)
            continue; // a directory without a database is not a capture
        INFO(dir.filename().string());
        Root root;
        root.put(db->rel_dir + "/" + db->name, dir / db->name);

        const auto host = read_root(root);
        REQUIRE(host.failure.empty());
        REQUIRE(host.ecosystem == (db->dpkg ? Eco::dpkg : Eco::rpm));

        const auto old_inv = old_inv_rows(dir, db->dpkg);
        const auto old_list = old_list_rows(dir, db->dpkg);
        const auto got_inv = new_inv_rows(host);
        const auto got_list = new_list_rows(host);
        REQUIRE_FALSE(old_inv.empty());
        CHECK(got_inv == old_inv);
        CHECK(got_list == old_list);
        // The row counts the PR body reports: packages the reader returned, inv rows, list rows.
        if (overridden)
            std::fprintf(stderr, "[pkgdb parity] %-24s packages=%zu inv_rows=%zu list_rows=%zu\n",
                         dir.filename().string().c_str(), host.dpkg.size() + host.rpm.size(),
                         got_inv.size(), got_list.size());
        ++checked;
    }
    // The committed parity fixtures: debian12, ubuntu2404, fedora41, alma9, leap156, tumbleweed, alma8,
    // alma8-s390x. debian12-statusd holds a status.d, not a database file, so it is skipped here.
    if (!overridden)
        CHECK(checked == 8);
    else
        CHECK(checked >= 1);
}

// ── sqlite, through the real connection ─────────────────────────────────────

TEST_CASE("pkgdb sqlite: fedora41 and alma9 read through the real connection, with and without sidecars",
          "[installed_apps][pkgdb]") {
    for (const char* capture : {"fedora41", "alma9"}) {
        INFO(capture);
        const fs::path src = default_fixture_root() / capture;
        const auto expect_names = [&] {
            std::set<std::string> n;
            std::istringstream ss(read_text(src / "inventory.tsv"));
            std::string line;
            while (std::getline(ss, line))
                n.insert(line.substr(0, line.find('\t')));
            return n;
        }();

        SECTION("no sidecars: an unprivileged-style read of a WAL-mode file (immutable)") {
            Root root;
            root.put("var/lib/rpm/rpmdb.sqlite", src / "rpmdb.sqlite");
            const auto host = read_root(root);
            REQUIRE(host.failure.empty());
            CHECK(host.ecosystem == Eco::rpm);
            CHECK(names_of(host) == expect_names);
            // Nothing was created beside the copy: no -wal, -shm or -journal.
            CHECK_FALSE(fs::exists(root.at("var/lib/rpm/rpmdb.sqlite-wal")));
            CHECK_FALSE(fs::exists(root.at("var/lib/rpm/rpmdb.sqlite-shm")));
        }
        SECTION("empty sidecars as rpm leaves them: still every row") {
            Root root;
            root.put("var/lib/rpm/rpmdb.sqlite", src / "rpmdb.sqlite");
            root.put_text("var/lib/rpm/rpmdb.sqlite-wal", "");
            root.put_text("var/lib/rpm/rpmdb.sqlite-shm", std::string(32768, '\0'));
            const auto host = read_root(root);
            REQUIRE(host.failure.empty());
            CHECK(names_of(host) == expect_names);
        }
        SECTION("a live WAL with committed pages: the reader honours it") {
            // EDITED copy: another connection deletes the first package and stays open, so its commit
            // lives only in the -wal. A reader that ignored the WAL would still see every row.
            Root root;
            const fs::path db = root.put("var/lib/rpm/rpmdb.sqlite", src / "rpmdb.sqlite");
            const auto writer = open_sqlite(db);
            sqlite3_wal_autocheckpoint(writer.get(), 0);
            exec_sql(writer.get(), "DELETE FROM Packages WHERE hnum = (SELECT min(hnum) FROM Packages)");
            REQUIRE(fs::file_size(root.at("var/lib/rpm/rpmdb.sqlite-wal")) > 0);
            const auto host = read_root(root);
            REQUIRE(host.failure.empty());
            CHECK(host.rpm.size() + 1 == expect_names.size());
        }
    }
}

TEST_CASE("pkgdb sqlite hostile: not sqlite, no Packages table, wrong column type, limits, clock, lock",
          "[installed_apps][pkgdb]") {
    const fs::path fedora = default_fixture_root() / "fedora41" / "rpmdb.sqlite";
    const auto failure_of = [](const Root& root, pkgdb::Limits lim = default_limits(),
                               std::function<bool()> expired = {}) {
        const auto h = read_root(root, lim, std::move(expired));
        CHECK(h.dpkg.empty());
        CHECK(h.rpm.empty());
        CHECK(h.ecosystem == Eco::none);
        return h.failure;
    };

    SECTION("random bytes are corrupt") {
        Root root;
        std::string noise(8192, '\0');
        std::uint32_t x = 0x9E3779B9u; // a fixed LCG: deterministic "random" bytes
        for (auto& c : noise) {
            x = x * 1664525u + 1013904223u;
            c = static_cast<char>(x >> 24);
        }
        root.put_text("var/lib/rpm/rpmdb.sqlite", noise);
        CHECK(failure_of(root) == "rpm_sqlite:corrupt");
    }
    SECTION("a file shorter than a sqlite header is corrupt") {
        Root root;
        root.put_text("var/lib/rpm/rpmdb.sqlite", "SQLite");
        CHECK(failure_of(root) == "rpm_sqlite:corrupt");
    }
    SECTION("a real sqlite database without a Packages table is corrupt") {
        Root root;
        fs::create_directories(root.at("var/lib/rpm"));
        {
            const auto db = open_sqlite(root.at("var/lib/rpm/rpmdb.sqlite"));
            exec_sql(db.get(), "CREATE TABLE Other(x INTEGER); INSERT INTO Other VALUES (1)");
        }
        CHECK(failure_of(root) == "rpm_sqlite:corrupt");
    }
    SECTION("a Packages row whose blob column is TEXT is corrupt") {
        Root root;
        fs::create_directories(root.at("var/lib/rpm"));
        {
            const auto db = open_sqlite(root.at("var/lib/rpm/rpmdb.sqlite"));
            exec_sql(db.get(), "CREATE TABLE Packages(hnum INTEGER PRIMARY KEY, blob TEXT); "
                               "INSERT INTO Packages(blob) VALUES ('not a header')");
        }
        CHECK(failure_of(root) == "rpm_sqlite:corrupt");
    }
    SECTION("a blob that is not an rpm header is corrupt") {
        Root root;
        fs::create_directories(root.at("var/lib/rpm"));
        {
            const auto db = open_sqlite(root.at("var/lib/rpm/rpmdb.sqlite"));
            exec_sql(db.get(), "CREATE TABLE Packages(hnum INTEGER PRIMARY KEY, blob BLOB); "
                               "INSERT INTO Packages(blob) VALUES (x'00112233445566778899')");
        }
        CHECK(failure_of(root) == "rpm_sqlite:corrupt");
    }
    SECTION("a small length limit is oversized") {
        Root root;
        root.put("var/lib/rpm/rpmdb.sqlite", fedora);
        pkgdb::Limits lim;
        lim.rpm_max_header_bytes = 1000; // every real header is bigger
        CHECK(failure_of(root, lim) == "rpm_sqlite:oversized");
    }
    SECTION("a package cap below the row count is row_cap") {
        Root root;
        root.put("var/lib/rpm/rpmdb.sqlite", fedora);
        pkgdb::Limits lim;
        lim.max_packages = 2;
        CHECK(failure_of(root, lim) == "rpm_sqlite:row_cap");
    }
    SECTION("a byte budget below the headers is byte_cap") {
        Root root;
        root.put("var/lib/rpm/rpmdb.sqlite", fedora);
        pkgdb::Limits lim;
        lim.rpm_max_total_bytes = 5000;
        CHECK(failure_of(root, lim) == "rpm_sqlite:byte_cap");
    }
    SECTION("an expired clock is timeout") {
        Root root;
        root.put("var/lib/rpm/rpmdb.sqlite", fedora);
        CHECK(failure_of(root, default_limits(), [] { return true; }) == "rpm_sqlite:timeout");
    }
    SECTION("a second connection holding BEGIN EXCLUSIVE on a rollback-journal copy is locked") {
        // EDITED copy (switch_to_rollback_journal).
        Root root;
        const fs::path db = root.put("var/lib/rpm/rpmdb.sqlite", fedora);
        switch_to_rollback_journal(db);
        const auto holder = open_sqlite(db);
        exec_sql(holder.get(), "BEGIN EXCLUSIVE");
        pkgdb::Limits lim;
        lim.sqlite_busy_ms = 0;
        const std::string failure = failure_of(root, lim);
        exec_sql(holder.get(), "ROLLBACK");
        CHECK(failure == "rpm_sqlite:locked");
        // Released, the same copy reads cleanly: the rollback-journal path works when nobody holds it.
        const auto ok = read_root(root);
        CHECK(ok.failure.empty());
        CHECK(ok.rpm.size() == 4);
    }
}

// ── detection ───────────────────────────────────────────────────────────────

TEST_CASE("pkgdb detection: dpkg wins over rpm; an empty status falls through to rpm",
          "[installed_apps][pkgdb]") {
    const fs::path debian = default_fixture_root() / "debian12";
    const fs::path fedora = default_fixture_root() / "fedora41";
    Root root;
    root.put("var/lib/dpkg/status", debian / "status");
    root.put("usr/lib/sysimage/rpm/rpmdb.sqlite", fedora / "rpmdb.sqlite");
    {
        const auto h = read_root(root);
        REQUIRE(h.failure.empty());
        CHECK(h.ecosystem == Eco::dpkg);
        CHECK(h.dpkg.size() == 10);
        CHECK(h.rpm.empty());
    }
    // A stale dpkg tree with no installed package must not hide the rpm database.
    root.put_text("var/lib/dpkg/status", "");
    {
        const auto h = read_root(root);
        REQUIRE(h.failure.empty());
        CHECK(h.ecosystem == Eco::rpm);
        CHECK(h.rpm.size() == 4);
        CHECK(h.dpkg.empty());
    }
    // A status whose every stanza is not-installed is "zero stanzas" too.
    root.put_text("var/lib/dpkg/status", "Package: gone\nStatus: purge ok not-installed\n\n");
    CHECK(read_root(root).ecosystem == Eco::rpm);
}

TEST_CASE("pkgdb detection: usr/lib/sysimage/rpm wins over var/lib/rpm; a symlinked directory is never "
          "followed, and is a refusal when a database sits behind it",
          "[installed_apps][pkgdb]") {
    const fs::path fedora = default_fixture_root() / "fedora41" / "rpmdb.sqlite";
    const fs::path alma9 = default_fixture_root() / "alma9" / "rpmdb.sqlite";
    {
        Root root;
        root.put("usr/lib/sysimage/rpm/rpmdb.sqlite", fedora);
        root.put("var/lib/rpm/rpmdb.sqlite", alma9);
        const auto h = read_root(root);
        REQUIRE(h.failure.empty());
        CHECK(names_of(h).contains("libssh-config")); // fedora41's, not alma9's
        CHECK_FALSE(names_of(h).contains("dbus"));
    }
    {
        // /var/lib/rpm -> a directory elsewhere that holds a database: never followed (nothing is opened
        // through the link, only stat'ed), and with no other candidate it is a refusal -- a database that
        // exists but may not be read is never an empty list.
        Root root;
        root.put("elsewhere/rpmdb.sqlite", alma9);
        fs::create_directories(root.at("var/lib"));
        fs::create_directory_symlink(root.at("elsewhere"), root.at("var/lib/rpm"));
        const auto h = read_root(root);
        CHECK(h.failure == "rpmdb:symlink_refused");
        CHECK(h.ecosystem == Eco::none);
        CHECK(h.rpm.empty());
    }
    {
        // The same for each kind of database file behind the link, and a data.mdb.
        for (const char* name : {"Packages.db", "Packages", "data.mdb"}) {
            INFO(name);
            Root root;
            root.put_text(std::string{"elsewhere/"} + name, "x");
            fs::create_directories(root.at("var/lib"));
            fs::create_directory_symlink(root.at("elsewhere"), root.at("var/lib/rpm"));
            CHECK(read_root(root).failure == "rpmdb:symlink_refused");
        }
    }
    {
        // A link to a directory with NO database behind it is as before: skipped, no failure, no rpm.
        Root root;
        fs::create_directories(root.at("elsewhere"));
        fs::create_directories(root.at("var/lib"));
        fs::create_directory_symlink(root.at("elsewhere"), root.at("var/lib/rpm"));
        const auto h = read_root(root);
        CHECK(h.failure.empty());
        CHECK(h.ecosystem == Eco::none);
    }
    {
        // The older layout: usr/lib/sysimage/rpm is the link and var/lib/rpm is the real directory. The
        // link is skipped, the later candidate yields the database, and nothing is refused.
        Root root;
        root.put("var/lib/rpm/rpmdb.sqlite", fedora);
        fs::create_directories(root.at("usr/lib/sysimage"));
        fs::create_directory_symlink("../../../var/lib/rpm", root.at("usr/lib/sysimage/rpm"));
        const auto h = read_root(root);
        REQUIRE(h.failure.empty());
        CHECK(h.ecosystem == Eco::rpm);
        CHECK(h.rpm.size() == 4);
    }
    {
        // The real modern layout: var/lib/rpm links to the sysimage copy, which is read directly.
        Root root;
        root.put("usr/lib/sysimage/rpm/rpmdb.sqlite", fedora);
        fs::create_directories(root.at("var/lib"));
        fs::create_directory_symlink("../../usr/lib/sysimage/rpm", root.at("var/lib/rpm"));
        const auto h = read_root(root);
        REQUIRE(h.failure.empty());
        CHECK(h.ecosystem == Eco::rpm);
        CHECK(h.rpm.size() == 4);
    }
}

TEST_CASE("pkgdb detection: format by file name, a lone data.mdb, and nothing at all",
          "[installed_apps][pkgdb]") {
    const fs::path pk = default_fixture_root();
    {
        Root root;
        root.put("var/lib/rpm/Packages", pk / "alma8" / "Packages");
        const auto h = read_root(root);
        REQUIRE(h.failure.empty());
        CHECK(h.ecosystem == Eco::rpm);
        CHECK(h.rpm.size() == 5);
    }
    {
        Root root;
        root.put("usr/lib/sysimage/rpm/Packages.db", pk / "tumbleweed" / "Packages.db");
        const auto h = read_root(root);
        REQUIRE(h.failure.empty());
        CHECK(h.rpm.size() == 11);
    }
    {
        // sqlite is preferred over a stale Berkeley DB file left by an upgrade.
        Root root;
        root.put("var/lib/rpm/rpmdb.sqlite", pk / "alma9" / "rpmdb.sqlite");
        root.put("var/lib/rpm/Packages", pk / "alma8" / "Packages");
        const auto h = read_root(root);
        REQUIRE(h.failure.empty());
        CHECK(h.rpm.size() == 5);
    }
    {
        Root root;
        root.put_text("var/lib/rpm/data.mdb", "an lmdb file this reader does not decode");
        const auto h = read_root(root);
        CHECK(h.failure == "rpmdb:unsupported_format");
        CHECK(h.ecosystem == Eco::none);
        CHECK(h.rpm.empty());
    }
    {
        Root root; // empty
        const auto h = read_root(root);
        CHECK(h.failure.empty());
        CHECK(h.ecosystem == Eco::none);
        CHECK(h.dpkg.empty());
        CHECK(h.rpm.empty());
    }
    {
        // A directory where the database file belongs, and a symlink in its place, are refused.
        Root root;
        fs::create_directories(root.at("var/lib/rpm/rpmdb.sqlite"));
        CHECK(read_root(root).failure == "rpm_sqlite:not_regular");
        Root root2;
        root2.put("real/Packages.db", pk / "leap156" / "Packages.db");
        fs::create_directories(root2.at("var/lib/rpm"));
        fs::create_symlink(root2.at("real/Packages.db"), root2.at("var/lib/rpm/Packages.db"));
        CHECK(read_root(root2).failure == "rpm_ndb:symlink_refused");
    }
    {
        // A corrupt ndb names its own source, not a generic one.
        Root root;
        root.put_text("var/lib/rpm/Packages.db", std::string(8192, 'x'));
        CHECK(read_root(root).failure == "rpm_ndb:unsupported_format");
        Root root2;
        root2.put_text("var/lib/rpm/Packages", std::string(8192, 'x'));
        CHECK(read_root(root2).failure == "rpm_bdb:unsupported_format");
    }
}

// ── dpkg refusals and status.d ──────────────────────────────────────────────

TEST_CASE("pkgdb dpkg refusals: a symlinked status, a directory and an over-cap file",
          "[installed_apps][pkgdb]") {
    const fs::path debian = default_fixture_root() / "debian12" / "status";
    {
        Root root;
        root.put("elsewhere/status", debian);
        fs::create_directories(root.at("var/lib/dpkg"));
        fs::create_symlink(root.at("elsewhere/status"), root.at("var/lib/dpkg/status"));
        const auto h = read_root(root);
        CHECK(h.failure == "dpkg_status:symlink_refused");
        CHECK(h.dpkg.empty());
        CHECK(h.ecosystem == Eco::none);
    }
    {
        Root root;
        fs::create_directories(root.at("var/lib/dpkg/status"));
        CHECK(read_root(root).failure == "dpkg_status:not_regular");
    }
    {
        Root root;
        root.put("var/lib/dpkg/status", debian);
        pkgdb::Limits lim;
        lim.dpkg_max_bytes = 1000;
        const auto h = read_root(root, lim);
        CHECK(h.failure == "dpkg_status:oversized");
        CHECK(h.dpkg.empty());
    }
    {
        // Corrupt text is refused whole: the one good stanza before the bad line does not survive.
        Root root;
        root.put_text("var/lib/dpkg/status",
                      "Package: a\nStatus: install ok installed\n\nthis line has no colon\n");
        const auto h = read_root(root);
        CHECK(h.failure == "dpkg_status:corrupt");
        CHECK(h.dpkg.empty());
    }
    {
        Root root;
        root.put("var/lib/dpkg/status", debian);
        pkgdb::Limits lim;
        lim.max_packages = 3;
        CHECK(read_root(root, lim).failure == "dpkg_status:row_cap");
    }
}

namespace {

// A real debian12 stanza, by name, and the status text without it.
struct SplitStatus {
    std::string rest;
    std::string stanza;
};
SplitStatus split_stanza(std::string_view name) {
    const std::string status = read_text(default_fixture_root() / "debian12" / "status");
    const std::string key = "Package: " + std::string{name} + "\n";
    const std::size_t at = status.find(key);
    REQUIRE(at != std::string::npos);
    const std::size_t end = status.find("\n\n", at) + 2;
    return {status.substr(0, at) + status.substr(end), status.substr(at, end - at)};
}

} // namespace

TEST_CASE("pkgdb status.d: a stanza moved into status.d (EDITED real debian12 capture) reads as before",
          "[installed_apps][pkgdb]") {
    // EDITED: the real libacl1 stanza is cut out of the debian12 status file and written to
    // status.d/libacl1, the layout minimal images use. The package set must equal the unedited
    // capture's, row for row.
    const auto [rest, stanza] = split_stanza("libacl1");
    Root root;
    root.put_text("var/lib/dpkg/status", rest);
    root.put_text("var/lib/dpkg/status.d/libacl1", stanza);
    const auto h = read_root(root);
    REQUIRE(h.failure.empty());
    REQUIRE(h.ecosystem == Eco::dpkg);

    Root whole;
    whole.put("var/lib/dpkg/status", default_fixture_root() / "debian12" / "status");
    const auto expect = read_root(whole);
    CHECK(new_inv_rows(h) == new_inv_rows(expect));
    CHECK(new_list_rows(h) == new_list_rows(expect));
    CHECK(h.dpkg.size() == 10);
}

TEST_CASE("pkgdb status.d: a host whose packages live only in status.d is dpkg", "[installed_apps][pkgdb]") {
    const auto [rest, stanza] = split_stanza("libacl1");
    Root root; // no status file at all: the layout of a minimal image with no package manager
    root.put_text("var/lib/dpkg/status.d/libacl1", stanza);
    const auto h = read_root(root);
    REQUIRE(h.failure.empty());
    CHECK(h.ecosystem == Eco::dpkg);
    REQUIRE(h.dpkg.size() == 1);
    CHECK(h.dpkg[0].name == "libacl1");
}

namespace {

// The real status.d capture (a minimal Debian 12 image with no shell): three packages, each a
// Status-less control file with a `<package>.md5sums` sibling. Copies every file into `root`.
const fs::path kStatusDCapture = default_fixture_root() / "debian12-statusd" / "status.d";
void put_status_d_capture(const Root& root) {
    for (const auto& e : fs::directory_iterator(kStatusDCapture))
        root.put("var/lib/dpkg/status.d/" + e.path().filename().string(), e.path());
}

} // namespace

TEST_CASE("pkgdb status.d: a real minimal-image capture reads as dpkg with its real package names",
          "[installed_apps][pkgdb]") {
    // REAL capture (provenance.txt): no status file, no Status field in any control file, and a
    // .md5sums sibling beside each. Six files, three packages.
    Root root;
    put_status_d_capture(root);
    const auto h = read_root(root);
    REQUIRE(h.failure.empty());
    CHECK(h.ecosystem == Eco::dpkg);
    REQUIRE(h.dpkg.size() == 3); // files are read in name order: base-files, media-types, netbase
    CHECK(h.dpkg[0].name == "base-files");
    CHECK(h.dpkg[0].version == "12.4+deb12u15");
    CHECK(h.dpkg[0].architecture == "arm64");
    CHECK(h.dpkg[0].maintainer == "Santiago Vila <sanvila@debian.org>");
    CHECK(h.dpkg[1].name == "media-types");
    CHECK(h.dpkg[1].version == "10.0.0");
    CHECK(h.dpkg[2].name == "netbase");
    CHECK(h.dpkg[2].version == "6.4");
    CHECK(h.dpkg[2].architecture == "all");
    for (const auto& p : h.dpkg) { // a present control file is an installed package
        INFO(p.name);
        CHECK(p.want == "install");
        CHECK(p.flag == "ok");
        CHECK(p.status == "installed");
    }
    // And both row sets carry all three: the mapping accepts what the reader hands over.
    CHECK(new_inv_rows(h).size() == 3);
    CHECK(new_list_rows(h).size() == 3);
}

TEST_CASE("pkgdb status.d: a .md5sums entry is skipped, a Status-less stanza is installed here and corrupt in "
          "the status file",
          "[installed_apps][pkgdb]") {
    CHECK(pkgdb::detail::status_d_skips("netbase.md5sums"));
    CHECK_FALSE(pkgdb::detail::status_d_skips("netbase"));

    const std::string netbase = read_text(kStatusDCapture / "netbase");
    REQUIRE(netbase.find("\nStatus:") == std::string::npos); // the real file has none
    SECTION("in status.d: installed") {
        Root root;
        root.put_text("var/lib/dpkg/status.d/netbase", netbase);
        const auto h = read_root(root);
        REQUIRE(h.failure.empty());
        REQUIRE(h.dpkg.size() == 1);
        CHECK(h.dpkg[0].status == "installed");
    }
    SECTION("in the status file: corrupt, as before") {
        Root root;
        root.put_text("var/lib/dpkg/status", netbase);
        const auto h = read_root(root);
        CHECK(h.failure == "dpkg_status:corrupt");
        CHECK(h.dpkg.empty());
        CHECK(h.ecosystem == Eco::none);
    }
    SECTION("a status.d stanza that has a Status is still held to it") {
        Root root;
        root.put_text("var/lib/dpkg/status.d/netbase", netbase + "Status: nonsense\n");
        CHECK(read_root(root).failure == "dpkg_status_d:corrupt");
    }
    SECTION("an md5sums file is not parsed: its content would be corrupt if it were") {
        Root root;
        root.put_text("var/lib/dpkg/status.d/netbase", netbase);
        root.put("var/lib/dpkg/status.d/netbase.md5sums", kStatusDCapture / "netbase.md5sums");
        const auto h = read_root(root);
        REQUIRE(h.failure.empty());
        CHECK(h.dpkg.size() == 1);
    }
}

TEST_CASE("pkgdb status.d: a package in both keeps the status entry; dotfiles and md5sums files are ignored",
          "[installed_apps][pkgdb]") {
    const auto [rest, stanza] = split_stanza("libacl1");
    Root root;
    root.put("var/lib/dpkg/status", default_fixture_root() / "debian12" / "status");
    // EDITED copy of the same stanza with another Version: the status file's must win.
    std::string other = stanza;
    const std::size_t v = other.find("Version: ");
    REQUIRE(v != std::string::npos);
    other.replace(v, other.find('\n', v) - v, "Version: 9.9.9");
    root.put_text("var/lib/dpkg/status.d/libacl1", other);
    // Names that are not packages, with content that would be corrupt if it were parsed.
    for (const char* junk : {".hidden", "x.md5sums"})
        root.put_text(std::string{"var/lib/dpkg/status.d/"} + junk, "garbage with no colon\n");
    const auto h = read_root(root);
    REQUIRE(h.failure.empty());
    REQUIRE(h.dpkg.size() == 10);
    const auto it = std::find_if(h.dpkg.begin(), h.dpkg.end(), [](const DpkgPackage& p) { return p.name == "libacl1"; });
    REQUIRE(it != h.dpkg.end());
    CHECK(it->version == "2.3.1-3");
}

TEST_CASE("pkgdb status.d hostile: symlink entry refused, directory entry skipped, oversized file, too many files",
          "[installed_apps][pkgdb]") {
    const auto [rest, stanza] = split_stanza("libacl1");
    SECTION("a symlink entry is refused, never followed") {
        Root root;
        root.put_text("elsewhere/target", stanza);
        fs::create_directories(root.at("var/lib/dpkg/status.d"));
        fs::create_symlink(root.at("elsewhere/target"), root.at("var/lib/dpkg/status.d/evil"));
        const auto h = read_root(root);
        CHECK(h.failure == "dpkg_status_d:symlink_refused");
        CHECK(h.dpkg.empty());
        CHECK(h.ecosystem == Eco::none);
    }
    SECTION("status.d itself a symlink is refused") {
        Root root;
        root.put_text("elsewhere/libacl1", stanza);
        fs::create_directories(root.at("var/lib/dpkg"));
        fs::create_directory_symlink(root.at("elsewhere"), root.at("var/lib/dpkg/status.d"));
        CHECK(read_root(root).failure == "dpkg_status_d:symlink_refused");
    }
    SECTION("a directory entry is skipped") {
        Root root;
        root.put_text("var/lib/dpkg/status.d/libacl1", stanza);
        fs::create_directories(root.at("var/lib/dpkg/status.d/subdir"));
        const auto h = read_root(root);
        REQUIRE(h.failure.empty());
        CHECK(h.dpkg.size() == 1);
    }
    SECTION("an oversized file fails the read") {
        Root root;
        root.put_text("var/lib/dpkg/status.d/libacl1", stanza + std::string(5000, '#'));
        pkgdb::Limits lim;
        lim.dpkg_max_bytes = 2000;
        CHECK(read_root(root, lim).failure == "dpkg_status_d:oversized");
    }
    SECTION("more files than max_packages is row_cap") {
        Root root;
        for (int i = 0; i < 4; ++i)
            root.put_text("var/lib/dpkg/status.d/f" + std::to_string(i),
                          "Package: p" + std::to_string(i) + "\nStatus: install ok installed\n");
        pkgdb::Limits lim;
        lim.max_packages = 3;
        CHECK(read_root(root, lim).failure == "dpkg_status_d:row_cap");
        lim.max_packages = 4;
        const auto h = read_root(root, lim);
        CHECK(h.failure.empty());
        CHECK(h.dpkg.size() == 4);
    }
    SECTION("a corrupt status.d file fails the whole read and returns no packages") {
        Root root;
        root.put("var/lib/dpkg/status", default_fixture_root() / "debian12" / "status");
        root.put_text("var/lib/dpkg/status.d/bad", "Package: x\nStatus: nonsense\n");
        const auto h = read_root(root);
        CHECK(h.failure == "dpkg_status_d:corrupt");
        CHECK(h.dpkg.empty());
        CHECK(h.ecosystem == Eco::none);
    }
    SECTION("the dpkg byte limit is one TOTAL across status and status.d: each fits, together byte_cap") {
        Root root;
        root.put_text("var/lib/dpkg/status", rest);
        root.put_text("var/lib/dpkg/status.d/libacl1", stanza);
        pkgdb::Limits lim;
        lim.dpkg_max_bytes = std::max(rest.size(), stanza.size()) + 1; // neither file alone is oversized
        CHECK(read_root(root, lim).failure == "dpkg_status_d:byte_cap");
        lim.dpkg_max_bytes = rest.size() + stanza.size(); // an exact fill is admitted
        const auto h = read_root(root, lim);
        CHECK(h.failure.empty());
        CHECK(h.dpkg.size() == 10);
    }
}

namespace {

// A scripted readdir: hands out `names` in order, then ends the listing with `end_errno` (0 = a clean
// end of directory, anything else = the listing failed there). The DIR* is ignored.
struct ScriptedReadDir {
    std::vector<std::string> names;
    int end_errno = 0;
    std::size_t next = 0;
    struct dirent entry {};

    struct dirent* operator()(DIR*) {
        if (next >= names.size()) {
            errno = end_errno;
            return nullptr;
        }
        std::strncpy(entry.d_name, names[next].c_str(), sizeof(entry.d_name) - 1);
        entry.d_name[sizeof(entry.d_name) - 1] = '\0';
        ++next;
        return &entry;
    }
};

// Two real control files from the debian12-statusd capture in a scratch status.d.
void put_two_status_d_files(const Root& root) {
    for (const char* name : {"base-files", "netbase"})
        root.put(std::string{"var/lib/dpkg/status.d/"} + name, kStatusDCapture / name);
}

pkgdb::detail::DpkgRead list_status_d(const Root& root, ScriptedReadDir& script) {
    const pkgdb::Limits lim = default_limits();
    yuzu::shared::PkgDbBudget budget{.rows_left = lim.max_packages,
                                     .bytes_left = lim.dpkg_max_bytes,
                                     .max_item_bytes = lim.dpkg_max_bytes,
                                     .expired = {}};
    return pkgdb::detail::read_dpkg_status_d(root.str(), lim, budget, script);
}

} // namespace

TEST_CASE("pkgdb status.d: a directory listing that fails part-way fails the read, never a shorter list",
          "[installed_apps][pkgdb]") {
    Root root;
    put_two_status_d_files(root);

    SECTION("control: a clean end after one name reads that one package") {
        ScriptedReadDir script{{"base-files"}, 0};
        const auto r = list_status_d(root, script);
        CHECK(r.failure.empty());
        REQUIRE(r.packages.size() == 1);
        CHECK(r.packages[0].name == "base-files");
    }
    SECTION("one real name, then the listing fails with EIO") {
        ScriptedReadDir script{{"base-files"}, EIO};
        const auto r = list_status_d(root, script);
        CHECK(r.failure == "dpkg_status_d:unreadable");
        CHECK(r.packages.empty());
    }
    SECTION("the listing fails on the first call") {
        ScriptedReadDir script{{}, EIO};
        const auto r = list_status_d(root, script);
        CHECK(r.failure == "dpkg_status_d:unreadable");
        CHECK(r.packages.empty());
    }
}

TEST_CASE("pkgdb status.d: skipped names are bounded and poll the deadline like any other entry",
          "[installed_apps][pkgdb]") {
    SECTION("a status.d of only skipped names still polls the deadline, and an expired one is timeout") {
        Root root;
        root.put_text("var/lib/dpkg/status.d/.hidden", "x");
        root.put_text("var/lib/dpkg/status.d/netbase.md5sums", "x");
        std::size_t polls = 0;
        const auto h = read_root(root, default_limits(), [&] {
            ++polls;
            return true;
        });
        REQUIRE(polls > 0);
        CHECK(h.failure == "dpkg_status_d:timeout");
        CHECK(h.dpkg.empty());
    }
    SECTION("the entry bound is twice max_packages: over it is row_cap, an exact fill reads") {
        const auto [rest, stanza] = split_stanza("libacl1");
        Root root; // one control file and five skipped names: six entries
        root.put_text("var/lib/dpkg/status.d/libacl1", stanza);
        for (const char* junk : {".a", ".b", "a.md5sums", "b.md5sums", "c.md5sums"})
            root.put_text(std::string{"var/lib/dpkg/status.d/"} + junk, "x");
        pkgdb::Limits lim;
        lim.max_packages = 2; // bound 4
        const auto over = read_root(root, lim);
        CHECK(over.failure == "dpkg_status_d:row_cap");
        CHECK(over.dpkg.empty());
        lim.max_packages = 3; // bound 6
        const auto fill = read_root(root, lim);
        CHECK(fill.failure.empty());
        CHECK(fill.dpkg.size() == 1);
    }
}

// ── detection edges: no installed stanza, an empty database, the rpm transaction lock, the dpkg journal ──

namespace {

// EDITED real debian12 status: every stanza's Status rewritten, alternately to config-files and to
// half-installed, so no stanza is `installed` (both words are real dpkg states; the packages stay).
std::string status_without_installed_stanza() {
    std::string text = read_text(default_fixture_root() / "debian12" / "status");
    const std::string_view from = "Status: install ok installed";
    std::size_t rewritten = 0;
    for (std::size_t at = text.find(from); at != std::string::npos; at = text.find(from, at)) {
        const std::string_view to = rewritten++ % 2 == 0 ? "Status: deinstall ok config-files"
                                                         : "Status: install reinstreq half-installed";
        text.replace(at, from.size(), to);
        at += to.size();
    }
    REQUIRE(rewritten == 10);
    return text;
}

// EDITED copy of a real sqlite rpm database with every package row deleted: a database that was read
// and holds no package. Closed (and so checkpointed) before it returns.
fs::path put_emptied_sqlite(const Root& root, std::string_view rel, const fs::path& src) {
    const fs::path db_path = root.put(rel, src);
    const auto db = open_sqlite(db_path);
    exec_sql(db.get(), "DELETE FROM Packages");
    return db_path;
}

} // namespace

TEST_CASE("pkgdb detection: a dpkg status with no installed stanza falls through to rpm, or to nothing",
          "[installed_apps][pkgdb]") {
    const fs::path fedora = default_fixture_root() / "fedora41" / "rpmdb.sqlite";
    SECTION("beside a real rpm database the host reads as rpm") {
        Root root;
        root.put_text("var/lib/dpkg/status", status_without_installed_stanza());
        root.put("usr/lib/sysimage/rpm/rpmdb.sqlite", fedora);
        const auto h = read_root(root);
        REQUIRE(h.failure.empty());
        CHECK(h.ecosystem == Eco::rpm);
        CHECK(h.rpm.size() == 4);
        CHECK(h.dpkg.empty());
    }
    SECTION("alone it is ecosystem none with no failure, so the pacman and apk legs run") {
        Root root;
        root.put_text("var/lib/dpkg/status", status_without_installed_stanza());
        const auto h = read_root(root);
        CHECK(h.failure.empty());
        CHECK(h.ecosystem == Eco::none);
        CHECK(h.dpkg.empty());
        CHECK(h.rpm.empty());
    }
    SECTION("one installed stanza among the others is enough: it is dpkg, and every parsed stanza is kept") {
        Root root;
        root.put_text("var/lib/dpkg/status",
                      status_without_installed_stanza() +
                          "Package: extra\nStatus: install ok installed\nArchitecture: all\nVersion: 1\n\n");
        const auto h = read_root(root);
        REQUIRE(h.failure.empty());
        CHECK(h.ecosystem == Eco::dpkg);
        CHECK(h.dpkg.size() == 11);
    }
}

TEST_CASE("pkgdb detection: an rpm database that was read and holds no package does not end detection",
          "[installed_apps][pkgdb]") {
    const fs::path fedora = default_fixture_root() / "fedora41" / "rpmdb.sqlite";
    const fs::path alma9 = default_fixture_root() / "alma9" / "rpmdb.sqlite";
    SECTION("alone (EDITED copy, rows deleted) it is ecosystem none with no failure") {
        Root root;
        put_emptied_sqlite(root, "var/lib/rpm/rpmdb.sqlite", fedora);
        const auto h = read_root(root);
        CHECK(h.failure.empty());
        CHECK(h.ecosystem == Eco::none);
        CHECK(h.rpm.empty());
    }
    SECTION("with a populated var/lib/rpm behind it, that one is read") {
        Root root;
        put_emptied_sqlite(root, "usr/lib/sysimage/rpm/rpmdb.sqlite", fedora);
        root.put("var/lib/rpm/rpmdb.sqlite", alma9);
        const auto h = read_root(root);
        REQUIRE(h.failure.empty());
        CHECK(h.ecosystem == Eco::rpm);
        CHECK(h.rpm.size() == 5);
    }
    SECTION("var/lib/rpm linking to the emptied directory is ecosystem none, never symlink_refused") {
        // The modern layout (a link to the directory just read), where the link is the NEXT candidate.
        Root root;
        put_emptied_sqlite(root, "usr/lib/sysimage/rpm/rpmdb.sqlite", fedora);
        fs::create_directories(root.at("var/lib"));
        fs::create_directory_symlink("../../usr/lib/sysimage/rpm", root.at("var/lib/rpm"));
        const auto h = read_root(root);
        CHECK(h.failure.empty());
        CHECK(h.ecosystem == Eco::none);
        CHECK(h.rpm.empty());
    }
    SECTION("a link with a database behind it and nothing else read is still symlink_refused") {
        Root root;
        root.put("elsewhere/rpmdb.sqlite", fedora);
        fs::create_directories(root.at("var/lib"));
        fs::create_directory_symlink(root.at("elsewhere"), root.at("var/lib/rpm"));
        CHECK(read_root(root).failure == "rpmdb:symlink_refused");
    }
}

TEST_CASE("pkgdb rpm lock: the ndb and Berkeley DB files are read only when no rpm transaction holds .rpm.lock",
          "[installed_apps][pkgdb]") {
    struct Format {
        const char* capture;
        const char* file;
        const char* dir;
        const char* source;
        std::size_t packages;
    };
    const Format formats[] = {{"tumbleweed", "Packages.db", "usr/lib/sysimage/rpm", "rpm_ndb", 11},
                              {"alma8", "Packages", "var/lib/rpm", "rpm_bdb", 5}};
    for (const auto& f : formats) {
        INFO(f.source);
        const auto scratch = [&f](const Root& root) {
            root.put(std::string{f.dir} + "/" + f.file, default_fixture_root() / f.capture / f.file);
        };
        const std::string lock_rel = std::string{f.dir} + "/.rpm.lock";
        SECTION("no lock file: no transaction has run there, it reads") {
            Root root;
            scratch(root);
            const auto h = read_root(root);
            REQUIRE(h.failure.empty());
            CHECK(h.rpm.size() == f.packages);
        }
        SECTION("a lock file nobody holds reads") {
            Root root;
            scratch(root);
            root.put_text(lock_rel, "");
            const auto h = read_root(root);
            REQUIRE(h.failure.empty());
            CHECK(h.rpm.size() == f.packages);
        }
        SECTION("a symlinked lock file is refused by name, never followed") {
            Root root;
            scratch(root);
            root.put_text("elsewhere/lock", "");
            fs::create_symlink(root.at("elsewhere/lock"), root.at(lock_rel));
            const auto h = read_root(root);
            CHECK(h.failure == std::string{f.source} + ":symlink_refused");
            CHECK(h.ecosystem == Eco::none);
            CHECK(h.rpm.empty());
        }
        SECTION("a directory in place of the lock file is refused by name") {
            Root root;
            scratch(root);
            fs::create_directories(root.at(lock_rel));
            const auto h = read_root(root);
            CHECK(h.failure == std::string{f.source} + ":not_regular");
            CHECK(h.rpm.empty());
        }
#ifdef __linux__
        SECTION("a write lock held on the lock file is locked with no rows; released, every row reads") {
            // An open-file-description lock belongs to its descriptor, not the process, so the reader's
            // F_GETLK in this process sees it: no second process is needed. Linux only: F_OFD_SETLK.
            Root root;
            scratch(root);
            const fs::path lock_path = root.put_text(lock_rel, "");
            std::optional<yuzu::shared::ScopedFile> holder{
                yuzu::shared::ScopedFile{::open(lock_path.c_str(), O_RDWR | O_CLOEXEC)}};
            REQUIRE(holder->valid());
            struct flock fl {};
            fl.l_type = F_WRLCK;
            fl.l_whence = SEEK_SET;
            REQUIRE(::fcntl(holder->fd(), F_OFD_SETLK, &fl) == 0);
            {
                const auto h = read_root(root);
                CHECK(h.failure == std::string{f.source} + ":locked");
                CHECK(h.ecosystem == Eco::none);
                CHECK(h.rpm.empty());
            }
            holder.reset(); // closing the descriptor releases the lock
            const auto h = read_root(root);
            REQUIRE(h.failure.empty());
            CHECK(h.rpm.size() == f.packages);
        }
#endif
    }
    SECTION("a sqlite database beside a symlinked lock file still reads: the lock is not its isolation") {
        Root root;
        root.put("var/lib/rpm/rpmdb.sqlite", default_fixture_root() / "fedora41" / "rpmdb.sqlite");
        root.put_text("elsewhere/lock", "");
        fs::create_symlink(root.at("elsewhere/lock"), root.at("var/lib/rpm/.rpm.lock"));
        const auto h = read_root(root);
        REQUIRE(h.failure.empty());
        CHECK(h.rpm.size() == 4);
    }
#ifdef __linux__
    SECTION("a sqlite database beside a HELD lock still reads") {
        Root root;
        root.put("var/lib/rpm/rpmdb.sqlite", default_fixture_root() / "fedora41" / "rpmdb.sqlite");
        const fs::path lock_path = root.put_text("var/lib/rpm/.rpm.lock", "");
        const yuzu::shared::ScopedFile holder{::open(lock_path.c_str(), O_RDWR | O_CLOEXEC)};
        REQUIRE(holder.valid());
        struct flock fl {};
        fl.l_type = F_WRLCK;
        fl.l_whence = SEEK_SET;
        REQUIRE(::fcntl(holder.fd(), F_OFD_SETLK, &fl) == 0);
        const auto h = read_root(root);
        REQUIRE(h.failure.empty());
        CHECK(h.rpm.size() == 4);
    }
#endif
}

namespace {

// The update-journal listing alone, with a scripted readdir over a real (empty) updates directory.
std::string updates_failure_of(const Root& root, ScriptedReadDir& script, std::function<bool()> expired = {}) {
    fs::create_directories(root.at("var/lib/dpkg/updates"));
    const pkgdb::Limits lim = default_limits();
    yuzu::shared::PkgDbBudget budget{.rows_left = lim.max_packages,
                                     .bytes_left = lim.dpkg_max_bytes,
                                     .max_item_bytes = lim.dpkg_max_bytes,
                                     .expired = std::move(expired)};
    return pkgdb::detail::dpkg_updates_failure(root.str(), lim, budget, script);
}

} // namespace

TEST_CASE("pkgdb dpkg update journal: a pending record is a refusal, never the pre-journal roster",
          "[installed_apps][pkgdb]") {
    const fs::path debian = default_fixture_root() / "debian12" / "status";

    SECTION("a record 0000 beside the debian12 status is dpkg_updates:locked with nothing returned") {
        Root root;
        root.put("var/lib/dpkg/status", debian);
        root.put_text("var/lib/dpkg/updates/0000", "");
        const auto h = read_root(root);
        CHECK(h.failure == "dpkg_updates:locked");
        CHECK(h.ecosystem == Eco::none);
        CHECK(h.dpkg.empty());
        CHECK(h.rpm.empty());
    }
    SECTION("only tmp.i and a dotfile are ignored: it reads all ten") {
        Root root;
        root.put("var/lib/dpkg/status", debian);
        root.put_text("var/lib/dpkg/updates/tmp.i", "");
        root.put_text("var/lib/dpkg/updates/.hidden", "");
        root.put_text("var/lib/dpkg/updates/0000.bak", ""); // not ASCII digits only
        const auto h = read_root(root);
        REQUIRE(h.failure.empty());
        CHECK(h.ecosystem == Eco::dpkg);
        CHECK(h.dpkg.size() == 10);
    }
    SECTION("an empty updates directory reads") {
        Root root;
        root.put("var/lib/dpkg/status", debian);
        fs::create_directories(root.at("var/lib/dpkg/updates"));
        const auto h = read_root(root);
        REQUIRE(h.failure.empty());
        CHECK(h.dpkg.size() == 10);
    }
    SECTION("a symlinked updates directory is refused by name, never followed") {
        Root root;
        root.put("var/lib/dpkg/status", debian);
        fs::create_directories(root.at("elsewhere"));
        fs::create_directory_symlink(root.at("elsewhere"), root.at("var/lib/dpkg/updates"));
        const auto h = read_root(root);
        CHECK(h.failure == "dpkg_updates:symlink_refused");
        CHECK(h.dpkg.empty());
    }
    SECTION("a regular file in place of the updates directory is refused by name") {
        Root root;
        root.put("var/lib/dpkg/status", debian);
        root.put_text("var/lib/dpkg/updates", "x");
        const auto h = read_root(root);
        CHECK(h.failure == "dpkg_updates:not_regular");
        CHECK(h.dpkg.empty());
    }
    SECTION("a pending record with an rpm database also present is still locked: no fall-through") {
        Root root;
        root.put("var/lib/dpkg/status", debian);
        root.put_text("var/lib/dpkg/updates/0001", "");
        root.put("usr/lib/sysimage/rpm/rpmdb.sqlite", default_fixture_root() / "fedora41" / "rpmdb.sqlite");
        const auto h = read_root(root);
        CHECK(h.failure == "dpkg_updates:locked");
        CHECK(h.ecosystem == Eco::none);
        CHECK(h.rpm.empty());
    }
    SECTION("a status.d-only host is held to the same journal rule") {
        Root root;
        put_two_status_d_files(root);
        root.put_text("var/lib/dpkg/updates/0002", "");
        CHECK(read_root(root).failure == "dpkg_updates:locked");
    }
    SECTION("control: a clean scripted listing of ignored names has no failure") {
        Root root;
        ScriptedReadDir script{{"tmp.i", ".x"}, 0};
        CHECK(updates_failure_of(root, script).empty());
    }
    SECTION("a record name stops the walk before the rest of the listing is read") {
        Root root;
        ScriptedReadDir script{{"tmp.i", "0000"}, EIO}; // the EIO is never reached
        CHECK(updates_failure_of(root, script) == "dpkg_updates:locked");
    }
    SECTION("a listing that fails part-way is unreadable, never an empty journal") {
        Root root;
        ScriptedReadDir script{{"tmp.i"}, EIO};
        CHECK(updates_failure_of(root, script) == "dpkg_updates:unreadable");
    }
    SECTION("an expired deadline is polled per entry and is timeout") {
        Root root;
        ScriptedReadDir script{{"tmp.i"}, 0};
        CHECK(updates_failure_of(root, script, [] { return true; }) == "dpkg_updates:timeout");
    }
    SECTION("the entry bound is twice max_packages: over it is row_cap") {
        Root root;
        fs::create_directories(root.at("var/lib/dpkg/updates"));
        for (const char* junk : {"a", "b", "c", "d", "e"})
            root.put_text(std::string{"var/lib/dpkg/updates/"} + junk, "");
        // One stanza, not the ten-stanza capture: a small max_packages would fail the status read first.
        root.put_text("var/lib/dpkg/status", "Package: p\nStatus: install ok installed\n\n");
        pkgdb::Limits lim;
        lim.max_packages = 2; // bound 4
        CHECK(read_root(root, lim).failure == "dpkg_updates:row_cap");
        lim.max_packages = 3; // bound 6
        CHECK(read_root(root, lim).failure.empty());
    }
}

// ── reader limits and edge branches through the shell ───────────────────────

TEST_CASE("pkgdb ndb and bdb: a package cap below the row count answers row_cap with no rows",
          "[installed_apps][pkgdb]") {
    pkgdb::Limits lim;
    lim.max_packages = 2;
    {
        Root root;
        root.put("usr/lib/sysimage/rpm/Packages.db", default_fixture_root() / "tumbleweed" / "Packages.db");
        const auto h = read_root(root, lim);
        CHECK(h.failure == "rpm_ndb:row_cap");
        CHECK(h.ecosystem == Eco::none);
        CHECK(h.rpm.empty());
    }
    {
        Root root;
        root.put("var/lib/rpm/Packages", default_fixture_root() / "alma8" / "Packages");
        const auto h = read_root(root, lim);
        CHECK(h.failure == "rpm_bdb:row_cap");
        CHECK(h.ecosystem == Eco::none);
        CHECK(h.rpm.empty());
    }
}

TEST_CASE("pkgdb kept text: a small kept-text bound is byte_cap with no rows in every rpm format",
          "[installed_apps][pkgdb]") {
    struct Format {
        const char* capture;
        const char* file;
        const char* dir;
        const char* source;
    };
    const Format formats[] = {{"fedora41", "rpmdb.sqlite", "var/lib/rpm", "rpm_sqlite"},
                              {"tumbleweed", "Packages.db", "usr/lib/sysimage/rpm", "rpm_ndb"},
                              {"alma8", "Packages", "var/lib/rpm", "rpm_bdb"}};
    for (const auto& f : formats) {
        INFO(f.source);
        Root root;
        root.put(std::string{f.dir} + "/" + f.file, default_fixture_root() / f.capture / f.file);
        pkgdb::Limits lim;
        lim.rpm_max_kept_bytes = 20; // the first package's text alone passes it quickly
        const auto h = read_root(root, lim);
        CHECK(h.failure == std::string{f.source} + ":byte_cap");
        CHECK(h.ecosystem == Eco::none);
        CHECK(h.rpm.empty());
        CHECK(read_root(root).failure.empty()); // control: the default bound admits the same file
    }
}

TEST_CASE("pkgdb fd_source: a read across the end of the file fails, one that ends at it reads",
          "[installed_apps][pkgdb]") {
    // A real file, and a source that claims 4096 bytes more than it holds: the range check passes, so
    // only pread's own end-of-file answer (0 bytes) stands between the reader and bytes that are not
    // there. The EINTR retry in the same loop needs a signal to reach and is not exercised here.
    const fs::path file = default_fixture_root() / "alma8" / "Packages";
    const std::uint64_t size = fs::file_size(file);
    const yuzu::shared::ScopedFile fd{::open(file.c_str(), O_RDONLY | O_CLOEXEC)};
    REQUIRE(fd.valid());
    const auto src = pkgdb::detail::fd_source(fd.fd(), size + 4096);
    std::array<std::uint8_t, 64> buf{};
    CHECK(src.read_at(size - buf.size(), buf)); // ends exactly at the end of the file
    CHECK_FALSE(src.read_at(size - 10, buf));   // ten bytes, then end of file
    CHECK_FALSE(src.read_at(size, buf));        // nothing left at all
    CHECK_FALSE(src.read_at(size + 4096 - 10, buf)); // past the claimed size: refused before any pread
    CHECK(src.read_at(0, buf));
    const std::string text = read_text(file);
    CHECK(std::memcmp(buf.data(), text.data(), buf.size()) == 0);
}

TEST_CASE("pkgdb sqlite: the progress handler is the only deadline poll when the statement returns no row",
          "[installed_apps][pkgdb]") {
    // EDITED input, built here: a database whose `Packages` is a view over a recursive CTE of about
    // 100,000 steps that never yields a row. The per-row poll never runs, so only sqlite's progress
    // handler can end the statement.
    Root root;
    fs::create_directories(root.at("var/lib/rpm"));
    {
        const auto db = open_sqlite(root.at("var/lib/rpm/rpmdb.sqlite"));
        exec_sql(db.get(), "CREATE VIEW Packages(blob) AS WITH RECURSIVE c(x) AS "
                           "(SELECT 1 UNION ALL SELECT x + 1 FROM c WHERE x < 100000) "
                           "SELECT x FROM c WHERE x < 0");
    }
    SECTION("control: with no deadline the statement runs to its end and the database is empty") {
        const auto h = read_root(root);
        CHECK(h.failure.empty());
        CHECK(h.ecosystem == Eco::none);
    }
    SECTION("an expired deadline interrupts it: rpm_sqlite:timeout") {
        const auto h = read_root(root, default_limits(), [] { return true; });
        CHECK(h.failure == "rpm_sqlite:timeout");
        CHECK(h.ecosystem == Eco::none);
        CHECK(h.rpm.empty());
    }
}

// ── mapping ─────────────────────────────────────────────────────────────────

TEST_CASE("pkgdb mapping: dpkg states decide inventory and list membership separately",
          "[installed_apps][pkgdb]") {
    const auto make = [](std::string want, std::string flag, std::string status) {
        return DpkgPackage{"p", "1:2.0-3", "amd64", "Maint <m@x.org>", std::move(want), std::move(flag), std::move(status)};
    };
    struct Case {
        DpkgPackage pkg;
        bool in_inventory;
        bool in_list;
    };
    const Case cases[] = {
        {make("install", "ok", "installed"), true, true},
        // a held package is present and scannable (inventory) but the legacy `list` filter excluded it
        {make("hold", "ok", "installed"), true, false},
        // "deinstall ok installed" contains "install ok installed": the old `list` substring test listed it
        {make("deinstall", "ok", "installed"), true, true},
        {make("purge", "ok", "installed"), true, false},
        {make("install", "reinstreq", "installed"), true, false},
        {make("install", "ok", "half-installed"), false, false},
        {make("install", "ok", "unpacked"), false, false},
        {make("install", "ok", "half-configured"), false, false},
        {make("install", "ok", "triggers-pending"), false, false},
        {make("deinstall", "ok", "config-files"), false, false},
    };
    for (const Case& c : cases) {
        INFO(c.pkg.want << " " << c.pkg.flag << " " << c.pkg.status);
        CHECK(inv::inv_record_from_dpkg(c.pkg).has_value() == c.in_inventory);
        CHECK(parsers::app_record_from_dpkg(c.pkg).has_value() == c.in_list);
    }
    const auto r = inv::inv_record_from_dpkg(make("install", "ok", "installed"));
    REQUIRE(r.has_value());
    CHECK(r->epoch == "1");
    CHECK(r->version == "2.0");
    CHECK(r->release == "3");
    CHECK(r->arch == "amd64");
    CHECK(r->publisher == "Maint <m@x.org>");
    CHECK(r->kind == "package");
    CHECK(r->ecosystem == "deb");
    const auto a = parsers::app_record_from_dpkg(make("install", "ok", "installed"));
    REQUIRE(a.has_value());
    CHECK(a->version == "1:2.0-3"); // `list` carries the raw dpkg version
    CHECK(a->install_date == "-");
}

TEST_CASE("pkgdb mapping: rpm publisher, signature, epoch and date", "[installed_apps][pkgdb]") {
    RpmPackage p;
    p.name = "n";
    p.version = "1.0";
    p.release = "2.el9";
    p.arch = "x86_64";
    p.install_time = 0;
    std::int64_t asked = -1;
    const auto tm_of = [&asked](std::int64_t t) {
        asked = t;
        return utc_tm(t);
    };

    SECTION("vendor, else packager, else empty; list shows the vendor or a dash") {
        p.vendor = "V";
        p.packager = "P";
        CHECK(inv::inv_record_from_rpm(p, tm_of).publisher == "V");
        p.vendor.clear();
        CHECK(inv::inv_record_from_rpm(p, tm_of).publisher == "P");
        p.packager.clear();
        CHECK(inv::inv_record_from_rpm(p, tm_of).publisher.empty());
        CHECK(parsers::app_record_from_rpm(p, tm_of).publisher == "-");
        p.vendor = "V";
        CHECK(parsers::app_record_from_rpm(p, tm_of).publisher == "V");
    }
    SECTION("signed when either stored tag has bytes, unsigned when neither") {
        CHECK(inv::inv_record_from_rpm(p, tm_of).signature_status == "unsigned");
        p.sigpgp = true;
        CHECK(inv::inv_record_from_rpm(p, tm_of).signature_status == "signed");
        p.sigpgp = false;
        p.rsaheader = true;
        CHECK(inv::inv_record_from_rpm(p, tm_of).signature_status == "signed");
    }
    SECTION("an absent epoch reads empty; epoch 0 reads \"0\"") {
        CHECK(inv::inv_record_from_rpm(p, tm_of).epoch.empty());
        p.epoch = 0;
        CHECK(inv::inv_record_from_rpm(p, tm_of).epoch == "0");
        p.epoch = 4000000000u;
        CHECK(inv::inv_record_from_rpm(p, tm_of).epoch == "4000000000");
    }
    SECTION("the date goes through the injected local-time function; absent reads empty") {
        p.install_time = 86400;
        const auto r = inv::inv_record_from_rpm(p, tm_of);
        CHECK(asked == 86400);
        CHECK(r.install_date == "Fri Jan  2 00:00:00 1970");
        CHECK(parsers::app_record_from_rpm(p, tm_of).install_date == "Fri Jan  2 00:00:00 1970");
        p.install_time.reset();
        CHECK(inv::inv_record_from_rpm(p, tm_of).install_date.empty());
        CHECK(parsers::app_record_from_rpm(p, tm_of).install_date.empty());
    }
    SECTION("the list version is VERSION-RELEASE; the inventory splits them") {
        CHECK(parsers::app_record_from_rpm(p, tm_of).version == "1.0-2.el9");
        const auto r = inv::inv_record_from_rpm(p, tm_of);
        CHECK(r.version == "1.0");
        CHECK(r.release == "2.el9");
        CHECK(r.arch == "x86_64");
        CHECK(r.kind == "package");
        CHECK(r.ecosystem == "rpm");
    }
}

// ── degraded contract ───────────────────────────────────────────────────────

TEST_CASE("pkgdb degraded contract: a named reason reaches the typed status and the error row, rc 1, no rows",
          "[installed_apps][pkgdb]") {
    // What the plugin does with a reader failure, driven through the same templates with a recording context.
    Root root;
    root.put_text("var/lib/rpm/rpmdb.sqlite", "SQLite");
    const auto host = read_root(root);
    REQUIRE(host.failure == "rpm_sqlite:corrupt");
    const std::string provenance = "installed_apps:" + host.failure;

    SECTION("list / query / list_per_user") {
        RecCtx ctx;
        CHECK_FALSE(parsers::report_degraded(ctx, true, provenance, provenance));
        CHECK(ctx.status == YUZU_RESULT_STATUS_CONSTRAINED);
        CHECK(ctx.completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
        CHECK(ctx.provenance == "installed_apps:rpm_sqlite:corrupt");
        REQUIRE(ctx.lines.size() == 1);
        CHECK(ctx.lines[0].starts_with("error|installed_apps: acquisition degraded ("));
        CHECK(ctx.lines[0].find("installed_apps:rpm_sqlite:corrupt") != std::string::npos);
        // The subprocess wording does not describe a database read and must not appear.
        CHECK(ctx.lines[0].find("tool timed out") == std::string::npos);
    }
    SECTION("list_inventory emits no rows and returns 1") {
        RecCtx ctx;
        const std::vector<inv::InvRecord> recs{{.name = "would-be-row"}};
        const int rc = parsers::emit_inventory(ctx, true, recs, [](const inv::InvRecord& r) { return r.name; },
                                               provenance);
        CHECK(rc == 1);
        CHECK(ctx.lines.empty());
        CHECK(ctx.status == YUZU_RESULT_STATUS_CONSTRAINED);
        CHECK(ctx.completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
        CHECK(ctx.provenance == "installed_apps:rpm_sqlite:corrupt");
    }
    SECTION("a clean read still declares OK / FULL, and the defaults for other legs are unchanged") {
        RecCtx ok;
        const std::vector<inv::InvRecord> recs{{.name = "row"}};
        CHECK(parsers::emit_inventory(ok, false, recs, [](const inv::InvRecord& r) { return r.name; }, provenance) == 0);
        CHECK(ok.status == YUZU_RESULT_STATUS_OK);
        CHECK(ok.completeness == YUZU_RESULT_COMPLETENESS_FULL);
        RecCtx plain;
        CHECK_FALSE(parsers::report_degraded(plain, true));
        CHECK(plain.provenance == parsers::kDegradedProvenance);
    }
}

// ── the stamp: a file that changes under the read ───────────────────────────

namespace {

// Rewrites byte 0 of `path` with the value it already holds (size and bytes unchanged), restores the
// mtime, and repeats until the file's ctime differs from what it was on entry. Returns whether it
// moved. This is the one case that reads a kernel timestamp: no program can set a ctime, and its
// granularity is the kernel's (one jiffy before Linux 6.13), so the write and the fixture copy before
// it can share a tick and leave the ctime unmoved. The bounded repeat waits that tick out; no sleep.
// A bool, not a REQUIRE: it runs inside the reader's deadline callback, where a throw would unwind
// through sqlite's progress handler.
bool rewrite_byte_restoring_mtime(const fs::path& path) {
    struct stat first {};
    if (::stat(path.c_str(), &first) != 0)
        return false;
    const yuzu::shared::ScopedFile fd{::open(path.c_str(), O_RDWR | O_CLOEXEC)};
    if (!fd.valid())
        return false;
    std::uint8_t byte = 0;
    if (::pread(fd.fd(), &byte, 1, 0) != 1)
        return false;
    const struct timespec times[2] = {{0, UTIME_OMIT}, yuzu::shared::mtime_of(first)};
    const struct timespec before = yuzu::shared::ctime_of(first);
    for (int attempt = 0; attempt < 2'000'000; ++attempt) {
        struct stat now {};
        if (::pwrite(fd.fd(), &byte, 1, 0) != 1 || ::futimens(fd.fd(), times) != 0 ||
            ::fstat(fd.fd(), &now) != 0)
            return false;
        const struct timespec after = yuzu::shared::ctime_of(now);
        if (after.tv_sec != before.tv_sec || after.tv_nsec != before.tv_nsec)
            return true;
    }
    return false;
}

} // namespace

TEST_CASE("pkgdb stamp: a database file that changes during the read is changed_during_read whatever the "
          "read made of it",
          "[installed_apps][pkgdb]") {
    // The expired callback is first polled INSIDE the reader, after the first stamp was taken (ndb once per
    // slot page, bdb at page 1, sqlite per row), so a callback that edits the file is a rewrite under the
    // read. The appended byte leaves the parse valid: the stamp wins over a successful read.
    struct Format {
        const char* capture;
        const char* file;
        const char* dir;
        const char* source;
        std::size_t packages;
    };
    const Format formats[] = {{"tumbleweed", "Packages.db", "usr/lib/sysimage/rpm", "rpm_ndb", 11},
                              {"alma8", "Packages", "var/lib/rpm", "rpm_bdb", 5},
                              {"fedora41", "rpmdb.sqlite", "var/lib/rpm", "rpm_sqlite", 4}};
    for (const auto& f : formats) {
        for (const std::string_view how : {"control", "append a byte", "move only the mtime",
                                           "rewrite a byte in place, mtime restored"}) {
            INFO(f.source << ": " << how);
            Root root;
            const fs::path file =
                root.put(std::string{f.dir} + "/" + f.file, default_fixture_root() / f.capture / f.file);
            const auto mtime_before = fs::last_write_time(file);
            const auto size_before = fs::file_size(file);
            bool ctime_moved = false;
            int polls = 0;
            const auto h = read_root(root, default_limits(), [&] {
                if (++polls == 1) {
                    if (how == "append a byte") { // EDITED copy
                        std::ofstream o(file, std::ios::binary | std::ios::app);
                        o.put('x');
                    } else if (how == "move only the mtime") {
                        fs::last_write_time(file, fs::last_write_time(file) + std::chrono::hours(1));
                    } else if (how == "rewrite a byte in place, mtime restored") {
                        ctime_moved = rewrite_byte_restoring_mtime(file);
                    }
                }
                return false;
            });
            REQUIRE(polls > 0); // the callback really ran inside the read
            if (how == "rewrite a byte in place, mtime restored") {
                // Only the ctime moved: size and mtime are what they were, so the stamp's ctime field
                // alone is what catches this write.
                CHECK(ctime_moved);
                CHECK(fs::file_size(file) == size_before);
                CHECK((fs::last_write_time(file) == mtime_before)); // parenthesised: Catch cannot print a file_time
            }
            if (how == "control") {
                REQUIRE(h.failure.empty());
                CHECK(h.rpm.size() == f.packages);
            } else {
                CHECK(h.failure == std::string{f.source} + ":changed_during_read");
                CHECK(h.ecosystem == Eco::none);
                CHECK(h.rpm.empty());
            }
        }
    }
}

// ── a writer that commits while the read is running ─────────────────────────

namespace {

// A second connection that never waits (busy timeout 0) and never checkpoints (autocheckpoint 0), and
// is kept open until the read returns. Its BEGIN IMMEDIATE / self-assigning UPDATE / COMMIT run once,
// from the reader's first expired poll -- i.e. while the read statement is active.
struct PollWriter {
    explicit PollWriter(const fs::path& db_path) : db{open_sqlite(db_path)} {
        sqlite3_busy_timeout(db.get(), 0);
        sqlite3_wal_autocheckpoint(db.get(), 0);
    }
    SqliteDb db;
    std::array<int, 3> rc{-1, -1, -1}; // BEGIN IMMEDIATE, UPDATE, COMMIT
    int polls = 0;
    bool operator()() {
        if (++polls == 1) {
            rc[0] = sqlite3_exec(db.get(), "BEGIN IMMEDIATE", nullptr, nullptr, nullptr);
            rc[1] = sqlite3_exec(db.get(),
                                 "UPDATE Packages SET blob = blob WHERE hnum = (SELECT max(hnum) FROM Packages)",
                                 nullptr, nullptr, nullptr);
            rc[2] = sqlite3_exec(db.get(), "COMMIT", nullptr, nullptr, nullptr);
        }
        return false;
    }
};

} // namespace

TEST_CASE("pkgdb sqlite: a writer commits DURING the read -- a WAL database never blocks it, a rollback-journal "
          "one makes it wait",
          "[installed_apps][pkgdb]") {
    const fs::path fedora = default_fixture_root() / "fedora41" / "rpmdb.sqlite";

    SECTION("WAL copy without sidecars (read immutable): every writer step succeeds, the read succeeds") {
        Root root;
        const fs::path db = root.put("var/lib/rpm/rpmdb.sqlite", fedora);
        PollWriter writer{db};
        const auto host = read_root(root, default_limits(), [&writer] { return writer(); });
        REQUIRE(writer.polls > 0);
        CHECK(writer.rc == std::array<int, 3>{SQLITE_OK, SQLITE_OK, SQLITE_OK});
        REQUIRE(host.failure.empty());
        CHECK(host.rpm.size() == 4);
    }
    SECTION("WAL copy with a live -wal (read read-only): every writer step succeeds, the read succeeds") {
        Root root;
        const fs::path db = root.put("var/lib/rpm/rpmdb.sqlite", fedora);
        PollWriter writer{db};
        exec_sql(writer.db.get(), "DELETE FROM Packages WHERE hnum = (SELECT min(hnum) FROM Packages)");
        REQUIRE(fs::file_size(root.at("var/lib/rpm/rpmdb.sqlite-wal")) > 0); // the commit lives only in the -wal
        const auto host = read_root(root, default_limits(), [&writer] { return writer(); });
        REQUIRE(writer.polls > 0);
        CHECK(writer.rc == std::array<int, 3>{SQLITE_OK, SQLITE_OK, SQLITE_OK});
        REQUIRE(host.failure.empty());
        CHECK(host.rpm.size() == 3);
    }
    SECTION("EDITED rollback-journal copy: the COMMIT is SQLITE_BUSY during the read, the read succeeds, "
            "and the same COMMIT succeeds once it has returned") {
        // The documented limit, measured: a rollback-journal database is read under a SHARED lock, so a
        // transaction that commits during the read waits for it (at most the wall bound).
        Root root;
        const fs::path db = root.put("var/lib/rpm/rpmdb.sqlite", fedora);
        switch_to_rollback_journal(db);
        PollWriter writer{db};
        const auto host = read_root(root, default_limits(), [&writer] { return writer(); });
        REQUIRE(writer.polls > 0);
        CHECK(writer.rc[0] == SQLITE_OK);
        CHECK(writer.rc[1] == SQLITE_OK);
        CHECK(writer.rc[2] == SQLITE_BUSY);
        REQUIRE(host.failure.empty());
        CHECK(host.rpm.size() == 4);
        CHECK(sqlite3_exec(writer.db.get(), "COMMIT", nullptr, nullptr, nullptr) == SQLITE_OK);
    }
}

// ── delimiter-bearing text and an absent RELEASE, from input bytes to rows ───

namespace {

std::uint32_t be32_at(const std::vector<std::uint8_t>& b, std::size_t o) {
    return (std::uint32_t{b[o]} << 24) | (std::uint32_t{b[o + 1]} << 16) | (std::uint32_t{b[o + 2]} << 8) |
           std::uint32_t{b[o + 3]};
}

// The header blob of the real fedora41 package `name`, read with immutable=1 so nothing is created beside
// the fixture.
std::vector<std::uint8_t> fedora_blob(std::string_view name) {
    sqlite3* raw = nullptr;
    const std::string uri = pkgdb::detail::sqlite_uri((default_fixture_root() / "fedora41" / "rpmdb.sqlite").string(), true);
    const int open_rc = sqlite3_open_v2(uri.c_str(), &raw, SQLITE_OPEN_READONLY | SQLITE_OPEN_URI, nullptr);
    SqliteDb db{raw};
    REQUIRE(open_rc == SQLITE_OK);
    sqlite3_stmt* raw_stmt = nullptr;
    REQUIRE(sqlite3_prepare_v2(db.get(), "SELECT blob FROM Packages ORDER BY hnum", -1, &raw_stmt, nullptr) ==
            SQLITE_OK);
    SqliteStmt stmt{raw_stmt};
    while (sqlite3_step(stmt.get()) == SQLITE_ROW) {
        const auto* p = static_cast<const std::uint8_t*>(sqlite3_column_blob(stmt.get(), 0));
        std::vector<std::uint8_t> blob(p, p + sqlite3_column_bytes(stmt.get(), 0));
        const auto header = yuzu::shared::RpmHeader::parse(blob);
        REQUIRE(header.has_value());
        const auto n = header->text(1000);
        if (n && *n && **n == name)
            return blob;
    }
    FAIL("no such package in the fedora41 capture: " << name);
    return {};
}

// Where a tag sits in a header blob: its index entry (tag, type, offset, count at 8 + 16 * i, big-endian)
// and the absolute offset of its data.
struct TagAt {
    std::size_t entry;
    std::size_t data;
};
TagAt tag_at(const std::vector<std::uint8_t>& blob, std::uint32_t tag) {
    const std::size_t il = be32_at(blob, 0);
    for (std::size_t i = 0; i < il; ++i) {
        const std::size_t e = 8 + 16 * i;
        if (be32_at(blob, e) == tag)
            return {e, 8 + 16 * il + be32_at(blob, e + 8)};
    }
    FAIL("tag " << tag << " not in the header");
    return {};
}

// Both edits keep every length, so the header stays structurally valid.
void overwrite_string_prefix(std::vector<std::uint8_t>& blob, std::uint32_t tag, std::string_view with) {
    const TagAt at = tag_at(blob, tag);
    for (std::size_t i = 0; i < with.size(); ++i) {
        REQUIRE(blob[at.data + i] != 0); // inside the value, not past its NUL
        blob[at.data + i] = static_cast<std::uint8_t>(with[i]);
    }
}
void renumber_tag(std::vector<std::uint8_t>& blob, std::uint32_t tag) {
    const TagAt at = tag_at(blob, tag);
    constexpr std::uint32_t kUnusedTag = 60001; // outside rpm's tag space; find() is a linear scan
    blob[at.entry] = static_cast<std::uint8_t>(kUnusedTag >> 24);
    blob[at.entry + 1] = static_cast<std::uint8_t>(kUnusedTag >> 16);
    blob[at.entry + 2] = static_cast<std::uint8_t>(kUnusedTag >> 8);
    blob[at.entry + 3] = static_cast<std::uint8_t>(kUnusedTag);
}

// A one-package rpm sqlite database holding exactly `blob`.
void write_one_package_db(const Root& root, const std::vector<std::uint8_t>& blob) {
    fs::create_directories(root.at("var/lib/rpm"));
    const auto db = open_sqlite(root.at("var/lib/rpm/rpmdb.sqlite"));
    exec_sql(db.get(), "PRAGMA synchronous=OFF; CREATE TABLE Packages(hnum INTEGER PRIMARY KEY, blob BLOB)");
    sqlite3_stmt* raw_stmt = nullptr;
    REQUIRE(sqlite3_prepare_v2(db.get(), "INSERT INTO Packages(blob) VALUES (?)", -1, &raw_stmt, nullptr) == SQLITE_OK);
    SqliteStmt stmt{raw_stmt};
    REQUIRE(sqlite3_bind_blob(stmt.get(), 1, blob.data(), static_cast<int>(blob.size()), SQLITE_STATIC) == SQLITE_OK);
    REQUIRE(sqlite3_step(stmt.get()) == SQLITE_DONE);
}

std::vector<std::string> split_on(const std::string& row, char sep) {
    std::vector<std::string> out;
    std::size_t at = 0;
    for (;;) {
        const std::size_t next = row.find(sep, at);
        if (next == std::string::npos) {
            out.push_back(row.substr(at));
            return out;
        }
        out.push_back(row.substr(at, next - at));
        at = next + 1;
    }
}

// Tokens of a row on its UNESCAPED '|' (a '\|' is part of a token).
std::size_t unescaped_pipes(const std::string& row) {
    std::size_t n = 0;
    for (std::size_t i = 0; i < row.size(); ++i) {
        if (row[i] == '\\')
            ++i; // skip the escaped character
        else if (row[i] == '|')
            ++n;
    }
    return n;
}

// The only row of a one-package host, in each wire form.
std::string only_inv_row(const pkgdb::HostPackages& h) {
    const auto rows = new_inv_rows(h);
    REQUIRE(rows.size() == 1);
    return rows[0];
}
std::string only_list_row(const pkgdb::HostPackages& h) {
    const auto rows = new_list_rows(h);
    REQUIRE(rows.size() == 1);
    return rows[0];
}

// `row` with token `index` (split on a plain '|') replaced; the pristine rows have no escaped pipe.
std::string with_token(const std::string& row, std::size_t index, const std::string& token) {
    auto parts = split_on(row, '|');
    REQUIRE(index < parts.size());
    parts[index] = token;
    std::string out;
    for (std::size_t i = 0; i < parts.size(); ++i)
        out += (i ? "|" : "") + parts[i];
    return out;
}

constexpr std::size_t kInvVersion = 2, kInvPublisher = 3, kInvRelease = 8;
constexpr std::size_t kListVersion = 2, kListPublisher = 3;

} // namespace

TEST_CASE("pkgdb rows: a Maintainer holding a pipe and a tab keeps its whole value in one row (EDITED real "
          "debian12 stanza)",
          "[installed_apps][pkgdb]") {
    // EDITED: the real libacl1 stanza with its Maintainer replaced. The old line parsers cut the value at
    // the first tab and the row at the pipe; the readers keep the value whole and the formatter strips
    // (inv) or escapes (list) the separators.
    const auto [rest, stanza] = split_stanza("libacl1");
    const std::size_t at = stanza.find("Maintainer: ");
    REQUIRE(at != std::string::npos);
    std::string edited = stanza;
    edited.replace(at, edited.find('\n', at) - at, "Maintainer: Pkg|Team\tOps");
    Root root;
    root.put_text("var/lib/dpkg/status", edited);
    const auto h = read_root(root);
    REQUIRE(h.failure.empty());
    REQUIRE(h.dpkg.size() == 1);
    CHECK(h.dpkg[0].maintainer == "Pkg|Team\tOps");

    const std::string inv_row = only_inv_row(h);
    CHECK(inv_row == "inv|libacl1|2.3.1|PkgTeamOps||package|deb||3|arm64||||");
    CHECK(unescaped_pipes(inv_row) == 13);
    const std::string list_row = only_list_row(h);
    CHECK(list_row == "app|libacl1|2.3.1-3|Pkg\\|Team\tOps|-|-|-");
    CHECK(unescaped_pipes(list_row) == 6);
}

TEST_CASE("pkgdb rows: a VENDOR holding a pipe, a tab and a newline keeps its whole value in one row (EDITED "
          "real fedora41 header)",
          "[installed_apps][pkgdb]") {
    Root pristine_root;
    pristine_root.put("var/lib/rpm/rpmdb.sqlite", default_fixture_root() / "fedora41" / "rpmdb.sqlite");
    const auto pristine = read_root(pristine_root);
    REQUIRE(pristine.failure.empty());
    const auto find_row = [](const std::vector<std::string>& rows, std::string_view prefix) {
        const auto it = std::find_if(rows.begin(), rows.end(),
                                     [&](const std::string& r) { return r.starts_with(prefix); });
        REQUIRE(it != rows.end());
        return *it;
    };
    const std::string pristine_inv = find_row(new_inv_rows(pristine), "inv|libssh-config|");
    const std::string pristine_list = find_row(new_list_rows(pristine), "app|libssh-config|");
    REQUIRE(pristine_inv.find("|Fedora Project|") != std::string::npos);

    // EDITED in memory: the first three bytes of VENDOR ("Fed") become a pipe, a tab and a newline.
    auto blob = fedora_blob("libssh-config");
    overwrite_string_prefix(blob, 1011, "|\t\n");
    Root root;
    write_one_package_db(root, blob);
    const auto h = read_root(root);
    REQUIRE(h.failure.empty());
    REQUIRE(h.rpm.size() == 1);
    CHECK(h.rpm[0].vendor == "|\t\nora Project");

    const std::string inv_row = only_inv_row(h);
    CHECK(inv_row == with_token(pristine_inv, kInvPublisher, "ora Project")); // separators stripped, one row
    CHECK(unescaped_pipes(inv_row) == 13);
    const std::string list_row = only_list_row(h);
    CHECK(list_row == with_token(pristine_list, kListPublisher, "\\|\t ora Project")); // '|' escaped, newline a space
    CHECK(unescaped_pipes(list_row) == 6);
}

TEST_CASE("pkgdb rows: PACKAGER is the inventory publisher when VENDOR is absent, delimiters stripped (EDITED real "
          "fedora41 header)",
          "[installed_apps][pkgdb]") {
    auto blob = fedora_blob("libssh-config");
    renumber_tag(blob, 1011);                      // EDITED: VENDOR now an unused tag, i.e. absent
    overwrite_string_prefix(blob, 1015, "|\t\n");  // EDITED: PACKAGER's first three bytes
    Root root;
    write_one_package_db(root, blob);
    const auto h = read_root(root);
    REQUIRE(h.failure.empty());
    REQUIRE(h.rpm.size() == 1);
    CHECK(h.rpm[0].vendor.empty());
    CHECK(h.rpm[0].packager == "|\t\nora Project");

    const std::string inv_row = only_inv_row(h);
    CHECK(split_on(inv_row, '|')[kInvPublisher] == "ora Project"); // the fallback, separators stripped
    CHECK(unescaped_pipes(inv_row) == 13);
    // `list` shows the VENDOR only: absent reads "-" whatever PACKAGER holds.
    const std::string list_row = only_list_row(h);
    CHECK(split_on(list_row, '|')[kListPublisher] == "-");
    CHECK(unescaped_pipes(list_row) == 6);
}

TEST_CASE("pkgdb rows: an absent RELEASE reads empty in the inventory and as VERSION- in the list (EDITED real "
          "fedora41 header)",
          "[installed_apps][pkgdb]") {
    auto blob = fedora_blob("libssh-config");
    renumber_tag(blob, 1002); // EDITED: RELEASE now an unused tag, i.e. absent; the other tags still resolve
    Root root;
    write_one_package_db(root, blob);
    const auto h = read_root(root);
    REQUIRE(h.failure.empty());
    REQUIRE(h.rpm.size() == 1);
    CHECK(h.rpm[0].release.empty());
    CHECK(h.rpm[0].version == "0.11.3");

    const auto inv_tokens = split_on(only_inv_row(h), '|');
    REQUIRE(inv_tokens.size() == 14);
    CHECK(inv_tokens[kInvVersion] == "0.11.3");
    CHECK(inv_tokens[kInvRelease].empty());
    CHECK(split_on(only_list_row(h), '|')[kListVersion] == "0.11.3-");
}

// ── the bounded form ────────────────────────────────────────────────────────

namespace {

// A reader parked on a latch: stands in for a pread on a wedged volume. State is shared, so the worker
// (which may outlive the call) never points at the test's stack.
struct Parked {
    std::mutex m;
    std::condition_variable cv;
    bool release = false;
    bool exited = false;
};

pkgdb::HostReader parked_reader(std::shared_ptr<Parked> st) {
    return [st](const std::string&, const pkgdb::Limits&, const std::function<bool()>&) {
        std::unique_lock lock(st->m);
        st->cv.wait(lock, [&] { return st->release; });
        st->exited = true;
        st->cv.notify_all();
        return pkgdb::HostPackages{};
    };
}

} // namespace

TEST_CASE("pkgdb bounded: a completed read returns its rows; a parked reader is given up on at the wall",
          "[installed_apps][pkgdb]") {
    using yuzu::shared::detail::g_outstanding_bounded_calls;

    SECTION("a fixture root completes with rows") {
        Root root;
        root.put("var/lib/dpkg/status", default_fixture_root() / "debian12" / "status");
        const auto h = pkgdb::read_host_packages_bounded(root.str(), default_limits());
        REQUIRE(h.failure.empty());
        CHECK(h.ecosystem == Eco::dpkg);
        CHECK(h.dpkg.size() == 10);
    }
    SECTION("a reader that never returns is pkgdb:timeout with no rows; released, its worker ends") {
        const int baseline = g_outstanding_bounded_calls.load();
        auto st = std::make_shared<Parked>();
        pkgdb::Limits lim;
        lim.wall = std::chrono::milliseconds{30};
        const auto h = pkgdb::read_host_packages_bounded("/does/not/matter", lim, {}, parked_reader(st));
        CHECK(h.failure == "pkgdb:timeout");
        CHECK(h.ecosystem == Eco::none);
        CHECK(h.dpkg.empty());
        CHECK(h.rpm.empty());
        {
            std::lock_guard lock(st->m);
            st->release = true;
        }
        st->cv.notify_all();
        std::unique_lock lock(st->m);
        st->cv.wait(lock, [&] { return st->exited; }); // the reader is done; every capture of the worker is by value
        lock.unlock();
        // The worker gives its slot on the ceiling back when its lambda is destroyed, a moment after the
        // reader returns; wait for it (a completion, not a delay) so no later case sees the straggler.
        while (g_outstanding_bounded_calls.load() > baseline)
            std::this_thread::yield();
    }
    SECTION("with the ceiling saturated the answer is pkgdb:busy and the reader never runs") {
        using yuzu::shared::detail::kMaxOutstandingBoundedCalls;
        using yuzu::shared::detail::OutstandingCallGuard;
        std::vector<OutstandingCallGuard> held;
        while (g_outstanding_bounded_calls.load() <= kMaxOutstandingBoundedCalls) {
            auto g = OutstandingCallGuard::try_acquire();
            if (!g)
                break;
            held.push_back(std::move(*g));
        }
        auto ran = std::make_shared<std::atomic<bool>>(false);
        const pkgdb::HostReader reader = [ran](const std::string&, const pkgdb::Limits&,
                                               const std::function<bool()>&) {
            ran->store(true);
            return pkgdb::HostPackages{};
        };
        const auto h = pkgdb::read_host_packages_bounded("/does/not/matter", default_limits(), {}, reader);
        held.clear(); // release the ceiling for later cases
        CHECK(h.failure == "pkgdb:busy");
        CHECK_FALSE(ran->load());
    }
    SECTION("a true stop predicate ends a real read with a :timeout cause") {
        Root root;
        root.put("var/lib/rpm/rpmdb.sqlite", default_fixture_root() / "fedora41" / "rpmdb.sqlite");
        const auto h = pkgdb::read_host_packages_bounded(root.str(), default_limits(), [] { return true; });
        CHECK(h.failure == "rpm_sqlite:timeout");
        CHECK(h.rpm.empty());
        CHECK(h.ecosystem == Eco::none);
    }
    SECTION("a stop predicate that stays false changes nothing") {
        Root root;
        root.put("var/lib/rpm/rpmdb.sqlite", default_fixture_root() / "fedora41" / "rpmdb.sqlite");
        const auto h = pkgdb::read_host_packages_bounded(root.str(), default_limits(), [] { return false; });
        CHECK(h.failure.empty());
        CHECK(h.rpm.size() == 4);
    }
    SECTION("a reader that throws is pkgdb:unreadable at once, not a wall-long pkgdb:timeout") {
        // Default 20 s wall: if the throw were left to bounded_call_ex this call would wait it out and
        // answer pkgdb:timeout. A std exception and a non-std one are both caught.
        const pkgdb::HostReader bad_alloc = [](const std::string&, const pkgdb::Limits&,
                                               const std::function<bool()>&) -> pkgdb::HostPackages {
            throw std::bad_alloc{};
        };
        const pkgdb::HostReader not_std = [](const std::string&, const pkgdb::Limits&,
                                             const std::function<bool()>&) -> pkgdb::HostPackages { throw 42; };
        for (const auto& reader : {bad_alloc, not_std}) {
            const auto h = pkgdb::read_host_packages_bounded("/does/not/matter", default_limits(), {}, reader);
            CHECK(h.failure == "pkgdb:unreadable");
            CHECK(h.ecosystem == Eco::none);
            CHECK(h.dpkg.empty());
            CHECK(h.rpm.empty());
        }
    }
}

TEST_CASE("pkgdb limits: the defaults the plugin runs with are bounded in rows, bytes and time",
          "[installed_apps][pkgdb]") {
    // The closed vocabulary of causes is pinned from production in test_rpmdb_parsers.cpp (every
    // PkgDbCause through pkgdb_cause_token), and every failure the shell produces is asserted by exact
    // token in the cases above; the tokens of the bounded wrapper are asserted below.
    const pkgdb::Limits lim{};
    CHECK(lim.max_packages == 50000);
    CHECK(lim.dpkg_max_bytes == 32ull * 1024 * 1024);
    CHECK(lim.rpm_max_header_bytes == 32ull * 1024 * 1024);
    CHECK(lim.rpm_max_total_bytes == (1ull << 30));
    CHECK(lim.rpm_max_kept_bytes == 8ull * 1024 * 1024);
    CHECK(lim.wall == std::chrono::seconds{20});
    CHECK(lim.sqlite_busy_ms == 2000);
}

#endif // !_WIN32
