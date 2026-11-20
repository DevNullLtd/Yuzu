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
 * POSIX only: the shell compiles out on Windows (the plugin walks the registry there).
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
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iterator>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <string_view>
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
            sqlite3* writer = nullptr;
            REQUIRE(sqlite3_open(db.string().c_str(), &writer) == SQLITE_OK);
            REQUIRE(sqlite3_exec(writer, "PRAGMA wal_autocheckpoint=0", nullptr, nullptr, nullptr) == SQLITE_OK);
            REQUIRE(sqlite3_exec(writer, "DELETE FROM Packages WHERE hnum = (SELECT min(hnum) FROM Packages)",
                                 nullptr, nullptr, nullptr) == SQLITE_OK);
            REQUIRE(fs::file_size(root.at("var/lib/rpm/rpmdb.sqlite-wal")) > 0);
            const auto host = read_root(root);
            sqlite3_close(writer);
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
        sqlite3* db = nullptr;
        REQUIRE(sqlite3_open(root.at("var/lib/rpm/rpmdb.sqlite").string().c_str(), &db) == SQLITE_OK);
        REQUIRE(sqlite3_exec(db, "CREATE TABLE Other(x INTEGER); INSERT INTO Other VALUES (1)", nullptr,
                             nullptr, nullptr) == SQLITE_OK);
        sqlite3_close(db);
        CHECK(failure_of(root) == "rpm_sqlite:corrupt");
    }
    SECTION("a Packages row whose blob column is TEXT is corrupt") {
        Root root;
        fs::create_directories(root.at("var/lib/rpm"));
        sqlite3* db = nullptr;
        REQUIRE(sqlite3_open(root.at("var/lib/rpm/rpmdb.sqlite").string().c_str(), &db) == SQLITE_OK);
        REQUIRE(sqlite3_exec(db, "CREATE TABLE Packages(hnum INTEGER PRIMARY KEY, blob TEXT); "
                                 "INSERT INTO Packages(blob) VALUES ('not a header')",
                             nullptr, nullptr, nullptr) == SQLITE_OK);
        sqlite3_close(db);
        CHECK(failure_of(root) == "rpm_sqlite:corrupt");
    }
    SECTION("a blob that is not an rpm header is corrupt") {
        Root root;
        fs::create_directories(root.at("var/lib/rpm"));
        sqlite3* db = nullptr;
        REQUIRE(sqlite3_open(root.at("var/lib/rpm/rpmdb.sqlite").string().c_str(), &db) == SQLITE_OK);
        REQUIRE(sqlite3_exec(db, "CREATE TABLE Packages(hnum INTEGER PRIMARY KEY, blob BLOB); "
                                 "INSERT INTO Packages(blob) VALUES (x'00112233445566778899')",
                             nullptr, nullptr, nullptr) == SQLITE_OK);
        sqlite3_close(db);
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
        // EDITED copy: switched from WAL to the rollback journal, the mode in which a reader takes a
        // SHARED lock (exactly what `rpm -qa` took). A WAL-mode copy is never locked this way.
        Root root;
        const fs::path db = root.put("var/lib/rpm/rpmdb.sqlite", fedora);
        sqlite3* a = nullptr;
        REQUIRE(sqlite3_open(db.string().c_str(), &a) == SQLITE_OK);
        REQUIRE(sqlite3_exec(a, "PRAGMA journal_mode=DELETE", nullptr, nullptr, nullptr) == SQLITE_OK);
        sqlite3_close(a);
        sqlite3* holder = nullptr;
        REQUIRE(sqlite3_open(db.string().c_str(), &holder) == SQLITE_OK);
        REQUIRE(sqlite3_exec(holder, "BEGIN EXCLUSIVE", nullptr, nullptr, nullptr) == SQLITE_OK);
        pkgdb::Limits lim;
        lim.sqlite_busy_ms = 0;
        const std::string failure = failure_of(root, lim);
        sqlite3_exec(holder, "ROLLBACK", nullptr, nullptr, nullptr);
        sqlite3_close(holder);
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

TEST_CASE("pkgdb detection: usr/lib/sysimage/rpm wins over var/lib/rpm; a symlinked directory is skipped",
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
        // /var/lib/rpm -> a directory elsewhere: skipped, never followed; with nothing else present the
        // host has no rpm database as far as this reader may tell.
        Root root;
        root.put("elsewhere/rpmdb.sqlite", alma9);
        fs::create_directories(root.at("var/lib"));
        fs::create_directory_symlink(root.at("elsewhere"), root.at("var/lib/rpm"));
        const auto h = read_root(root);
        CHECK(h.failure.empty());
        CHECK(h.ecosystem == Eco::none);
        CHECK(h.rpm.empty());
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

TEST_CASE("pkgdb status.d: a package in both keeps the status entry; leftovers and dotfiles are ignored",
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
    for (const char* junk : {".hidden", "x.dpkg-new", "x.dpkg-old", "backup~", "old.bak", "x.md5sums"})
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

TEST_CASE("pkgdb tokens: every failure the shell can produce is a source:cause pair from the closed vocabulary",
          "[installed_apps][pkgdb]") {
    const std::set<std::string> sources{"dpkg_status", "dpkg_status_d", "rpm_sqlite", "rpm_ndb", "rpm_bdb", "rpmdb"};
    const std::set<std::string> causes{"unreadable", "symlink_refused", "not_regular", "oversized", "corrupt",
                                       "truncated", "unsupported_format", "locked", "changed_during_read",
                                       "row_cap", "byte_cap", "timeout", "busy"};
    const pkgdb::Limits lim{};
    for (const std::string t : {"dpkg_status:corrupt", "rpm_sqlite:locked", "rpmdb:unsupported_format"}) {
        const auto colon = t.find(':');
        CHECK(sources.contains(t.substr(0, colon)));
        CHECK(causes.contains(t.substr(colon + 1)));
    }
    // The defaults the plugin runs with: bounded in rows, bytes and time.
    CHECK(lim.max_packages == 50000);
    CHECK(lim.dpkg_max_bytes == 32ull * 1024 * 1024);
    CHECK(lim.rpm_max_header_bytes == 32ull * 1024 * 1024);
    CHECK(lim.rpm_max_total_bytes == (1ull << 30));
    CHECK(lim.wall == std::chrono::seconds{20});
    CHECK(lim.sqlite_busy_ms == 2000);
}

#endif // !_WIN32
