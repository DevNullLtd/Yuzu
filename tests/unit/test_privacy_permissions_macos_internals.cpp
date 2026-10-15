/**
 * test_privacy_permissions_macos_internals.cpp -- TU-inclusion seam over
 * privacy_permissions_macos.cpp's internal-linkage `open_readonly`, `read_tcc_source` and
 * `read_all_sources`. The binding contract's single most important property -- a refused TCC.db
 * open must never collapse into `absent` -- is proven here against the real open this leg
 * makes, not only at the pure layer.
 *
 * Both take the db path as a parameter specifically so this test can
 * force each outcome branch deterministically, without a non-FDA identity and without touching
 * any real TCC.db: a missing per-user db must read `absent`, a missing SYSTEM db `unreadable`, a
 * present-but-unopenable file (mode 000, the same refusal an SIP/TCC denial produces) `denied`
 * -- never absent -- and a hostile file (view, WAL, sidecar, oversized) is bounded or refused.
 * Every database here is synthetic, built under a TempDir; the deadline is an injected budget,
 * never a sleep.
 *
 * #if defined(__APPLE__) guards the WHOLE body -- empty TU elsewhere, mirroring every other
 * Apple-only internals-seam test in this tree (test_autoruns_macos_local.cpp's seam is the
 * direct precedent this file copies).
 */
#if !defined(__APPLE__)

// Nothing to test off macOS -- see the file banner above.

#else // defined(__APPLE__)

#include <catch2/catch_test_macros.hpp>

#include <algorithm>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#include <cstdlib>
#include <cstring>

#include <fcntl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>

#include "test_helpers.hpp"

// Direct source inclusion, macOS-only, mirroring autoruns_macos.cpp's
// YUZU_AUTORUNS_MACOS_UNIT_TEST_INTERNALS_ONLY seam (see that file's own banner, and
// YUZU_PRIVACY_PERMISSIONS_MACOS_UNIT_TEST_INTERNALS_ONLY's definition comment in
// privacy_permissions_macos.cpp): `open_readonly`, `read_tcc_source`, `run_collection` and friends have
// internal (anonymous-namespace) linkage, so there is no header seam to reach them through
// otherwise. This TU never statically links the real plugin either way
// (test_privacy_permissions_local_dispatcher.cpp loads it via PluginHandle::load/dlopen at
// runtime), so a second compilation of the same free functions here creates no ODR/duplicate-
// symbol conflict.
#define YUZU_PRIVACY_PERMISSIONS_MACOS_UNIT_TEST_INTERNALS_ONLY 1
#include "../../agents/plugins/privacy_permissions/src/privacy_permissions_macos.cpp"
#undef YUZU_PRIVACY_PERMISSIONS_MACOS_UNIT_TEST_INTERNALS_ONLY

namespace yuzu::privacy_permissions {

namespace {

constexpr std::string_view kAccessSchema =
    "CREATE TABLE access(service TEXT, client TEXT, client_type INTEGER, auth_value INTEGER, "
    "PRIMARY KEY(service, client, client_type));";

// Canonical: the temp dir sits under the /var -> /private/var symlink O_NOFOLLOW_ANY refuses.
std::filesystem::path scratch_dir(const yuzu::test::TempDir& tmp) {
    std::filesystem::create_directories(tmp.path);
    return std::filesystem::canonical(tmp.path);
}

void make_db(const std::filesystem::path& path, const std::string& sql) {
    sqlite3* raw = nullptr;
    REQUIRE(sqlite3_open_v2(path.c_str(), &raw, SQLITE_OPEN_READWRITE | SQLITE_OPEN_CREATE,
                            nullptr) == SQLITE_OK);
    const DbPtr db{raw};
    REQUIRE(sqlite3_exec(db.get(), sql.c_str(), nullptr, nullptr, nullptr) == SQLITE_OK);
}

std::vector<std::string> listing(const std::filesystem::path& dir) {
    std::vector<std::string> names;
    for (const auto& e : std::filesystem::directory_iterator(dir))
        names.push_back(e.path().filename().string());
    std::sort(names.begin(), names.end());
    return names;
}

struct SourceRead {
    std::vector<PermissionRow> rows;
    yuzu::shared::ConstraintAccumulator acc;

    [[nodiscard]] std::size_t count(std::string_view category, PermissionState state) const {
        return static_cast<std::size_t>(std::count_if(rows.begin(), rows.end(), [&](const auto& r) {
            return r.category == category && r.state == state;
        }));
    }
    [[nodiscard]] bool has_raw(std::string_view raw) const {
        return std::any_of(rows.begin(), rows.end(), [&](const auto& r) { return r.raw == raw; });
    }
};

SourceRead read_source(const std::filesystem::path& db, const macos::ReadBounds& bounds = {}) {
    SourceRead r;
    read_tcc_source("evil", db.string(), /*missing_is_absent=*/true, r.rows, r.acc, bounds);
    return r;
}

} // namespace

TEST_CASE("privacy_permissions macOS: open_readonly on a genuinely unopenable path fails "
          "through the same generic path a real TCC/SIP denial would, with a real "
          "sqlite3_errmsg diagnostic",
          "[privacy_permissions][macos][internals]") {
    const auto db = open_readonly("/nonexistent/deliberately-broken/privacy_permissions_test.db");
    REQUIRE_FALSE(db.has_value());
    const auto& failure = db.error();
    CHECK(failure.cause.rfind("open_failed:", 0) == 0);
    CHECK(failure.cause.size() > std::string_view{"open_failed:"}.size());
    // A missing parent directory is SQLITE_CANTOPEN with ENOENT from the VFS -- not a refusal.
    CHECK(failure.outcome == macos::SourceOutcome::unreadable);
}

TEST_CASE("privacy_permissions macOS: read_tcc_source on a MISSING per-user db is one absent "
          "row with no token; a missing SYSTEM db is unreadable, never absent",
          "[privacy_permissions][macos][internals]") {
    yuzu::test::TempDir tmp{"yuzu_test_pp_missing_"};
    // Canonical: O_NOFOLLOW_ANY refuses the /var -> /private/var symlink before it can report ENOENT.
    const std::string missing = (scratch_dir(tmp) / "no_such_dir" / "TCC.db").string();

    yuzu::shared::ConstraintAccumulator user_acc;
    std::vector<PermissionRow> user_rows;
    read_tcc_source("alice", missing, /*missing_is_absent=*/true, user_rows, user_acc);
    REQUIRE(user_rows.size() == 1);
    CHECK(format_row(user_rows[0]) == "permissions|macos|alice/-|-|absent|-|-|-");
    CHECK_FALSE(user_acc.any_failure());

    yuzu::shared::ConstraintAccumulator sys_acc;
    std::vector<PermissionRow> sys_rows;
    read_tcc_source({}, missing, /*missing_is_absent=*/false, sys_rows, sys_acc);
    REQUIRE(sys_rows.size() == 1);
    CHECK(sys_rows[0].state == PermissionState::unreadable);
    CHECK(sys_rows[0].raw == "tcc_db:missing");
    CHECK(select_status(sys_acc, any_denied(sys_rows), false).status ==
          YUZU_RESULT_STATUS_CONSTRAINED);
}

TEST_CASE("privacy_permissions macOS: read_tcc_source on a PRESENT file the process cannot open "
          "(mode 000 -- the same SQLITE_CANTOPEN a TCC refusal produces) is denied and promotes "
          "PERMISSION_DENIED, never absent",
          "[privacy_permissions][macos][internals]") {
    if (::geteuid() == 0) SKIP("root ignores mode 000 -- the refusal cannot be forced here");
    yuzu::test::TempDir tmp{"yuzu_test_pp_tcc_"};
    const auto path = scratch_dir(tmp) / "TCC.db";
    { std::ofstream{path} << "x"; }
    REQUIRE(::chmod(path.c_str(), 0) == 0);

    yuzu::shared::ConstraintAccumulator acc;
    std::vector<PermissionRow> rows;
    read_tcc_source("alice", path.string(), /*missing_is_absent=*/true, rows, acc);

    REQUIRE(rows.size() == 1);
    CHECK(rows[0].app_id == "alice\\-");
    CHECK(rows[0].state == PermissionState::denied);
    CHECK(rows[0].read_denied);
    CHECK(rows[0].raw.rfind("alice:tcc_db:open_failed:", 0) == 0);
    const auto st = select_status(acc, any_denied(rows), false);
    CHECK(st.status == YUZU_RESULT_STATUS_PERMISSION_DENIED);
    CHECK(st.completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
}

TEST_CASE("privacy_permissions macOS: read_tcc_source through a SYMLINKED directory is refused by "
          "O_NOFOLLOW_ANY as unreadable, never a false denied",
          "[privacy_permissions][macos][internals]") {
    yuzu::test::TempDir tmp{"yuzu_test_pp_link_"};
    const auto base = scratch_dir(tmp); // no symlink but the one below
    const auto real_dir = base / "real";
    const auto link_dir = base / "link";
    std::filesystem::create_directories(real_dir);
    std::filesystem::create_directory_symlink(real_dir, link_dir);
    make_db(real_dir / "TCC.db", std::string{kAccessSchema});

    yuzu::shared::ConstraintAccumulator acc;
    std::vector<PermissionRow> rows;
    read_tcc_source("alice", (link_dir / "TCC.db").string(), /*missing_is_absent=*/true, rows, acc);

    REQUIRE(rows.size() == 1);
    CHECK(rows[0].state == PermissionState::unreadable);
    CHECK_FALSE(rows[0].read_denied);
    CHECK(rows[0].raw == "alice:tcc_db:open_failed:symlink");
    CHECK(select_status(acc, any_denied(rows), false).status == YUZU_RESULT_STATUS_CONSTRAINED);
}

TEST_CASE("privacy_permissions macOS: a db reads sorted, whatever the path's spelling, "
          "with a 64-bit auth_value and hostile bytes sanitized, and the directory is untouched",
          "[privacy_permissions][macos][internals]") {
    yuzu::test::TempDir tmp{"yuzu_test_pp_honest_"};
    const auto dir = scratch_dir(tmp) / "q?x# h%20";
    std::filesystem::create_directories(dir);
    make_db(dir / "TCC.db", // a view: scan order is the UNION order, so the sort is observable
            "CREATE VIEW access AS SELECT 'kTCCServiceCamera' AS service, CAST(x'C328FF41' AS TEXT) "
            "AS client, 0 AS client_type, 2 AS auth_value UNION ALL SELECT 'kTCCServiceCamera', "
            "'b.app', 0, 4294967298 UNION ALL SELECT 'kTCCServiceCamera', 'a.app', 0, 0;");
    const auto before = listing(dir);

    CHECK(open_readonly((dir / "TCC.db").string()).has_value()); // the URI builder round-trips it
    const auto r = read_source(dir / "TCC.db");
    REQUIRE(r.rows.size() == 5);
    CHECK(format_row(r.rows[0]) == "permissions|macos|evil/a.app|camera|denied|0|-|-");
    CHECK(r.rows[1].state == PermissionState::prompt_undetermined);
    CHECK(r.rows[1].raw == "4294967298");
    CHECK(format_row(r.rows[2]) == "permissions|macos|evil/\xEF\xBF\xBD(\xEF\xBF\xBD"
                                   "A|camera|allowed|2|-|-"); // split: 'A' extends a hex escape
    CHECK(r.count("microphone", PermissionState::absent) == 1);
    CHECK_FALSE(r.acc.any_failure());
    CHECK(listing(dir) == before);
}

TEST_CASE("privacy_permissions macOS: a hostile view is cut at the row cap, never read to the end",
          "[privacy_permissions][macos][internals]") {
    yuzu::test::TempDir tmp{"yuzu_test_pp_view_"};
    const auto db = scratch_dir(tmp) / "TCC.db";
    make_db(db,
            "CREATE VIEW access AS WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n "
            "LIMIT 5000) SELECT 'kTCCServiceCamera' AS service, 'c'||i AS client, 0 AS "
            "client_type, 2 AS auth_value FROM n;");

    const auto r = read_source(db);
    CHECK(r.count("camera", PermissionState::allowed) == macos::kMaxRowsPerService);
    CHECK(r.has_raw("evil:tcc_db:camera:row_cap"));
    CHECK(r.rows.size() <= macos::kMaxRowsPerService + 3);
    CHECK(select_status(r.acc, any_denied(r.rows), false).status == YUZU_RESULT_STATUS_CONSTRAINED);
}

TEST_CASE("privacy_permissions macOS: anything that is not one quiescent rollback-mode SQLite file "
          "is refused with a named cause, and nothing is created or opened beside it",
          "[privacy_permissions][macos][internals]") {
    yuzu::test::TempDir tmp{"yuzu_test_pp_refuse_"};
    const auto dir = scratch_dir(tmp);
    const auto db = dir / "TCC.db";
    const std::string honest =
        std::string{kAccessSchema} + "INSERT INTO access VALUES('kTCCServiceCamera','a.app',0,2);";

    make_db(db, "PRAGMA journal_mode=WAL;" + honest);
    const auto before = listing(dir);
    CHECK(read_source(db).rows.at(0).raw == "evil:tcc_db:wal_mode");
    CHECK(listing(dir) == before);
    std::filesystem::remove(db);

    make_db(db, honest);
    for (const char* suffix : {"-wal", "-journal", "-shm"}) {
        { std::ofstream{db.string() + suffix}; }
        const auto with_sidecar = listing(dir);
        const auto r = read_source(db);
        INFO(suffix);
        REQUIRE(r.rows.size() == 1);
        CHECK(r.rows[0].raw == "evil:tcc_db:sidecar_present");
        CHECK(listing(dir) == with_sidecar);
        std::filesystem::remove(db.string() + suffix);
    }
    if (::mkfifo((db.string() + "-journal").c_str(), 0600) == 0) // lstat never opens it
        CHECK(read_source(db).rows.at(0).raw == "evil:tcc_db:sidecar_present");

    { std::ofstream{dir / "empty.db"}; }
    { std::ofstream{dir / "junk.db"} << std::string(300, 'x'); }
    REQUIRE(::mkfifo((dir / "fifo.db").c_str(), 0600) == 0);
    CHECK(read_source(dir / "empty.db").rows.at(0).raw == "evil:tcc_db:size_out_of_range");
    CHECK(read_source(dir / "junk.db").rows.at(0).raw == "evil:tcc_db:not_sqlite");
    CHECK(read_source(dir / "fifo.db").rows.at(0).raw == "evil:tcc_db:not_regular");
    { std::ofstream{dir / "huge.db"}; }
    REQUIRE(::truncate((dir / "huge.db").c_str(), macos::kMaxDbBytes + 1) == 0); // sparse
    CHECK(read_source(dir / "huge.db").rows.at(0).raw == "evil:tcc_db:size_out_of_range");
}

TEST_CASE("privacy_permissions macOS: the value limit lands after the schema loads, and an "
          "oversized record is one category's failure",
          "[privacy_permissions][macos][internals]") {
    yuzu::test::TempDir tmp{"yuzu_test_pp_big_"};
    const auto dir = scratch_dir(tmp);
    make_db(dir / "schema.db",
            "CREATE TABLE access(service TEXT, client TEXT, client_type INTEGER, auth_value "
            "INTEGER, PRIMARY KEY(service, client, client_type) /* " +
                std::string(macos::kMaxValueBytes + 1024, 'p') +
                " */);INSERT INTO access VALUES('kTCCServiceCamera','a.app',0,2);");
    const auto schema = read_source(dir / "schema.db");
    CHECK(schema.count("camera", PermissionState::allowed) == 1);
    CHECK_FALSE(schema.acc.any_failure());

    make_db(dir / "cell.db",
            std::string{kAccessSchema} + "INSERT INTO access VALUES('kTCCServiceCamera','" +
                std::string(2 * macos::kMaxValueBytes, 'c') +
                "',0,2);INSERT INTO access VALUES('kTCCServiceMicrophone','m.app',0,2);");
    const auto cell = read_source(dir / "cell.db");
    CHECK(cell.has_raw("evil:tcc_db:camera:value_oversized"));
    CHECK(cell.count("camera", PermissionState::absent) == 0);
    CHECK(cell.count("microphone", PermissionState::allowed) == 1);
}

TEST_CASE("privacy_permissions macOS: a spent run or source budget is a named timeout, never "
          "absent, and the installed progress handler interrupts an endless query",
          "[privacy_permissions][macos][internals]") {
    yuzu::test::TempDir tmp{"yuzu_test_pp_budget_"};
    const auto db = scratch_dir(tmp) / "TCC.db";
    make_db(db, std::string{kAccessSchema});

    macos::ReadBounds run_spent;
    run_spent.run_end = std::chrono::steady_clock::time_point{};
    CHECK(read_source(db, run_spent).rows.at(0).raw == "evil:tcc_db:timeout");

    macos::ReadBounds source_spent;
    source_spent.source_budget = std::chrono::steady_clock::duration::zero();
    const auto cut = read_source(db, source_spent);
    REQUIRE(cut.rows.size() == macos::kTccServices.size());
    for (const auto& svc : macos::kTccServices)
        CHECK(cut.has_raw("evil:tcc_db:" + std::string{svc.category} + ":timeout"));

    Deadline deadline{std::chrono::steady_clock::time_point{}};
    auto opened = open_readonly(db.string(), &deadline);
    REQUIRE(opened.has_value());
    const DbPtr handle = std::move(*opened);
    sqlite3_stmt* raw = nullptr;
    REQUIRE(sqlite3_prepare_v2(handle.get(),
                               "WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n) "
                               "SELECT i FROM n WHERE i < 0",
                               -1, &raw, nullptr) == SQLITE_OK);
    const StmtPtr stmt{raw};
    CHECK(sqlite3_step(stmt.get()) == SQLITE_INTERRUPT);
    CHECK(deadline.fired);
}

TEST_CASE("privacy_permissions macOS: the bounded schema and untrusted-database posture still "
          "read a real-shape 17-column db, and refuse a hostile schema before it is parsed",
          "[privacy_permissions][macos][internals]") {
    yuzu::test::TempDir tmp{"yuzu_test_pp_schema_"};
    const auto dir = scratch_dir(tmp);
    make_db(dir / "real.db",
            "CREATE TABLE access (service TEXT NOT NULL, client TEXT NOT NULL, client_type INTEGER "
            "NOT NULL, auth_value INTEGER NOT NULL, auth_reason INTEGER NOT NULL, auth_version "
            "INTEGER NOT NULL, csreq BLOB, policy_id INTEGER, indirect_object_identifier_type "
            "INTEGER, indirect_object_identifier TEXT NOT NULL DEFAULT 'UNUSED', "
            "indirect_object_code_identity BLOB, flags INTEGER, last_modified INTEGER NOT NULL "
            "DEFAULT (CAST(strftime('%s','now') AS INTEGER)), pid INTEGER, pid_version INTEGER, "
            "boot_uuid TEXT NOT NULL DEFAULT 'UNUSED', last_reminded INTEGER NOT NULL DEFAULT 0, "
            "PRIMARY KEY (service, client, client_type, indirect_object_identifier));"
            "INSERT INTO access(service,client,client_type,auth_value,auth_reason,auth_version,"
            "csreq) VALUES('kTCCServiceCamera','com.apple.Terminal',0,2,4,1,zeroblob(5000));"
            "INSERT INTO access(service,client,client_type,auth_value,auth_reason,auth_version,"
            "csreq) VALUES('kTCCServiceMicrophone','com.zoom.us',0,0,4,1,zeroblob(300));");
    const auto real = read_source(dir / "real.db");
    CHECK(real.count("camera", PermissionState::allowed) == 1);
    CHECK(real.count("microphone", PermissionState::denied) == 1);
    CHECK_FALSE(real.acc.any_failure());

    std::string list = "0";
    for (int i = 0; i < 40000; ++i) list += ",0";
    make_db(dir / "check.db",
            "CREATE TABLE access(service TEXT, client TEXT, client_type INTEGER, auth_value "
            "INTEGER CHECK (auth_value IN (" + list + ")));");
    make_db(dir / "name.db",
            "CREATE VIEW access AS SELECT 'kTCCServiceCamera' AS service, 'c' AS client, 0 AS "
            "client_type, 2 AS auth_value FROM \"" + std::string(100000, 'n') + "\";");
    for (const char* hostile : {"check.db", "name.db"})
        CHECK(read_source(dir / hostile).rows.at(0).raw ==
              "evil:tcc_db:prepare_failed:string or blob too big");

    make_db(dir / "msg.db",
            "CREATE VIEW access AS SELECT 'kTCCServiceCamera' AS service, 'c' AS client, 0 AS "
            "client_type, 2 AS auth_value FROM \"a\nINFO forged\x1b\xE2\x80\xA8log line" +
                std::string(50000, 'm') + "\";");
    const auto msg = read_source(dir / "msg.db").rows.at(0).raw;
    CHECK(msg.rfind("evil:tcc_db:prepare_failed:no such table: main.a INFO forged  log", 0) == 0);
    CHECK(msg.size() <= std::string_view{"evil:tcc_db:prepare_failed:"}.size() + 200);
    CHECK(std::none_of(msg.begin(), msg.end(), [](unsigned char c) { return c < 0x20; }));
    CHECK(msg.find("\xE2\x80\xA8") == std::string::npos); // ESC and U+2028 fold to spaces too
}

TEST_CASE("privacy_permissions macOS: one source keeps at most kMaxSourceBytes of client text; "
          "the other categories are still read",
          "[privacy_permissions][macos][internals]") {
    yuzu::test::TempDir tmp{"yuzu_test_pp_bytes_"};
    const auto db = scratch_dir(tmp) / "TCC.db";
    make_db(db, // 450 x 0xFF scrubs to 1350 bytes, so the byte cap binds before the row cap
            "CREATE VIEW access AS WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n "
            "LIMIT 5000) SELECT 'kTCCServiceCamera' AS service, CAST(unhex(replace(hex("
            "zeroblob(450)),'00','FF')) AS TEXT)||i AS client, 0 AS client_type, 2 AS auth_value "
            "FROM n UNION ALL SELECT 'kTCCServiceMicrophone', 'm.app', 0, 2;");

    const auto r = read_source(db);
    CHECK(r.has_raw("evil:tcc_db:camera:byte_cap"));
    CHECK_FALSE(r.has_raw("evil:tcc_db:camera:row_cap"));
    CHECK(r.count("camera", PermissionState::allowed) < macos::kMaxRowsPerService);
    CHECK(r.count("microphone", PermissionState::allowed) == 1);
    std::size_t kept = 0;
    for (const auto& row : r.rows)
        if (row.category == "camera" && row.state == PermissionState::allowed)
            kept += row.app_id.size() - std::string_view{"evil\\"}.size();
    CHECK(kept <= macos::kMaxSourceBytes);
}

// The `poke()` scalar lets a view change the file while the statement is stepping.
struct Poke {
    std::string path;
    bool bump_counter = false;
    bool create_journal = false;
    bool replace_path = false; // unlink `path` and create a DIFFERENT file there (TOCTOU probe)
    bool rewrite_keep_mtime = false; // same-size in-place write, then restore mtime (ctime probe)
    Deadline* expire = nullptr;      // set `fired` from inside the running query (timeout probe)
} g_poke;

void poke_fn(sqlite3_context* ctx, int, sqlite3_value**) {
    if (g_poke.bump_counter) {
        yuzu::agent::ScopedFd fd{::open(g_poke.path.c_str(), O_WRONLY | O_CLOEXEC)};
        const unsigned char counter[4] = {0, 0, 0, 9};
        static_cast<void>(::pwrite(fd.get(), counter, sizeof counter, 24));
    }
    if (g_poke.create_journal) { std::ofstream{g_poke.path + "-journal"} << "x"; }
    if (g_poke.replace_path) {
        // A different inode: unlink the path SQLite opened (the original fd, already open
        // via /dev/fd/N, keeps its own inode alive under POSIX unlink-while-open semantics)
        // and create a hostile replacement at the same name.
        ::unlink(g_poke.path.c_str());
        std::ofstream{g_poke.path} << "not a sqlite database, and not the original bytes";
    }
    if (g_poke.rewrite_keep_mtime) {
        // What an owner CAN do: rewrite a byte of the open inode in place (same value, same size,
        // header untouched) and put the old mtime back. It cannot put ctime back.
        struct stat before{};
        ::stat(g_poke.path.c_str(), &before);
        yuzu::agent::ScopedFd fd{::open(g_poke.path.c_str(), O_RDWR | O_CLOEXEC)};
        unsigned char byte = 0;
        static_cast<void>(::pread(fd.get(), &byte, 1, 200));
        static_cast<void>(::pwrite(fd.get(), &byte, 1, 200));
        const struct timespec times[2] = {{0, UTIME_OMIT}, before.st_mtimespec};
        ::futimens(fd.get(), times);
    }
    if (g_poke.expire) g_poke.expire->fired = true;
    sqlite3_result_int(ctx, 0);
}

int poke_entry(sqlite3* db, char**, const sqlite3_api_routines*) {
    const int rc = sqlite3_create_function(db, "poke", 0, SQLITE_UTF8 | SQLITE_INNOCUOUS, nullptr,
                                           poke_fn, nullptr, nullptr);
    return rc != SQLITE_OK ? rc
                           : sqlite3_create_function(db, "poke_unsafe", 0, SQLITE_UTF8, nullptr,
                                                     poke_fn, nullptr, nullptr);
}

struct PokeRegistered {
    PokeRegistered() { sqlite3_auto_extension(reinterpret_cast<void (*)()>(poke_entry)); }
    ~PokeRegistered() { sqlite3_cancel_auto_extension(reinterpret_cast<void (*)()>(poke_entry)); }
};

TEST_CASE("privacy_permissions macOS: a change made to the file while it is being read discards "
          "the read; a function the schema may not trust is refused",
          "[privacy_permissions][macos][internals]") {
    yuzu::test::TempDir tmp{"yuzu_test_pp_race_"};
    const auto dir = scratch_dir(tmp);
    const auto view = [](const char* call) {
        return std::string{"CREATE VIEW access AS SELECT 'kTCCServiceCamera' AS service, 'a.app' "
                           "AS client, 0 AS client_type, 2 + "} + call + " AS auth_value;";
    };
    make_db(dir / "TCC.db", view("poke()"));
    make_db(dir / "unsafe.db", view("poke_unsafe()"));
    const PokeRegistered registered;
    g_poke = {(dir / "TCC.db").string(), false, false};

    CHECK(read_source(dir / "TCC.db").count("camera", PermissionState::allowed) == 1);
    g_poke.bump_counter = true;
    CHECK(read_source(dir / "TCC.db").rows.at(0).raw == "evil:tcc_db:changed_during_read");
    g_poke.bump_counter = false;
    g_poke.create_journal = true;
    CHECK(read_source(dir / "TCC.db").rows.at(0).raw == "evil:tcc_db:sidecar_present");
    g_poke.create_journal = false;
    CHECK(read_source(dir / "unsafe.db").rows.at(0).raw.rfind(
              "evil:tcc_db:prepare_failed:unsafe use of poke_unsafe()", 0) == 0);
}

TEST_CASE("privacy_permissions macOS: replacing the file mid-read is refused as "
          "changed_during_read and the replacement is never parsed (the unlink moves the open "
          "inode's ctime; both snapshots come from the same fd's fstat(), never a path re-lstat())",
          "[privacy_permissions][macos][internals]") {
    yuzu::test::TempDir tmp{"yuzu_test_pp_toctou_"};
    const auto dir = scratch_dir(tmp);
    const auto view = [](const char* call) {
        return std::string{"CREATE VIEW access AS SELECT 'kTCCServiceCamera' AS service, 'a.app' "
                           "AS client, 0 AS client_type, 2 + "} + call + " AS auth_value;";
    };
    make_db(dir / "TCC.db", view("poke()"));
    const PokeRegistered registered;
    g_poke = {(dir / "TCC.db").string(), false, false, false};

    g_poke.replace_path = true;
    const auto result = read_source(dir / "TCC.db");
    g_poke.replace_path = false;

    // The unlink moves the original inode's ctime, so the read is refused as changed_during_read
    // (a replaced file is a changed file). The one row is that refusal: nothing was built from the
    // replacement text ("not a sqlite database ..."), which would surface as not_sqlite or a
    // prepare/step failure. (That SQLite reads the inode it opened, not the path, is a property of
    // its open at sqlite3_open_v2, which precedes this poke -- not observable from here.)
    REQUIRE(result.rows.size() == 1);
    CHECK(result.rows[0].raw == "evil:tcc_db:changed_during_read");
    CHECK_FALSE(result.has_raw("evil:tcc_db:not_sqlite"));
}

TEST_CASE("privacy_permissions macOS: an in-place write that restores mtime, size and the header "
          "counter is still a change during the read (ctime cannot be put back)",
          "[privacy_permissions][macos][internals]") {
    yuzu::test::TempDir tmp{"yuzu_test_pp_ctime_"};
    const auto dir = scratch_dir(tmp);
    make_db(dir / "TCC.db",
            "CREATE VIEW access AS SELECT 'kTCCServiceCamera' AS service, 'a.app' AS client, 0 AS "
            "client_type, 2 + poke() AS auth_value;");
    const PokeRegistered registered;
    g_poke = {};
    g_poke.path = (dir / "TCC.db").string();

    CHECK(read_source(dir / "TCC.db").count("camera", PermissionState::allowed) == 1);
    g_poke.rewrite_keep_mtime = true;
    const auto result = read_source(dir / "TCC.db");
    g_poke.rewrite_keep_mtime = false;
    CHECK(result.rows.at(0).raw == "evil:tcc_db:changed_during_read");
    CHECK(result.count("camera", PermissionState::allowed) == 0);
}

TEST_CASE("privacy_permissions macOS: a path on a network mount is refused before any syscall "
          "touches it, and the rest of the run still reads",
          "[privacy_permissions][macos][internals]") {
    if (::geteuid() < 500) SKIP("homes owned by a system uid are not enumerated");
    yuzu::test::TempDir tmp{"yuzu_test_pp_mounts_"};
    const auto base = scratch_dir(tmp);
    const auto users = base / "users";
    const std::string honest =
        std::string{kAccessSchema} + "INSERT INTO access VALUES('kTCCServiceCamera','x.app',0,2);";
    for (const char* name : {"a", "b"}) {
        const auto dir = users / name / "Library/Application Support/com.apple.TCC";
        std::filesystem::create_directories(dir);
        make_db(dir / "TCC.db", honest);
    }
    make_db(base / "system.db", honest);

    SECTION("a source under a network mount is never opened -- not even to learn it is missing") {
        macos::ReadBounds bounds;
        bounds.mounts = {{"/", "apfs"}, {(base / "gone").string(), "nfs"}};
        SourceRead r;
        read_tcc_source("evil", (base / "gone" / "TCC.db").string(), /*missing_is_absent=*/true,
                        r.rows, r.acc, bounds);
        REQUIRE(r.rows.size() == 1);
        CHECK(r.rows[0].raw == "evil:tcc_db:network_mount");
        CHECK(r.rows[0].state == PermissionState::unreadable); // a missing file would read absent
    }
    SECTION("a home that is itself a network mount point is skipped by name; its sibling reads") {
        macos::ReadBounds bounds;
        bounds.mounts = {{(users / "a").string(), "smbfs"}};
        SourceRead r;
        macos::OutputBudget output;
        read_all_sources(r.rows, r.acc, (base / "system.db").string(), users.string(), bounds,
                         output);
        CHECK(r.has_raw("a:network_mount"));
        CHECK(std::none_of(r.rows.begin(), r.rows.end(), [](const auto& row) {
            return row.app_id.rfind("a\\", 0) == 0 && row.state == PermissionState::allowed;
        }));
        CHECK(std::any_of(r.rows.begin(), r.rows.end(), [](const auto& row) {
            return row.app_id.rfind("b\\", 0) == 0 && row.state == PermissionState::allowed;
        }));
    }
    SECTION("a home whose name carries delimiters reaches tokens with them folded") {
        const auto weird = users / "x,y|z";
        std::filesystem::create_directories(weird / "Library/Application Support/com.apple.TCC");
        macos::ReadBounds bounds;
        bounds.mounts = {{weird.string(), "nfs"}};
        SourceRead r;
        macos::OutputBudget output;
        read_all_sources(r.rows, r.acc, (base / "system.db").string(), users.string(), bounds,
                         output);
        CHECK(r.has_raw("x/y/z:network_mount"));
        CHECK(std::none_of(r.rows.begin(), r.rows.end(), [](const auto& row) {
            return row.raw.find(',') != std::string::npos;
        }));
    }
    SECTION("a users directory on a network mount is not opened at all") {
        macos::ReadBounds bounds;
        bounds.mounts = {{users.string(), "nfs"}};
        SourceRead r;
        macos::OutputBudget output;
        read_all_sources(r.rows, r.acc, (base / "system.db").string(), users.string(), bounds,
                         output);
        CHECK(r.has_raw("users:network_mount"));
    }
}

// A caller-owned array like getmntinfo_r_np hands back, so snapshot_mounts' free() is exercised.
std::string g_fake_mount_point;
int g_fake_fetch_calls = 0;
int g_fake_fetch_flags = 0;
int fake_fetch_nfs(struct statfs** out, int flags) {
    ++g_fake_fetch_calls;
    g_fake_fetch_flags = flags;
    auto* table = static_cast<struct statfs*>(std::calloc(2, sizeof(struct statfs)));
    std::strncpy(table[0].f_mntonname, "/", sizeof table[0].f_mntonname - 1);
    std::strncpy(table[0].f_fstypename, "apfs", sizeof table[0].f_fstypename - 1);
    std::strncpy(table[1].f_mntonname, g_fake_mount_point.c_str(), sizeof table[1].f_mntonname - 1);
    std::strncpy(table[1].f_fstypename, "nfs", sizeof table[1].f_fstypename - 1);
    *out = table;
    return 2;
}
int fake_fetch_null_array(struct statfs** out, int flags) { // count > 0 but nothing to read
    ++g_fake_fetch_calls;
    g_fake_fetch_flags = flags;
    *out = nullptr;
    return 3;
}
int fake_fetch_fails(struct statfs** out, int flags) {
    ++g_fake_fetch_calls;
    g_fake_fetch_flags = flags;
    *out = nullptr;
    return 0;
}

TEST_CASE("privacy_permissions macOS: one collection takes exactly one non-blocking mount "
          "snapshot and the guard it builds is what the reads obey",
          "[privacy_permissions][macos][internals]") {
    if (::geteuid() < 500) SKIP("homes owned by a system uid are not enumerated");
    yuzu::test::TempDir tmp{"yuzu_test_pp_collect_"};
    const auto base = scratch_dir(tmp);
    const auto users = base / "users";
    const std::string honest =
        std::string{kAccessSchema} + "INSERT INTO access VALUES('kTCCServiceCamera','x.app',0,2);";
    for (const char* name : {"a", "b"}) {
        const auto dir = users / name / "Library/Application Support/com.apple.TCC";
        std::filesystem::create_directories(dir);
        make_db(dir / "TCC.db", honest);
    }
    make_db(base / "system.db", honest);
    const auto allowed_for = [](const SourceRead& r, std::string_view home) {
        return std::any_of(r.rows.begin(), r.rows.end(), [&](const auto& row) {
            return row.app_id.rfind(std::string{home} + "\\", 0) == 0 &&
                   row.state == PermissionState::allowed;
        });
    };

    SECTION("the snapshot's network mount refuses that home; the sibling still reads") {
        g_fake_mount_point = (users / "a").string();
        g_fake_fetch_calls = 0;
        SourceRead r;
        run_collection(r.rows, r.acc, (base / "system.db").string(), users.string(), fake_fetch_nfs);
        CHECK(g_fake_fetch_calls == 1);
        CHECK(g_fake_fetch_flags == MNT_NOWAIT);
        CHECK(r.has_raw("a:network_mount"));
        CHECK_FALSE(allowed_for(r, "a"));
        CHECK(allowed_for(r, "b"));
    }
    SECTION("a count with no array is the same named failure, never a null dereference") {
        SourceRead r;
        run_collection(r.rows, r.acc, (base / "system.db").string(), users.string(),
                       fake_fetch_null_array);
        CHECK(r.has_raw("mounts:getmntinfo_failed"));
        CHECK(allowed_for(r, "a"));
    }
    SECTION("a snapshot that cannot be read is named, and the sources are still read") {
        g_fake_fetch_calls = 0;
        SourceRead r;
        run_collection(r.rows, r.acc, (base / "system.db").string(), users.string(), fake_fetch_fails);
        CHECK(g_fake_fetch_calls == 1);
        CHECK(g_fake_fetch_flags == MNT_NOWAIT);
        CHECK(r.has_raw("mounts:getmntinfo_failed"));
        CHECK(r.acc.any_failure()); // CONSTRAINED: the run says it read without the guard
        CHECK(allowed_for(r, "a"));
        CHECK(allowed_for(r, "b"));
    }
}

int open_fd_count() {
    int n = 0;
    for (int fd = 0; fd < 256; ++fd)
        if (::fcntl(fd, F_GETFD) != -1) ++n;
    return n;
}

TEST_CASE("privacy_permissions macOS: a NULL auth_value and a failing step are named failures, "
          "never a fabricated denied or a clean absent",
          "[privacy_permissions][macos][internals]") {
    yuzu::test::TempDir tmp{"yuzu_test_pp_nullstep_"};
    const auto dir = scratch_dir(tmp);
    make_db(dir / "null.db",
            "CREATE VIEW access AS SELECT 'kTCCServiceCamera' AS service, 'a.app' AS client, 0 AS "
            "client_type, NULL AS auth_value;");
    const auto nul = read_source(dir / "null.db");
    CHECK(nul.has_raw("evil:tcc_db:camera:auth_value_unreadable"));
    CHECK(nul.count("camera", PermissionState::denied) == 0);
    CHECK(nul.count("camera", PermissionState::allowed) == 0);

    // abs(INT64_MIN) is an integer overflow the engine raises AT STEP time, on a row.
    make_db(dir / "step.db",
            "CREATE VIEW access AS SELECT 'kTCCServiceMicrophone' AS service, 'x' AS client, 0 AS "
            "client_type, abs(-9223372036854775807-1) AS auth_value;");
    const auto step = read_source(dir / "step.db");
    CHECK(step.has_raw("evil:tcc_db:microphone:query_step_failed"));
    CHECK(step.count("microphone", PermissionState::absent) == 0);
    CHECK(step.acc.any_failure());
}

TEST_CASE("privacy_permissions macOS: a client with an embedded NUL is kept whole, not truncated "
          "to its prefix, and no NUL reaches a row",
          "[privacy_permissions][macos][internals]") {
    yuzu::test::TempDir tmp{"yuzu_test_pp_nul_"};
    const auto dir = scratch_dir(tmp);
    make_db(dir / "TCC.db",
            "CREATE VIEW access AS SELECT 'kTCCServiceCamera' AS service, CAST(x'610078' AS TEXT) "
            "AS client, 0 AS client_type, 2 AS auth_value UNION ALL SELECT 'kTCCServiceCamera', "
            "CAST(x'610079' AS TEXT), 0, 2;");
    const auto r = read_source(dir / "TCC.db");
    REQUIRE(r.count("camera", PermissionState::allowed) == 2);
    std::vector<std::string> ids;
    for (const auto& row : r.rows)
        if (row.category == "camera" && row.state == PermissionState::allowed)
            ids.push_back(row.app_id);
    CHECK(ids == std::vector<std::string>{"evil\\a?x", "evil\\a?y"});
}

TEST_CASE("privacy_permissions macOS: the open is the first syscall on the path -- a symlinked or "
          "dangling intermediate component is refused, never followed and never `absent`",
          "[privacy_permissions][macos][internals]") {
    yuzu::test::TempDir tmp{"yuzu_test_pp_dangling_"};
    const auto base = scratch_dir(tmp);
    std::filesystem::create_directory_symlink(base / "does_not_exist", base / "Library");
    SourceRead r;
    read_tcc_source("alice", (base / "Library" / "TCC.db").string(), /*missing_is_absent=*/true,
                    r.rows, r.acc);
    REQUIRE(r.rows.size() == 1);
    CHECK(r.rows[0].raw == "alice:tcc_db:open_failed:symlink"); // ELOOP, not ENOENT -> not absent
    CHECK(r.rows[0].state == PermissionState::unreadable);

    // A plain file where a directory is expected is a genuinely missing db.
    { std::ofstream{base / "file"}; }
    SourceRead f;
    read_tcc_source("alice", (base / "file" / "TCC.db").string(), true, f.rows, f.acc);
    REQUIRE(f.rows.size() == 1);
    CHECK(f.rows[0].state == PermissionState::absent);
}

TEST_CASE("privacy_permissions macOS: reading a source leaks no descriptor on any outcome",
          "[privacy_permissions][macos][internals]") {
    yuzu::test::TempDir tmp{"yuzu_test_pp_fdleak_"};
    const auto dir = scratch_dir(tmp);
    make_db(dir / "good.db",
            std::string{kAccessSchema} + "INSERT INTO access VALUES('kTCCServiceCamera','x.app',0,2);");
    make_db(dir / "schema.db", "CREATE TABLE unrelated(x);");
    { std::ofstream{dir / "junk.db"} << std::string(200, 'j'); }
    const auto pass = [&] {
        for (const char* name : {"good.db", "schema.db", "junk.db", "missing.db"})
            static_cast<void>(read_source(dir / name));
    };
    pass(); // one-time lazy descriptors (sqlite, locale) are opened here, not counted as a leak
    const int before = open_fd_count();
    for (int i = 0; i < 20; ++i) pass();
    CHECK(open_fd_count() == before);
}

TEST_CASE("privacy_permissions macOS: a source whose deadline fires DURING the query is cut as a "
          "timeout, deterministically -- never a step failure and never a hang",
          "[privacy_permissions][macos][internals]") {
    yuzu::test::TempDir tmp{"yuzu_test_pp_midstep_"};
    const auto dir = scratch_dir(tmp);
    // Finite (a regression that loses the progress handler ends in DONE, not a hang); poke() runs
    // on every row and expires the deadline from inside the running query.
    make_db(dir / "mid.db",
            "CREATE VIEW access AS WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i+1 FROM n "
            "LIMIT 30000000) SELECT 'kTCCServiceCamera' AS service, 'x' AS client, 0 AS "
            "client_type, 2 AS auth_value FROM n WHERE poke() = 1;");
    const PokeRegistered registered;
    g_poke = {};
    Deadline deadline{std::chrono::steady_clock::now() + std::chrono::hours{1}};
    g_poke.expire = &deadline;

    auto opened = open_readonly((dir / "mid.db").string(), &deadline);
    REQUIRE(opened.has_value());
    const DbPtr db = std::move(*opened);
    sqlite3_stmt* raw = nullptr;
    REQUIRE(sqlite3_prepare_v2(db.get(),
                               "SELECT service, client, auth_value FROM access WHERE service = ?",
                               -1, &raw, nullptr) == SQLITE_OK);
    const StmtPtr stmt{raw};
    const auto reads = read_services(stmt.get(), deadline, macos::kMaxRowsPerService);
    g_poke = {};

    REQUIRE(reads.size() == macos::kTccServices.size());
    CHECK(deadline.fired);
    CHECK(reads[0].cut == macos::kCutTimeout);
    CHECK_FALSE(reads[0].step_failed);
    CHECK(reads[0].grants.empty());
    CHECK(reads[1].cut == macos::kCutTimeout); // the rest see the fired deadline at the loop top
}

TEST_CASE("privacy_permissions macOS: a delimiter or backslash in a sqlite diagnostic is folded once, "
          "not escaped twice",
          "[privacy_permissions][macos][internals]") {
    yuzu::test::TempDir tmp{"yuzu_test_pp_errmsg_"};
    const auto dir = scratch_dir(tmp);
    make_db(dir / "pipe.db",
            "CREATE VIEW access AS SELECT 'kTCCServiceCamera' AS service, 'c' AS client, 0 AS "
            "client_type, 2 AS auth_value FROM \"a|b\\c,d\";");
    const auto r = read_source(dir / "pipe.db");
    CHECK(r.rows.at(0).raw == "evil:tcc_db:prepare_failed:no such table: main.a/b/c/d");
    CHECK(r.rows.at(0).raw.find(',') == std::string::npos); // a comma would forge a second token
    CHECK(r.rows.at(0).raw.find('|') == std::string::npos);
    CHECK(r.rows.at(0).raw.find('\\') == std::string::npos);
}

TEST_CASE("privacy_permissions macOS: one run deadline covers every source, and homes stop being "
          "read once the run-wide output budget is spent",
          "[privacy_permissions][macos][internals]") {
    if (::geteuid() < 500) SKIP("homes owned by a system uid are not enumerated");
    yuzu::test::TempDir tmp{"yuzu_test_pp_users_"};
    const auto base = scratch_dir(tmp);
    const auto users = base / "users";
    const std::string honest =
        std::string{kAccessSchema} + "INSERT INTO access VALUES('kTCCServiceCamera','x.app',0,2);";
    for (const char* name : {"a", "b", "c"}) {
        const auto dir = users / name / "Library/Application Support/com.apple.TCC";
        std::filesystem::create_directories(dir);
        make_db(dir / "TCC.db", honest);
    }
    std::filesystem::create_directory_symlink(users / "a", users / "link");
    { std::ofstream{users / "file"}; }
    make_db(base / "system.db", honest);
    const std::string system_db = (base / "system.db").string();
    SourceRead r;
    const auto from = [&](const std::string& home) {
        return std::any_of(r.rows.begin(), r.rows.end(), [&](const auto& row) {
            return row.app_id.rfind(home + "\\", 0) == 0;
        });
    };

    SECTION("a spent run deadline is seen by the system db and every home") {
        macos::ReadBounds bounds;
        bounds.run_end = std::chrono::steady_clock::time_point{};
        macos::OutputBudget output;
        read_all_sources(r.rows, r.acc, system_db, users.string(), bounds, output);
        for (const char* token : {"tcc_db:timeout", "a:tcc_db:timeout", "b:tcc_db:timeout",
                                  "c:tcc_db:timeout"})
            CHECK(r.has_raw(token));
    }
    SECTION("the home that spends the budget is kept, the next is not read") {
        macos::OutputBudget output;
        {
            SourceRead sys; // what the system db alone is charged
            read_tcc_source({}, system_db, false, sys.rows, sys.acc);
            macos::OutputBudget probe;
            probe.charge(sys.rows);
            // The system db stays under it; one home's rows do not.
            output.budget.max_bytes = probe.budget.bytes + 1;
        }
        read_all_sources(r.rows, r.acc, system_db, users.string(), {}, output);
        CHECK(from("a"));
        CHECK_FALSE(from("b"));
        CHECK_FALSE(from("c"));
        CHECK(r.has_raw("collection:budget_exceeded"));
    }
    SECTION("a missing system db is never absent; a symlink and a plain file are not homes") {
        macos::OutputBudget output;
        read_all_sources(r.rows, r.acc, (base / "missing.db").string(), users.string(), {}, output);
        const auto missing = std::find_if(r.rows.begin(), r.rows.end(), [](const auto& row) {
            return row.raw == "tcc_db:missing";
        });
        REQUIRE(missing != r.rows.end());
        CHECK(missing->state == PermissionState::unreadable);
        CHECK(from("a"));
        CHECK_FALSE(from("link"));
        CHECK_FALSE(from("file"));
    }
    SECTION("an absent users dir is a named row") {
        macos::OutputBudget output;
        read_all_sources(r.rows, r.acc, system_db, (base / "nope").string(), {}, output);
        CHECK(r.has_raw("users:open_errno_2"));
    }
}

} // namespace yuzu::privacy_permissions

#endif // defined(__APPLE__)
