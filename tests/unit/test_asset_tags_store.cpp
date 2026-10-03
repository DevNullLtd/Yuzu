/**
 * test_asset_tags_store.cpp -- asset_tags_store.hpp (#232): the atomic
 * state-file lifecycle. Filesystem-backed (one small file per case in a
 * TempDir) because the defect class -- non-atomic write, a planted temp
 * path, and on Windows an open handle during rename -- is unobservable from
 * pure code. No threads, clocks, sleeps or processes.
 *
 * Atomicity is asserted, not assumed (code-review F-codex-3): on POSIX the
 * replace case holds a descriptor on the OLD file across the write and
 * proves the destination changed inode while the old descriptor still reads
 * the whole old content -- a direct truncate+write over the destination
 * fails both checks deterministically, with no timing involved.
 *
 * The temp name is now a random, unpredictable sibling
 * (`<dest>.tmp.<16 hex>`, adversarial-review round 1 finding F1), so a case
 * can no longer name the exact temp path to check it is gone. Every case
 * that used to check for one fixed name instead checks that `dest`'s parent
 * directory holds no entry beyond what the case itself put there.
 */
#include "asset_tags_parsers.hpp"
#include "asset_tags_store.hpp"

#include "test_helpers.hpp"

#include <catch2/catch_test_macros.hpp>

#include <expected>
#include <filesystem>
#include <fstream>
#include <optional>
#include <string>
#include <vector>

#ifndef _WIN32
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

using namespace yuzu::asset_tags;
namespace fs = std::filesystem;

namespace {

// A write that succeeded with no warning attached.
bool wrote_clean(const std::expected<std::optional<WriteWarning>, IoError>& r) {
    return r.has_value() && !r->has_value();
}

// Every temp file this header creates lives beside `dest`, named
// `<dest.filename()>.tmp.<16 hex>` -- the suffix is unpredictable, so a case
// can no longer check for one exact name. Instead it lists `dir`'s entries
// and reports every one that is not `dest` itself: an empty result means no
// temp (and nothing else) survived.
std::vector<fs::path> unexpected_entries(const fs::path& dir, const fs::path& dest) {
    std::vector<fs::path> extra;
    std::error_code ec;
    for (const auto& e : fs::directory_iterator(dir, ec)) {
        if (e.path() != dest)
            extra.push_back(e.path());
    }
    return extra;
}

} // namespace

TEST_CASE("asset_tags store: missing parent directories are created",
          "[agent][asset_tags_store]") {
    yuzu::test::TempDir dir{"yuzu_test_asset_tags_"};
    const auto dest = dir.path / "nested" / "deeper" / "state.json";

    REQUIRE(wrote_clean(write_state_file_atomic(dest, "{\"a\":1}")));
    CHECK(fs::is_directory(dest.parent_path()));
    auto text = read_state_file(dest);
    REQUIRE(text.has_value());
    REQUIRE(text->has_value());
    CHECK(**text == "{\"a\":1}");
}

TEST_CASE("asset_tags store: first write creates the file", "[agent][asset_tags_store]") {
    yuzu::test::TempDir dir{"yuzu_test_asset_tags_"};
    const auto dest = dir.path / "sub" / "asset_tags.json";

    REQUIRE(wrote_clean(write_state_file_atomic(dest, "{\"a\":1}")));
    CHECK(fs::exists(dest));
    CHECK(unexpected_entries(dest.parent_path(), dest).empty());

    auto text = read_state_file(dest);
    REQUIRE(text.has_value());
    REQUIRE(text->has_value());
    CHECK(**text == "{\"a\":1}");

#ifndef _WIN32
    CHECK(fs::status(dest).permissions() ==
          (fs::perms::owner_read | fs::perms::owner_write));
#endif
}

TEST_CASE("asset_tags store: replace is atomic and leaves no temp", "[agent][asset_tags_store]") {
    yuzu::test::TempDir dir{"yuzu_test_asset_tags_"};
    const auto dest = dir.path / "asset_tags.json";

    REQUIRE(wrote_clean(write_state_file_atomic(dest, "AAAA")));
    REQUIRE(wrote_clean(write_state_file_atomic(dest, "B")));
    auto text = read_state_file(dest);
    REQUIRE(text.has_value());
    REQUIRE(text->has_value());
    CHECK(**text == "B");
    CHECK(unexpected_entries(dir.path, dest).empty());

#ifndef _WIN32
    // Hold the OLD file open across the replace. A rename swaps the directory
    // entry to a new inode and leaves the old one intact for its readers; a
    // truncate+write in place would keep the inode and overwrite what the
    // reader sees. Both checks are deterministic -- no reader races a writer.
    struct stat before {};
    REQUIRE(::stat(dest.c_str(), &before) == 0);
    const int old_fd = ::open(dest.c_str(), O_RDONLY);
    REQUIRE(old_fd >= 0);
    yuzu::test::ScopeExit close_old{[&] { ::close(old_fd); }};

    REQUIRE(wrote_clean(write_state_file_atomic(dest, "CCCCCCCC")));

    struct stat after {};
    REQUIRE(::stat(dest.c_str(), &after) == 0);
    CHECK(after.st_ino != before.st_ino);

    struct stat old_now {};
    REQUIRE(::fstat(old_fd, &old_now) == 0);
    CHECK(old_now.st_nlink == 0); // the old inode was unlinked by the rename, not rewritten

    std::string old_view;
    char buf[64];
    for (ssize_t n = ::read(old_fd, buf, sizeof buf); n > 0; n = ::read(old_fd, buf, sizeof buf))
        old_view.append(buf, static_cast<std::size_t>(n));
    CHECK(old_view == "B"); // wholly old -- never "CCCCCCCC", never empty

    text = read_state_file(dest);
    REQUIRE(text.has_value());
    REQUIRE(text->has_value());
    CHECK(**text == "CCCCCCCC"); // wholly new through the path
    CHECK(unexpected_entries(dir.path, dest).empty());
#endif
}

TEST_CASE("asset_tags store: a planted file at the old fixed temp path is left untouched (F1)",
          "[agent][asset_tags_store]") {
    // Before adversarial-review round 1, the temp name was the fixed
    // `<dest>.tmp` -- predictable and, on POSIX, followed if it was a
    // symlink. Plant exactly that legacy path pointing at (POSIX) or holding
    // (Windows) a canary and prove the write neither follows nor overwrites
    // it: the temp name is now random, so this fixed path is just an
    // ordinary bystander file to the real write.
    yuzu::test::TempDir dir{"yuzu_test_asset_tags_"};
    std::error_code ec;
    fs::create_directories(dir.path, ec); // TempDir only reserves the name
    REQUIRE_FALSE(ec);

    const auto dest = dir.path / "asset_tags.json";
    const auto canary = dir.path / "canary.txt";
    const auto legacy_fixed_tmp = fs::path{dest.string() + ".tmp"};
    const std::string sentinel = "SENTINEL-DO-NOT-TOUCH";

    {
        std::ofstream f(canary, std::ios::binary);
        f << sentinel;
    }

#ifndef _WIN32
    fs::create_symlink(canary, legacy_fixed_tmp, ec);
    REQUIRE_FALSE(ec);
    REQUIRE(fs::is_symlink(legacy_fixed_tmp));
#else
    {
        std::ofstream f(legacy_fixed_tmp, std::ios::binary);
        f << sentinel;
    }
#endif

    REQUIRE(wrote_clean(write_state_file_atomic(dest, "PAYLOAD")));

    // The real write never touched the planted path at all.
#ifndef _WIN32
    CHECK(fs::is_symlink(legacy_fixed_tmp));
    std::ifstream canary_after(canary, std::ios::binary);
    std::string canary_content{std::istreambuf_iterator<char>(canary_after),
                               std::istreambuf_iterator<char>()};
    CHECK(canary_content == sentinel); // untouched
#else
    std::ifstream planted_after(legacy_fixed_tmp, std::ios::binary);
    std::string planted_content{std::istreambuf_iterator<char>(planted_after),
                                std::istreambuf_iterator<char>()};
    CHECK(planted_content == sentinel); // untouched
#endif

    CHECK_FALSE(fs::is_symlink(dest));
    auto text = read_state_file(dest);
    REQUIRE(text.has_value());
    REQUIRE(text->has_value());
    CHECK(**text == "PAYLOAD");

    // dest's parent now holds exactly: dest, canary.txt, and the planted
    // legacy-named bystander -- nothing named after the real (random) temp.
    auto extra = unexpected_entries(dir.path, dest);
    CHECK(extra.size() == 2);
}

TEST_CASE("asset_tags store: a planted file at the ACTUAL temp path fails the exclusive create",
          "[agent][asset_tags_store]") {
    // The previous "old fixed temp path" case above only ever plants at the
    // retired `<dest>.tmp` name, which production code never opens (it opens
    // `<dest>.tmp.<16 hex>`) -- so it cannot falsify a regression that keeps
    // the random naming but drops O_EXCL|O_NOFOLLOW (adversarial-review,
    // twice-confirmed coverage gap). `forced_temp_suffix` (a test-only seam;
    // see its doc comment) pins the exact path the write will try to create,
    // so this planted file sits where the real O_CREAT|O_EXCL open actually
    // lands.
    yuzu::test::TempDir dir{"yuzu_test_asset_tags_"};
    std::error_code ec;
    fs::create_directories(dir.path, ec); // TempDir only reserves the name
    REQUIRE_FALSE(ec);

    const auto dest = dir.path / "asset_tags.json";
    const auto canary = dir.path / "canary.txt";
    const auto forced_tmp = fs::path{dest.string() + ".tmp.forced"};
    const std::string sentinel = "SENTINEL-DO-NOT-TOUCH";

    {
        std::ofstream f(canary, std::ios::binary);
        f << sentinel;
    }

#ifndef _WIN32
    fs::create_symlink(canary, forced_tmp, ec);
    REQUIRE_FALSE(ec);
    REQUIRE(fs::is_symlink(forced_tmp));
#else
    {
        std::ofstream f(forced_tmp, std::ios::binary);
        f << sentinel;
    }
#endif

    auto r = write_state_file_atomic(dest, "PAYLOAD", "forced");
    REQUIRE_FALSE(r.has_value());
    CHECK_FALSE(r.error().message.empty());

    // The exclusive create failed, so TempFileGuard was never armed: nothing
    // was removed, and the planted file is exactly as it was planted.
#ifndef _WIN32
    CHECK(fs::is_symlink(forced_tmp));
    std::ifstream canary_after(canary, std::ios::binary);
    std::string canary_content{std::istreambuf_iterator<char>(canary_after),
                               std::istreambuf_iterator<char>()};
    CHECK(canary_content == sentinel); // untouched
#else
    std::ifstream planted_after(forced_tmp, std::ios::binary);
    std::string planted_content{std::istreambuf_iterator<char>(planted_after),
                                std::istreambuf_iterator<char>()};
    CHECK(planted_content == sentinel); // untouched
#endif

    CHECK_FALSE(fs::exists(dest)); // the rename never ran
    // dir holds exactly: canary.txt and the planted forced-name temp --
    // nothing else appeared or disappeared.
    auto extra = unexpected_entries(dir.path, dest);
    CHECK(extra.size() == 2);
}

TEST_CASE("asset_tags store: restart recovery", "[agent][asset_tags_store]") {
    yuzu::test::TempDir dir{"yuzu_test_asset_tags_"};
    const auto dest = dir.path / "asset_tags.json";

    AssetTagState st;
    CategoryValues v{"db", "Production", "Rack A|3", ""};
    apply_sync(st, v, 100);
    v[0] = "db2";
    apply_sync(st, v, 200);
    REQUIRE(st.tags.size() == 3);
    REQUIRE(st.change_log.size() == 4);

    REQUIRE(wrote_clean(write_state_file_atomic(dest, serialize_state(st))));
    auto text = read_state_file(dest);
    REQUIRE(text.has_value());
    REQUIRE(text->has_value());
    auto parsed = parse_state(**text);
    REQUIRE(parsed.has_value());
    CHECK(parsed->tags == st.tags);
    CHECK(parsed->change_log.size() == st.change_log.size());

    SECTION("a corrupt file is read, rejected by the parser, then replaced") {
        REQUIRE(wrote_clean(write_state_file_atomic(dest, "{not json")));
        text = read_state_file(dest);
        REQUIRE(text.has_value());
        REQUIRE(text->has_value());
        auto rejected = parse_state(**text);
        REQUIRE_FALSE(rejected.has_value());
        CHECK_FALSE(rejected.error().message.empty());

        REQUIRE(wrote_clean(write_state_file_atomic(dest, serialize_state(st))));
        text = read_state_file(dest);
        REQUIRE(text.has_value());
        REQUIRE(text->has_value());
        CHECK(parse_state(**text).has_value());
    }
}

TEST_CASE("asset_tags store: failure paths", "[agent][asset_tags_store]") {
    yuzu::test::TempDir dir{"yuzu_test_asset_tags_"};
    std::error_code mk_ec;
    fs::create_directories(dir.path, mk_ec); // TempDir only reserves the name
    REQUIRE_FALSE(mk_ec);

    SECTION("parent path is a regular file") {
        const auto blocker = dir.path / "blocker";
        {
            std::ofstream f(blocker, std::ios::binary);
            f << "x";
        }
        const auto dest = blocker / "asset_tags.json";
        auto r = write_state_file_atomic(dest, "{}");
        REQUIRE_FALSE(r.has_value());
        CHECK_FALSE(r.error().message.empty());
        // The failure is at the create_directories/is_directory check, before
        // any temp path is even computed -- dir.path holds only `blocker`.
        CHECK(unexpected_entries(dir.path, blocker).empty());
    }
    SECTION("a missing file is a first run, not an error") {
        auto text = read_state_file(dir.path / "absent.json");
        REQUIRE(text.has_value());
        CHECK_FALSE(text->has_value());
    }
    SECTION("a directory is an error") {
        auto text = read_state_file(dir.path);
        REQUIRE_FALSE(text.has_value());
        CHECK_FALSE(text.error().message.empty());
    }
}

#ifndef _WIN32
// ---------------------------------------------------------------------------
// fd-ordering / fsync / creation-mode seams (#4726, #4727). Capture-less
// lambdas record into these statics, then forward to the real syscall.
// ---------------------------------------------------------------------------
namespace {

struct FdRec {
    int seq = 0;
    // Descriptor numbers are REUSED (the file fd is closed before the directory
    // is opened), so each identity is cleared when its fd closes.
    int file_fd = -1, dir_fd = -1;
    int file_fsync_seq = 0, file_fchmod_seq = 0, file_close_seq = 0;
    int dir_fsync_seq = 0, dir_close_seq = 0;
    int file_fsync_n = 0, file_fchmod_n = 0, file_close_n = 0;
    int dir_fsync_n = 0, dir_close_n = 0, stray_n = 0;
    mode_t open_mode = 0;
    bool fail_fchmod = false, fail_file_fsync = false, fail_dir_fsync = false;
    bool fail_dir_close = false, fail_dir_open = false, fail_file_close = false;
    fs::path dest;
    bool dest_final_at_dir_fsync = false; // rename done + temp gone when the dir fsync ran
} g;

yuzu::shared::PosixFdOps recording_ops() {
    const auto dest = g.dest;
    g = FdRec{};
    g.dest = dest;
    yuzu::shared::PosixFdOps o;
    o.open = [](const char* p, int fl, mode_t m) {
        if ((fl & O_DIRECTORY) && g.fail_dir_open) {
            errno = EACCES;
            return -1;
        }
        const int fd = ::open(p, fl, m);
        if (fl & O_DIRECTORY) {
            g.dir_fd = fd;
        } else {
            g.file_fd = fd;
            g.open_mode = m;
        }
        return fd;
    };
    o.fsync = [](int fd) {
        if (fd == g.file_fd) {
            g.file_fsync_seq = ++g.seq;
            ++g.file_fsync_n;
            if (g.fail_file_fsync) { errno = EIO; return -1; }
        } else if (fd == g.dir_fd) {
            g.dir_fsync_seq = ++g.seq;
            ++g.dir_fsync_n;
            std::error_code ec;
            g.dest_final_at_dir_fsync =
                !g.dest.empty() && fs::exists(g.dest, ec) &&
                unexpected_entries(g.dest.parent_path(), g.dest).empty();
            if (g.fail_dir_fsync) { errno = EIO; return -1; }
        } else {
            ++g.stray_n;
        }
        return ::fsync(fd);
    };
    o.fchmod = [](int fd, mode_t m) {
        if (fd == g.file_fd) {
            g.file_fchmod_seq = ++g.seq;
            ++g.file_fchmod_n;
        } else {
            ++g.stray_n;
        }
        if (g.fail_fchmod) { errno = EPERM; return -1; }
        return ::fchmod(fd, m);
    };
    o.close = [](int fd) {
        const int rc = ::close(fd);
        if (fd == g.file_fd) {
            g.file_close_seq = ++g.seq;
            ++g.file_close_n;
            g.file_fd = -1;
            if (g.fail_file_close) { errno = EIO; return -1; }
        } else if (fd == g.dir_fd) {
            g.dir_close_seq = ++g.seq;
            ++g.dir_close_n;
            g.dir_fd = -1;
            if (g.fail_dir_close) { errno = EIO; return -1; }
        } else {
            ++g.stray_n;
        }
        return rc;
    };
    return o;
}

} // namespace

TEST_CASE("asset_tags store: fchmod and fsync run on the open fd BEFORE close (#4726)",
          "[agent][asset_tags_store]") {
    yuzu::test::TempDir dir{"yuzu_test_asset_tags_"};
    const auto dest = dir.path / "s.json";
    g.dest = dest;
    const auto ops = recording_ops();
    auto r = write_state_file_atomic(dest, "{}", {}, &ops);
    REQUIRE(wrote_clean(r));
    CHECK(g.file_fsync_n == 1);
    CHECK(g.file_fchmod_n == 1);
    CHECK(g.file_close_n == 1);
    CHECK(g.file_fsync_seq < g.file_fchmod_seq);
    CHECK(g.file_fchmod_seq < g.file_close_seq);
    // The directory fd is a second, later fsync/close pair, run only after the
    // rename has published the payload and consumed the temp.
    CHECK(g.dir_fsync_n == 1);
    CHECK(g.dir_close_n == 1);
    CHECK(g.file_close_seq < g.dir_fsync_seq);
    CHECK(g.dir_fsync_seq < g.dir_close_seq);
    CHECK(g.dest_final_at_dir_fsync);
    CHECK(g.stray_n == 0);
}

TEST_CASE("asset_tags store: a failed fchmod is a mode_unrestricted warning",
          "[agent][asset_tags_store]") {
    yuzu::test::TempDir dir{"yuzu_test_asset_tags_"};
    const auto dest = dir.path / "s.json";
    const auto ops = recording_ops();
    g.fail_fchmod = true;
    auto r = write_state_file_atomic(dest, "{}", {}, &ops);
    REQUIRE(r.has_value());
    REQUIRE(r->has_value());
    CHECK((*r)->mode_unrestricted);
    CHECK_FALSE((*r)->dir_fsync_failed);
    CHECK(fs::exists(dest));
}

TEST_CASE("asset_tags store: a failed file fsync is an IoError and leaves no temp",
          "[agent][asset_tags_store]") {
    yuzu::test::TempDir dir{"yuzu_test_asset_tags_"};
    const auto dest = dir.path / "s.json";
    const auto ops = recording_ops();
    g.fail_file_fsync = true;
    auto r = write_state_file_atomic(dest, "{}", {}, &ops);
    REQUIRE_FALSE(r.has_value());
    CHECK_FALSE(fs::exists(dest));
    CHECK(unexpected_entries(dir.path, dest).empty());
}

TEST_CASE("asset_tags store: a failed directory fsync is a dir_fsync_failed warning",
          "[agent][asset_tags_store]") {
    yuzu::test::TempDir dir{"yuzu_test_asset_tags_"};
    const auto dest = dir.path / "s.json";
    const auto ops = recording_ops();
    g.fail_dir_fsync = true;
    auto r = write_state_file_atomic(dest, "{}", {}, &ops);
    REQUIRE(r.has_value());
    REQUIRE(r->has_value());
    CHECK((*r)->dir_fsync_failed);
    CHECK_FALSE((*r)->mode_unrestricted);
    CHECK(fs::exists(dest));
}

TEST_CASE("asset_tags store: a failed directory open or close is a dir_fsync_failed warning",
          "[agent][asset_tags_store]") {
    yuzu::test::TempDir dir{"yuzu_test_asset_tags_"};
    const auto dest = dir.path / "s.json";
    g.dest = dest;
    const auto ops = recording_ops();
    SECTION("open") {
        g.fail_dir_open = true;
    }
    SECTION("close") {
        g.fail_dir_close = true;
    }
    auto r = write_state_file_atomic(dest, "{}", {}, &ops);
    REQUIRE(r.has_value());
    REQUIRE(r->has_value());
    CHECK((*r)->dir_fsync_failed);
    CHECK_FALSE((*r)->mode_unrestricted);
    CHECK(fs::exists(dest));
}

TEST_CASE("asset_tags store: creation mode follows owner_only_mode (R1)",
          "[agent][asset_tags_store]") {
    yuzu::test::TempDir dir{"yuzu_test_asset_tags_"};
    const auto ops = recording_ops();
    REQUIRE(yuzu::shared::write_file_atomic(dir.path / "a", "x", {.owner_only_mode = true, .fd_ops = &ops}).has_value());
    CHECK(g.open_mode == 0600);
    const auto ops2 = recording_ops();
    REQUIRE(yuzu::shared::write_file_atomic(dir.path / "b", "x", {.owner_only_mode = false, .fd_ops = &ops2}).has_value());
    CHECK(g.open_mode == 0666);
    CHECK(g.file_fchmod_n == 0); // no fchmod when the policy is not owner-only
}

TEST_CASE("asset_tags store: a failed file close is an IoError and leaves no temp",
          "[agent][asset_tags_store]") {
    yuzu::test::TempDir dir{"yuzu_test_asset_tags_"};
    const auto dest = dir.path / "s.json";
    std::error_code mk_ec;
    fs::create_directories(dir.path, mk_ec); // TempDir only reserves the name
    REQUIRE_FALSE(mk_ec);
    {
        std::ofstream(dest, std::ios::binary) << "ORIGINAL";
    }
    REQUIRE(fs::file_size(dest) == 8);
    const auto ops = recording_ops();
    g.fail_file_close = true;
    auto r = write_state_file_atomic(dest, "REPLACEMENT", {}, &ops);
    REQUIRE_FALSE(r.has_value());
    CHECK(r.error().message.find("close of") != std::string::npos);
    std::ifstream in(dest, std::ios::binary);
    std::string content((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    CHECK(content == "ORIGINAL");
    CHECK(unexpected_entries(dir.path, dest).empty());
}
#endif
