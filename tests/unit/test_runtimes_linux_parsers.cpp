/**
 * test_runtimes_linux_parsers.cpp -- tests for the runtimes plugin's Linux leg
 * (runtimes_linux_parsers.hpp): the portable pure layer on EVERY OS, and the
 * injected-root directory walks over a materialized fixture tree on POSIX.
 *
 * SCOPED GUARD (reasoned exception to the never-guard-a-test-TU rule): the walk
 * shell is built on agents/shared/posix_dir_walk.hpp, which does not exist on
 * Windows, so the tree walk tests sit in one `#if !defined(_WIN32)` region.
 * Everything else (manifest decoder, errno maps, wire-grammar checks) is
 * unguarded. The dispatcher TU is never guarded.
 *
 * FIXTURE TREE. tests/unit/fixtures/wave10/runtimes/linux/tree.manifest
 * describes a root subtree (REAL CAPTURE structure: eclipse-temurin:17,
 * mcr.microsoft.com/dotnet/runtime:8.0, debian:12 -- commands and dates in
 * provenance.txt), materialized under a fresh yuzu_test_runtimes_ TempDir;
 * nothing is read from a real /usr. Line grammar (decoded and tested here):
 *   <relative-path> TAB T:<text with \n \t \\ escapes> | L:<symlink target> | D:
 * Shapes the captures lack (an sdk/ directory, an oversized `release`, a planted
 * symlink) are built inline and labelled SYNTHETIC.
 *
 * MUTATION NOTES: exact-row assertions fail if a *_rows_at stops reading its
 * root or drops the vendor/flavour/version wiring;
 * resetting the accumulator per root turns the "later root never hides an
 * earlier failure" case red; dropping O_NOFOLLOW on `release` surfaces the
 * planted target as a row; following symlinked entries duplicates rows; dropping
 * the 64 KiB bound or the nullopt-row check loses the oversize/unparsable tokens;
 * discarding the rows before emit_read in run_linux_at turns the clean
 * CommandContext case red; reporting OK/FULL regardless of the accumulator turns
 * the forced-constraint CommandContext case red; requiring an alias target to
 * OPEN turns the dangling-alias case red; each budget, the release-less-home probe, the extra
 * jvm roots, the network-mount guard, the mount-table stream and the FIFO/fd cases carry their
 * mutation in their own comment. The guard-before-any-syscall orderings change which directories
 * are OPENED, not the rows or tokens, so on Linux the "never opened" case watches IN_OPEN with
 * inotify. The `exhausted` checks in dotnet_rows_at and list_entries' aggregate flag show only in
 * the token of a LATER unreadable entry and are not pinned; push_row's sticky flag is pinned by the
 * cross-root byte-budget case.
 * The chmod cases SKIP at euid 0;
 * the constrained path stays covered there by the symlink, cap and oversize
 * cases and by the forced-constraint CommandContext case, none of which needs
 * permission bits.
 */
#include <catch2/catch_test_macros.hpp>

#include "runtimes_legs.hpp"
#include "runtimes_linux_parsers.hpp"
#include "runtimes_parsers.hpp"

#include "test_helpers.hpp" // yuzu::test::TempDir

#include <cstddef>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <tuple>
#include <vector>

#if !defined(_WIN32)
#include "local_dispatcher.hpp" // yuzu::agent::LocalDispatcher (a real CommandContext)

#include <yuzu/plugin.h>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#if defined(__linux__)
#include <sys/inotify.h>
#endif
#endif

namespace rt = yuzu::runtimes;
namespace lnx = yuzu::runtimes::lnx;
namespace fs = std::filesystem;

namespace {

// -- manifest line decoder (pure; portable) ----------------------------------------

enum class ManifestKind { text, symlink, directory };

struct ManifestEntry {
    std::string rel;
    ManifestKind kind = ManifestKind::text;
    std::string payload; // decoded text | link target | (unused)
};

enum class LineOutcome { skipped, entry, malformed };

struct ParsedLine {
    LineOutcome outcome = LineOutcome::skipped;
    ManifestEntry entry;
    std::string error;
};

/// Decodes the escapes of a `T:` payload (\n, \t, \\). nullopt on a dangling
/// backslash or an unknown escape.
std::optional<std::string> unescape_text(std::string_view s) {
    std::string out;
    for (std::size_t i = 0; i < s.size(); ++i) {
        if (s[i] != '\\') {
            out += s[i];
            continue;
        }
        if (++i >= s.size()) return std::nullopt;
        switch (s[i]) {
        case 'n':  out += '\n'; break;
        case 't':  out += '\t'; break;
        case '\\': out += '\\'; break;
        default:   return std::nullopt;
        }
    }
    return out;
}

ParsedLine parse_manifest_line(std::string line) {
    ParsedLine r;
    if (!line.empty() && line.back() == '\r') line.pop_back(); // CRLF checkout tolerance
    if (line.empty() || line.front() == '#') return r;
    const auto bad = [&r](std::string msg) {
        r.outcome = LineOutcome::malformed;
        r.error = std::move(msg);
        return r;
    };
    const auto tab = line.find('\t');
    if (tab == std::string::npos || tab == 0) return bad("no tab separator: " + line);
    r.entry.rel = line.substr(0, tab);
    if (r.entry.rel.front() == '/' || r.entry.rel.find("..") != std::string::npos)
        return bad("path must be relative and inside the tree: " + r.entry.rel);
    const std::string payload = line.substr(tab + 1);
    if (payload.size() < 2 || payload[1] != ':') return bad("payload lacks a kind prefix: " + line);
    const std::string body = payload.substr(2);
    switch (payload[0]) {
    case 'T': {
        auto t = unescape_text(body);
        if (!t) return bad("bad escape in T: payload: " + line);
        r.entry.kind = ManifestKind::text;
        r.entry.payload = std::move(*t);
        break;
    }
    case 'L':
        r.entry.kind = ManifestKind::symlink;
        r.entry.payload = body;
        break;
    case 'D': r.entry.kind = ManifestKind::directory; break;
    default: return bad("unknown payload kind: " + line);
    }
    if (r.entry.kind == ManifestKind::symlink && r.entry.payload.empty())
        return bad("empty L: payload: " + line);
    r.outcome = LineOutcome::entry;
    return r;
}

bool token_matches_leg_grammar(std::string_view t) {
    // ^linux:[a-z0-9_]+(:[a-z0-9_]+)*$
    constexpr std::string_view p = "linux:";
    if (t.substr(0, p.size()) != p) return false;
    t.remove_prefix(p.size());
    bool seg_nonempty = false;
    for (char c : t) {
        if (c == ':') {
            if (!seg_nonempty) return false;
            seg_nonempty = false;
        } else if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_') {
            seg_nonempty = true;
        } else {
            return false;
        }
    }
    return seg_nonempty;
}

} // namespace

// == portable pure layer (every OS) =====================================================

TEST_CASE("runtimes linux: manifest line decoder handles every payload kind",
          "[runtimes][linux][manifest]") {
    // Blank lines and comments are skipped.
    CHECK(parse_manifest_line("").outcome == LineOutcome::skipped);
    CHECK(parse_manifest_line("# a comment\twith a tab").outcome == LineOutcome::skipped);

    auto t = parse_manifest_line("usr/x\tT:a\\nb\\tc\\\\d");
    REQUIRE(t.outcome == LineOutcome::entry);
    CHECK(t.entry.rel == "usr/x");
    CHECK(t.entry.kind == ManifestKind::text);
    CHECK(t.entry.payload == "a\nb\tc\\d");

    auto empty = parse_manifest_line("usr/empty\tT:");
    REQUIRE(empty.outcome == LineOutcome::entry);
    CHECK(empty.entry.payload.empty()); // an empty regular file

    auto crlf = parse_manifest_line("opt/r\tT:JAVA_VERSION=\"17\"\\n\r"); // CRLF tolerated
    REQUIRE(crlf.outcome == LineOutcome::entry);
    CHECK(crlf.entry.kind == ManifestKind::text);
    CHECK(crlf.entry.payload == "JAVA_VERSION=\"17\"\n");

    auto l = parse_manifest_line("usr/lib/jvm/java-1.17.0-openjdk-arm64\tL:java-17-openjdk-arm64");
    REQUIRE(l.outcome == LineOutcome::entry);
    CHECK(l.entry.kind == ManifestKind::symlink);
    CHECK(l.entry.payload == "java-17-openjdk-arm64");

    auto d = parse_manifest_line("usr/share/dotnet/sdk\tD:");
    REQUIRE(d.outcome == LineOutcome::entry);
    CHECK(d.entry.kind == ManifestKind::directory);
}

TEST_CASE("runtimes linux: manifest line decoder rejects malformed lines, never skips them",
          "[runtimes][linux][manifest]") {
    for (const char* bad : {"no-tab-here", "\tT:x", "/abs\tT:x", "a/../b\tT:x", "usr/x\tQ:x",
                            "usr/x\tnokind", "usr/x\tT:bad\\q", "usr/x\tT:dangling\\",
                            "usr/x\tF:sibling.txt", "usr/x\tL:"}) {
        INFO("line: " << bad);
        CHECK(parse_manifest_line(bad).outcome == LineOutcome::malformed);
    }
}

TEST_CASE("runtimes linux: errno maps separate absent from failure",
          "[runtimes][linux][parsers]") {
    // ENOENT is the ONLY benign case in each map.
    CHECK_FALSE(lnx::dir_open_errno_token(ENOENT).has_value());
    CHECK_FALSE(lnx::stat_errno_token(ENOENT).has_value());
    CHECK_FALSE(lnx::file_open_errno_token(ENOENT).has_value());

    CHECK(lnx::dir_open_errno_token(EACCES) == lnx::kTokPermissionDenied);
    CHECK(lnx::dir_open_errno_token(ELOOP) == lnx::kTokSymlinkRefused);
    CHECK(lnx::dir_open_errno_token(ENOTDIR) == lnx::kTokNotADirectory);
    CHECK(lnx::dir_open_errno_token(EIO) == lnx::kTokOpenFailed);
    CHECK(lnx::stat_errno_token(EACCES) == lnx::kTokPermissionDenied);
    CHECK(lnx::stat_errno_token(EIO) == lnx::kTokStatFailed);
    CHECK(lnx::file_open_errno_token(EACCES) == lnx::kTokPermissionDenied);
    CHECK(lnx::file_open_errno_token(ELOOP) == lnx::kTokSymlinkRefused);
    CHECK(lnx::file_open_errno_token(EIO) == lnx::kTokReadFailed);
}

TEST_CASE("runtimes linux: every failure token matches the leg-token grammar",
          "[runtimes][linux][parsers]") {
    for (const auto tok :
         {lnx::kTokPermissionDenied, lnx::kTokSymlinkRefused, lnx::kTokNotADirectory,
          lnx::kTokOpenFailed, lnx::kTokStatFailed, lnx::kTokReadFailed, lnx::kTokRowCap,
          lnx::kTokNotRegular, lnx::kTokOversized, lnx::kTokFieldOversized,
          lnx::kTokReleaseUnparsable, lnx::kTokReleaseMissing, lnx::kTokNetworkFsSkipped,
          lnx::kTokMountinfoUnreadable}) {
        INFO("token: " << tok);
        CHECK(token_matches_leg_grammar(tok));
    }
}

TEST_CASE("runtimes linux: the failure token spellings and the bounds are a contract",
          "[runtimes][linux][parsers]") {
    // Consumers key on these strings (README, plugin JSON); a rename must be deliberate. The shared
    // cause names (oversized, not_regular, row_cap, open_failed) match the sibling plugins.
    CHECK(lnx::kTokPermissionDenied == "linux:runtimes:permission_denied");
    CHECK(lnx::kTokSymlinkRefused == "linux:runtimes:symlink_refused");
    CHECK(lnx::kTokNotADirectory == "linux:runtimes:not_a_directory");
    CHECK(lnx::kTokOpenFailed == "linux:runtimes:open_failed");
    CHECK(lnx::kTokStatFailed == "linux:runtimes:stat_failed");
    CHECK(lnx::kTokReadFailed == "linux:runtimes:read_failed");
    CHECK(lnx::kTokRowCap == "linux:runtimes:row_cap");
    CHECK(lnx::kTokNotRegular == "linux:runtimes:not_regular");
    CHECK(lnx::kTokOversized == "linux:runtimes:oversized");
    CHECK(lnx::kTokFieldOversized == "linux:runtimes:field_oversized");
    CHECK(lnx::kTokReleaseUnparsable == "linux:runtimes:release_unparsable");
    CHECK(lnx::kTokReleaseMissing == "linux:runtimes:release_missing");
    CHECK(lnx::kTokNetworkFsSkipped == "linux:runtimes:network_fs_skipped");
    CHECK(lnx::kTokMountinfoUnreadable == "linux:runtimes:mountinfo_unreadable");
    // The production bounds, pinned by literal (a test that derived them from the constants would
    // follow a mutation of the constants).
    static_assert(lnx::kMaxDirEntries == 16384);
    static_assert(lnx::kMaxReleaseBytes == 65536);
    static_assert(lnx::kMaxRows == 4096);
    static_assert(lnx::kMaxRowBytes == 1048576);
    static_assert(lnx::kMaxEntriesVisited == 65536);
    static_assert(lnx::kMountinfoChunk == 65536);
    static_assert(lnx::kMaxMountinfoLine == 65536);
    static_assert(lnx::kMaxMountinfoBytes == 268435456);
    // The bounds a production walk actually runs under: WalkLimits{} must carry every one of them.
    static_assert(lnx::WalkLimits{}.dir_entries == 16384 && lnx::WalkLimits{}.rows == 4096 &&
                  lnx::WalkLimits{}.row_bytes == 1048576 && lnx::WalkLimits{}.entries_visited == 65536);
}

TEST_CASE("runtimes linux: join_logical avoids a doubled slash",
          "[runtimes][linux][parsers]") {
    CHECK(lnx::join_logical("/", "usr") == "/usr");
    CHECK(lnx::join_logical("/usr", "bin") == "/usr/bin");
}

// == mount-table guard, pure layer (every OS: MSVC compiles AND runs these) ===============

namespace {

fs::path fixture_dir() {
#ifdef YUZU_TEST_FIXTURE_DIR
    return fs::path(YUZU_TEST_FIXTURE_DIR) / "wave10" / "runtimes" / "linux";
#else
    return fs::path("tests/unit/fixtures/wave10/runtimes/linux");
#endif
}

std::string read_text_fixture(const char* name) {
    std::ifstream in(fixture_dir() / name, std::ios::binary);
    REQUIRE(in.good());
    return std::string(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
}

} // namespace

TEST_CASE("runtimes linux: mountinfo parsing reports the network mounts and nothing local",
          "[runtimes][linux][mounts]") {
    // The real capture (an overlay root, proc/sysfs/tmpfs/devpts/cgroup2/ext4 bind mounts and one
    // nfs4 mount): exactly the nfs4 mount point comes back.
    CHECK(lnx::network_mount_points(read_text_fixture("mountinfo_docker_nfs4.txt")) ==
          std::vector<std::string>{"/mnt/nfs"});
    // SYNTHETIC lines modelled on the real ones: octal escapes decode, optional fields before the
    // separator are skipped, fuse.overlayfs is local, a malformed line names nothing.
    const std::string text =
        "10 1 0:5 / /srv/a\\040b rw shared:1 master:2 - cifs //srv/share rw\n"
        "11 1 0:6 / /mnt/s rw - fuse.sshfs u@h:/ rw\n"
        "12 1 0:7 / /mnt/local rw - fuse.overlayfs overlay rw\n"
        "13 1 0:8 / /mnt/tmp rw - tmpfs nfs:/looks-remote rw\n"
        "no separator here\n"
        "14 1 0:9 /only - nfs4 h:/x rw\n"
        "15 1 0:10 / /mnt/n rw - nfs4 h:/x rw\n";
    CHECK(lnx::network_mount_points(text) ==
          std::vector<std::string>{"/srv/a b", "/mnt/s", "/mnt/n"});
    CHECK(lnx::network_mount_points("").empty());
    CHECK(lnx::unescape_mountinfo("a\\040b\\011c\\134d\\12") == "a b\tc\\d\\12"); // short escape kept verbatim
}

TEST_CASE("runtimes linux: a path touches a network mount when on, under or containing it",
          "[runtimes][linux][mounts]") {
    const std::vector<std::string> mounts{"/opt/java"};
    CHECK(lnx::touches_network_mount("/opt/java", mounts));
    CHECK(lnx::touches_network_mount("/opt/java/jdk-17", mounts)); // under
    CHECK(lnx::touches_network_mount("/opt", mounts));             // contains
    CHECK_FALSE(lnx::touches_network_mount("/opt/javax", mounts)); // segment boundary
    CHECK_FALSE(lnx::touches_network_mount("/usr/lib/jvm", mounts));
    CHECK(lnx::touches_network_mount("/usr/lib/jvm", std::vector<std::string>{"/"})); // NFS root
    CHECK_FALSE(lnx::touches_network_mount("/usr/lib/jvm", std::vector<std::string>{}));
}

// == walks over the fixture tree (POSIX) =================================================

#if !defined(_WIN32)

namespace {

/// Materializes tree.manifest under `root`. Returns false with `error` set on any
/// failure so the caller can REQUIRE with a useful message.
bool materialize_manifest(const fs::path& root, std::string& error,
                          const char* manifest_name = "tree.manifest") {
    const auto manifest_file = fixture_dir() / manifest_name;
    std::ifstream in(manifest_file, std::ios::binary);
    if (!in) {
        error = "could not open " + manifest_file.string();
        return false;
    }
    std::string line;
    while (std::getline(in, line)) {
        const auto p = parse_manifest_line(line);
        if (p.outcome == LineOutcome::skipped) continue;
        if (p.outcome == LineOutcome::malformed) {
            error = p.error;
            return false;
        }
        const fs::path target = root / p.entry.rel;
        std::error_code ec;
        fs::create_directories(p.entry.kind == ManifestKind::directory ? target
                                                                        : target.parent_path(),
                               ec);
        if (ec) {
            error = "create_directories failed for " + target.string() + ": " + ec.message();
            return false;
        }
        switch (p.entry.kind) {
        case ManifestKind::directory: break;
        case ManifestKind::symlink:
            fs::create_symlink(p.entry.payload, target, ec);
            if (ec) {
                error = "create_symlink failed for " + target.string() + ": " + ec.message();
                return false;
            }
            break;
        case ManifestKind::text: {
            std::ofstream out(target, std::ios::binary);
            if (!out) {
                error = "could not create " + target.string();
                return false;
            }
            out << p.entry.payload;
            break;
        }
        }
    }
    return true;
}

void write_text(const fs::path& p, const std::string& text) {
    std::error_code ec;
    fs::create_directories(p.parent_path(), ec);
    REQUIRE_FALSE(ec);
    std::ofstream out(p, std::ios::binary);
    REQUIRE(out.good());
    out << text;
}

void make_dir(const fs::path& p) {
    std::error_code ec;
    fs::create_directories(p, ec);
    REQUIRE_FALSE(ec);
}

/// Restores a path's permission bits at scope exit (declared AFTER the TempDir so it runs
/// first and remove_all can descend).
struct PermRestore {
    fs::path path;
    ~PermRestore() { ::chmod(path.c_str(), 0755); }
};

/// permission-bit cases are vacuous when the process bypasses them.
bool running_privileged() { return ::geteuid() == 0; }

using Acc = yuzu::shared::ConstraintAccumulator;

lnx::WalkConfig dir_cap(std::size_t n) {
    lnx::WalkConfig c;
    c.limits.dir_entries = n;
    return c;
}

const char* kTemurinRow = "jvm|jdk|17.0.20|/opt/java/openjdk|Eclipse Adoptium";
const char* kDebianRow = "jvm|unmodelled|17.0.20.1|/usr/lib/jvm/java-17-openjdk-arm64|Debian";
const char* kDotnetRow =
    "dotnet|core|8.0.31|/usr/share/dotnet/shared/Microsoft.NETCore.App/8.0.31|-";

// -- CommandContext-level harness --------------------------------------------------------
// Drives the PRODUCTION leg body (lnx::run_linux_at) through a real CommandContext via
// LocalDispatcher (the test_filesystem_posture_local_dispatcher.cpp precedent: a synthetic
// descriptor whose execute() calls the code under test), so what is asserted is the rows the
// command actually emits AND the typed result status it reports -- not only the walk's return
// values.

struct LegRun {
    int rc = -1;
    std::vector<std::string> rows;
    YuzuResultStatus status = YUZU_RESULT_STATUS_UNDECLARED;
    YuzuResultCompleteness completeness = YUZU_RESULT_COMPLETENESS_UNKNOWN;
    std::string provenance;
};

const fs::path* g_leg_root = nullptr;
const lnx::WalkConfig* g_leg_cfg = nullptr;

int leg_execute(YuzuCommandContext* raw, const char* action, const YuzuParam* /*params*/,
                std::size_t /*param_count*/) {
    yuzu::CommandContext ctx{raw};
    const auto a = rt::parse_action(action);
    if (!a) return 1;
    return lnx::run_linux_at(ctx, *a, *g_leg_root, *g_leg_cfg);
}

LegRun run_leg(rt::Action action, const fs::path& root, const lnx::WalkConfig& cfg = {}) {
    g_leg_root = &root;
    g_leg_cfg = &cfg;
    yuzu::test::ScopeExit reset{[] { g_leg_root = nullptr, g_leg_cfg = nullptr; }}; // even if the run throws
    YuzuPluginDescriptor descriptor{};
    descriptor.execute = &leg_execute;
    yuzu::agent::LocalDispatcher dispatcher;
    const auto result = dispatcher.run(&descriptor, rt::action_name(action));

    LegRun out;
    out.rc = result.rc;
    out.status = result.result_status;
    out.completeness = result.result_completeness;
    out.provenance = result.result_provenance;
    std::istringstream lines(result.captured);
    for (std::string line; std::getline(lines, line);)
        if (!line.empty()) out.rows.push_back(line);
    return out;
}

} // namespace

TEST_CASE("runtimes linux: jvm_rows_at reads both roots' release files, skips the alias symlink",
          "[runtimes][linux][walk]") {
    yuzu::test::TempDir dir{"yuzu_test_runtimes_jvm_"};
    std::string err;
    REQUIRE(materialize_manifest(dir.path, err));
    Acc acc;
    const auto rows = lnx::jvm_rows_at(dir.path, acc);
    CHECK_FALSE(acc.any_failure());
    // Root order: /usr/lib/jvm (Debian, no IMAGE_TYPE -> unmodelled), then /opt/java (Temurin).
    // java-1.17.0-openjdk-arm64 is a symlink alias of java-17-openjdk-arm64: not a second row.
    REQUIRE(rows.size() == 2);
    CHECK(rows[0] == kDebianRow);
    CHECK(rows[1] == kTemurinRow);
}

TEST_CASE("runtimes linux: dotnet_rows_at reads the captured runtime tree",
          "[runtimes][linux][walk]") {
    yuzu::test::TempDir dir{"yuzu_test_runtimes_dotnet_"};
    std::string err;
    REQUIRE(materialize_manifest(dir.path, err));
    Acc acc;
    const auto rows = lnx::dotnet_rows_at(dir.path, acc);
    CHECK_FALSE(acc.any_failure());
    REQUIRE(rows.size() == 1);
    CHECK(rows[0] == kDotnetRow);
}

TEST_CASE("runtimes linux: dotnet sdk, unmodelled framework and non-version entries (SYNTHETIC)",
          "[runtimes][linux][walk]") {
    // SYNTHETIC tree: the captured runtime image has no sdk/ directory and no unusual entries.
    // Modelled on the documented dotnet install layout (shared/<fw>/<ver>, sdk/<ver>).
    yuzu::test::TempDir dir{"yuzu_test_runtimes_dotnet_syn_"};
    make_dir(dir.path / "usr/lib64/dotnet/sdk/8.0.100");
    make_dir(dir.path / "usr/lib64/dotnet/sdk/NuGetFallbackFolder"); // not a version
    write_text(dir.path / "usr/lib64/dotnet/sdk/9.0.100", "a file, not a version dir");
    make_dir(dir.path / "usr/lib64/dotnet/shared/Microsoft.AspNetCore.App/8.0.31");
    make_dir(dir.path / "usr/lib64/dotnet/shared/Some.Other.App/1.0.0");
    make_dir(dir.path / "usr/lib64/dotnet/shared/Microsoft.NETCore.App/not a version");
    Acc acc;
    const auto rows = lnx::dotnet_rows_at(dir.path, acc);
    CHECK_FALSE(acc.any_failure());
    REQUIRE(rows.size() == 3);
    // shared/ frameworks first (sorted by name), then sdk/.
    CHECK(rows[0] == "dotnet|core|8.0.31|/usr/lib64/dotnet/shared/Microsoft.AspNetCore.App/8.0.31|-");
    CHECK(rows[1] == "dotnet|unmodelled|1.0.0|/usr/lib64/dotnet/shared/Some.Other.App/1.0.0|-");
    CHECK(rows[2] == "dotnet|sdk|8.0.100|/usr/lib64/dotnet/sdk/8.0.100|-");
}

TEST_CASE("runtimes linux: an absent root is supported with zero rows, not constrained",
          "[runtimes][linux][walk]") {
    yuzu::test::TempDir dir{"yuzu_test_runtimes_absent_"};
    make_dir(dir.path); // exists, empty
    for (const fs::path& root : {dir.path, dir.path / "no_such_root"}) {
        INFO("root: " << root.string());
        Acc acc;
        CHECK(lnx::dotnet_rows_at(root, acc).empty());
        CHECK(lnx::jvm_rows_at(root, acc).empty());
        CHECK_FALSE(acc.any_failure());
        const auto out = rt::compose_output("jvm", {}, acc);
        REQUIRE(out.size() == 1);
        CHECK(out[0] == "status|jvm|supported|-");
    }
}

TEST_CASE("runtimes linux: an unreadable directory is constrained with a token, never absent",
          "[runtimes][linux][walk]") {
    if (running_privileged()) SKIP("running as root (or CAP_DAC_OVERRIDE): permission bits bypassed");
    yuzu::test::TempDir dir{"yuzu_test_runtimes_eacces_"};
    std::string err;
    REQUIRE(materialize_manifest(dir.path, err));
    const PermRestore restore{dir.path / "usr/lib/jvm"};
    REQUIRE(::chmod(restore.path.c_str(), 0000) == 0);

    Acc acc;
    const auto rows = lnx::jvm_rows_at(dir.path, acc);

    // The first root (/usr/lib/jvm) failed; the second (/opt/java) still succeeded and its row is
    // present -- and the later success did NOT erase the earlier failure (mutation: resetting the
    // accumulator per root makes this constrained assertion fail).
    REQUIRE(rows.size() == 1);
    CHECK(rows[0] == kTemurinRow);
    REQUIRE(acc.any_failure());
    CHECK(acc.reason() == std::string{lnx::kTokPermissionDenied});
    const auto out = rt::compose_output("jvm", rows, acc);
    REQUIRE(out.size() == 2);
    CHECK(out[0] == "status|jvm|constrained|linux:runtimes:permission_denied");
    CHECK(out[1] == kTemurinRow);
}

TEST_CASE("runtimes linux: an unreadable release file is constrained and yields no row",
          "[runtimes][linux][walk]") {
    if (running_privileged()) SKIP("running as root (or CAP_DAC_OVERRIDE): permission bits bypassed");
    yuzu::test::TempDir dir{"yuzu_test_runtimes_release_eacces_"};
    std::string err;
    REQUIRE(materialize_manifest(dir.path, err));
    const PermRestore restore{dir.path / "opt/java/openjdk/release"};
    REQUIRE(::chmod(restore.path.c_str(), 0000) == 0);

    Acc acc;
    const auto rows = lnx::jvm_rows_at(dir.path, acc);
    REQUIRE(rows.size() == 1); // only the Debian home
    CHECK(rows[0] == kDebianRow);
    REQUIRE(acc.any_failure());
    CHECK(acc.reason() == std::string{lnx::kTokPermissionDenied});
}

TEST_CASE("runtimes linux: a symlinked release file is refused, not followed (SYNTHETIC)",
          "[runtimes][linux][walk]") {
    // SYNTHETIC: a `release` that is a symlink to a real, parseable file elsewhere in the tree.
    // O_NOFOLLOW must refuse it (mutation: dropping O_NOFOLLOW surfaces the target as a row).
    yuzu::test::TempDir dir{"yuzu_test_runtimes_release_link_"};
    write_text(dir.path / "elsewhere/release", "JAVA_VERSION=\"21.0.1\"\nIMAGE_TYPE=\"JDK\"\n");
    make_dir(dir.path / "usr/lib/jvm/evil");
    std::error_code ec;
    fs::create_symlink(dir.path / "elsewhere/release", dir.path / "usr/lib/jvm/evil/release", ec);
    REQUIRE_FALSE(ec);

    Acc acc;
    const auto rows = lnx::jvm_rows_at(dir.path, acc);
    CHECK(rows.empty());
    REQUIRE(acc.any_failure());
    CHECK(acc.reason() == std::string{lnx::kTokSymlinkRefused});
}

TEST_CASE("runtimes linux: a symlinked candidate root is an alias, skipped without following",
          "[runtimes][linux][walk]") {
    // SYNTHETIC: Fedora's /usr/share/dotnet -> ../lib64/dotnet. The real tree is read through its
    // own candidate path; the symlinked candidate contributes nothing and is not a failure.
    yuzu::test::TempDir dir{"yuzu_test_runtimes_alias_"};
    make_dir(dir.path / "usr/lib64/dotnet/shared/Microsoft.NETCore.App/8.0.31");
    make_dir(dir.path / "usr/share");
    std::error_code ec;
    fs::create_symlink("../lib64/dotnet", dir.path / "usr/share/dotnet", ec);
    REQUIRE_FALSE(ec);

    Acc acc;
    const auto rows = lnx::dotnet_rows_at(dir.path, acc);
    CHECK_FALSE(acc.any_failure());
    REQUIRE(rows.size() == 1); // exactly once, via the real path
    CHECK(rows[0] == "dotnet|core|8.0.31|/usr/lib64/dotnet/shared/Microsoft.NETCore.App/8.0.31|-");
}

TEST_CASE("runtimes linux: a symlinked intermediate component is not followed",
          "[runtimes][linux][walk]") {
    // SYNTHETIC: /usr/lib64 -> lib (Arch). The candidate /usr/lib64/dotnet resolves through a
    // symlinked parent, which is refused hop-by-hop; /usr/lib/dotnet is the real path.
    yuzu::test::TempDir dir{"yuzu_test_runtimes_alias_mid_"};
    make_dir(dir.path / "usr/lib/dotnet/sdk/8.0.100");
    std::error_code ec;
    fs::create_symlink("lib", dir.path / "usr/lib64", ec);
    REQUIRE_FALSE(ec);

    Acc acc;
    const auto rows = lnx::dotnet_rows_at(dir.path, acc);
    CHECK_FALSE(acc.any_failure());
    REQUIRE(rows.size() == 1);
    CHECK(rows[0] == "dotnet|sdk|8.0.100|/usr/lib/dotnet/sdk/8.0.100|-");
}

TEST_CASE("runtimes linux: a dangling in-set candidate alias is genuine absence, not constrained "
          "(SYNTHETIC)",
          "[runtimes][linux][walk]") {
    // Arch: /usr/lib64 -> lib on EVERY host, here with no .NET installed. The candidate
    // /usr/lib64/dotnet stops at the lib64 alias; its target /usr/lib/dotnet is another candidate
    // that is simply absent, so the family is absent: supported + zero rows. MUTATION:
    // alias_is_covered requiring the target to OPEN (== OpenStatus::opened) records
    // symlink_refused here and reports a stock host as constrained.
    yuzu::test::TempDir with_lib{"yuzu_test_runtimes_dangling_"};
    make_dir(with_lib.path / "usr/lib"); // exists, holds no dotnet
    yuzu::test::TempDir without_lib{"yuzu_test_runtimes_dangling2_"};
    make_dir(without_lib.path / "usr"); // no usr/lib at all
    for (const fs::path& root : {with_lib.path, without_lib.path}) {
        INFO("root: " << root.string());
        std::error_code ec;
        fs::create_symlink("lib", root / "usr/lib64", ec);
        REQUIRE_FALSE(ec);
        Acc acc;
        CHECK(lnx::dotnet_rows_at(root, acc).empty());
        CHECK_FALSE(acc.any_failure());
        const auto out = rt::compose_output("dotnet", {}, acc);
        REQUIRE(out.size() == 1);
        CHECK(out[0] == "status|dotnet|supported|-");
    }

    // jvm: /opt/java -> ../usr/lib/jvm with no JVM installed anywhere.
    yuzu::test::TempDir jvm{"yuzu_test_runtimes_dangling_jvm_"};
    make_dir(jvm.path / "opt");
    std::error_code ec;
    fs::create_symlink("../usr/lib/jvm", jvm.path / "opt/java", ec);
    REQUIRE_FALSE(ec);
    Acc acc;
    CHECK(lnx::jvm_rows_at(jvm.path, acc).empty());
    CHECK_FALSE(acc.any_failure());
}

TEST_CASE("runtimes linux: a refused symlink with no alternative candidate is constrained, not "
          "an empty success (SYNTHETIC)",
          "[runtimes][linux][walk]") {
    // /usr/share/dotnet points OUTSIDE the candidate set and every other candidate is absent: the
    // install it names is unread, so the result must not claim "no dotnet" (supported + zero rows).
    yuzu::test::TempDir dir{"yuzu_test_runtimes_refused_"};
    make_dir(dir.path / "srv/dotnet/shared/Microsoft.NETCore.App/8.0.31");
    make_dir(dir.path / "usr/share");
    std::error_code ec;
    fs::create_symlink("../../srv/dotnet", dir.path / "usr/share/dotnet", ec);
    REQUIRE_FALSE(ec);

    Acc acc;
    const auto rows = lnx::dotnet_rows_at(dir.path, acc);
    CHECK(rows.empty()); // not followed
    REQUIRE(acc.any_failure());
    CHECK(acc.reason() == std::string{lnx::kTokSymlinkRefused});
    const auto out = rt::compose_output("dotnet", rows, acc);
    REQUIRE(out.size() == 1);
    CHECK(out[0] == "status|dotnet|constrained|linux:runtimes:symlink_refused");
}

TEST_CASE("runtimes linux: an absolute link target is read from the injected root (SYNTHETIC)",
          "[runtimes][linux][walk]") {
    // Production /usr/share/dotnet -> /usr/lib64/dotnet: an absolute target naming another
    // candidate is a covered alias; one naming anything else (/etc/alternatives) is refused.
    yuzu::test::TempDir dir{"yuzu_test_runtimes_abs_"};
    make_dir(dir.path / "usr/lib64/dotnet/sdk/8.0.100");
    make_dir(dir.path / "usr/share");
    std::error_code ec;
    fs::create_symlink("/usr/lib64/dotnet", dir.path / "usr/share/dotnet", ec);
    REQUIRE_FALSE(ec);
    Acc covered;
    const auto rows = lnx::dotnet_rows_at(dir.path, covered);
    CHECK_FALSE(covered.any_failure());
    REQUIRE(rows.size() == 1);
    CHECK(rows[0] == "dotnet|sdk|8.0.100|/usr/lib64/dotnet/sdk/8.0.100|-");

    yuzu::test::TempDir other{"yuzu_test_runtimes_abs2_"};
    make_dir(other.path / "usr/share");
    fs::create_symlink("/etc/alternatives/dotnet", other.path / "usr/share/dotnet", ec);
    REQUIRE_FALSE(ec);
    Acc refused;
    CHECK(lnx::dotnet_rows_at(other.path, refused).empty());
    REQUIRE(refused.any_failure());
    CHECK(refused.reason() == std::string{lnx::kTokSymlinkRefused});
}

TEST_CASE("runtimes linux: mutually aliasing candidates are refused, not both trusted (SYNTHETIC)",
          "[runtimes][linux][walk]") {
    // usr/share/dotnet -> ../lib/dotnet and usr/lib/dotnet -> ../share/dotnet: each names the
    // other, neither opens directly, so no directory is ever read. The cycle must be constrained.
    yuzu::test::TempDir dir{"yuzu_test_runtimes_cycle_"};
    make_dir(dir.path / "usr/share");
    make_dir(dir.path / "usr/lib");
    std::error_code ec;
    fs::create_symlink("../lib/dotnet", dir.path / "usr/share/dotnet", ec);
    REQUIRE_FALSE(ec);
    fs::create_symlink("../share/dotnet", dir.path / "usr/lib/dotnet", ec);
    REQUIRE_FALSE(ec);
    Acc acc;
    CHECK(lnx::dotnet_rows_at(dir.path, acc).empty());
    REQUIRE(acc.any_failure());
    CHECK(acc.reason() == std::string{lnx::kTokSymlinkRefused});
}

TEST_CASE("runtimes linux: a symlinked shared/ or sdk/ subdirectory is refused (SYNTHETIC)",
          "[runtimes][linux][walk]") {
    yuzu::test::TempDir dir{"yuzu_test_runtimes_subdir_"};
    make_dir(dir.path / "usr/lib/dotnet");
    make_dir(dir.path / "srv/sdk/8.0.100");
    std::error_code ec;
    fs::create_symlink("../../../srv/sdk", dir.path / "usr/lib/dotnet/sdk", ec);
    REQUIRE_FALSE(ec);
    Acc acc;
    CHECK(lnx::dotnet_rows_at(dir.path, acc).empty());
    REQUIRE(acc.any_failure());
    CHECK(acc.reason() == std::string{lnx::kTokSymlinkRefused});
}

TEST_CASE("runtimes linux: a symlinked jvm root with no alternative is refused (SYNTHETIC)",
          "[runtimes][linux][walk]") {
    yuzu::test::TempDir dir{"yuzu_test_runtimes_refused_jvm_"};
    make_dir(dir.path / "srv/jvm/jdk/");
    write_text(dir.path / "srv/jvm/jdk/release", "JAVA_VERSION=\"21.0.1\"\nIMAGE_TYPE=\"JDK\"\n");
    make_dir(dir.path / "usr/lib");
    std::error_code ec;
    fs::create_symlink("../../srv/jvm", dir.path / "usr/lib/jvm", ec);
    REQUIRE_FALSE(ec);

    Acc jvm_acc;
    CHECK(lnx::jvm_rows_at(dir.path, jvm_acc).empty());
    REQUIRE(jvm_acc.any_failure());
    CHECK(jvm_acc.reason() == std::string{lnx::kTokSymlinkRefused});
}

TEST_CASE("runtimes linux: the per-directory cap bounds the rows and becomes `row_cap` "
          "(SYNTHETIC)",
          "[runtimes][linux][walk][cap]") {
    // The cap is a parameter (production: kMaxDirEntries = 16384) so this needs 5 directories,
    // not 16k. Mutations: dropping the cap argument in a walk enumerates all 5 rows; dropping
    // the `res.truncated` record leaves the accumulator clean.
    constexpr std::size_t kCap = 3;
    yuzu::test::TempDir dir{"yuzu_test_runtimes_cap_"};
    for (const char* v : {"8.0.100", "8.0.101", "8.0.102", "8.0.103", "8.0.104"})
        make_dir(dir.path / "usr/lib/dotnet/sdk" / v);
    for (const char* h : {"a", "b", "c", "d", "e"})
        write_text(dir.path / "usr/lib/jvm" / h / "release", "JAVA_VERSION=\"17.0.1\"\n");

    const auto check_truncated = [](const std::vector<std::string>& rows, const Acc& acc) {
        CHECK(rows.size() == kCap); // bounded, not all 5
        REQUIRE(acc.any_failure());
        CHECK(acc.reason() == std::string{lnx::kTokRowCap});
    };
    {
        Acc acc;
        check_truncated(lnx::dotnet_rows_at(dir.path, acc, dir_cap(kCap)), acc);
    }
    {
        Acc acc;
        check_truncated(lnx::jvm_rows_at(dir.path, acc, dir_cap(kCap)), acc);
    }
    // Boundary: a directory holding exactly `cap` entries is complete, not truncated.
    {
        Acc acc;
        CHECK(lnx::dotnet_rows_at(dir.path, acc, dir_cap(5)).size() == 5);
        CHECK_FALSE(acc.any_failure());
    }
    // The truncated output is constrained, never a bare full-looking inventory.
    {
        Acc acc;
        const auto rows = lnx::dotnet_rows_at(dir.path, acc, dir_cap(kCap));
        const auto out = rt::compose_output("dotnet", rows, acc);
        REQUIRE(out.size() == kCap + 1);
        CHECK(out[0] == "status|dotnet|constrained|linux:runtimes:row_cap");
    }
}

TEST_CASE("runtimes linux: a release over 64 KiB is constrained, exactly 64 KiB is read (SYNTHETIC)",
          "[runtimes][linux][walk]") {
    // The edge is pinned by LITERAL size (65536 ok, 65537 refused) so a mutated kMaxReleaseBytes
    // cannot follow the test. A comment line pads: it is not a `KEY=value` line, so it is ignored.
    const auto release_of_size = [](std::size_t total) {
        std::string body = "JAVA_VERSION=\"17.0.1\"\n#";
        body += std::string(total - body.size() - 1, 'A');
        body += '\n';
        return body;
    };
    for (const auto& [size, expect_row] :
         {std::pair{std::size_t{65536}, true}, std::pair{std::size_t{65537}, false}}) {
        INFO("release bytes: " << size);
        yuzu::test::TempDir dir{"yuzu_test_runtimes_oversize_"};
        write_text(dir.path / "opt/java/big/release", release_of_size(size));
        Acc acc;
        const auto rows = lnx::jvm_rows_at(dir.path, acc);
        CHECK(rows.size() == (expect_row ? 1u : 0u));
        CHECK(acc.any_failure() == !expect_row);
        if (!expect_row) CHECK(acc.reason() == std::string{lnx::kTokOversized});
    }
}

TEST_CASE("runtimes linux: a version-less release is constrained; a home without one is silent "
          "(SYNTHETIC)",
          "[runtimes][linux][walk]") {
    yuzu::test::TempDir dir{"yuzu_test_runtimes_unparsable_"};
    write_text(dir.path / "usr/lib/jvm/garbled/release", "not a release file\nMODULES=\"java.base\"\n");
    make_dir(dir.path / "usr/lib/jvm/not-a-jvm"); // no release file: not a JVM home
    write_text(dir.path / "usr/lib/jvm/.hidden.jinfo", "a file, ignored");
    Acc acc;
    const auto rows = lnx::jvm_rows_at(dir.path, acc);
    CHECK(rows.empty());
    REQUIRE(acc.any_failure());
    CHECK(acc.reason() == std::string{lnx::kTokReleaseUnparsable}); // only the garbled one
}

TEST_CASE("runtimes linux: action_rows_at routes each action to its own walk",
          "[runtimes][linux][walk][wire]") {
    // The injected entry point run_linux_at is `action_rows_at` + emit_read. Exact-row
    // equality per action fails if a switch arm is removed (empty rows -> a `supported` status
    // with no data) or two arms are swapped.
    yuzu::test::TempDir dir{"yuzu_test_runtimes_dispatch_"};
    std::string err;
    REQUIRE(materialize_manifest(dir.path, err));

    Acc jvm_acc;
    const auto jvm = lnx::action_rows_at(rt::Action::jvm, dir.path, jvm_acc);
    CHECK_FALSE(jvm_acc.any_failure());
    CHECK(jvm == std::vector<std::string>{kDebianRow, kTemurinRow});

    Acc dn_acc;
    const auto dn = lnx::action_rows_at(rt::Action::dotnet, dir.path, dn_acc);
    CHECK_FALSE(dn_acc.any_failure());
    CHECK(dn == std::vector<std::string>{kDotnetRow});

    // The composed output a consumer sees: status row first, then the rows, per action.
    for (const auto& [action, rows, acc] :
         {std::tuple{rt::Action::jvm, &jvm, &jvm_acc},
          std::tuple{rt::Action::dotnet, &dn, &dn_acc}}) {
        const auto out = rt::compose_output(rt::action_name(action), *rows, *acc);
        REQUIRE(out.size() == rows->size() + 1);
        CHECK(out[0] == std::string{"status|"} + std::string{rt::action_name(action)} +
                            "|supported|-");
    }
}

TEST_CASE("runtimes linux: action_rows_at carries a failure through for every action",
          "[runtimes][linux][walk][wire]") {
    // A refused (symlinked, no alternative) candidate for each action must surface through the
    // dispatch as a recorded failure -- an arm that dropped its accumulator would report supported.
    yuzu::test::TempDir dir{"yuzu_test_runtimes_dispatch_fail_"};
    make_dir(dir.path / "usr/lib");
    make_dir(dir.path / "usr/share");
    make_dir(dir.path / "srv");
    std::error_code ec;
    fs::create_symlink("../../srv", dir.path / "usr/share/dotnet", ec);
    REQUIRE_FALSE(ec);
    fs::create_symlink("../../srv", dir.path / "usr/lib/jvm", ec);
    REQUIRE_FALSE(ec);
    for (const auto action : {rt::Action::dotnet, rt::Action::jvm}) {
        INFO("action: " << rt::action_name(action));
        Acc acc;
        CHECK(lnx::action_rows_at(action, dir.path, acc).empty());
        REQUIRE(acc.any_failure());
        CHECK(acc.reason() == std::string{lnx::kTokSymlinkRefused});
    }
}

TEST_CASE("runtimes linux: run_linux_at emits the populated rows and OK/FULL through a real "
          "CommandContext",
          "[runtimes][linux][walk][wire]") {
    // The populated jvm and dotnet rows are asserted here at the command level, not just below
    // the emission seam (action_rows_at): the host-independent replacement for a host-guaranteed
    // populated-row assertion (a CI runner may have no JVM or .NET installed).
    // MUTATION: discarding the rows before emit_read in run_linux_at (`emit_read(ctx, a, {}, acc)`)
    // leaves only the status row and fails the exact-row assertions below; dropping the status
    // row fails them too. The CONSTRAINED arm of emit_read is pinned by the next case.
    yuzu::test::TempDir dir{"yuzu_test_runtimes_leg_"};
    std::string err;
    REQUIRE(materialize_manifest(dir.path, err));

    const auto jvm = run_leg(rt::Action::jvm, dir.path);
    CHECK(jvm.rc == 0);
    // status row first, then the two captured homes in root order (the alias symlink is no row).
    CHECK(jvm.rows == std::vector<std::string>{"status|jvm|supported|-", kDebianRow, kTemurinRow});
    CHECK(jvm.status == YUZU_RESULT_STATUS_OK);
    CHECK(jvm.completeness == YUZU_RESULT_COMPLETENESS_FULL);
    CHECK(jvm.provenance.empty());

    const auto dn = run_leg(rt::Action::dotnet, dir.path);
    CHECK(dn.rc == 0);
    CHECK(dn.rows == std::vector<std::string>{"status|dotnet|supported|-", kDotnetRow});
    CHECK(dn.status == YUZU_RESULT_STATUS_OK);
    CHECK(dn.completeness == YUZU_RESULT_COMPLETENESS_FULL);
    CHECK(dn.provenance.empty());
}

TEST_CASE("runtimes linux: run_linux_at reports a forced constraint through BOTH the status row "
          "and the typed status of a real CommandContext",
          "[runtimes][linux][walk][wire]") {
    // The failure source is a planted symlink, refused by O_NOFOLLOW on every POSIX host, root
    // included -- no chmod, so no euid-0 SKIP: this case runs everywhere. The real rows are
    // still read, so one run pins "rows survive" AND "the typed status degrades".
    // MUTATION (an orchestrator probe confirmed it survived before this case existed): making
    // emit_read report OK/FULL regardless of the accumulator turns every status/completeness/
    // provenance assertion below red while the status ROW still says `constrained`.
    yuzu::test::TempDir dir{"yuzu_test_runtimes_leg_constrained_"};
    std::string err;
    REQUIRE(materialize_manifest(dir.path, err));
    std::error_code ec;
    // jvm: a symlinked `release` in an extra home; the two captured homes are still read.
    write_text(dir.path / "elsewhere/release", "JAVA_VERSION=\"21.0.1\"\nIMAGE_TYPE=\"JDK\"\n");
    make_dir(dir.path / "usr/lib/jvm/evil");
    fs::create_symlink(dir.path / "elsewhere/release", dir.path / "usr/lib/jvm/evil/release", ec);
    REQUIRE_FALSE(ec);
    // dotnet: a symlinked fixed `sdk` subdirectory is refused outright; shared/ is still read.
    fs::create_symlink("../../../srv/sdk", dir.path / "usr/share/dotnet/sdk", ec);
    REQUIRE_FALSE(ec);

    const auto jvm = run_leg(rt::Action::jvm, dir.path);
    CHECK(jvm.rc == 0); // a degraded read is never a failed command
    CHECK(jvm.rows == std::vector<std::string>{
              "status|jvm|constrained|linux:runtimes:symlink_refused", kDebianRow, kTemurinRow});
    CHECK(jvm.status == YUZU_RESULT_STATUS_CONSTRAINED);
    CHECK(jvm.completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
    CHECK(jvm.provenance == std::string{lnx::kTokSymlinkRefused}); // one seam, two views

    const auto dn = run_leg(rt::Action::dotnet, dir.path);
    CHECK(dn.rc == 0);
    CHECK(dn.rows == std::vector<std::string>{
              "status|dotnet|constrained|linux:runtimes:symlink_refused", kDotnetRow});
    CHECK(dn.status == YUZU_RESULT_STATUS_CONSTRAINED);
    CHECK(dn.completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
    CHECK(dn.provenance == std::string{lnx::kTokSymlinkRefused});
}

// == budgets, release-less homes, extra roots, network guard, hostile inputs =================

namespace {

lnx::WalkConfig limits_cfg(const lnx::WalkLimits& l) {
    lnx::WalkConfig c;
    c.limits = l;
    return c;
}

std::string release_with(std::string_view version) {
    return "JAVA_VERSION=\"" + std::string{version} + "\"\n";
}

int open_fd_count() {
    int n = 0;
    for (int fd = 0; fd < 1024; ++fd)
        if (::fcntl(fd, F_GETFD) != -1) ++n;
    return n;
}

} // namespace

TEST_CASE("runtimes linux: the row and row-byte budgets bound the rows and report row_cap (SYNTHETIC)",
          "[runtimes][linux][walk][cap]") {
    // Six homes, one row each. MUTATION: dropping push_row's row or byte check returns all six.
    yuzu::test::TempDir dir{"yuzu_test_runtimes_rowcap_"};
    for (const char* h : {"a", "b", "c", "d", "e", "f"})
        write_text(dir.path / "usr/lib/jvm" / h / "release", release_with("17.0.1"));
    const std::size_t row_len = std::string{"jvm|unmodelled|17.0.1|/usr/lib/jvm/a|-"}.size();
    struct Case { std::size_t rows, bytes, expect; bool capped; };
    for (const Case& c : {Case{3, 1 << 20, 3, true}, Case{6, 1 << 20, 6, false},   // rows: n+? and exactly n
                          Case{99, 2 * row_len, 2, true}, Case{99, 2 * row_len - 1, 1, true},
                          Case{99, 6 * row_len, 6, false}}) {                        // bytes: edge both sides
        INFO("rows=" << c.rows << " bytes=" << c.bytes);
        lnx::WalkLimits l;
        l.rows = c.rows;
        l.row_bytes = c.bytes;
        Acc acc;
        CHECK(lnx::jvm_rows_at(dir.path, acc, limits_cfg(l)).size() == c.expect);
        CHECK(acc.any_failure() == c.capped);
        if (c.capped) CHECK(acc.reason() == std::string{lnx::kTokRowCap});
    }
}

TEST_CASE("runtimes linux: a spent byte budget stops the walk, so a smaller later row is not admitted "
          "(SYNTHETIC)",
          "[runtimes][linux][walk][cap]") {
    // The rows returned must be a PREFIX of the walk. MUTATION: dropping `b.exhausted = true` in
    // push_row admits /opt/java/c after /usr/lib/jvm/b was refused for size (1 row becomes 2).
    yuzu::test::TempDir dir{"yuzu_test_runtimes_bytes_root_"};
    write_text(dir.path / "usr/lib/jvm/a/release", release_with("1"));
    write_text(dir.path / "usr/lib/jvm/b/release", release_with(std::string(100, '9')));
    write_text(dir.path / "opt/java/c/release", release_with("1"));
    lnx::WalkLimits l;
    l.row_bytes = std::string{"jvm|unmodelled|1|/usr/lib/jvm/a|-"}.size() +
                  std::string{"jvm|unmodelled|1|/opt/java/c|-"}.size();
    Acc acc;
    CHECK(lnx::jvm_rows_at(dir.path, acc, limits_cfg(l)).size() == 1);
    CHECK(acc.reason() == std::string{lnx::kTokRowCap});
}

TEST_CASE("runtimes linux: the entries-visited budget spans nesting levels and roots (SYNTHETIC)",
          "[runtimes][linux][walk][cap]") {
    // usr/share/dotnet: 2 frameworks x 3 versions = 2 + 3 + 3 = 8 entries visited; usr/lib/dotnet
    // (the second root) holds one sdk. MUTATION: charging nothing to the budget walks both roots
    // in full whatever the limit.
    yuzu::test::TempDir dir{"yuzu_test_runtimes_entries_"};
    for (const char* fw : {"Microsoft.AspNetCore.App", "Microsoft.NETCore.App"})
        for (const char* v : {"8.0.1", "8.0.2", "8.0.3"})
            make_dir(dir.path / "usr/share/dotnet/shared" / fw / v);
    make_dir(dir.path / "usr/lib/dotnet/sdk/9.0.100");
    struct Case { std::size_t entries, expect; bool capped; };
    for (const Case& c : {Case{100, 7, false}, Case{8, 6, true}, Case{5, 3, true}}) {
        INFO("entries_visited=" << c.entries);
        lnx::WalkLimits l;
        l.entries_visited = c.entries;
        Acc acc;
        CHECK(lnx::dotnet_rows_at(dir.path, acc, limits_cfg(l)).size() == c.expect);
        CHECK(acc.any_failure() == c.capped);
        if (c.capped) CHECK(acc.reason() == std::string{lnx::kTokRowCap});
    }
}

TEST_CASE("runtimes linux: the per-directory cap applies at every listing site (SYNTHETIC)",
          "[runtimes][linux][walk][cap]") {
    // dotnet shared/ (frameworks), shared/<fw>/ (versions), sdk/, and the jvm root (homes): each
    // tree has ONE directory of 3 entries against a cap of 2; the control has none over the cap.
    const auto build = [](const fs::path& r, int site) {
        const auto dn = r / "usr/share/dotnet";
        if (site == 0) for (const char* f : {"F1", "F2", "F3"}) make_dir(dn / "shared" / f / "8.0.1");
        if (site == 1) for (const char* v : {"8.0.1", "8.0.2", "8.0.3"}) make_dir(dn / "shared/F1" / v);
        if (site == 2) for (const char* v : {"8.0.100", "8.0.101", "8.0.102"}) make_dir(dn / "sdk" / v);
        if (site == 3) for (const char* h : {"a", "b", "c"}) write_text(r / "usr/lib/jvm" / h / "release", release_with("17"));
        if (site == 4) { make_dir(dn / "shared/F1/8.0.1"); make_dir(dn / "shared/F2/8.0.1"); }
    };
    for (int site = 0; site <= 4; ++site) {
        INFO("site: " << site << (site == 4 ? " (control)" : ""));
        yuzu::test::TempDir dir{"yuzu_test_runtimes_sites_"};
        build(dir.path, site);
        Acc acc;
        (void)lnx::dotnet_rows_at(dir.path, acc, dir_cap(2));
        (void)lnx::jvm_rows_at(dir.path, acc, dir_cap(2));
        CHECK(acc.any_failure() == (site != 4));
        if (site != 4) CHECK(acc.reason() == std::string{lnx::kTokRowCap});
    }
}

TEST_CASE("runtimes linux: an oversized release VALUE is field_oversized and the row survives (SYNTHETIC)",
          "[runtimes][linux][walk]") {
    // A JAVA_VERSION of 257 bytes is dropped (no version -> release_unparsable too); an oversized
    // IMPLEMENTOR is dropped but the version still yields a row.
    yuzu::test::TempDir dir{"yuzu_test_runtimes_value_"};
    write_text(dir.path / "usr/lib/jvm/vendor/release",
               "JAVA_VERSION=\"17.0.1\"\nIMPLEMENTOR=\"" + std::string(257, 'v') + "\"\n");
    write_text(dir.path / "usr/lib/jvm/version/release",
               "JAVA_VERSION=\"" + std::string(257, '1') + "\"\nIMPLEMENTOR=\"x\"\n");
    Acc acc;
    const auto rows = lnx::jvm_rows_at(dir.path, acc);
    REQUIRE(rows.size() == 1);
    CHECK(rows[0] == "jvm|unmodelled|17.0.1|/usr/lib/jvm/vendor|-");
    CHECK(acc.reason() == std::string{lnx::kTokFieldOversized} + "," + std::string{lnx::kTokReleaseUnparsable});
}

TEST_CASE("runtimes linux: an OpenJDK 8 home with no release file is still a row (REAL CAPTURE)",
          "[runtimes][linux][walk][jdk8]") {
    // Ubuntu, Rocky and Alpine OpenJDK 8 packages ship NO `release` file (jdk_layouts.manifest).
    // MUTATION: dropping the java-binary probe leaves zero rows and `supported`; probing only
    // bin/java fails Rocky (jre/bin/java only). The bin/java-only branch has no real capture, so the
    // last case is SYNTHETIC.
    yuzu::test::TempDir dir{"yuzu_test_runtimes_jdk8_"};
    std::string err;
    REQUIRE(materialize_manifest(dir.path, err, "jdk_layouts.manifest"));
    struct Layout { const char* root; const char* row; };
    for (const Layout& l :
         {Layout{"ubuntu2204-openjdk8", "jvm|unmodelled|-|/usr/lib/jvm/java-8-openjdk-arm64|-"},
          Layout{"rocky9-openjdk8", "jvm|unmodelled|-|/usr/lib/jvm/java-1.8.0-openjdk-1.8.0.504.b01-1.2.el9_8.aarch64|-"},
          Layout{"alpine320-openjdk8", "jvm|unmodelled|-|/usr/lib/jvm/java-1.8-openjdk|-"}}) {
        INFO("layout: " << l.root);
        Acc acc;
        const auto rows = lnx::jvm_rows_at(dir.path / "roots" / l.root, acc); // aliases and .jinfo: no rows
        REQUIRE(rows.size() == 1);
        CHECK(rows[0] == l.row);
        CHECK(acc.reason() == std::string{lnx::kTokReleaseMissing});
        CHECK(rt::compose_output("jvm", rows, acc)[0] == "status|jvm|constrained|linux:runtimes:release_missing");
    }
    yuzu::test::TempDir syn{"yuzu_test_runtimes_jdk8_syn_"};
    write_text(syn.path / "opt/java/only-bin/bin/java", "");
    make_dir(syn.path / "opt/java/no-java/bin"); // a bin/ without java: not a JVM home
    Acc acc;
    const auto rows = lnx::jvm_rows_at(syn.path, acc);
    REQUIRE(rows.size() == 1);
    CHECK(rows[0] == "jvm|unmodelled|-|/opt/java/only-bin|-");
}

TEST_CASE("runtimes linux: a release-less home's java probe records what it cannot check (SYNTHETIC)",
          "[runtimes][linux][walk][jdk8]") {
    // MUTATIONS: folding a failed stat into "no java"; dropping the alias flag; refusing though the
    // jre route found java; accepting any dirent named java as a JVM.
    const auto probe = [](auto&& setup, std::vector<std::string> rows, std::string_view reason) {
        yuzu::test::TempDir d{"yuzu_test_runtimes_probe_"};
        setup(d.path / "opt/java");
        Acc acc;
        CHECK(lnx::jvm_rows_at(d.path, acc) == rows);
        CHECK(acc.reason() == reason);
    };
    const auto link = [](const char* to, const fs::path& at) { fs::create_symlink(to, at); };
    probe([&](const fs::path& j) { write_text(j / "h/real/java", ""); link("real", j / "h/bin"); },
          {}, lnx::kTokSymlinkRefused); // a symlinked bin is never followed, but never silent
    probe([&](const fs::path& j) { write_text(j / "g/jre/bin/java", ""); link("jre/bin", j / "g/bin"); },
          {"jvm|unmodelled|-|/opt/java/g|-"}, lnx::kTokReleaseMissing); // found via jre: no refusal
    probe([&](const fs::path& j) {
              make_dir(j / "d/bin/java");
              make_dir(j / "f/bin");
              REQUIRE(::mkfifo((j / "f/bin/java").c_str(), 0644) == 0);
          },
          {}, ""); // a directory or FIFO named java is no JVM
    // bin/ readable but not searchable: fstatat(java) is EACCES
    if (running_privileged()) SKIP("euid 0: permission bits are bypassed, the unsearchable-bin case is not run");
    yuzu::test::TempDir dir{"yuzu_test_runtimes_binstat_"};
    write_text(dir.path / "opt/java/h/bin/java", "");
    REQUIRE(::chmod((dir.path / "opt/java/h/bin").c_str(), 0644) == 0);
    const PermRestore restore{dir.path / "opt/java/h/bin"};
    Acc acc;
    CHECK(lnx::jvm_rows_at(dir.path, acc).empty());
    CHECK(acc.reason() == std::string{lnx::kTokPermissionDenied});
}

TEST_CASE("runtimes linux: openSUSE keeps JVMs under /usr/lib64/jvm (REAL CAPTURE layout)",
          "[runtimes][linux][walk][roots]") {
    // SUSE has no /usr/lib/jvm; the verbatim release file is the manifest payload. MUTATION:
    // dropping usr/lib64/jvm from kJvmRoots yields zero rows and `supported` on a host with Java.
    yuzu::test::TempDir dir{"yuzu_test_runtimes_suse_"};
    std::string err;
    REQUIRE(materialize_manifest(dir.path, err, "jdk_layouts.manifest"));
    Acc acc;
    const auto rows = lnx::jvm_rows_at(dir.path / "roots/opensuse156-openjdk17", acc);
    CHECK_FALSE(acc.any_failure());
    REQUIRE(rows.size() == 1); // the four jre* alias symlinks are no rows
    CHECK(rows[0] == "jvm|unmodelled|17.0.18|/usr/lib64/jvm/java-17-openjdk-17|N/A");
}

TEST_CASE("runtimes linux: /opt -> var/opt (rpm-ostree) is a covered alias, not a refusal (SYNTHETIC)",
          "[runtimes][linux][walk][roots]") {
    // Fedora CoreOS/Silverblue/RHCOS/RHEL Edge link /opt to var/opt. MUTATION: dropping var/opt/java
    // from kJvmRoots reports symlink_refused on EVERY jvm dispatch of such a host, Java or not.
    yuzu::test::TempDir dir{"yuzu_test_runtimes_ostree_"};
    make_dir(dir.path / "var/opt");
    std::error_code ec;
    fs::create_symlink("var/opt", dir.path / "opt", ec);
    REQUIRE_FALSE(ec);
    {
        Acc acc;
        CHECK(lnx::jvm_rows_at(dir.path, acc).empty());
        CHECK_FALSE(acc.any_failure()); // no Java installed: silent, not constrained
    }
    write_text(dir.path / "var/opt/java/temurin-17/release",
               "JAVA_VERSION=\"17.0.20\"\nIMPLEMENTOR=\"Eclipse Adoptium\"\nIMAGE_TYPE=\"JDK\"\n");
    Acc acc;
    const auto rows = lnx::jvm_rows_at(dir.path, acc);
    CHECK_FALSE(acc.any_failure());
    REQUIRE(rows.size() == 1); // once, through its own candidate
    CHECK(rows[0] == "jvm|jdk|17.0.20|/var/opt/java/temurin-17|Eclipse Adoptium");
}

TEST_CASE("runtimes linux: a candidate on a network mount is skipped and the other roots are still read "
          "(SYNTHETIC)",
          "[runtimes][linux][walk][mounts]") {
    // opt/java is a regular FILE here: had the walk opened it, `not_a_directory` would join the
    // token. Only network_fs_skipped is allowed, and the other roots are still read.
    // MUTATION: dropping the guard adds not_a_directory (the file is opened as a directory); moving it
    // after walk_path is pinned by the inotify case below.
    yuzu::test::TempDir dir{"yuzu_test_runtimes_guard_"};
    write_text(dir.path / "opt/java", "a file where a mount would be");
    write_text(dir.path / "usr/lib/jvm/deb/release", release_with("17.0.20.1"));
    lnx::WalkConfig cfg;
    cfg.network_mounts = {"/opt/java"};
    Acc acc;
    const auto rows = lnx::jvm_rows_at(dir.path, acc, cfg);
    REQUIRE(rows.size() == 1);
    CHECK(acc.reason() == std::string{lnx::kTokNetworkFsSkipped});
    // An ancestor mount (/usr/lib) and a mount below the candidate both skip it.
    yuzu::test::TempDir only{"yuzu_test_runtimes_guard2_"};
    write_text(only.path / "usr/lib/jvm/deb/release", release_with("17.0.20.1"));
    for (const char* mount : {"/usr/lib", "/usr/lib/jvm/deb"}) {
        INFO("mount: " << mount);
        cfg.network_mounts = {mount};
        Acc a2;
        CHECK(lnx::jvm_rows_at(only.path, a2, cfg).empty());
        CHECK(a2.reason() == std::string{lnx::kTokNetworkFsSkipped});
    }
    // An alias whose target is a network-mounted candidate is not opened either: the target
    // records the skip, the alias adds nothing (no symlink_refused).
    yuzu::test::TempDir al{"yuzu_test_runtimes_guard_alias_"};
    make_dir(al.path / "usr/lib/dotnet/sdk/8.0.100");
    make_dir(al.path / "usr/share");
    std::error_code ec;
    fs::create_symlink("../lib/dotnet", al.path / "usr/share/dotnet", ec);
    REQUIRE_FALSE(ec);
    cfg.network_mounts = {"/usr/lib/dotnet"};
    Acc a3;
    CHECK(lnx::dotnet_rows_at(al.path, a3, cfg).empty());
    CHECK(a3.reason() == std::string{lnx::kTokNetworkFsSkipped});
}

TEST_CASE("runtimes linux: run_linux_at hands the guard to both walks (SYNTHETIC)",
          "[runtimes][linux][walk][mounts]") {
    // MUTATION: dropping cfg in run_linux_at, or in an action_rows_at arm, leaves that action
    // unguarded: the file at the mount point is opened and adds not_a_directory.
    yuzu::test::TempDir dir{"yuzu_test_runtimes_wiring_"};
    write_text(dir.path / "opt/java", "a file where a mount would be");
    write_text(dir.path / "usr/lib/dotnet", "a file where a mount would be");
    lnx::WalkConfig cfg;
    cfg.network_mounts = {"/opt/java", "/usr/lib/dotnet"};
    for (const auto a : {rt::Action::jvm, rt::Action::dotnet}) {
        const auto run = run_leg(a, dir.path, cfg);
        CHECK(run.rows == std::vector<std::string>{"status|" + std::string{rt::action_name(a)} +
                                                    "|constrained|linux:runtimes:network_fs_skipped"});
        CHECK(run.status == YUZU_RESULT_STATUS_CONSTRAINED);
    }
}

#if defined(__linux__)

namespace {

/// IN_OPEN watch: the only way to observe that a walk NEVER touched a directory (skipping the
/// guard's position changes which syscalls run, not the rows or tokens).
struct OpenWatch {
    yuzu::agent::ScopedFd fd{::inotify_init1(IN_NONBLOCK | IN_CLOEXEC)};
    const bool armed; // false when inotify is unavailable (instance or watch limit): the caller SKIPs
    explicit OpenWatch(const fs::path& p)
        : armed(fd.valid() && ::inotify_add_watch(fd.get(), p.c_str(), IN_OPEN) >= 0) {}
    [[nodiscard]] bool opened() const {
        char buf[512];
        return ::read(fd.get(), buf, sizeof buf) > 0;
    }
};

} // namespace

TEST_CASE("runtimes linux: a network-mounted candidate is never opened, directly or through an alias "
          "(SYNTHETIC)",
          "[runtimes][linux][walk][mounts]") {
    // MUTATION: checking the guard after walk_path, or after resolving an alias's target, opens the
    // mount (in production a hung one) before skipping it; rows and tokens are unchanged.
    yuzu::test::TempDir dir{"yuzu_test_runtimes_never_"};
    make_dir(dir.path / "opt/java/jdk");
    make_dir(dir.path / "usr/lib/dotnet/sdk/8.0.100");
    make_dir(dir.path / "usr/share");
    fs::create_symlink("../lib/dotnet", dir.path / "usr/share/dotnet");
    const OpenWatch jvm{dir.path / "opt/java"}, dotnet{dir.path / "usr/lib/dotnet"};
    if (!jvm.armed || !dotnet.armed) SKIP("inotify unavailable (instance or watch limit)");
    lnx::WalkConfig cfg;
    cfg.network_mounts = {"/opt/java", "/usr/lib/dotnet"};
    Acc a, b;
    CHECK(lnx::jvm_rows_at(dir.path, a, cfg).empty());
    CHECK(lnx::dotnet_rows_at(dir.path, b, cfg).empty());
    CHECK(a.reason() == std::string{lnx::kTokNetworkFsSkipped});
    CHECK(b.reason() == std::string{lnx::kTokNetworkFsSkipped});
    CHECK_FALSE(jvm.opened());
    CHECK_FALSE(dotnet.opened());
}

TEST_CASE("runtimes linux: the read loop bounds a file whose fstat size lies (procfs)",
          "[runtimes][linux][walk]") {
    // procfs reports st_size 0, so the in-loop bound is the ONLY bound. MUTATION: removing it reads
    // a procfs (or growing) file without limit.
    const auto r = lnx::walk::read_file_bounded_at(AT_FDCWD, "/proc/self/status", 64);
    CHECK(r.status == lnx::walk::ReadStatus::failed);
    CHECK(r.token == lnx::kTokOversized);
}

#endif // __linux__

TEST_CASE("runtimes linux: the mount table is scanned, an unreadable one is reported and the tree still read",
          "[runtimes][linux][walk][mounts]") {
    const auto scan = lnx::walk::scan_mounts((fixture_dir() / "mountinfo_docker_nfs4.txt").c_str());
    CHECK(scan.ok);
    CHECK(scan.network_mounts == std::vector<std::string>{"/mnt/nfs"});
    CHECK_FALSE(lnx::walk::scan_mounts((fixture_dir() / "no_such_mountinfo").c_str()).ok);
    CHECK_FALSE(lnx::walk::scan_mounts(fixture_dir().c_str()).ok); // a directory is not a mount table

    yuzu::test::TempDir dir{"yuzu_test_runtimes_mi_"};
    std::string err;
    REQUIRE(materialize_manifest(dir.path, err));
    lnx::WalkConfig cfg;
    cfg.mountinfo_unreadable = true;
    const auto run = run_leg(rt::Action::jvm, dir.path, cfg);
    CHECK(run.rows == std::vector<std::string>{
              "status|jvm|constrained|linux:runtimes:mountinfo_unreadable", kDebianRow, kTemurinRow});
    CHECK(run.status == YUZU_RESULT_STATUS_CONSTRAINED);
}

TEST_CASE("runtimes linux: production_config arms the guard from the mount table it is pointed at",
          "[runtimes][linux][mounts]") {
    // MUTATION: a config that never reads the table (or drops its result) leaves the guard unarmed.
    const auto cfg = lnx::production_config((fixture_dir() / "mountinfo_docker_nfs4.txt").c_str());
    CHECK(cfg.network_mounts == std::vector<std::string>{"/mnt/nfs"});
    CHECK_FALSE(cfg.mountinfo_unreadable);
    CHECK(lnx::production_config((fixture_dir() / "no_such_mountinfo").c_str()).mountinfo_unreadable);
}

TEST_CASE("runtimes linux: the mount table is streamed: a line split across reads is kept and the bounds "
          "hold (SYNTHETIC)",
          "[runtimes][linux][mounts]") {
    // MUTATION: parsing each read on its own loses the network line that straddles the first 64 KiB
    // boundary; a whole-table size cap fails the guard OPEN on the busiest hosts.
    yuzu::test::TempDir dir{"yuzu_test_runtimes_stream_"};
    const std::string local = "20 1 0:20 / /mnt/l rw - ext4 /dev/sda1 rw\n";
    const std::string nfs = "21 1 0:21 / /mnt/straddle rw - nfs4 h:/x rw\n";
    std::string text(lnx::kMountinfoChunk - 21, 'x'); // a filler line that ends 20 bytes before the boundary
    text += "\n" + nfs;
    while (text.size() < 3 * lnx::kMountinfoChunk) text += local;
    text += "22 1 0:22 / /mnt/last rw - cifs //h/s rw"; // no trailing newline
    write_text(dir.path / "mountinfo", text);
    const auto scan = lnx::walk::scan_mounts((dir.path / "mountinfo").c_str());
    CHECK(scan.ok);
    CHECK(scan.network_mounts == std::vector<std::string>{"/mnt/straddle", "/mnt/last"});
    // A line too long to keep is skipped, not fatal: mounts before it are kept, mounts after it are
    // armed (one in its newline's read, one at the next read boundary), `ok` is false and
    // production_config keeps them all. MUTATION: a wrong resume, an uncleared head or a discarded
    // partial result loses one of the three.
    const std::size_t chunk = lnx::kMountinfoChunk;
    const std::string before = "20 1 0:20 / /mnt/before rw - nfs4 h:/z rw\n";
    const std::string head = "23 1 0:23 / /mnt/long rw - overlay overlay rw,lowerdir=";
    const std::string after = "24 1 0:24 / /mnt/after rw - nfs4 h:/y rw\n";
    write_text(dir.path / "longline",
               before + head + std::string(3 * chunk - before.size() - head.size(), 'x') + "\n" +
                   after + std::string(chunk - 2 - after.size(), 'y') + "\n" + nfs);
    const auto longscan = lnx::walk::scan_mounts((dir.path / "longline").c_str());
    const std::vector<std::string> armed{"/mnt/before", "/mnt/after", "/mnt/straddle"};
    CHECK_FALSE(longscan.ok);
    CHECK(longscan.network_mounts == armed);
    const auto cfg = lnx::production_config((dir.path / "longline").c_str());
    CHECK(cfg.mountinfo_unreadable);
    CHECK(cfg.network_mounts == armed);
    const auto size = fs::file_size(dir.path / "mountinfo");
    CHECK(lnx::walk::scan_mounts((dir.path / "mountinfo").c_str(), size).ok);
    CHECK_FALSE(lnx::walk::scan_mounts((dir.path / "mountinfo").c_str(), size - 1).ok);
    // A FIFO reads as an empty table (EOF, no writer): only the regular-file check refuses it.
    REQUIRE(::mkfifo((dir.path / "fifo").c_str(), 0644) == 0);
    CHECK_FALSE(lnx::walk::scan_mounts((dir.path / "fifo").c_str()).ok);
}

TEST_CASE("runtimes linux: a FIFO or directory named release is refused without blocking (SYNTHETIC)",
          "[runtimes][linux][walk]") {
    // MUTATION: dropping O_NONBLOCK from the release open makes the FIFO case hang forever; dropping
    // the S_ISREG check reads the directory (EISDIR -> read_failed) instead of not_regular.
    yuzu::test::TempDir dir{"yuzu_test_runtimes_fifo_"};
    make_dir(dir.path / "usr/lib/jvm/fifo");
    REQUIRE(::mkfifo((dir.path / "usr/lib/jvm/fifo/release").c_str(), 0644) == 0);
    make_dir(dir.path / "usr/lib/jvm/dir/release");
    Acc acc;
    CHECK(lnx::jvm_rows_at(dir.path, acc).empty());
    CHECK(acc.reason() == std::string{lnx::kTokNotRegular});
}

TEST_CASE("runtimes linux: a FIFO where a directory is expected is not_a_directory, never a hang "
          "(SYNTHETIC)",
          "[runtimes][linux][walk]") {
    // MUTATION: dropping O_DIRECTORY from kDirFlags makes open(2) of a FIFO block for a writer.
    for (const char* rel : {"usr/lib/dotnet/sdk", "usr/lib/dotnet/shared", "opt/java/h/bin", "opt/java/h/jre"}) {
        INFO("fifo at: " << rel);
        yuzu::test::TempDir dir{"yuzu_test_runtimes_fifodir_"};
        make_dir((dir.path / rel).parent_path());
        REQUIRE(::mkfifo((dir.path / rel).c_str(), 0644) == 0);
        Acc acc;
        (void)lnx::action_rows_at(std::string_view{rel}.starts_with("opt") ? rt::Action::jvm : rt::Action::dotnet,
                                  dir.path, acc);
        CHECK(acc.reason() == std::string{lnx::kTokNotADirectory});
    }
}

TEST_CASE("runtimes linux: a plain file where a directory is expected is constrained, not absent "
          "(SYNTHETIC)",
          "[runtimes][linux][walk]") {
    yuzu::test::TempDir jvm{"yuzu_test_runtimes_notdir_jvm_"};
    write_text(jvm.path / "usr/lib/jvm", "a file, not a directory");
    Acc a1;
    CHECK(lnx::jvm_rows_at(jvm.path, a1).empty());
    CHECK(a1.reason() == std::string{lnx::kTokNotADirectory});

    yuzu::test::TempDir dn{"yuzu_test_runtimes_notdir_dn_"};
    write_text(dn.path / "usr/lib/dotnet/shared", "a file, not a directory");
    make_dir(dn.path / "usr/lib/dotnet/sdk/8.0.100");
    Acc a2;
    const auto rows = lnx::dotnet_rows_at(dn.path, a2);
    CHECK(rows == std::vector<std::string>{"dotnet|sdk|8.0.100|/usr/lib/dotnet/sdk/8.0.100|-"});
    CHECK(a2.reason() == std::string{lnx::kTokNotADirectory});
}

TEST_CASE("runtimes linux: every descriptor a walk opens is closed on success and failure paths",
          "[runtimes][linux][walk]") {
    // MUTATION: dropping closedir (DirHandle) or the release ScopedFd leaves descriptors open, so
    // the count after the walks exceeds the count before them.
    yuzu::test::TempDir dir{"yuzu_test_runtimes_fds_"};
    std::string err;
    REQUIRE(materialize_manifest(dir.path, err));
    REQUIRE(materialize_manifest(dir.path, err, "jdk_layouts.manifest"));
    make_dir(dir.path / "usr/lib/jvm/fifo");
    REQUIRE(::mkfifo((dir.path / "usr/lib/jvm/fifo/release").c_str(), 0644) == 0);
    write_text(dir.path / "opt/java/big/release", std::string(70000, 'x')); // oversize refusal
    const int before = open_fd_count();
    for (int i = 0; i < 3; ++i) {
        for (const auto a : {rt::Action::jvm, rt::Action::dotnet}) {
            Acc acc;
            (void)lnx::action_rows_at(a, dir.path, acc);
            Acc capped;
            (void)lnx::action_rows_at(a, dir.path, capped, dir_cap(1)); // the row_cap path
        }
        Acc acc;
        (void)lnx::jvm_rows_at(dir.path / "roots/rocky9-openjdk8", acc); // the java-binary probe
        (void)lnx::walk::scan_mounts((fixture_dir() / "mountinfo_docker_nfs4.txt").c_str());
        (void)lnx::walk::scan_mounts(fixture_dir().c_str()); // refused: a directory
    }
    CHECK(open_fd_count() == before);
}

TEST_CASE("runtimes linux: an action with no walk arm is a visible failure, never supported + 0 rows",
          "[runtimes][linux][walk]") {
    Acc acc;
    CHECK(lnx::action_rows_at(static_cast<rt::Action>(99), "/nonexistent", acc).empty());
    CHECK(acc.reason() == "internal_error");
}

#endif // !defined(_WIN32)
