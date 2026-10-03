/**
 * test_update_source_trust_linux_parsers.cpp -- manifest-materialised tree
 * suite for the update_source_trust Linux leg (lnx::apt_rows_at /
 * lnx::rpm_family_planned_at / lnx::linux_rows_at / lnx::run_linux_at in
 * update_source_trust_linux_parsers.hpp).
 *
 * WHAT THIS ADDS. test_update_source_trust_parsers.cpp drives the same walk
 * over the per-distro capture trees. This TU layers ONE composite root
 * on top: tests/unit/fixtures/wave10/update_source_trust/linux/tree.manifest
 * merges a real debian:bookworm deb822 source and a real ubuntu:22.04 one-line
 * sources.list with labelled RECONSTRUCTION entries (a third-party apt source
 * pair, a keyring, three names the apt filters must ignore, and a placeholder
 * /etc/yum.repos.d/placeholder.repo standing for the deferred rpm/dnf family)
 * into a single host-shaped tree, so
 * the apt rows and the rpm family's planned constraint come from the SAME root:
 * one mixed host, walked once. Row bytes are asserted exactly, and the
 * tripwire's three cases (directory with entries -> constrained `planned`;
 * empty or absent -> supported; unreadable -> a real failure token) plus the
 * failure paths (absent, EACCES) are checked on that tree.
 * The [seam] cases drive the PRODUCTION leg body (lnx::run_linux_at) through
 * a real CommandContext, so the wire status row AND the typed result are what
 * is asserted, not only the walk's return values.
 *
 * MANIFEST GRAMMAR (defined and unit-tested HERE). One line per file:
 *     <relative path> TAB <payload>
 * with payload  T:<text; escapes \n \t \\>  |  B:<base64>  |  F:<committed
 * fixture path relative to the manifest's directory>  |  L:<symlink target>.
 * Blank lines and lines starting with '#' are skipped. F: exists so the real
 * captures are never duplicated into the manifest. The materialiser is
 * TU-local on purpose (test_peripherals_linux_parsers.cpp is its ancestor and
 * is not includable: its copy is in an anonymous namespace).
 *
 * POSIX ONLY. The walk shell under test is `#if !defined(_WIN32)`
 * (agents/shared/posix_dir_walk.hpp; no <dirent.h> on Windows), so the whole
 * TU body is guarded the same way test_posix_dir_walk.cpp guards its own. The
 * portable pure parsers and the dispatcher have their own unguarded TUs.
 */
#include <catch2/catch_test_macros.hpp>

#if !defined(_WIN32)

#include "update_source_trust_linux_parsers.hpp"

#include "local_dispatcher.hpp"
#include "test_helpers.hpp" // yuzu::test::TempDir

#include <constraint_accumulator.hpp>
#include <yuzu/plugin.h>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <algorithm>
#include <cstddef>
#include <cstring>
#include <filesystem>
#include <format>
#include <functional>
#include <fstream>
#include <iterator>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace {

namespace fs = std::filesystem;
namespace lnx = yuzu::update_source_trust::lnx;
namespace ust = yuzu::update_source_trust;

fs::path fixture_dir() {
#ifdef YUZU_TEST_FIXTURE_DIR
    return fs::path(YUZU_TEST_FIXTURE_DIR) / "wave10" / "update_source_trust" / "linux";
#else
    return fs::path("tests/unit/fixtures/wave10/update_source_trust/linux");
#endif
}

// ── manifest materialiser ─────────────────────────────────────────────────

std::optional<std::string> base64_decode(std::string_view in) {
    std::string out;
    unsigned buf = 0;
    int bits = 0;
    std::size_t pad = 0;
    for (const char c : in) {
        int v;
        if (c >= 'A' && c <= 'Z')
            v = c - 'A';
        else if (c >= 'a' && c <= 'z')
            v = c - 'a' + 26;
        else if (c >= '0' && c <= '9')
            v = c - '0' + 52;
        else if (c == '+')
            v = 62;
        else if (c == '/')
            v = 63;
        else if (c == '=') {
            ++pad;
            continue;
        } else
            return std::nullopt;
        if (pad != 0)
            return std::nullopt; // data after padding
        buf = (buf << 6) | static_cast<unsigned>(v);
        bits += 6;
        if (bits >= 8) {
            bits -= 8;
            out.push_back(static_cast<char>((buf >> bits) & 0xFFu));
        }
    }
    return out;
}

std::optional<std::string> unescape_text(std::string_view in) {
    std::string out;
    for (std::size_t i = 0; i < in.size(); ++i) {
        if (in[i] != '\\') {
            out.push_back(in[i]);
            continue;
        }
        if (++i >= in.size())
            return std::nullopt;
        switch (in[i]) {
        case 'n': out.push_back('\n'); break;
        case 't': out.push_back('\t'); break;
        case '\\': out.push_back('\\'); break;
        default: return std::nullopt;
        }
    }
    return out;
}

/// A manifest path must stay under the root: relative, no `..`, no backslash.
bool safe_rel_path(std::string_view rel) {
    if (rel.empty() || rel.front() == '/' || rel.find('\\') != std::string_view::npos)
        return false;
    std::size_t i = 0;
    while (i <= rel.size()) {
        const std::size_t j = rel.find('/', i);
        const std::string_view seg = rel.substr(i, j == std::string_view::npos ? j : j - i);
        if (seg.empty() || seg == "..")
            return false;
        if (j == std::string_view::npos)
            break;
        i = j + 1;
    }
    return true;
}

/// Writes every manifest entry under `root` (created if missing). false + `error`
/// on any malformed line or I/O failure so the calling REQUIRE names the cause
/// instead of a downstream "0 rows" mismatch.
bool materialize_tree(std::string_view manifest, const fs::path& fixtures, const fs::path& root,
                      std::string& error) {
    std::error_code ec;
    fs::create_directories(root, ec);
    if (ec) {
        error = "create_directories(root): " + ec.message();
        return false;
    }
    std::size_t pos = 0;
    while (pos < manifest.size()) {
        const std::size_t nl = manifest.find('\n', pos);
        std::string_view line =
            manifest.substr(pos, nl == std::string_view::npos ? std::string_view::npos : nl - pos);
        pos = nl == std::string_view::npos ? manifest.size() : nl + 1;
        if (!line.empty() && line.back() == '\r') // CRLF-checkout tolerance
            line.remove_suffix(1);
        if (line.empty() || line.front() == '#')
            continue;
        const std::size_t tab = line.find('\t');
        if (tab == std::string_view::npos) {
            error = "no tab separator: " + std::string{line};
            return false;
        }
        const std::string_view rel = line.substr(0, tab);
        const std::string_view payload = line.substr(tab + 1);
        if (!safe_rel_path(rel) || payload.size() < 2 || payload[1] != ':') {
            error = "bad path or payload prefix: " + std::string{line.substr(0, 80)};
            return false;
        }
        const fs::path out = root / fs::path(std::string{rel});
        fs::create_directories(out.parent_path(), ec);
        if (ec) {
            error = "create_directories(" + out.parent_path().string() + "): " + ec.message();
            return false;
        }
        const std::string_view body = payload.substr(2);
        std::optional<std::string> bytes;
        switch (payload[0]) {
        case 'T': bytes = unescape_text(body); break;
        case 'B': bytes = base64_decode(body); break;
        case 'F': {
            if (!safe_rel_path(body)) {
                error = "bad F: path: " + std::string{body};
                return false;
            }
            std::ifstream in(fixtures / fs::path(std::string{body}), std::ios::binary);
            if (!in) {
                error = "F: source not readable: " + std::string{body};
                return false;
            }
            bytes = std::string(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());
            break;
        }
        case 'L':
            fs::create_symlink(std::string{body}, out, ec);
            if (ec) {
                error = "create_symlink: " + ec.message();
                return false;
            }
            continue;
        default:
            error = "unknown payload kind: " + std::string{line.substr(0, 80)};
            return false;
        }
        if (!bytes) {
            error = "undecodable payload for " + std::string{rel};
            return false;
        }
        std::ofstream f(out, std::ios::binary);
        f.write(bytes->data(), static_cast<std::streamsize>(bytes->size()));
        if (!f) {
            error = "write failed: " + out.string();
            return false;
        }
    }
    return true;
}

bool materialize_manifest_file(const fs::path& root, std::string& error) {
    const fs::path mf = fixture_dir() / "tree.manifest";
    std::ifstream in(mf, std::ios::binary);
    if (!in) {
        error = "could not open " + mf.string();
        return false;
    }
    const std::string text((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    return materialize_tree(text, fixture_dir(), root, error);
}

std::string slurp(const fs::path& p) {
    std::ifstream in(p, std::ios::binary);
    return std::string((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
}

// ── row helpers ───────────────────────────────────────────────────────────

/// Escape-aware split: safe_output_field writes a literal '|' as `\|`.
std::vector<std::string> split_wire(const std::string& row) {
    std::vector<std::string> out;
    std::string cur;
    for (std::size_t i = 0; i < row.size(); ++i) {
        if (row[i] == '\\' && i + 1 < row.size() && row[i + 1] == '|') {
            cur += '|';
            ++i;
        } else if (row[i] == '|') {
            out.push_back(cur);
            cur.clear();
        } else {
            cur += row[i];
        }
    }
    out.push_back(cur);
    return out;
}

bool reason_has(const yuzu::shared::ConstraintAccumulator& acc, std::string_view token) {
    return acc.reason().find(token) != std::string::npos;
}

/// Restores a chmod-000 path in every exit path so TempDir can remove the tree.
struct PermRestore {
    fs::path path;
    ~PermRestore() { ::chmod(path.c_str(), 0700); }
};

// The tree is built fresh per test (a TempDir under the yuzu_test_ prefix).
struct Tree {
    yuzu::test::TempDir dir{"yuzu_test_update_source_trust_linux_"};
    Tree() {
        std::string error;
        const bool ok = materialize_manifest_file(dir.path, error);
        INFO(error);
        REQUIRE(ok);
    }
};

std::vector<std::string> captured_rows(const std::string& captured) {
    std::vector<std::string> out;
    std::istringstream ss(captured);
    std::string line;
    while (std::getline(ss, line)) {
        if (!line.empty() && line.back() == '\r')
            line.pop_back();
        if (!line.empty())
            out.push_back(line);
    }
    return out;
}

// ── CommandContext-level harness ─────────────────────────────────────────
// Drives the PRODUCTION leg body (lnx::run_linux_at) through a real
// yuzu::CommandContext via LocalDispatcher (the synthetic-descriptor precedent
// in test_filesystem_posture_local_dispatcher.cpp), so what is asserted is the
// emitted status row AND the CC-07 typed status the command actually reports.
const fs::path* g_leg_root = nullptr;

int leg_execute(YuzuCommandContext* raw, const char* /*action*/, const YuzuParam* /*params*/,
                std::size_t /*param_count*/) {
    yuzu::CommandContext ctx{raw};
    return lnx::run_linux_at(ctx, *g_leg_root);
}

yuzu::agent::LocalDispatcher::Result run_leg(const fs::path& root) {
    g_leg_root = &root;
    YuzuPluginDescriptor descriptor{};
    descriptor.execute = &leg_execute;
    yuzu::agent::LocalDispatcher dispatcher;
    auto result = dispatcher.run(&descriptor, "sources");
    g_leg_root = nullptr;
    return result;
}

} // namespace

// ── the manifest grammar itself ───────────────────────────────────────────

TEST_CASE("tree.manifest grammar: T/B/F/L payloads, comments and CRLF materialise byte-exactly",
          "[update_source_trust][walk][manifest]") {
    yuzu::test::TempDir dir{"yuzu_test_update_source_trust_grammar_"};
    const std::string manifest =
        "# a comment\r\n"
        "\r\n"
        "a/t.txt\tT:one\\ntwo\\tx\\\\y\r\n"
        "a/b/bin.dat\tB:mQENBA==\n"
        "c/copy.sources\tF:debian-bookworm/etc/apt/sources.list.d/debian.sources\n"
        "d/link\tL:/nonexistent-target\n";
    std::string error;
    const bool built = materialize_tree(manifest, fixture_dir(), dir.path, error);
    INFO(error);
    REQUIRE(built);
    // MUTATION: a wrong unescape, a base64 decoder off by one, or F: not reading the
    // committed fixture each change one of these.
    CHECK(slurp(dir.path / "a/t.txt") == "one\ntwo\tx\\y");
    CHECK(slurp(dir.path / "a/b/bin.dat") == std::string("\x99\x01\x0d\x04", 4));
    CHECK(slurp(dir.path / "c/copy.sources") ==
          slurp(fixture_dir() / "debian-bookworm/etc/apt/sources.list.d/debian.sources"));
    CHECK_FALSE(slurp(dir.path / "c/copy.sources").empty());
    CHECK(fs::is_symlink(dir.path / "d/link"));
    CHECK(fs::read_symlink(dir.path / "d/link") == fs::path("/nonexistent-target"));
}

TEST_CASE("tree.manifest grammar: malformed lines and path escapes are refused, not skipped",
          "[update_source_trust][walk][manifest]") {
    for (const char* bad : {
             "no-tab-here\n",
             "a/b\tX:unknown-kind\n",
             "a/b\tB:!!!notbase64\n",
             "a/b\tT:bad escape \\q\n",
             "../escape\tT:x\n",
             "/abs/path\tT:x\n",
             "a/../b\tT:x\n",
             "a/b\tF:../linux/tree.manifest\n",
             "a/b\tF:does/not/exist\n",
         }) {
        yuzu::test::TempDir dir{"yuzu_test_update_source_trust_badgrammar_"};
        std::string error;
        INFO("manifest line: " << bad);
        CHECK_FALSE(materialize_tree(bad, fixture_dir(), dir.path, error));
        CHECK_FALSE(error.empty());
    }
}

// ── composite tree: populated rows ────────────────────────────────────────

TEST_CASE("apt_rows_at over the composite tree: deb822 + one-line sources with signed-by, three keyrings",
          "[update_source_trust][walk][apt]") {
    const Tree t;
    yuzu::shared::ConstraintAccumulator acc;
    lnx::pio::InputBudget budget;
    const auto rows = lnx::apt_rows_at(t.dir.path, acc, budget);
    CHECK_FALSE(acc.any_failure());
    CHECK_FALSE(acc.incomplete());
    // 10 ubuntu one-line + 2 debian deb822 + 2 thirdparty + 3 keyrings.
    REQUIRE(rows.size() == 17);

    // MUTATION: sources.list not read (rows[0] and the count change); the .sources
    // dispatch dropped (rows[10..11]); the .list dispatch dropped (rows[12..13]).
    CHECK(rows[0] == "apt_source|/etc/apt/sources.list|one_line|deb|"
                     "http://ports.ubuntu.com/ubuntu-ports/|jammy|main restricted|-|"
                     "unset|unset|yes");
    CHECK(rows[10] == "apt_source|/etc/apt/sources.list.d/debian.sources|deb822|deb|"
                      "http://deb.debian.org/debian|bookworm bookworm-updates|main|"
                      "/usr/share/keyrings/debian-archive-keyring.gpg|unset|unset|yes");
    CHECK(rows[11] == "apt_source|/etc/apt/sources.list.d/debian.sources|deb822|deb|"
                      "http://deb.debian.org/debian-security|bookworm-security|main|"
                      "/usr/share/keyrings/debian-archive-keyring.gpg|unset|unset|yes");
    CHECK(rows[12] == "apt_source|/etc/apt/sources.list.d/thirdparty.list|one_line|deb|"
                      "https://repo.example.com/apt|stable|main|"
                      "/etc/apt/keyrings/thirdparty.gpg|unset|unset|yes");
    // trusted=yes / allow-insecure=yes surface as `yes`, not unset.
    CHECK(rows[13] == "apt_source|/etc/apt/sources.list.d/thirdparty.list|one_line|deb|"
                      "http://insecure.example.com/apt|./|-|-|yes|yes|yes");

    // MUTATION: dropping the etc_apt_keyrings scan loses rows[16]; re-scoping either
    // directory changes the scope field. The two name filters are pinned below.
    CHECK(rows[14] == "apt_keyring|/etc/apt/trusted.gpg.d/debian-archive-bookworm-stable.asc|"
                      "trusted_gpg_d|armored|461");
    CHECK(rows[15] == "apt_keyring|/etc/apt/trusted.gpg.d/ubuntu-keyring-2018-archive.gpg|"
                      "trusted_gpg_d|binary|1733");
    CHECK(rows[16] == "apt_keyring|/etc/apt/keyrings/thirdparty.gpg|etc_apt_keyrings|binary|4");
    // MUTATION: dropping the trusted.gpg.d .gpg/.asc filter turns
    // README and z.txt into two `unmodelled` keyring rows (19 rows; rows[16]
    // shifts); dropping the sources.list.d suffix dispatch parses notes.txt into
    // an 18th apt_source row. The 17 REQUIRE above is the kill for both.
    for (const auto& r : rows) {
        CHECK(r.find("/etc/apt/trusted.gpg.d/README") == std::string::npos);
        CHECK(r.find("/etc/apt/trusted.gpg.d/z.txt") == std::string::npos);
        CHECK(r.find("ignored.example") == std::string::npos);
    }

    // The acceptance shape, stated directly: apt_source rows WITH a signed-by value.
    std::size_t signed_by = 0;
    for (const auto& r : rows) {
        const auto f = split_wire(r);
        if (f[0] == "apt_source") {
            REQUIRE(f.size() == 11);
            if (f[7] != "-")
                ++signed_by;
        } else {
            REQUIRE(f[0] == "apt_keyring");
            REQUIRE(f.size() == 5);
        }
    }
    CHECK(signed_by == 3); // both debian stanzas + the thirdparty signed-by line
}

// ── the shipped leg through the real emission seam ───────────────────────

TEST_CASE("update_source_trust seam: the composite tree reaches the wire as constrained linux:rpm_repo:planned through run_linux_at",
          "[update_source_trust][walk][seam]") {
    const Tree t;
    const auto result = run_leg(t.dir.path);
    CHECK(result.rc == 0); // a degraded read is never a failed command
    const auto rows = captured_rows(result.captured);
    // MUTATION: run_linux_at calling apt_rows_at instead of linux_rows_at turns
    // rows[0] into supported|- and the typed status into OK/FULL.
    REQUIRE(rows.size() == 18); // the status row + the 17 apt rows
    CHECK(rows[0] == "status|sources|constrained|linux:rpm_repo:planned");
    CHECK(rows[1] == "apt_source|/etc/apt/sources.list|one_line|deb|"
                     "http://ports.ubuntu.com/ubuntu-ports/|jammy|main restricted|-|"
                     "unset|unset|yes");
    CHECK(rows[17] == "apt_keyring|/etc/apt/keyrings/thirdparty.gpg|etc_apt_keyrings|binary|4");
    CHECK(result.result_status == YUZU_RESULT_STATUS_CONSTRAINED);
    CHECK(result.result_completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
    CHECK(result.result_provenance == "linux:rpm_repo:planned"); // one seam, two views
}

TEST_CASE("update_source_trust seam: without /etc/yum.repos.d the same tree reaches the wire as supported + OK/FULL",
          "[update_source_trust][walk][seam]") {
    const Tree t;
    std::error_code ec;
    REQUIRE(fs::remove_all(t.dir.path / "etc" / "yum.repos.d", ec) == 2); // the dir + placeholder.repo
    REQUIRE_FALSE(ec);
    const auto result = run_leg(t.dir.path);
    CHECK(result.rc == 0);
    const auto rows = captured_rows(result.captured);
    // MUTATION: an unconditional `planned` token, or mapping ENOENT to it, fails here.
    REQUIRE(rows.size() == 18);
    CHECK(rows[0] == "status|sources|supported|-");
    CHECK(result.result_status == YUZU_RESULT_STATUS_OK);
    CHECK(result.result_completeness == YUZU_RESULT_COMPLETENESS_FULL);
    CHECK(result.result_provenance.empty());
}

// ── rpm-family tripwire: empty or absent is silent ───────────────────────

TEST_CASE("an empty or absent /etc/yum.repos.d is not a skipped family: supported, no token",
          "[update_source_trust][walk][rpm]") {
    const Tree t;
    const fs::path repo_dir = t.dir.path / "etc" / "yum.repos.d";
    std::error_code ec;

    // Directory present but empty: there was nothing to skip.
    REQUIRE(fs::remove(repo_dir / "placeholder.repo", ec));
    REQUIRE_FALSE(ec);
    yuzu::shared::ConstraintAccumulator empty_acc;
    lnx::pio::InputBudget budget;
    CHECK(lnx::linux_rows_at(t.dir.path, empty_acc, budget).size() == 17);
    CHECK_FALSE(empty_acc.any_failure());
    CHECK_FALSE(empty_acc.incomplete());

    // Directory absent altogether (a Debian/Ubuntu host).
    REQUIRE(fs::remove(repo_dir, ec));
    REQUIRE_FALSE(ec);
    yuzu::shared::ConstraintAccumulator absent_acc;
    lnx::pio::InputBudget budget2;
    CHECK(lnx::linux_rows_at(t.dir.path, absent_acc, budget2).size() == 17);
    // MUTATION: dropping the `!names.empty()` guard makes the empty directory
    // constrained; mapping ENOENT to `planned` makes the absent one constrained.
    CHECK_FALSE(absent_acc.any_failure());
    CHECK_FALSE(absent_acc.incomplete());
}

// ── absent / EACCES ───────────────────────────────────────────────────────

TEST_CASE("a root that does not exist is absent for every family: zero rows, supported",
          "[update_source_trust][walk][absent]") {
    yuzu::test::TempDir dir{"yuzu_test_update_source_trust_noroot_"};
    const fs::path missing = dir.path / "no-such-root";
    yuzu::shared::ConstraintAccumulator acc;
    lnx::pio::InputBudget budget;
    CHECK(lnx::linux_rows_at(missing, acc, budget).empty());
    // MUTATION: mapping ENOENT to a failure token would make a host with no apt
    // configuration (or no rpm directory) read `constrained` forever.
    CHECK_FALSE(acc.any_failure());
    CHECK_FALSE(acc.incomplete());
}

TEST_CASE("an unreadable root is constrained with a token per source, never absent",
          "[update_source_trust][walk][eacces]") {
    const Tree t;
    const PermRestore restore{t.dir.path};
    REQUIRE(::chmod(t.dir.path.c_str(), 0000) == 0);
    // Probe the traversal the walk needs (opening `etc` through the 0000 root) rather
    // than the uid or the root itself: root, CAP_DAC_OVERRIDE and some FUSE mounts
    // (virtiofs) let a mode-0000 directory be traversed.
    if (const yuzu::agent::ScopedFd probe(::open((t.dir.path / "etc").c_str(), O_RDONLY | O_DIRECTORY));
        probe.valid())
        SKIP("permission bits do not stop traversal here (root, CAP_DAC_OVERRIDE or a FUSE mount)");

    yuzu::shared::ConstraintAccumulator acc;
    lnx::pio::InputBudget budget;
    CHECK(lnx::linux_rows_at(t.dir.path, acc, budget).empty());
    // MUTATION: mapping EACCES to `absent` (zero rows, supported) drops these tokens --
    // including the rpm one, which proves the tripwire's own directory read reports an
    // unreadable directory as a real failure rather than as absent or as `planned`.
    CHECK(reason_has(acc, "linux:apt_sources:permission_denied"));
    CHECK(reason_has(acc, "linux:apt_keyring:permission_denied"));
    CHECK(reason_has(acc, "linux:rpm_repo:permission_denied"));
    CHECK_FALSE(reason_has(acc, "linux:rpm_repo:planned")); // unreadable is not "has entries"
    CHECK(acc.incomplete());
}

// ── injected syscall seam: one case per failure token ───────────────────────
//
// PosixOps are plain function pointers, so the injected behaviour lives in one
// TU-local state block that every case resets. Each case runs the composite tree
// WITHOUT its rpm placeholder, so acc.reason() is exactly the token under test.
// errno_detail maps EIO to `io_error` at EVERY stage, so `open_failed` and
// `read_failed` are produced with EMFILE / EBADF (errnos outside its special set).

namespace {

enum class ReadMode { pass, fail_first, zero_first, eintr_first, burst_then_fail };

struct Inject {
    std::string open_fail_suffix; // open() of a path ending so fails with `err`
    int err = 0;
    int fstat_fail_on = 0; // the Nth fstat call fails with `err`
    int fstat_calls = 0;
    ReadMode read_mode = ReadMode::pass;
    int read_calls = 0;
    bool fdopendir_null = false;
    yuzu::shared::DirWalkResult walk_result{};
    bool walk_injected = false;
};
Inject g_inj;

int inj_open(const char* p, int flags, ...) {
    if (!g_inj.open_fail_suffix.empty() &&
        lnx::pio::ends_with(p, g_inj.open_fail_suffix)) {
        errno = g_inj.err;
        return -1;
    }
    return ::open(p, flags);
}
int inj_fstat(int fd, struct stat* st) {
    if (++g_inj.fstat_calls == g_inj.fstat_fail_on) {
        errno = g_inj.err;
        return -1;
    }
    return ::fstat(fd, st);
}
ssize_t inj_read(int fd, void* buf, std::size_t n) {
    const int call = ++g_inj.read_calls;
    switch (g_inj.read_mode) {
    case ReadMode::pass: break;
    case ReadMode::fail_first:
        if (call == 1) {
            errno = g_inj.err;
            return -1;
        }
        break;
    case ReadMode::zero_first:
        if (call == 1)
            return 0;
        break;
    case ReadMode::eintr_first:
        if (call == 1) {
            errno = EINTR;
            return -1;
        }
        break;
    case ReadMode::burst_then_fail: { // every file: 48 bytes, then an error
        if (call % 2 == 0) {
            errno = g_inj.err;
            return -1;
        }
        const std::size_t k = std::min<std::size_t>(48, n);
        std::memset(buf, 'x', k);
        return static_cast<ssize_t>(k);
    }
    }
    return ::read(fd, buf, n);
}
DIR* inj_fdopendir(int fd) {
    if (g_inj.fdopendir_null) {
        errno = g_inj.err;
        return nullptr;
    }
    return ::fdopendir(fd);
}
yuzu::shared::DirWalkResult inj_walk(DIR* d, std::size_t cap,
                                     const std::function<bool(const dirent*)>& on_entry) {
    if (g_inj.walk_injected)
        return g_inj.walk_result; // no names: the listing "failed" before any entry
    return lnx::pio::detail::real_walk(d, cap, on_entry);
}

lnx::pio::PosixOps injected_ops() {
    lnx::pio::PosixOps ops;
    ops.open = &inj_open;
    ops.fstat = &inj_fstat;
    ops.read = &inj_read;
    ops.fdopendir = &inj_fdopendir;
    ops.walk = &inj_walk;
    return ops;
}

struct Walked {
    std::vector<std::string> rows;
    yuzu::shared::ConstraintAccumulator acc;
    lnx::pio::InputBudget budget;
};

Walked walk_injected(std::size_t max_input = lnx::pio::kMaxInputBytes) {
    g_inj.fstat_calls = 0;
    g_inj.read_calls = 0;
    const Tree t;
    std::error_code ec;
    fs::remove_all(t.dir.path / "etc" / "yum.repos.d", ec);
    Walked w;
    w.budget.max_input_bytes = max_input;
    w.rows = lnx::linux_rows_at(t.dir.path, w.acc, w.budget, injected_ops());
    g_inj = Inject{};
    return w;
}

} // namespace

TEST_CASE("injected ops: open EMFILE on sources.list is open_failed",
          "[update_source_trust][walk][seam_ops]") {
    g_inj = Inject{};
    g_inj.open_fail_suffix = "/etc/apt/sources.list";
    g_inj.err = EMFILE;
    const auto w = walk_injected();
    // MUTATION: IoStage::read_file at the open-failure site reports read_failed.
    CHECK(w.acc.reason() == "linux:apt_sources:open_failed");
    CHECK(w.rows.size() == 7); // sources.list's 10 rows are gone, the other 17 - 10 stay
}

TEST_CASE("injected ops: read EBADF is read_failed, EIO is io_error, a failing fstat is read_failed",
          "[update_source_trust][walk][seam_ops]") {
    g_inj = Inject{};
    g_inj.read_mode = ReadMode::fail_first;
    g_inj.err = EBADF;
    CHECK(walk_injected().acc.reason() == "linux:apt_sources:read_failed");

    g_inj = Inject{};
    g_inj.read_mode = ReadMode::fail_first;
    g_inj.err = EIO;
    CHECK(walk_injected().acc.reason() == "linux:apt_sources:io_error");

    g_inj = Inject{};
    g_inj.fstat_fail_on = 1; // the first file's opening fstat
    g_inj.err = EBADF;
    CHECK(walk_injected().acc.reason() == "linux:apt_sources:read_failed");
}

TEST_CASE("injected ops: read returning 0 before the fstat size is short_read",
          "[update_source_trust][walk][seam_ops]") {
    g_inj = Inject{};
    g_inj.read_mode = ReadMode::zero_first;
    CHECK(walk_injected().acc.reason() == "linux:apt_sources:short_read");
}

TEST_CASE("injected ops: a read interrupted by EINTR is retried and is no failure",
          "[update_source_trust][walk][seam_ops]") {
    g_inj = Inject{};
    g_inj.read_mode = ReadMode::eintr_first;
    const auto w = walk_injected();
    // MUTATION: dropping the EINTR `continue` turns it into read_failed.
    CHECK_FALSE(w.acc.any_failure());
    CHECK(w.rows.size() == 17);
}

TEST_CASE("injected ops: fdopendir failure is dir_open_failed for each source",
          "[update_source_trust][walk][seam_ops]") {
    g_inj = Inject{};
    g_inj.fdopendir_null = true;
    g_inj.err = EMFILE;
    CHECK(walk_injected().acc.reason() ==
          "linux:apt_sources:dir_open_failed,linux:apt_keyring:dir_open_failed");
}

TEST_CASE("injected ops: walk flags surface as enumeration_error and entry_cap",
          "[update_source_trust][walk][seam_ops]") {
    g_inj = Inject{};
    g_inj.walk_injected = true;
    g_inj.walk_result.enumeration_error = true;
    CHECK(walk_injected().acc.reason() ==
          "linux:apt_sources:enumeration_error,linux:apt_keyring:enumeration_error");

    g_inj = Inject{};
    g_inj.walk_injected = true;
    g_inj.walk_result.truncated = true;
    CHECK(walk_injected().acc.reason() ==
          "linux:apt_sources:entry_cap,linux:apt_keyring:entry_cap");
}

// ── input budget ────────────────────────────────────────────────────────────

TEST_CASE("input budget: a walk past the budget records input_cap and stops",
          "[update_source_trust][walk][input_cap]") {
    g_inj = Inject{};
    // The second read crosses the limit (the first file's size plus one byte), so its
    // rows and every later file are dropped.
    const auto sl = fs::file_size(fixture_dir() / "ubuntu-2204/etc/apt/sources.list");
    const auto ds = fs::file_size(fixture_dir() / "debian-bookworm/etc/apt/sources.list.d/debian.sources");
    const auto w = walk_injected(sl + 1);
    // MUTATION: never charging the budget removes the token and restores all 17 rows.
    CHECK(w.acc.reason() == "linux:apt_sources:input_cap");
    CHECK(w.rows.size() == 10); // sources.list's rows only
    CHECK(w.budget.used == sl + ds);
    for (const auto& r : w.rows)
        CHECK(r.rfind("apt_keyring|", 0) == std::string::npos);
}

TEST_CASE("input budget: bytes of FAILED reads are charged (a run of failing files cannot bypass it)",
          "[update_source_trust][walk][input_cap]") {
    g_inj = Inject{};
    g_inj.read_mode = ReadMode::burst_then_fail; // 48 bytes then EBADF, for every file
    g_inj.err = EBADF;
    const auto w = walk_injected(100);
    // Files 1 and 2 fail after 48 bytes each (96 charged, within 100); file 3 fails
    // too and crosses the budget (144), so the walk stops there: 3 files x 2 reads.
    // MUTATION: charging on the ok path only leaves used == 0, records no input_cap
    // and keeps walking.
    CHECK(w.acc.reason() == "linux:apt_sources:read_failed,linux:apt_sources:input_cap");
    CHECK(w.budget.used == 144);
    CHECK(w.rows.empty());
}

TEST_CASE("input budget: the production 16 MiB budget stops the walk at the first keyring read",
          "[update_source_trust][walk][input_cap][seam]") {
    // Real I/O through run_linux_at (default PosixOps, fresh default budget): fifteen
    // hardlinks of one 1 MiB comment-only file (zero rows) plus two 4-byte keyrings.
    yuzu::test::TempDir dir{"yuzu_test_update_source_trust_linux_"};
    const fs::path d = dir.path / "etc" / "apt";
    fs::create_directories(d / "sources.list.d");
    fs::create_directories(d / "trusted.gpg.d");
    const std::string pgp("\x99\x01\x0d\x04", 4);
    const auto put = [](const fs::path& p, const std::string& body) {
        std::ofstream(p, std::ios::binary) << body;
    };
    put(d / "sources.list.d" / "a00.list", std::string(lnx::pio::kMaxFileBytes, '#'));
    const auto link = [&](int i) {
        fs::create_hard_link(d / "sources.list.d" / "a00.list",
                             d / "sources.list.d" / std::format("a{:02}.list", i));
    };
    for (int i = 1; i < 15; ++i)
        link(i);
    put(d / "trusted.gpg", pgp);
    put(d / "trusted.gpg.d" / "x.gpg", pgp);

    const auto count = [](const std::vector<std::string>& rows, std::string_view kind) {
        return std::count_if(rows.begin(), rows.end(),
                             [&](const std::string& r) { return r.rfind(kind, 0) == 0; });
    };
    // 15 MiB + two heads: within the budget, every row present.
    {
        const auto result = run_leg(dir.path);
        const auto rows = captured_rows(result.captured);
        CHECK(result.result_status == YUZU_RESULT_STATUS_OK);
        CHECK(result.result_completeness == YUZU_RESULT_COMPLETENESS_FULL);
        CHECK(result.result_provenance.empty());
        CHECK(count(rows, "apt_keyring|") == 2);
        CHECK(count(rows, "apt_source|") == 0);
    }
    // The 16th link lands EXACTLY on kMaxInputBytes (`used > max` is still false), so
    // the 4-byte trusted.gpg head is the read that crosses. The symlink is the
    // sentinel: visited only if the walk wrongly continued into trusted.gpg.d, where
    // it would add symlink_refused to the provenance.
    // MUTATION: a changed constant, a `>=` flip, a default-budget wiring change or
    // add_keyring_file ignoring Outcome::input_cap fails one of the two runs.
    link(15);
    fs::create_symlink("nowhere", d / "trusted.gpg.d" / "y.gpg");
    {
        const auto result = run_leg(dir.path);
        const auto rows = captured_rows(result.captured);
        CHECK(result.result_status == YUZU_RESULT_STATUS_CONSTRAINED);
        CHECK(result.result_completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
        CHECK(result.result_provenance == "linux:apt_keyring:input_cap");
        CHECK(count(rows, "apt_keyring|") == 0);
        CHECK(count(rows, "apt_source|") == 0);
        REQUIRE_FALSE(rows.empty());
        CHECK(rows[0] == "status|sources|constrained|linux:apt_keyring:input_cap");
    }
}

TEST_CASE("walk: a replaced byte inside redacted userinfo does not set invalid_bytes; one after the '@' does",
          "[update_source_trust][walk][wire]") {
    yuzu::test::TempDir dir{"yuzu_test_update_source_trust_linux_"};
    const fs::path f = dir.path / "etc" / "apt" / "sources.list";
    fs::create_directories(f.parent_path());
    const auto walk = [&](const std::string& line, yuzu::shared::ConstraintAccumulator& acc) {
        std::ofstream(f, std::ios::binary | std::ios::trunc) << line;
        lnx::pio::InputBudget budget;
        return lnx::linux_rows_at(dir.path, acc, budget);
    };
    {
        yuzu::shared::ConstraintAccumulator acc;
        const auto rows = walk("deb http://user:pa\xff" "ss@host.example/debian bookworm main\n", acc);
        REQUIRE(rows.size() == 1);
        CHECK(rows[0].find("http://REDACTED@host.example/debian") != std::string::npos);
        CHECK(rows[0].find('?') == std::string::npos);
        CHECK_FALSE(acc.any_failure());
    }
    {
        yuzu::shared::ConstraintAccumulator acc;
        const auto rows = walk("deb http://user:pass@host\xff.example/debian bookworm main\n", acc);
        REQUIRE(rows.size() == 1);
        CHECK(acc.reason() == "linux:apt_sources:invalid_bytes");
    }
}

#endif // !defined(_WIN32)
