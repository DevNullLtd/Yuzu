/**
 * test_update_source_trust_linux_parsers.cpp -- manifest-materialised tree
 * suite for the update_source_trust Linux leg (lnx::apt_rows_at /
 * lnx::rpm_rows_at in update_source_trust_linux_parsers.hpp).
 *
 * WHAT THIS ADDS. test_update_source_trust_parsers.cpp drives the same walk
 * over the three per-distro wave-1 capture trees one family at a time. This TU
 * layers ONE composite root on top: tests/unit/fixtures/wave10/
 * update_source_trust/linux/tree.manifest merges a real debian:bookworm deb822
 * source, a real ubuntu:22.04 one-line sources.list, and the real
 * rockylinux:9 .repo files (plus two labelled RECONSTRUCTION entries) into a
 * single host-shaped tree, so apt and rpm rows come from the SAME root, which
 * is what a real host looks like. Row bytes are asserted exactly, and the
 * failure paths (absent, EACCES, partial EACCES) are checked on that tree.
 *
 * MANIFEST GRAMMAR (defined and unit-tested HERE; the macOS TU carries a
 * verbatim copy of materialize_tree). One line per file:
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

#include "test_helpers.hpp" // yuzu::test::TempDir

#include <constraint_accumulator.hpp>

#include <sys/stat.h>
#include <unistd.h>

#include <cstddef>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace {

namespace fs = std::filesystem;
namespace lnx = yuzu::update_source_trust::lnx;

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
        "c/copy.repo\tF:rocky-9/etc/yum.repos.d/rocky-devel.repo\n"
        "d/link\tL:/nonexistent-target\n";
    std::string error;
    REQUIRE(materialize_tree(manifest, fixture_dir(), dir.path, error));
    INFO(error);
    // MUTATION: a wrong unescape, a base64 decoder off by one, or F: not reading the
    // committed fixture each change one of these.
    CHECK(slurp(dir.path / "a/t.txt") == "one\ntwo\tx\\y");
    CHECK(slurp(dir.path / "a/b/bin.dat") == std::string("\x99\x01\x0d\x04", 4));
    CHECK(slurp(dir.path / "c/copy.repo") ==
          slurp(fixture_dir() / "rocky-9/etc/yum.repos.d/rocky-devel.repo"));
    CHECK_FALSE(slurp(dir.path / "c/copy.repo").empty());
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
    const auto rows = lnx::apt_rows_at(t.dir.path, acc);
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

    // MUTATION: the trusted.gpg.d .asc/.gpg filter and the etc_apt_keyrings scan each
    // add, drop or re-scope one of these.
    CHECK(rows[14] == "apt_keyring|/etc/apt/trusted.gpg.d/debian-archive-bookworm-stable.asc|"
                      "trusted_gpg_d|armored|461");
    CHECK(rows[15] == "apt_keyring|/etc/apt/trusted.gpg.d/ubuntu-keyring-2018-archive.gpg|"
                      "trusted_gpg_d|binary|1733");
    CHECK(rows[16] == "apt_keyring|/etc/apt/keyrings/thirdparty.gpg|etc_apt_keyrings|binary|4");

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

TEST_CASE("rpm_rows_at over the composite tree: every rocky section, exact gpgcheck row",
          "[update_source_trust][walk][rpm]") {
    const Tree t;
    yuzu::shared::ConstraintAccumulator acc;
    const auto rows = lnx::rpm_rows_at(t.dir.path, acc);
    CHECK_FALSE(acc.any_failure());
    CHECK_FALSE(acc.incomplete());
    REQUIRE(rows.size() == 36); // 18 + 3 + 6 + 9 sections, files in sorted order

    // MUTATION: reading only some .repo files, or losing the gpgcheck/gpgkey wiring,
    // changes the count or this exact string.
    CHECK(rows[0].starts_with("rpm_repo|/etc/yum.repos.d/rocky-addons.repo|"));
    CHECK(rows[27] == "rpm_repo|/etc/yum.repos.d/rocky.repo|baseos|Rocky Linux $releasever - BaseOS|"
                      "yes|yes|unset|file:///etc/pki/rpm-gpg/RPM-GPG-KEY-Rocky-9|-|"
                      "https://mirrors.rockylinux.org/mirrorlist?arch=$basearch&"
                      "repo=BaseOS-$releasever$rltype|unset");
    std::size_t gpgcheck_yes = 0;
    for (const auto& r : rows) {
        const auto f = split_wire(r);
        REQUIRE(f.size() == 11);
        CHECK(f[0] == "rpm_repo");
        if (f[5] == "yes")
            ++gpgcheck_yes; // fields: 0 kind, 1 file, 2 id, 3 name, 4 enabled, 5 gpgcheck
    }
    CHECK(gpgcheck_yes >= 1);
}

// ── absent / EACCES ───────────────────────────────────────────────────────

TEST_CASE("a root that does not exist is absent for both families: zero rows, supported",
          "[update_source_trust][walk][absent]") {
    yuzu::test::TempDir dir{"yuzu_test_update_source_trust_noroot_"};
    const fs::path missing = dir.path / "no-such-root";
    yuzu::shared::ConstraintAccumulator acc;
    CHECK(lnx::apt_rows_at(missing, acc).empty());
    CHECK(lnx::rpm_rows_at(missing, acc).empty());
    // MUTATION: mapping ENOENT to a failure token would make an rpm-only or
    // apt-only host read `constrained` forever.
    CHECK_FALSE(acc.any_failure());
    CHECK_FALSE(acc.incomplete());
}

TEST_CASE("an unreadable root is constrained with a token per source, never absent",
          "[update_source_trust][walk][eacces]") {
    const Tree t;
    if (::geteuid() == 0)
        SKIP("running as root (or CAP_DAC_OVERRIDE): permission bits bypassed");
    const PermRestore restore{t.dir.path};
    REQUIRE(::chmod(t.dir.path.c_str(), 0000) == 0);

    yuzu::shared::ConstraintAccumulator acc;
    CHECK(lnx::apt_rows_at(t.dir.path, acc).empty());
    CHECK(lnx::rpm_rows_at(t.dir.path, acc).empty());
    // MUTATION: mapping EACCES to `absent` (zero rows, supported) drops these tokens.
    CHECK(reason_has(acc, "linux:apt_sources:permission_denied"));
    CHECK(reason_has(acc, "linux:apt_keyring:permission_denied"));
    CHECK(reason_has(acc, "linux:rpm_repo:permission_denied"));
    CHECK(acc.incomplete());
}

TEST_CASE("an unreadable rpm directory constrains rpm only; the apt rows are still fully reported",
          "[update_source_trust][walk][eacces]") {
    const Tree t;
    if (::geteuid() == 0)
        SKIP("running as root (or CAP_DAC_OVERRIDE): permission bits bypassed");
    const fs::path repo_dir = t.dir.path / "etc" / "yum.repos.d";
    const PermRestore restore{repo_dir};
    REQUIRE(::chmod(repo_dir.c_str(), 0000) == 0);

    yuzu::shared::ConstraintAccumulator rpm_acc;
    CHECK(lnx::rpm_rows_at(t.dir.path, rpm_acc).empty());
    CHECK(reason_has(rpm_acc, "linux:rpm_repo:permission_denied"));
    CHECK(rpm_acc.incomplete());

    // A failure in one family must not eat, or be reported by, the other.
    yuzu::shared::ConstraintAccumulator apt_acc;
    CHECK(lnx::apt_rows_at(t.dir.path, apt_acc).size() == 17);
    CHECK_FALSE(apt_acc.any_failure());
}

#endif // !defined(_WIN32)
