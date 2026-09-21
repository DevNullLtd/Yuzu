/**
 * test_update_source_trust_macos_parsers.cpp -- manifest-materialised tree
 * suite for the update_source_trust macOS leg (mac::swu_rows_at in
 * update_source_trust_macos_parsers.hpp).
 *
 * `swu_rows_at` is a NOVEL seam (the peripherals `_at(root)` precedent is
 * Linux-only), so it gets the full absent / EACCES / symlink / unparseable
 * treatment here on top of the populated rows.
 *
 * TREE. tests/unit/fixtures/wave10/update_source_trust/macos/tree.manifest
 * materialises two plists under an injected root:
 *   Library/Preferences/com.apple.SoftwareUpdate.plist           REAL CAPTURE of
 *       this Mac's plist (format-converted to BINARY, "bplist00", the on-disk
 *       format real hosts use)
 *   Library/Managed Preferences/com.apple.SoftwareUpdate.plist   RECONSTRUCTION
 *       from Apple's documented payload keys (no MDM host was available)
 * so on an Apple host the MANAGED leg is executed end to end here, not only
 * parsed: swu_rows_at must return one `macos_swu|local|` AND one
 * `macos_swu|managed|` row.
 *
 * The CoreFoundation decode exists only on Apple hosts. Off Apple,
 * parse_swu_plist_bytes reports "cannot decode" and a PRESENT plist is the
 * constrained token `unparseable` (never fabricated facts), so each case below
 * asserts the host-appropriate outcome under `#if defined(__APPLE__)`. The
 * absent / EACCES / symlink / garbage cases are host-independent.
 *
 * MANIFEST GRAMMAR. materialize_tree below is a VERBATIM COPY of the one in
 * test_update_source_trust_linux_parsers.cpp (TU-local by design, never
 * included); the grammar (T:/B:/F:/L: payloads) is unit-tested there.
 *
 * POSIX ONLY: the read shell under test is `#if !defined(_WIN32)`, so the
 * whole TU body is guarded (test_posix_dir_walk.cpp precedent).
 */
#include <catch2/catch_test_macros.hpp>

#if !defined(_WIN32)

#include "update_source_trust_macos_parsers.hpp"

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
namespace mac = yuzu::update_source_trust::mac;

fs::path fixture_dir() {
#ifdef YUZU_TEST_FIXTURE_DIR
    return fs::path(YUZU_TEST_FIXTURE_DIR) / "wave10" / "update_source_trust" / "macos";
#else
    return fs::path("tests/unit/fixtures/wave10/update_source_trust/macos");
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

std::string slurp(const fs::path& p) {
    std::ifstream in(p, std::ios::binary);
    return std::string((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
}

bool reason_has(const yuzu::shared::ConstraintAccumulator& acc, std::string_view token) {
    return acc.reason().find(token) != std::string::npos;
}

/// Restores a chmod-000 path in every exit path so TempDir can remove the tree.
struct PermRestore {
    fs::path path;
    ~PermRestore() { ::chmod(path.c_str(), 0700); }
};

constexpr const char* kLocalRel = "Library/Preferences/com.apple.SoftwareUpdate.plist";
constexpr const char* kManagedRel = "Library/Managed Preferences/com.apple.SoftwareUpdate.plist";

// The tree is built fresh per test (a TempDir under the yuzu_test_ prefix).
struct Tree {
    yuzu::test::TempDir dir{"yuzu_test_update_source_trust_macos_"};
    Tree() {
        std::ifstream in(fixture_dir() / "tree.manifest", std::ios::binary);
        REQUIRE(in);
        const std::string text((std::istreambuf_iterator<char>(in)),
                               std::istreambuf_iterator<char>());
        std::string error;
        const bool ok = materialize_tree(text, fixture_dir(), dir.path, error);
        INFO(error);
        REQUIRE(ok);
    }
};

/// Materialises a one-off inline manifest (RECONSTRUCTION inputs).
void build(const fs::path& root, std::string_view manifest) {
    std::string error;
    const bool ok = materialize_tree(manifest, fixture_dir(), root, error);
    INFO(error);
    REQUIRE(ok);
}

} // namespace

TEST_CASE("swu_rows_at over the tree: the local AND the managed leg both produce a row",
          "[update_source_trust][walk][swu]") {
    const Tree t;
    // The real capture must really be the binary format, or this test is not
    // exercising what real hosts have.
    REQUIRE(slurp(t.dir.path / kLocalRel).substr(0, 8) == "bplist00");

    yuzu::shared::ConstraintAccumulator acc;
    const auto rows = mac::swu_rows_at(t.dir.path, acc);
#if defined(__APPLE__)
    CHECK_FALSE(acc.any_failure());
    CHECK_FALSE(acc.incomplete());
    REQUIRE(rows.size() == 2);
    // MUTATION: removing the local add_swu_scope call, the managed add_swu_scope
    // call, or either logical path drops or reorders one of these two rows; a
    // wrong key spelling in parse_swu_plist_bytes turns a `yes`/`no` into `unset`.
    CHECK(rows[0] == "macos_swu|local|-|unset|yes|yes|yes|yes|unset");
    CHECK(rows[1] == "macos_swu|managed|"
                     "https://swscan.example.com/content/catalogs/others/index-15-14-13.merged-1.sucatalog|"
                     "yes|yes|no|yes|yes|no");
#else
    // No CoreFoundation: both PRESENT plists are constrained, never empty-success.
    CHECK(rows.empty());
    CHECK(reason_has(acc, "macos:swu_local:unparseable"));
    CHECK(reason_has(acc, "macos:swu_managed:unparseable"));
    CHECK(acc.incomplete());
#endif
}

TEST_CASE("swu_rows_at: a host with only the managed plist reports only the managed row",
          "[update_source_trust][walk][swu]") {
    const Tree t;
    REQUIRE(fs::remove(t.dir.path / kLocalRel));

    yuzu::shared::ConstraintAccumulator acc;
    const auto rows = mac::swu_rows_at(t.dir.path, acc);
#if defined(__APPLE__)
    CHECK_FALSE(acc.any_failure()); // an absent local plist is zero rows, supported
    REQUIRE(rows.size() == 1);
    CHECK(rows[0].starts_with("macos_swu|managed|https://swscan.example.com/"));
#else
    CHECK(rows.empty());
    CHECK(reason_has(acc, "macos:swu_managed:unparseable"));
    CHECK_FALSE(reason_has(acc, "macos:swu_local"));
#endif
}

TEST_CASE("swu_rows_at: a root that does not exist is absent, zero rows, supported",
          "[update_source_trust][walk][absent]") {
    yuzu::test::TempDir dir{"yuzu_test_update_source_trust_macos_noroot_"};
    yuzu::shared::ConstraintAccumulator acc;
    CHECK(mac::swu_rows_at(dir.path / "no-such-root", acc).empty());
    // MUTATION: mapping ENOENT to a failure token makes an unmanaged Mac read
    // `constrained` forever.
    CHECK_FALSE(acc.any_failure());
    CHECK_FALSE(acc.incomplete());
}

TEST_CASE("swu_rows_at: undecodable bytes are `unparseable`, never an empty success",
          "[update_source_trust][walk][swu]") {
    yuzu::test::TempDir dir{"yuzu_test_update_source_trust_macos_garbage_"};
    // RECONSTRUCTION: not a plist at all, and an empty file.
    build(dir.path, std::string{kLocalRel} + "\tT:this is not a plist\n" + "\n" +
                        std::string{kManagedRel} + "\tT:\n");
    yuzu::shared::ConstraintAccumulator acc;
    CHECK(mac::swu_rows_at(dir.path, acc).empty());
    // MUTATION: treating a failed decode as "no facts" drops both tokens.
    CHECK(reason_has(acc, "macos:swu_local:unparseable"));
    CHECK(reason_has(acc, "macos:swu_managed:unparseable"));
    CHECK(acc.incomplete());
}

TEST_CASE("swu_rows_at: a symlink leaf is refused, not followed",
          "[update_source_trust][walk][fault]") {
    yuzu::test::TempDir dir{"yuzu_test_update_source_trust_macos_symlink_"};
    // RECONSTRUCTION: the managed path is a symlink (to a real, readable file).
    build(dir.path, std::string{kLocalRel} + "\tF:com.apple.SoftwareUpdate.managed.plist\n" +
                        std::string{kManagedRel} + "\tL:../Preferences/com.apple.SoftwareUpdate.plist\n");
    yuzu::shared::ConstraintAccumulator acc;
    const auto rows = mac::swu_rows_at(dir.path, acc);
    // MUTATION: dropping O_NOFOLLOW would follow the link and emit a managed row.
    CHECK(reason_has(acc, "macos:swu_managed:symlink_refused"));
    CHECK(acc.incomplete());
    for (const auto& r : rows)
        CHECK_FALSE(r.starts_with("macos_swu|managed|"));
}

TEST_CASE("swu_rows_at: an unreadable managed directory constrains managed only, local still reported",
          "[update_source_trust][walk][eacces]") {
    const Tree t;
    if (::geteuid() == 0)
        SKIP("running as root (or CAP_DAC_OVERRIDE): permission bits bypassed");
    const fs::path managed_dir = t.dir.path / "Library" / "Managed Preferences";
    const PermRestore restore{managed_dir};
    REQUIRE(::chmod(managed_dir.c_str(), 0000) == 0);

    yuzu::shared::ConstraintAccumulator acc;
    const auto rows = mac::swu_rows_at(t.dir.path, acc);
    // MUTATION: mapping EACCES to `absent` drops this token (an MDM-locked policy
    // would then read as "no managed policy").
    CHECK(reason_has(acc, "macos:swu_managed:permission_denied"));
    CHECK(acc.incomplete());
#if defined(__APPLE__)
    REQUIRE(rows.size() == 1);
    CHECK(rows[0] == "macos_swu|local|-|unset|yes|yes|yes|yes|unset");
#else
    CHECK(rows.empty());
    CHECK(reason_has(acc, "macos:swu_local:unparseable"));
#endif
}

TEST_CASE("swu_rows_at: an unreadable root is constrained for both scopes, zero rows",
          "[update_source_trust][walk][eacces]") {
    const Tree t;
    if (::geteuid() == 0)
        SKIP("running as root (or CAP_DAC_OVERRIDE): permission bits bypassed");
    const PermRestore restore{t.dir.path};
    REQUIRE(::chmod(t.dir.path.c_str(), 0000) == 0);

    yuzu::shared::ConstraintAccumulator acc;
    CHECK(mac::swu_rows_at(t.dir.path, acc).empty());
    CHECK(reason_has(acc, "macos:swu_local:permission_denied"));
    CHECK(reason_has(acc, "macos:swu_managed:permission_denied"));
    CHECK(acc.incomplete());
}

#endif // !defined(_WIN32)
