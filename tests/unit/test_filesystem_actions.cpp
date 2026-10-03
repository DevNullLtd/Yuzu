/**
 * test_filesystem_actions.cpp -- Unit tests for filesystem plugin new actions
 *
 * Tests the helper functions (glob_match, has_nested_quantifiers,
 * atomic_write_file) and core file operation logic (search, replace,
 * append, delete_lines) by replicating the algorithms from the plugin.
 * Also covers the macOS get_signature/get_version_info plugin-level seams
 * (select_info_plist's PLAN-08 base_dir re-validation, the BR-006 immediate
 * pre-exec TOCTOU re-check, and the PLAN-02 timed_out short-circuit) -- the
 * classify_codesign_result/classify_plutil_extract mappers themselves are
 * covered separately by test_filesystem_macos_sig.cpp.
 *
 * Same pattern as test_filesystem_read.cpp: helpers are copied into the
 * test file's anonymous namespace since we cannot link the plugin directly.
 */

#include "test_helpers.hpp"

// classify_codesign_result / classify_plutil_extract mappers used by the
// PLAN-02 short-circuit seam below -- header-only, no __APPLE__ guard, so
// this runs on every CI host regardless of platform (already an include
// directory here via tests/meson.build, filesystem_macos_sig.hpp #2273/1.14).
#include "filesystem_macos_sig.hpp"

#include <catch2/catch_test_macros.hpp>

// yuzu::util::safe_output_field -- do_get_version_info now calls the SDK
// helper directly (no plugin-local copy), so the output-framing tests below
// exercise that exact function rather than a replica (already linked into
// this test binary via yuzu_sdk_dep; see test_string_utils.cpp for precedent).
#include <yuzu/string_utils.hpp>

#include <atomic_file_write.hpp> // yuzu::shared::write_file_atomic (production primitive)

#include <algorithm>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <regex>
#include <string>
#include <string_view>
#include <vector>

namespace fs = std::filesystem;

namespace {

// ── TempFile / TempDir helpers ──────────────────────────────────────────

// Every fixture below lives under ONE process-salted base dir. The fixed
// literal names the ~27 call sites pass stay readable, but two concurrent CI
// jobs on the same shared-identity box (one shared %TEMP%) can no longer see
// each other's files — under the old fixed paths, one job's fixture dtor
// deleted the other job's live file mid-test (#1883). The base is created
// once. NOTE (#3507): it is NOT removed at process exit any more. TempDir's
// only cleanup is its destructor, and the Catch2 main hard_exit()s after
// Session::run() on Windows and macOS, which skips static destruction - so
// this base leaks one directory per run under $TMPDIR/%TEMP% on those two
// platforms. Bounded (macOS purges unaccessed temp entries after ~3 days) and
// tracked; the durable fix is a testRunEnded listener, not a destructor.
const fs::path& fsaction_base() {
    static yuzu::test::TempDir base{"yuzu_test_fsaction-"};
    static const bool created = [] {
        std::error_code ec;
        fs::create_directories(base.path, ec);
        return fs::exists(base.path);
    }();
    // A silently-failed creation would fail every fixture below with
    // confusing downstream errors — fail loudly at the source (gov safe-2).
    REQUIRE(created);
    return base.path;
}

struct TempFile {
    fs::path path;

    explicit TempFile(const std::string& content = "",
                      const std::string& name = "yuzu_test_fsaction.txt") {
        path = fsaction_base() / name;
        std::ofstream f(path, std::ios::binary);
        f << content;
    }

    ~TempFile() {
        std::error_code ec;
        fs::remove(path, ec);
    }
};

struct TempDir {
    fs::path path;

    explicit TempDir(const std::string& name = "yuzu_test_fsaction_dir") {
        path = fsaction_base() / name;
        std::error_code ec;
        fs::create_directories(path, ec);
    }

    ~TempDir() {
        std::error_code ec;
        fs::remove_all(path, ec);
    }
};

// ── Replicated: glob_match ──────────────────────────────────────────────
// Exact copy from filesystem_plugin.cpp's anonymous-namespace glob_match
// (agents/plugins/filesystem/src/filesystem_plugin.cpp). This test links a
// COPY, not the plugin symbol, so the two can silently diverge (qe-L1): keep
// this replica byte-identical to the plugin, and re-sync it on any change to
// the plugin-side helper. If a third consumer ever needs it, promote it to a
// pure header (the *_macos.hpp pattern) so there is a single source of truth.

bool glob_match(std::string_view pattern, std::string_view text) {
    size_t px = 0, tx = 0;
    size_t star_px = std::string_view::npos, star_tx = 0;

    while (tx < text.size()) {
        if (px < pattern.size() && (pattern[px] == '?' ||
            (pattern[px] != '*' && pattern[px] != '[' && (pattern[px] == text[tx])))) {
            ++px; ++tx;
        } else if (px < pattern.size() && pattern[px] == '[') {
            ++px;
            bool negate = (px < pattern.size() && pattern[px] == '!');
            if (negate) ++px;
            bool matched = false;
            while (px < pattern.size() && pattern[px] != ']') {
                if (px + 2 < pattern.size() && pattern[px + 1] == '-') {
                    if (text[tx] >= pattern[px] && text[tx] <= pattern[px + 2])
                        matched = true;
                    px += 3;
                } else {
                    if (text[tx] == pattern[px]) matched = true;
                    ++px;
                }
            }
            if (px < pattern.size()) ++px; // skip ']'
            if (matched == negate) {
                if (star_px != std::string_view::npos) { px = star_px + 1; tx = ++star_tx; }
                else return false;
            } else { ++tx; }
        } else if (px < pattern.size() && pattern[px] == '*') {
            star_px = px; star_tx = tx; ++px;
        } else if (star_px != std::string_view::npos) {
            px = star_px + 1; tx = ++star_tx;
        } else {
            return false;
        }
    }
    while (px < pattern.size() && pattern[px] == '*') ++px;
    return px == pattern.size();
}

// ── Replicated: has_nested_quantifiers ──────────────────────────────────
// Exact copy from filesystem_plugin.cpp

bool has_nested_quantifiers(std::string_view pattern) {
    int paren_depth = 0;
    bool last_was_quantifier = false;
    for (size_t i = 0; i < pattern.size(); ++i) {
        char c = pattern[i];
        if (c == '\\' && i + 1 < pattern.size()) { ++i; last_was_quantifier = false; continue; }
        if (c == '(') { ++paren_depth; last_was_quantifier = false; continue; }
        if (c == ')') {
            --paren_depth;
            if (i + 1 < pattern.size() && last_was_quantifier) {
                char next = pattern[i + 1];
                if (next == '+' || next == '*' || next == '?' || next == '{')
                    return true;
            }
            last_was_quantifier = false;
            continue;
        }
        last_was_quantifier = (c == '+' || c == '*' || c == '?' ||
                               (c == '}' && pattern.substr(0, i).rfind('{') != std::string_view::npos));
    }
    return false;
}

// atomic_write_file: thin adapter over the production shared primitive (same
// owner_only_mode=false policy the filesystem plugin uses).
bool atomic_write_file(const fs::path& target, std::string_view content) {
    return yuzu::shared::write_file_atomic(target, content, {.owner_only_mode = false}).has_value();
}

// ── Helper: read entire file as string ──────────────────────────────────

std::string read_file(const fs::path& p) {
    std::ifstream f(p, std::ios::binary);
    return std::string((std::istreambuf_iterator<char>(f)),
                        std::istreambuf_iterator<char>());
}

// ── Helper: read file lines ─────────────────────────────────────────────

std::vector<std::string> read_lines(const fs::path& p) {
    std::ifstream f(p);
    std::vector<std::string> lines;
    std::string line;
    while (std::getline(f, line)) {
        lines.push_back(std::move(line));
    }
    return lines;
}

// ── Replicated: validate_path (macOS get_signature/get_version_info seam) ──
// Same logic as filesystem_plugin.cpp -- select_info_plist below re-validates
// the derived Info.plist through this exact function (PLAN-08).

std::string validate_path(std::string_view raw_path, std::string_view base_dir) {
    if (raw_path.empty())
        return {};

    std::error_code ec;
    std::string path_str{raw_path};

    if (!fs::exists(path_str, ec))
        return {};

    auto canonical = fs::canonical(path_str, ec);
    if (ec)
        return {};

    if (!base_dir.empty()) {
        auto canonical_base = fs::canonical(std::string{base_dir}, ec);
        if (ec)
            return {};

        auto canon_str = canonical.string();
        auto base_str = canonical_base.string();

        if (canon_str.size() < base_str.size() ||
            canon_str.compare(0, base_str.size(), base_str) != 0) {
            return {};
        }
        if (canon_str.size() > base_str.size() && canon_str[base_str.size()] != '/' &&
            canon_str[base_str.size()] != '\\') {
            return {};
        }
    }

    return canonical.string();
}

// ── Replicated: select_info_plist (do_get_version_info macOS, PLAN-08) ─────
// `validated` is already base_dir-validated by the caller and may be a .app
// bundle directory or a direct Info.plist file. The DERIVED
// Contents/Info.plist is re-canonicalized and re-validated against base_dir
// here -- a bundle whose Info.plist is a symlink resolving outside base_dir
// is rejected, not read.

std::string select_info_plist(const std::string& validated, std::string_view base_dir) {
    fs::path vpath(validated);
    std::error_code ec;
    std::string candidate;
    if (fs::is_directory(vpath, ec) && vpath.extension() == ".app") {
        candidate = (vpath / "Contents" / "Info.plist").string();
    } else if (vpath.filename() == "Info.plist") {
        candidate = validated;
    } else {
        return {};
    }

    return validate_path(candidate, base_dir);
}

// ── Replicated: do_get_signature / do_get_version_info PLAN-02/BR-008
// short-circuit. A timed-out OR output_truncated subprocess run is reported
// honestly (unknown / absent) BEFORE the run's exit_code/output is ever
// handed to the classifier -- a codesign killed at the deadline can still
// have tool_ran=true and partial stderr diagnostics, and a 1MB-truncated
// capture is only a PREFIX of what the tool actually said; either way
// classify_codesign_result/classify_plutil_extract would otherwise read the
// partial data as a genuine verdict.

yuzu::filesystem_macos::SignatureStatus signature_status_for(bool timed_out,
                                                              bool output_truncated,
                                                              bool tool_ran, int exit_code,
                                                              std::string_view output) {
    if (timed_out || output_truncated)
        return yuzu::filesystem_macos::SignatureStatus::unknown;
    return yuzu::filesystem_macos::classify_codesign_result(tool_ran, exit_code, output);
}

yuzu::filesystem_macos::PlutilExtractResult version_field_for(bool timed_out,
                                                               bool output_truncated,
                                                               bool tool_ran, int exit_code,
                                                               std::string_view output) {
    if (timed_out || output_truncated)
        return {};
    return yuzu::filesystem_macos::classify_plutil_extract(tool_ran, exit_code, output);
}

} // namespace

// ============================================================================
// Section A: glob_match tests
// ============================================================================

TEST_CASE("GlobMatch: wildcard *.txt matches hello.txt", "[filesystem][glob]") {
    CHECK(glob_match("*.txt", "hello.txt") == true);
}

TEST_CASE("GlobMatch: wildcard *.txt does not match hello.cpp", "[filesystem][glob]") {
    CHECK(glob_match("*.txt", "hello.cpp") == false);
}

TEST_CASE("GlobMatch: prefix wildcard test*", "[filesystem][glob]") {
    CHECK(glob_match("test*", "testing") == true);
}

TEST_CASE("GlobMatch: single char ? matches one char", "[filesystem][glob]") {
    CHECK(glob_match("test?", "test1") == true);
}

TEST_CASE("GlobMatch: single char ? does not match two chars", "[filesystem][glob]") {
    CHECK(glob_match("test?", "test12") == false);
}

TEST_CASE("GlobMatch: character class [abc] matches 'a'", "[filesystem][glob]") {
    CHECK(glob_match("[abc]", "a") == true);
}

TEST_CASE("GlobMatch: character class [abc] does not match 'd'", "[filesystem][glob]") {
    CHECK(glob_match("[abc]", "d") == false);
}

TEST_CASE("GlobMatch: character range [a-z] matches 'm'", "[filesystem][glob]") {
    CHECK(glob_match("[a-z]", "m") == true);
}

TEST_CASE("GlobMatch: negated class [!a-z] matches digit", "[filesystem][glob]") {
    CHECK(glob_match("[!a-z]", "1") == true);
}

TEST_CASE("GlobMatch: bare * matches anything", "[filesystem][glob]") {
    CHECK(glob_match("*", "anything") == true);
}

TEST_CASE("GlobMatch: empty pattern matches empty string", "[filesystem][glob]") {
    CHECK(glob_match("", "") == true);
}

TEST_CASE("GlobMatch: empty pattern does not match non-empty", "[filesystem][glob]") {
    CHECK(glob_match("", "x") == false);
}

TEST_CASE("GlobMatch: exact match without wildcards", "[filesystem][glob]") {
    CHECK(glob_match("hello.txt", "hello.txt") == true);
    CHECK(glob_match("hello.txt", "hello.txT") == false);
}

TEST_CASE("GlobMatch: multiple wildcards", "[filesystem][glob]") {
    CHECK(glob_match("*test*", "my_test_file") == true);
    CHECK(glob_match("*test*", "nope") == false);
}

TEST_CASE("GlobMatch: ? in middle of pattern", "[filesystem][glob]") {
    CHECK(glob_match("h?llo", "hello") == true);
    CHECK(glob_match("h?llo", "hallo") == true);
    CHECK(glob_match("h?llo", "hllo") == false);
}

TEST_CASE("GlobMatch: combined wildcards and classes", "[filesystem][glob]") {
    CHECK(glob_match("[a-z]*.[ch]pp", "main.cpp") == true);
    CHECK(glob_match("[a-z]*.[ch]pp", "test.hpp") == true);
    CHECK(glob_match("[a-z]*.[ch]pp", "Main.cpp") == false);
}

// ============================================================================
// Section B: has_nested_quantifiers tests (ReDoS guard)
// ============================================================================

TEST_CASE("NestedQuantifiers: (a+)+ is ReDoS", "[filesystem][redos]") {
    CHECK(has_nested_quantifiers("(a+)+") == true);
}

TEST_CASE("NestedQuantifiers: (a*)+ is ReDoS", "[filesystem][redos]") {
    CHECK(has_nested_quantifiers("(a*)+") == true);
}

TEST_CASE("NestedQuantifiers: (a+)* is ReDoS", "[filesystem][redos]") {
    CHECK(has_nested_quantifiers("(a+)*") == true);
}

TEST_CASE("NestedQuantifiers: simple a+ is safe", "[filesystem][redos]") {
    CHECK(has_nested_quantifiers("a+") == false);
}

TEST_CASE("NestedQuantifiers: (abc)+ no inner quantifier is safe", "[filesystem][redos]") {
    CHECK(has_nested_quantifiers("(abc)+") == false);
}

TEST_CASE("NestedQuantifiers: escaped parens not a group", "[filesystem][redos]") {
    CHECK(has_nested_quantifiers("\\(a+\\)+") == false);
}

TEST_CASE("NestedQuantifiers: character class not a group", "[filesystem][redos]") {
    CHECK(has_nested_quantifiers("[a-z]+") == false);
}

TEST_CASE("NestedQuantifiers: (a*){2} is ReDoS", "[filesystem][redos]") {
    CHECK(has_nested_quantifiers("(a*){2}") == true);
}

TEST_CASE("NestedQuantifiers: simple patterns are safe", "[filesystem][redos]") {
    CHECK(has_nested_quantifiers("hello") == false);
    CHECK(has_nested_quantifiers("^foo$") == false);
    CHECK(has_nested_quantifiers("[abc]+") == false);
    CHECK(has_nested_quantifiers("a{3}") == false);
}

// ============================================================================
// Section C: atomic_write_file tests
// ============================================================================

TEST_CASE("AtomicWrite: replaces existing file content", "[filesystem][atomic]") {
    TempFile tf("original content", "yuzu_test_atomic_replace.txt");
    CHECK(read_file(tf.path) == "original content");

    bool ok = atomic_write_file(tf.path, "new content");
    CHECK(ok == true);
    CHECK(read_file(tf.path) == "new content");
}

TEST_CASE("AtomicWrite: writes new file in existing directory", "[filesystem][atomic]") {
    TempDir td("yuzu_test_atomic_new");
    auto target = td.path / "new_file.txt";

    // Create an initial file so rename target exists
    { std::ofstream f(target); f << ""; }

    bool ok = atomic_write_file(target, "hello world");
    CHECK(ok == true);
    CHECK(read_file(target) == "hello world");

    std::error_code ec;
    fs::remove(target, ec);
}

TEST_CASE("AtomicWrite: writes empty content", "[filesystem][atomic]") {
    TempFile tf("non-empty", "yuzu_test_atomic_empty.txt");

    bool ok = atomic_write_file(tf.path, "");
    CHECK(ok == true);
    CHECK(read_file(tf.path).empty());
}

TEST_CASE("AtomicWrite: a planted file at the exact temp path fails the write",
          "[filesystem][atomic]") {
    TempDir td("yuzu_test_atomic_planted");
    auto target = td.path / "target.txt";
    auto planted = fs::path{target.string() + ".tmp.forced"};
    { std::ofstream f(planted, std::ios::binary); f << "SENTINEL"; }

    auto r = yuzu::shared::write_file_atomic(
        target, "PAYLOAD", {.owner_only_mode = false, .forced_temp_suffix = "forced"});
    REQUIRE_FALSE(r.has_value());
    CHECK_FALSE(fs::exists(target));
    CHECK(read_file(planted) == "SENTINEL"); // untouched, not followed or removed
}

#ifndef _WIN32
TEST_CASE("AtomicWrite: owner_only_mode=false creates at 0666 & ~umask, not 0600",
          "[filesystem][atomic]") {
    const mode_t u = ::umask(0);
    ::umask(u);
    TempDir td("yuzu_test_atomic_mode");
    auto target = td.path / "mode.txt";

    auto r = yuzu::shared::write_file_atomic(target, "x", {.owner_only_mode = false});
    REQUIRE(r.has_value());
    struct stat st{};
    REQUIRE(::stat(target.c_str(), &st) == 0);
    CHECK((st.st_mode & 0777) == (0666 & ~u));
}

TEST_CASE("AtomicWrite: owner_only_mode=false fails on a file fsync error, keeps dest, no temp",
          "[filesystem][atomic]") {
    TempDir td("yuzu_test_atomic_fsync_eio");
    auto target = td.path / "keep.txt";
    { std::ofstream f(target, std::ios::binary); f << "ORIGINAL"; }

    // Capture-less seam: every fsync fails. The file fsync runs first, so the
    // write must fail before the rename publishes anything.
    yuzu::shared::PosixFdOps ops;
    ops.fsync = [](int) {
        errno = EIO;
        return -1;
    };
    auto r = yuzu::shared::write_file_atomic(target, "PAYLOAD",
                                             {.owner_only_mode = false, .fd_ops = &ops});
    REQUIRE_FALSE(r.has_value());
    CHECK(read_file(target) == "ORIGINAL");
    std::size_t entries = 0;
    for (const auto& e : fs::directory_iterator(td.path)) {
        (void)e;
        ++entries;
    }
    CHECK(entries == 1); // only the destination; the staging temp was removed
}
#endif

TEST_CASE("AtomicWrite: writes large content 1MB", "[filesystem][atomic]") {
    TempFile tf("", "yuzu_test_atomic_large.txt");

    // Generate 1MB of content
    std::string large(1024 * 1024, 'X');
    bool ok = atomic_write_file(tf.path, large);
    CHECK(ok == true);

    auto result = read_file(tf.path);
    CHECK(result.size() == 1024 * 1024);
    CHECK(result == large);
}

TEST_CASE("AtomicWrite: content roundtrip preserves exact bytes", "[filesystem][atomic]") {
    TempFile tf("", "yuzu_test_atomic_exact.txt");

    // Include special characters, newlines, tabs, unicode-like bytes
    std::string content = "line1\nline2\r\nline3\ttab\0null";
    // Note: the string literal above with \0 only goes up to \0
    // Use explicit construction for content with embedded NUL
    std::string with_nul = "abc";
    with_nul += '\0';
    with_nul += "def";

    bool ok = atomic_write_file(tf.path, with_nul);
    CHECK(ok == true);

    auto result = read_file(tf.path);
    CHECK(result.size() == with_nul.size());
    CHECK(result == with_nul);
}

// ============================================================================
// Section D: File content operations -- Search
// ============================================================================

TEST_CASE("Search: literal string finds correct line numbers", "[filesystem][search]") {
    std::string content = "alpha\nbeta\ngamma\nalpha beta\nepsilon\n";
    TempFile tf(content, "yuzu_test_search_literal.txt");

    // Replicate the search logic: read line by line, find pattern
    std::ifstream f(tf.path);
    std::string line;
    int line_num = 0;
    std::vector<int> match_lines;
    std::string pattern = "alpha";

    while (std::getline(f, line)) {
        ++line_num;
        if (line.find(pattern) != std::string::npos) {
            match_lines.push_back(line_num);
        }
    }

    REQUIRE(match_lines.size() == 2);
    CHECK(match_lines[0] == 1);
    CHECK(match_lines[1] == 4);
}

TEST_CASE("Search: case-insensitive search", "[filesystem][search]") {
    std::string content = "Hello World\nhello world\nHELLO WORLD\nno match\n";
    TempFile tf(content, "yuzu_test_search_icase.txt");

    std::ifstream f(tf.path);
    std::string line;
    int line_num = 0;
    int match_count = 0;
    std::string pattern = "hello";

    while (std::getline(f, line)) {
        ++line_num;
        std::string lower = line;
        std::transform(lower.begin(), lower.end(), lower.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        if (lower.find(pattern) != std::string::npos) {
            ++match_count;
        }
    }

    CHECK(match_count == 3);
}

TEST_CASE("Search: regex search", "[filesystem][search]") {
    std::string content = "error: file not found\nwarning: deprecated\nerror: timeout\ninfo: ok\n";
    TempFile tf(content, "yuzu_test_search_regex.txt");

    std::regex re("error:.*");
    std::ifstream f(tf.path);
    std::string line;
    int match_count = 0;
    std::vector<int> match_lines;
    int line_num = 0;

    while (std::getline(f, line)) {
        ++line_num;
        if (std::regex_search(line, re)) {
            ++match_count;
            match_lines.push_back(line_num);
        }
    }

    REQUIRE(match_count == 2);
    CHECK(match_lines[0] == 1);
    CHECK(match_lines[1] == 3);
}

TEST_CASE("Search: no matches returns empty", "[filesystem][search]") {
    std::string content = "alpha\nbeta\ngamma\n";
    TempFile tf(content, "yuzu_test_search_nomatch.txt");

    std::ifstream f(tf.path);
    std::string line;
    int match_count = 0;

    while (std::getline(f, line)) {
        if (line.find("delta") != std::string::npos) {
            ++match_count;
        }
    }

    CHECK(match_count == 0);
}

TEST_CASE("Search: pattern at beginning, middle, and end of line", "[filesystem][search]") {
    std::string content = "ABC start\nmid ABC mid\nend ABC\n";
    TempFile tf(content, "yuzu_test_search_positions.txt");

    std::ifstream f(tf.path);
    std::string line;
    int match_count = 0;

    while (std::getline(f, line)) {
        if (line.find("ABC") != std::string::npos) {
            ++match_count;
        }
    }

    CHECK(match_count == 3);
}

// ============================================================================
// Section D: File content operations -- Replace
// ============================================================================

TEST_CASE("Replace: literal replace modifies file", "[filesystem][replace]") {
    std::string content = "hello world\nhello planet\ngoodbye world\n";
    TempFile tf(content, "yuzu_test_replace_literal.txt");

    // Read file content
    std::string data = read_file(tf.path);

    // Perform literal replace of "hello" with "greetings"
    std::string search = "hello";
    std::string replacement = "greetings";
    std::string result;
    size_t pos = 0;
    int count = 0;

    while (pos < data.size()) {
        size_t found = data.find(search, pos);
        if (found == std::string::npos) {
            result.append(data, pos, data.size() - pos);
            break;
        }
        result.append(data, pos, found - pos);
        result.append(replacement);
        pos = found + search.size();
        ++count;
    }

    CHECK(count == 2);

    // Write back
    bool ok = atomic_write_file(tf.path, result);
    CHECK(ok == true);

    auto final_content = read_file(tf.path);
    CHECK(final_content == "greetings world\ngreetings planet\ngoodbye world\n");
}

TEST_CASE("Replace: dry run does not modify file", "[filesystem][replace]") {
    std::string content = "hello world\n";
    TempFile tf(content, "yuzu_test_replace_dryrun.txt");

    // Read and count matches but do NOT write
    std::string data = read_file(tf.path);
    bool dry_run = true;
    int count = 0;
    size_t pos = 0;
    std::string search = "hello";

    while (pos < data.size()) {
        size_t found = data.find(search, pos);
        if (found == std::string::npos) break;
        ++count;
        pos = found + search.size();
    }

    CHECK(count == 1);

    if (!dry_run) {
        // Would write here
    }

    // Verify original content unchanged
    auto actual = read_file(tf.path);
    CHECK(actual == "hello world\n");
}

TEST_CASE("Replace: max_replacements honored", "[filesystem][replace]") {
    std::string content = "aaa bbb aaa ccc aaa\n";
    TempFile tf(content, "yuzu_test_replace_max.txt");

    std::string data = read_file(tf.path);
    std::string search = "aaa";
    std::string replacement = "XXX";
    int max_replacements = 2;
    int count = 0;
    std::string result;
    size_t pos = 0;

    while (pos < data.size()) {
        size_t found = data.find(search, pos);
        if (found == std::string::npos) {
            result.append(data, pos, data.size() - pos);
            break;
        }
        if (max_replacements > 0 && count >= max_replacements) {
            result.append(data, pos, data.size() - pos);
            break;
        }
        result.append(data, pos, found - pos);
        result.append(replacement);
        pos = found + search.size();
        ++count;
    }

    CHECK(count == 2);

    bool ok = atomic_write_file(tf.path, result);
    CHECK(ok == true);

    auto final_content = read_file(tf.path);
    CHECK(final_content == "XXX bbb XXX ccc aaa\n");
}

TEST_CASE("Replace: regex replace", "[filesystem][replace]") {
    std::string content = "error 123\nerror 456\ninfo 789\n";
    TempFile tf(content, "yuzu_test_replace_regex.txt");

    std::string data = read_file(tf.path);
    std::regex re("error (\\d+)");
    std::string replacement = "fixed $1";

    auto it = std::sregex_iterator(data.begin(), data.end(), re);
    auto end = std::sregex_iterator();
    int count = static_cast<int>(std::distance(it, end));
    CHECK(count == 2);

    std::string result = std::regex_replace(data, re, replacement);
    bool ok = atomic_write_file(tf.path, result);
    CHECK(ok == true);

    auto final_content = read_file(tf.path);
    CHECK(final_content == "fixed 123\nfixed 456\ninfo 789\n");
}

TEST_CASE("Replace: no occurrences leaves file unchanged", "[filesystem][replace]") {
    std::string content = "alpha beta gamma\n";
    TempFile tf(content, "yuzu_test_replace_none.txt");

    std::string data = read_file(tf.path);
    size_t pos = data.find("delta");
    CHECK(pos == std::string::npos);

    // File should remain unchanged
    auto actual = read_file(tf.path);
    CHECK(actual == content);
}

// ============================================================================
// Section D: File content operations -- Append
// ============================================================================

TEST_CASE("Append: to file ending with newline -- no extra newline", "[filesystem][append]") {
    std::string content = "line1\nline2\n";
    TempFile tf(content, "yuzu_test_append_nl.txt");

    // Replicate the append logic: check if file ends with newline
    std::string data = read_file(tf.path);
    CHECK(!data.empty());
    CHECK(data.back() == '\n');

    // Append without adding extra newline
    std::ofstream ofs(tf.path, std::ios::binary | std::ios::app);
    std::string to_append = "line3\n";

    // Since file ends with \n, do not add extra
    ofs.write(to_append.data(), static_cast<std::streamsize>(to_append.size()));
    ofs.close();

    auto result = read_file(tf.path);
    CHECK(result == "line1\nline2\nline3\n");

    auto lines = read_lines(tf.path);
    CHECK(lines.size() == 3);
}

TEST_CASE("Append: to file NOT ending with newline -- newline auto-added", "[filesystem][append]") {
    std::string content = "line1\nline2";
    TempFile tf(content, "yuzu_test_append_nonl.txt");

    // Check file does not end with newline
    std::string data = read_file(tf.path);
    REQUIRE(!data.empty());
    CHECK(data.back() != '\n');

    // Replicate the append logic with newline auto-add
    std::ofstream ofs(tf.path, std::ios::binary | std::ios::app);
    size_t bytes = 0;

    // Auto-add newline before appending
    ofs.put('\n');
    ++bytes;

    std::string to_append = "line3";
    ofs.write(to_append.data(), static_cast<std::streamsize>(to_append.size()));
    bytes += to_append.size();
    ofs.close();

    auto result = read_file(tf.path);
    CHECK(result == "line1\nline2\nline3");
    CHECK(bytes == to_append.size() + 1); // +1 for the auto newline
}

TEST_CASE("Append: empty content appended", "[filesystem][append]") {
    std::string content = "existing\n";
    TempFile tf(content, "yuzu_test_append_empty.txt");

    std::ofstream ofs(tf.path, std::ios::binary | std::ios::app);
    std::string to_append = "";
    ofs.write(to_append.data(), static_cast<std::streamsize>(to_append.size()));
    ofs.close();

    auto result = read_file(tf.path);
    CHECK(result == "existing\n");
}

TEST_CASE("Append: verify total size correct", "[filesystem][append]") {
    std::string content = "hello";
    TempFile tf(content, "yuzu_test_append_size.txt");

    std::string to_append = " world";

    // Auto-add newline since file doesn't end with \n
    {
        std::ofstream ofs(tf.path, std::ios::binary | std::ios::app);
        // File doesn't end with \n, so add one
        ofs.put('\n');
        ofs.write(to_append.data(), static_cast<std::streamsize>(to_append.size()));
    }

    std::error_code ec;
    auto total_size = fs::file_size(tf.path, ec);
    // "hello" (5) + '\n' (1) + " world" (6) = 12
    CHECK(total_size == 12);
}

TEST_CASE("Append: multiple appends accumulate correctly", "[filesystem][append]") {
    std::string content = "line1\n";
    TempFile tf(content, "yuzu_test_append_multi.txt");

    for (int i = 2; i <= 5; ++i) {
        std::ofstream ofs(tf.path, std::ios::binary | std::ios::app);
        std::string line = "line" + std::to_string(i) + "\n";
        ofs.write(line.data(), static_cast<std::streamsize>(line.size()));
    }

    auto lines = read_lines(tf.path);
    REQUIRE(lines.size() == 5);
    CHECK(lines[0] == "line1");
    CHECK(lines[4] == "line5");
}

// ============================================================================
// Section D: File content operations -- Delete lines
// ============================================================================

TEST_CASE("DeleteLines: delete middle range", "[filesystem][deletelines]") {
    std::string content = "line1\nline2\nline3\nline4\nline5\n";
    TempFile tf(content, "yuzu_test_dellines_mid.txt");

    // Read all lines
    auto lines = read_lines(tf.path);
    REQUIRE(lines.size() == 5);

    // Delete lines 2-4 (1-based)
    int start_line = 2;
    int end_line = 4;
    lines.erase(lines.begin() + (start_line - 1), lines.begin() + end_line);

    // Rebuild content
    std::string result;
    for (size_t i = 0; i < lines.size(); ++i) {
        result += lines[i];
        if (i + 1 < lines.size()) result += '\n';
    }
    if (!lines.empty()) result += '\n';

    bool ok = atomic_write_file(tf.path, result);
    CHECK(ok == true);

    auto final_lines = read_lines(tf.path);
    REQUIRE(final_lines.size() == 2);
    CHECK(final_lines[0] == "line1");
    CHECK(final_lines[1] == "line5");
}

TEST_CASE("DeleteLines: delete first line", "[filesystem][deletelines]") {
    std::string content = "first\nsecond\nthird\n";
    TempFile tf(content, "yuzu_test_dellines_first.txt");

    auto lines = read_lines(tf.path);
    REQUIRE(lines.size() == 3);

    // Delete line 1
    lines.erase(lines.begin());

    std::string result;
    for (size_t i = 0; i < lines.size(); ++i) {
        result += lines[i];
        if (i + 1 < lines.size()) result += '\n';
    }
    if (!lines.empty()) result += '\n';

    bool ok = atomic_write_file(tf.path, result);
    CHECK(ok == true);

    auto final_lines = read_lines(tf.path);
    REQUIRE(final_lines.size() == 2);
    CHECK(final_lines[0] == "second");
    CHECK(final_lines[1] == "third");
}

TEST_CASE("DeleteLines: delete last line", "[filesystem][deletelines]") {
    std::string content = "first\nsecond\nthird\n";
    TempFile tf(content, "yuzu_test_dellines_last.txt");

    auto lines = read_lines(tf.path);
    REQUIRE(lines.size() == 3);

    // Delete line 3 (the last)
    int total = static_cast<int>(lines.size());
    lines.erase(lines.begin() + (total - 1));

    std::string result;
    for (size_t i = 0; i < lines.size(); ++i) {
        result += lines[i];
        if (i + 1 < lines.size()) result += '\n';
    }
    if (!lines.empty()) result += '\n';

    bool ok = atomic_write_file(tf.path, result);
    CHECK(ok == true);

    auto final_lines = read_lines(tf.path);
    REQUIRE(final_lines.size() == 2);
    CHECK(final_lines[0] == "first");
    CHECK(final_lines[1] == "second");
}

TEST_CASE("DeleteLines: start_line > total lines is an error", "[filesystem][deletelines]") {
    std::string content = "line1\nline2\nline3\n";
    TempFile tf(content, "yuzu_test_dellines_oob.txt");

    auto lines = read_lines(tf.path);
    int total_before = static_cast<int>(lines.size());
    int start_line = 10;

    CHECK(start_line > total_before);

    // The plugin would return an error here; verify the condition
    // and that original file is untouched
    auto original = read_file(tf.path);
    CHECK(original == content);
}

TEST_CASE("DeleteLines: delete all lines", "[filesystem][deletelines]") {
    std::string content = "line1\nline2\nline3\n";
    TempFile tf(content, "yuzu_test_dellines_all.txt");

    auto lines = read_lines(tf.path);
    REQUIRE(lines.size() == 3);

    // Delete lines 1-3
    lines.erase(lines.begin(), lines.begin() + 3);
    CHECK(lines.empty());

    // Rebuild: empty content since no lines remain
    std::string result;
    // The plugin would write "" if lines is empty (the trailing newline
    // is only added when !lines.empty())

    bool ok = atomic_write_file(tf.path, result);
    CHECK(ok == true);

    auto final_content = read_file(tf.path);
    CHECK(final_content.empty());
}

TEST_CASE("DeleteLines: delete single line from multi-line file", "[filesystem][deletelines]") {
    std::string content = "alpha\nbeta\ngamma\ndelta\nepsilon\n";
    TempFile tf(content, "yuzu_test_dellines_single.txt");

    auto lines = read_lines(tf.path);
    REQUIRE(lines.size() == 5);

    // Delete only line 3 (gamma)
    int start_line = 3;
    int end_line = 3;
    lines.erase(lines.begin() + (start_line - 1), lines.begin() + end_line);

    std::string result;
    for (size_t i = 0; i < lines.size(); ++i) {
        result += lines[i];
        if (i + 1 < lines.size()) result += '\n';
    }
    if (!lines.empty()) result += '\n';

    bool ok = atomic_write_file(tf.path, result);
    CHECK(ok == true);

    auto final_lines = read_lines(tf.path);
    REQUIRE(final_lines.size() == 4);
    CHECK(final_lines[0] == "alpha");
    CHECK(final_lines[1] == "beta");
    CHECK(final_lines[2] == "delta");
    CHECK(final_lines[3] == "epsilon");
}

TEST_CASE("DeleteLines: end_line clamped to total lines", "[filesystem][deletelines]") {
    std::string content = "line1\nline2\nline3\n";
    TempFile tf(content, "yuzu_test_dellines_clamp.txt");

    auto lines = read_lines(tf.path);
    int total_before = static_cast<int>(lines.size());
    REQUIRE(total_before == 3);

    // Request delete lines 2-100, should clamp end_line to 3
    int start_line = 2;
    int end_line = 100;
    if (end_line > total_before) end_line = total_before;

    CHECK(end_line == 3);

    lines.erase(lines.begin() + (start_line - 1), lines.begin() + end_line);

    std::string result;
    for (size_t i = 0; i < lines.size(); ++i) {
        result += lines[i];
        if (i + 1 < lines.size()) result += '\n';
    }
    if (!lines.empty()) result += '\n';

    bool ok = atomic_write_file(tf.path, result);
    CHECK(ok == true);

    auto final_lines = read_lines(tf.path);
    REQUIRE(final_lines.size() == 1);
    CHECK(final_lines[0] == "line1");
}

// ── select_info_plist (do_get_version_info macOS, PLAN-08) ─────────────────
//
// Fixture-only: real temp directories/files (a .app bundle shape, a
// symlinked Info.plist) drive the replicated pure helper above -- no
// codesign/plutil fork, no macOS box required.

TEST_CASE("SelectInfoPlist: a .app bundle resolves to its Contents/Info.plist",
          "[filesystem][macos_sig][plist]") {
    auto base = fsaction_base() / "yuzu_test_plist_ok_base";
    std::error_code ec;
    fs::create_directories(base / "MyApp.app" / "Contents", ec);
    REQUIRE(!ec);
    {
        std::ofstream f(base / "MyApp.app" / "Contents" / "Info.plist");
        f << "<plist/>";
    }

    auto result = select_info_plist((base / "MyApp.app").string(), base.string());
    CHECK(!result.empty());
    CHECK(fs::path(result).filename() == "Info.plist");

    fs::remove_all(base, ec);
}

TEST_CASE("SelectInfoPlist: a direct Info.plist path resolves to itself",
          "[filesystem][macos_sig][plist]") {
    auto base = fsaction_base() / "yuzu_test_plist_direct_base";
    std::error_code ec;
    fs::create_directories(base, ec);
    REQUIRE(!ec);
    auto plist = base / "Info.plist";
    {
        std::ofstream f(plist);
        f << "<plist/>";
    }

    auto result = select_info_plist(plist.string(), base.string());
    CHECK(!result.empty());

    fs::remove_all(base, ec);
}

TEST_CASE("SelectInfoPlist: neither a .app bundle nor an Info.plist is honest-empty",
          "[filesystem][macos_sig][plist]") {
    auto base = fsaction_base() / "yuzu_test_plist_neither_base";
    std::error_code ec;
    fs::create_directories(base, ec);
    REQUIRE(!ec);
    auto plain = base / "SomeBinary";
    {
        std::ofstream f(plain);
        f << "not a bundle";
    }

    auto result = select_info_plist(plain.string(), base.string());
    CHECK(result.empty());

    fs::remove_all(base, ec);
}

TEST_CASE("SelectInfoPlist: a .app with no Contents/Info.plist at all is honest-empty",
          "[filesystem][macos_sig][plist]") {
    auto base = fsaction_base() / "yuzu_test_plist_missing_base";
    std::error_code ec;
    fs::create_directories(base / "Empty.app" / "Contents", ec);
    REQUIRE(!ec);

    auto result = select_info_plist((base / "Empty.app").string(), base.string());
    CHECK(result.empty());

    fs::remove_all(base, ec);
}

TEST_CASE("SelectInfoPlist: PLAN-08 -- a symlinked Info.plist resolving outside base_dir "
          "is rejected, not read",
          "[filesystem][macos_sig][plist]") {
    auto base = fsaction_base() / "yuzu_test_plist_escape_base";
    std::error_code ec;
    fs::create_directories(base / "Evil.app" / "Contents", ec);
    REQUIRE(!ec);

    // The escape target lives OUTSIDE base -- a sibling of it, not nested
    // inside (mirrors test_filesystem_read.cpp's sibling convention for an
    // unambiguous "outside base_dir" fixture).
    auto outside_target = fsaction_base() / "yuzu_test_plist_escape_target.plist";
    {
        std::ofstream f(outside_target);
        f << "<plist>secret</plist>";
    }

    auto link = base / "Evil.app" / "Contents" / "Info.plist";
    fs::create_symlink(outside_target, link, ec);
    if (ec) {
        SUCCEED("symlinks unsupported on this platform — skip");
    } else {
        auto result = select_info_plist((base / "Evil.app").string(), base.string());
        CHECK(result.empty());
    }

    fs::remove(outside_target, ec);
    fs::remove_all(base, ec);
}

// ── BR-006: TOCTOU re-check (get_signature / get_version_info) ─────────────
//
// do_get_signature/do_get_version_info re-run validate_path on the exact
// path about to be handed to codesign/plutil immediately before building
// that tool's argv, comparing the result against the already-validated
// value. These fixtures drive the replicated validate_path/select_info_plist
// helpers through the same two-call sequence the plugin uses, simulating an
// unprivileged writer inside base_dir swapping the target for a symlink to
// an out-of-scope path in the window between the first validate_path() call
// and the re-check -- no codesign/plutil fork involved (pure path helpers
// only).

TEST_CASE("BR-006: re-check of an untouched validated path still matches (get_signature seam)",
          "[filesystem][macos_sig][br006]") {
    auto base = fsaction_base() / "yuzu_test_br006_stable_base";
    std::error_code ec;
    fs::create_directories(base, ec);
    REQUIRE(!ec);
    auto target = base / "Target.app";
    fs::create_directories(target, ec);
    REQUIRE(!ec);

    auto validated = validate_path(target.string(), base.string());
    REQUIRE(!validated.empty());

    // Re-run exactly as do_get_signature does immediately before building
    // codesign's argv -- nothing changed on disk, so it must match.
    auto recheck = validate_path(validated, base.string());
    CHECK(recheck == validated);

    fs::remove_all(base, ec);
}

TEST_CASE("BR-006: re-check catches a path swapped for a symlink outside base_dir "
          "after the initial validate (get_signature seam)",
          "[filesystem][macos_sig][br006]") {
    auto base = fsaction_base() / "yuzu_test_br006_swap_base";
    std::error_code ec;
    fs::create_directories(base, ec);
    REQUIRE(!ec);
    auto target = base / "Target.app";
    fs::create_directories(target, ec);
    REQUIRE(!ec);

    // Step 1 (mirrors do_get_signature's earlier validate_path call): the
    // path is legitimate and inside base_dir at this point.
    auto validated = validate_path(target.string(), base.string());
    REQUIRE(!validated.empty());

    // Step 2: an attacker swaps the validated path for a symlink resolving
    // OUTSIDE base_dir, in the window before codesign is ever invoked.
    auto outside_target = fsaction_base() / "yuzu_test_br006_outside_target";
    fs::create_directories(outside_target, ec);
    REQUIRE(!ec);
    fs::remove_all(target, ec);
    fs::create_directory_symlink(outside_target, target, ec);
    if (ec) {
        SUCCEED("symlinks unsupported on this platform — skip");
    } else {
        // Step 3 (the BR-006 re-check, immediately before building the
        // codesign argv): must no longer match the originally validated
        // value, so do_get_signature aborts rather than invoking the tool.
        auto recheck = validate_path(validated, base.string());
        CHECK(recheck != validated);
    }

    fs::remove_all(outside_target, ec);
    fs::remove_all(base, ec);
}

TEST_CASE("BR-006: re-check catches an Info.plist swapped for a symlink outside base_dir "
          "after select_info_plist (get_version_info seam)",
          "[filesystem][macos_sig][br006]") {
    auto base = fsaction_base() / "yuzu_test_br006_plist_swap_base";
    std::error_code ec;
    fs::create_directories(base / "MyApp.app" / "Contents", ec);
    REQUIRE(!ec);
    auto plist = base / "MyApp.app" / "Contents" / "Info.plist";
    {
        std::ofstream f(plist);
        f << "<plist/>";
    }

    // Step 1 (do_get_version_info's select_info_plist call, PLAN-08): the
    // derived Info.plist path is legitimate and inside base_dir.
    auto info_plist = select_info_plist((base / "MyApp.app").string(), base.string());
    REQUIRE(!info_plist.empty());

    // Step 2: an attacker swaps the Info.plist for a symlink resolving
    // OUTSIDE base_dir, in the window before plutil is ever invoked.
    auto outside_target = fsaction_base() / "yuzu_test_br006_plist_outside.plist";
    {
        std::ofstream f(outside_target);
        f << "<plist>secret</plist>";
    }
    fs::remove(plist, ec);
    fs::create_symlink(outside_target, plist, ec);
    if (ec) {
        SUCCEED("symlinks unsupported on this platform — skip");
    } else {
        // Step 3 (the BR-006 re-check, immediately before building the
        // plutil argv): must no longer match the value select_info_plist
        // returned, so do_get_version_info aborts to not_available rather
        // than invoking the tool.
        auto recheck = validate_path(info_plist, base.string());
        CHECK(recheck != info_plist);
    }

    fs::remove(outside_target, ec);
    fs::remove_all(base, ec);
}

// ── PLAN-02: timed_out short-circuit (get_signature / get_version_info) ────
//
// do_get_signature/do_get_version_info must never hand a killed subprocess
// run's exit_code/output to the classifier -- these fixtures drive the
// replicated ternaries above directly, no fork involved.

TEST_CASE("PLAN-02: a timed-out codesign run is unknown despite a nonzero exit and "
          "captured diagnostics",
          "[filesystem][macos_sig][plan02]") {
    // Mirrors a real codesign killed mid-diagnostic: tool_ran=true, a
    // nonzero exit_code, and partial stderr text that would otherwise
    // classify as `invalid`.
    auto status = signature_status_for(/*timed_out=*/true, /*output_truncated=*/false,
                                        /*tool_ran=*/true, /*exit_code=*/1,
                                        "a sealed resource is missing or invalid");
    CHECK(status == yuzu::filesystem_macos::SignatureStatus::unknown);
}

TEST_CASE("PLAN-02: a codesign run that finishes before the deadline still classifies normally",
          "[filesystem][macos_sig][plan02]") {
    auto status = signature_status_for(/*timed_out=*/false, /*output_truncated=*/false,
                                        /*tool_ran=*/true, /*exit_code=*/0, "");
    CHECK(status == yuzu::filesystem_macos::SignatureStatus::valid);
}

TEST_CASE("PLAN-02: a timed-out plutil run is honest-absent despite captured stdout",
          "[filesystem][macos_sig][plan02]") {
    auto result = version_field_for(/*timed_out=*/true, /*output_truncated=*/false,
                                     /*tool_ran=*/true, /*exit_code=*/0, "1.2.3\n");
    CHECK(result.available == false);
}

TEST_CASE("PLAN-02: a plutil run that finishes before the deadline still classifies normally",
          "[filesystem][macos_sig][plan02]") {
    auto result = version_field_for(/*timed_out=*/false, /*output_truncated=*/false,
                                     /*tool_ran=*/true, /*exit_code=*/0, "1.2.3\n");
    CHECK(result.available == true);
    CHECK(result.value == "1.2.3");
}

// ── BR-008: output_truncated short-circuit (get_signature / get_version_info)
//
// A 1MB-truncated capture is only a PREFIX of what codesign/plutil actually
// said -- classifying that prefix (e.g. a truncated "satisfies its
// Designated Requirement" string that happens to look like a clean pass)
// would report a complete verdict from incomplete data. Verified separately
// from timed_out since a truncated capture can complete (tool_ran=true,
// exit_code==0) despite the cap having discarded real output.

TEST_CASE("BR-008: a truncated codesign capture is unknown despite a clean exit",
          "[filesystem][macos_sig][br008]") {
    auto status = signature_status_for(/*timed_out=*/false, /*output_truncated=*/true,
                                        /*tool_ran=*/true, /*exit_code=*/0,
                                        "valid on disk\nsatisfies its Designated Requirement");
    CHECK(status == yuzu::filesystem_macos::SignatureStatus::unknown);
}

TEST_CASE("BR-008: a truncated plutil capture is honest-absent despite a clean exit",
          "[filesystem][macos_sig][br008]") {
    auto result = version_field_for(/*timed_out=*/false, /*output_truncated=*/true,
                                     /*tool_ran=*/true, /*exit_code=*/0, "1.2.3\n");
    CHECK(result.available == false);
}

// ── yuzu::util::safe_output_field (do_get_version_info macOS output framing)
// A raw CFBundleShortVersionString/CFBundleVersion value is interpolated
// into a pipe-delimited output line -- an untrusted Info.plist must not be
// able to inject extra columns (via `|`), extra rows (via embedded CR/LF),
// or ambiguous data (via a literal backslash the shared decoder can't undo).
// do_get_version_info now calls the SDK helper directly (SHOULD-1), so these
// tests exercise that exact function.

TEST_CASE("SafeOutputField: a plain version string passes through unchanged",
          "[filesystem][output_framing]") {
    CHECK(yuzu::util::safe_output_field("1.2.3") == "1.2.3");
}

TEST_CASE("SafeOutputField: an embedded pipe is escaped, not left as a column separator",
          "[filesystem][output_framing]") {
    auto out = yuzu::util::safe_output_field("1.0\nversion_status|not_available");
    CHECK(out.find('\n') == std::string::npos);
    // The literal '|' must be escaped (\|), never a bare delimiter.
    CHECK(out.find("status|not_available") == std::string::npos);
}

TEST_CASE("SafeOutputField: embedded CR/LF is folded to spaces, not left as a row break",
          "[filesystem][output_framing]") {
    auto out = yuzu::util::safe_output_field("1.0\r\nfile_version|9.9.9");
    CHECK(out.find('\r') == std::string::npos);
    CHECK(out.find('\n') == std::string::npos);
    CHECK(out == "1.0  file_version\\|9.9.9");
}

TEST_CASE("SafeOutputField: a literal backslash folds to '/' (SDK helper, stronger than the "
          "old plugin-local copy)",
          "[filesystem][output_framing]") {
    // The shared server decoder only undoes "\|"; a raw backslash would
    // otherwise survive as ambiguous data. The SDK helper folds it to '/'.
    // This is exactly the behaviour the removed plugin-local safe_output_field
    // LACKED, and the reason do_get_version_info now uses the SDK one.
    CHECK(yuzu::util::safe_output_field("1.0\\beta") == "1.0/beta");
}
