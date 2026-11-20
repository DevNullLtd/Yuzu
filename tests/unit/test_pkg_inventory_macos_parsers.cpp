/**
 * test_pkg_inventory_macos_parsers.cpp — injected-root tests for the pkg_inventory
 * macOS Homebrew walks (macos_manager_rows_at, macos_package_rows_at). The
 * happy-path cases run over a committed REAL CAPTURE tree manifest
 * (tests/unit/fixtures/wave10/pkg_inventory/macos/tree.manifest; provenance.txt
 * beside it); the failure, hostile-tree, budget and seam cases build small
 * SYNTHETIC trees in code. The seams are NOVEL design (peripherals' injected-root
 * precedent is Linux-only). This TU is UNGUARDED: the manifest parser cases run
 * on every OS; the TEST_CASEs that materialize a tree and run the walk are
 * wrapped in `#if !defined(_WIN32)` (absent, not empty, on Windows) because the
 * O_NOFOLLOW/dirent walk shell (posix_dir_walk.hpp) does not exist on Windows.
 * They run on Linux CI too: the walk reads an injected root, not this host's
 * /opt/homebrew.
 *
 * The capture is FORMULAE-ONLY (ten real Cellar entries, an empty real Caskroom,
 * no Taps directory): the capture host has no casks
 * and no taps, and populated trees would be invented. taps=0 / casks=0 here are
 * real "absent" / "exists but empty" readings; cask ROWS and non-zero tap counts
 * are not exercised against real data by this TU (see provenance.txt).
 *
 * MATERIALIZER: `<relpath><TAB><payload>`, payload `T:<text; escapes \n \t \\>` |
 * `D:` (directory) | `L:<target>` (symlink); '#' lines are comments. This tree
 * uses `D:` only, because the capture is a listing of directories.
 *
 * MUTATION NOTES (each names a wiring removal that would fail a case here):
 *  - dropping the Cellar walk in macos_package_rows_at      -> the ten exact package rows
 *  - dropping the Cellar count in macos_manager_rows_at     -> "formulae=10" exact row
 *  - dropping the Caskroom count                            -> "casks=0" exact row
 *  - dropping the Taps count                                -> "taps=0" exact row
 *  - reporting the injected root instead of the logical prefix -> the "/opt/homebrew" exact row
 *  - swallowing an open failure as zero rows / a false 0    -> the unreadable-Cellar case
 *  - dropping the constraint at the emit seam (run_macos_at -> emit_result)
 *                                                          -> the forced-constraint seam case
 *  - dropping the single-flight slot from run_macos_guarded -> the busy-slot cases
 *  - pointing the plugin's run_macos at run_macos_at         -> the entry-point busy case (Apple only)
 *  - dropping the per-entry wall-clock check in count_subdirs -> the managers zero-clock case
 *  - leaking a Dir/fd on an early return                     -> the fd-balance case
 *  - opening a marker as one joined path instead of open_under_prefix's per-hop
 *    O_NOFOLLOW                                            -> the symlinked Library and prefix cases
 *  - dropping the caller-side `walk_budget` record, or the count_taps budget check
 *                                                          -> the budget boundary/files/clock/managers cases
 */
#include <catch2/catch_test_macros.hpp>

#include <yuzu/plugin.h>

#include "pkg_inventory_macos_parsers.hpp"
#include "pkg_inventory_parsers.hpp"

#include "local_dispatcher.hpp"

#include "pkg_inventory_test_support.hpp"
#include "test_helpers.hpp" // yuzu::test::TempDir

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <initializer_list>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#if !defined(_WIN32)
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace fs = std::filesystem;

using yuzu::test::pkg_inventory_support::captured_rows;
using yuzu::test::pkg_inventory_support::split_fields_escape_aware;
#if !defined(_WIN32)
using yuzu::test::pkg_inventory_support::ModeGuard;
using yuzu::test::pkg_inventory_support::open_fd_count;
#endif

namespace {

// ── manifest format (portable: pure text, no filesystem) ─────────────────

enum class Payload { text, dir, link };

struct Entry {
    std::string rel;
    Payload kind = Payload::text;
    std::string data; ///< decoded text (T:) or link target (L:); empty for D:
};

/// Decodes a T: payload. Only \n, \t and \\ are escapes; anything else after a
/// backslash (or a trailing backslash) is a malformed manifest, never guessed.
bool unescape_text(std::string_view in, std::string& out, std::string& error) {
    out.clear();
    for (std::size_t i = 0; i < in.size(); ++i) {
        if (in[i] != '\\') {
            out += in[i];
            continue;
        }
        if (i + 1 >= in.size()) {
            error = "trailing backslash in T: payload";
            return false;
        }
        switch (in[++i]) {
        case 'n': out += '\n'; break;
        case 't': out += '\t'; break;
        case '\\': out += '\\'; break;
        default: error = std::string{"unknown escape \\"} + in[i]; return false;
        }
    }
    return true;
}

bool rel_path_ok(std::string_view rel) {
    if (rel.empty() || rel.front() == '/' || rel.find('\\') != std::string_view::npos) return false;
    std::size_t pos = 0;
    while (pos <= rel.size()) {
        const auto slash = rel.find('/', pos);
        const auto seg = rel.substr(pos, slash == std::string_view::npos ? slash : slash - pos);
        if (seg.empty() || seg == "." || seg == "..") return false;
        if (slash == std::string_view::npos) break;
        pos = slash + 1;
    }
    return true;
}

/// One manifest line -> Entry. Comment and blank lines are the caller's to skip.
bool parse_manifest_line(const std::string& line, Entry& out, std::string& error) {
    const auto tab = line.find('\t');
    if (tab == std::string::npos) {
        error = "no tab separator: " + line;
        return false;
    }
    out = Entry{};
    out.rel = line.substr(0, tab);
    if (!rel_path_ok(out.rel)) {
        error = "unsafe relative path: " + out.rel;
        return false;
    }
    const std::string payload = line.substr(tab + 1);
    if (payload == "D:") {
        out.kind = Payload::dir;
        return true;
    }
    if (payload.rfind("L:", 0) == 0) {
        out.kind = Payload::link;
        out.data = payload.substr(2);
        // A link target is trusted only inside the tree: no absolute target and
        // no `.`/`..` segment, or a later entry could be written through the
        // link, outside the root.
        if (out.data.empty() || !rel_path_ok(out.data)) {
            error = "unsafe link target for " + out.rel;
            return false;
        }
        return true;
    }
    if (payload.rfind("T:", 0) == 0) {
        out.kind = Payload::text;
        return unescape_text(std::string_view{payload}.substr(2), out.data, error);
    }
    error = "unknown payload scheme for " + out.rel;
    return false;
}

bool parse_manifest(std::istream& in, std::vector<Entry>& out, std::string& error) {
    std::string line;
    while (std::getline(in, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back(); // CRLF-checkout tolerance
        if (line.empty() || line.front() == '#') continue;
        Entry e;
        if (!parse_manifest_line(line, e, error)) return false;
        out.push_back(std::move(e));
    }
    return true;
}

fs::path fixture_dir() {
#ifdef YUZU_TEST_FIXTURE_DIR
    return fs::path(YUZU_TEST_FIXTURE_DIR) / "wave10" / "pkg_inventory" / "macos";
#else
    return fs::path("tests/unit/fixtures/wave10/pkg_inventory/macos");
#endif
}

bool load_tree_manifest(std::vector<Entry>& out, std::string& error) {
    const auto path = fixture_dir() / "tree.manifest";
    std::ifstream in(path, std::ios::binary);
    if (!in) {
        error = "could not open " + path.string();
        return false;
    }
    return parse_manifest(in, out, error);
}

const Entry* find_entry(const std::vector<Entry>& entries, std::string_view rel) {
    for (const auto& e : entries)
        if (e.rel == rel) return &e;
    return nullptr;
}

} // namespace

TEST_CASE("pkg_inventory macos tree manifest: line grammar", "[pkg_inventory][macos][manifest]") {
    Entry e;
    std::string err;

    REQUIRE(parse_manifest_line("opt/homebrew/Cellar/fmt/12.2.0\tD:", e, err));
    CHECK(e.kind == Payload::dir);
    REQUIRE(parse_manifest_line("a/b\tT:x\\ny", e, err));
    CHECK(e.kind == Payload::text);
    CHECK(e.data == "x\ny");
    REQUIRE(parse_manifest_line("a/link\tL:b", e, err));
    CHECK(e.kind == Payload::link);
    CHECK(e.data == "b");

    CHECK_FALSE(parse_manifest_line("no-tab-here", e, err));
    CHECK_FALSE(parse_manifest_line("a\tX:unknown", e, err));
    CHECK_FALSE(parse_manifest_line("a\tT:bad\\q", e, err));
    CHECK_FALSE(parse_manifest_line("../escape\tD:", e, err));
    CHECK_FALSE(parse_manifest_line("/abs\tD:", e, err));
    CHECK_FALSE(parse_manifest_line("a//b\tD:", e, err));
    // MUTATION: dropping the rel_path_ok check on a link target fails these two.
    CHECK_FALSE(parse_manifest_line("a/link\tL:/tmp", e, err));
    CHECK_FALSE(parse_manifest_line("a/link\tL:../x", e, err));
}

TEST_CASE("pkg_inventory macos tree manifest: the committed capture parses",
          "[pkg_inventory][macos][manifest]") {
    std::vector<Entry> entries;
    std::string err;
    REQUIRE(load_tree_manifest(entries, err));
    INFO(err);
    CHECK(entries.size() == 14); // ten Cellar version directories + three receipts + the empty Caskroom

    const auto* fmt = find_entry(entries, "opt/homebrew/Cellar/fmt/12.2.0");
    REQUIRE(fmt != nullptr);
    CHECK(fmt->kind == Payload::dir);
    const auto* receipt = find_entry(entries, "opt/homebrew/Cellar/xz/5.8.3/INSTALL_RECEIPT.json");
    REQUIRE(receipt != nullptr);
    CHECK(receipt->kind == Payload::text);
    CHECK(receipt->data.find("\"tap\": \"homebrew/core\"") != std::string::npos);
    const auto* casks = find_entry(entries, "opt/homebrew/Caskroom");
    REQUIRE(casks != nullptr);
    CHECK(casks->kind == Payload::dir);
    // Formulae-only capture: no Taps entry is recorded (the host has none).
    for (const auto& e : entries)
        CHECK(e.rel.find("Library/Taps") == std::string::npos);
}

#if !defined(_WIN32)

namespace {

bool materialize(const fs::path& root, const std::vector<Entry>& entries, std::string& error) {
    std::error_code ec;
    fs::create_directories(root, ec);
    if (ec) {
        error = "create_directories(root): " + ec.message();
        return false;
    }
    for (const auto& e : entries) {
        const auto out_path = root / e.rel;
        if (e.kind == Payload::dir) {
            fs::create_directories(out_path, ec);
        } else {
            fs::create_directories(out_path.parent_path(), ec);
            if (ec) {
                error = "create_directories failed for " + out_path.parent_path().string();
                return false;
            }
            if (e.kind == Payload::link) {
                fs::create_symlink(e.data, out_path, ec);
            } else {
                std::ofstream out(out_path, std::ios::binary);
                if (!out) {
                    error = "could not create " + out_path.string();
                    return false;
                }
                out << e.data;
            }
        }
        if (ec) {
            error = "materialize failed for " + out_path.string() + ": " + ec.message();
            return false;
        }
    }
    return true;
}

bool build_macos_tree(const fs::path& root, std::string& error) {
    std::vector<Entry> entries;
    return load_tree_manifest(entries, error) && materialize(root, entries, error);
}

// ── CommandContext-level harness ─────────────────────────────────────────
// Drives the PRODUCTION leg body (mac::run_macos_at) through a real
// yuzu::CommandContext via LocalDispatcher (the synthetic-descriptor precedent
// in test_filesystem_posture_local_dispatcher.cpp), so what is asserted is the
// emitted status row AND the CC-07 typed status the command actually reports,
// not just the walk's return values.
const fs::path* g_leg_root = nullptr;
yuzu::pkg_inventory::Action g_leg_action = yuzu::pkg_inventory::Action::managers;
/// Which seam the harness drives: the bare walk, the walk behind the single-flight
/// slot, or (Apple only) the plugin's own `run_macos` entry point that execute() calls.
enum class Via { at, guarded, entry };
Via g_leg_via = Via::at;
const yuzu::pkg_inventory::mac::UserPrefixConfig* g_leg_ucfg = nullptr;

int leg_execute(YuzuCommandContext* raw, const char* /*action*/, const YuzuParam* /*params*/,
                std::size_t /*param_count*/) {
    yuzu::CommandContext ctx{raw};
    const yuzu::pkg_inventory::mac::UserPrefixConfig none{};
    const auto& ucfg = g_leg_ucfg != nullptr ? *g_leg_ucfg : none;
    switch (g_leg_via) {
    case Via::guarded:
        return yuzu::pkg_inventory::mac::run_macos_guarded(ctx, g_leg_action, *g_leg_root, ucfg);
#if defined(__APPLE__)
    case Via::entry: return yuzu::pkg_inventory::run_macos(ctx, g_leg_action);
#else
    case Via::entry: break;
#endif
    case Via::at: break;
    }
    return yuzu::pkg_inventory::mac::run_macos_at(ctx, g_leg_action, *g_leg_root, ucfg);
}

yuzu::agent::LocalDispatcher::Result
run_leg(const fs::path& root, yuzu::pkg_inventory::Action a, Via via = Via::at,
        const yuzu::pkg_inventory::mac::UserPrefixConfig* ucfg = nullptr) {
    g_leg_root = &root;
    g_leg_action = a;
    g_leg_via = via;
    g_leg_ucfg = ucfg;
    YuzuPluginDescriptor descriptor{};
    descriptor.execute = &leg_execute;
    yuzu::agent::LocalDispatcher dispatcher;
    auto result = dispatcher.run(&descriptor, "probe");
    g_leg_root = nullptr;
    g_leg_via = Via::at;
    g_leg_ucfg = nullptr;
    return result;
}

} // namespace

TEST_CASE("pkg_inventory macos: manager row over the real-capture tree",
          "[pkg_inventory][macos][walk]") {
    using namespace yuzu::pkg_inventory;
    yuzu::test::TempDir dir{"yuzu_test_pkg_inventory_macos_"};
    std::string err;
    REQUIRE(build_macos_tree(dir.path, err));

    std::optional<std::string> token;
    const auto rows = mac::macos_manager_rows_at(dir.path, token);

    CHECK_FALSE(token.has_value());
    // Exactly one prefix (/opt/homebrew) holds Homebrew; /usr/local is absent.
    // The counts are read from the tree (10 Cellar formulae, an empty Caskroom,
    // no Taps directory), and root_path is the LOGICAL prefix, not the temp dir.
    REQUIRE(rows.size() == 1);
    CHECK(rows[0] == "manager|homebrew|present|-|/opt/homebrew|taps=0;formulae=10;casks=0|-");
    CHECK(split_fields_escape_aware(rows[0]).size() == 7);
    CHECK(rows[0].find(dir.path.string()) == std::string::npos);
}

TEST_CASE("pkg_inventory macos: package rows over the real-capture tree",
          "[pkg_inventory][macos][walk]") {
    using namespace yuzu::pkg_inventory;
    yuzu::test::TempDir dir{"yuzu_test_pkg_inventory_macos_pkgs_"};
    std::string err;
    REQUIRE(build_macos_tree(dir.path, err));

    std::optional<std::string> token;
    const auto rows = mac::macos_package_rows_at(dir.path, token);

    CHECK_FALSE(token.has_value());
    // Sorted by formula name; version is the real directory name. The Caskroom
    // is empty in the capture, so there are formula rows only. Three formulae carry a
    // captured receipt (ccache, cmake: requested; xz: pulled in as a dependency); the other
    // seven have none in the manifest, so their receipt fields are `-`.
    const std::string tail = "|machine|-|/opt/homebrew";
    const std::vector<std::string> expected{
        "package|homebrew|ccache|4.13.6_1|formula|1787233798|homebrew/core|true" + tail,
        "package|homebrew|cmake|4.4.2|formula|1787233798|homebrew/core|true" + tail,
        "package|homebrew|fmt|12.2.0|formula|-|-|-" + tail,
        "package|homebrew|lz4|1.10.0|formula|-|-|-" + tail,
        "package|homebrew|meson|1.12.0|formula|-|-|-" + tail,
        "package|homebrew|ninja|1.13.2|formula|-|-|-" + tail,
        "package|homebrew|openssl@3|3.6.3|formula|-|-|-" + tail,
        "package|homebrew|sqlite|3.53.4|formula|-|-|-" + tail,
        "package|homebrew|xz|5.8.3|formula|1787233794|homebrew/core|false" + tail,
        "package|homebrew|zstd|1.5.7_1|formula|-|-|-" + tail,
    };
    REQUIRE(rows.size() == expected.size());
    for (std::size_t i = 0; i < expected.size(); ++i) {
        INFO("row " << i);
        CHECK(rows[i] == expected[i]);
        CHECK(split_fields_escape_aware(rows[i]).size() == 11);
    }
}

TEST_CASE("pkg_inventory macos: an absent root is supported with zero rows",
          "[pkg_inventory][macos][walk]") {
    using namespace yuzu::pkg_inventory;
    yuzu::test::TempDir dir{"yuzu_test_pkg_inventory_macos_absent_"};

    std::error_code ec;
    fs::create_directories(dir.path / "empty_root", ec);
    REQUIRE_FALSE(ec);

    for (const auto& root : {dir.path / "no_such_root", dir.path / "empty_root"}) {
        INFO("root: " << root.filename().string());
        std::optional<std::string> token;
        CHECK(mac::macos_manager_rows_at(root, token).empty());
        CHECK_FALSE(token.has_value());
        CHECK(mac::macos_package_rows_at(root, token).empty());
        CHECK_FALSE(token.has_value());
    }
}

TEST_CASE("pkg_inventory macos: an unreadable Cellar is constrained, never a false zero",
          "[pkg_inventory][macos][walk]") {
    using namespace yuzu::pkg_inventory;
    // Root (or CAP_DAC_OVERRIDE) bypasses the permission bits this case relies on.
    if (::geteuid() == 0)
        SKIP("running as root (or CAP_DAC_OVERRIDE): permission bits bypassed");

    yuzu::test::TempDir dir{"yuzu_test_pkg_inventory_macos_eacces_"};
    std::string err;
    REQUIRE(build_macos_tree(dir.path, err));

    const auto cellar = dir.path / "opt/homebrew/Cellar";
    REQUIRE(::chmod(cellar.string().c_str(), 0000) == 0);
    ModeGuard restore{cellar, 0755};

    std::optional<std::string> token;
    const auto managers = mac::macos_manager_rows_at(dir.path, token);
    REQUIRE(token.has_value());
    CHECK(*token == "macos:homebrew_cellar:permission_denied");
    // Homebrew is still reported present (Caskroom reads fine), but the
    // unreadable formulae fact is OMITTED rather than emitted as formulae=0.
    REQUIRE(managers.size() == 1);
    CHECK(managers[0] == "manager|homebrew|present|-|/opt/homebrew|taps=0;casks=0|-");

    token.reset();
    const auto packages = mac::macos_package_rows_at(dir.path, token);
    CHECK(packages.empty());
    REQUIRE(token.has_value());
    CHECK(*token == "macos:homebrew_cellar:permission_denied");
}

TEST_CASE("pkg_inventory macos: a symlinked Library component is refused, never silently counted",
          "[pkg_inventory][macos][walk]") {
    using namespace yuzu::pkg_inventory;
    // A symlinked "Library" component is refused by the O_NOFOLLOW openat on
    // every POSIX host, root included (no chmod, so no euid-0 SKIP).
    // MUTATION: opening "<prefix>/Library/Taps" as one joined-path string
    // (instead of walking Library then Taps component-by-component, each its
    // own O_NOFOLLOW openat) lets the kernel resolve "Library" through normal,
    // symlink-following path resolution and silently count the planted tap
    // below -- this case must see neither a fabricated taps count nor the
    // attacker's tap name.
    yuzu::test::TempDir dir{"yuzu_test_pkg_inventory_macos_library_symlink_"};
    fs::create_directories(dir.path / "elsewhere/Taps/attacker-org/attacker-repo");
    fs::create_directories(dir.path / "opt/homebrew/Caskroom");
    std::error_code ec;
    fs::create_directory_symlink(dir.path / "elsewhere", dir.path / "opt/homebrew/Library", ec);
    REQUIRE_FALSE(ec);

    std::optional<std::string> token;
    const auto rows = mac::macos_manager_rows_at(dir.path, token);

    REQUIRE(token.has_value());
    CHECK(token->rfind("macos:homebrew_taps:", 0) == 0); // a symlink is ENOTDIR (not_a_directory) under O_DIRECTORY|O_NOFOLLOW
    // Homebrew is still reported present (Caskroom reads fine); the refused
    // Taps marker's fact is OMITTED (never a fabricated non-zero count), and
    // the attacker's tap name never reaches the row.
    REQUIRE(rows.size() == 1);
    CHECK(rows[0] == "manager|homebrew|present|-|/opt/homebrew|formulae=0;casks=0|-");
    CHECK(rows[0].find("attacker") == std::string::npos);
}

TEST_CASE("pkg_inventory macos: a whole-action walk budget stops a breadth-distributed tree, rows kept",
          "[pkg_inventory][macos][walk]") {
    using namespace yuzu::pkg_inventory;
    // Breadth DISTRIBUTED across several id-directories (not one huge
    // directory -- that would only re-test the pre-existing per-directory
    // cap): four id-directories, two version entries each, over a
    // test-local 6-entry budget. The top-level listing (4 ids) plus the
    // first id-directory's version listing (2) exhausts it before the
    // second id-directory is even opened.
    // MUTATION: dropping the whole-action budget check (or checking only the
    // pre-existing per-directory cap) reads all four id-directories and
    // returns 8 rows instead of 2.
    yuzu::test::TempDir dir{"yuzu_test_pkg_inventory_macos_walk_budget_"};
    for (const char* id : {"pkg-a", "pkg-b", "pkg-c", "pkg-d"}) {
        fs::create_directories(dir.path / "opt/homebrew/Cellar" / id / "1.0.0");
        fs::create_directories(dir.path / "opt/homebrew/Cellar" / id / "1.0.1");
    }

    Limits lim;
    lim.max_walk_entries = 6;

    std::optional<std::string> token;
    const auto rows = mac::macos_package_rows_at(dir.path, token, lim);

    REQUIRE(token.has_value());
    CHECK(*token == "macos:homebrew_cellar:walk_budget");
    // Only the first (alphabetically sorted) id-directory's rows survive: the
    // budget stopped BEFORE pkg-b's version listing started, so what pkg-a
    // already produced is a constraint, not a discard.
    REQUIRE(rows.size() == 2);
    CHECK(rows[0] == "package|homebrew|pkg-a|1.0.0|formula|-|-|-|machine|-|/opt/homebrew");
    CHECK(rows[1] == "package|homebrew|pkg-a|1.0.1|formula|-|-|-|machine|-|/opt/homebrew");
}

TEST_CASE("pkg_inventory macos: a budget that dies at a container boundary is still a constraint",
          "[pkg_inventory][macos][walk]") {
    using namespace yuzu::pkg_inventory;
    // Cellar charges exactly 4 entries (top listing 2 + two one-entry version
    // listings), so a 4-entry budget is spent at the END of the Cellar walk with
    // no id-directory left to trip the in-loop check. The Caskroom is then
    // skipped: it must be reported, not read as an empty Caskroom.
    // MUTATION: dropping the caller-side `walk_budget` record in
    // macos_package_rows_at returns the two formula rows with NO token.
    yuzu::test::TempDir dir{"yuzu_test_pkg_inventory_macos_budget_edge_"};
    fs::create_directories(dir.path / "opt/homebrew/Cellar/pkg-a/1.0");
    fs::create_directories(dir.path / "opt/homebrew/Cellar/pkg-b/1.0");
    fs::create_directories(dir.path / "opt/homebrew/Caskroom/cask-c/2.0");

    Limits lim;
    lim.max_walk_entries = 4;

    std::optional<std::string> token;
    const auto rows = mac::macos_package_rows_at(dir.path, token, lim);

    REQUIRE(token.has_value());
    CHECK(*token == "macos:homebrew_caskroom:walk_budget");
    REQUIRE(rows.size() == 2);
    CHECK(rows[0] == "package|homebrew|pkg-a|1.0|formula|-|-|-|machine|-|/opt/homebrew");
    CHECK(rows[1] == "package|homebrew|pkg-b|1.0|formula|-|-|-|machine|-|/opt/homebrew");
}

TEST_CASE("pkg_inventory macos: a Cellar of plain files that eats the budget hides nothing silently",
          "[pkg_inventory][macos][walk]") {
    using namespace yuzu::pkg_inventory;
    // Well-named regular files never classify as ids, so the in-loop check is
    // never reached; the two files still spend the whole 2-entry budget and the
    // real cask behind them must be reported as skipped.
    yuzu::test::TempDir dir{"yuzu_test_pkg_inventory_macos_budget_files_"};
    fs::create_directories(dir.path / "opt/homebrew/Cellar");
    for (const char* name : {"file-a", "file-b"}) {
        std::ofstream out(dir.path / "opt/homebrew/Cellar" / name);
        REQUIRE(out.good());
    }
    fs::create_directories(dir.path / "opt/homebrew/Caskroom/real-cask/1.0");

    Limits lim;
    lim.max_walk_entries = 2;

    std::optional<std::string> token;
    const auto rows = mac::macos_package_rows_at(dir.path, token, lim);

    REQUIRE(token.has_value());
    CHECK(*token == "macos:homebrew_caskroom:walk_budget");
    CHECK(rows.empty());
}

TEST_CASE("pkg_inventory macos: an already-expired wall-clock budget is a constraint, not zero packages",
          "[pkg_inventory][macos][walk]") {
    using namespace yuzu::pkg_inventory;
    // A zero-second budget is expired by the first check, deterministically (the
    // steady clock never runs backwards), so no timing assumption is involved.
    yuzu::test::TempDir dir{"yuzu_test_pkg_inventory_macos_budget_clock_"};
    fs::create_directories(dir.path / "opt/homebrew/Cellar/pkg-a/1.0");

    Limits lim;
    lim.max_walk_seconds = 0;

    std::optional<std::string> token;
    const auto rows = mac::macos_package_rows_at(dir.path, token, lim);

    REQUIRE(token.has_value());
    CHECK(*token == "macos:homebrew_cellar:walk_budget");
    CHECK(rows.empty());
}

TEST_CASE("pkg_inventory macos: the managers walk is bounded by the same whole-action budget",
          "[pkg_inventory][macos][walk]") {
    using namespace yuzu::pkg_inventory;
    // Breadth spread across three tap orgs (the nested walk): the org listing
    // (3) plus the first org's repo listing (1) spend the 4-entry budget before
    // the second org is opened. The taps count would be a lower bound, so the
    // fact is omitted and the constraint names it.
    // MUTATION: dropping the budget check in count_taps reads all three orgs and
    // reports taps=3 with no token.
    yuzu::test::TempDir dir{"yuzu_test_pkg_inventory_macos_managers_budget_"};
    for (const char* org : {"org-a", "org-b", "org-c"})
        fs::create_directories(dir.path / "opt/homebrew/Library/Taps" / org / "repo-1");

    Limits lim;
    lim.max_walk_entries = 4;

    std::optional<std::string> token;
    const auto rows = mac::macos_manager_rows_at(dir.path, token, lim);

    REQUIRE(token.has_value());
    CHECK(*token == "macos:homebrew_taps:walk_budget");
    REQUIRE(rows.size() == 1);
    CHECK(rows[0] == "manager|homebrew|present|-|/opt/homebrew|formulae=0;casks=0|-");
}

TEST_CASE("pkg_inventory macos: a symlinked Homebrew prefix is refused by both actions, never followed",
          "[pkg_inventory][macos][walk]") {
    using namespace yuzu::pkg_inventory;
    // O_NOFOLLOW on a joined "<prefix>/Cellar" path guards only its final
    // component; the prefix itself must be refused hop by hop, root included (no
    // chmod, so no euid-0 SKIP).
    // MUTATION: opening Cellar/Caskroom as one joined string follows the link and
    // reports the planted rows below as a clean supported result with no token.
    yuzu::test::TempDir dir{"yuzu_test_pkg_inventory_macos_prefix_symlink_"};
    fs::create_directories(dir.path / "elsewhere/Cellar/evil-formula/9.9.9");
    fs::create_directories(dir.path / "elsewhere/Caskroom/evil-cask/1.0");
    fs::create_directories(dir.path / "opt");
    std::error_code ec;
    fs::create_directory_symlink(dir.path / "elsewhere", dir.path / "opt/homebrew", ec);
    REQUIRE_FALSE(ec);

    std::optional<std::string> token;
    const auto packages = mac::macos_package_rows_at(dir.path, token);
    CHECK(packages.empty());
    REQUIRE(token.has_value());
    CHECK(token->rfind("macos:homebrew_cellar:", 0) == 0); // a symlink is ENOTDIR (not_a_directory) under O_DIRECTORY|O_NOFOLLOW
    CHECK(token->find("evil") == std::string::npos);

    token.reset();
    const auto managers = mac::macos_manager_rows_at(dir.path, token);
    REQUIRE(token.has_value());
    // Something is there but nothing could be read: unavailable, never a row
    // that counts what the link points at.
    REQUIRE(managers.size() == 1);
    CHECK(managers[0].rfind("manager|homebrew|unavailable|-|/opt/homebrew|-|macos:homebrew_taps:", 0) == 0);
    CHECK(managers[0].find("evil") == std::string::npos);
    CHECK(managers[0].find("formulae=") == std::string::npos);
}

// MUTATION: crossing the Action -> walk switch in run_macos_at (managers <->
// packages), or reporting a non-OK/FULL typed status on a clean read, fails the
// exact rows and the OK/FULL asserts below.
TEST_CASE("pkg_inventory macos seam: a clean tree reaches the wire as supported + OK/FULL through run_macos_at",
          "[pkg_inventory][macos][seam]") {
    using namespace yuzu::pkg_inventory;
    yuzu::test::TempDir dir{"yuzu_test_pkg_inventory_macos_seam_ok_"};
    std::string err;
    REQUIRE(build_macos_tree(dir.path, err));

    const auto managers = run_leg(dir.path, Action::managers);
    CHECK(managers.rc == 0);
    const auto mrows = captured_rows(managers.captured);
    REQUIRE(mrows.size() == 2);
    CHECK(mrows[0] == "status|managers|supported|-");
    CHECK(mrows[1] == "manager|homebrew|present|-|/opt/homebrew|taps=0;formulae=10;casks=0|-");
    CHECK(managers.result_status == YUZU_RESULT_STATUS_OK);
    CHECK(managers.result_completeness == YUZU_RESULT_COMPLETENESS_FULL);
    CHECK(managers.result_provenance.empty());

    const auto packages = run_leg(dir.path, Action::packages);
    CHECK(packages.rc == 0);
    const auto prows = captured_rows(packages.captured);
    REQUIRE(prows.size() == 11); // status row + the ten captured formula rows
    CHECK(prows[0] == "status|packages|supported|-");
    CHECK(prows[1] == "package|homebrew|ccache|4.13.6_1|formula|1787233798|homebrew/core|true|machine|-|"
                      "/opt/homebrew");
    CHECK(packages.result_status == YUZU_RESULT_STATUS_OK);
    CHECK(packages.result_completeness == YUZU_RESULT_COMPLETENESS_FULL);
}

TEST_CASE("pkg_inventory macos seam: a forced constraint reaches BOTH the status row and the typed status through run_macos_at",
          "[pkg_inventory][macos][seam]") {
    using namespace yuzu::pkg_inventory;
    // A symlinked Cellar is refused by the O_NOFOLLOW open on every POSIX host,
    // root included (no chmod, so no euid-0 SKIP): a deterministic constraint.
    // MUTATION: passing std::nullopt instead of `constraint` in run_macos_at
    // turns every assertion below into supported|- and OK/FULL.
    yuzu::test::TempDir dir{"yuzu_test_pkg_inventory_macos_seam_constrained_"};
    fs::create_directories(dir.path / "elsewhere/wget/1.24.5");
    fs::create_directories(dir.path / "opt/homebrew");
    std::error_code ec;
    fs::create_directory_symlink(dir.path / "elsewhere", dir.path / "opt/homebrew/Cellar", ec);
    REQUIRE_FALSE(ec);

    const auto packages = run_leg(dir.path, Action::packages);
    CHECK(packages.rc == 0); // a degraded read is never a failed command
    const auto prows = captured_rows(packages.captured);
    REQUIRE(prows.size() == 1); // the status row only: the link target must not appear
    const auto pstatus = split_fields_escape_aware(prows[0]);
    REQUIRE(pstatus.size() == 4);
    CHECK(pstatus[0] == "status");
    CHECK(pstatus[1] == "packages");
    CHECK(pstatus[2] == "constrained");
    CHECK(pstatus[3].rfind("macos:homebrew_cellar:", 0) == 0); // a symlink is ENOTDIR (not_a_directory) under O_DIRECTORY|O_NOFOLLOW
    CHECK(packages.result_status == YUZU_RESULT_STATUS_CONSTRAINED);
    CHECK(packages.result_completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
    CHECK(packages.result_provenance == pstatus[3]); // one seam, two views

    const auto managers = run_leg(dir.path, Action::managers);
    CHECK(managers.rc == 0);
    const auto mrows = captured_rows(managers.captured);
    REQUIRE(mrows.size() == 2);
    const auto mstatus = split_fields_escape_aware(mrows[0]);
    REQUIRE(mstatus.size() == 4);
    CHECK(mstatus[2] == "constrained");
    CHECK(mstatus[3].rfind("macos:homebrew_cellar:", 0) == 0);
    // The Cellar marker exists but cannot be opened and nothing else is there:
    // unavailable, with this prefix's token in the reason field.
    CHECK(mrows[1].rfind("manager|homebrew|unavailable|-|/opt/homebrew|-|macos:homebrew_cellar:", 0) == 0);
    CHECK(managers.result_status == YUZU_RESULT_STATUS_CONSTRAINED);
    CHECK(managers.result_completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
    CHECK(managers.result_provenance == mstatus[3]);
}


TEST_CASE("pkg_inventory macos: managers under an already-expired wall-clock budget omits the fact "
          "it could not finish counting",
          "[pkg_inventory][macos][walk]") {
    using namespace yuzu::pkg_inventory;
    // count_subdirs checks the clock per entry, so even ONE big listing cannot outlast
    // the budget on a slow filesystem. Zero seconds is expired deterministically (the
    // steady clock never runs backwards).
    yuzu::test::TempDir dir{"yuzu_test_pkg_inventory_macos_managers_clock_"};
    fs::create_directories(dir.path / "opt/homebrew/Cellar/a/1.0");
    fs::create_directories(dir.path / "opt/homebrew/Cellar/b/1.0");

    Limits lim;
    lim.max_walk_seconds = 0;
    std::optional<std::string> token;
    const auto rows = mac::macos_manager_rows_at(dir.path, token, lim);
    REQUIRE(token.has_value());
    CHECK(*token == "macos:homebrew_cellar:walk_budget");
    REQUIRE(rows.size() == 1);
    CHECK(rows[0] == "manager|homebrew|present|-|/opt/homebrew|taps=0;casks=0|-");
}

TEST_CASE("pkg_inventory macos seam: a same-action dispatch while a walk is in flight is answered "
          "busy at once and walks nothing",
          "[pkg_inventory][macos][seam][busy]") {
    using namespace yuzu::pkg_inventory;
    // The walk's wall clock cannot interrupt a syscall stalled on a hung mount inside
    // the tree, so one stalled walk must not let every later dispatch pin another pool
    // worker.
    yuzu::test::TempDir dir{"yuzu_test_pkg_inventory_macos_busy_"};
    std::string err;
    REQUIRE(build_macos_tree(dir.path, err));

    {
        const auto held = WalkSlot::try_acquire(Action::managers);
        REQUIRE(held.has_value());
        CHECK_FALSE(WalkSlot::try_acquire(Action::managers).has_value()); // single-flight

        const auto busy = run_leg(dir.path, Action::managers, Via::guarded);
        CHECK(busy.rc == 0); // a busy answer is a degraded read, not a failed command
        const auto rows = captured_rows(busy.captured);
        REQUIRE(rows.size() == 1); // the status row only: nothing was walked
        CHECK(rows[0] == "status|managers|constrained|macos:managers:busy");
        CHECK(busy.result_status == YUZU_RESULT_STATUS_CONSTRAINED);
        CHECK(busy.result_completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
        CHECK(busy.result_provenance == "macos:managers:busy");

        // The slots are per action: `packages` is not blocked by a held `managers`.
        const auto other = run_leg(dir.path, Action::packages, Via::guarded);
        const auto orows = captured_rows(other.captured);
        REQUIRE(orows.size() == 11);
        CHECK(orows[0] == "status|packages|supported|-");
        CHECK(other.result_status == YUZU_RESULT_STATUS_OK);
    }

    // Released with the guard: the same action walks again, and releases its own slot.
    for (int i = 0; i < 2; ++i) {
        const auto again = run_leg(dir.path, Action::managers, Via::guarded);
        const auto rows = captured_rows(again.captured);
        REQUIRE(rows.size() == 2);
        CHECK(rows[0] == "status|managers|supported|-");
        CHECK(again.result_status == YUZU_RESULT_STATUS_OK);
    }
    CHECK(WalkSlot::try_acquire(Action::managers).has_value());
    CHECK(WalkSlot::try_acquire(Action::packages).has_value());
}

#if defined(__APPLE__)
TEST_CASE("pkg_inventory macos seam: the plugin's own run_macos entry point walks behind the slot",
          "[pkg_inventory][macos][seam][busy]") {
    using namespace yuzu::pkg_inventory;
    // run_macos is what execute() calls in production (pkg_inventory_macos.cpp). Holding
    // the slot proves THAT call site is the guarded one, without walking this host's
    // real "/" tree. MUTATION: calling run_macos_at from run_macos walks instead.
    const auto held = WalkSlot::try_acquire(Action::packages);
    REQUIRE(held.has_value());
    const auto busy = run_leg(fs::path{"/"}, Action::packages, Via::entry);
    CHECK(busy.rc == 0);
    const auto rows = captured_rows(busy.captured);
    REQUIRE(rows.size() == 1);
    CHECK(rows[0] == "status|packages|constrained|macos:packages:busy");
    CHECK(busy.result_status == YUZU_RESULT_STATUS_CONSTRAINED);
}
#endif // defined(__APPLE__)

TEST_CASE("pkg_inventory macos: walks leave the process's file descriptors exactly as they found them",
          "[pkg_inventory][macos][walk]") {
    using namespace yuzu::pkg_inventory;
    // Peak use is two fds; every early return between acquire and release (a refused
    // symlink hop, a failed openat, a truncated listing, a budget stop) must give
    // them back.
    yuzu::test::TempDir dir{"yuzu_test_pkg_inventory_macos_fdbalance_"};
    fs::create_directories(dir.path / "elsewhere/Cellar/evil/1.0");
    fs::create_directories(dir.path / "opt");
    std::error_code ec;
    fs::create_directory_symlink(dir.path / "elsewhere", dir.path / "opt/homebrew", ec); // refused prefix
    REQUIRE_FALSE(ec);
    fs::create_directories(dir.path / "usr/local/Homebrew/Library/Taps/org/repo");
    fs::create_directories(dir.path / "usr/local/Cellar/a/1.0");
    fs::create_directories(dir.path / "usr/local/Cellar/b/1.0");
    fs::create_directories(dir.path / "usr/local/Caskroom/c/1.0");
    fs::create_directory_symlink(dir.path / "elsewhere", dir.path / "usr/local/Cellar/link", ec);
    REQUIRE_FALSE(ec);

    // A Users tree too: a real home with both candidates, a symlinked home, a symlinked Cellar.
    fs::create_directories(dir.path / "Users/alpha/homebrew/Cellar/a/1.0/sub");
    fs::create_directories(dir.path / "Users/alpha/homebrew/Caskroom/c/1.0");
    fs::create_directories(dir.path / "Users/alpha/.homebrew/Cellar/b/1.0");
    fs::create_directories(dir.path / "Users/beta/homebrew");
    fs::create_directory_symlink(dir.path / "elsewhere", dir.path / "Users/beta/homebrew/Cellar", ec);
    REQUIRE_FALSE(ec);
    fs::create_directory_symlink(dir.path / "elsewhere", dir.path / "Users/linkhome", ec);
    REQUIRE_FALSE(ec);
    {
        std::ofstream receipt(dir.path / "Users/alpha/homebrew/Cellar/a/1.0/INSTALL_RECEIPT.json");
        receipt << R"({"time": 1767225600})";
    }
    mac::UserPrefixConfig ucfg;
    ucfg.min_home_uid = 0;

    Limits tight;
    tight.max_entries_per_dir = 1; // truncated listings
    Limits expired;
    expired.max_walk_seconds = 0; // budget stops

    const Limits defaults;
    const Limits* const all_limits[] = {&defaults, &tight, &expired};
    const auto before = open_fd_count();
    std::optional<std::string> token;
    for (const Limits* lim : all_limits) {
        (void)mac::macos_manager_rows_at(dir.path, token, *lim);
        (void)mac::macos_package_rows_at(dir.path, token, *lim, ucfg);
    }
    CHECK(open_fd_count() == before);
}

// ── receipts and user-owned prefixes ─────────────────────────────────────

namespace {

constexpr std::string_view kGoodReceipt =
    R"({"installed_on_request": true, "time": 1767225600, "source": {"tap": "homebrew/core"}})";
constexpr std::string_view kMachineTail = "|machine|-|/opt/homebrew";

void write_text(const fs::path& p, std::string_view body) {
    fs::create_directories(p.parent_path());
    std::ofstream out(p, std::ios::binary);
    REQUIRE(out.good());
    out << body;
}

/// A formula `id`/`ver` under `<root>/Users/<home>/<cand>/Cellar`, with a good receipt.
void make_user_formula(const fs::path& root, const std::string& home, const std::string& cand,
                       const std::string& id, const std::string& ver) {
    const auto v = root / "Users" / home / cand / "Cellar" / id / ver;
    fs::create_directories(v);
    write_text(v / "INSTALL_RECEIPT.json", kGoodReceipt);
}

std::string user_row(const std::string& id, const std::string& ver, const std::string& home,
                     const std::string& cand) {
    return "package|homebrew|" + id + "|" + ver + "|formula|1767225600|homebrew/core|true|user|" +
           home + "|~/" + cand;
}

/// The unprivileged config the happy-path cases use: every uid counts as a real home.
yuzu::pkg_inventory::mac::UserPrefixConfig any_uid_config() {
    yuzu::pkg_inventory::mac::UserPrefixConfig c;
    c.min_home_uid = 0;
    return c;
}

std::uint32_t euid32() { return static_cast<std::uint32_t>(::geteuid()); }

bool leaks(const std::vector<std::string>& rows, const std::optional<std::string>& token,
           const fs::path& root) {
    const auto bad = [&](const std::string& t) {
        return t.find("/Users/") != std::string::npos || t.find(root.string()) != std::string::npos;
    };
    for (const auto& r : rows)
        if (bad(r)) return true;
    return token && bad(*token);
}

} // namespace

TEST_CASE("pkg_inventory macos receipts: a symlink, FIFO, directory or oversized receipt gives `-`, "
          "never a token or a hang",
          "[pkg_inventory][macos][walk][receipt]") {
    using namespace yuzu::pkg_inventory;
    yuzu::test::TempDir dir{"yuzu_test_pkg_inventory_macos_receipt_bad_"};
    const auto cellar = dir.path / "opt/homebrew/Cellar";
    write_text(cellar / "good/1.0/INSTALL_RECEIPT.json", kGoodReceipt);
    fs::create_directories(cellar / "sym/1.0");
    std::error_code ec;
    fs::create_symlink(cellar / "good/1.0/INSTALL_RECEIPT.json", cellar / "sym/1.0/INSTALL_RECEIPT.json",
                       ec);
    REQUIRE_FALSE(ec);
    fs::create_directories(cellar / "fifo/1.0");
    REQUIRE(::mkfifo((cellar / "fifo/1.0/INSTALL_RECEIPT.json").c_str(), 0600) == 0);
    fs::create_directories(cellar / "dirr/1.0/INSTALL_RECEIPT.json");
    write_text(cellar / "big/1.0/INSTALL_RECEIPT.json",
               std::string{kGoodReceipt} + std::string(kMaxBrewReceiptBytes, ' '));

    std::optional<std::string> token;
    const auto rows = mac::macos_package_rows_at(dir.path, token);
    CHECK_FALSE(token.has_value());
    const std::vector<std::string> expected{
        "package|homebrew|big|1.0|formula|-|-|-" + std::string{kMachineTail},
        "package|homebrew|dirr|1.0|formula|-|-|-" + std::string{kMachineTail},
        "package|homebrew|fifo|1.0|formula|-|-|-" + std::string{kMachineTail},
        "package|homebrew|good|1.0|formula|1767225600|homebrew/core|true" + std::string{kMachineTail},
        "package|homebrew|sym|1.0|formula|-|-|-" + std::string{kMachineTail},
    };
    CHECK(rows == expected);
}

TEST_CASE("pkg_inventory macos receipts: a cask never reads a receipt, even a planted one",
          "[pkg_inventory][macos][walk][receipt]") {
    using namespace yuzu::pkg_inventory;
    yuzu::test::TempDir dir{"yuzu_test_pkg_inventory_macos_receipt_cask_"};
    write_text(dir.path / "opt/homebrew/Caskroom/somecask/1.0/INSTALL_RECEIPT.json", kGoodReceipt);
    std::optional<std::string> token;
    const auto rows = mac::macos_package_rows_at(dir.path, token);
    CHECK_FALSE(token.has_value());
    REQUIRE(rows.size() == 1);
    CHECK(rows[0] == "package|homebrew|somecask|1.0|cask|-|-|-" + std::string{kMachineTail});
}

TEST_CASE("pkg_inventory macos receipts: the owner rule gates parsing (injected owner, no root)",
          "[pkg_inventory][macos][walk][receipt]") {
    using namespace yuzu::pkg_inventory;
    yuzu::test::TempDir dir{"yuzu_test_pkg_inventory_macos_receipt_owner_"};
    write_text(dir.path / "v/INSTALL_RECEIPT.json", kGoodReceipt);
    const auto vdir = posix::open_dir_no_follow((dir.path / "v").string());
    REQUIRE(vdir.dir.valid());

    const auto own = mac::detail::read_brew_receipt(vdir.dir, euid32());
    CHECK(own.install_time == "1767225600");
    CHECK(own.tap == "homebrew/core");
    CHECK(own.on_request == "true");

    const auto foreign = mac::detail::read_brew_receipt(vdir.dir, euid32() + 1);
    CHECK(foreign.install_time.empty());
    CHECK(foreign.tap.empty());
    CHECK(foreign.on_request.empty());
}

TEST_CASE("pkg_inventory macos user prefixes: a home's own prefixes are listed after the machine "
          "rows, as user rows with no absolute path",
          "[pkg_inventory][macos][walk][user]") {
    using namespace yuzu::pkg_inventory;
    yuzu::test::TempDir dir{"yuzu_test_pkg_inventory_macos_user_ok_"};
    write_text(dir.path / "opt/homebrew/Cellar/mach/1.0/INSTALL_RECEIPT.json", kGoodReceipt);
    make_user_formula(dir.path, "beta", "homebrew", "tool", "2.0");
    make_user_formula(dir.path, "alpha", "homebrew", "wget", "1.0");
    make_user_formula(dir.path, "alpha", ".homebrew", "jq", "1.7");
    fs::create_directories(dir.path / "Users/alpha/homebrew/Caskroom/mycask/3.1");
    write_text(dir.path / "Users/.localized", "");        // dotfile: not a home
    write_text(dir.path / "Users/plainfile", "x");        // not a directory

    std::optional<std::string> token;
    const auto rows = mac::macos_package_rows_at(dir.path, token, Limits{}, any_uid_config());
    CHECK_FALSE(token.has_value());
    const std::vector<std::string> expected{
        "package|homebrew|mach|1.0|formula|1767225600|homebrew/core|true" + std::string{kMachineTail},
        user_row("wget", "1.0", "alpha", "homebrew"),
        "package|homebrew|mycask|3.1|cask|-|-|-|user|alpha|~/homebrew",
        user_row("jq", "1.7", "alpha", ".homebrew"),
        user_row("tool", "2.0", "beta", "homebrew"),
    };
    CHECK(rows == expected);
    for (const auto& row : rows)
        CHECK(split_fields_escape_aware(row).size() == 11);
    CHECK_FALSE(leaks(rows, token, dir.path));
}

TEST_CASE("pkg_inventory macos user prefixes: a home below the uid floor is skipped silently",
          "[pkg_inventory][macos][walk][user]") {
    using namespace yuzu::pkg_inventory;
    yuzu::test::TempDir dir{"yuzu_test_pkg_inventory_macos_user_floor_"};
    make_user_formula(dir.path, "alpha", "homebrew", "wget", "1.0");
    mac::UserPrefixConfig cfg;
    cfg.min_home_uid = euid32() + 1; // the temp tree's owner is below the floor
    std::optional<std::string> token;
    CHECK(mac::macos_package_rows_at(dir.path, token, Limits{}, cfg).empty());
    CHECK_FALSE(token.has_value());
}

TEST_CASE("pkg_inventory macos user prefixes: a symlinked home or candidate and a plain file are "
          "skipped, and the link target's packages never appear",
          "[pkg_inventory][macos][walk][user]") {
    using namespace yuzu::pkg_inventory;
    yuzu::test::TempDir dir{"yuzu_test_pkg_inventory_macos_user_links_"};
    make_user_formula(dir.path, "../elsewhere1", "homebrew", "secret1", "9.9"); // Users/../elsewhere1
    fs::create_directories(dir.path / "Users");
    std::error_code ec;
    fs::create_directory_symlink(dir.path / "elsewhere1", dir.path / "Users/linkhome", ec);
    REQUIRE_FALSE(ec);
    fs::create_directories(dir.path / "elsewhere2/Cellar/secret2/9.9");
    fs::create_directories(dir.path / "Users/alpha");
    fs::create_directory_symlink(dir.path / "elsewhere2", dir.path / "Users/alpha/homebrew", ec);
    REQUIRE_FALSE(ec);
    write_text(dir.path / "Users/beta/homebrew", "not a directory");
    write_text(dir.path / "Users/beta/.homebrew", "not a directory either");

    std::optional<std::string> token;
    const auto rows = mac::macos_package_rows_at(dir.path, token, Limits{}, any_uid_config());
    CHECK(rows.empty());
    CHECK_FALSE(token.has_value());
}

TEST_CASE("pkg_inventory macos user prefixes: a symlinked Cellar in a real prefix constrains the "
          "answer with a named token",
          "[pkg_inventory][macos][walk][user]") {
    using namespace yuzu::pkg_inventory;
    yuzu::test::TempDir dir{"yuzu_test_pkg_inventory_macos_user_cellar_link_"};
    fs::create_directories(dir.path / "elsewhere/secret/9.9");
    fs::create_directories(dir.path / "Users/alpha/homebrew");
    std::error_code ec;
    fs::create_directory_symlink(dir.path / "elsewhere", dir.path / "Users/alpha/homebrew/Cellar", ec);
    REQUIRE_FALSE(ec);
    std::optional<std::string> token;
    const auto rows = mac::macos_package_rows_at(dir.path, token, Limits{}, any_uid_config());
    CHECK(rows.empty());
    REQUIRE(token.has_value());
    CHECK(*token == "macos:homebrew_user_cellar:not_a_directory");
    CHECK_FALSE(leaks(rows, token, dir.path));
}

TEST_CASE("pkg_inventory macos user prefixes: network mounts are never touched",
          "[pkg_inventory][macos][walk][user]") {
    using namespace yuzu::pkg_inventory;
    yuzu::test::TempDir dir{"yuzu_test_pkg_inventory_macos_user_mounts_"};
    make_user_formula(dir.path, "alpha", "homebrew", "wget", "1.0");
    make_user_formula(dir.path, "beta", "homebrew", "tool", "2.0");
    std::optional<std::string> token;

    // /Users itself on a mount: no home is opened.
    auto cfg = any_uid_config();
    cfg.network_mounts = {"/Users"};
    CHECK(mac::macos_package_rows_at(dir.path, token, Limits{}, cfg).empty());
    REQUIRE(token.has_value());
    CHECK(*token == "macos:user_homes:network_mount");

    // One home on a mount: a token, and the other home is still walked.
    cfg.network_mounts = {"/Users/alpha"};
    auto rows = mac::macos_package_rows_at(dir.path, token, Limits{}, cfg);
    REQUIRE(token.has_value());
    CHECK(*token == "macos:user_homes:network_mount");
    REQUIRE(rows.size() == 1);
    CHECK(rows[0] == user_row("tool", "2.0", "beta", "homebrew"));

    // A mount INSIDE a candidate prefix: that prefix is never opened.
    cfg.network_mounts = {"/Users/alpha/homebrew/Cellar"};
    rows = mac::macos_package_rows_at(dir.path, token, Limits{}, cfg);
    REQUIRE(token.has_value());
    CHECK(*token == "macos:homebrew_user_prefix:network_mount");
    REQUIRE(rows.size() == 1);
    CHECK(rows[0] == user_row("tool", "2.0", "beta", "homebrew"));
}

TEST_CASE("pkg_inventory macos user prefixes: an unreadable mount table skips the user walk with a "
          "token and keeps the machine rows",
          "[pkg_inventory][macos][walk][user]") {
    using namespace yuzu::pkg_inventory;
    yuzu::test::TempDir dir{"yuzu_test_pkg_inventory_macos_user_mounts_unreadable_"};
    write_text(dir.path / "opt/homebrew/Cellar/mach/1.0/INSTALL_RECEIPT.json", kGoodReceipt);
    make_user_formula(dir.path, "alpha", "homebrew", "wget", "1.0");
    auto cfg = any_uid_config();
    cfg.mounts_unreadable = true;
    std::optional<std::string> token;
    const auto rows = mac::macos_package_rows_at(dir.path, token, Limits{}, cfg);
    REQUIRE(token.has_value());
    CHECK(*token == "macos:user_homes:mounts_unreadable");
    REQUIRE(rows.size() == 1);
    CHECK(rows[0].find("|machine|") != std::string::npos);
}

TEST_CASE("pkg_inventory macos user prefixes: every bound stops the user walk and is recorded once",
          "[pkg_inventory][macos][walk][user][limits]") {
    using namespace yuzu::pkg_inventory;
    yuzu::test::TempDir dir{"yuzu_test_pkg_inventory_macos_user_caps_"};
    for (const char* home : {"alpha", "beta"}) {
        make_user_formula(dir.path, home, "homebrew", "a", "1.0");
        make_user_formula(dir.path, home, "homebrew", "b", "1.0");
    }
    const auto cfg = any_uid_config();
    std::optional<std::string> token;

    // /Users listing cut at the entry cap: the one home read is kept, the cut is named.
    Limits entry_cap;
    entry_cap.max_entries_per_dir = 1;
    auto rows = mac::macos_package_rows_at(dir.path, token, entry_cap, cfg);
    REQUIRE(token.has_value());
    CHECK(token->find("macos:user_homes:entry_cap") != std::string::npos);

    // Whole-action walk budget spent by the /Users listing itself: nothing is opened.
    Limits budget;
    budget.max_walk_entries = 2;
    rows = mac::macos_package_rows_at(dir.path, token, budget, cfg);
    CHECK(rows.empty());
    REQUIRE(token.has_value());
    CHECK(*token == "macos:user_homes:walk_budget");

    // Row cap under the user source: one row, then the walk stops (the second home is not read).
    Limits row_cap;
    row_cap.max_package_rows = 1;
    rows = mac::macos_package_rows_at(dir.path, token, row_cap, cfg);
    REQUIRE(rows.size() == 1);
    REQUIRE(token.has_value());
    CHECK(*token == "macos:homebrew_user_cellar:row_cap");

    // Byte cap under the user source: exactly one user row fits.
    Limits byte_cap;
    byte_cap.max_output_bytes =
        user_row("a", "1.0", "alpha", "homebrew").size() + 1;
    rows = mac::macos_package_rows_at(dir.path, token, byte_cap, cfg);
    REQUIRE(rows.size() == 1);
    REQUIRE(token.has_value());
    CHECK(*token == "macos:homebrew_user_cellar:byte_cap");
}

TEST_CASE("pkg_inventory macos user prefixes: a home name that cannot be a wire field is refused, "
          "and a home with only an empty ~/.homebrew yields nothing",
          "[pkg_inventory][macos][walk][user]") {
    using namespace yuzu::pkg_inventory;
    yuzu::test::TempDir dir{"yuzu_test_pkg_inventory_macos_user_name_"};
    make_user_formula(dir.path, "caf\xc3\xa9", "homebrew", "wget", "1.0"); // non-ASCII name
    make_user_formula(dir.path, "zed", "homebrew", "tool", "2.0");
    fs::create_directories(dir.path / "Users/n\xc3\xa9" "e/.homebrew"); // Homebrew's state dir only
    std::optional<std::string> token;
    const auto rows = mac::macos_package_rows_at(dir.path, token, Limits{}, any_uid_config());
    REQUIRE(token.has_value());
    CHECK(*token == "macos:homebrew_user_prefix:owner_name_unsupported");
    REQUIRE(rows.size() == 1); // the refused home gave no row; the next home is still read
    CHECK(rows[0] == user_row("tool", "2.0", "zed", "homebrew"));
}

TEST_CASE("pkg_inventory macos user prefixes: the prefix owner must equal the home's (injected "
          "owner, no root)",
          "[pkg_inventory][macos][walk][user][owner]") {
    using namespace yuzu::pkg_inventory;
    yuzu::test::TempDir dir{"yuzu_test_pkg_inventory_macos_user_owner_"};
    fs::create_directories(dir.path / "home/homebrew/Cellar/planted/1.0");
    const auto home = posix::open_dir_no_follow((dir.path / "home").string());
    REQUIRE(home.dir.valid());
    const Limits lim;
    const mac::UserPrefixConfig cfg;

    {
        std::vector<std::string> rows;
        yuzu::shared::ConstraintAccumulator acc;
        auto budget = WalkBudget::from(lim);
        (void)mac::detail::append_home_prefix_rows(home.dir, euid32(), "alpha", cfg, lim, rows, acc,
                                                   budget);
        CHECK_FALSE(acc.any_failure());
        REQUIRE(rows.size() == 1);
        CHECK(rows[0].find("|user|alpha|~/homebrew") != std::string::npos);
    }
    {
        std::vector<std::string> rows;
        yuzu::shared::ConstraintAccumulator acc;
        auto budget = WalkBudget::from(lim);
        (void)mac::detail::append_home_prefix_rows(home.dir, euid32() + 1, "alpha", cfg, lim, rows,
                                                   acc, budget);
        CHECK(rows.empty());
        CHECK(acc.reason() == "macos:homebrew_user_prefix:owner_mismatch");
        CHECK(acc.incomplete());
    }
}

TEST_CASE("pkg_inventory macos user prefixes (root only): another account's prefix or receipt is "
          "refused through the full walk",
          "[pkg_inventory][macos][walk][user][owner]") {
    using namespace yuzu::pkg_inventory;
    if (::geteuid() != 0) SKIP("needs root to chown a tree to another account");
    constexpr uid_t kOther = 12345;
    {
        yuzu::test::TempDir dir{"yuzu_test_pkg_inventory_macos_user_root_prefix_"};
        make_user_formula(dir.path, "alpha", "homebrew", "planted", "1.0");
        REQUIRE(::chown((dir.path / "Users/alpha/homebrew").c_str(), kOther, static_cast<gid_t>(-1)) == 0);
        std::optional<std::string> token;
        const auto rows = mac::macos_package_rows_at(dir.path, token, Limits{}, any_uid_config());
        CHECK(rows.empty());
        REQUIRE(token.has_value());
        CHECK(*token == "macos:homebrew_user_prefix:owner_mismatch");
        CHECK(token->find("planted") == std::string::npos);
    }
    {
        yuzu::test::TempDir dir{"yuzu_test_pkg_inventory_macos_user_root_receipt_"};
        make_user_formula(dir.path, "alpha", "homebrew", "wget", "1.0");
        REQUIRE(::chown((dir.path / "Users/alpha/homebrew/Cellar/wget/1.0/INSTALL_RECEIPT.json").c_str(),
                        kOther, static_cast<gid_t>(-1)) == 0);
        std::optional<std::string> token;
        const auto rows = mac::macos_package_rows_at(dir.path, token, Limits{}, any_uid_config());
        CHECK_FALSE(token.has_value());
        REQUIRE(rows.size() == 1);
        CHECK(rows[0] == "package|homebrew|wget|1.0|formula|-|-|-|user|alpha|~/homebrew");
    }
}

TEST_CASE("pkg_inventory macos seam: a user-prefix failure reaches BOTH the status row and the "
          "typed status through run_macos_at",
          "[pkg_inventory][macos][seam][user]") {
    using namespace yuzu::pkg_inventory;
    yuzu::test::TempDir dir{"yuzu_test_pkg_inventory_macos_user_seam_"};
    write_text(dir.path / "opt/homebrew/Cellar/mach/1.0/INSTALL_RECEIPT.json", kGoodReceipt);
    fs::create_directories(dir.path / "elsewhere");
    fs::create_directories(dir.path / "Users/alpha/homebrew");
    std::error_code ec;
    fs::create_directory_symlink(dir.path / "elsewhere", dir.path / "Users/alpha/homebrew/Cellar", ec);
    REQUIRE_FALSE(ec);
    const auto cfg = any_uid_config();

    const auto packages = run_leg(dir.path, Action::packages, Via::at, &cfg);
    CHECK(packages.rc == 0);
    const auto prows = captured_rows(packages.captured);
    REQUIRE_FALSE(prows.empty());
    CHECK(prows[0] == "status|packages|constrained|macos:homebrew_user_cellar:not_a_directory");
    CHECK(packages.result_status == YUZU_RESULT_STATUS_CONSTRAINED);
    CHECK(packages.result_completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
    CHECK(packages.result_provenance == "macos:homebrew_user_cellar:not_a_directory");

    // `managers` never walks /Users: the same tree answers it in full.
    const auto managers = run_leg(dir.path, Action::managers, Via::at, &cfg);
    CHECK(managers.result_status == YUZU_RESULT_STATUS_OK);
}


#endif // !defined(_WIN32)
