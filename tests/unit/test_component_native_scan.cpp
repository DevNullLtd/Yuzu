/**
 * test_component_native_scan.cpp -- tests for the component_inventory `native` scan
 * (agents/plugins/component_inventory/src/component_native_scan.hpp). The scan is driven over an
 * in-memory tree and a fake clock (component_fixture_tree.hpp); nothing here touches the host except
 * the one POSIX-only case at the end, which materialises a small tree under a yuzu_test_ temporary
 * directory and runs the real filesystem leg and the real parsers over it.
 *
 * Most cases use a parse function that reads no bytes (the real name rules over a file name), so the
 * scan's own decisions are tested apart from the adapter, which test_component_native_parsers.cpp
 * covers (the readers themselves are the shared binary_header readers).
 *
 * MUTATION NOTES (each assertion below FAILS if the named wiring is removed):
 *  - kind: writing `java` for every row fails the wire-row case.
 *  - skip_dir: not consulting the policy fails the excluded-tree case (the tree is listed and its
 *    library appears); not counting fails the token assertion (a silent skip).
 *  - not a library: emitting a row for every name match fails the no-row case.
 *  - unreadable library: dropping the unreadable fallback in describe_*_file fails the item-gap case
 *    (no row at all, a hidden library).
 *  - changed file: dropping the unchanged() check, or the not-openable record, fails those rows.
 *  - one deadline: checking the clock only in the walk fails the budget_time case.
 *  - mount-table guard: walking when mount_table_unreadable is set fails the no-walk case.
 */
#include <catch2/catch_test_macros.hpp>

#include "component_fixture_tree.hpp"
#include "component_native_scan.hpp"

#include <algorithm>
#include <chrono>
#include <cstdint>
#include <string>
#include <stdexcept>
#include <string_view>
#include <utility>
#include <vector>

#if !defined(_WIN32)
#include "component_legs.hpp"
#include "test_helpers.hpp"

#include <filesystem>
#include <fstream>
#endif

using namespace yuzu::component_inventory;
using namespace yuzu::component_inventory::fixture;
using namespace std::chrono_literals;
using yuzu::shared::StatusLevel;

namespace {

/// A parse that reads no bytes: every name match is a library, named by the Linux file-name rules.
/// `opened` counts the files the scan asked about.
struct CountingParse {
    int* calls;
    std::optional<NativeDescription> operator()(std::string_view leaf, const ReadAt&, std::uint64_t) const {
        ++*calls;
        return describe_linux(leaf, std::nullopt);
    }
};

WalkPolicy linux_policy() {
    WalkPolicy p;
    p.is_candidate = &is_linux_native_candidate;
    return p;
}

ScanResult run(MemTree& tree, const WalkPolicy& policy, const NativeParse& parse, WalkLimits limits = native_limits(),
               const std::vector<std::string>& roots = {"/opt"}) {
    const FsOps fs = tree.ops();
    return scan_native(roots, limits, fs, policy, parse);
}

struct FakeTargets {
    std::vector<std::string> roots{"/opt"};
    bool mount_table_unreadable{false};
    std::size_t roots_link_skipped{0};
    std::size_t roots_network_skipped{0};
};

struct FakeCtx {
    std::vector<std::string> out;
    YuzuResultStatus status{YUZU_RESULT_STATUS_UNDECLARED};
    YuzuResultCompleteness completeness{YUZU_RESULT_COMPLETENESS_UNKNOWN};
    std::string provenance;
    void write_output(std::string_view t) { out.emplace_back(t); }
    void set_result_status(YuzuResultStatus s, YuzuResultCompleteness c, std::string_view p = {}) {
        status = s;
        completeness = c;
        provenance = std::string(p);
    }
};

/// Plugin-context recorder type for emit_answer's heartbeat parameter (never reached with a null one).
struct FakeKv {
    bool storage_set(std::string_view, std::string_view) { return true; }
};

} // namespace

TEST_CASE("native scan: rows carry kind native and the documented fields over an in-memory tree",
          "[runtime][component_native_scan][component_inventory]") {
    MemTree tree;
    tree.add_file("/opt/acme/lib/libwidget.so.1.2", "x");
    tree.mtimes["/opt/acme/lib/libwidget.so.1.2"] = 1700000123;
    tree.add_file("/opt/acme/readme.txt", "no");
    int calls = 0;
    const auto r = run(tree, linux_policy(), CountingParse{&calls});

    CHECK(r.stop == Stop::complete);
    REQUIRE(r.rows.size() == 1);
    CHECK(calls == 1); // the readme is not a candidate: never opened
    const auto& row = r.rows[0];
    CHECK(row.kind == "native");
    CHECK(row.name == "libwidget");
    CHECK(row.version == "1.2");
    CHECK(row.version_source == "filename");
    CHECK(row.path == "/opt/acme/lib/libwidget.so.1.2");
    CHECK(row.size == 1);
    CHECK(row.mtime == 1700000123);
    CHECK(row.anchor_app == "acme");
    CHECK(format_component_row(row) ==
          "comp|native|libwidget|1.2|filename|/opt/acme/lib/libwidget.so.1.2|1|1700000123|acme");
    CHECK(tree.total_opens == 1); // one open per candidate
}

TEST_CASE("native scan: the section cap, the anchor cap and the deadline end the scan with their own cause",
          "[runtime][component_native_scan][component_inventory]") {
    int calls = 0;
    SECTION("section_rows") {
        MemTree tree;
        for (int i = 0; i < 5; ++i)
            tree.add_file("/opt/app" + std::to_string(i) + "/libx.so.1", "x");
        WalkLimits l = native_limits();
        l.max_rows = 3;
        const auto r = run(tree, linux_policy(), CountingParse{&calls}, l);
        CHECK(r.stop == Stop::section_rows);
        CHECK(r.rows.size() == 3);
    }
    SECTION("anchor_rows") {
        MemTree tree;
        for (int i = 0; i < 4; ++i)
            tree.add_file("/opt/app/libx" + std::to_string(i) + ".so.1", "x");
        WalkLimits l = native_limits();
        l.max_rows_per_anchor = 2;
        const auto r = run(tree, linux_policy(), CountingParse{&calls}, l);
        CHECK(r.stop == Stop::anchor_rows);
        CHECK(r.rows.size() == 2);
    }
    SECTION("the native limits: a 5,000-row cap, every other bound the scan's") {
        const auto l = native_limits();
        const WalkLimits d;
        CHECK(l.max_rows == 5000);
        CHECK(l.max_entries == d.max_entries);
        CHECK(l.max_wall == d.max_wall);
        CHECK(l.max_rows_per_anchor == d.max_rows_per_anchor);
        CHECK(l.max_depth == d.max_depth);
        CHECK(l.max_dir_entries == d.max_dir_entries);
    }
    SECTION("budget_time: the fake clock passes 45 s while files are read") {
        MemTree tree;
        for (int i = 0; i < 3; ++i)
            tree.add_file("/opt/app" + std::to_string(i) + "/libx.so.1", "x");
        tree.open_step = 46s; // the first open alone uses the whole budget
        const auto r = run(tree, linux_policy(), CountingParse{&calls});
        CHECK(r.stop == Stop::budget_time);
        CHECK(r.rows.size() == 1);
        CHECK(tree.total_opens == 1); // the one deadline is checked between files
    }
}

TEST_CASE("native scan: an excluded directory is not listed, is counted, and is reported on a complete scan",
          "[runtime][component_native_scan][component_inventory]") {
    MemTree tree;
    tree.add_file("/opt/app/libkeep.so.1", "x");
    tree.add_file("/opt/Cellar/pkg/libhidden.so.1", "x");
    WalkPolicy p = linux_policy();
    p.skip_dir = [](const std::string& d) { return d == "/opt/Cellar"; };
    int calls = 0;
    const auto r = run(tree, p, CountingParse{&calls});

    CHECK(r.stop == Stop::complete);
    REQUIRE(r.rows.size() == 1);
    CHECK(r.rows[0].name == "libkeep");
    CHECK(r.stats.dirs_excluded == 1);
    CHECK(std::ranges::find(tree.listed, "/opt/Cellar") == tree.listed.end());
    CHECK(std::ranges::find(tree.listed, "/opt/Cellar/pkg") == tree.listed.end());

    const auto v = scan_verdict("macos", r.stop, false, 0, 0, 0, 0, r.stats.dirs_excluded);
    CHECK(v.level == StatusLevel::supported);
    CHECK(v.complete);
    CHECK(v.tokens == "macos:component_inventory:package_tree_skipped");

    // The same tree with no policy exclusion: nothing is counted and the library is found.
    MemTree open_tree;
    open_tree.add_file("/opt/app/libkeep.so.1", "x");
    open_tree.add_file("/opt/Cellar/pkg/libhidden.so.1", "x");
    const auto all = run(open_tree, linux_policy(), CountingParse{&calls});
    CHECK(all.rows.size() == 2);
    CHECK(all.stats.dirs_excluded == 0);
}

TEST_CASE("native scan: not a library gives no row; an unreadable library an item-level gap; a changed file a cause",
          "[runtime][component_native_scan][component_inventory]") {
    const auto linux_parse = [](std::string_view leaf, const ReadAt& rd, std::uint64_t size) {
        return describe_linux_file(leaf, rd, size);
    };

    SECTION("the name matches and the magic does not: no row, and the scan is complete") {
        MemTree tree;
        tree.add_file("/opt/app/libfake.so", "#!/bin/sh\necho hello, this is a script\n");
        const auto r = run(tree, linux_policy(), linux_parse);
        CHECK(r.rows.empty());
        CHECK(r.stop == Stop::complete);
    }
    SECTION("the right magic that cannot be parsed in bounds: a row from the name, version unreadable, still complete") {
        MemTree tree;
        std::string elf = "\x7f" "ELF";
        elf += std::string{2, 1, 1};
        elf.resize(40, '\0'); // an ELF64 header cut short
        tree.add_file("/opt/app/libcut.so", elf);
        tree.add_file("/opt/app/libcut2.so.4", elf);
        const auto r = run(tree, linux_policy(), linux_parse);
        CHECK(r.stop == Stop::complete);
        REQUIRE(r.rows.size() == 2);
        for (const auto& row : r.rows) {
            if (row.name == "libcut") {
                CHECK(row.version.empty());
                CHECK(row.version_source == "unreadable");
            } else {
                CHECK(row.name == "libcut2");
                CHECK(row.version == "4");
                CHECK(row.version_source == "filename");
            }
        }
        CHECK(r.version_unreadable == 1);
        const auto v = scan_verdict("linux", r.stop, false, 0, 0, 0, r.version_unreadable);
        CHECK(v.level == StatusLevel::supported);
        CHECK(v.tokens == "linux:component_inventory:version_unreadable");
    }
    SECTION("a file changed while read records the changed cause and keeps its row") {
        MemTree tree;
        tree.add_file("/opt/app/libx.so.1", "x");
        tree.changed.insert("/opt/app/libx.so.1");
        int calls = 0;
        const auto r = run(tree, linux_policy(), CountingParse{&calls});
        CHECK(r.stop == Stop::archive_changed);
        CHECK(r.rows.size() == 1);
    }
    SECTION("a listed file that cannot be opened is a file that changed: the cause, no row") {
        MemTree tree;
        tree.add_file("/opt/app/libx.so.1", "x");
        tree.unopenable.insert("/opt/app/libx.so.1");
        int calls = 0;
        const auto r = run(tree, linux_policy(), CountingParse{&calls});
        CHECK(r.stop == Stop::archive_changed);
        CHECK(r.rows.empty());
        CHECK(calls == 0);
    }
}

TEST_CASE("native answer: the status row names `native`, an unreadable mount table walks nothing, the catch-all answers one row",
          "[runtime][component_native_scan][answer][component_inventory]") {
    int calls = 0;
    SECTION("a populated answer: the status row first, then the comp rows") {
        MemTree tree;
        tree.add_file("/opt/app/libx.so.2", "x");
        const auto a = answer_native("linux", FakeTargets{}, [&](const FakeTargets&) { return tree.ops(); },
                                     native_limits(), linux_policy(), CountingParse{&calls});
        REQUIRE(a.lines.size() == 2);
        CHECK(a.lines[0] == "status|native|supported|-");
        CHECK(a.lines[1].starts_with("comp|native|libx|2|filename|/opt/app/libx.so.2|"));
        CHECK(a.verdict.complete);
    }
    SECTION("an unreadable mount table walks nothing and says so") {
        FakeTargets t;
        t.mount_table_unreadable = true;
        int made = 0;
        const auto a = answer_native("linux", t, [&](const FakeTargets&) {
            ++made;
            return FsOps{};
        }, native_limits(), linux_policy(), CountingParse{&calls});
        CHECK(made == 0);
        REQUIRE(a.lines.size() == 1);
        CHECK(a.lines[0] == "status|native|constrained|linux:component_inventory:mount_table_unreadable");
        CHECK_FALSE(a.verdict.complete);
    }
    SECTION("an excluded tree rides the status row of a complete answer") {
        MemTree tree;
        tree.add_file("/opt/Cellar/p/libh.so.1", "x");
        WalkPolicy p = linux_policy();
        p.skip_dir = [](const std::string& d) { return d == "/opt/Cellar"; };
        const auto a = answer_native("macos", FakeTargets{}, [&](const FakeTargets&) { return tree.ops(); },
                                     native_limits(), p, CountingParse{&calls});
        REQUIRE(a.lines.size() == 1);
        CHECK(a.lines[0] == "status|native|supported|macos:component_inventory:package_tree_skipped");
    }
    SECTION("the catch-all answers one constrained row for the action that ran, and writes no heartbeat") {
        FakeCtx ctx;
        constexpr std::string_view token = "linux:component_inventory:internal_error";
        answer_internal_error(ctx, token, false, kNativeAction);
        REQUIRE(ctx.out.size() == 1);
        CHECK(ctx.out[0] == "status|native|constrained|linux:component_inventory:internal_error");
        CHECK(ctx.status == YUZU_RESULT_STATUS_CONSTRAINED);
        CHECK(ctx.completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
        CHECK(ctx.provenance == token);

        // Default action is still scan: the existing callers are unchanged.
        FakeCtx scan_ctx;
        answer_internal_error(scan_ctx, token, false);
        REQUIRE(scan_ctx.out.size() == 1);
        CHECK(scan_ctx.out[0] == "status|scan|constrained|linux:component_inventory:internal_error");
    }
    SECTION("emit_answer with no heartbeat context writes the rows and the typed result only") {
        MemTree tree;
        tree.add_file("/opt/app/libx.so.2", "x");
        const auto a = answer_native("linux", FakeTargets{}, [&](const FakeTargets&) { return tree.ops(); },
                                     native_limits(), linux_policy(), CountingParse{&calls});
        FakeCtx ctx;
        bool wrote = false;
        emit_answer(ctx, static_cast<FakeKv*>(nullptr), a, wrote); // a null context: no heartbeat key is set
        CHECK(wrote);
        CHECK(ctx.out == a.lines);
        CHECK(ctx.status == YUZU_RESULT_STATUS_OK);
        CHECK(ctx.completeness == YUZU_RESULT_COMPLETENESS_FULL);
    }
}

#if !defined(_WIN32)
namespace {

void put(std::string& b, std::size_t pos, std::uint64_t v, unsigned n, bool big) {
    if (b.size() < pos + n)
        b.resize(pos + n, '\0');
    for (unsigned i = 0; i < n; ++i)
        b[pos + i] = static_cast<char>((v >> (big ? 8 * (n - 1 - i) : 8 * i)) & 0xFF);
}

/// A minimal little-endian ELF64 shared object whose DT_SONAME is `soname` (DT_NULL-terminated).
std::string minimal_elf64(const std::string& soname) {
    const std::size_t dyn_off = 64 + 2 * 56, dyn_size = 4 * 16, str_off = dyn_off + dyn_size;
    const std::string strtab = std::string(1, '\0') + soname + '\0';
    std::string b(str_off + strtab.size(), '\0');
    b.replace(0, 4, "\x7f" "ELF");
    b[4] = 2;
    b[5] = 1;
    b[6] = 1;
    put(b, 16, 3, 2, false);
    put(b, 32, 64, 8, false);
    put(b, 54, 56, 2, false);
    put(b, 56, 2, 2, false);
    put(b, 64, 1, 4, false); // PT_LOAD at vaddr 0x1000
    put(b, 64 + 8, 0, 8, false);
    put(b, 64 + 16, 0x1000, 8, false);
    put(b, 64 + 32, b.size(), 8, false);
    put(b, 120, 2, 4, false); // PT_DYNAMIC
    put(b, 120 + 8, dyn_off, 8, false);
    put(b, 120 + 16, 0x1000 + dyn_off, 8, false);
    put(b, 120 + 32, dyn_size, 8, false);
    put(b, dyn_off, 14, 8, false); // DT_SONAME -> 1
    put(b, dyn_off + 8, 1, 8, false);
    put(b, dyn_off + 16, 5, 8, false); // DT_STRTAB
    put(b, dyn_off + 24, 0x1000 + str_off, 8, false);
    put(b, dyn_off + 32, 10, 8, false); // DT_STRSZ
    put(b, dyn_off + 40, strtab.size(), 8, false);
    b.replace(str_off, strtab.size(), strtab);
    return b;
}

/// A minimal little-endian thin Mach-O 64 dylib with an LC_ID_DYLIB.
std::string minimal_macho64(const std::string& install_name, std::uint32_t current) {
    const std::size_t cmdsize = (24 + install_name.size() + 1 + 7) & ~std::size_t{7};
    std::string b(32 + cmdsize, '\0');
    put(b, 0, 0xFEEDFACFU, 4, false);
    put(b, 12, 6, 4, false);
    put(b, 16, 1, 4, false);
    put(b, 20, cmdsize, 4, false);
    put(b, 32, 0xD, 4, false);
    put(b, 36, cmdsize, 4, false);
    put(b, 40, 24, 4, false);
    put(b, 48, current, 4, false);
    b.replace(56, install_name.size(), install_name);
    return b;
}

struct TempTree {
    yuzu::test::TempDir tmp{"yuzu_test_component_native_"};
    std::filesystem::path root; // canonical: /var and /tmp are links on macOS and the leg refuses them

    TempTree() {
        REQUIRE(std::filesystem::create_directory(tmp.path));
        root = std::filesystem::canonical(tmp.path);
    }

    void write(const std::string& rel, const std::string& bytes) const {
        const auto p = root / rel;
        std::filesystem::create_directories(p.parent_path());
        std::ofstream(p, std::ios::binary) << bytes;
    }
};

bool either_candidate(std::string_view leaf) {
    return is_linux_native_candidate(leaf) || is_macos_native_candidate(leaf);
}

} // namespace

TEST_CASE("native scan: through the real POSIX leg and the real parsers over a materialised tree",
          "[runtime][component_native_scan][posix][component_inventory]") {
    TempTree tmp;
    tmp.write("app/lib/libssl.so.3.0.13", minimal_elf64("libssl.so.3"));
    tmp.write("app/lib/libplain.so", minimal_elf64("libplain.so.7"));
    tmp.write("app/Frameworks/libmac.2.dylib", minimal_macho64("@rpath/libmac.2.dylib", 0x00020001));
    tmp.write("app/lib/libscript.so", "#!/bin/sh\n");
    tmp.write("Cellar/pkg/libpkg.so.1", minimal_elf64("libpkg.so.1"));

    const auto targets = scan_targets({tmp.root.string()}, [] { return std::optional{std::vector<std::string>{}}; });
    REQUIRE(targets.roots.size() == 1);

    WalkPolicy policy;
    policy.is_candidate = &either_candidate;
    const std::string cellar = (tmp.root / "Cellar").string();
    policy.skip_dir = [cellar](const std::string& d) { return d == cellar; };
    const NativeParse parse = [](std::string_view leaf, const ReadAt& rd, std::uint64_t size) {
        return leaf.ends_with(".dylib") ? describe_macos_file(leaf, rd, size) : describe_linux_file(leaf, rd, size);
    };
    const FsOps fs = make_fs_ops(targets);
    const auto r = scan_native(targets.roots, native_limits(), fs, policy, parse);

    CHECK(r.stop == Stop::complete);
    CHECK(r.stats.dirs_excluded == 1);
    REQUIRE(r.rows.size() == 3); // the script is not a library; the Cellar tree is not walked
    const auto find = [&](const std::string& name) -> const Row* {
        for (const auto& row : r.rows)
            if (row.name == name)
                return &row;
        return nullptr;
    };
    const auto* ssl = find("libssl");
    REQUIRE(ssl != nullptr);
    CHECK(ssl->kind == "native");
    CHECK(ssl->version == "3.0.13");
    CHECK(ssl->version_source == "filename");
    CHECK(ssl->path == (tmp.root / "app/lib/libssl.so.3.0.13").string());
    CHECK(ssl->size == std::filesystem::file_size(tmp.root / "app/lib/libssl.so.3.0.13"));
    CHECK(ssl->anchor_app == "app");
    const auto* plain = find("libplain");
    REQUIRE(plain != nullptr);
    CHECK(plain->version == "7");
    CHECK(plain->version_source == "elf");
    const auto* mac = find("libmac");
    REQUIRE(mac != nullptr);
    CHECK(mac->version == "2.0.1");
    CHECK(mac->version_source == "macho");
}

TEST_CASE("native scan: the deadline holds inside a parse, and a hostile SONAME reaches a row sanitised",
          "[runtime][component_native_scan][posix][component_inventory]") {
    SECTION("a read after the deadline answers nullopt: the library is a name-only row, unreadable") {
        MemTree tree;
        tree.add_file("/opt/app/libx.so", minimal_elf64("libx.so.7"));
        tree.open_step = 46s; // the open alone uses the whole 45 s budget
        std::optional<std::string> late{"unset"};
        const NativeParse probe = [&late](std::string_view leaf, const ReadAt& rd, std::uint64_t size) {
            late = rd(0, 4);
            return describe_linux_file(leaf, rd, size);
        };
        const auto r = run(tree, linux_policy(), probe);
        CHECK_FALSE(late.has_value());
        REQUIRE(r.rows.size() == 1);
        CHECK(r.rows[0].name == "libx");
        CHECK(r.rows[0].version.empty()); // the SONAME's version was never read
        CHECK(r.rows[0].version_source == "unreadable");
        CHECK(r.stop == Stop::budget_time);
    }
    SECTION("before the deadline the same file is read and its SONAME version used") {
        MemTree tree;
        tree.add_file("/opt/app/libx.so", minimal_elf64("libx.so.7"));
        const auto r = run(tree, linux_policy(), describe_linux_file);
        REQUIRE(r.rows.size() == 1);
        CHECK(r.rows[0].version == "7");
        CHECK(r.rows[0].version_source == "elf");
    }
    SECTION("control bytes and high bytes in a SONAME never reach the row name") {
        MemTree tree;
        tree.add_file("/opt/app/libx.so", minimal_elf64(std::string("lib\x01\xff|x.so.1")));
        const auto r = run(tree, linux_policy(), describe_linux_file);
        REQUIRE(r.rows.size() == 1);
        CHECK(r.rows[0].name == "lib??|x");
    }
    SECTION("a read that throws is a name-only row, not an abort") {
        MemTree tree;
        tree.add_file("/opt/app/libx.so.2", minimal_elf64("libx.so.2"));
        const NativeParse throwing = [](std::string_view leaf, const ReadAt& rd, std::uint64_t size) {
            const ReadAt bad = [&rd](std::uint64_t off, std::size_t len) -> std::optional<std::string> {
                if (off != 0)
                    throw std::runtime_error("boom");
                return rd(off, len);
            };
            return describe_linux_file(leaf, bad, size);
        };
        const auto r = run(tree, linux_policy(), throwing);
        REQUIRE(r.rows.size() == 1);
        CHECK(r.rows[0].name == "libx");
        CHECK(r.rows[0].version == "2");
        CHECK(r.rows[0].version_source == "filename");
    }
    SECTION("a file changed during a real parse is still the changed cause") {
        MemTree tree;
        tree.add_file("/opt/app/libx.so.2", minimal_elf64("libx.so.2"));
        tree.changed.insert("/opt/app/libx.so.2");
        const auto r = run(tree, linux_policy(), describe_linux_file);
        CHECK(r.stop == Stop::archive_changed);
    }
}

TEST_CASE("native legs: the roots and the excluded trees per OS", "[runtime][component_native_scan][posix][component_inventory]") {
#if defined(__APPLE__)
    CHECK(native_candidate_roots() == std::vector<std::string>{"/Applications", "/usr/local", "/opt/homebrew"});
    CHECK(native_excluded_dirs() == std::vector<std::string>{"/usr/local/Cellar", "/opt/homebrew/Cellar"});
#else
    CHECK(native_candidate_roots() == std::vector<std::string>{"/opt", "/usr/local/lib"});
    CHECK(native_excluded_dirs().empty());
#endif
    // The package manager's own trees are never roots.
    for (const auto& root : native_candidate_roots()) {
        CHECK_FALSE(root == "/usr/lib");
        CHECK_FALSE(root == "/lib");
        CHECK_FALSE(root == "/usr");
    }
}
#endif
