/**
 * test_file_search_local_dispatcher.cpp -- loads the ACTUAL built file_search plugin (file_search.dylib /
 * .so / .dll) via PluginHandle::load and drives it through yuzu::agent::LocalDispatcher.
 *
 * RUNS ON ALL THREE PLATFORMS, deliberately: no platform guard on the TU (a guarded dispatcher TU is how a
 * sibling plugin once shipped a compiled-out Windows leg and stayed green). Only the expectations differ per
 * host: the POSIX cases drive one real search over a fixture directory, the Windows cases the same over a
 * fixture under the build root, in the canonical label form (`/C:/...`).
 *
 * THE FIXTURE lives under the canonical build root (MESON_BUILD_ROOT) in a yuzu_test_ directory with the
 * test helpers' salt, never under $TMPDIR: /var is a link on macOS and /tmp is often tmpfs or overlay on
 * Linux, neither of which the search would plan as local disk. Whether the fixture's filesystem is one the
 * plan searches decides which of two assertions runs, and the case prints which. It never skips: a volume
 * the plan refuses is asserted to be reported, with its reason, and to yield no match row. The refused
 * branch is only taken on a filesystem the OS itself (statfs, independent of the rows under test) says the
 * plan would refuse: a fixture on ext4, xfs, btrfs or an allow-listed macOS type that was not searched fails
 * with the volume rows shown, so a green run on such a host has always made the positive control.
 *
 * Run it with MESON_BUILD_ROOT set (`meson test` always does); without it the plugin is not found and the
 * cases warn and return, which is a false green outside `meson test`.
 *
 * MUTATION NOTES (each case FAILS if the named production rule is removed):
 *  - descriptors: adding a second action, changing a declared leg (the Windows leg is constrained, rung 1),
 *    or loading the wrong plugin fails the descriptor case.
 *  - invalid rows: a parameter error that reaches the filesystem, or that is not a typed `invalid` trailer
 *    with the status 1, fails the refusal case; a forged cursor that is not refused before the mount table
 *    is read fails it too (its fixture root does not exist).
 *  - real slice: a match without its extents row, an extents row whose key is not the match's identity, a
 *    link or FIFO reported as a match, a verdict that is not complete, a trailer without the semantics id,
 *    or a typed status other than OK/FULL fails the slice case.
 *  - name rule: comparing bytes on macOS, or folding on Linux, fails the name case; on Linux the byte-exact
 *    spelling of the pattern is planted beside the decomposed name and must be the only match.
 *  - root: a root that is a link walked instead of refused fails the root case.
 *  - heartbeat: an init that leaves the KV keys in place, or that does not zero the in-memory totals, fails
 *    the heartbeat case (a seeded key survives init, or the count after one slice is not 1).
 *  - pin: an init that does not pin the module fails the pin case on a loader that unloads at the last
 *    dlclose (glibc) when the case runs before any other init in the process. macOS's dyld keeps this
 *    plugin's image resident whether or not it is pinned (checked with a bare dlopen/dlclose pair), so on
 *    that host the case cannot fail; the Linux run is the one that discriminates.
 *  - shutdown: a shutdown that does not set the stop flag, an init that does not clear it, or a shell that
 *    does not hand the flag to the driver fails the shutdown case (the next search is not cancelled, or the
 *    one after a re-init still is).
 */
#include <catch2/catch_test_macros.hpp>

#include <yuzu/agent/kv_store.hpp>
#include <yuzu/agent/plugin_loader.hpp>
#include <yuzu/plugin.h>
#include <yuzu/plugin.hpp>

#include "file_search_rows.hpp"
#include "file_search_test_support.hpp"
#include "file_search_win_rules.hpp"
#include "local_dispatcher.hpp"
#include "test_helpers.hpp"
#include "win_junction_test_support.hpp"

#include <file_search_names.hpp>
#include <network_fstype.hpp>

#include <algorithm>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#else
#include <dlfcn.h>
#include <sys/stat.h>
#include <unistd.h>
#if defined(__APPLE__)
#include <sys/mount.h>
#include <sys/param.h>
#else
#include <linux/magic.h>
#include <sys/vfs.h>
#endif
#endif

namespace fs = std::filesystem;
namespace fsr = yuzu::shared::file_search;
using namespace yuzu::file_search_test;

namespace {

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

/// Under `meson test` (MESON_BUILD_ROOT is always set) a missing plugin means the build is genuinely broken
/// and must NOT report "All tests passed".
#if defined(_MSC_VER)
#pragma warning(push)
#pragma warning(disable : 4996)
#endif
void require_plugin_or_skip() {
    if (std::getenv("MESON_BUILD_ROOT") != nullptr) {
        FAIL("file_search plugin library not found under meson test -- the plugin did not build, or "
             "link_depends is not forcing it to build before this test runs");
    }
    WARN("file_search plugin library not found -- skipping the LocalDispatcher round-trip");
}
#if defined(_MSC_VER)
#pragma warning(pop)
#endif

#if defined(_WIN32)
constexpr const char* kPluginExt = ".dll";
#elif defined(__APPLE__)
constexpr const char* kPluginExt = ".dylib";
#else
constexpr const char* kPluginExt = ".so";
#endif

fs::path find_plugin() {
    const std::string lib_name = std::string{"file_search"} + kPluginExt;
    std::vector<fs::path> candidates;
#if defined(_MSC_VER)
#pragma warning(push)
#pragma warning(disable : 4996)
#endif
    auto* build_root = std::getenv("MESON_BUILD_ROOT");
#if defined(_MSC_VER)
#pragma warning(pop)
#endif
    if (build_root)
        candidates.emplace_back(fs::path{build_root} / "agents" / "plugins" / "file_search" / lib_name);
    candidates.emplace_back(fs::path{"agents"} / "plugins" / "file_search" / lib_name);
    candidates.emplace_back(fs::path{".."} / "agents" / "plugins" / "file_search" / lib_name);
    for (const char* b : {"build-macos", "build-linux", "build-windows"})
        candidates.emplace_back(fs::path{b} / "agents" / "plugins" / "file_search" / lib_name);
    for (const auto& c : candidates)
        if (std::error_code ec; fs::exists(c, ec))
            return c;
    return {};
}

struct LoadedPlugin {
    yuzu::agent::PluginHandle handle;
    const YuzuPluginDescriptor* descriptor{nullptr};
    explicit operator bool() const { return descriptor != nullptr; }
};

std::optional<LoadedPlugin> load_plugin() {
    auto path = find_plugin();
    if (path.empty())
        return std::nullopt;
    auto loaded = yuzu::agent::PluginHandle::load(path);
    if (!loaded)
        return std::nullopt;
    const auto* d = loaded->descriptor();
    if (!d)
        return std::nullopt;
    return LoadedPlugin{std::move(*loaded), d};
}

/// One search call's parameters, owned so the YuzuParam pointers stay valid for the call.
struct Call {
    std::string root, pattern, kinds, cursor;
    [[nodiscard]] yuzu::agent::LocalDispatcher::Result run(const YuzuPluginDescriptor* d) const {
        std::vector<YuzuParam> params;
        params.push_back({"root", root.c_str()});
        params.push_back({"pattern", pattern.c_str()});
        if (!kinds.empty())
            params.push_back({"kinds", kinds.c_str()});
        if (!cursor.empty())
            params.push_back({"cursor", cursor.c_str()});
        yuzu::agent::LocalDispatcher dispatcher;
        return dispatcher.run(d, "search", params);
    }
};

void write_file(const fs::path& p, const std::string& content) {
    fs::create_directories(p.parent_path());
    std::ofstream(p, std::ios::binary) << content;
}

/// Every slice of one search, following the cursor until a slice names none (or `max_slices` ran).
struct Search {
    std::vector<yuzu::agent::LocalDispatcher::Result> slices;
    std::vector<std::string> rows; // every row of every slice, in order
    [[nodiscard]] const yuzu::agent::LocalDispatcher::Result& last() const { return slices.back(); }
};

Search search_all(const YuzuPluginDescriptor* d, Call call, std::size_t max_slices = 8) {
    Search s;
    while (s.slices.size() < max_slices) {
        auto r = call.run(d);
        std::string cursor;
        for (auto& row : captured_rows(r.captured)) {
            if (starts(row, "cursor|"))
                cursor = row.substr(7);
            s.rows.push_back(std::move(row));
        }
        s.slices.push_back(std::move(r));
        if (cursor.empty())
            break;
        call.cursor = cursor;
    }
    return s;
}

/// A unit of the plan was searched: some volume row reads complete or partial (a refused mount reads
/// not_searched and a nested firmlink row reads partial only from "/", which no fixture root is).
bool fixture_was_searched(const Search& s) {
    for (const auto& row : s.rows)
        if (starts(row, "volume|")) {
            const auto f = split(row);
            if (f.size() > 3 && (f[3] == "complete" || f[3] == "partial"))
                return true;
        }
    return false;
}

std::vector<std::string> found_paths(const Search& s) {
    std::vector<std::string> out;
    for (const auto& row : s.rows)
        if (starts(row, "match|")) {
            const auto path = fsr::decode_name(split(row)[1]);
            REQUIRE(path.has_value());
            out.push_back(*path);
        }
    std::ranges::sort(out);
    return out;
}

#if !defined(_WIN32)

/// What the OS itself says about the fixture root's filesystem, independent of the rows under
/// test: true when it is a type the plan's allow-list admits. That allow-list is
/// `is_searchable_local_fstype` in agents/shared/network_fstype.hpp. macOS calls it over the statfs
/// type name. Linux statfs returns no type name, so the Linux branch spells ext4, xfs and btrfs by
/// magic number: a hand-kept subset of that allow-list, which must stay inside it (0xEF53 covers
/// ext2, ext3 and ext4). No runner-specific flag is needed or trusted: a host whose workspace is on
/// another filesystem keeps the refused branch below, and a host whose workspace is on one of
/// these must have searched it.
bool filesystem_is_searchable(const fs::path& root) {
    struct statfs sf {};
    if (::statfs(root.c_str(), &sf) != 0)
        return false;
#if defined(__APPLE__)
    return yuzu::shared::is_searchable_local_fstype(sf.f_fstypename);
#else
    const auto magic = static_cast<unsigned long>(sf.f_type);
    return magic == static_cast<unsigned long>(EXT4_SUPER_MAGIC) || magic == static_cast<unsigned long>(XFS_SUPER_MAGIC) ||
           magic == static_cast<unsigned long>(BTRFS_SUPER_MAGIC);
#endif
}

/// The positive control made mandatory where the host can state it: a fixture on a searchable filesystem
/// that the plan still did not search (refused for a path reason, say) is a host to look at, so it FAILS
/// with the volume rows shown. Otherwise the refused branch of the caller stays.
void require_searched_when_searchable(const fs::path& root, const Search& s, bool searched) {
    if (searched || !filesystem_is_searchable(root))
        return;
    std::string volumes;
    for (const auto& row : s.rows)
        if (starts(row, "volume|"))
            volumes += "\n  " + row;
    FAIL("the fixture's filesystem is one the plan searches, yet no volume was searched; volume rows:" << volumes);
}

#if defined(__APPLE__)
constexpr const char* kSemantics = "macos_nfc_casefold_v1";
constexpr yuzu::file_search::Os kOs = yuzu::file_search::Os::macos;
#else
constexpr const char* kSemantics = "bytes";
constexpr yuzu::file_search::Os kOs = yuzu::file_search::Os::linux_os;
#endif

#else // _WIN32

constexpr const char* kSemantics = "windows_upcase_v1";
constexpr yuzu::file_search::Os kOs = yuzu::file_search::Os::windows;

/// What the OS itself says about the fixture's volume, independent of the rows under test: a fixed drive whose
/// filesystem the plan's allow-list admits must have been searched (the positive control, made mandatory where
/// the host can state it). Anything else keeps the refused branch.
bool volume_is_searchable(const fs::path& root) {
    wchar_t mount[MAX_PATH + 1] = {};
    if (!GetVolumePathNameW(root.c_str(), mount, MAX_PATH) || GetDriveTypeW(mount) != DRIVE_FIXED)
        return false;
    wchar_t name[MAX_PATH + 1] = {};
    if (!GetVolumeInformationW(mount, nullptr, 0, nullptr, nullptr, nullptr, name, MAX_PATH))
        return false;
    for (const wchar_t* ok : {L"NTFS", L"ReFS", L"FAT", L"FAT32", L"exFAT"})
        if (std::wstring_view(name) == ok)
            return true;
    return false;
}

void require_searched_when_searchable(const fs::path& root, const Search& s, bool searched) {
    if (searched || !volume_is_searchable(root))
        return;
    std::string volumes;
    for (const auto& row : s.rows)
        if (starts(row, "volume|"))
            volumes += "\n  " + row;
    FAIL("the fixture's volume is one the plan searches, yet no volume was searched; volume rows:" << volumes);
}

/// The canonical label of a Windows path, as the rows spell it.
std::string label_of(const fs::path& p) {
    const auto label = yuzu::file_search::win_rules::normalise_windows_root(p.string());
    REQUIRE(label.has_value());
    return *label;
}

#endif // _WIN32

} // namespace

TEST_CASE("file_search plugin: exactly one action, `search`, with the declared legs",
          "[file_search][file_search_dispatcher][descriptors]") {
    auto plugin = load_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }
    CHECK(std::string_view{plugin->descriptor->name} == "file_search");
    CHECK(std::string_view{plugin->descriptor->version} == "1.0.0");

    std::vector<std::string> actions;
    for (const char* const* a = plugin->descriptor->actions; a && *a; ++a)
        actions.emplace_back(*a);
    REQUIRE(actions.size() == 1);
    CHECK(actions[0] == "search");

    REQUIRE(plugin->descriptor->action_descriptors != nullptr);
    REQUIRE(plugin->descriptor->action_descriptor_count == 1);
    const auto& d = plugin->descriptor->action_descriptors[0];
    CHECK(std::string_view{d.action} == "search");
    CHECK(d.linux_leg.support == YUZU_SUPPORT_CONSTRAINED);
    CHECK(d.linux_leg.rung == 1);
    CHECK(d.macos_leg.support == YUZU_SUPPORT_CONSTRAINED);
    CHECK(d.macos_leg.rung == 1);
    CHECK(d.windows_leg.support == YUZU_SUPPORT_CONSTRAINED);
    CHECK(d.windows_leg.rung == 1);
}

TEST_CASE("file_search plugin: an unknown action is refused with one non-status line",
          "[file_search][file_search_dispatcher]") {
    auto plugin = load_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }
    yuzu::agent::LocalDispatcher dispatcher;
    const auto result = dispatcher.run(plugin->descriptor, "no_such_action");
    CHECK(result.rc != 0);
    const auto rows = captured_rows(result.captured);
    REQUIRE(rows.size() == 1);
    CHECK(rows[0] == "unknown action: no_such_action");

    // The request-supplied name goes through safe_output_field: a pipe cannot open a second field.
    const auto hostile = dispatcher.run(plugin->descriptor, "no|such\\");
    CHECK(hostile.rc != 0);
    const auto hrows = captured_rows(hostile.captured);
    REQUIRE(hrows.size() == 1);
    CHECK(hrows[0] == "unknown action: no\\|such/");
}

#if defined(_WIN32)

TEST_CASE("file_search plugin (Windows): a missing or malformed root answers one typed invalid row and the status 1",
          "[file_search][file_search_dispatcher]") {
    auto plugin = load_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }
    const auto check = [&](const Call& call, const std::string& token, const std::string& semantics_and_query) {
        const auto r = call.run(plugin->descriptor);
        INFO(token);
        const auto rows = captured_rows(r.captured);
        REQUIRE(rows.size() == 1);
        CHECK(starts(rows[0], "search|invalid|" + token + "|" + semantics_and_query));
        CHECK(rows[0].find("|links_skipped=0") != std::string::npos);
        CHECK(r.rc == 1);
        CHECK(r.result_status == YUZU_RESULT_STATUS_UNAVAILABLE);
        CHECK(r.result_provenance == "file_search:" + token);
    };
    // Refused before any pattern is compiled: no semantics and no query to name.
    check({"", "yuzu-fs-control-*.bin", "", ""}, "missing_root", "-|seq=0|q=-|");
    check({"relative\\dir", "yuzu-fs-control-*.bin", "", ""}, "root_not_absolute", "-|seq=0|q=-|");
    check({"C:", "yuzu-fs-control-*.bin", "", ""}, "root_not_absolute", "-|seq=0|q=-|");
    check({"C:\\does\\..\\x", "yuzu-fs-control-*.bin", "", ""}, "root_bad_component", "-|seq=0|q=-|");
    check({"\\\\.\\C:\\", "yuzu-fs-control-*.bin", "", ""}, "root_device_path", "-|seq=0|q=-|");
    check({"C:\\", "", "", ""}, "missing_pattern", "-|seq=0|q=-|");
    check({"C:\\", "ab", "", ""}, "pattern_too_few_literals", "-|seq=0|q=-|");
    check({"C:\\", "yuzu-fs-control-*.bin", "everything", ""}, "bad_kinds", "-|seq=0|q=-|");
    // A forged cursor is refused by the driver, before the mount table is read: the root need not exist.
    check({"C:\\does\\not\\exist", "yuzu-fs-control-*.bin", "", "fsv1.0.0000000000000000.0000000000000000.forged"},
          "bad_cursor", std::string{kSemantics} + "|seq=0|q=");
}

TEST_CASE("file_search plugin (Windows): a UNC root answers root_unc and nothing is opened",
          "[file_search][file_search_dispatcher]") {
    auto plugin = load_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }
    for (const char* root : {"\\\\server\\share", "//server/share", "\\\\?\\UNC\\server\\share"}) {
        const auto r = Call{root, "yuzu-fs-control-*.bin", "", ""}.run(plugin->descriptor);
        const auto rows = captured_rows(r.captured);
        INFO(root);
        REQUIRE(rows.size() == 1); // the trailer alone: no volume, no coverage, no match
        CHECK(starts(rows[0], "search|invalid|root_unc|"));
        CHECK(r.rc == 1);
    }
}

TEST_CASE("file_search plugin (Windows): one real search over a fixture finds the controls once, with their extents",
          "[file_search][file_search_dispatcher][file_search_real]") {
    auto plugin = load_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }
    yuzu::agent::StandalonePluginContext pctx("file_search", {});
    REQUIRE(plugin->descriptor->init(pctx.get()) == 0);
    yuzu::test::ScopeExit shutdown_on_exit{[&] { plugin->descriptor->shutdown(pctx.get()); }};

    Fixture fx{"yuzu_test_fs_disp_"};
    const std::string salt = fx.root.filename().string();
    const std::string c1 = "yuzu-fs-control-" + salt + "-1.bin";
    const std::string c2 = "yuzu-fs-control-" + salt + "-2.bin";
    fs::path deep = fx.root;
    for (int i = 1; i <= 11; ++i)
        deep /= "d" + std::to_string(i);
    write_file(fx.root / c1, "control");                         // depth 1, seven bytes
    write_file(deep / c2, "");                                   // depth 12, empty
    write_file(fx.root / "d1" / "noise.txt", "not a match");
    fs::create_directories(fx.root / ("yuzu-fs-control-" + salt + "-dir.bin")); // a directory: not a file match
    fs::create_directories(fx.root / "junction-target");
    REQUIRE(yuzu::test::create_junction(fx.root / ("yuzu-fs-control-" + salt + "-junc.bin"), fx.root / "junction-target"));
    yuzu::test::JunctionCleanup junction_cleanup{fx.root / ("yuzu-fs-control-" + salt + "-junc.bin")}; // removes the link, never the target

    const Search s = search_all(plugin->descriptor, {fx.root.string(), "yuzu-fs-control-" + salt + "-*.bin", "", ""});
    REQUIRE_FALSE(s.slices.empty());
    const auto& last = s.last();
    CHECK(last.rc == 0);

    const bool searched = fixture_was_searched(s);
    require_searched_when_searchable(fx.root, s, searched);
    WARN(std::string{"file_search real slice: branch="} + (searched ? "allowed (the plan searched the fixture's volume)"
                                                                    : "refused (the plan reported the fixture's volume and did not search it)"));
    const auto trailer = captured_rows(last.captured).back();
    REQUIRE(starts(trailer, "search|"));
    const auto t = split(trailer);
    REQUIRE(t.size() == 7);
    CHECK(t[1] == "ok");
    CHECK(t[3] == kSemantics);

    if (searched) {
        const std::string label = label_of(fx.root);
        std::string deep_label = label;
        for (int i = 1; i <= 11; ++i)
            deep_label += "/d" + std::to_string(i);
        std::vector<std::string> expected{label + "/" + c1, deep_label + "/" + c2};
        std::ranges::sort(expected);
        CHECK(found_paths(s) == expected);
        for (const auto& row : s.rows) {
            if (!starts(row, "match|"))
                continue;
            const auto f = split(row);
            REQUIRE(f.size() == 7);
            CHECK(f[2] == "file");
            const std::string path = *fsr::decode_name(f[1]);
            if (yuzu::file_search::is_user_profile_path(path, kOs))
                CHECK(f[6] == "user"); // a fixture inside a profile; another account's relocated profile may also tag user
            else
                CHECK((f[6] == "system" || f[6] == "user"));
            if (path == label + "/" + c1) {
                CHECK(f[4] == "7"); // size, from the opened handle
            } else {
                CHECK(f[4] == "0");
            }
            CHECK(f[5] != "-"); // a modification time
            // A file's extents row follows its match row. Counting by the identity key would see
            // both controls' rows under each where the id is unknown (`device:0`: ReFS, FAT).
            const auto next = static_cast<std::size_t>(&row - s.rows.data()) + 1;
            REQUIRE(next < s.rows.size());
            REQUIRE(starts(s.rows[next], "extents|" + f[3] + "|"));
            const auto e = split(s.rows[next]);
            REQUIRE(e.size() == 5);
            const std::string state = e[2].substr(0, e[2].find(':'));
            CHECK((state == "ok" || state == "unsupported" || state == "compressed" ||
                   state == "failed"));
        }
        const auto count_kind = [&](const std::string& kind) {
            return std::ranges::count_if(s.rows,
                                         [&](const std::string& r) { return starts(r, kind); });
        };
        CHECK(count_kind("extents|") == count_kind("match|"));
        CHECK(std::ranges::none_of(s.rows, [](const std::string& r) { return starts(r, "gap|"); }));
        CHECK(std::ranges::any_of(s.rows, [](const std::string& r) { return starts(r, "coverage|complete|"); }));
        CHECK(t[2] == "none");
        CHECK(t[6] == "links_skipped=1"); // the planted junction: counted, never followed
        CHECK(last.result_status == YUZU_RESULT_STATUS_OK);
        CHECK(last.result_completeness == YUZU_RESULT_COMPLETENESS_FULL);

        // The same fixture with kinds=both: the directory joins the two controls as a third match, with no size, no
        // time and no extents row (a directory is never opened); the junction is still counted and never matched.
        const Search both = search_all(plugin->descriptor, {fx.root.string(), "yuzu-fs-control-" + salt + "-*.bin", "both", ""});
        REQUIRE_FALSE(both.slices.empty());
        const std::string dir_path = label + "/yuzu-fs-control-" + salt + "-dir.bin";
        std::vector<std::string> expected_both = expected;
        expected_both.push_back(dir_path);
        std::ranges::sort(expected_both);
        CHECK(found_paths(both) == expected_both);
        std::size_t dir_rows = 0;
        for (const auto& row : both.rows) {
            if (!starts(row, "match|"))
                continue;
            const auto f = split(row);
            REQUIRE(f.size() == 7);
            if (*fsr::decode_name(f[1]) != dir_path)
                continue;
            ++dir_rows;
            CHECK(f[2] == "directory");
            CHECK(f[4] == "-");
            CHECK(f[5] == "-");
        }
        CHECK(dir_rows == 1);
        CHECK(std::ranges::count_if(both.rows, [](const std::string& r) { return starts(r, "extents|"); }) == 2); // the controls only
        CHECK(std::ranges::none_of(both.rows, [](const std::string& r) { return starts(r, "gap|"); }));
        CHECK(std::ranges::any_of(both.rows, [](const std::string& r) { return starts(r, "coverage|complete|"); }));
        const auto both_trailer = split(captured_rows(both.last().captured).back());
        REQUIRE(both_trailer.size() == 7);
        CHECK(both_trailer[1] == "ok");
        CHECK(both_trailer[2] == "none");
        CHECK(both_trailer[6] == "links_skipped=1");
        CHECK(both.last().result_status == YUZU_RESULT_STATUS_OK);
        CHECK(both.last().result_completeness == YUZU_RESULT_COMPLETENESS_FULL);
    } else {
        CHECK(std::ranges::none_of(s.rows, [](const std::string& r) { return starts(r, "match|"); }));
        CHECK(std::ranges::any_of(s.rows, [](const std::string& r) { return starts(r, "volume|") && r.find("|not_searched|") != std::string::npos; }));
        CHECK(std::ranges::any_of(s.rows, [](const std::string& r) { return starts(r, "coverage|partial|"); }));
    }
}

TEST_CASE("file_search plugin (Windows): init pins the module, so it stays mapped after the handle that loaded it is released",
          "[file_search][file_search_dispatcher][file_search_pin]") {
    const fs::path path = find_plugin();
    if (path.empty()) {
        require_plugin_or_skip();
        return;
    }
    {
        auto plugin = load_plugin();
        REQUIRE(plugin.has_value());
        yuzu::agent::StandalonePluginContext pctx("file_search", {});
        REQUIRE(plugin->descriptor->init(pctx.get()) == 0);
        plugin->descriptor->shutdown(pctx.get());
    } // the PluginHandle is destroyed here: FreeLibrary, which unmaps an unpinned module
    // GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT: the probe itself adds no reference.
    HMODULE still_mapped = nullptr;
    CHECK(GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, path.filename().c_str(), &still_mapped) != 0);
    CHECK(still_mapped != nullptr);
}

// After the pin case on purpose: that case discriminates only when it runs before any other init.
TEST_CASE("file_search plugin (Windows): the heartbeat totals count from this process's start, not from the KV file's",
          "[file_search][file_search_dispatcher][file_search_heartbeat]") {
    auto plugin = load_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }
    yuzu::test::TempDir dir_guard{"yuzu_test_fs_hb_"};
    std::error_code ec;
    fs::create_directories(dir_guard.path, ec);
    auto kv = yuzu::agent::KvStore::open(dir_guard.path / "kv_store.db");
    REQUIRE(kv.has_value());
    REQUIRE(kv->set("file_search", "heartbeat.stalled", "4"));
    REQUIRE(kv->set("file_search", "heartbeat.slices", "9"));

    yuzu::agent::StandalonePluginContext pctx("file_search", {}, &*kv);
    REQUIRE(plugin->descriptor->init(pctx.get()) == 0);
    yuzu::test::ScopeExit shutdown_on_exit{[&] { plugin->descriptor->shutdown(pctx.get()); }};
    CHECK_FALSE(kv->get("file_search", "heartbeat.stalled").has_value());
    CHECK_FALSE(kv->get("file_search", "heartbeat.slices").has_value());

    Fixture fx{"yuzu_test_fs_disp_"};
    const std::string salt = fx.root.filename().string();
    write_file(fx.root / ("yuzu-fs-control-" + salt + "-1.bin"), "control");
    const auto r = Call{fx.root.string(), "yuzu-fs-control-" + salt + "-*.bin", "", ""}.run(plugin->descriptor);
    REQUIRE(r.rc == 0);
    const auto slices = kv->get("file_search", "heartbeat.slices");
    REQUIRE(slices.has_value());
    CHECK(*slices == "1");
    CHECK_FALSE(kv->get("file_search", "heartbeat.stalled").has_value());
}

#else

TEST_CASE("file_search plugin: a missing or malformed parameter answers one typed invalid row and the status 1",
          "[file_search][file_search_dispatcher]") {
    auto plugin = load_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }
    const auto check = [&](const Call& call, const std::string& token, const std::string& semantics_and_query) {
        const auto r = call.run(plugin->descriptor);
        INFO(token);
        const auto rows = captured_rows(r.captured);
        REQUIRE(rows.size() == 1);
        CHECK(starts(rows[0], "search|invalid|" + token + "|" + semantics_and_query));
        CHECK(rows[0].find("|links_skipped=0") != std::string::npos);
        CHECK(r.rc == 1);
        CHECK(r.result_status == YUZU_RESULT_STATUS_UNAVAILABLE);
        CHECK(r.result_provenance == "file_search:" + token);
    };
    // Refused before any pattern is compiled: no semantics and no query to name.
    check({"", "yuzu-fs-control-*.bin", "", ""}, "missing_root", "-|seq=0|q=-|");
    check({"relative/dir", "yuzu-fs-control-*.bin", "", ""}, "root_not_absolute", "-|seq=0|q=-|");
    check({"/does/not/matter/..", "yuzu-fs-control-*.bin", "", ""}, "root_bad_component", "-|seq=0|q=-|");
    check({"/", "", "", ""}, "missing_pattern", "-|seq=0|q=-|");
    check({"/", "ab", "", ""}, "pattern_too_few_literals", "-|seq=0|q=-|");
    check({"/", "yuzu-fs-control-*.bin", "everything", ""}, "bad_kinds", "-|seq=0|q=-|");
    // A forged cursor is refused by the driver, before the mount table is read: the root need not exist.
    check({"/does/not/exist", "yuzu-fs-control-*.bin", "", "fsv1.0.0000000000000000.0000000000000000.forged"},
          "bad_cursor", std::string{kSemantics} + "|seq=0|q=");
}

TEST_CASE("file_search plugin: one real search over a fixture finds the controls once, with their extents",
          "[file_search][file_search_dispatcher][file_search_real]") {
    auto plugin = load_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }
    yuzu::agent::StandalonePluginContext pctx("file_search", {});
    REQUIRE(plugin->descriptor->init(pctx.get()) == 0);
    yuzu::test::ScopeExit shutdown_on_exit{[&] { plugin->descriptor->shutdown(pctx.get()); }};

    Fixture fx{"yuzu_test_fs_disp_"};
    const std::string salt = fx.root.filename().string();
    const std::string c1 = "yuzu-fs-control-" + salt + "-1.bin";
    const std::string c2 = "yuzu-fs-control-" + salt + "-2.bin";
    write_file(fx.root / c1, "control");                         // depth 1, seven bytes
    write_file(fx.root / "sub" / "deep" / c2, "");               // depth 3, empty
    write_file(fx.root / "sub" / "noise.txt", "not a match");
    fs::create_directories(fx.root / ("yuzu-fs-control-" + salt + "-dir.bin")); // a directory: not a file match
    fs::create_symlink(fx.root / c1, fx.root / ("yuzu-fs-control-" + salt + "-link.bin")); // never followed
    REQUIRE(::mkfifo((fx.root / ("yuzu-fs-control-" + salt + "-fifo.bin")).c_str(), 0600) == 0); // never opened

    const Search s = search_all(plugin->descriptor, {fx.root.string(), "yuzu-fs-control-" + salt + "-*.bin", "", ""});
    REQUIRE_FALSE(s.slices.empty());
    const auto& last = s.last();
    CHECK(last.rc == 0);

    const bool searched = fixture_was_searched(s);
    require_searched_when_searchable(fx.root, s, searched);
    WARN(std::string{"file_search real slice: branch="} + (searched ? "allowed (the plan searched the fixture's filesystem)"
                                                                    : "refused (the plan reported the fixture's filesystem and did not search it)"));
    const auto trailer = captured_rows(last.captured).back();
    REQUIRE(starts(trailer, "search|"));
    const auto t = split(trailer);
    REQUIRE(t.size() == 7);
    CHECK(t[1] == "ok");
    CHECK(t[3] == kSemantics);

    if (searched) {
        // the allowed branch: the two controls once each, each with its extents row, and a complete verdict
        const fs::path p1 = fx.root / c1;
        const fs::path p2 = fx.root / "sub" / "deep" / c2;
        std::vector<std::string> expected{p1.string(), p2.string()};
        std::ranges::sort(expected);
        CHECK(found_paths(s) == expected);
        for (const auto& row : s.rows) {
            if (!starts(row, "match|"))
                continue;
            const auto f = split(row);
            REQUIRE(f.size() == 7);
            CHECK(f[2] == "file");
            const std::string path = *fsr::decode_name(f[1]);
            CHECK(f[6] == yuzu::file_search::to_token(yuzu::file_search::is_user_profile_path(path, kOs)
                                                          ? yuzu::file_search::Scope::user
                                                          : yuzu::file_search::Scope::system));
            if (path == p1.string()) {
                CHECK(f[4] == "7"); // size, from the opened descriptor
            } else {
                CHECK(f[4] == "0");
            }
            CHECK(f[5] != "-"); // a modification time
            // exactly one extents row carries this match's identity key, and it states a closed state
            std::size_t extents_rows = 0;
            for (const auto& other : s.rows)
                if (starts(other, "extents|" + f[3] + "|")) {
                    ++extents_rows;
                    const auto e = split(other);
                    REQUIRE(e.size() == 5);
                    CHECK((e[2] == "ok" || e[2] == "unsupported" || e[2] == "compressed" || e[2] == "failed"));
                    if (path == p2.string() && e[2] == "ok")
                        CHECK(e[3] == "0"); // an empty file has no extents
                }
            CHECK(extents_rows == 1);
        }
        CHECK(std::ranges::none_of(s.rows, [](const std::string& r) { return starts(r, "gap|"); }));
        CHECK(std::ranges::any_of(s.rows, [](const std::string& r) { return starts(r, "coverage|complete|"); }));
        CHECK(t[2] == "none");
        CHECK(t[6] == "links_skipped=1"); // the planted link: counted, never followed
        CHECK(last.result_status == YUZU_RESULT_STATUS_OK);
        CHECK(last.result_completeness == YUZU_RESULT_COMPLETENESS_FULL);
    } else {
        // the refused branch: the filesystem is reported with its reason and nothing is matched
        CHECK(std::ranges::none_of(s.rows, [](const std::string& r) { return starts(r, "match|"); }));
        CHECK(std::ranges::any_of(s.rows, [](const std::string& r) { return starts(r, "volume|") && r.find("|not_searched|") != std::string::npos; }));
        CHECK(std::ranges::any_of(s.rows, [](const std::string& r) { return starts(r, "coverage|partial|"); }));
    }
}

TEST_CASE("file_search plugin: the name rule of the OS decides whether a different spelling matches",
          "[file_search][file_search_dispatcher][file_search_real]") {
    auto plugin = load_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }
    yuzu::agent::StandalonePluginContext pctx("file_search", {});
    REQUIRE(plugin->descriptor->init(pctx.get()) == 0);

    yuzu::test::ScopeExit shutdown_on_exit{[&] { plugin->descriptor->shutdown(pctx.get()); }};
    Fixture fx{"yuzu_test_fs_disp_"};
    // The name on disk: lower case, decomposed (e then a combining acute). The pattern: upper case, composed.
    const std::string on_disk = "cafe\xCC\x81-yuzu-fs-name.bin";
    write_file(fx.root / on_disk, "x");
#if !defined(__APPLE__)
    // The positive control, planted beside the decomposed name: the byte-exact spelling of the pattern. Not on
    // macOS, where a case- and normalisation-insensitive volume holds both spellings as one file.
    const std::string exact = "CAF\xC3\x89-yuzu-fs-name.bin";
    write_file(fx.root / exact, "y");
#endif
    const Search s = search_all(plugin->descriptor, {fx.root.string(), "CAF\xC3\x89-yuzu-fs-name.*", "", ""});
    REQUIRE_FALSE(s.slices.empty());
    const bool searched = fixture_was_searched(s);
    require_searched_when_searchable(fx.root, s, searched);
    if (!searched) {
        WARN("file_search name rule: the fixture's filesystem is not searched here; the spelling check is not made");
    } else {
#if defined(__APPLE__)
        CHECK(found_paths(s) == std::vector<std::string>{(fx.root / on_disk).string()}); // NFC plus case folding
#else
        // byte for byte: another case and another normal form is another name, so the byte-exact spelling is
        // the only match, and an empty answer would mean the search found nothing at all
        CHECK(found_paths(s) == std::vector<std::string>{(fx.root / exact).string()});
#endif
    }
}

TEST_CASE("file_search plugin: a root that is a link is refused with its own token and nothing is walked",
          "[file_search][file_search_dispatcher][file_search_real]") {
    auto plugin = load_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }
    yuzu::agent::StandalonePluginContext pctx("file_search", {});
    REQUIRE(plugin->descriptor->init(pctx.get()) == 0);

    yuzu::test::ScopeExit shutdown_on_exit{[&] { plugin->descriptor->shutdown(pctx.get()); }};
    Fixture fx{"yuzu_test_fs_disp_"};
    write_file(fx.root / "real" / "yuzu-fs-control-link-1.bin", "x");
    fs::create_directory_symlink(fx.root / "real", fx.root / "lnk");

    const Search plain = search_all(plugin->descriptor, {(fx.root / "real").string(), "yuzu-fs-control-link-*.bin", "", ""});
    const bool plain_searched = fixture_was_searched(plain);
    require_searched_when_searchable(fx.root, plain, plain_searched);
    if (!plain_searched) {
        WARN("file_search root check: the fixture's filesystem is not searched here; the link check is not reached");
    } else {
        const auto r = Call{(fx.root / "lnk").string(), "yuzu-fs-control-link-*.bin", "", ""}.run(plugin->descriptor);
        const auto rows = captured_rows(r.captured);
        REQUIRE(rows.size() == 1);
        CHECK(starts(rows[0], "search|invalid|root_is_link|"));
        CHECK(r.rc == 1);
        CHECK(r.result_status == YUZU_RESULT_STATUS_UNAVAILABLE);

        const auto missing = Call{(fx.root / "nothere").string(), "yuzu-fs-control-link-*.bin", "", ""}.run(plugin->descriptor);
        const auto mrows = captured_rows(missing.captured);
        REQUIRE(mrows.size() == 1);
        CHECK(starts(mrows[0], "search|invalid|root_not_found|"));
    }
}

TEST_CASE("file_search plugin: init pins the module, so it stays mapped after the handle that loaded it is released",
          "[file_search][file_search_dispatcher][file_search_pin]") {
    const fs::path path = find_plugin();
    if (path.empty()) {
        require_plugin_or_skip();
        return;
    }
    {
        auto plugin = load_plugin();
        REQUIRE(plugin.has_value());
        yuzu::agent::StandalonePluginContext pctx("file_search", {});
        REQUIRE(plugin->descriptor->init(pctx.get()) == 0);
        plugin->descriptor->shutdown(pctx.get());
    } // the PluginHandle is destroyed here: dlclose, which unmaps an unpinned module on a loader that unloads
    void* still_mapped = ::dlopen(path.c_str(), RTLD_NOW | RTLD_NOLOAD);
    CHECK(still_mapped != nullptr);
    if (still_mapped != nullptr)
        ::dlclose(still_mapped);
}

// After the pin case on purpose: that case discriminates only when it runs before any other init.
TEST_CASE("file_search plugin: the heartbeat totals count from this process's start, not from the KV file's",
          "[file_search][file_search_dispatcher][file_search_heartbeat]") {
    auto plugin = load_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }
    yuzu::test::TempDir dir_guard{"yuzu_test_fs_hb_"};
    std::error_code ec;
    fs::create_directories(dir_guard.path, ec);
    auto kv = yuzu::agent::KvStore::open(dir_guard.path / "kv_store.db");
    REQUIRE(kv.has_value());
    // what the last agent process left in the file: a counter this process never counts, and one it will
    REQUIRE(kv->set("file_search", "heartbeat.stalled", "4"));
    REQUIRE(kv->set("file_search", "heartbeat.slices", "9"));

    yuzu::agent::StandalonePluginContext pctx("file_search", {}, &*kv);
    REQUIRE(plugin->descriptor->init(pctx.get()) == 0);
    yuzu::test::ScopeExit shutdown_on_exit{[&] { plugin->descriptor->shutdown(pctx.get()); }};
    // a tag is absent until this process counts something: neither survives init
    CHECK_FALSE(kv->get("file_search", "heartbeat.stalled").has_value());
    CHECK_FALSE(kv->get("file_search", "heartbeat.slices").has_value());

    Fixture fx{"yuzu_test_fs_disp_"};
    const std::string salt = fx.root.filename().string();
    write_file(fx.root / ("yuzu-fs-control-" + salt + "-1.bin"), "control");
    const auto r = Call{fx.root.string(), "yuzu-fs-control-" + salt + "-*.bin", "", ""}.run(plugin->descriptor);
    REQUIRE(r.rc == 0);
    // one real slice: its own count, digits, from zero (the 9 above is gone)
    const auto slices = kv->get("file_search", "heartbeat.slices");
    REQUIRE(slices.has_value());
    CHECK(std::ranges::all_of(*slices, [](unsigned char c) { return c >= '0' && c <= '9'; }));
    CHECK(*slices == "1");
    CHECK_FALSE(kv->get("file_search", "heartbeat.stalled").has_value()); // a counter that never fired stays absent
}

#endif // !_WIN32

// Runs after the pin and heartbeat cases on purpose: it inits the plugin twice. Wiring only: the driver's
// handling of the flag is pinned in test_file_search_driver.cpp ("a stop request ends the slice cancelled").
TEST_CASE("file_search plugin: shutdown ends the next search cancelled and the next init clears it",
          "[file_search][file_search_dispatcher][file_search_shutdown]") {
    auto plugin = load_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }
    Fixture fx{"yuzu_test_fs_disp_"};
    const std::string salt = fx.root.filename().string();
    write_file(fx.root / ("yuzu-fs-control-" + salt + "-1.bin"), "control");
    const Call call{fx.root.string(), "yuzu-fs-control-" + salt + "-*.bin", "", ""};

    yuzu::agent::StandalonePluginContext pctx("file_search", {});
    REQUIRE(plugin->descriptor->init(pctx.get()) == 0);
    plugin->descriptor->shutdown(pctx.get()); // sets the stop flag
    const auto stopped = call.run(plugin->descriptor);
    REQUIRE(plugin->descriptor->init(pctx.get()) == 0); // clears it
    yuzu::test::ScopeExit shutdown_on_exit{[&] { plugin->descriptor->shutdown(pctx.get()); }};
    const Search running = search_all(plugin->descriptor, call);

    // The cancelled end is reached only by a walk, so a fixture the plan refuses cannot show it.
    const bool searched = fixture_was_searched(running);
    require_searched_when_searchable(fx.root, running, searched);
    if (!searched) {
        WARN("file_search shutdown: the fixture's filesystem is not searched here; the cancelled end is not checked");
        return;
    }
    const auto stopped_rows = captured_rows(stopped.captured);
    REQUIRE_FALSE(stopped_rows.empty());
    CHECK(starts(stopped_rows.back(), "search|failed|cancelled|"));
    CHECK(std::ranges::none_of(stopped_rows, [](const std::string& r) { return starts(r, "cursor|"); }));

    REQUIRE_FALSE(running.slices.empty());
    const auto trailer = split(captured_rows(running.last().captured).back());
    REQUIRE(trailer.size() == 7);
    CHECK(trailer[1] == "ok");
    CHECK(std::ranges::any_of(running.rows, [](const std::string& r) { return starts(r, "match|"); }));
}
