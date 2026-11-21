/**
 * test_file_search_local_dispatcher.cpp -- loads the ACTUAL built file_search plugin (file_search.dylib /
 * .so / .dll) via PluginHandle::load and drives it through yuzu::agent::LocalDispatcher.
 *
 * RUNS ON ALL THREE PLATFORMS, deliberately: no platform guard on the TU (a guarded dispatcher TU is how a
 * sibling plugin once shipped a compiled-out Windows leg and stayed green). Only the expectations differ per
 * host: Windows answers `planned`, and the POSIX cases drive one real search over a fixture directory.
 *
 * THE FIXTURE lives under the canonical build root (MESON_BUILD_ROOT) in a yuzu_test_ directory with the
 * test helpers' salt, never under $TMPDIR: /var is a link on macOS and /tmp is often tmpfs or overlay on
 * Linux, neither of which the search would plan as local disk. Whether the fixture's filesystem is one the
 * plan searches decides which of two assertions runs, and the case prints which. It never skips: a volume
 * the plan refuses is asserted to be reported, with its reason, and to yield no match row.
 *
 * Run it with MESON_BUILD_ROOT set (`meson test` always does); without it the plugin is not found and the
 * cases warn and return, which is a false green outside `meson test`.
 *
 * MUTATION NOTES (each case FAILS if the named production rule is removed):
 *  - descriptors: adding a second action, changing a declared leg, or loading the wrong plugin fails the
 *    descriptor case; removing the planned reporter on Windows fails the planned case.
 *  - invalid rows: a parameter error that reaches the filesystem, or that is not a typed `invalid` trailer
 *    with the status 1, fails the refusal case; a forged cursor that is not refused before the mount table
 *    is read fails it too (its fixture root does not exist).
 *  - real slice: a match without its extents row, an extents row whose key is not the match's identity, a
 *    link or FIFO reported as a match, a verdict that is not complete, a trailer without the semantics id,
 *    or a typed status other than OK/FULL fails the slice case.
 *  - name rule: comparing bytes on macOS, or folding on Linux, fails the name case.
 *  - root: a root that is a link walked instead of refused fails the root case.
 *  - pin: an init that does not pin the module fails the pin case on a loader that unloads at the last
 *    dlclose (glibc) when the case runs before any other init in the process. macOS's dyld keeps this
 *    plugin's image resident whether or not it is pinned (checked with a bare dlopen/dlclose pair), so on
 *    that host the case cannot fail; the Linux run is the one that discriminates.
 */
#include <catch2/catch_test_macros.hpp>

#include <yuzu/agent/plugin_loader.hpp>
#include <yuzu/plugin.h>
#include <yuzu/plugin.hpp>

#include "file_search_rows.hpp"
#include "local_dispatcher.hpp"
#include "test_helpers.hpp"

#include <file_search_names.hpp>

#include <algorithm>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

#if !defined(_WIN32)
#include <dlfcn.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

namespace fs = std::filesystem;
namespace fsr = yuzu::shared::file_search;

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

#if !defined(_WIN32)

std::vector<std::string> fields(const std::string& row) {
    std::vector<std::string> out;
    std::size_t at = 0;
    for (;;) {
        const auto bar = row.find('|', at);
        out.push_back(row.substr(at, bar == std::string::npos ? std::string::npos : bar - at));
        if (bar == std::string::npos)
            return out;
        at = bar + 1;
    }
}

bool starts(const std::string& s, const std::string& p) { return s.rfind(p, 0) == 0; }

/// A directory under the canonical build root, named with the yuzu_test_ prefix and the helpers' salt.
struct Fixture {
    fs::path root;
    Fixture() {
        fs::path base;
        if (const char* b = std::getenv("MESON_BUILD_ROOT"); b != nullptr && *b != '\0')
            base = fs::canonical(fs::path{b});
        else
            base = fs::canonical(fs::temp_directory_path());
        root = base / yuzu::test::unique_temp_path("yuzu_test_fs_disp_").filename();
        fs::create_directories(root);
        root = fs::canonical(root);
    }
    ~Fixture() {
        std::error_code ec;
        fs::remove_all(root, ec);
    }
    Fixture(const Fixture&) = delete;
    Fixture& operator=(const Fixture&) = delete;
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
            const auto f = fields(row);
            if (f.size() > 3 && (f[3] == "complete" || f[3] == "partial"))
                return true;
        }
    return false;
}

std::vector<std::string> found_paths(const Search& s) {
    std::vector<std::string> out;
    for (const auto& row : s.rows)
        if (starts(row, "match|")) {
            const auto path = fsr::decode_name(fields(row)[1]);
            REQUIRE(path.has_value());
            out.push_back(*path);
        }
    std::ranges::sort(out);
    return out;
}

#if defined(__APPLE__)
constexpr const char* kSemantics = "macos_nfc_casefold_v1";
constexpr yuzu::file_search::Os kOs = yuzu::file_search::Os::macos;
#else
constexpr const char* kSemantics = "bytes";
constexpr yuzu::file_search::Os kOs = yuzu::file_search::Os::linux_os;
#endif

#endif // !_WIN32

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
    CHECK(d.windows_leg.support == YUZU_SUPPORT_PLANNED);
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
TEST_CASE("file_search plugin: the Windows leg answers the planned row at once", "[file_search][file_search_dispatcher]") {
    auto plugin = load_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }
    yuzu::agent::LocalDispatcher dispatcher;
    const auto result = dispatcher.run(plugin->descriptor, "search");
    CHECK(result.rc == 0); // a planned leg is not a failed command
    const auto rows = captured_rows(result.captured);
    REQUIRE(rows.size() == 1);
    CHECK(rows[0] == "status|search|unsupported|windows:planned");
    CHECK(result.result_status == YUZU_RESULT_STATUS_UNAVAILABLE);
    CHECK(result.result_completeness == YUZU_RESULT_COMPLETENESS_UNKNOWN);
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

    Fixture fx;
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
    WARN(std::string{"file_search real slice: branch="} + (searched ? "allowed (the plan searched the fixture's filesystem)"
                                                                    : "refused (the plan reported the fixture's filesystem and did not search it)"));
    const auto trailer = captured_rows(last.captured).back();
    REQUIRE(starts(trailer, "search|"));
    const auto t = fields(trailer);
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
            const auto f = fields(row);
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
                    const auto e = fields(other);
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
    plugin->descriptor->shutdown(pctx.get());
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

    Fixture fx;
    // The name on disk: lower case, decomposed (e then a combining acute). The pattern: upper case, composed.
    const std::string on_disk = "cafe\xCC\x81-yuzu-fs-name.bin";
    write_file(fx.root / on_disk, "x");
    const Search s = search_all(plugin->descriptor, {fx.root.string(), "CAF\xC3\x89-yuzu-fs-name.*", "", ""});
    REQUIRE_FALSE(s.slices.empty());
    if (!fixture_was_searched(s)) {
        WARN("file_search name rule: the fixture's filesystem is not searched here; the spelling check is not made");
    } else {
#if defined(__APPLE__)
        CHECK(found_paths(s) == std::vector<std::string>{(fx.root / on_disk).string()}); // NFC plus case folding
#else
        CHECK(found_paths(s).empty()); // byte for byte: another case and another normal form is another name
#endif
    }
    plugin->descriptor->shutdown(pctx.get());
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

    Fixture fx;
    write_file(fx.root / "real" / "yuzu-fs-control-link-1.bin", "x");
    fs::create_directory_symlink(fx.root / "real", fx.root / "lnk");

    const Search plain = search_all(plugin->descriptor, {(fx.root / "real").string(), "yuzu-fs-control-link-*.bin", "", ""});
    if (!fixture_was_searched(plain)) {
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
    plugin->descriptor->shutdown(pctx.get());
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

#endif // !_WIN32
