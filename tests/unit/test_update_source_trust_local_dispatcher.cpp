/**
 * test_update_source_trust_local_dispatcher.cpp -- loads the ACTUAL built
 * update_source_trust plugin (.dylib / .so / .dll) via PluginHandle::load and
 * drives its one action, `sources`, through yuzu::agent::LocalDispatcher, so
 * the real per-OS leg (run_linux / run_macos / run_windows) executes on the
 * build host. Modelled on test_peripherals_local_dispatcher.cpp.
 *
 * UNGUARDED, deliberately, on all three platforms: a platform-guarded
 * dispatcher TU is how a sibling plugin once shipped a Windows leg that was
 * compiled out and stayed green. Everything platform-specific below is a
 * runtime/`#if` choice INSIDE a test body; the TU and every case always exist.
 *
 * WHAT THIS DOES NOT ASSERT. It runs against the LIVE host (CI runners are
 * shared, unknown hardware), so it never asserts that a real-host source
 * exists. Where a row is asserted it is guarded on the host actually having
 * the input (a readable regular file that the leg is documented to read) AND
 * on the leg reporting `supported`; the populated-row assertions on injected
 * fixture trees live in test_update_source_trust_linux_parsers.cpp.
 *
 * What it DOES pin on every host: the first row is the status row, the status
 * row agrees with the typed CC-07 result the plugin reported, the return code
 * is 0 (a degraded read is not a failed command), and every data row has the
 * exact field count of its kind under an escape-aware split. The Windows and
 * macOS legs are PLANNED placeholders and are pinned to their exact single row.
 * The [seam] case drives execute_sources (update_source_trust_legs.hpp) through
 * a synthetic descriptor with a leg that throws, so the ABI containment and the
 * unknown-action path are pinned on every OS without loading the plugin.
 */
#include <catch2/catch_test_macros.hpp>

#include <yuzu/agent/plugin_loader.hpp>
#include <yuzu/plugin.h>
#include <yuzu/plugin.hpp>

#include "local_dispatcher.hpp"

#include "update_source_trust_legs.hpp" // execute_sources (the plugin's whole execute body)
#if defined(__linux__)
#include "update_source_trust_linux_parsers.hpp" // lnx::linux_rows_at: the in-process oracle
#endif

#include <cstdlib>
#include <filesystem>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace fs = std::filesystem;

namespace {

/// Escape-aware field split: safe_output_field writes a literal '|' as `\|`,
/// so a naive split('|') overcounts on a row whose text contains a pipe.
std::vector<std::string> split_fields_escape_aware(const std::string& row) {
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

/// Under `meson test` (MESON_BUILD_ROOT is always set) a missing plugin means
/// the build is genuinely broken and must NOT report "All tests passed".
#if defined(_MSC_VER)
#pragma warning(push)
#pragma warning(disable : 4996)
#endif
void require_plugin_or_skip() {
    if (std::getenv("MESON_BUILD_ROOT") != nullptr) {
        FAIL("update_source_trust plugin library not found under meson test -- the plugin did not "
             "build, or link_depends is not forcing it to build before this test runs");
    }
    WARN("update_source_trust plugin library not found -- skipping the LocalDispatcher round-trip");
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
    const std::string lib_name = std::string{"update_source_trust"} + kPluginExt;
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
        candidates.emplace_back(fs::path{build_root} / "agents" / "plugins" / "update_source_trust" /
                                lib_name);
    candidates.emplace_back(fs::path{"agents"} / "plugins" / "update_source_trust" / lib_name);
    candidates.emplace_back(fs::path{".."} / "agents" / "plugins" / "update_source_trust" / lib_name);
    for (const char* b : {"build-macos", "build-linux", "build-windows"})
        candidates.emplace_back(fs::path{b} / "agents" / "plugins" / "update_source_trust" / lib_name);
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

/// Documented field counts, kind token included (only the kinds this plugin
/// EMITS; the planned rpm_repo / macos_swu / wsus shapes are deliberately absent,
/// so an emission of one is a regression -- see the `want != 0` guard below):
///   status|sources|<state>|<reason>                                       4
///   apt_source|file|format|types|uris|suites|components|signed_by|
///              trusted|allow_insecure|enabled                            11
///   apt_keyring|path|scope|format|size_bytes                              5
std::size_t expected_field_count(const std::string& kind) {
    if (kind == "status")
        return 4;
    if (kind == "apt_source")
        return 11;
    if (kind == "apt_keyring")
        return 5;
    return 0; // unknown (or planned, never emitted) kind
}

/// The execute-seam probes: a leg that throws, run through the production
/// execute_sources exactly as the plugin TU wires its host leg.
int throwing_leg(yuzu::CommandContext&) { throw std::runtime_error("probe: the leg threw"); }

int seam_execute(YuzuCommandContext* raw, const char* action, const YuzuParam* /*params*/,
                 std::size_t /*param_count*/) {
    yuzu::CommandContext ctx{raw};
    return yuzu::update_source_trust::execute_sources(ctx, action, &throwing_leg,
                                                      "linux:leg:exception");
}

} // namespace

TEST_CASE("update_source_trust plugin: status row first, agrees with the typed result, rc 0",
          "[update_source_trust][dispatcher]") {
    auto plugin = load_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }
    yuzu::agent::LocalDispatcher dispatcher;
    const auto result = dispatcher.run(plugin->descriptor, "sources");
    CHECK(result.rc == 0); // a degraded read is never a failed command
    CHECK_FALSE(result.truncated);

    const auto rows = captured_rows(result.captured);
    REQUIRE_FALSE(rows.empty());

    const auto status = split_fields_escape_aware(rows[0]);
    INFO("status row: " << rows[0]);
    REQUIRE(status.size() == 4);
    CHECK(status[0] == "status");
    CHECK(status[1] == "sources");

#if defined(_WIN32)
    // The Windows leg is PLANNED: exactly one row, and an UNAVAILABLE result.
    // MUTATION: implementing (or wiring) any Windows read changes this row.
    REQUIRE(rows.size() == 1);
    CHECK(rows[0] == "status|sources|unsupported|windows:planned");
    CHECK(result.result_status == YUZU_RESULT_STATUS_UNAVAILABLE);
    CHECK(result.result_completeness == YUZU_RESULT_COMPLETENESS_UNKNOWN);
    CHECK(result.result_provenance == "windows:planned");
#elif defined(__APPLE__)
    // The macOS leg is PLANNED: exactly one row, and an UNAVAILABLE result.
    // MUTATION: implementing (or wiring) any macOS read changes this row.
    REQUIRE(rows.size() == 1);
    CHECK(rows[0] == "status|sources|unsupported|macos:planned");
    CHECK(result.result_status == YUZU_RESULT_STATUS_UNAVAILABLE);
    CHECK(result.result_completeness == YUZU_RESULT_COMPLETENESS_UNKNOWN);
    CHECK(result.result_provenance == "macos:planned");
#else
    // Linux: supported (clean read, full) or constrained (reason + partial; e.g. an
    // rpm host reports `linux:rpm_repo:planned`). The row and the typed result are
    // written together by report_sources, so they can never disagree.
    if (status[2] == "supported") {
        CHECK(status[3] == "-");
        CHECK(result.result_status == YUZU_RESULT_STATUS_OK);
        CHECK(result.result_completeness == YUZU_RESULT_COMPLETENESS_FULL);
    } else {
        REQUIRE(status[2] == "constrained");
        CHECK(status[3] != "-");
        CHECK(result.result_status == YUZU_RESULT_STATUS_CONSTRAINED);
        CHECK(result.result_completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
        CHECK_FALSE(result.result_provenance.empty()); // the reason travels with the status
    }

    // The shipped root wiring, observed on whatever THIS host is. The oracle is the
    // SAME walk body run in-process over the host's real root: the built .so's
    // run_linux -> "/" must report exactly what lnx::linux_rows_at("/") reports
    // here -- deb822-only hosts (Debian 13, Ubuntu 24.04), one-line hosts, rpm
    // hosts (`linux:rpm_repo:planned`) and hosts with neither. MUTATIONS: a leg
    // walking another root fails the row comparison wherever apt config exists;
    // dropping the rpm tripwire fails the state/token comparison on an rpm host;
    // an unconditional token fails it everywhere else.
    yuzu::shared::ConstraintAccumulator oracle;
    const auto oracle_rows = yuzu::update_source_trust::lnx::linux_rows_at("/", oracle);
    CHECK((status[2] == "constrained") == oracle.any_failure());
    CHECK(status[3] == (oracle.any_failure() ? oracle.reason() : std::string{"-"}));
    const std::vector<std::string> data_rows(rows.begin() + 1, rows.end());
    CHECK(data_rows == oracle_rows);
    if (oracle_rows.empty() && !oracle.any_failure())
        WARN("no apt or yum configuration on this host: the shipped root wiring was not exercised");
#endif
}

TEST_CASE("update_source_trust plugin: every data row has its kind's exact field count",
          "[update_source_trust][dispatcher]") {
    auto plugin = load_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }
    yuzu::agent::LocalDispatcher dispatcher;
    const auto rows = captured_rows(dispatcher.run(plugin->descriptor, "sources").captured);
    REQUIRE_FALSE(rows.empty());

    for (std::size_t i = 0; i < rows.size(); ++i) {
        INFO("row " << i << ": " << rows[i]);
        const auto f = split_fields_escape_aware(rows[i]);
        if (i == 0)
            CHECK(f[0] == "status"); // the status row is FIRST and only first
        else
            CHECK(f[0] != "status");
        const std::size_t want = expected_field_count(f[0]);
        REQUIRE(want != 0); // an unknown row kind is a regression
        CHECK(f.size() == want);
#if defined(__linux__)
        CHECK((f[0] == "status" || f[0] == "apt_source" || f[0] == "apt_keyring"));
#endif
    }
}

TEST_CASE("update_source_trust plugin: an unknown action is refused, not silently ignored",
          "[update_source_trust][dispatcher]") {
    auto plugin = load_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }
    yuzu::agent::LocalDispatcher dispatcher;
    const auto result = dispatcher.run(plugin->descriptor, "no_such_action");
    CHECK(result.rc == 1);
    // Deliberately not a data or status row, and the diagnostic text is pinned.
    // MUTATION: deleting the `unknown action:` write in execute_sources fails here.
    const auto rows = captured_rows(result.captured);
    REQUIRE(rows.size() == 1);
    CHECK(rows[0] == "unknown action: no_such_action");
    CHECK(result.result_status == YUZU_RESULT_STATUS_UNDECLARED); // no status is reported
}

TEST_CASE("update_source_trust execute seam: a leg that throws is contained as one unsupported row + UNAVAILABLE; a hostile action name is escaped",
          "[update_source_trust][dispatcher][seam]") {
    YuzuPluginDescriptor descriptor{};
    descriptor.execute = &seam_execute;
    yuzu::agent::LocalDispatcher dispatcher;

    const auto thrown = dispatcher.run(&descriptor, "sources");
    CHECK(thrown.rc == 0); // contained: a leg that threw is reported, never unwound
    const auto rows = captured_rows(thrown.captured);
    // MUTATION: removing the catch arm lets the exception escape to Catch2 (red);
    // writing `constrained` (the r1 shape) or CONSTRAINED here fails the pair below.
    REQUIRE(rows.size() == 1);
    CHECK(rows[0] == "status|sources|unsupported|linux:leg:exception");
    CHECK(thrown.result_status == YUZU_RESULT_STATUS_UNAVAILABLE);
    CHECK(thrown.result_completeness == YUZU_RESULT_COMPLETENESS_UNKNOWN);
    CHECK(thrown.result_provenance == "linux:leg:exception"); // one seam, two views

    // The unknown-action write sits INSIDE the same try. The request-supplied
    // name goes through safe_output_field, so a pipe and a trailing backslash can
    // neither open a second field nor swallow a delimiter.
    const auto hostile = dispatcher.run(&descriptor, "no|such\\");
    CHECK(hostile.rc == 1);
    const auto hrows = captured_rows(hostile.captured);
    REQUIRE(hrows.size() == 1);
    CHECK(hrows[0] == "unknown action: no\\|such/");
    CHECK(split_fields_escape_aware(hrows[0]).size() == 1);
}
