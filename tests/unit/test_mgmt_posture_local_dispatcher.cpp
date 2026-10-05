/**
 * test_mgmt_posture_local_dispatcher.cpp -- loads the ACTUAL built mgmt_posture
 * plugin via PluginHandle::load and drives `posture` through
 * yuzu::agent::LocalDispatcher, so the real per-OS leg executes on the build host.
 * Modelled on test_update_source_trust_local_dispatcher.cpp.
 *
 * UNGUARDED TU on all three platforms (a guarded dispatcher TU is how a sibling
 * plugin once shipped a compiled-out Windows leg that stayed green); only the
 * per-OS assertions inside a test body are #if'd.
 *
 * The live-host cases assert shape (status row first, fixed row order, value
 * vocabularies), never host-specific values: the MDM enrolment state, the plane and
 * the keytab presence of a shared CI runner are unknown. The fault-injection cases
 * (SSSD EACCES, keytab errno, conf.d errors, fixed profiles argv) live in
 * test_mgmt_posture_legs.cpp; the [seam] cases here only pin execute_posture and the
 * PERMISSION_DENIED/PARTIAL pairing, without loading the plugin.
 */
#include <catch2/catch_test_macros.hpp>

#include <yuzu/agent/plugin_loader.hpp>
#include <yuzu/plugin.h>
#include <yuzu/plugin.hpp>

#include "local_dispatcher.hpp"

#include "mgmt_posture_legs.hpp" // execute_posture / report_posture

#include <cstdlib>
#include <filesystem>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

namespace fs = std::filesystem;

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

bool starts_with(const std::string& s, const std::string& p) { return s.rfind(p, 0) == 0; }

/// Under `meson test` (MESON_BUILD_ROOT is always set) a missing plugin means the
/// build is genuinely broken and must NOT report "All tests passed".
#if defined(_MSC_VER)
#pragma warning(push)
#pragma warning(disable : 4996)
#endif
void require_plugin_or_skip() {
    if (std::getenv("MESON_BUILD_ROOT") != nullptr) {
        FAIL("mgmt_posture plugin library not found under meson test -- the plugin did not "
             "build, or link_depends is not forcing it to build before this test runs");
    }
    WARN("mgmt_posture plugin library not found -- skipping the LocalDispatcher round-trip");
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
    const std::string lib_name = std::string{"mgmt_posture"} + kPluginExt;
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
        candidates.emplace_back(fs::path{build_root} / "agents" / "plugins" / "mgmt_posture" /
                                lib_name);
    candidates.emplace_back(fs::path{"agents"} / "plugins" / "mgmt_posture" / lib_name);
    candidates.emplace_back(fs::path{".."} / "agents" / "plugins" / "mgmt_posture" / lib_name);
    for (const char* b : {"build-macos", "build-linux", "build-windows"})
        candidates.emplace_back(fs::path{b} / "agents" / "plugins" / "mgmt_posture" / lib_name);
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

/// Seam probes: execute_posture over legs that throw / report a refused read.
int throwing_leg(yuzu::CommandContext&) { throw std::runtime_error("probe: the leg threw"); }

int denied_leg(yuzu::CommandContext& ctx) {
    yuzu::mgmt_posture::report_posture(ctx, {}, yuzu::mgmt_posture::StatusState::permission_denied,
                                       "linux:mgmt_posture:sssd_conf:permission_denied");
    return 0;
}

template <yuzu::mgmt_posture::LegFn Leg>
int seam_execute(YuzuCommandContext* raw, const char* action, const YuzuParam* /*params*/,
                 std::size_t /*param_count*/) {
    yuzu::CommandContext ctx{raw};
    return yuzu::mgmt_posture::execute_posture(ctx, action, Leg, "linux:leg:exception");
}

} // namespace

TEST_CASE("mgmt_posture plugin: an unknown action is refused with one non-status line",
          "[mgmt_posture][dispatcher]") {
    auto plugin = load_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }
    yuzu::agent::LocalDispatcher dispatcher;
    const auto result = dispatcher.run(plugin->descriptor, "no_such_action");
    CHECK(result.rc == 1);
    const auto rows = captured_rows(result.captured);
    REQUIRE(rows.size() == 1);
    CHECK(rows[0] == "unknown action: no_such_action");
    CHECK(result.result_status == YUZU_RESULT_STATUS_UNDECLARED);
}

TEST_CASE("mgmt_posture plugin: status row first, fixed row order, rc 0 on the host OS",
          "[mgmt_posture][dispatcher]") {
    auto plugin = load_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }
    yuzu::agent::LocalDispatcher dispatcher;
    const auto result = dispatcher.run(plugin->descriptor, "posture");
    CHECK(result.rc == 0); // a degraded read is never a failed command
    CHECK_FALSE(result.truncated);
    const auto rows = captured_rows(result.captured);
    REQUIRE_FALSE(rows.empty());
    INFO("status row: " << rows[0]);
    REQUIRE(starts_with(rows[0], "status|posture|"));

#if defined(_WIN32)
    // PLANNED leg: exactly one row and UNAVAILABLE/UNKNOWN.
    // MUTATION: wiring any Windows read changes this row.
    REQUIRE(rows.size() == 1);
    CHECK(rows[0] == "status|posture|unsupported|windows:planned");
    CHECK(result.result_status == YUZU_RESULT_STATUS_UNAVAILABLE);
    CHECK(result.result_completeness == YUZU_RESULT_COMPLETENESS_UNKNOWN);
    CHECK(result.result_provenance == "windows:planned");
#elif defined(__APPLE__)
    if (starts_with(rows[0], "status|posture|supported|")) {
        REQUIRE(rows.size() == 5);
        CHECK(rows[1] == "plane|-");
        CHECK((rows[2] == "mdm_enrolled|true" || rows[2] == "mdm_enrolled|false"));
        CHECK(starts_with(rows[3], "mdm_provider|"));
        CHECK(rows[4] == "tenant_id|-");
        CHECK(result.result_status == YUZU_RESULT_STATUS_OK);
        CHECK(result.result_completeness == YUZU_RESULT_COMPLETENESS_FULL);
    } else {
        // Runner refused (e.g. a sandbox): constrained, no data rows, never an empty success.
        CHECK(starts_with(rows[0], "status|posture|constrained|"));
        CHECK(rows.size() == 1);
        CHECK(result.result_status == YUZU_RESULT_STATUS_CONSTRAINED);
        CHECK(result.result_completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
    }
#else
    // Linux: supported, constrained or permission_denied (an unprivileged run over a
    // 0600 sssd.conf); in every case the same five data rows follow in fixed order.
    const bool denied = starts_with(rows[0], "status|posture|permission_denied|");
    CHECK((denied || starts_with(rows[0], "status|posture|supported|") ||
           starts_with(rows[0], "status|posture|constrained|")));
    REQUIRE(rows.size() == 6);
    const std::string plane = rows[1].substr(rows[1].find('|') + 1);
    CHECK(starts_with(rows[1], "plane|"));
    CHECK((plane == "none" || plane == "ad" || plane == "ipa" || plane == "unknown"));
    CHECK(rows[2] == "mdm_enrolled|-");
    CHECK(rows[3] == "mdm_provider|-");
    CHECK(rows[4] == "tenant_id|-");
    CHECK(starts_with(rows[5], "krb5_keytab|"));
    if (starts_with(rows[0], "status|posture|supported|")) {
        CHECK((rows[5] == "krb5_keytab|present" || rows[5] == "krb5_keytab|absent"));
        CHECK(result.result_status == YUZU_RESULT_STATUS_OK);
    }
    if (denied) {
        CHECK(plane == "unknown"); // a refused read is never "not joined"
        CHECK(result.result_status == YUZU_RESULT_STATUS_PERMISSION_DENIED);
        CHECK(result.result_completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
    }
#endif
}

TEST_CASE("mgmt_posture execute seam: unknown action is escaped; a throwing leg is contained; a "
          "refused read pairs PERMISSION_DENIED with PARTIAL",
          "[mgmt_posture][dispatcher][seam]") {
    yuzu::agent::LocalDispatcher dispatcher;

    YuzuPluginDescriptor throwing{};
    throwing.execute = &seam_execute<&throwing_leg>;

    const auto thrown = dispatcher.run(&throwing, "posture");
    CHECK(thrown.rc == 0); // contained, never unwound
    const auto trows = captured_rows(thrown.captured);
    REQUIRE(trows.size() == 1);
    CHECK(trows[0] == "status|posture|unsupported|linux:leg:exception");
    CHECK(thrown.result_status == YUZU_RESULT_STATUS_UNAVAILABLE);
    CHECK(thrown.result_completeness == YUZU_RESULT_COMPLETENESS_UNKNOWN);
    CHECK(thrown.result_provenance == "linux:leg:exception");

    // The request-supplied name goes through safe_output_field: a pipe and a trailing
    // backslash can neither open a second field nor swallow a delimiter.
    const auto hostile = dispatcher.run(&throwing, "no|such\\");
    CHECK(hostile.rc == 1);
    const auto hrows = captured_rows(hostile.captured);
    REQUIRE(hrows.size() == 1);
    CHECK(hrows[0] == "unknown action: no\\|such/");

    // ... and it is made valid UTF-8 first (a protobuf string field must be), exactly as
    // posture_row does for its values: an invalid byte becomes '?', a valid sequence survives.
    const auto binary = dispatcher.run(&throwing, "bad\xff!");
    CHECK(binary.rc == 1);
    const auto brows = captured_rows(binary.captured);
    REQUIRE(brows.size() == 1);
    CHECK(brows[0] == "unknown action: bad?!");
    const auto accented = dispatcher.run(&throwing, "caf\xc3\xa9");
    const auto arows = captured_rows(accented.captured);
    REQUIRE(arows.size() == 1);
    CHECK(arows[0] == "unknown action: caf\xc3\xa9");

    YuzuPluginDescriptor denied{};
    denied.execute = &seam_execute<&denied_leg>;
    const auto d = dispatcher.run(&denied, "posture");
    CHECK(d.rc == 0);
    const auto drows = captured_rows(d.captured);
    REQUIRE(drows.size() == 1);
    CHECK(drows[0] == "status|posture|permission_denied|linux:mgmt_posture:sssd_conf:permission_denied");
    CHECK(d.result_status == YUZU_RESULT_STATUS_PERMISSION_DENIED);
    CHECK(d.result_completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
    CHECK(d.result_provenance == "linux:mgmt_posture:sssd_conf:permission_denied");
}
