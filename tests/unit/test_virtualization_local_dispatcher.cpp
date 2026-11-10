/**
 * test_virtualization_local_dispatcher.cpp -- loads the ACTUAL built virtualization plugin via
 * PluginHandle::load and drives `host` through yuzu::agent::LocalDispatcher, so the real per-OS
 * leg executes on the build host. Modelled on test_mgmt_posture_local_dispatcher.cpp.
 *
 * UNGUARDED TU on all three platforms (a guarded dispatcher TU is how a sibling plugin once
 * shipped a compiled-out Windows leg that stayed green); only the per-OS assertions inside a
 * test body are #if'd.
 *
 * The live-host cases assert SHAPE (status row first, fixed row order, closed vocabularies),
 * never host-specific values: whether a shared CI runner is a VM, which hypervisor, or whether
 * it sits in a container is unknown. Every classification case lives in
 * test_virtualization_parsers.cpp; the [seam] cases here only pin execute_action and the
 * report_host status pairing, without loading the plugin.
 */
#include <catch2/catch_test_macros.hpp>

#include <yuzu/agent/plugin_loader.hpp>
#include <yuzu/plugin.h>
#include <yuzu/plugin.hpp>

#include "local_dispatcher.hpp"

#include "virtualization_legs.hpp" // execute_action / report_host

#include <algorithm>
#include <cstdlib>
#include <filesystem>
#include <initializer_list>
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
        FAIL("virtualization plugin library not found under meson test -- the plugin did not "
             "build, or link_depends is not forcing it to build before this test runs");
    }
    WARN("virtualization plugin library not found -- skipping the LocalDispatcher round-trip");
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
    const std::string lib_name = std::string{"virtualization"} + kPluginExt;
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
        candidates.emplace_back(fs::path{build_root} / "agents" / "plugins" / "virtualization" /
                                lib_name);
    candidates.emplace_back(fs::path{"agents"} / "plugins" / "virtualization" / lib_name);
    candidates.emplace_back(fs::path{".."} / "agents" / "plugins" / "virtualization" / lib_name);
    for (const char* b : {"build-macos", "build-linux", "build-windows"})
        candidates.emplace_back(fs::path{b} / "agents" / "plugins" / "virtualization" / lib_name);
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

/// Seam probes: execute_action over legs that throw / report a constrained read.
int throwing_leg(yuzu::CommandContext&) { throw std::runtime_error("probe: the leg threw"); }

/// Throws AFTER report_host already wrote its rows: the catch arm appends a second status row.
int late_throwing_leg(yuzu::CommandContext& ctx) {
    yuzu::virtualization::report_host(
        ctx, yuzu::virtualization::Posture{yuzu::virtualization::StatusState::supported, "",
                                           {"host|no|bare_metal|x|y|cpuid|high"}});
    throw std::runtime_error("probe: the leg threw after reporting");
}

int constrained_leg(yuzu::CommandContext& ctx) {
    yuzu::virtualization::report_host(
        ctx,
        yuzu::virtualization::Posture{yuzu::virtualization::StatusState::constrained,
                                      "linux:virtualization:dmi:permission_denied",
                                      {"host|unknown|unknown|-|-|linux:virtualization:dmi:permission_denied|low"}});
    return 0;
}

int supported_leg(yuzu::CommandContext& ctx) {
    yuzu::virtualization::report_host(
        ctx, yuzu::virtualization::Posture{yuzu::virtualization::StatusState::supported, "", {}});
    return 0;
}

template <yuzu::virtualization::LegFn Leg, yuzu::virtualization::LegFn WslLeg = Leg,
          yuzu::virtualization::LegFn RuntimeLeg = Leg>
int seam_execute(YuzuCommandContext* raw, const char* action, const YuzuParam* /*params*/,
                 std::size_t /*param_count*/) {
    yuzu::CommandContext ctx{raw};
    return yuzu::virtualization::execute_action(
        ctx, action, yuzu::virtualization::Legs{Leg, WslLeg, RuntimeLeg}, "linux:leg:exception");
}

/// A leg that reports a status row named for the action it serves, so a routing test can tell
/// which leg ran.
template <const char* Name>
int named_leg(yuzu::CommandContext& ctx) {
    yuzu::virtualization::report(
        ctx, Name, yuzu::virtualization::Posture{yuzu::virtualization::StatusState::supported, "", {}});
    return 0;
}
constexpr char kHostName[] = "host";
constexpr char kWslName[] = "wsl";
constexpr char kRuntimeName[] = "runtime_posture";

std::size_t field_count(const std::string& row) {
    std::size_t n = 1;
    for (std::size_t i = 0; i < row.size(); ++i) {
        if (row[i] == '\\' && i + 1 < row.size() && row[i + 1] == '|')
            ++i;
        else if (row[i] == '|')
            ++n;
    }
    return n;
}

bool one_of(const std::string& v, std::initializer_list<const char*> set) {
    for (const char* s : set)
        if (v == s)
            return true;
    return false;
}

std::string field(const std::string& row, std::size_t index) {
    std::size_t cur = 0;
    std::string out;
    for (std::size_t i = 0; i < row.size(); ++i) {
        if (row[i] == '\\' && i + 1 < row.size() && row[i + 1] == '|') {
            if (cur == index)
                out += "\\|";
            ++i;
        } else if (row[i] == '|') {
            ++cur;
        } else if (cur == index) {
            out += row[i];
        }
    }
    return out;
}

} // namespace

TEST_CASE("virtualization plugin: an unknown action is refused with one non-status line",
          "[virtualization][dispatcher]") {
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

TEST_CASE("virtualization plugin: status row first then one host row and one container row",
          "[virtualization][dispatcher]") {
    auto plugin = load_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }
    yuzu::agent::LocalDispatcher dispatcher;
    const auto result = dispatcher.run(plugin->descriptor, "host");
    CHECK(result.rc == 0); // a degraded read is never a failed command
    CHECK_FALSE(result.truncated);
    const auto rows = captured_rows(result.captured);
    REQUIRE(rows.size() == 3);
    INFO("status row: " << rows[0]);
    REQUIRE(starts_with(rows[0], "status|host|"));
    const bool supported = starts_with(rows[0], "status|host|supported|");
    const bool constrained = starts_with(rows[0], "status|host|constrained|");
    CHECK((supported || constrained)); // never unsupported on a build host
    if (supported) {
        CHECK(result.result_status == YUZU_RESULT_STATUS_OK);
        CHECK(result.result_completeness == YUZU_RESULT_COMPLETENESS_FULL);
    } else if (constrained) {
        CHECK(result.result_status == YUZU_RESULT_STATUS_CONSTRAINED);
        CHECK(result.result_completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
    }

    INFO("host row: " << rows[1]);
    REQUIRE(starts_with(rows[1], "host|"));
    CHECK(field_count(rows[1]) == 7);
    CHECK(one_of(field(rows[1], 1), {"yes", "no", "unknown"}));
    CHECK(one_of(field(rows[1], 2), {"guest", "host_with_hypervisor", "bare_metal", "unknown"}));
    CHECK(one_of(field(rows[1], 6), {"high", "medium", "low"}));
    // The kind and the is_virtual answer agree.
    const auto kind = field(rows[1], 2);
    if (kind == "guest")
        CHECK(field(rows[1], 1) == "yes");
    if (kind == "host_with_hypervisor" || kind == "bare_metal")
        CHECK(field(rows[1], 1) == "no");
    if (kind == "unknown") {
        CHECK(field(rows[1], 1) == "unknown");
        CHECK(field(rows[1], 5) != "-"); // an unknown carries its reason on the row
    }

    INFO("container row: " << rows[2]);
    REQUIRE(starts_with(rows[2], "container|"));
    CHECK(field_count(rows[2]) == 3);
    CHECK(one_of(field(rows[2], 1), {"yes", "no", "unknown"}));
#if defined(__APPLE__)
    CHECK(rows[2] == "container|no|macos:no_container_runtime");
#elif defined(_WIN32)
    CHECK(rows[2] == "container|unknown|windows:virtualization:container:not_read");
#endif
}

TEST_CASE("virtualization execute seam: unknown action is escaped; a throwing leg is contained; "
          "a constrained read pairs CONSTRAINED with PARTIAL",
          "[virtualization][dispatcher][seam]") {
    yuzu::agent::LocalDispatcher dispatcher;

    YuzuPluginDescriptor throwing{};
    throwing.execute = &seam_execute<&throwing_leg>;

    const auto thrown = dispatcher.run(&throwing, "host");
    CHECK(thrown.rc == 0); // contained, never unwound
    const auto trows = captured_rows(thrown.captured);
    REQUIRE(trows.size() == 1);
    CHECK(trows[0] == "status|host|unsupported|linux:leg:exception");
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

    // ... and an invalid UTF-8 byte is replaced first; a valid sequence survives.
    const auto binary = dispatcher.run(&throwing, "bad\xff!");
    CHECK(binary.rc == 1);
    const auto brows = captured_rows(binary.captured);
    REQUIRE(brows.size() == 1);
    CHECK(brows[0] == "unknown action: bad?!");

    YuzuPluginDescriptor constrained{};
    constrained.execute = &seam_execute<&constrained_leg>;
    const auto c = dispatcher.run(&constrained, "host");
    CHECK(c.rc == 0);
    const auto crows = captured_rows(c.captured);
    REQUIRE(crows.size() == 2);
    CHECK(crows[0] == "status|host|constrained|linux:virtualization:dmi:permission_denied");
    CHECK(c.result_status == YUZU_RESULT_STATUS_CONSTRAINED);
    CHECK(c.result_completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
    CHECK(c.result_provenance == "linux:virtualization:dmi:permission_denied");

    YuzuPluginDescriptor supported{};
    supported.execute = &seam_execute<&supported_leg>;
    const auto s = dispatcher.run(&supported, "host");
    const auto srows = captured_rows(s.captured);
    REQUIRE(srows.size() == 1);
    CHECK(srows[0] == "status|host|supported|-");
    CHECK(s.result_status == YUZU_RESULT_STATUS_OK);
    CHECK(s.result_completeness == YUZU_RESULT_COMPLETENESS_FULL);
    CHECK(s.result_provenance.empty());
}

TEST_CASE("virtualization execute seam: a leg that throws after reporting keeps its rows and the last "
          "status wins",
          "[virtualization][dispatcher][seam]") {
    yuzu::agent::LocalDispatcher dispatcher;
    YuzuPluginDescriptor late{};
    late.execute = &seam_execute<&late_throwing_leg>;

    const auto r = dispatcher.run(&late, "host");
    CHECK(r.rc == 0); // contained, never unwound
    const auto rows = captured_rows(r.captured);
    REQUIRE(rows.size() == 3);
    CHECK(rows[0] == "status|host|supported|-");
    CHECK(rows[1] == "host|no|bare_metal|x|y|cpuid|high"); // retained between the two status rows
    CHECK(rows[2] == "status|host|unsupported|linux:leg:exception");
    CHECK(std::count_if(rows.begin(), rows.end(),
                        [](const std::string& row) { return starts_with(row, "status|host|"); }) == 2);
    CHECK(r.result_status == YUZU_RESULT_STATUS_UNAVAILABLE); // the recovery's status, not the leg's OK
    CHECK(r.result_completeness == YUZU_RESULT_COMPLETENESS_UNKNOWN);
    CHECK(r.result_provenance == "linux:leg:exception");
}

// ---------------------------------------------------------------------------------------------
// wsl
// ---------------------------------------------------------------------------------------------

TEST_CASE("virtualization plugin: wsl answers per OS (one unsupported row off Windows)",
          "[virtualization][dispatcher][wsl]") {
#if defined(_WIN32)
    // The Windows leg walks the machine's real ProfileList and may mount every logged-off
    // NTUSER.DAT (disk I/O, and it changes those hives' sequence numbers, #4977): not something a
    // unit suite does on a shared runner. Its content-bearing evidence is the plugin-capture
    // `--action host --action wsl` run on a Windows host, recorded in the PR body.
    SKIP("the Windows wsl leg reads the live profile list and hives; see the PR's Windows capture");
#else
    auto plugin = load_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }
    yuzu::agent::LocalDispatcher dispatcher;
    const auto result = dispatcher.run(plugin->descriptor, "wsl");
    CHECK(result.rc == 0); // a degraded read is never a failed command
    CHECK_FALSE(result.truncated);
    const auto rows = captured_rows(result.captured);
    REQUIRE(rows.size() == 1);
#if defined(__APPLE__)
    CHECK(rows[0] == "status|wsl|unsupported|macos:virtualization:wsl:unsupported");
#else
    CHECK(rows[0] == "status|wsl|unsupported|linux:virtualization:wsl:unsupported");
#endif
    CHECK(result.result_status == YUZU_RESULT_STATUS_UNAVAILABLE);
    CHECK(result.result_completeness == YUZU_RESULT_COMPLETENESS_UNKNOWN);
#endif
}

TEST_CASE("virtualization descriptor advertises host, wsl and runtime_posture at version 1.2.0",
          "[virtualization][dispatcher][wsl]") {
    auto plugin = load_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }
    const YuzuPluginDescriptor& d = *plugin->descriptor;
    CHECK(std::string{d.version} == "1.2.0");

    REQUIRE(d.actions != nullptr);
    std::vector<std::string> actions;
    for (const char* const* a = d.actions; *a != nullptr; ++a)
        actions.emplace_back(*a);
    CHECK(actions == std::vector<std::string>{"host", "wsl", "runtime_posture"});

    REQUIRE(d.action_descriptors != nullptr);
    REQUIRE(d.action_descriptor_count == 3);
    const YuzuActionDescriptor* wsl = nullptr;
    for (std::size_t i = 0; i < d.action_descriptor_count; ++i)
        if (std::string{d.action_descriptors[i].action} == "wsl")
            wsl = &d.action_descriptors[i];
    REQUIRE(wsl != nullptr);
    // Windows-only: constrained at rung 1 there, unsupported at rung 0 elsewhere.
    CHECK(wsl->linux_leg.support == YUZU_SUPPORT_UNSUPPORTED);
    CHECK(wsl->linux_leg.rung == 0);
    CHECK(wsl->macos_leg.support == YUZU_SUPPORT_UNSUPPORTED);
    CHECK(wsl->macos_leg.rung == 0);
    CHECK(wsl->windows_leg.support == YUZU_SUPPORT_CONSTRAINED);
    CHECK(wsl->windows_leg.rung == 1);

    // runtime_posture is Linux-only: constrained at rung 1 there (no containers without the opt-in,
    // containerd presence only), unsupported at rung 0 elsewhere.
    const YuzuActionDescriptor* rt = nullptr;
    for (std::size_t i = 0; i < d.action_descriptor_count; ++i)
        if (std::string{d.action_descriptors[i].action} == "runtime_posture")
            rt = &d.action_descriptors[i];
    REQUIRE(rt != nullptr);
    CHECK(rt->linux_leg.support == YUZU_SUPPORT_CONSTRAINED);
    CHECK(rt->linux_leg.rung == 1);
    CHECK(rt->macos_leg.support == YUZU_SUPPORT_UNSUPPORTED);
    CHECK(rt->macos_leg.rung == 0);
    CHECK(rt->windows_leg.support == YUZU_SUPPORT_UNSUPPORTED);
    CHECK(rt->windows_leg.rung == 0);
}

TEST_CASE("virtualization execute seam: a throwing wsl leg is contained under its own action name",
          "[virtualization][dispatcher][seam][wsl]") {
    yuzu::agent::LocalDispatcher dispatcher;
    YuzuPluginDescriptor d{};
    d.execute = &seam_execute<&supported_leg, &throwing_leg>;

    const auto w = dispatcher.run(&d, "wsl");
    CHECK(w.rc == 0);
    const auto wrows = captured_rows(w.captured);
    REQUIRE(wrows.size() == 1);
    CHECK(wrows[0] == "status|wsl|unsupported|linux:leg:exception");
    CHECK(w.result_status == YUZU_RESULT_STATUS_UNAVAILABLE);

    // The host leg of the same table is untouched and keeps its own status name.
    const auto h = dispatcher.run(&d, "host");
    const auto hrows = captured_rows(h.captured);
    REQUIRE(hrows.size() == 1);
    CHECK(hrows[0] == "status|host|supported|-");
}

// ---------------------------------------------------------------------------------------------
// runtime_posture
// ---------------------------------------------------------------------------------------------

TEST_CASE("virtualization plugin: runtime_posture without an endpoint reports detection only, "
          "unsupported off Linux",
          "[virtualization][dispatcher][runtime]") {
    auto plugin = load_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }
    // The real init() with a config that lacks agent.runtime_endpoint: the plugin never opens a socket.
    yuzu::agent::StandalonePluginContext ctx("virtualization", {});
    REQUIRE(plugin->descriptor->init(ctx.get()) == 0);

    yuzu::agent::LocalDispatcher dispatcher;
    const auto result = dispatcher.run(plugin->descriptor, "runtime_posture");
    CHECK(result.rc == 0); // a degraded read is never a failed command
    CHECK_FALSE(result.truncated);
    const auto rows = captured_rows(result.captured);
    REQUIRE_FALSE(rows.empty());
#if defined(__linux__)
    INFO("status row: " << rows[0]);
    REQUIRE(starts_with(rows[0], "status|runtime_posture|"));
    const bool supported = starts_with(rows[0], "status|runtime_posture|supported|");
    const bool constrained = starts_with(rows[0], "status|runtime_posture|constrained|");
    CHECK((supported || constrained)); // never unsupported on a Linux host
    REQUIRE(rows.size() >= 5);
    CHECK(rows[1] == "endpoint|unset|-|-");
    CHECK(starts_with(rows[2], "runtime|docker|"));
    CHECK(starts_with(rows[3], "runtime|podman|"));
    CHECK(starts_with(rows[4], "runtime|containerd|"));
    for (const auto& r : rows) {
        CHECK_FALSE(starts_with(r, "container|")); // no endpoint, so no container is ever listed
        CHECK(field_count(r) <= 8);
    }
    for (std::size_t i = 2; i <= 4; ++i) {
        CHECK(field_count(rows[i]) == 7);
        CHECK(one_of(field(rows[i], 2), {"not_detected", "detected"})); // never `served`
    }
#else
    REQUIRE(rows.size() == 1);
#if defined(__APPLE__)
    CHECK(rows[0] == "status|runtime_posture|unsupported|macos:virtualization:runtime_posture:unsupported");
#else
    CHECK(rows[0] == "status|runtime_posture|unsupported|windows:virtualization:runtime_posture:unsupported");
#endif
    CHECK(result.result_status == YUZU_RESULT_STATUS_UNAVAILABLE);
    CHECK(result.result_completeness == YUZU_RESULT_COMPLETENESS_UNKNOWN);
#endif
    plugin->descriptor->shutdown(ctx.get());
}

#if defined(__linux__)
TEST_CASE("virtualization plugin: init() plumbs agent.runtime_endpoint into runtime_posture",
          "[virtualization][dispatcher][runtime][endpoint]") {
    auto plugin = load_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }
    // The endpoint is process-global in the plugin: whatever happens below, re-init with an empty
    // config so the `endpoint|unset` case above cannot be poisoned by test order.
    struct ResetEndpoint {
        const YuzuPluginDescriptor* d;
        ~ResetEndpoint() {
            yuzu::agent::StandalonePluginContext empty("virtualization", {});
            d->init(empty.get());
        }
    } reset{plugin->descriptor};

    yuzu::agent::LocalDispatcher dispatcher;
    // Both values are refused on the path alone, so no socket is ever opened, whatever this host runs.
    struct Case {
        const char* endpoint;
        const char* reason;
    };
    for (const Case c : {Case{"relative.sock", "relative"}, Case{"/run/docker.sock", "default_socket"}}) {
        INFO(c.endpoint);
        yuzu::agent::StandalonePluginContext ctx("virtualization",
                                                 {{"agent.runtime_endpoint", c.endpoint}});
        REQUIRE(plugin->descriptor->init(ctx.get()) == 0);
        const auto result = dispatcher.run(plugin->descriptor, "runtime_posture");
        CHECK(result.rc == 0);
        const auto rows = captured_rows(result.captured);
        REQUIRE(rows.size() >= 5);
        // the value reached the leg: a typed refusal, never `unset`, and the path is never echoed
        CHECK(rows[1] == std::string{"endpoint|endpoint_refused|"} + c.reason + "|-");
        CHECK(starts_with(rows[0], "status|runtime_posture|constrained|"));
        CHECK(rows[0].find(std::string{"endpoint:"} + c.reason) != std::string::npos);
        for (const auto& r : rows) {
            CHECK_FALSE(starts_with(r, "container|"));
            CHECK(r.find(c.endpoint) == std::string::npos);
        }
        plugin->descriptor->shutdown(ctx.get());
    }
}
#endif

TEST_CASE("virtualization execute seam: every action routes to its own leg and an unknown one is "
          "still refused",
          "[virtualization][dispatcher][seam][runtime]") {
    yuzu::agent::LocalDispatcher dispatcher;
    YuzuPluginDescriptor d{};
    d.execute = &seam_execute<&named_leg<kHostName>, &named_leg<kWslName>, &named_leg<kRuntimeName>>;

    for (const char* action : {"host", "wsl", "runtime_posture"}) {
        const auto r = dispatcher.run(&d, action);
        INFO(action);
        CHECK(r.rc == 0);
        const auto rows = captured_rows(r.captured);
        REQUIRE(rows.size() == 1);
        CHECK(rows[0] == std::string{"status|"} + action + "|supported|-");
        CHECK(r.result_status == YUZU_RESULT_STATUS_OK);
    }
    const auto unknown = dispatcher.run(&d, "runtime_posture2");
    CHECK(unknown.rc == 1);
    const auto urows = captured_rows(unknown.captured);
    REQUIRE(urows.size() == 1);
    CHECK(urows[0] == "unknown action: runtime_posture2");
}

TEST_CASE("virtualization execute seam: a throwing runtime_posture leg is contained under its own name",
          "[virtualization][dispatcher][seam][runtime]") {
    yuzu::agent::LocalDispatcher dispatcher;
    YuzuPluginDescriptor d{};
    d.execute = &seam_execute<&supported_leg, &supported_leg, &throwing_leg>;

    const auto r = dispatcher.run(&d, "runtime_posture");
    CHECK(r.rc == 0); // contained, never unwound across the ABI
    const auto rows = captured_rows(r.captured);
    REQUIRE(rows.size() == 1);
    CHECK(rows[0] == "status|runtime_posture|unsupported|linux:leg:exception"); // no body text
    CHECK(r.result_status == YUZU_RESULT_STATUS_UNAVAILABLE);
    CHECK(r.result_provenance == "linux:leg:exception");

    // the other legs of the same table keep their own status names
    const auto h = dispatcher.run(&d, "host");
    const auto hrows = captured_rows(h.captured);
    REQUIRE(hrows.size() == 1);
    CHECK(hrows[0] == "status|host|supported|-");
}
