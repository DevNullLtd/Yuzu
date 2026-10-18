/**
 * test_remote_access_audit_local_dispatcher.cpp -- loads the ACTUAL built remote_access_audit
 * plugin via PluginHandle::load and drives `list` through yuzu::agent::LocalDispatcher, so the real
 * per-OS leg executes on the build host. Modelled on test_mgmt_posture_local_dispatcher.cpp.
 *
 * UNGUARDED TU on all three platforms; only the per-OS assertions inside a test body are
 * #if'd. The live-host cases assert shape (status row first, fixed source rows, every config
 * key once, per-kind field counts, fingerprint form), never host-specific values: which
 * accounts and keys a CI runner holds is unknown. The fault-injection cases live in
 * test_remote_access_audit_legs.cpp; the [seam] cases here pin execute_list, the status/result
 * pairing and the nowhere-in-the-output privacy contract without loading the plugin.
 */
#include <catch2/catch_test_macros.hpp>

#include <yuzu/agent/plugin_loader.hpp>
#include <yuzu/plugin.h>
#include <yuzu/plugin.hpp>

#include "local_dispatcher.hpp"

#include "remote_access_audit_legs.hpp" // execute_list / report_list

#include <algorithm>
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

/// Under `meson test` (MESON_BUILD_ROOT is always set) a missing plugin means the
/// build is genuinely broken and must NOT report "All tests passed".
#if defined(_MSC_VER)
#pragma warning(push)
#pragma warning(disable : 4996)
#endif
void require_plugin_or_skip() {
    if (std::getenv("MESON_BUILD_ROOT") != nullptr) {
        FAIL("remote_access_audit plugin library not found under meson test -- the plugin did not "
             "build, or link_depends is not forcing it to build before this test runs");
    }
    WARN("remote_access_audit plugin library not found -- skipping the LocalDispatcher round-trip");
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
    const std::string lib_name = std::string{"remote_access_audit"} + kPluginExt;
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
        candidates.emplace_back(fs::path{build_root} / "agents" / "plugins" / "remote_access_audit" /
                                lib_name);
    candidates.emplace_back(fs::path{"agents"} / "plugins" / "remote_access_audit" / lib_name);
    candidates.emplace_back(fs::path{".."} / "agents" / "plugins" / "remote_access_audit" / lib_name);
    for (const char* b : {"build-macos", "build-linux", "build-windows"})
        candidates.emplace_back(fs::path{b} / "agents" / "plugins" / "remote_access_audit" / lib_name);
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

/// Seam probes: execute_list over legs that throw / report a refused read.
int throwing_leg(yuzu::CommandContext&) { throw std::runtime_error("probe: the leg threw"); }

int denied_leg(yuzu::CommandContext& ctx) {
    yuzu::remote_access_audit::report_list(ctx, {}, yuzu::remote_access_audit::StatusState::permission_denied,
                              "linux:remote_access_audit:sshd_config:permission_denied");
    return 0;
}

/// A constrained read: the status row names a fixed token, and no data row follows.
int constrained_leg(yuzu::CommandContext& ctx) {
    yuzu::remote_access_audit::report_list(ctx, {},
                                           yuzu::remote_access_audit::StatusState::constrained,
                                           "linux:remote_access_audit:keys:network_mount_skipped");
    return 0;
}

/// Writes its status row, THEN throws while "emitting data": the catch arm appends a second.
int row_then_throw_leg(yuzu::CommandContext& ctx) {
    yuzu::remote_access_audit::report_list(ctx, {"source|sshd_config|absent|-"}, yuzu::remote_access_audit::StatusState::supported, "");
    throw std::runtime_error("probe: threw after the status row");
}

template <yuzu::remote_access_audit::LegFn Leg>
int seam_execute(YuzuCommandContext* raw, const char* action, const YuzuParam* /*params*/,
                 std::size_t /*param_count*/) {
    yuzu::CommandContext ctx{raw};
    return yuzu::remote_access_audit::execute_list(ctx, action, Leg, "linux:leg:exception");
}


/// A config whose AuthorizedKeysFile names a distinctive path, reported through the real
/// report_list exactly as list_posix would.
int akf_leg(yuzu::CommandContext& ctx) {
    using namespace yuzu::remote_access_audit;
    SshdConfigState st;
    parse_sshd_config("AuthorizedKeysFile /etc/ssh/zq-distinctive-9731/authorized_keys %h/.ssh/zq-9731\n",
                      "sshd_config", st, [](const IncludeDirective&) {});
    bool ov = false;
    report_list(ctx, config_rows(st, true, ov), StatusState::supported, "");
    return 0;
}

std::vector<std::string> fields(const std::string& row) {
    std::vector<std::string> f;
    std::string cur;
    for (std::size_t i = 0; i < row.size(); ++i) {
        if (row[i] == '\\' && i + 1 < row.size() && row[i + 1] == '|') {
            cur += '|';
            ++i;
        } else if (row[i] == '|') {
            f.push_back(cur);
            cur.clear();
        } else {
            cur += row[i];
        }
    }
    f.push_back(cur);
    return f;
}

bool in(const std::string& v, std::initializer_list<const char*> set) {
    return std::ranges::any_of(set, [&](const char* s) { return v == s; });
}

} // namespace

// MUTATION: flip a leg's declared support without changing the code behind it (Windows to
// SUPPORTED while the leg is still the placeholder, Linux back to SUPPORTED although the unprivileged
// agent usually cannot open other users' homes, macOS to PLANNED) -> the exact-level checks fail. The mechanism/notes prose is not pinned: the capability-matrix check gates it.
TEST_CASE("remote_access_audit plugin: the descriptor declares Linux constrained, macOS supported and Windows planned",
          "[remote_access_audit][descriptors]") {
    auto plugin = load_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }
    CHECK(std::string_view{plugin->descriptor->name} == "remote_access_audit");
    REQUIRE(plugin->descriptor->action_descriptors != nullptr);
    REQUIRE(plugin->descriptor->action_descriptor_count == 1);
    const auto& d = plugin->descriptor->action_descriptors[0];
    CHECK(std::string_view{d.action} == "list");
    CHECK(d.linux_leg.support == YUZU_SUPPORT_CONSTRAINED);
    CHECK(d.linux_leg.rung == 2);
    CHECK(d.macos_leg.support == YUZU_SUPPORT_SUPPORTED);
    CHECK(d.macos_leg.rung == 2);
    CHECK(d.windows_leg.support == YUZU_SUPPORT_PLANNED);
    CHECK(d.windows_leg.rung == 1);
}

TEST_CASE("remote_access_audit plugin: an unknown action is refused with one non-status line",
          "[remote_access_audit][dispatcher]") {
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

TEST_CASE("remote_access_audit plugin: status row first, fixed source and config rows, well-formed rows",
          "[remote_access_audit][dispatcher]") {
    auto plugin = load_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }
    yuzu::agent::LocalDispatcher dispatcher;
    const auto result = dispatcher.run(plugin->descriptor, "list");
    CHECK(result.rc == 0); // a degraded read is never a failed command
    CHECK_FALSE(result.truncated);
    const auto rows = captured_rows(result.captured);
    REQUIRE_FALSE(rows.empty());
    INFO("status row: " << rows[0]);
    REQUIRE(rows[0].starts_with("status|list|"));
    CHECK(std::ranges::count_if(rows, [](const std::string& r) { return r.starts_with("status|"); }) == 1);

    // The paired result status follows the status row's state.
    if (rows[0].starts_with("status|list|supported|")) {
        CHECK(result.result_status == YUZU_RESULT_STATUS_OK);
        CHECK(result.result_completeness == YUZU_RESULT_COMPLETENESS_FULL);
    } else if (rows[0].starts_with("status|list|constrained|")) {
        CHECK(result.result_status == YUZU_RESULT_STATUS_CONSTRAINED);
        CHECK(result.result_completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
    } else if (rows[0].starts_with("status|list|permission_denied|")) {
        CHECK(result.result_status == YUZU_RESULT_STATUS_PERMISSION_DENIED);
        CHECK(result.result_completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
    } else {
        REQUIRE(rows[0].starts_with("status|list|unsupported|"));
        CHECK(result.result_status == YUZU_RESULT_STATUS_UNAVAILABLE);
        CHECK(result.result_completeness == YUZU_RESULT_COMPLETENESS_UNKNOWN);
    }

#if defined(_WIN32)
    // PLANNED leg: exactly one row and UNAVAILABLE/UNKNOWN.
    // MUTATION: wiring any read here changes this row.
    REQUIRE(rows.size() == 1);
    CHECK(rows[0] == "status|list|unsupported|windows:planned");
    CHECK(result.result_provenance == "windows:planned");
#else
    REQUIRE(rows.size() >= 1 + 3 + 13);
    CHECK(rows[1].starts_with("source|sshd_config|"));
    CHECK(rows[2].starts_with("source|homes|"));
    CHECK(rows[3].starts_with("source|service|"));
    for (std::size_t i = 1; i <= 3; ++i)
        CHECK(in(fields(rows[i])[2], {"read", "absent", "refused", "failed"}));
    // The homes row alone carries a fifth field (entries the eligibility probe refused; `-` on Linux).
    CHECK(fields(rows[2]).size() == 5);
    // The production wiring, asserted only on what is environment-stable. sshd_config is world-readable
    // on every Mac and is either there or not on a CI image; a path that was mis-bound would read `failed`.
    CHECK(in(fields(rows[1])[2], {"read", "absent"}));
#if defined(__APPLE__)
    // launchctl print-disabled answers an unprivileged caller, so the service source IS read and the one
    // row names the label and the mechanism. MUTATION: a wrong tool path or arguments drops this row.
    CHECK(fields(rows[3])[2] == "read");
    const auto svc = std::ranges::find_if(rows, [](const std::string& r) { return r.starts_with("service|"); });
    REQUIRE(svc != rows.end());
    const auto sf = fields(*svc);
    CHECK(sf[1] == "com.openssh.sshd");
    CHECK(in(sf[2], {"enabled", "disabled", "unknown"}));
    CHECK(sf[3] == "launchctl_print_disabled");
    // the macOS home roots are /Users and /var/root: the eligibility probe is wired, so the skipped count is a number
    CHECK(fields(rows[2])[4] != "-");
#else
    // systemctl may not exist on a CI image (a failed service source, no service rows) or exist but answer
    // for no unit (a container without a bus: failed, the three units reported with an unknown state);
    // when it ran, every row is for one of the three units and names the mechanism.
    CHECK(fields(rows[2])[4] == "-"); // Linux has no eligibility probe, so nothing is detectably skipped
    CHECK(in(fields(rows[3])[2], {"read", "failed"}));
    const auto n_svc = std::ranges::count_if(rows, [](const std::string& r) { return r.starts_with("service|"); });
    if (fields(rows[3])[2] == "read")
        CHECK(n_svc == 3);
    else
        CHECK((n_svc == 0 || n_svc == 3));
    for (const auto& r : rows) {
        if (!r.starts_with("service|"))
            continue;
        const auto sf = fields(r);
        CHECK(in(sf[1], {"ssh.service", "sshd.service", "ssh.socket"}));
        CHECK(sf[3] == "systemctl_is_enabled");
    }
#endif
#if defined(__APPLE__)
    // MUTATION: binding the macOS root home as /var/root (a link to private/var/root on stock macOS)
    // makes the home open ELOOP and puts `homes:eloop` in this row.
    CHECK(rows[0].find("homes:eloop") == std::string::npos);
    // `os == "macos"` also selects the Data-volume alias guard; a mistyped value would change the
    // token prefix of every failure. The supported case carries `-`.
    CHECK((fields(rows[0])[3] == "-" || fields(rows[0])[3].starts_with("macos:")));
#endif

    // every allowlisted key exactly once, in row order
    std::vector<std::string> config_keys;
    for (const auto& r : rows) {
        if (r.starts_with("config|"))
            config_keys.push_back(fields(r)[1]);
    }
    CHECK(config_keys ==
          std::vector<std::string>{"permitrootlogin", "passwordauthentication",
                                   "pubkeyauthentication", "kbdinteractiveauthentication",
                                   "permitemptypasswords", "usepam", "port", "authorizedkeysfile",
                                   "allowusers_count", "allowgroups_count", "denyusers_count",
                                   "denygroups_count", "match_blocks"});

    for (std::size_t i = 4; i < rows.size(); ++i) {
        INFO("row " << i << ": " << rows[i]);
        CHECK(rows[i].find('\0') == std::string::npos);
        CHECK(yuzu::shared::count_invalid_wire_bytes(rows[i]) == 0);
        const auto f = fields(rows[i]);
        if (f[0] == "config" || f[0] == "service") {
            CHECK(f.size() == 4);
        } else if (f[0] == "file") {
            REQUIRE(f.size() == 7);
            CHECK(in(f[2], {"authorized_keys", "authorized_keys2", "custom"}));
            CHECK(in(f[3], {"read", "absent", "refused", "failed"}));
        } else if (f[0] == "key") {
            REQUIRE(f.size() == 8);
            // SHA256: plus 43 unpadded base64 characters, exactly as ssh-keygen -l prints it
            CHECK(f[4].size() == 7 + 43);
            CHECK(f[4].starts_with("SHA256:"));
            CHECK(f[4].find('=') == std::string::npos);
        } else {
            FAIL("unexpected row kind: " << f[0]);
        }
    }
#endif
}

// P1: nothing but a count of the AuthorizedKeysFile tokens ever reaches the wire.
TEST_CASE("remote_access_audit execute seam: a configured key-file path appears nowhere in the output",
          "[remote_access_audit][dispatcher][seam]") {
    yuzu::agent::LocalDispatcher dispatcher;
    YuzuPluginDescriptor leg{};
    leg.execute = &seam_execute<&akf_leg>;
    const auto r = dispatcher.run(&leg, "list");
    CHECK(r.rc == 0);
    CHECK(r.captured.find("zq-distinctive-9731") == std::string::npos);
    CHECK(r.captured.find("zq-9731") == std::string::npos);
    CHECK(r.captured.find("config|authorizedkeysfile|custom:2|sshd_config") != std::string::npos);
    CHECK(r.result_status == YUZU_RESULT_STATUS_OK);
    // MUTATION: pairing `supported` with PARTIAL (or swapping its row in the table) fails here.
    CHECK(r.result_completeness == YUZU_RESULT_COMPLETENESS_FULL);
    CHECK(captured_rows(r.captured)[0] == "status|list|supported|-");
}

TEST_CASE("remote_access_audit execute seam: unknown action is escaped; a throwing leg is contained; a "
          "refused read pairs PERMISSION_DENIED with PARTIAL",
          "[remote_access_audit][dispatcher][seam]") {
    yuzu::agent::LocalDispatcher dispatcher;

    YuzuPluginDescriptor throwing{};
    throwing.execute = &seam_execute<&throwing_leg>;

    const auto thrown = dispatcher.run(&throwing, "list");
    CHECK(thrown.rc == 0); // contained, never unwound
    const auto trows = captured_rows(thrown.captured);
    REQUIRE(trows.size() == 1);
    CHECK(trows[0] == "status|list|unsupported|linux:leg:exception");
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

    // Invalid UTF-8 bytes are replaced first (scrub_wire_bytes); a valid sequence survives.
    const auto binary = dispatcher.run(&throwing, "bad\xff!");
    CHECK(binary.rc == 1);
    const auto brows = captured_rows(binary.captured);
    REQUIRE(brows.size() == 1);
    CHECK(brows[0] == "unknown action: bad?!");

    YuzuPluginDescriptor denied{};
    denied.execute = &seam_execute<&denied_leg>;
    const auto d = dispatcher.run(&denied, "list");
    CHECK(d.rc == 0);
    const auto drows = captured_rows(d.captured);
    REQUIRE(drows.size() == 1);
    CHECK(drows[0] == "status|list|permission_denied|linux:remote_access_audit:sshd_config:permission_denied");
    CHECK(d.result_status == YUZU_RESULT_STATUS_PERMISSION_DENIED);
    CHECK(d.result_completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);

    // The constrained pairing, pinned off the host: CONSTRAINED with PARTIAL, token on the row.
    YuzuPluginDescriptor constrained{};
    constrained.execute = &seam_execute<&constrained_leg>;
    const auto c = dispatcher.run(&constrained, "list");
    CHECK(c.rc == 0);
    const auto crows = captured_rows(c.captured);
    REQUIRE(crows.size() == 1);
    CHECK(crows[0] ==
          "status|list|constrained|linux:remote_access_audit:keys:network_mount_skipped");
    CHECK(c.result_status == YUZU_RESULT_STATUS_CONSTRAINED);
    CHECK(c.result_completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);

    // A leg that wrote its status row and then threw: two status rows, the LAST wins.
    YuzuPluginDescriptor late{};
    late.execute = &seam_execute<&row_then_throw_leg>;
    const auto l = dispatcher.run(&late, "list");
    CHECK(l.rc == 0);
    const auto lrows = captured_rows(l.captured);
    REQUIRE(lrows.size() == 3);
    CHECK(lrows[0] == "status|list|supported|-");
    CHECK(lrows[2] == "status|list|unsupported|linux:leg:exception");
    CHECK(l.result_status == YUZU_RESULT_STATUS_UNAVAILABLE);
}
