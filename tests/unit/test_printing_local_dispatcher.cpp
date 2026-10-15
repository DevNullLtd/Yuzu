/**
 * test_printing_local_dispatcher.cpp — loads the ACTUAL built `printing`
 * plugin (printing.dylib/.so/.dll) via `PluginHandle::load` and drives it
 * through `yuzu::agent::LocalDispatcher` (power_health's local-dispatcher
 * pattern), exercising `printers`/`jobs`/`clear_queue`'s real per-OS legs
 * end to end on the build host.
 *
 * DELIBERATELY UNGUARDED — no `#ifdef` gating this whole TU to one platform
 * (per `test_power_health_local_dispatcher.cpp`'s own header comment: a
 * platform-guarded dispatcher TU is exactly the shape that hid a dead
 * Windows leg on PR6.1-b). Runs and exercises the real leg on every host;
 * a host with no CUPS socket / no `yuzu_test` print queue SKIPs by NAME,
 * never silently.
 *
 * NEVER cancels a real job — `clear_queue`'s live-effect cases below only
 * target job ids that cannot resolve to a real queued job (a missing param,
 * `job_id=all`, or a numeric id against a printer name that does not
 * exist), so every assertion is on the plugin's own validation/error
 * shaping, not on any live cupsd/winspool mutation.
 *
 * POSIX LIVE COVERAGE has three cases, deliberately not merged, because the
 * root-cause bug this file exists to prevent is a live path that SKIPs on
 * every host with the suite still green:
 *   1. Live read (printers + jobs) over the real per-OS leg — unconditional
 *      whenever a CUPS Unix socket exists (it does on this Mac and on any
 *      CUPS host); SKIPs by name ONLY when no socket path exists at all,
 *      never for want of a populated queue.
 *   2. Live clear_queue negative, over the real socket WITH the
 *      `Authorization: PeerCred` header — unconditional; on POSIX it stops at
 *      the pre-cancel Get-Jobs (the printer cannot exist), so it never sends
 *      a Cancel-Job and cancels nothing. The bind-then-cancel ladder itself is
 *      covered by the pure run_clear_queue() tests in test_printing_parsers.cpp.
 *   3. Populated-queue assertion (a real `yuzu_test` row) — the ONLY case
 *      in this file allowed to SKIP, and only by name.
 */
#include <catch2/catch_test_macros.hpp>

#include <yuzu/agent/plugin_loader.hpp>
#include <yuzu/plugin.h>
#include <yuzu/plugin.hpp>

#include "local_dispatcher.hpp"

#include <cstdlib>
#include <filesystem>
#include <optional>
#include <sstream>
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

std::vector<std::string> split_fields(const std::string& row) {
    std::vector<std::string> f;
    std::string cur;
    for (char c : row) {
        if (c == '|') {
            f.push_back(cur);
            cur.clear();
        } else {
            cur.push_back(c);
        }
    }
    f.push_back(cur);
    return f;
}

void require_plugin_or_skip() {
    if (std::getenv("MESON_BUILD_ROOT") != nullptr) {
        FAIL("printing plugin library not found under meson test — the plugin did not build, "
             "or link_depends is not forcing it to build before this test runs");
    }
    WARN("printing plugin library not found -- skipping LocalDispatcher round-trip test (run "
         "from the build root, or via `meson test`, to exercise it)");
}

#if defined(_WIN32)
constexpr const char* kPluginExt = ".dll";
#elif defined(__APPLE__)
constexpr const char* kPluginExt = ".dylib";
#else
constexpr const char* kPluginExt = ".so";
#endif

fs::path find_printing_plugin() {
    const std::string lib_name = std::string{"printing"} + kPluginExt;

    std::vector<fs::path> candidates;
    if (auto* build_root = std::getenv("MESON_BUILD_ROOT")) {
        candidates.emplace_back(fs::path{build_root} / "agents" / "plugins" / "printing" / lib_name);
    }
    candidates.emplace_back(fs::path{"agents"} / "plugins" / "printing" / lib_name);
    candidates.emplace_back(fs::path{".."} / "agents" / "plugins" / "printing" / lib_name);
    candidates.emplace_back(fs::path{"build-macos"} / "agents" / "plugins" / "printing" / lib_name);
    candidates.emplace_back(fs::path{"build-windows"} / "agents" / "plugins" / "printing" / lib_name);
    candidates.emplace_back(fs::path{"build-linux"} / "agents" / "plugins" / "printing" / lib_name);

    for (const auto& p : candidates) {
        std::error_code ec;
        if (fs::exists(p, ec) && !ec)
            return fs::absolute(p, ec);
    }
    return {};
}

struct LoadedPlugin {
    yuzu::agent::PluginHandle handle;
    const YuzuPluginDescriptor* descriptor;
};

#if !defined(_WIN32)
// Mirrors printing_plugin.cpp's own candidate list — used ONLY to decide
// whether the live-read/live-clear_queue cases below may SKIP (they may,
// per the package spec, ONLY when no CUPS Unix socket exists at all; never
// for want of a populated queue). Not a build dependency on the plugin's
// internals — a plain filesystem probe.
bool any_cups_socket_present() {
    static constexpr const char* kCandidates[] = {
        "/private/var/run/cupsd",
        "/var/run/cupsd",
        "/run/cups/cups.sock",
        "/var/run/cups/cups.sock",
    };
    for (const char* p : kCandidates) {
        std::error_code ec;
        if (fs::exists(p, ec) && !ec)
            return true;
    }
    return false;
}
#endif

std::optional<LoadedPlugin> load_printing_plugin() {
    auto plugin_path = find_printing_plugin();
    if (plugin_path.empty())
        return std::nullopt;
    auto handle = yuzu::agent::PluginHandle::load(plugin_path);
    if (!handle.has_value())
        return std::nullopt;
    const auto* descriptor = handle->descriptor();
    if (!descriptor)
        return std::nullopt;
    return LoadedPlugin{std::move(*handle), descriptor};
}

} // namespace

TEST_CASE("printing plugin: ABI4 descriptors declare all three OS legs for every action, never "
          "#ifdef'd out (plugin.h:115-136)",
          "[printing][descriptors]") {
    auto plugin = load_printing_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }

    REQUIRE(plugin->descriptor->action_descriptor_count == 3);
    REQUIRE(plugin->descriptor->action_descriptors != nullptr);

    for (std::size_t i = 0; i < plugin->descriptor->action_descriptor_count; ++i) {
        const auto& d = plugin->descriptor->action_descriptors[i];
        INFO("action: " << (d.action ? d.action : "<null>"));
        CHECK(d.linux_leg.support != YUZU_SUPPORT_UNDECLARED);
        CHECK(d.macos_leg.support != YUZU_SUPPORT_UNDECLARED);
        CHECK(d.windows_leg.support != YUZU_SUPPORT_UNDECLARED);
    }
}

// Case 1 (live read, unconditional): with a CUPS Unix socket present (or
// on Windows, always — winspool has no socket concept), `printers` MUST
// dispatch against the real per-OS leg and produce rc 0 plus a
// well-formed row. Row shapes: 2 fields ("printer|none" — no printers),
// 3 fields ("printer|unavailable|<token>" — the read itself failed, still
// rc 0 per this plugin's read-never-fails contract), or 8 fields (a
// populated printer row: printer|name|state|state_reasons|is_default|
// make_model|uri|queued_jobs). This case never SKIPs for want of a
// populated queue — only CHANGE 4's dedicated case 3 below does that.
TEST_CASE("printing plugin: printers action — live read over the real per-OS leg, rc 0 and a "
          "well-formed row, unconditional whenever a CUPS socket exists",
          "[printing][actions]") {
    auto plugin = load_printing_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }
#if !defined(_WIN32)
    if (!any_cups_socket_present()) {
        SKIP("no CUPS Unix socket found on this host — printers live read requires one");
        return;
    }
#endif

    yuzu::agent::LocalDispatcher dispatcher;
    auto result = dispatcher.run(plugin->descriptor, "printers");
    CHECK(result.rc == 0);

    const auto rows = captured_rows(result.captured);
    REQUIRE_FALSE(rows.empty());
    for (const auto& r : rows) {
        const auto f = split_fields(r);
        REQUIRE(f[0] == "printer");
        REQUIRE((f.size() == 2 || f.size() == 3 || f.size() == 8));
    }
}

// Case 1 (live read, unconditional) — jobs half. Same shape rules as
// printers above, but a populated job row is 8 fields: job|printer|
// job_id|owner|document|status|submitted_at|size_bytes; a read failure
// surfaces as "job|unavailable|<token>" (round-3 review Minor: do_jobs
// previously emitted the printers action's "printer|" discriminator by
// copy-paste, fixed on both the Windows and POSIX legs).
TEST_CASE("printing plugin: jobs action — live read over the real per-OS leg, rc 0 and a "
          "well-formed row, unconditional whenever a CUPS socket exists",
          "[printing][actions]") {
    auto plugin = load_printing_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }
#if !defined(_WIN32)
    if (!any_cups_socket_present()) {
        SKIP("no CUPS Unix socket found on this host — jobs live read requires one");
        return;
    }
#endif

    yuzu::agent::LocalDispatcher dispatcher;
    auto result = dispatcher.run(plugin->descriptor, "jobs");
    CHECK(result.rc == 0);

    const auto rows = captured_rows(result.captured);
    REQUIRE_FALSE(rows.empty());
    for (const auto& r : rows) {
        const auto f = split_fields(r);
        REQUIRE(f[0] == "job");
        REQUIRE((f.size() == 2 || f.size() == 3 || f.size() == 8));
    }
}

// Case 3 (populated-queue assertion, SKIP-by-name permitted): the ONLY
// case in this file allowed to SKIP. Re-runs printers looking specifically
// for a live `yuzu_test` row (8 fields, name == "yuzu_test") — present
// only after a manual `capture.sh --phase-b` run leaves the queue up, or
// on a host that happens to have one configured. Every other host SKIPs
// by name, never silently.
TEST_CASE("printing plugin: printers action — a populated yuzu_test row is observed when the "
          "queue exists; SKIP by name otherwise",
          "[printing][actions]") {
    auto plugin = load_printing_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }

    yuzu::agent::LocalDispatcher dispatcher;
    auto result = dispatcher.run(plugin->descriptor, "printers");
    CHECK(result.rc == 0);

    const auto rows = captured_rows(result.captured);
    bool saw_yuzu_test = false;
    for (const auto& r : rows) {
        const auto f = split_fields(r);
        if (f.size() == 8 && f[0] == "printer" && f[1] == "yuzu_test")
            saw_yuzu_test = true;
    }

    if (!saw_yuzu_test) {
        SKIP("no cupsd socket / no yuzu_test queue on this host — live printer row not observed");
        return;
    }
}

TEST_CASE("printing plugin: clear_queue — missing job_id is rc 1 error|invalid_job_id, before "
          "any I/O",
          "[printing][actions][clear_queue]") {
    auto plugin = load_printing_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }

    const YuzuParam params[] = {{"printer", "yuzu_test"}};
    yuzu::agent::LocalDispatcher dispatcher;
    auto result = dispatcher.run(plugin->descriptor, "clear_queue", params);
    CHECK(result.rc == 1);

    const auto rows = captured_rows(result.captured);
    REQUIRE_FALSE(rows.empty());
    const auto f = split_fields(rows.front());
    REQUIRE(f.size() == 5);
    CHECK(f[0] == "clear_queue");
    CHECK(f[3] == "error");
    CHECK(f[4] == "invalid_job_id");
}

TEST_CASE("printing plugin: clear_queue — missing printer is rc 1 error|missing_printer with a "
          "\"-\" printer field, before any I/O",
          "[printing][actions][clear_queue]") {
    auto plugin = load_printing_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }

    const YuzuParam params[] = {{"job_id", "1"}};
    yuzu::agent::LocalDispatcher dispatcher;
    auto result = dispatcher.run(plugin->descriptor, "clear_queue", params);
    CHECK(result.rc == 1);

    const auto rows = captured_rows(result.captured);
    REQUIRE_FALSE(rows.empty());
    const auto f = split_fields(rows.front());
    REQUIRE(f.size() == 5);
    CHECK(f[0] == "clear_queue");
    CHECK(f[1] == "-");
    CHECK(f[3] == "error");
    CHECK(f[4] == "missing_printer");
    CHECK(result.result_status == YUZU_RESULT_STATUS_UNAVAILABLE);
    CHECK(result.result_completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
}

TEST_CASE("printing plugin: clear_queue — job_id=\"all\" is rc 1, never a purge-all path",
          "[printing][actions][clear_queue]") {
    auto plugin = load_printing_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }

    const YuzuParam params[] = {{"printer", "yuzu_test"}, {"job_id", "all"}};
    yuzu::agent::LocalDispatcher dispatcher;
    auto result = dispatcher.run(plugin->descriptor, "clear_queue", params);
    CHECK(result.rc == 1);

    const auto rows = captured_rows(result.captured);
    REQUIRE_FALSE(rows.empty());
    const auto f = split_fields(rows.front());
    CHECK(f[0] == "clear_queue");
    CHECK(f[3] == "error");
}

// Case 2 (live clear_queue negative, unconditional): dispatched for real
// over whatever socket/leg this host has — on POSIX this exercises the
// pre-cancel Get-Jobs round trip including the `Authorization: PeerCred`
// header (do_clear_queue attaches it unconditionally whenever a socket is
// found) with no sudo and without cancelling anything: the target printer
// cannot exist, so it never reaches Cancel-Job. Asserted on the PARSED outcome the plugin
// actually returns, never a value hardcoded ahead of the real dispatch.
TEST_CASE("printing plugin: clear_queue — live negative round trip over the real per-OS leg "
          "(POSIX: with the Authorization: PeerCred header) — rc 1, never a crash, never a "
          "successful cancel",
          "[printing][actions][clear_queue]") {
    auto plugin = load_printing_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }

    const YuzuParam params[] = {{"printer", "yuzu_test_definitely_does_not_exist"}, {"job_id", "1"}};
    yuzu::agent::LocalDispatcher dispatcher;
    auto result = dispatcher.run(plugin->descriptor, "clear_queue", params);
    CHECK(result.rc == 1);

    const auto rows = captured_rows(result.captured);
    REQUIRE_FALSE(rows.empty());
    const auto f = split_fields(rows.front());
    REQUIRE(f.size() == 5);
    CHECK(f[0] == "clear_queue");
    CHECK((f[3] == "not_found" || f[3] == "refused" || f[3] == "error"));
    // The shell must pair the outcome with the matching status/completeness.
    if (f[3] == "not_found") {
        CHECK(result.result_status == YUZU_RESULT_STATUS_UNAVAILABLE);
        CHECK(result.result_completeness == YUZU_RESULT_COMPLETENESS_FULL);
    } else if (f[3] == "refused") {
        CHECK(result.result_status == YUZU_RESULT_STATUS_PERMISSION_DENIED);
        CHECK(result.result_completeness == YUZU_RESULT_COMPLETENESS_FULL);
    } else {
        CHECK(result.result_status == YUZU_RESULT_STATUS_UNAVAILABLE);
        CHECK(result.result_completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
    }
}
