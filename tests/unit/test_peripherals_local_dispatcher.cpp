/**
 * test_peripherals_local_dispatcher.cpp — loads the ACTUAL built peripherals
 * plugin (peripherals.dylib / .so / .dll) via PluginHandle::load and drives
 * it through yuzu::agent::LocalDispatcher, exercising the real per-OS legs
 * on the build host.
 *
 * FIXTURE PROVENANCE CONVENTION (wave-wide, ws91). This TU does not itself
 * ship any fixture file -- it drives the built plugin's real per-OS legs
 * directly against the live host instead (see the file banner above), so
 * there is nothing here to fixture against; the convention is recorded here
 * because every wave-1 sibling package in ws91 uses it and the pure-parser
 * test TUs (test_peripherals_{linux,macos,win}_parsers.cpp) are where the
 * fixture-backed cases actually land. A captured fixture under
 * tests/unit/fixtures/wave9/probes/ carries a
 * sibling `<name>.provenance.txt` with these lines, in order:
 *
 *   host:      the machine the capture ran on (hostname or CI runner id)
 *   os:        exact OS/kernel version string
 *   identity:  the account the capture ran as (root/admin/unprivileged, and
 *              which one -- matters for a permission-dependent read)
 *   command:   the exact command whose output was captured
 *   date:      capture date (YYYY-MM-DD)
 *   status:    REAL CAPTURE, or RECONSTRUCTION (<reason>; <ABI doc cited>)
 *              for a fixture built from a specification rather than a live
 *              run -- never presented as a capture it is not
 *   lines:     <n> (budget <m>) -- the fixture's line count against its
 *              stated budget, so a runaway capture is visible in the diff
 *
 * RUNS ON ALL THREE PLATFORMS, deliberately and from the outset -- no
 * `#ifndef _WIN32` guard on the whole TU. A platform-guarded dispatcher TU is
 * exactly how a sibling plugin once shipped a Windows leg that had been
 * compiled out entirely and stayed green (#test_disk_actions_local_dispatcher
 * .cpp's own header makes the same point). LocalDispatcher and PluginHandle
 * are both platform-neutral, so nothing technical requires the exclusion.
 *
 * SCOPE. The cases below also accept the `<kind>|unavailable|<token>` row as
 * a valid shape (a genuine leg-level failure, e.g. a permissions error) in
 * addition to the real per-OS reads Wave 2 (P91-6+) landed, so the suite
 * stays green on a host where a leg legitimately cannot attempt the read,
 * and any other regression still fails. There is deliberately NO
 * host-specific count/name assertion anywhere in this file: CI's
 * macOS suite runs on `yuzu-bigmags-macos` (.github/workflows/ci.yml:1845;
 * no --suite filter at :2059), a shared, unknown-hardware runner.
 */
#include <catch2/catch_test_macros.hpp>

#include <yuzu/agent/plugin_loader.hpp>
#include <yuzu/plugin.h>
#include <yuzu/plugin.hpp>

#include "local_dispatcher.hpp"

#include "peripherals_legs.hpp"
#include "peripherals_parsers.hpp"

#include <cstdlib>
#include <filesystem>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace fs = std::filesystem;

namespace {

/// Escape-aware field split. yuzu::util::safe_output_field escapes a literal
/// '|' as '\|', so a naive split('|') overcounts fields on any row whose text
/// happens to contain a pipe.
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
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (!line.empty()) out.push_back(line);
    }
    return out;
}

/// Under `meson test` (MESON_BUILD_ROOT is always set) a missing plugin means
/// the build is genuinely broken and must NOT report "All tests passed".
///
/// getenv (not _dupenv_s) matches every sibling *_local_dispatcher.cpp's
/// identical helper -- MSVC's C4996 is silenced locally rather than
/// diverging from that shared idiom (the-rig MSVC verification, P91-7).
#if defined(_MSC_VER)
#pragma warning(push)
#pragma warning(disable : 4996)
#endif
void require_plugin_or_skip() {
    if (std::getenv("MESON_BUILD_ROOT") != nullptr) {
        FAIL("peripherals plugin library not found under meson test -- the plugin did not build, "
             "or link_depends is not forcing it to build before this test runs");
    }
    WARN("peripherals plugin library not found -- skipping the LocalDispatcher round-trip");
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

fs::path find_peripherals_plugin() {
    const std::string lib_name = std::string{"peripherals"} + kPluginExt;
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
        candidates.emplace_back(fs::path{build_root} / "agents" / "plugins" / "peripherals" /
                                lib_name);
    candidates.emplace_back(fs::path{"agents"} / "plugins" / "peripherals" / lib_name);
    candidates.emplace_back(fs::path{".."} / "agents" / "plugins" / "peripherals" / lib_name);
    for (const char* b : {"build-macos", "build-linux", "build-windows"})
        candidates.emplace_back(fs::path{b} / "agents" / "plugins" / "peripherals" / lib_name);
    for (const auto& c : candidates)
        if (std::error_code ec; fs::exists(c, ec)) return c;
    return {};
}

struct LoadedPlugin {
    yuzu::agent::PluginHandle handle;
    const YuzuPluginDescriptor* descriptor{nullptr};
    explicit operator bool() const { return descriptor != nullptr; }
};

std::optional<LoadedPlugin> load_peripherals_plugin() {
    auto path = find_peripherals_plugin();
    if (path.empty()) return std::nullopt;
    // PluginHandle::load returns std::expected<PluginHandle, LoadError>.
    auto loaded = yuzu::agent::PluginHandle::load(path);
    if (!loaded) return std::nullopt;
    const auto* d = loaded->descriptor();
    if (!d) return std::nullopt;
    return LoadedPlugin{std::move(*loaded), d};
}

/// The three actions and their documented field counts (kind token included),
/// used to drive the per-action loop below instead of repeating it 3x.
struct ActionShape {
    const char* action;
    const char* kind;
    std::size_t field_count;
};
constexpr ActionShape kActions[] = {
    {"usb", "usb", 11},
    {"pci", "pci", 9},
    {"thunderbolt", "thunderbolt", 8},
};

bool is_hex(const std::string& s, std::size_t n) {
    if (s.size() != n) return false;
    for (char c : s)
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
    return true;
}

} // namespace

TEST_CASE("peripherals plugin: every action's row shape is well-formed",
          "[peripherals][actions]") {
    auto plugin = load_peripherals_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }
    yuzu::agent::LocalDispatcher dispatcher;

    for (const auto& a : kActions) {
        INFO("action: " << a.action);
        auto result = dispatcher.run(plugin->descriptor, a.action);
        CHECK(result.rc == 0); // a degraded read is never a failed command

        const auto rows = captured_rows(result.captured);
        // Every leg emits at least one row, including an `unavailable` one on
        // a genuine leg-level failure: a consumer reading rows must never see
        // silence and infer "this host has no such devices".
        REQUIRE_FALSE(rows.empty());

        for (const auto& r : rows) {
            INFO("row: " << r);
            const auto f = split_fields_escape_aware(r);
            CHECK(f[0] == a.kind);
            if (f.size() == 2) {
                // <kind>|none -- the leg read cleanly and found nothing.
                CHECK(f[1] == "none");
            } else if (f.size() == 3) {
                // <kind>|unavailable|<token> -- a genuine leg-level failure
                // (see mark_result_read, peripherals_legs.hpp).
                CHECK(f[1] == "unavailable");
            } else {
                // A real row: the documented field count for this action.
                REQUIRE(f.size() == a.field_count);
            }
        }
    }
}

TEST_CASE("peripherals plugin: usb hex fields are lowercase and fixed-width",
          "[peripherals][actions]") {
    auto plugin = load_peripherals_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }
    yuzu::agent::LocalDispatcher dispatcher;
    auto result = dispatcher.run(plugin->descriptor, "usb");
    const auto rows = captured_rows(result.captured);
    REQUIRE_FALSE(rows.empty());
    for (const auto& r : rows) {
        const auto f = split_fields_escape_aware(r);
        if (f.size() != 11) continue; // skip none/unavailable placeholder rows
        INFO("row: " << r);
        CHECK(is_hex(f[2], 4)); // vendor_id
        CHECK(is_hex(f[3], 4)); // product_id
        CHECK(is_hex(f[4], 2)); // class
        CHECK(is_hex(f[5], 2)); // subclass
        CHECK((f[10] == "0" || f[10] == "1")); // is_hub
    }
}

TEST_CASE("peripherals plugin: pci hex fields are lowercase and fixed-width",
          "[peripherals][actions]") {
    auto plugin = load_peripherals_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }
    yuzu::agent::LocalDispatcher dispatcher;
    auto result = dispatcher.run(plugin->descriptor, "pci");
    const auto rows = captured_rows(result.captured);
    REQUIRE_FALSE(rows.empty());
    for (const auto& r : rows) {
        const auto f = split_fields_escape_aware(r);
        if (f.size() != 9) continue; // skip none/unavailable placeholder rows
        INFO("row: " << r);
        CHECK(is_hex(f[2], 4)); // vendor_id
        CHECK(is_hex(f[3], 4)); // device_id
        CHECK(is_hex(f[4], 6)); // class
        CHECK(is_hex(f[5], 4)); // subsystem_vendor
        CHECK(is_hex(f[6], 4)); // subsystem_device
    }
}

TEST_CASE("peripherals plugin: thunderbolt role is a fixed vocabulary",
          "[peripherals][actions]") {
    auto plugin = load_peripherals_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }
    yuzu::agent::LocalDispatcher dispatcher;
    auto result = dispatcher.run(plugin->descriptor, "thunderbolt");
    const auto rows = captured_rows(result.captured);
    REQUIRE_FALSE(rows.empty());
    for (const auto& r : rows) {
        const auto f = split_fields_escape_aware(r);
        if (f.size() != 8) continue; // skip none/unavailable placeholder rows
        INFO("row: " << r);
        CHECK((f[2] == "host_controller" || f[2] == "device"));
        CHECK((f[7] == "1" || f[7] == "0" || f[7] == "-"));
    }
}

// One capability-conditional case per action: SKIP by name when only the
// none row came back (this host genuinely has no devices of that kind --
// the real Wave-2 legs report that as `<kind>|none`, distinct from an
// `unavailable` leg-level failure), else assert at least one real
// (non-placeholder) row.
TEST_CASE("peripherals plugin: usb reports a real row or is explicitly SKIPped",
          "[peripherals][actions]") {
    auto plugin = load_peripherals_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }
    yuzu::agent::LocalDispatcher dispatcher;
    const auto rows = captured_rows(dispatcher.run(plugin->descriptor, "usb").captured);
    REQUIRE_FALSE(rows.empty());
    if (rows.size() == 1 && split_fields_escape_aware(rows[0]).size() == 2) {
        SKIP("no usb device on this host");
    }
    bool saw_real_row = false;
    for (const auto& r : rows)
        if (split_fields_escape_aware(r).size() == 11) saw_real_row = true;
    CHECK(saw_real_row);
}

TEST_CASE("peripherals plugin: pci reports a real row or is explicitly SKIPped",
          "[peripherals][actions]") {
    auto plugin = load_peripherals_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }
    yuzu::agent::LocalDispatcher dispatcher;
    const auto rows = captured_rows(dispatcher.run(plugin->descriptor, "pci").captured);
    REQUIRE_FALSE(rows.empty());
    if (rows.size() == 1 && split_fields_escape_aware(rows[0]).size() == 2) {
        SKIP("no pci device on this host");
    }
    bool saw_real_row = false;
    for (const auto& r : rows)
        if (split_fields_escape_aware(r).size() == 9) saw_real_row = true;
    CHECK(saw_real_row);
}

TEST_CASE("peripherals plugin: thunderbolt reports a real row or is explicitly SKIPped",
          "[peripherals][actions]") {
    auto plugin = load_peripherals_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }
    yuzu::agent::LocalDispatcher dispatcher;
    const auto rows = captured_rows(dispatcher.run(plugin->descriptor, "thunderbolt").captured);
    REQUIRE_FALSE(rows.empty());
    if (rows.size() == 1 && split_fields_escape_aware(rows[0]).size() == 2) {
        SKIP("no thunderbolt/usb4 bus on this host");
    }
    bool saw_real_row = false;
    for (const auto& r : rows)
        if (split_fields_escape_aware(r).size() == 8) saw_real_row = true;
    CHECK(saw_real_row);
}

// K2/FV-3-shaped assertion (disk_actions precedent): nothing above asserted
// result_status, so every mark_result_read call could be deleted and the
// suite would stay green on the row-shape checks alone. LocalDispatcher's
// Result exposes the seam precisely so a test can prove it fires.
//
// P91-6-02 (Architect ruling, ws91): this case originally pinned the wave-1
// truth (every leg is the not_implemented placeholder -> every action
// reports CONSTRAINED/PARTIAL). Wave 2 replaced all three legs' bodies with
// real bus walks, so that blanket assertion went false on every OS the
// moment I91-2 wired this suite in -- a healthy walk (this Mac's 8 IOPCIDevice
// nodes, say) reports OK/FULL, not CONSTRAINED/PARTIAL. Retargeted to the
// invariant that survives now that no leg is a placeholder: the seam fired,
// and it paired status with completeness correctly, on either branch.
TEST_CASE("peripherals: every leg reports through the typed status seam",
          "[peripherals][status]") {
    auto plugin = load_peripherals_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }
    yuzu::agent::LocalDispatcher dispatcher;
    for (const auto& a : kActions) {
        INFO("action: " << a.action);
        auto result = dispatcher.run(plugin->descriptor, a.action);
        CHECK(result.rc == 0);
        // mark_result_read can only produce one of these two pairings --
        // never a third status, and never a mismatched pairing.
        bool is_ok = result.result_status == YUZU_RESULT_STATUS_OK;
        bool is_constrained = result.result_status == YUZU_RESULT_STATUS_CONSTRAINED;
        CHECK((is_ok || is_constrained));
        if (is_ok) {
            CHECK(result.result_completeness == YUZU_RESULT_COMPLETENESS_FULL);
        } else if (is_constrained) {
            CHECK(result.result_completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
            // Only the degraded branch carries a failure token; mark_result_read
            // passes an empty reason on the OK branch, so asserting non-empty
            // provenance unconditionally would itself be a false assertion.
            CHECK_FALSE(result.result_provenance.empty());
        }
    }
}

TEST_CASE("peripherals plugin: an unknown action is refused, not silently ignored",
          "[peripherals][actions]") {
    auto plugin = load_peripherals_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }
    yuzu::agent::LocalDispatcher dispatcher;
    auto result = dispatcher.run(plugin->descriptor, "no_such_action");
    CHECK(result.rc != 0);
}

// BUILD-COMPLETENESS CASE (P91-6, wave 2). All three legs (Windows/Linux/
// macOS) replaced their wave-1 `<os>:leg:not_implemented` placeholder in this
// same wave, so this case is host-agnostic and carries no platform #ifdef --
// it is GREEN on every CI OS now that wave 2 has integrated, and RED only if
// a real leg placeholder ever survives a future wave. It does not assert row shape or
// count (those are the cases above); it asserts only the one thing every
// leg's placeholder body shares regardless of OS: the `:leg:not_implemented`
// suffix on the unavailable token's provenance string. Host-specific counts
// (usb/pci/thunderbolt node totals on this Mac) are report-only, per the
// package spec -- never committed as an assertion here, since CI runs this
// suite on a shared, unknown-hardware runner (yuzu-bigmags-macos).
TEST_CASE("peripherals plugin: no leg reports its wave-1 not_implemented placeholder",
          "[peripherals][actions]") {
    auto plugin = load_peripherals_plugin();
    if (!plugin) {
        require_plugin_or_skip();
        return;
    }
    yuzu::agent::LocalDispatcher dispatcher;
    for (const auto& a : kActions) {
        INFO("action: " << a.action);
        auto result = dispatcher.run(plugin->descriptor, a.action);
        const auto rows = captured_rows(result.captured);
        REQUIRE_FALSE(rows.empty());
        for (const auto& r : rows) {
            INFO("row: " << r);
            CHECK(r.find(":leg:not_implemented") == std::string::npos);
        }
    }
}
