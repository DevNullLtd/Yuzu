/**
 * test_hardware_drivers_inventory.cpp -- the hardware `drivers_inventory` action.
 *
 *   * Pure compose / field parsers / Linux collection over an injected sysfs reader: run on every
 *     host. Windows fixtures are copied from the kingsley Win32_PnPSignedDriver capture
 *     (178 rows with a DeviceName; many carry only a HardWareID; the PowerShell capture printed
 *     the date in a locale form, which the parser must not trust).
 *   * read_linux() against a materialised directory tree (POSIX hosts only, `yuzu_test_` prefix):
 *     bounded no-follow reads, a symlinked attribute is refused.
 *   * The real hardware plugin through LocalDispatcher: row FAMILIES only (never host values), per
 *     OS. NOT verified on this host: the Windows WMI leg itself (the dispatcher case runs on
 *     Windows CI/kingsley only).
 */
#include <catch2/catch_test_macros.hpp>

#include <yuzu/agent/plugin_loader.hpp>
#include <yuzu/plugin.h>
#include <yuzu/plugin.hpp>

#include "hardware_drivers_inventory.hpp"
#include "local_dispatcher.hpp"

#include <algorithm>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <map>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <string_view>
#include <tuple>
#include <vector>

#if !defined(_WIN32)
#include <unistd.h>
#endif

namespace fs = std::filesystem;
namespace di = yuzu::hardware::drivers_inventory;
using yuzu::shared::ConstraintAccumulator;

namespace {

/// Splits a wire row on unescaped '|' (escape_pipes writes `\|`; every other backslash was folded
/// to '/', so a '\' in a row is always an escape).
std::vector<std::string> split_row(const std::string& row) {
    std::vector<std::string> out(1);
    for (std::size_t i = 0; i < row.size(); ++i) {
        if (row[i] == '\\' && i + 1 < row.size() && row[i + 1] == '|') {
            out.back() += '|';
            ++i;
        } else if (row[i] == '|') {
            out.emplace_back();
        } else {
            out.back() += row[i];
        }
    }
    return out;
}

std::vector<std::string> captured_rows(const std::string& captured) {
    std::vector<std::string> out;
    std::istringstream ss(captured);
    for (std::string line; std::getline(ss, line);) {
        if (!line.empty() && line.back() == '\r')
            line.pop_back();
        if (!line.empty())
            out.push_back(line);
    }
    return out;
}

di::Row wmi_row(std::map<std::string, std::string> m) { return di::row_from_wmi(m); }

// Two rows copied from the capture ('ACP HDA Node' has only a HardWareID) plus a Microsoft
// machine.inf device.
std::vector<di::Row> capture_rows() {
    return {
        wmi_row({{"DeviceName", "ACPI Power Button"},
                 {"DriverVersion", "10.0.26100.1150"},
                 {"DriverDate", "20060621000000.000000-000"},
                 {"DriverProviderName", "Microsoft"},
                 {"DeviceClass", "SYSTEM"},
                 {"Signer", "Microsoft Windows"},
                 {"IsSigned", "true"},
                 {"InfName", "machine.inf"},
                 {"HardWareID", "ACPI\\VEN_PNP&DEV_0C0C"}}),
        wmi_row({{"DeviceName", "ACP HDA Node"},
                 {"HardWareID", "ACP\\DEVTYPE_0001&DEVREV_0000&VEN_1022&DEV_15E2&SUBSYS_102215E2&REV_63"}}),
        wmi_row({{"DeviceName", "AMD Audio CoProcessor"},
                 {"DriverVersion", "6.0.0.109"},
                 {"DriverDate", "26/03/2025 00:00:00"}, // locale form from the PowerShell capture
                 {"DriverProviderName", "AMD"},
                 {"DeviceClass", "SYSTEM"},
                 {"Signer", "Microsoft Windows Hardware Compatibility Publisher"},
                 {"IsSigned", "True"},
                 {"InfName", "oem18.inf"},
                 {"HardWareID", "PCI\\VEN_1022&DEV_15E2&SUBSYS_15E21022&REV_63"}}),
    };
}

} // namespace

// ── compose ────────────────────────────────────────────────────────────────────────────────

TEST_CASE("drivers_inventory compose: unsorted duplicate input is sorted and deduplicated",
          "[hardware][drivers_inventory][compose]") {
    auto rows = capture_rows();
    rows.push_back(rows[0]); // exact duplicate
    rows.push_back(rows[1]); // exact duplicate
    std::reverse(rows.begin(), rows.end());

    ConstraintAccumulator acc;
    const auto c = di::compose(rows, acc);

    REQUIRE(c.lines.size() == 4); // status + three distinct drivers
    CHECK_FALSE(c.constrained);
    CHECK(c.tokens.empty());
    CHECK(c.lines[0] == "status|drivers_inventory|supported|-");

    std::vector<std::string> names;
    for (std::size_t i = 1; i < c.lines.size(); ++i) {
        const auto f = split_row(c.lines[i]);
        REQUIRE(f.size() == 10);
        CHECK(f[0] == "driver_inv");
        names.push_back(f[1]);
    }
    CHECK(names == std::vector<std::string>{"ACP HDA Node", "ACPI Power Button",
                                            "AMD Audio CoProcessor"});
}

TEST_CASE("drivers_inventory compose: empty fields become '-' and the capture fields map",
          "[hardware][drivers_inventory][compose]") {
    ConstraintAccumulator acc;
    const auto c = di::compose(capture_rows(), acc);
    REQUIRE(c.lines.size() == 4);

    // 'ACP HDA Node': only a hardware id; the backslash is folded by the row escaper.
    CHECK(c.lines[1] ==
          "driver_inv|ACP HDA Node|-|-|-|-|-|-|-|"
          "ACP/DEVTYPE_0001&DEVREV_0000&VEN_1022&DEV_15E2&SUBSYS_102215E2&REV_63");
    // CIM date, true -> signed, INF and hardware id carried.
    CHECK(c.lines[2] == "driver_inv|ACPI Power Button|10.0.26100.1150|2006-06-21|Microsoft|SYSTEM|"
                        "Microsoft Windows|signed|machine.inf|ACPI/VEN_PNP&DEV_0C0C");
    // Locale-formatted date is not trusted: '-'. "True" (PowerShell case) is also signed.
    const auto amd = split_row(c.lines[3]);
    REQUIRE(amd.size() == 10);
    CHECK(amd[3] == "-");
    CHECK(amd[7] == "signed");
}

TEST_CASE("drivers_inventory compose: a pipe in a name is escaped, a newline folded",
          "[hardware][drivers_inventory][compose]") {
    di::Row r;
    r.name = "evil|name\nsecond";
    ConstraintAccumulator acc;
    const auto c = di::compose({r}, acc);
    REQUIRE(c.lines.size() == 2);
    CHECK(c.lines[1].find("evil\\|name second") != std::string::npos);
    CHECK(c.lines[1].find('\n') == std::string::npos);
    CHECK(split_row(c.lines[1]).size() == 10);
}

TEST_CASE("drivers_inventory compose: ordering is (name, inf, hwid, version)",
          "[hardware][drivers_inventory][compose]") {
    const auto mk = [](const char* name, const char* inf, const char* hwid, const char* ver) {
        di::Row r;
        r.name = name;
        r.inf = inf;
        r.hwid = hwid;
        r.version = ver;
        return r;
    };
    const std::vector<di::Row> in{mk("b", "a.inf", "h", "1"), mk("a", "z.inf", "h", "1"),
                                  mk("a", "a.inf", "z", "1"), mk("a", "a.inf", "h", "2"),
                                  mk("a", "a.inf", "h", "1")};
    ConstraintAccumulator acc;
    const auto c = di::compose(in, acc);
    REQUIRE(c.lines.size() == 6);
    std::vector<std::string> keys;
    for (std::size_t i = 1; i < c.lines.size(); ++i) {
        const auto f = split_row(c.lines[i]);
        keys.push_back(f[1] + "/" + f[8] + "/" + f[9] + "/" + f[2]);
    }
    CHECK(keys == std::vector<std::string>{"a/a.inf/h/1", "a/a.inf/h/2", "a/a.inf/z/1",
                                           "a/z.inf/h/1", "b/a.inf/h/1"});
}

TEST_CASE("drivers_inventory compose: a failure token makes the status constrained, rows kept",
          "[hardware][drivers_inventory][compose]") {
    ConstraintAccumulator acc;
    acc.add_failure(di::kWindowsRowCap);
    acc.add_failure(di::kWindowsRowCap); // deduplicated
    const auto c = di::compose(capture_rows(), acc);
    CHECK(c.constrained);
    CHECK(c.tokens == "windows:drivers_inventory:row_cap");
    CHECK(c.lines.size() == 4);
    CHECK(c.lines[0] == "status|drivers_inventory|constrained|windows:drivers_inventory:row_cap");

    // A leg that read nothing at all is constrained, never an empty supported answer.
    ConstraintAccumulator failed;
    failed.add_failure("windows:drivers_inventory:wmi_deadline_exceeded");
    const auto none = di::compose({}, failed);
    REQUIRE(none.lines.size() == 1);
    CHECK(none.lines[0] ==
          "status|drivers_inventory|constrained|windows:drivers_inventory:wmi_deadline_exceeded");
}

TEST_CASE("drivers_inventory: the macOS answer is one unsupported status row",
          "[hardware][drivers_inventory][compose]") {
    CHECK(di::unsupported_line(di::kMacosUnsupported) ==
          "status|drivers_inventory|unsupported|macos:no_enumeration_api");
}

// ── field parsers ──────────────────────────────────────────────────────────────────────────

TEST_CASE("drivers_inventory date_to_iso: CIM and ISO accepted, nothing is guessed",
          "[hardware][drivers_inventory][parse]") {
    CHECK(di::date_to_iso("20250326000000.000000-000") == "2025-03-26");
    CHECK(di::date_to_iso("20250326") == "2025-03-26");
    CHECK(di::date_to_iso("2025-03-26") == "2025-03-26");
    CHECK(di::date_to_iso("2025-03-26 00:00:00") == "2025-03-26");
    CHECK(di::date_to_iso("26/03/2025 00:00:00") == "-"); // locale form from the capture
    CHECK(di::date_to_iso("03/26/2025") == "-");
    CHECK(di::date_to_iso("") == "-");
    CHECK(di::date_to_iso("2025") == "-");
    CHECK(di::date_to_iso("20251340000000.000000-000") == "-"); // month 13
    CHECK(di::date_to_iso("20250300000000.000000-000") == "-"); // day 00
    CHECK(di::date_to_iso("00000000000000.000000-000") == "-");
}

TEST_CASE("drivers_inventory signed_from_wmi / signed_from_taint", "[hardware][drivers_inventory][parse]") {
    CHECK(di::signed_from_wmi("true") == "signed");
    CHECK(di::signed_from_wmi("True") == "signed");
    CHECK(di::signed_from_wmi("false") == "unsigned");
    CHECK(di::signed_from_wmi("False") == "unsigned");
    CHECK(di::signed_from_wmi("") == "-");
    CHECK(di::signed_from_wmi("maybe") == "-");
    CHECK(di::signed_from_taint("OE\n") == "unsigned");
    CHECK(di::signed_from_taint("E") == "unsigned");
    CHECK(di::signed_from_taint("\n") == "-");
    CHECK(di::signed_from_taint("OF") == "-");
}

TEST_CASE("drivers_inventory valid_module_name: [A-Za-z0-9_-]{1,64}", "[hardware][drivers_inventory][parse]") {
    CHECK(di::valid_module_name("nf_conntrack"));
    CHECK(di::valid_module_name("snd-hda-intel"));
    CHECK(di::valid_module_name(std::string(64, 'a')));
    CHECK_FALSE(di::valid_module_name(std::string(65, 'a')));
    CHECK_FALSE(di::valid_module_name(""));
    CHECK_FALSE(di::valid_module_name("a/b"));
    CHECK_FALSE(di::valid_module_name(".."));
    CHECK_FALSE(di::valid_module_name("a.b"));
    CHECK_FALSE(di::valid_module_name("a b"));
}

// ── Linux collection over a fake sysfs reader ───────────────────────────────────────────────

namespace {
const std::string kProcModules =
    "nf_conntrack 172032 3 xt_conntrack,nf_nat, Live 0x0000000000000000\n"
    "vboxdrv 589824 2 vboxnetflt,vboxnetadp, Live 0x0000000000000000 (OE)\n"
    "bad/name 1 0 - Live 0x0\n"
    "\n"
    "snd_hda_intel 61440 0 - Live 0x0000000000000000\n";

di::ModuleAttrs fake_attrs(std::string_view m) {
    using S = di::SysRead::Status;
    di::ModuleAttrs a;
    if (m == "nf_conntrack") {
        a.version = {S::absent, ""};
        a.taint = {S::ok, "\n"};
    } else if (m == "vboxdrv") {
        a.version = {S::ok, "7.0.20 r163906\n"};
        a.taint = {S::ok, "OE\n"};
    } else {
        a.version = {S::absent, ""};
        a.taint = {S::absent, ""};
    }
    return a;
}
} // namespace

TEST_CASE("drivers_inventory linux: /proc/modules text plus a fake sysfs maps version and taint",
          "[hardware][drivers_inventory][linux]") {
    ConstraintAccumulator acc;
    const auto rows = di::collect_linux_rows(kProcModules, fake_attrs, acc);
    // The invalid name is skipped with a token; the blank line is ignored.
    REQUIRE(rows.size() == 3);
    CHECK(acc.reason() == "linux:drivers_inventory:invalid_module_name");

    const auto c = di::compose(rows, acc);
    CHECK(c.constrained);
    REQUIRE(c.lines.size() == 4);
    CHECK(c.lines[0] ==
          "status|drivers_inventory|constrained|linux:drivers_inventory:invalid_module_name");
    // Sorted by name: nf_conntrack, snd_hda_intel, vboxdrv.
    CHECK(c.lines[1] == "driver_inv|nf_conntrack|-|-|kernel|module|-|-|-|-");
    CHECK(c.lines[2] == "driver_inv|snd_hda_intel|-|-|kernel|module|-|-|-|-");
    CHECK(c.lines[3] == "driver_inv|vboxdrv|7.0.20 r163906|-|kernel|module|-|unsigned|-|-");
}

TEST_CASE("drivers_inventory linux: reaching the cap stops the walk with a row_cap token",
          "[hardware][drivers_inventory][linux]") {
    ConstraintAccumulator acc;
    const auto rows = di::collect_linux_rows("a 1 0 - Live 0x0\nb 1 0 - Live 0x0\nc 1 0 - Live 0x0\n",
                                             fake_attrs, acc, /*cap=*/2);
    CHECK(rows.size() == 2);
    CHECK(acc.reason() == "linux:drivers_inventory:row_cap");
    const auto c = di::compose(rows, acc);
    CHECK(c.constrained);
    CHECK(c.lines[0] == "status|drivers_inventory|constrained|linux:drivers_inventory:row_cap");

    // Exactly `cap` modules is complete, not capped.
    ConstraintAccumulator exact;
    const auto two = di::collect_linux_rows("a 1 0 - Live 0x0\nb 1 0 - Live 0x0\n", fake_attrs,
                                            exact, /*cap=*/2);
    CHECK(two.size() == 2);
    CHECK_FALSE(exact.any_failure());
}

TEST_CASE("drivers_inventory linux: denied and failed attribute reads are recorded",
          "[hardware][drivers_inventory][linux]") {
    using S = di::SysRead::Status;
    ConstraintAccumulator acc;
    const auto rows = di::collect_linux_rows(
        "a 1 0 - Live 0x0\nb 1 0 - Live 0x0\n",
        [](std::string_view m) {
            di::ModuleAttrs a;
            a.version.status = m == "a" ? S::denied : S::ok;
            a.version.data = "1.0";
            a.taint.status = m == "b" ? S::failed : S::ok;
            a.taint.data = "E";
            return a;
        },
        acc);
    REQUIRE(rows.size() == 2);
    CHECK(acc.reason() ==
          "linux:drivers_inventory:permission_denied,linux:drivers_inventory:read_failed");
    // A denied/failed read never becomes a value.
    CHECK(rows[0].version.empty());
    CHECK(rows[1].signed_state.empty());
}

#if !defined(_WIN32)
namespace {
struct TempTree {
    fs::path root;
    TempTree() {
        root = fs::temp_directory_path() /
               ("yuzu_test_drvinv_" + std::to_string(::getpid()) + "_" +
                std::to_string(reinterpret_cast<std::uintptr_t>(this)));
        fs::create_directories(root);
    }
    ~TempTree() {
        std::error_code ec;
        fs::remove_all(root, ec);
    }
    void write(const fs::path& rel, const std::string& body) const {
        fs::create_directories((root / rel).parent_path());
        std::ofstream(root / rel, std::ios::binary) << body;
    }
};
} // namespace

TEST_CASE("drivers_inventory read_linux: bounded no-follow reads over a real tree",
          "[hardware][drivers_inventory][linux]") {
    TempTree t;
    t.write("proc_modules", kProcModules + "linked 1 0 - Live 0x0\ngone 1 0 - Live 0x0\n");
    t.write("sys/vboxdrv/version", "7.0.20 r163906\n");
    t.write("sys/vboxdrv/taint", "OE\n");
    t.write("sys/nf_conntrack/taint", "\n");
    t.write("secret_version", "STOLEN\n");
    fs::create_directories(t.root / "sys" / "linked");
    fs::create_symlink(t.root / "secret_version", t.root / "sys" / "linked" / "version");
    // "gone" has no sys directory at all (unloaded between the two reads): a normal absence.

    ConstraintAccumulator acc;
    const auto rows = di::read_linux((t.root / "proc_modules").string(), (t.root / "sys").string(), acc);
    const auto c = di::compose(rows, acc);

    const auto find = [&](std::string_view name) -> std::vector<std::string> {
        for (const auto& l : c.lines) {
            const auto f = split_row(l);
            if (f.size() == 10 && f[1] == name)
                return f;
        }
        return {};
    };
    const auto vbox = find("vboxdrv");
    REQUIRE(vbox.size() == 10);
    CHECK(vbox[2] == "7.0.20 r163906");
    CHECK(vbox[7] == "unsigned");
    const auto nf = find("nf_conntrack");
    REQUIRE(nf.size() == 10);
    CHECK(nf[2] == "-");
    CHECK(nf[7] == "-");
    const auto gone = find("gone");
    REQUIRE(gone.size() == 10);
    CHECK(gone[2] == "-");

    // The symlinked attribute was refused, not followed: its target's text never appears.
    const auto linked = find("linked");
    REQUIRE(linked.size() == 10);
    CHECK(linked[2] == "-");
    for (const auto& l : c.lines)
        CHECK(l.find("STOLEN") == std::string::npos);
    CHECK(c.constrained);
    CHECK(c.tokens.find("linux:drivers_inventory:read_failed") != std::string::npos);
    CHECK(c.tokens.find("linux:drivers_inventory:invalid_module_name") != std::string::npos);
}

TEST_CASE("drivers_inventory read_linux: an unreadable /proc/modules or /sys/module is constrained",
          "[hardware][drivers_inventory][linux]") {
    TempTree t;
    {
        ConstraintAccumulator acc;
        const auto rows = di::read_linux((t.root / "missing").string(), (t.root / "sys").string(), acc);
        CHECK(rows.empty());
        CHECK(acc.reason() == "linux:drivers_inventory:read_failed");
        CHECK(di::compose(rows, acc).constrained);
    }
    {
        // /proc/modules readable, /sys/module absent: versions cannot be read, and that is said.
        t.write("proc_modules", "a 1 0 - Live 0x0\n");
        ConstraintAccumulator acc;
        const auto rows =
            di::read_linux((t.root / "proc_modules").string(), (t.root / "nosys").string(), acc);
        REQUIRE(rows.size() == 1);
        CHECK(acc.reason() == "linux:drivers_inventory:read_failed");
    }
    {
        // A /proc/modules over the 1 MiB bound is refused whole.
        t.write("big", std::string(di::kProcModulesCap + 1, 'x'));
        ConstraintAccumulator acc;
        const auto rows = di::read_linux((t.root / "big").string(), (t.root / "sys").string(), acc);
        CHECK(rows.empty());
        CHECK(acc.reason() == "linux:drivers_inventory:proc_modules_oversized");
    }
}
#endif // !_WIN32

// ── the real plugin through LocalDispatcher (row families only) ─────────────────────────────

namespace {

#if defined(_WIN32)
constexpr const char* kPluginExt = ".dll";
#elif defined(__APPLE__)
constexpr const char* kPluginExt = ".dylib";
#else
constexpr const char* kPluginExt = ".so";
#endif

struct LoadedPlugin {
    yuzu::agent::PluginHandle handle;
    const YuzuPluginDescriptor* descriptor;
};

std::optional<LoadedPlugin> load_plugin() {
    const fs::path rel =
        fs::path{"agents"} / "plugins" / "hardware" / (std::string{"hardware"} + kPluginExt);
    std::vector<fs::path> candidates;
    if (auto* root = std::getenv("MESON_BUILD_ROOT"))
        candidates.push_back(fs::path{root} / rel);
    for (const char* dir : {".", "..", "build-macos", "build-windows", "build-linux"})
        candidates.push_back(fs::path{dir} / rel);
    for (const auto& p : candidates) {
        std::error_code ec;
        if (!fs::exists(p, ec) || ec)
            continue;
        auto handle = yuzu::agent::PluginHandle::load(fs::absolute(p, ec));
        if (!handle.has_value() || !handle->descriptor())
            return std::nullopt;
        const auto* descriptor = handle->descriptor();
        return LoadedPlugin{std::move(*handle), descriptor};
    }
    return std::nullopt;
}

void require_plugin_or_skip() {
    if (std::getenv("MESON_BUILD_ROOT") != nullptr)
        FAIL("hardware plugin library not found under meson test -- the plugin did not build, or "
             "link_depends does not order it before this test");
    WARN("hardware plugin library not found -- skipping (run from the build root)");
}

const YuzuActionDescriptor* find_descriptor(const YuzuPluginDescriptor* d, std::string_view name) {
    for (std::size_t i = 0; i < d->action_descriptor_count; ++i)
        if (std::string_view{d->action_descriptors[i].action} == name)
            return &d->action_descriptors[i];
    return nullptr;
}

} // namespace

TEST_CASE("hardware plugin: drivers_inventory is listed and described on every leg",
          "[hardware][drivers_inventory][descriptors]") {
    auto plugin = load_plugin();
    if (!plugin)
        return require_plugin_or_skip();

    bool listed = false;
    for (const char* const* a = plugin->descriptor->actions; a && *a; ++a)
        listed = listed || std::string_view{*a} == "drivers_inventory";
    CHECK(listed);

    const auto* d = find_descriptor(plugin->descriptor, "drivers_inventory");
    REQUIRE(d != nullptr);
    CHECK(d->linux_leg.support == YUZU_SUPPORT_SUPPORTED);
    CHECK(d->linux_leg.rung == 1);
    CHECK(d->windows_leg.support == YUZU_SUPPORT_SUPPORTED);
    CHECK(d->windows_leg.rung == 1);
    CHECK(d->macos_leg.support == YUZU_SUPPORT_UNSUPPORTED);
    CHECK(d->macos_leg.mechanism == nullptr);
    // The existing drivers action keeps its own row.
    CHECK(find_descriptor(plugin->descriptor, "drivers") != nullptr);
}

TEST_CASE("hardware plugin: drivers_inventory answers a status row first, then ten-field sorted rows",
          "[hardware][drivers_inventory][actions]") {
    auto plugin = load_plugin();
    if (!plugin)
        return require_plugin_or_skip();

    yuzu::agent::LocalDispatcher dispatcher;
    auto result = dispatcher.run(plugin->descriptor, "drivers_inventory");
    CHECK(result.rc == 0);
    const auto rows = captured_rows(result.captured);
    REQUIRE_FALSE(rows.empty());

    const auto status = split_row(rows[0]);
    REQUIRE(status.size() == 4);
    CHECK(status[0] == "status");
    CHECK(status[1] == "drivers_inventory");

#if defined(__APPLE__)
    CHECK(rows.size() == 1);
    CHECK(rows[0] == "status|drivers_inventory|unsupported|macos:no_enumeration_api");
    CHECK(result.result_status == YUZU_RESULT_STATUS_UNAVAILABLE);
    CHECK(result.result_completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
#else
    CHECK((status[2] == "supported" || status[2] == "constrained"));
    if (status[2] == "supported") {
        CHECK(status[3] == "-");
        CHECK(result.result_status == YUZU_RESULT_STATUS_OK);
        CHECK(result.result_completeness == YUZU_RESULT_COMPLETENESS_FULL);
    } else {
        CHECK(status[3] != "-");
        CHECK(result.result_status == YUZU_RESULT_STATUS_CONSTRAINED);
        CHECK(result.result_completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
    }
#if defined(_WIN32)
    // Any Windows host has drivers; a Linux kernel with no modules is a legitimate empty answer.
    if (status[2] == "supported")
        CHECK(rows.size() > 1);
#endif

    std::vector<std::vector<std::string>> data;
    for (std::size_t i = 1; i < rows.size(); ++i) {
        INFO("row: " << rows[i]);
        auto f = split_row(rows[i]);
        REQUIRE(f.size() == 10);
        CHECK(f[0] == "driver_inv");
        CHECK((f[7] == "signed" || f[7] == "unsigned" || f[7] == "-"));
        for (std::size_t k = 1; k < f.size(); ++k)
            CHECK_FALSE(f[k].empty()); // an absent value is '-', never empty
        data.push_back(std::move(f));
    }
    // Sorted by (name, inf, hwid, version) and free of exact duplicates.
    const auto key = [](const std::vector<std::string>& f) {
        return std::tie(f[1], f[8], f[9], f[2]);
    };
    CHECK(std::is_sorted(data.begin(), data.end(),
                         [&](const auto& a, const auto& b) { return key(a) < key(b); }));
    CHECK(std::adjacent_find(data.begin(), data.end()) == data.end());
#endif
}
