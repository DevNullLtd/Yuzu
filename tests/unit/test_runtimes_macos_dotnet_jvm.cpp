/**
 * test_runtimes_macos_dotnet_jvm.cpp -- the runtimes plugin's macOS `dotnet` and `jvm` walks
 * (runtimes_macos_parsers.hpp `mac::dotnet_rows_at` / `mac::jvm_rows_at` / `mac::run_macos_at`)
 * over materialized fixture trees (runtimes_fixture_tree.hpp). POSIX only: the whole body sits in
 * one `#if !defined(_WIN32)` region (the walk layer is POSIX-only; no-op TU on Windows, as
 * test_runtimes_linux_parsers.cpp).
 *
 * PROVENANCE. Every tree here is SYNTHETIC: no .NET or JDK is installed on the development Mac, so
 * the trees are built from the documented layouts (the Microsoft installer's /usr/local/share/dotnet
 * with its x64 Rosetta sub-root; a JDK bundle's Contents/Home/release + Contents/Info.plist JavaVM
 * dictionary). Nothing here is a real macOS capture.
 *
 * MUTATION NOTES: dropping the O_NOFOLLOW from a hop follows the planted symlink and surfaces the
 * `canary` rows; stamping the vendor on the native root as well as x64 fails the vendor checks;
 * reading Info.plist when `release` exists makes the release-wins case report the plist's values;
 * dropping the dedupe/sort changes the dotnet row order.
 */
#include <catch2/catch_test_macros.hpp>

#include "runtimes_fixture_tree.hpp"
#include "runtimes_legs.hpp"

#include "test_helpers.hpp" // yuzu::test::TempDir

#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#if !defined(_WIN32)
#include "local_dispatcher.hpp" // yuzu::agent::LocalDispatcher (a real CommandContext)
#include "runtimes_macos_parsers.hpp"

#include <yuzu/plugin.h>

#include <sstream>
#include <sys/stat.h>
#include <unistd.h>

namespace rt = yuzu::runtimes;
namespace mac = yuzu::runtimes::mac;
namespace fs = std::filesystem;
using namespace runtimes_fixture;
using Acc = yuzu::shared::ConstraintAccumulator;

namespace {

constexpr const char* kDotnet = "usr/local/share/dotnet";
constexpr const char* kJvms = "Library/Java/JavaVirtualMachines";

void write_file(const fs::path& p, const std::string& text) {
    std::error_code ec;
    fs::create_directories(p.parent_path(), ec);
    REQUIRE_FALSE(ec);
    std::ofstream out(p, std::ios::binary);
    REQUIRE(out.good());
    out << text;
}

void make_symlink(const std::string& target, const fs::path& link) {
    std::error_code ec;
    fs::create_directories(link.parent_path(), ec);
    fs::create_symlink(target, link, ec);
    REQUIRE_FALSE(ec);
}

/// Materializes an inline manifest (runtimes_fixture_tree.hpp grammar) under `root` through the
/// shared helper, via a temp manifest file next to the tree.
void materialize(const fs::path& root, const std::string& manifest) {
    const fs::path file = root.parent_path() / (root.filename().string() + ".manifest");
    write_file(file, manifest);
    std::string err;
    REQUIRE(materialize_manifest_file(root, err, file));
}

std::string plist(std::string_view version, std::string_view vendor) {
    return "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<plist version=\"1.0\"><dict>\n"
           "<key>CFBundleIdentifier</key><string>net.example.jdk</string>\n"
           "<key>JavaVM</key><dict>\n"
           "<key>JVMPlatformVersion</key><string>" + std::string{version} + "</string>\n"
           "<key>JVMVendor</key><string>" + std::string{vendor} + "</string>\n"
           "<key>JVMVersion</key><string>" + std::string{version} + "</string>\n"
           "</dict></dict></plist>\n";
}

// install_path prefixes
const std::string kD = "/usr/local/share/dotnet";
const std::string kDx = "/usr/local/share/dotnet/x64";
const std::string kJ = "/Library/Java/JavaVirtualMachines";

// A synthetic release file as a manifest T: payload (\n escapes).
constexpr const char* kReleaseTemurin =
    "T:IMPLEMENTOR=\"Eclipse Adoptium\"\\nIMAGE_TYPE=\"JDK\"\\nJAVA_VERSION=\"21.0.13\"\\n"
    "JAVA_RUNTIME_VERSION=\"21.0.13+9-LTS\"\\n";

std::string manifest_line(const std::string& rel, const std::string& payload) {
    return rel + "\t" + payload + "\n";
}

bool privileged() { return ::geteuid() == 0; }

} // namespace

// == dotnet ======================================================================================

TEST_CASE("macos dotnet: two frameworks x two versions + one sdk -> five sorted rows (SYNTHETIC)",
          "[runtimes][dotnet][macos]") {
    yuzu::test::TempDir dir{"yuzu_test_runtimes_macdn_"};
    const fs::path root = dir.path / "root";
    std::string m;
    for (const char* fw : {"Microsoft.NETCore.App", "Microsoft.AspNetCore.App"})
        for (const char* v : {"8.0.11", "9.0.0"})
            m += manifest_line(std::string{kDotnet} + "/shared/" + fw + "/" + v + "/.version", "D:");
    m += manifest_line(std::string{kDotnet} + "/sdk/9.0.100/dotnet.dll", "T:x");
    m += manifest_line(std::string{kDotnet} + "/sdk/notaversion/x", "T:x");              // ignored
    m += manifest_line(std::string{kDotnet} + "/shared/Microsoft.NETCore.App/README", "T:x"); // file
    materialize(root, m);
    Acc acc;
    const auto rows = mac::dotnet_rows_at(root, acc);
    CHECK(rows == std::vector<std::string>{
                      "dotnet|core|8.0.11|" + kD + "/shared/Microsoft.AspNetCore.App/8.0.11|-",
                      "dotnet|core|8.0.11|" + kD + "/shared/Microsoft.NETCore.App/8.0.11|-",
                      "dotnet|core|9.0.0|" + kD + "/shared/Microsoft.AspNetCore.App/9.0.0|-",
                      "dotnet|core|9.0.0|" + kD + "/shared/Microsoft.NETCore.App/9.0.0|-",
                      "dotnet|sdk|9.0.100|" + kD + "/sdk/9.0.100|-"});
    CHECK_FALSE(acc.any_failure());
}

TEST_CASE("macos dotnet: the x64 Rosetta sub-root contributes its rows once, vendor Microsoft "
          "(SYNTHETIC)",
          "[runtimes][dotnet][macos]") {
    yuzu::test::TempDir dir{"yuzu_test_runtimes_macdn_x64_"};
    const fs::path root = dir.path / "root";
    fs::create_directories(root / kDotnet / "shared/Microsoft.NETCore.App/9.0.0");
    fs::create_directories(root / kDotnet / "x64/shared/Microsoft.NETCore.App/8.0.11");
    fs::create_directories(root / kDotnet / "x64/sdk/8.0.400");
    Acc acc;
    const auto rows = mac::dotnet_rows_at(root, acc);
    CHECK(rows == std::vector<std::string>{
                      "dotnet|core|8.0.11|" + kDx + "/shared/Microsoft.NETCore.App/8.0.11|Microsoft",
                      "dotnet|core|9.0.0|" + kD + "/shared/Microsoft.NETCore.App/9.0.0|-",
                      "dotnet|sdk|8.0.400|" + kDx + "/sdk/8.0.400|Microsoft"});
    CHECK_FALSE(acc.any_failure());
}

TEST_CASE("macos dotnet: absent roots are supported with zero rows and no token",
          "[runtimes][dotnet][macos]") {
    yuzu::test::TempDir dir{"yuzu_test_runtimes_macdn_absent_"};
    Acc acc;
    CHECK(mac::dotnet_rows_at(dir.path, acc).empty());
    CHECK_FALSE(acc.any_failure());
    // an empty dotnet root (no shared/sdk) is likewise silent
    fs::create_directories(dir.path / kDotnet);
    CHECK(mac::dotnet_rows_at(dir.path, acc).empty());
    CHECK_FALSE(acc.any_failure());
}

TEST_CASE("macos dotnet: a symlinked framework, version or sdk entry is refused, never followed "
          "(SYNTHETIC)",
          "[runtimes][dotnet][macos]") {
    // MUTATION: following the entry lists the canary tree's rows.
    yuzu::test::TempDir dir{"yuzu_test_runtimes_macdn_link_"};
    const fs::path root = dir.path / "root";
    fs::create_directories(dir.path / "elsewhere/canary/9.9.9");
    fs::create_directories(root / kDotnet / "shared/Microsoft.NETCore.App/8.0.11");
    SECTION("framework entry") {
        make_symlink("../../../../../../elsewhere", root / kDotnet / "shared/Microsoft.AspNetCore.App");
        Acc acc;
        CHECK(mac::dotnet_rows_at(root, acc) ==
              std::vector<std::string>{"dotnet|core|8.0.11|" + kD + "/shared/Microsoft.NETCore.App/8.0.11|-"});
        CHECK(acc.reason() == "macos:runtimes:symlink_refused");
    }
    SECTION("version entry") {
        make_symlink("8.0.11", root / kDotnet / "shared/Microsoft.NETCore.App/8.0.12");
        Acc acc;
        CHECK(mac::dotnet_rows_at(root, acc).size() == 1);
        CHECK(acc.reason() == "macos:runtimes:symlink_refused");
    }
    SECTION("sdk entry") {
        make_symlink("../../../../../../elsewhere/canary/9.9.9", root / kDotnet / "sdk/9.0.100");
        Acc acc;
        CHECK(mac::dotnet_rows_at(root, acc).size() == 1);
        CHECK(acc.reason() == "macos:runtimes:symlink_refused");
    }
    SECTION("a symlinked non-version name is not a runtime and raises nothing") {
        make_symlink("8.0.11", root / kDotnet / "sdk/latest");
        Acc acc;
        CHECK(mac::dotnet_rows_at(root, acc).size() == 1);
        CHECK_FALSE(acc.any_failure());
    }
}

TEST_CASE("macos dotnet: a symlinked shared/ or dotnet hop is refused (SYNTHETIC)",
          "[runtimes][dotnet][macos]") {
    yuzu::test::TempDir dir{"yuzu_test_runtimes_macdn_hop_"};
    const fs::path root = dir.path / "root";
    fs::create_directories(dir.path / "elsewhere/Microsoft.NETCore.App/9.9.9");
    SECTION("shared/") {
        fs::create_directories(root / kDotnet);
        make_symlink("../../../../../elsewhere", root / kDotnet / "shared");
        Acc acc;
        CHECK(mac::dotnet_rows_at(root, acc).empty());
        CHECK(acc.reason() == "macos:runtimes:symlink_refused");
    }
    SECTION("usr/local/share/dotnet itself") {
        fs::create_directories(root / "usr/local/share");
        make_symlink("../../../../elsewhere", root / kDotnet);
        Acc acc;
        CHECK(mac::dotnet_rows_at(root, acc).empty());
        CHECK(acc.reason() == "macos:runtimes:symlink_refused");
    }
}

TEST_CASE("macos dotnet: a network-mount root is skipped before any syscall touches it (SYNTHETIC)",
          "[runtimes][dotnet][macos][mounts]") {
    yuzu::test::TempDir dir{"yuzu_test_runtimes_macdn_net_"};
    const fs::path root = dir.path / "root";
    fs::create_directories(root / kDotnet / "shared/Microsoft.NETCore.App/9.0.0");
    rt::lnx::WalkConfig cfg;
    cfg.network_mounts = {"/usr/local/share/dotnet"};
    Acc acc;
    CHECK(mac::dotnet_rows_at(root, acc, cfg).empty());
    CHECK(acc.reason() == "macos:runtimes:network_fs_skipped");
    // an unrelated mount does not suppress the walk
    rt::lnx::WalkConfig other;
    other.network_mounts = {"/Volumes/share"};
    Acc acc2;
    CHECK(mac::dotnet_rows_at(root, acc2, other).size() == 1);
    CHECK_FALSE(acc2.any_failure());
}

TEST_CASE("macos dotnet: a too-small row budget yields row_cap (SYNTHETIC)",
          "[runtimes][dotnet][macos][cap]") {
    yuzu::test::TempDir dir{"yuzu_test_runtimes_macdn_cap_"};
    const fs::path root = dir.path / "root";
    for (const char* v : {"8.0.1", "8.0.2", "8.0.3"})
        fs::create_directories(root / kDotnet / "shared/Microsoft.NETCore.App" / v);
    rt::lnx::WalkConfig cfg;
    cfg.limits.rows = 2;
    Acc acc;
    CHECK(mac::dotnet_rows_at(root, acc, cfg).size() == 2);
    CHECK(acc.reason() == "macos:runtimes:row_cap");
}

// == jvm =========================================================================================

TEST_CASE("macos jvm: a bundle with release takes version, flavour and vendor from release "
          "(SYNTHETIC)",
          "[runtimes][jvm][macos]") {
    yuzu::test::TempDir dir{"yuzu_test_runtimes_macjvm_"};
    const fs::path root = dir.path / "root";
    std::string m;
    m += manifest_line(std::string{kJvms} + "/temurin-21.jdk/Contents/Home/release", kReleaseTemurin);
    // release wins over a disagreeing plist
    m += manifest_line(std::string{kJvms} + "/temurin-21.jdk/Contents/Info.plist",
                       "T:" + std::string{"<key>JVMVersion</key><string>1.0.0</string>"});
    materialize(root, m);
    Acc acc;
    CHECK(mac::jvm_rows_at(root, acc) ==
          std::vector<std::string>{"jvm|jdk|21.0.13|" + kJ + "/temurin-21.jdk|Eclipse Adoptium"});
    CHECK_FALSE(acc.any_failure());
}

TEST_CASE("macos jvm: release absent falls back to the Info.plist JavaVM dictionary (SYNTHETIC)",
          "[runtimes][jvm][macos]") {
    yuzu::test::TempDir dir{"yuzu_test_runtimes_macjvm_plist_"};
    const fs::path root = dir.path / "root";
    write_file(root / kJvms / "jdk-17.0.5.jdk/Contents/Info.plist", plist("17.0.5", "Oracle Corporation"));
    fs::create_directories(root / kJvms / "jdk-17.0.5.jdk/Contents/Home");
    write_file(root / kJvms / "zulu-11.jdk/Contents/Info.plist", plist("11.0.20", "Azul Systems, Inc."));
    Acc acc;
    CHECK(mac::jvm_rows_at(root, acc) ==
          std::vector<std::string>{
              "jvm|unmodelled|17.0.5|" + kJ + "/jdk-17.0.5.jdk|Oracle Corporation",
              "jvm|unmodelled|11.0.20|" + kJ + "/zulu-11.jdk|Azul Systems, Inc."});
    CHECK_FALSE(acc.any_failure());
}

TEST_CASE("macos jvm: neither release nor plist is an unmodelled row naming the bundle, flagged "
          "release_missing (SYNTHETIC)",
          "[runtimes][jvm][macos]") {
    yuzu::test::TempDir dir{"yuzu_test_runtimes_macjvm_none_"};
    const fs::path root = dir.path / "root";
    fs::create_directories(root / kJvms / "mystery.jdk/Contents/Home");
    Acc acc;
    CHECK(mac::jvm_rows_at(root, acc) ==
          std::vector<std::string>{"jvm|unmodelled|-|" + kJ + "/mystery.jdk|-"});
    CHECK(acc.reason() == "macos:runtimes:release_missing");
}

TEST_CASE("macos jvm: a Contents/Home symlink is refused, never followed (SYNTHETIC)",
          "[runtimes][jvm][macos]") {
    // MUTATION: following Home reads the canary release (JAVA_VERSION=9.9.9) into the row.
    yuzu::test::TempDir dir{"yuzu_test_runtimes_macjvm_homelink_"};
    const fs::path root = dir.path / "root";
    write_file(dir.path / "elsewhere/release", "JAVA_VERSION=\"9.9.9\"\nIMPLEMENTOR=\"canary\"\n");
    fs::create_directories(root / kJvms / "linked.jdk/Contents");
    make_symlink("../../../../../elsewhere", root / kJvms / "linked.jdk/Contents/Home");
    SECTION("no plist: the bundle row survives, with the refusal and no canary values") {
        Acc acc;
        const auto rows = mac::jvm_rows_at(root, acc);
        CHECK(rows == std::vector<std::string>{"jvm|unmodelled|-|" + kJ + "/linked.jdk|-"});
        CHECK(acc.reason() == "macos:runtimes:symlink_refused");
    }
    SECTION("plist present: its values are used, the refusal still recorded") {
        write_file(root / kJvms / "linked.jdk/Contents/Info.plist", plist("21.0.1", "Vendor"));
        Acc acc;
        CHECK(mac::jvm_rows_at(root, acc) ==
              std::vector<std::string>{"jvm|unmodelled|21.0.1|" + kJ + "/linked.jdk|Vendor"});
        CHECK(acc.reason() == "macos:runtimes:symlink_refused");
    }
}

TEST_CASE("macos jvm: symlinked entries and hops are never followed (SYNTHETIC)",
          "[runtimes][jvm][macos]") {
    yuzu::test::TempDir dir{"yuzu_test_runtimes_macjvm_link_"};
    const fs::path root = dir.path / "root";
    write_file(dir.path / "elsewhere/Contents/Home/release", "JAVA_VERSION=\"9.9.9\"\n");
    SECTION("a bundle entry that is a symlink (brew link) is skipped silently") {
        fs::create_directories(root / kJvms);
        make_symlink("../../../elsewhere", root / kJvms / "openjdk.jdk");
        Acc acc;
        CHECK(mac::jvm_rows_at(root, acc).empty());
        CHECK_FALSE(acc.any_failure());
    }
    SECTION("a symlinked Contents is refused") {
        fs::create_directories(root / kJvms / "c.jdk");
        make_symlink("../../../../elsewhere/Contents", root / kJvms / "c.jdk/Contents");
        Acc acc;
        CHECK(mac::jvm_rows_at(root, acc) == std::vector<std::string>{"jvm|unmodelled|-|" + kJ + "/c.jdk|-"});
        CHECK(acc.reason() == "macos:runtimes:symlink_refused");
    }
    SECTION("a symlinked JavaVirtualMachines directory is refused") {
        fs::create_directories(root / "Library/Java");
        make_symlink("../../../elsewhere", root / kJvms);
        Acc acc;
        CHECK(mac::jvm_rows_at(root, acc).empty());
        CHECK(acc.reason() == "macos:runtimes:symlink_refused");
    }
    SECTION("a symlinked release file is refused") {
        write_file(dir.path / "secret", "JAVA_VERSION=\"9.9.9\"\n");
        fs::create_directories(root / kJvms / "r.jdk/Contents/Home");
        make_symlink("../../../../../../../secret", root / kJvms / "r.jdk/Contents/Home/release");
        Acc acc;
        CHECK(mac::jvm_rows_at(root, acc).empty());
        CHECK(acc.reason() == "macos:runtimes:symlink_refused");
    }
}

TEST_CASE("macos jvm: hostile or oversized metadata never reads as an empty success (SYNTHETIC)",
          "[runtimes][jvm][macos]") {
    yuzu::test::TempDir dir{"yuzu_test_runtimes_macjvm_bad_"};
    const fs::path root = dir.path / "root";
    SECTION("release with no version is release_unparsable and no row") {
        write_file(root / kJvms / "a.jdk/Contents/Home/release", "SOURCE=\"x\"\n");
        Acc acc;
        CHECK(mac::jvm_rows_at(root, acc).empty());
        CHECK(acc.reason() == "macos:runtimes:release_unparsable");
    }
    SECTION("release over the read bound is oversized and no row") {
        write_file(root / kJvms / "a.jdk/Contents/Home/release", std::string(64 * 1024 + 1, 'x'));
        Acc acc;
        CHECK(mac::jvm_rows_at(root, acc).empty());
        CHECK(acc.reason() == "macos:runtimes:oversized");
    }
    SECTION("an over-long plist vendor is dropped and flagged field_oversized") {
        write_file(root / kJvms / "a.jdk/Contents/Info.plist", plist("17.0.5", std::string(300, 'v')));
        Acc acc;
        CHECK(mac::jvm_rows_at(root, acc) ==
              std::vector<std::string>{"jvm|unmodelled|17.0.5|" + kJ + "/a.jdk|-"});
        CHECK(acc.reason() == "macos:runtimes:field_oversized");
    }
    SECTION("a binary plist is not parsed: the bundle is flagged release_missing") {
        write_file(root / kJvms / "a.jdk/Contents/Info.plist", "bplist00\x01\x02");
        Acc acc;
        CHECK(mac::jvm_rows_at(root, acc) == std::vector<std::string>{"jvm|unmodelled|-|" + kJ + "/a.jdk|-"});
        CHECK(acc.reason() == "macos:runtimes:release_missing");
    }
}

TEST_CASE("macos jvm: an unopenable JavaVirtualMachines directory is permission_denied, never absent "
          "(SYNTHETIC)",
          "[runtimes][jvm][macos]") {
    if (privileged()) SKIP("permission bits are bypassed at euid 0");
    yuzu::test::TempDir dir{"yuzu_test_runtimes_macjvm_eacces_"};
    const fs::path root = dir.path / "root";
    fs::create_directories(root / kJvms / "a.jdk");
    REQUIRE(::chmod((root / kJvms).c_str(), 0000) == 0);
    Acc acc;
    const auto rows = mac::jvm_rows_at(root, acc);
    ::chmod((root / kJvms).c_str(), 0755);
    CHECK(rows.empty());
    CHECK(acc.reason() == "macos:runtimes:permission_denied");
}

TEST_CASE("macos jvm: absent roots are supported with zero rows and no token", "[runtimes][jvm][macos]") {
    yuzu::test::TempDir dir{"yuzu_test_runtimes_macjvm_absent_"};
    Acc acc;
    CHECK(mac::jvm_rows_at(dir.path, acc).empty());
    CHECK_FALSE(acc.any_failure());
}

TEST_CASE("macos jvm: network-mount root skipped; a too-small row budget yields row_cap (SYNTHETIC)",
          "[runtimes][jvm][macos][mounts][cap]") {
    yuzu::test::TempDir dir{"yuzu_test_runtimes_macjvm_net_"};
    const fs::path root = dir.path / "root";
    for (const char* b : {"a.jdk", "b.jdk", "c.jdk"})
        write_file(root / kJvms / b / "Contents/Home/release", "JAVA_VERSION=\"17.0.1\"\n");
    SECTION("mount under /Library") {
        rt::lnx::WalkConfig cfg;
        cfg.network_mounts = {"/Library"};
        Acc acc;
        CHECK(mac::jvm_rows_at(root, acc, cfg).empty());
        CHECK(acc.reason() == "macos:runtimes:network_fs_skipped");
    }
    SECTION("rows limit") {
        rt::lnx::WalkConfig cfg;
        cfg.limits.rows = 2;
        Acc acc;
        CHECK(mac::jvm_rows_at(root, acc, cfg).size() == 2);
        CHECK(acc.reason() == "macos:runtimes:row_cap");
    }
}

// == dispatch ====================================================================================

namespace {

struct LegRun {
    int rc = -1;
    std::vector<std::string> rows;
    YuzuResultStatus status = YUZU_RESULT_STATUS_UNDECLARED;
    YuzuResultCompleteness completeness = YUZU_RESULT_COMPLETENESS_UNKNOWN;
    std::string provenance;
};

const fs::path* g_leg_root = nullptr;

int leg_execute(YuzuCommandContext* raw, const char* action, const YuzuParam* /*params*/,
                std::size_t /*param_count*/) {
    yuzu::CommandContext ctx{raw};
    const auto a = rt::parse_action(action);
    if (!a) return 1;
    return mac::run_macos_at(ctx, *a, *g_leg_root);
}

LegRun run_leg(rt::Action action, const fs::path& root) {
    g_leg_root = &root;
    yuzu::test::ScopeExit reset{[] { g_leg_root = nullptr; }};
    YuzuPluginDescriptor descriptor{};
    descriptor.execute = &leg_execute;
    yuzu::agent::LocalDispatcher dispatcher;
    const auto result = dispatcher.run(&descriptor, rt::action_name(action));
    LegRun out;
    out.rc = result.rc;
    out.status = result.result_status;
    out.completeness = result.result_completeness;
    out.provenance = result.result_provenance;
    std::istringstream lines(result.captured);
    for (std::string line; std::getline(lines, line);)
        if (!line.empty()) out.rows.push_back(line);
    return out;
}

} // namespace

TEST_CASE("macos: run_macos_at dispatches dotnet and jvm (no longer planned) with the status row first "
          "(SYNTHETIC)",
          "[runtimes][dotnet][jvm][macos]") {
    // MUTATION: leaving either action on emit_planned reports unsupported|macos:planned.
    yuzu::test::TempDir dir{"yuzu_test_runtimes_macleg_"};
    const fs::path root = dir.path / "root";
    fs::create_directories(root / kDotnet / "shared/Microsoft.NETCore.App/9.0.0");
    write_file(root / kJvms / "a.jdk/Contents/Home/release", "JAVA_VERSION=\"17.0.1\"\nIMPLEMENTOR=\"V\"\n");
    {
        const auto run = run_leg(rt::Action::dotnet, root);
        CHECK(run.rc == 0);
        CHECK(run.rows == std::vector<std::string>{
                              "status|dotnet|supported|-",
                              "dotnet|core|9.0.0|" + kD + "/shared/Microsoft.NETCore.App/9.0.0|-"});
        CHECK(run.status == YUZU_RESULT_STATUS_OK);
        CHECK(run.completeness == YUZU_RESULT_COMPLETENESS_FULL);
    }
    {
        const auto run = run_leg(rt::Action::jvm, root);
        CHECK(run.rows == std::vector<std::string>{"status|jvm|supported|-",
                                                   "jvm|unmodelled|17.0.1|" + kJ + "/a.jdk|V"});
        CHECK(run.status == YUZU_RESULT_STATUS_OK);
    }
    {
        const auto run = run_leg(rt::Action::python, root); // absent framework: still supported
        CHECK(run.rows == std::vector<std::string>{"status|python|supported|-"});
    }
}

TEST_CASE("macos: a refused dotnet entry reports CONSTRAINED/PARTIAL through the leg (SYNTHETIC)",
          "[runtimes][dotnet][macos]") {
    yuzu::test::TempDir dir{"yuzu_test_runtimes_macleg_c_"};
    const fs::path root = dir.path / "root";
    fs::create_directories(root / kDotnet / "shared/Microsoft.NETCore.App");
    make_symlink("9.0.0", root / kDotnet / "shared/Microsoft.NETCore.App/9.0.1");
    const auto run = run_leg(rt::Action::dotnet, root);
    CHECK(run.rows == std::vector<std::string>{"status|dotnet|constrained|macos:runtimes:symlink_refused"});
    CHECK(run.status == YUZU_RESULT_STATUS_CONSTRAINED);
    CHECK(run.completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
    CHECK(run.provenance == "macos:runtimes:symlink_refused");
}

#endif // !defined(_WIN32)
