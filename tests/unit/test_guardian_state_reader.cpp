// test_guardian_state_reader.cpp - the production IStateReader (ADR-0021 spark
// rung 5). The file reader is fully exercised against a real filesystem on every
// platform; the systemd service reader runs on Linux (skipped cleanly when no
// system bus is reachable); the registry reader and the Windows SCM service
// reader are behind _WIN32 and are validated on the Windows rig (DGRHP). The
// non-Windows registry branch (Unknown-per-value) IS asserted here.

#include "guardian_state_reader.hpp"

#include "test_helpers.hpp" // yuzu::test::TempDir

#include <catch2/catch_test_macros.hpp>

#include <filesystem>
#include <fstream>
#include <string>

using namespace yuzu::agent;

namespace {

// NIST SHA-256("abc"); the file reader must reproduce this from the pinned fd.
constexpr const char* kSha256Abc =
    "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

std::filesystem::path write_file(const std::filesystem::path& dir, const std::string& name,
                                 const std::string& content) {
    std::filesystem::create_directories(dir);
    const auto fp = dir / name;
    std::ofstream o(fp, std::ios::binary);
    o.write(content.data(), static_cast<std::streamsize>(content.size()));
    o.close();
    return fp;
}

} // namespace

TEST_CASE("read_file: an absent path is a Known non-existent snapshot", "[spark][statereader]") {
    yuzu::test::TempDir dir;
    std::filesystem::create_directories(dir.path);
    GuardianStateReader reader;
    const auto r = reader.read_file(FileSparkParams{.path = (dir.path / "nope").string()},
                                    FileReadPlan{.hash_cap = 0});
    REQUIRE(r.known);
    REQUIRE_FALSE(r.snapshot.exists);
}

TEST_CASE("read_file: exists-only (hash_cap 0) resolves metadata without hashing",
          "[spark][statereader]") {
    yuzu::test::TempDir dir;
    const auto fp = write_file(dir.path, "f.txt", "abc");
    GuardianStateReader reader;
    const auto r = reader.read_file(FileSparkParams{.path = fp.string()}, FileReadPlan{.hash_cap = 0});
    REQUIRE(r.known);
    REQUIRE(r.snapshot.exists);
    REQUIRE(r.snapshot.readable);
    REQUIRE(r.snapshot.size == 3);
    REQUIRE(r.snapshot.hash.empty());        // hash_cap 0 -> not hashed
    REQUIRE_FALSE(r.snapshot.identity.empty());
    REQUIRE(r.snapshot.mtime_ns != 0);
}

TEST_CASE("read_file: hashes at the cap and reproduces the known SHA-256", "[spark][statereader]") {
    yuzu::test::TempDir dir;
    const auto fp = write_file(dir.path, "f.txt", "abc");
    GuardianStateReader reader;
    const auto r =
        reader.read_file(FileSparkParams{.path = fp.string()}, FileReadPlan{.hash_cap = 1u << 20});
    REQUIRE(r.known);
    REQUIRE(r.snapshot.exists);
    REQUIRE(r.snapshot.readable);
    REQUIRE(r.snapshot.size == 3);
    REQUIRE(r.snapshot.hash == kSha256Abc);
}

TEST_CASE("read_file: a file larger than the cap is Known oversize with no hash",
          "[spark][statereader]") {
    yuzu::test::TempDir dir;
    const auto fp = write_file(dir.path, "f.txt", "abc"); // 3 bytes
    GuardianStateReader reader;
    const auto r =
        reader.read_file(FileSparkParams{.path = fp.string()}, FileReadPlan{.hash_cap = 2});
    REQUIRE(r.known);
    REQUIRE(r.snapshot.exists);
    REQUIRE(r.snapshot.readable); // readable + empty hash + size>cap -> evaluator projects <oversize>
    REQUIRE(r.snapshot.size == 3);
    REQUIRE(r.snapshot.hash.empty());
}

TEST_CASE("read_file: a directory at the path exists but is unreadable", "[spark][statereader]") {
    yuzu::test::TempDir dir;
    std::filesystem::create_directories(dir.path);
    GuardianStateReader reader;
    const auto r =
        reader.read_file(FileSparkParams{.path = dir.path.string()}, FileReadPlan{.hash_cap = 64});
    REQUIRE(r.known);
    REQUIRE(r.snapshot.exists);
    REQUIRE_FALSE(r.snapshot.readable); // a directory is not a verifiable regular file
}

TEST_CASE("read_file: a changed file changes the identity/hash across reads", "[spark][statereader]") {
    yuzu::test::TempDir dir;
    const auto fp = write_file(dir.path, "f.txt", "abc");
    GuardianStateReader reader;
    const auto r1 =
        reader.read_file(FileSparkParams{.path = fp.string()}, FileReadPlan{.hash_cap = 1u << 20});
    write_file(dir.path, "f.txt", "abcd"); // rewrite content
    const auto r2 =
        reader.read_file(FileSparkParams{.path = fp.string()}, FileReadPlan{.hash_cap = 1u << 20});
    REQUIRE(r1.known);
    REQUIRE(r2.known);
    REQUIRE(r2.snapshot.size == 4);
    REQUIRE(r1.snapshot.hash != r2.snapshot.hash); // content changed -> digest changed
}

#ifndef _WIN32
TEST_CASE("read_file: a permission-denied existing file is Known unreadable, not absent/Unknown",
          "[spark][statereader]") {
    yuzu::test::TempDir dir;
    const auto fp = write_file(dir.path, "locked.txt", "secret");
    std::error_code ec;
    std::filesystem::permissions(fp, std::filesystem::perms::none, ec);
    if (ec)
        SKIP("could not remove file permissions");
    GuardianStateReader reader;
    const auto r =
        reader.read_file(FileSparkParams{.path = fp.string()}, FileReadPlan{.hash_cap = 64});
    std::filesystem::permissions(fp, std::filesystem::perms::owner_all, ec); // restore for cleanup
    if (r.known && r.snapshot.readable)
        SKIP("running as root: permission bits bypassed"); // open() succeeded, file is readable
    REQUIRE(r.known);                 // the target demonstrably EXISTS (stat succeeded)...
    REQUIRE(r.snapshot.exists);       // ...so this is a Known "<unreadable>" drift...
    REQUIRE_FALSE(r.snapshot.readable); // ...never a fabricated present-and-compliant, never Unknown
}

TEST_CASE("read_file: an unresolvable symlink loop is Unknown, never fabricated present",
          "[spark][statereader]") {
    yuzu::test::TempDir dir;
    std::filesystem::create_directories(dir.path);
    std::error_code ec;
    const auto a = dir.path / "a";
    const auto b = dir.path / "b";
    std::filesystem::create_symlink("b", a, ec); // a -> b
    std::filesystem::create_symlink("a", b, ec); // b -> a  (loop)
    if (ec)
        SKIP("could not create symlinks");
    GuardianStateReader reader;
    const auto r = reader.read_file(FileSparkParams{.path = a.string()}, FileReadPlan{.hash_cap = 64});
    REQUIRE_FALSE(r.known); // open + stat both ELOOP: cannot determine, so NOT a Known present
}

TEST_CASE("read_registry off Windows yields Unknown per requested value", "[spark][statereader]") {
    GuardianStateReader reader;
    const auto r = reader.read_registry(
        RegistrySparkParams{.hive = "HKLM", .key = "Software\\Yuzu"},
        RegistryReadPlan{.value_names = {"Alpha", "Beta"}});
    REQUIRE(r.values.size() == 2);
    for (const auto& [name, res] : r.values) {
        INFO("value_name=" << name);
        REQUIRE_FALSE(res.known); // registry cannot be read off Windows -> Unknown, never absent
    }
}
#endif

#if defined(__linux__) && defined(YUZU_HAVE_LIBSYSTEMD)
TEST_CASE("read_service rejects an invalid unit name as Unknown (no bus touched)",
          "[spark][statereader]") {
    GuardianStateReader reader;
    const auto r = reader.read_service(ServiceSparkParams{.service_name = "bad name!"});
    REQUIRE_FALSE(r.known); // charset-invalid name is refused before any sd_bus work
    REQUIRE(r.error.find("invalid unit name") != std::string::npos);
}

TEST_CASE("read_service maps a truly absent unit to Stopped (R5)", "[spark][statereader]") {
    GuardianStateReader reader;
    const auto r =
        reader.read_service(ServiceSparkParams{.service_name = "yuzu-nonexistent-unit-xyz.service"});
    if (!r.known && r.error.find("sd_bus_open_system") != std::string::npos) {
        SKIP("no reachable system bus in this environment");
    }
    REQUIRE(r.known);                                       // absence is a KNOWN terminal state...
    REQUIRE(r.snapshot == ServiceRunState::Stopped);        // ...that folds to Stopped (R5)
}
#endif

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

TEST_CASE("read_registry (Windows): SZ/DWORD round-trip, REG_BINARY unsupported, absent value",
          "[spark][statereader]") {
    const wchar_t* kSub = L"Software\\YuzuStateReaderTest";
    HKEY h = nullptr;
    REQUIRE(RegCreateKeyExW(HKEY_CURRENT_USER, kSub, 0, nullptr, 0, KEY_SET_VALUE, nullptr, &h,
                            nullptr) == ERROR_SUCCESS);
    const wchar_t* sval = L"hello world";
    RegSetValueExW(h, L"Str", 0, REG_SZ, reinterpret_cast<const BYTE*>(sval),
                   static_cast<DWORD>((wcslen(sval) + 1) * sizeof(wchar_t)));
    DWORD dval = 4242;
    RegSetValueExW(h, L"Num", 0, REG_DWORD, reinterpret_cast<const BYTE*>(&dval), sizeof(dval));
    const BYTE bval[] = {0xDE, 0xAD, 0xBE, 0xEF, 0x00};
    RegSetValueExW(h, L"Bin", 0, REG_BINARY, bval, sizeof(bval));
    RegCloseKey(h);

    GuardianStateReader reader;
    const auto r = reader.read_registry(
        RegistrySparkParams{.hive = "HKCU", .key = "Software\\YuzuStateReaderTest"},
        RegistryReadPlan{.value_names = {"Str", "Num", "Bin", "Missing"}});

    RegDeleteKeyW(HKEY_CURRENT_USER, kSub); // cleanup (values only, no subkeys)

    REQUIRE(r.values.size() == 4);
    REQUIRE(r.values.at("Str").known);
    REQUIRE(r.values.at("Str").snapshot.present);
    REQUIRE(r.values.at("Str").snapshot.supported);
    REQUIRE(r.values.at("Str").snapshot.value == "hello world");
    REQUIRE(r.values.at("Num").snapshot.present);
    REQUIRE(r.values.at("Num").snapshot.value == "4242"); // REG_DWORD -> decimal
    REQUIRE(r.values.at("Bin").snapshot.present);
    REQUIRE_FALSE(r.values.at("Bin").snapshot.supported); // REG_BINARY -> "<unsupported-type>"
    REQUIRE(r.values.at("Missing").known);
    REQUIRE_FALSE(r.values.at("Missing").snapshot.present); // absent value -> "<absent>"
}

TEST_CASE("read_service (Windows): a live service is Known; an absent one folds to Stopped (R5)",
          "[spark][statereader]") {
    GuardianStateReader reader;
    // EventLog is present and running on every live Windows box (a terminal state -> Known).
    const auto live = reader.read_service(ServiceSparkParams{.service_name = "EventLog"});
    REQUIRE(live.known);
    const auto absent =
        reader.read_service(ServiceSparkParams{.service_name = "YuzuNoSuchServiceXyz123"});
    REQUIRE(absent.known);
    REQUIRE(absent.snapshot == ServiceRunState::Stopped); // R5: absent SCM service -> Stopped
}
#endif // _WIN32
