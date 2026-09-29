/**
 * test_bitlocker_windows_wmi.cpp — bitlocker_windows_wmi.hpp (Wave-3
 * native-acquisition migration: Win32_EncryptableVolume WMI query +
 * GetConversionStatus()/GetEncryptionMethod() method calls, replacing the
 * raw `manage-bde -status` popen).
 *
 * Portable and unguarded — the header takes plain
 * std::map<std::string, std::string> rows with no COM/<windows.h>
 * dependency, so this TU carries no platform guard and runs on every leg,
 * macOS included. That is deliberate: this is the only part of the
 * Windows WMI path that can be verified off-Windows, mirroring
 * test_discovery_parsers.cpp's format_mac48 precedent and
 * test_users_win_events.cpp's host-agnostic wevtapi-shape parser tests.
 * Fixture rows are synthetic (constructed to the documented WMI property
 * shapes), not a live capture — there is no portable way to run a real WMI
 * query from this suite.
 */
#include "bitlocker_windows_wmi.hpp"

#include <catch2/catch_test_macros.hpp>

#include <functional>
#include <map>
#include <optional>
#include <string>
#include <utility>
#include <vector>

using namespace yuzu::bitlocker::windows;

TEST_CASE("protection_status_text maps the documented ProtectionStatus enum",
          "[agent][bitlocker_windows_wmi]") {
    CHECK(protection_status_text("0") == "Protection Off");
    CHECK(protection_status_text("1") == "Protection On");
    CHECK(protection_status_text("2") == "Protection Unknown");
    CHECK(protection_status_text("") == "Protection Unknown");
    CHECK(protection_status_text("garbage") == "Protection Unknown");
}

TEST_CASE("conversion_status_text maps the documented ConversionStatus enum",
          "[agent][bitlocker_windows_wmi]") {
    CHECK(conversion_status_text("0") == "Fully Decrypted");
    CHECK(conversion_status_text("1") == "Fully Encrypted");
    CHECK(conversion_status_text("2") == "Encryption In Progress");
    CHECK(conversion_status_text("3") == "Decryption In Progress");
    CHECK(conversion_status_text("4") == "Encryption Paused");
    CHECK(conversion_status_text("5") == "Decryption Paused");
    CHECK(conversion_status_text("6") == "Unknown");
    CHECK(conversion_status_text("") == "Unknown");
}

TEST_CASE("format_percentage renders a plain integer with a trailing percent sign",
          "[agent][bitlocker_windows_wmi]") {
    CHECK(format_percentage("100") == "100%");
    CHECK(format_percentage("0") == "0%");
    CHECK(format_percentage("57") == "57%");
}

TEST_CASE("format_percentage reports unknown rather than fabricating a value",
          "[agent][bitlocker_windows_wmi]") {
    CHECK(format_percentage("") == "unknown");
    CHECK(format_percentage("N/A") == "unknown");
    CHECK(format_percentage("-1") == "unknown"); // '-' is not a digit — never a fabricated percent
    CHECK(format_percentage("50.5") == "unknown");
}

TEST_CASE("parse_encryptable_volumes maps a full WMI row", "[agent][bitlocker_windows_wmi]") {
    std::vector<WmiRow> rows = {
        {{"DeviceID", R"(\\?\Volume{7263f4b6-1234-5678-9abc-def012345678}\)"},
         {"DriveLetter", "C:"},
         {"ProtectionStatus", "1"}},
    };
    auto volumes = parse_encryptable_volumes(rows);
    REQUIRE(volumes.size() == 1);
    CHECK(volumes[0].device_id == R"(\\?\Volume{7263f4b6-1234-5678-9abc-def012345678}\)");
    CHECK(volumes[0].drive_letter == "C:");
    CHECK(volumes[0].protection_status_raw == "1");
}

TEST_CASE("parse_encryptable_volumes drops a row missing DeviceID",
          "[agent][bitlocker_windows_wmi]") {
    std::vector<WmiRow> rows = {
        {{"DriveLetter", "D:"}, {"ProtectionStatus", "0"}},
        {{"DeviceID", ""}, {"DriveLetter", "E:"}, {"ProtectionStatus", "0"}},
    };
    CHECK(parse_encryptable_volumes(rows).empty());
}

TEST_CASE("parse_encryptable_volumes tolerates a row missing DriveLetter/ProtectionStatus",
          "[agent][bitlocker_windows_wmi]") {
    std::vector<WmiRow> rows = {
        {{"DeviceID", R"(\\?\Volume{aaaaaaaa-0000-0000-0000-000000000000}\)"}},
    };
    auto volumes = parse_encryptable_volumes(rows);
    REQUIRE(volumes.size() == 1);
    CHECK(volumes[0].drive_letter.empty());
    CHECK(volumes[0].protection_status_raw.empty());
}

TEST_CASE("build_volume_object_path doubles every backslash for the WQL string literal",
          "[agent][bitlocker_windows_wmi]") {
    auto path = build_volume_object_path(R"(\\?\Volume{GUID}\)");
    CHECK(path == R"(Win32_EncryptableVolume.DeviceID="\\\\?\\Volume{GUID}\\")");
}

TEST_CASE("parse_conversion_status decodes a full method-call result row",
          "[agent][bitlocker_windows_wmi]") {
    WmiRow row = {{"ReturnValue", "0"}, {"ConversionStatus", "1"}, {"EncryptionPercentage", "100"}};
    auto state = parse_conversion_status(row);
    CHECK(state.conversion_text == "Fully Encrypted");
    CHECK(state.percent_text == "100%");
}

TEST_CASE("parse_conversion_status degrades honestly when fields are absent",
          "[agent][bitlocker_windows_wmi]") {
    WmiRow empty_row;
    auto state = parse_conversion_status(empty_row);
    CHECK(state.conversion_text == "Unknown");
    CHECK(state.percent_text == "unknown");
}

TEST_CASE("parse_conversion_status rejects a non-zero method ReturnValue",
          "[agent][bitlocker_windows_wmi]") {
    // The WMI method call transported successfully (COM layer OK) but
    // BitLocker's own method failed — out params must not be trusted even
    // though ConversionStatus/EncryptionPercentage are present and well-formed.
    WmiRow row = {{"ReturnValue", "2150694912"}, {"ConversionStatus", "0"},
                  {"EncryptionPercentage", "0"}};
    auto state = parse_conversion_status(row);
    CHECK(state.conversion_text == "Unknown");
    CHECK(state.percent_text == "unknown");
}

TEST_CASE("format_volume_row assembles the frozen 5-field shape with the real method",
          "[agent][bitlocker_windows_wmi]") {
    EncryptableVolume vol;
    vol.drive_letter = "C:";
    vol.protection_status_raw = "1";
    ConversionState conv{"Fully Encrypted", "100%"};
    CHECK(format_volume_row(vol, conv, "XTS-AES 128") ==
          "volume|C:|Fully Encrypted|100%|XTS-AES 128|Protection On");
}

TEST_CASE("format_volume_row falls back to unknown for a missing drive letter",
          "[agent][bitlocker_windows_wmi]") {
    EncryptableVolume vol; // drive_letter left empty
    ConversionState conv{"Unknown", "unknown"};
    CHECK(format_volume_row(vol, conv, "Unknown") ==
          "volume|unknown|Unknown|unknown|Unknown|Protection Unknown");
}

TEST_CASE("encryption_method_text maps the documented EncryptionMethod enum",
          "[agent][bitlocker_windows_wmi]") {
    CHECK(encryption_method_text("0") == "None");
    CHECK(encryption_method_text("1") == "AES 128 with Diffuser");
    CHECK(encryption_method_text("2") == "AES 256 with Diffuser");
    CHECK(encryption_method_text("3") == "AES 128");
    CHECK(encryption_method_text("4") == "AES 256");
    CHECK(encryption_method_text("5") == "Hardware Encryption");
    CHECK(encryption_method_text("6") == "XTS-AES 128");
    CHECK(encryption_method_text("7") == "XTS-AES 256");
    CHECK(encryption_method_text("8") == "Unknown");
    CHECK(encryption_method_text("") == "Unknown");
    CHECK(encryption_method_text("garbage") == "Unknown");
}

TEST_CASE("parse_encryption_method decodes a full method-call result row",
          "[agent][bitlocker_windows_wmi]") {
    WmiRow row = {{"ReturnValue", "0"}, {"EncryptionMethod", "6"}};
    CHECK(parse_encryption_method(row) == "XTS-AES 128");
}

TEST_CASE("parse_encryption_method degrades honestly when fields are absent",
          "[agent][bitlocker_windows_wmi]") {
    WmiRow empty_row;
    CHECK(parse_encryption_method(empty_row) == "Unknown");
}

TEST_CASE("parse_encryption_method rejects a non-zero method ReturnValue",
          "[agent][bitlocker_windows_wmi]") {
    // Transported fine (COM layer OK) but BitLocker's own method failed —
    // EncryptionMethod must not be trusted even though present and well-formed.
    WmiRow row = {{"ReturnValue", "2150694912"}, {"EncryptionMethod", "6"}};
    CHECK(parse_encryption_method(row) == "Unknown");
}

TEST_CASE("is_permission_denied recognizes the E_ACCESSDENIED phrasings",
          "[agent][bitlocker_windows_wmi]") {
    CHECK(is_permission_denied(std::optional<std::string>{"Access is denied."}));
    CHECK(is_permission_denied(std::optional<std::string>{"ACCESS DENIED"}));
    CHECK(is_permission_denied(std::optional<std::string>{"WMI call failed: 0x80070005"}));
}

TEST_CASE("is_permission_denied is false for an unrelated error or no error",
          "[agent][bitlocker_windows_wmi]") {
    CHECK_FALSE(is_permission_denied(std::optional<std::string>{"RPC server unavailable"}));
    CHECK_FALSE(is_permission_denied(std::nullopt));
}

// --- acquire_volume_row: injected-executor wiring proof ---------------------
//
// Adversarial-review finding (gate 2, PR3.3-b): test_bitlocker_local_
// dispatcher.cpp's only pin on the GetEncryptionMethod wiring was
// `method != "unknown"` (lowercase) -- production initializes
// `method = "Unknown"` (capitalized) before the call and keeps it on ANY
// failure, so deleting the GetEncryptionMethod call entirely still passed
// that test. These fixtures inject a fake executor and assert the exact
// method NAMES called and the exact VALUES threaded through -- a deleted
// or mis-wired call fails these directly, no live host or real WMI
// provider required.

namespace {

// Records every (object_path, method_name) call it receives and returns a
// canned row per method name, or std::nullopt for a name with no entry.
struct RecordingExecutor {
    std::vector<std::pair<std::string, std::string>> calls;
    std::map<std::string, WmiRow> responses;

    std::optional<WmiRow> operator()(const std::string& object_path,
                                     const std::string& method_name) {
        calls.emplace_back(object_path, method_name);
        auto it = responses.find(method_name);
        if (it == responses.end())
            return std::nullopt;
        return it->second;
    }
};

} // namespace

TEST_CASE("acquire_volume_row: calls both methods by their documented names",
          "[agent][bitlocker_windows_wmi]") {
    EncryptableVolume vol;
    vol.device_id = R"(\\?\Volume{aaaaaaaa-0000-0000-0000-000000000000}\)";
    vol.drive_letter = "C:";
    vol.protection_status_raw = "1";

    RecordingExecutor exec;
    exec.responses["GetConversionStatus"] = {
        {"ReturnValue", "0"}, {"ConversionStatus", "1"}, {"EncryptionPercentage", "100"}};
    exec.responses["GetEncryptionMethod"] = {{"ReturnValue", "0"}, {"EncryptionMethod", "6"}};

    acquire_volume_row(vol, std::ref(exec));

    REQUIRE(exec.calls.size() == 2);
    CHECK(exec.calls[0].second == "GetConversionStatus");
    CHECK(exec.calls[1].second == "GetEncryptionMethod");
}

TEST_CASE("acquire_volume_row: a real (non-Unknown) EncryptionMethod response reaches the "
          "output row -- the regression pin for a deleted/broken GetEncryptionMethod call",
          "[agent][bitlocker_windows_wmi]") {
    EncryptableVolume vol;
    vol.device_id = R"(\\?\Volume{bbbbbbbb-0000-0000-0000-000000000000}\)";
    vol.drive_letter = "D:";
    vol.protection_status_raw = "1";

    RecordingExecutor exec;
    exec.responses["GetConversionStatus"] = {
        {"ReturnValue", "0"}, {"ConversionStatus", "1"}, {"EncryptionPercentage", "100"}};
    exec.responses["GetEncryptionMethod"] = {{"ReturnValue", "0"}, {"EncryptionMethod", "7"}};

    auto row = acquire_volume_row(vol, std::ref(exec));

    // If GetEncryptionMethod were never called (or its object_path/method
    // name were wrong so the fixture map missed), method would stay
    // "Unknown" -- this fixture's injected value (XTS-AES 256, enum "7")
    // is deliberately distinct from that fallback so the assertion fails
    // on exactly that regression.
    CHECK(row == "volume|D:|Fully Encrypted|100%|XTS-AES 256|Protection On");
}

TEST_CASE("acquire_volume_row: GetEncryptionMethod failure degrades only the method field, "
          "conversion fields survive",
          "[agent][bitlocker_windows_wmi]") {
    EncryptableVolume vol;
    vol.device_id = R"(\\?\Volume{cccccccc-0000-0000-0000-000000000000}\)";
    vol.drive_letter = "E:";
    vol.protection_status_raw = "1";

    RecordingExecutor exec;
    exec.responses["GetConversionStatus"] = {
        {"ReturnValue", "0"}, {"ConversionStatus", "1"}, {"EncryptionPercentage", "100"}};
    // No "GetEncryptionMethod" entry -- operator() returns std::nullopt for it.

    auto row = acquire_volume_row(vol, std::ref(exec));
    CHECK(row == "volume|E:|Fully Encrypted|100%|Unknown|Protection On");
}

TEST_CASE("acquire_volume_row: GetConversionStatus failure degrades only conversion fields, "
          "method survives",
          "[agent][bitlocker_windows_wmi]") {
    EncryptableVolume vol;
    vol.device_id = R"(\\?\Volume{dddddddd-0000-0000-0000-000000000000}\)";
    vol.drive_letter = "F:";
    vol.protection_status_raw = "0";

    RecordingExecutor exec;
    // No "GetConversionStatus" entry.
    exec.responses["GetEncryptionMethod"] = {{"ReturnValue", "0"}, {"EncryptionMethod", "6"}};

    auto row = acquire_volume_row(vol, std::ref(exec));
    CHECK(row == "volume|F:|Unknown|unknown|XTS-AES 128|Protection Off");
}
