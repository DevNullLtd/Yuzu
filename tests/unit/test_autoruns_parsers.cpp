/**
 * test_autoruns_parsers.cpp — pure autoruns parser tests (autoruns_parsers.hpp).
 *
 * Every parser under test is fed either a REAL CAPTURE fixture (A1/A2,
 * `tests/unit/fixtures/wave7/autoruns/{windows,linux,macos}/`, loaded via
 * YUZU_TEST_FIXTURE_DIR with REQUIRE(exists) -- never skipped on a missing
 * fixture) or a RECONSTRUCTION negative proving graceful handling of
 * malformed/truncated input. No OS call anywhere in this file: every
 * fixture is read as plain bytes/text and handed to a pure function.
 */
#include "autoruns_catalog.hpp"
#include "autoruns_parsers.hpp"

#include <constraint_accumulator.hpp>

#include <catch2/catch_test_macros.hpp>

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <map>
#include <sstream>
#include <string>
#include <vector>

using namespace yuzu::autoruns;
namespace fs = std::filesystem;

namespace {

fs::path fixture_path(const std::string& rel) {
    return fs::path{YUZU_TEST_FIXTURE_DIR} / "wave7" / "autoruns" / rel;
}

std::string read_fixture_bytes(const std::string& rel) {
    const fs::path p = fixture_path(rel);
    REQUIRE(fs::exists(p));
    std::ifstream f(p, std::ios::binary);
    std::ostringstream ss;
    ss << f.rdbuf();
    return ss.str();
}

/// The Windows .reg fixtures are real `reg export` output: UTF-16LE with a
/// BOM. Strips the BOM and decodes via the parser header's own
/// utf16le_to_utf8 (this is a file-encoding concern, not the reg(1) TEXT
/// grammar parse_reg_run_values itself performs -- see that function's doc
/// comment).
std::string read_fixture_reg_text(const std::string& rel) {
    const std::string raw = read_fixture_bytes(rel);
    std::size_t start = 0;
    if (raw.size() >= 2 && static_cast<unsigned char>(raw[0]) == 0xFF &&
        static_cast<unsigned char>(raw[1]) == 0xFE)
        start = 2;
    std::vector<unsigned char> bytes(raw.begin() + static_cast<long>(start), raw.end());
    return utf16le_to_utf8(std::span<const unsigned char>{bytes.data(), bytes.size()});
}

/// Extracts the comma-hex byte payload of a `"name"=hex:....` line (no
/// continuation) -- test-setup convenience only, not a claim on
/// parse_reg_run_values' own hex(2) handling (which is exercised directly
/// via the Run-key fixtures below).
std::vector<unsigned char> hex_bytes_after(const std::string& text, const std::string& marker) {
    std::vector<unsigned char> out;
    std::size_t pos = text.find(marker);
    REQUIRE(pos != std::string::npos);
    pos += marker.size();
    std::size_t end = text.find('\n', pos);
    std::string_view line = end == std::string::npos ? std::string_view{text}.substr(pos)
                                                      : std::string_view{text}.substr(pos, end - pos);
    std::size_t i = 0;
    while (i < line.size()) {
        while (i < line.size() && (line[i] == ' ' || line[i] == ',' || line[i] == '\r')) ++i;
        std::size_t start = i;
        while (i < line.size() && line[i] != ',' && line[i] != '\r') ++i;
        if (i > start) {
            unsigned int v = 0;
            for (std::size_t k = start; k < i; ++k) {
                char c = line[k];
                v <<= 4;
                if (c >= '0' && c <= '9') v |= static_cast<unsigned int>(c - '0');
                else if (c >= 'a' && c <= 'f') v |= static_cast<unsigned int>(c - 'a' + 10);
                else if (c >= 'A' && c <= 'F') v |= static_cast<unsigned int>(c - 'A' + 10);
            }
            out.push_back(static_cast<unsigned char>(v & 0xFF));
        }
    }
    return out;
}

} // namespace

// ── format_row / format_source_status / sanitize ────────────────────────

TEST_CASE("autoruns: format_row separates fields and folds a literal pipe", "[autoruns][format]") {
    Row row{};
    row.source_id = SourceId::win_run_hklm;
    row.catalog_version = kAutorunSourceCatalogVersion;
    row.location = "HKLM\\...\\Run";
    row.entry = "Evil|Entry";
    row.target = "C:\\evil.exe";
    row.args = "-x";
    row.enabled = Enabled::enabled;
    row.scope = Scope::system;
    row.user = "-";
    row.signed_state = Signed::not_checked;
    row.mtime = 12345;
    const auto s = format_row(row);
    CHECK(s.rfind("autorun|win_run_hklm|1|", 0) == 0);
    CHECK(s.find("Evil\u2502Entry") != std::string::npos);
    CHECK(s.find('|', s.find("Evil\u2502Entry") + 12) != std::string::npos);
}

TEST_CASE("autoruns: format_source_status renders '-' for a declared-only row, a real "
          "count otherwise",
          "[autoruns][format]") {
    CHECK(format_source_status(SourceId::win_run_hklm, YUZU_SUPPORT_SUPPORTED, std::nullopt,
                               "declared") == "source|win_run_hklm|supported|-|declared");
    CHECK(format_source_status(SourceId::lnx_init_d, YUZU_SUPPORT_CONSTRAINED, std::size_t{3},
                               "listing-only") ==
          "source|lnx_init_d|constrained|3|listing-only");
    CHECK(format_source_status(SourceId::mac_login_items, YUZU_SUPPORT_UNSUPPORTED, std::size_t{0},
                               "foreign_os") == "source|mac_login_items|unsupported|0|foreign_os");
}

// ── 0b. utf16le_to_utf8 ───────────────────────────────────────────────────

TEST_CASE("autoruns: utf16le_to_utf8 pairs a real surrogate pair into one "
          "supplementary-plane code point (4-byte UTF-8), not two separate "
          "3-byte CESU-8 sequences",
          "[autoruns][parsers]") {
    // U+1F600 GRINNING FACE -> UTF-16LE surrogate pair D83D DE00 -> UTF-8
    // F0 9F 98 80.
    const std::vector<unsigned char> bytes = {0x3D, 0xD8, 0x00, 0xDE, 0x00, 0x00};
    const auto out = utf16le_to_utf8(std::span<const unsigned char>{bytes.data(), bytes.size()});
    REQUIRE(out.size() == 4);
    CHECK(static_cast<unsigned char>(out[0]) == 0xF0);
    CHECK(static_cast<unsigned char>(out[1]) == 0x9F);
    CHECK(static_cast<unsigned char>(out[2]) == 0x98);
    CHECK(static_cast<unsigned char>(out[3]) == 0x80);
}

TEST_CASE("autoruns: utf16le_to_utf8 emits U+FFFD for an unpaired high surrogate "
          "or a lone low surrogate, never a half-formed sequence",
          "[autoruns][parsers]") {
    SECTION("high surrogate followed by a non-surrogate unit") {
        const std::vector<unsigned char> bytes = {0x3D, 0xD8, 'A', 0x00, 0x00, 0x00};
        const auto out =
            utf16le_to_utf8(std::span<const unsigned char>{bytes.data(), bytes.size()});
        // U+FFFD (EF BF BD) followed by 'A'.
        REQUIRE(out.size() == 4);
        CHECK(static_cast<unsigned char>(out[0]) == 0xEF);
        CHECK(static_cast<unsigned char>(out[1]) == 0xBF);
        CHECK(static_cast<unsigned char>(out[2]) == 0xBD);
        CHECK(out[3] == 'A');
    }
    SECTION("lone low surrogate with no preceding high surrogate") {
        const std::vector<unsigned char> bytes = {0x00, 0xDE, 0x00, 0x00};
        const auto out =
            utf16le_to_utf8(std::span<const unsigned char>{bytes.data(), bytes.size()});
        REQUIRE(out.size() == 3);
        CHECK(static_cast<unsigned char>(out[0]) == 0xEF);
        CHECK(static_cast<unsigned char>(out[1]) == 0xBF);
        CHECK(static_cast<unsigned char>(out[2]) == 0xBD);
    }
}

// ── 1. split_command_line ────────────────────────────────────────────────

TEST_CASE("autoruns: split_command_line separates a quoted path from its flags "
          "(HKLM_Run.reg RtkAudUService, real capture)",
          "[autoruns][parsers]") {
    const auto text = read_fixture_reg_text("windows/HKLM_Run.reg");
    const auto values = parse_reg_run_values(text);
    const RegValue* rtk = nullptr;
    for (const auto& v : values)
        if (v.name == "RtkAudUService") rtk = &v;
    REQUIRE(rtk != nullptr);
    const auto split = split_command_line(rtk->data);
    CHECK(split.target ==
          "C:\\WINDOWS\\System32\\DriverStore\\FileRepository\\"
          "realtekservice.inf_amd64_c607c18cb15933d8\\RtkAudUService64.exe");
    CHECK(split.args == "-background");
}

TEST_CASE("autoruns: split_command_line handles a rundll32-style bare command",
          "[autoruns][parsers]") {
    // RECONSTRUCTION: no real capture in this catalog carries a rundll32
    // Run entry; this pins the documented bare-command shape.
    const auto split = split_command_line("rundll32.exe shell32.dll,Control_RunDLL");
    CHECK(split.target == "rundll32.exe");
    CHECK(split.args == "shell32.dll,Control_RunDLL");
}

TEST_CASE("autoruns: split_command_line on an empty string returns an empty split",
          "[autoruns][parsers]") {
    const auto split = split_command_line("");
    CHECK(split.target.empty());
    CHECK(split.args.empty());
}

TEST_CASE("autoruns: split_command_line closes a quoted target on an EVEN "
          "backslash run before the closing quote -- a bare single-backslash "
          "check (this function's prior form) gets this wrong for a run of 2 "
          "or more",
          "[autoruns][parsers]") {
    // Input: "C:\dir\\" -flag -- two backslashes immediately before the
    // closing quote is an EVEN run, so the quote genuinely terminates the
    // target (a plain trailing path separator; the target keeps both
    // backslashes verbatim, this function never unescapes), and "-flag" is
    // the argument tail -- not scanned past as if the quote were escaped.
    const auto split = split_command_line("\"C:\\dir\\\\\" -flag");
    CHECK(split.target == "C:\\dir\\\\");
    CHECK(split.args == "-flag");
}

TEST_CASE("autoruns: split_command_line treats an ODD backslash run before a "
          "quote as an escaped quote, not the real close",
          "[autoruns][parsers]") {
    // Input: "C:\a\"b\\" -flag -- ONE backslash immediately before the
    // inner quote is an ODD run (escaped, not a real close), so scanning
    // continues past it to the actual closing quote (preceded by an even,
    // 2-backslash run) rather than stopping early and reading " -flag"
    // (attached to the wrong half) as part of the target.
    const auto split = split_command_line("\"C:\\a\\\"b\\\\\" -flag");
    CHECK(split.target == "C:\\a\\\"b\\\\");
    CHECK(split.args == "-flag");
}

// ── 2. parse_reg_run_values ──────────────────────────────────────────────

TEST_CASE("autoruns: parse_reg_run_values decodes a hex(2) REG_EXPAND_SZ value "
          "(HKLM_Run.reg SecurityHealth, real capture)",
          "[autoruns][parsers]") {
    const auto text = read_fixture_reg_text("windows/HKLM_Run.reg");
    const auto values = parse_reg_run_values(text);
    REQUIRE(values.size() == 2);
    const RegValue* sh = nullptr;
    for (const auto& v : values)
        if (v.name == "SecurityHealth") sh = &v;
    REQUIRE(sh != nullptr);
    CHECK(sh->data.find("SecurityHealthSystray.exe") != std::string::npos);
}

TEST_CASE("autoruns: parse_reg_run_values on an empty key section returns no values "
          "(HKLM_RunOnce.reg, real capture)",
          "[autoruns][parsers]") {
    const auto text = read_fixture_reg_text("windows/HKLM_RunOnce.reg");
    CHECK(parse_reg_run_values(text).empty());
}

TEST_CASE("autoruns: parse_reg_run_values decodes quoted HKU values "
          "(HKU_SID_Run.reg Discord, real capture)",
          "[autoruns][parsers]") {
    const auto text = read_fixture_reg_text("windows/HKU_SID_Run.reg");
    const auto values = parse_reg_run_values(text);
    const RegValue* discord = nullptr;
    for (const auto& v : values)
        if (v.name == "Discord") discord = &v;
    REQUIRE(discord != nullptr);
    const auto split = split_command_line(discord->data);
    CHECK(split.target == "C:\\Users\\Alex\\AppData\\Local\\Discord\\Update.exe");
    CHECK(split.args == "--processStart Discord.exe");
}

TEST_CASE("autoruns: parse_reg_run_values ignores non-string value types",
          "[autoruns][parsers]") {
    // RECONSTRUCTION: a dword-typed value alongside a real string value must
    // not be mis-decoded as string data.
    const std::string text =
        "Windows Registry Editor Version 5.00\n\n"
        "[HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run]\n"
        "\"NotAString\"=dword:00000001\n"
        "\"Real\"=\"C:\\\\real.exe\"\n";
    const auto values = parse_reg_run_values(text);
    REQUIRE(values.size() == 1);
    CHECK(values[0].name == "Real");
    CHECK(values[0].data == "C:\\real.exe");
}

// ── 3. parse_startup_approved_blob ───────────────────────────────────────

TEST_CASE("autoruns: parse_startup_approved_blob reads byte0=0x03 as disabled "
          "(HKLM_StartupApproved_Run.reg SecurityHealth, real capture)",
          "[autoruns][parsers]") {
    const auto text = read_fixture_reg_text("windows/HKLM_StartupApproved_Run.reg");
    const auto bytes = hex_bytes_after(text, "\"SecurityHealth\"=hex:");
    REQUIRE(bytes.size() == 12);
    CHECK(parse_startup_approved_blob(std::span<const unsigned char>{bytes.data(), bytes.size()}) ==
          Enabled::disabled);
}

TEST_CASE("autoruns: parse_startup_approved_blob reads byte0=0x02 as enabled",
          "[autoruns][parsers]") {
    // RECONSTRUCTION: the real captures on this host are all disabled (0x03);
    // this pins the documented enabled encoding.
    const std::array<unsigned char, 12> blob{0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    CHECK(parse_startup_approved_blob(std::span<const unsigned char>{blob.data(), blob.size()}) ==
          Enabled::enabled);
}

TEST_CASE("autoruns: parse_startup_approved_blob on a truncated 3-byte blob is unmodelled",
          "[autoruns][parsers]") {
    // RECONSTRUCTION negative (acceptance criterion): a short/malformed read
    // must never be guessed at as enabled or disabled.
    const std::array<unsigned char, 3> blob{0x03, 0x00, 0x00};
    CHECK(parse_startup_approved_blob(std::span<const unsigned char>{blob.data(), blob.size()}) ==
          Enabled::unmodelled);
}

// ── 4. parse_winlogon_shell / parse_winlogon_userinit ────────────────────

TEST_CASE("autoruns: parse_winlogon_shell on the documented default flags nothing "
          "(HKLM_Winlogon.reg Shell, real capture)",
          "[autoruns][parsers]") {
    const auto text = read_fixture_reg_text("windows/HKLM_Winlogon.reg");
    const auto values = parse_reg_run_values(text);
    const RegValue* shell = nullptr;
    for (const auto& v : values)
        if (v.name == "Shell") shell = &v;
    REQUIRE(shell != nullptr);
    CHECK(shell->data == "explorer.exe");
    const auto parsed = parse_winlogon_shell(shell->data);
    CHECK_FALSE(parsed.flag_beyond_default);
}

TEST_CASE("autoruns: parse_winlogon_userinit tolerates the trailing-comma default "
          "(HKLM_Winlogon.reg Userinit, real capture)",
          "[autoruns][parsers]") {
    const auto text = read_fixture_reg_text("windows/HKLM_Winlogon.reg");
    const auto values = parse_reg_run_values(text);
    const RegValue* userinit = nullptr;
    for (const auto& v : values)
        if (v.name == "Userinit") userinit = &v;
    REQUIRE(userinit != nullptr);
    CHECK(userinit->data == "C:\\windows\\system32\\userinit.exe,");
    const auto parsed = parse_winlogon_userinit(userinit->data);
    REQUIRE(parsed.entries.size() == 1); // the trailing comma's empty tail is dropped
    CHECK_FALSE(parsed.flag_beyond_default);
}

TEST_CASE("autoruns: parse_winlogon_shell flags a program appended beyond explorer.exe",
          "[autoruns][parsers]") {
    // RECONSTRUCTION: a hijacked Shell value chaining a second program.
    const auto parsed = parse_winlogon_shell("explorer.exe,evil.exe");
    REQUIRE(parsed.entries.size() == 2);
    CHECK(parsed.flag_beyond_default);
}

// ── 5. parse_appinit_dlls ─────────────────────────────────────────────────

TEST_CASE("autoruns: parse_appinit_dlls on an empty value returns no DLLs "
          "(HKLM_AppInit_DLLs.reg, real capture)",
          "[autoruns][parsers]") {
    // This fixture is a full, unscoped hive export (not single-key-scoped
    // text as parse_reg_run_values's own doc comment describes as the
    // calling convention) -- it is provided by A1/A2 and not owned by this
    // package, so it cannot be re-scoped here. parse_reg_run_values is
    // documented to collect values "across every section in the text",
    // so feeding it a wider export and filtering the result by name (as
    // done below) is exactly how a real caller must behave against any
    // hive export that happens to carry adjacent unrelated keys.
    const auto text = read_fixture_reg_text("windows/HKLM_AppInit_DLLs.reg");
    const auto values = parse_reg_run_values(text);
    const RegValue* v = nullptr;
    for (const auto& e : values)
        if (e.name == "AppInit_DLLs") v = &e;
    REQUIRE(v != nullptr);
    CHECK(v->data.empty());
    CHECK(parse_appinit_dlls(v->data).empty());
}

TEST_CASE("autoruns: parse_appinit_dlls splits a populated, space-separated list",
          "[autoruns][parsers]") {
    // RECONSTRUCTION: this host's own AppInit_DLLs is empty; pins the
    // documented populated shape.
    const auto dlls = parse_appinit_dlls("C:\\evil1.dll C:\\evil2.dll");
    REQUIRE(dlls.size() == 2);
    CHECK(dlls[0] == "C:\\evil1.dll");
    CHECK(dlls[1] == "C:\\evil2.dll");
}

// ── 6. parse_ifeo_debugger ────────────────────────────────────────────────

TEST_CASE("autoruns: parse_ifeo_debugger with no Debugger value reports has_debugger=false "
          "(HKLM_IFEO_sample.reg appverif.exe, real capture)",
          "[autoruns][parsers]") {
    const auto entry = parse_ifeo_debugger("appverif.exe", "");
    CHECK_FALSE(entry.has_debugger);
    CHECK(entry.exe_name == "appverif.exe");
}

TEST_CASE("autoruns: parse_ifeo_debugger with a Debugger value reports it",
          "[autoruns][parsers]") {
    // RECONSTRUCTION: the classic IFEO hijack shape (a debugger substituted
    // for the named exe).
    const auto entry = parse_ifeo_debugger("notepad.exe", "C:\\evil.exe");
    CHECK(entry.has_debugger);
    CHECK(entry.debugger == "C:\\evil.exe");
}

// ── 6b. resolve_profile_shell_folder ─────────────────────────────────────

TEST_CASE("autoruns: resolve_profile_shell_folder expands %USERPROFILE% against "
          "the ENUMERATED PROFILE's own path, never a process environment lookup "
          "(#4219 -- this is the fix for the bug that resolved against the agent's "
          "own LocalSystem environment instead)",
          "[autoruns][parsers]") {
    auto no_machine_lookup = [](std::string_view) -> std::optional<std::string> {
        FAIL("machine_var should not be consulted for a user-scoped token");
        return std::nullopt;
    };
    const auto result = resolve_profile_shell_folder(
        "%USERPROFILE%\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup",
        "REG_EXPAND_SZ", "C:\\Users\\alice", "alice", no_machine_lookup);
    REQUIRE(result.path.has_value());
    CHECK(*result.path ==
         "C:\\Users\\alice\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup");
    CHECK(result.constraint.empty());
}

TEST_CASE("autoruns: resolve_profile_shell_folder's token match is case-insensitive "
          "(%AppData% not just %APPDATA%) and shorthand tokens resolve against the "
          "profile path, not a lookup",
          "[autoruns][parsers]") {
    auto no_machine_lookup = [](std::string_view) -> std::optional<std::string> {
        FAIL("machine_var should not be consulted for a user-scoped token");
        return std::nullopt;
    };
    const auto appdata = resolve_profile_shell_folder("%AppData%\\CorpStartup", "REG_EXPAND_SZ",
                                                      "C:\\Users\\alice", "alice",
                                                      no_machine_lookup);
    REQUIRE(appdata.path.has_value());
    CHECK(*appdata.path == "C:\\Users\\alice\\AppData\\Roaming\\CorpStartup");

    const auto localappdata = resolve_profile_shell_folder(
        "%LOCALAPPDATA%\\CorpStartup", "REG_EXPAND_SZ", "C:\\Users\\alice", "alice",
        no_machine_lookup);
    REQUIRE(localappdata.path.has_value());
    CHECK(*localappdata.path == "C:\\Users\\alice\\AppData\\Local\\CorpStartup");

    const auto username = resolve_profile_shell_folder("C:\\Corp\\%USERNAME%\\Startup",
                                                        "REG_EXPAND_SZ", "C:\\Users\\alice",
                                                        "alice", no_machine_lookup);
    REQUIRE(username.path.has_value());
    CHECK(*username.path == "C:\\Corp\\alice\\Startup");
}

TEST_CASE("autoruns: resolve_profile_shell_folder resolves a machine-scoped token "
          "(identical for every user on this host) via the injected lookup",
          "[autoruns][parsers]") {
    const auto result = resolve_profile_shell_folder(
        "%SystemDrive%\\CorpStartup", "REG_EXPAND_SZ", "C:\\Users\\alice", "alice",
        [](std::string_view name) -> std::optional<std::string> {
            CHECK(name == "SystemDrive");
            return std::string{"C:"};
        });
    REQUIRE(result.path.has_value());
    CHECK(*result.path == "C:\\CorpStartup");
    CHECK(result.constraint.empty());
}

TEST_CASE("autoruns: resolve_profile_shell_folder reports startup_redirect_unresolved, "
          "never a guess, for a token it doesn't recognize",
          "[autoruns][parsers]") {
    const auto result = resolve_profile_shell_folder(
        "%OneDrive%\\Startup", "REG_EXPAND_SZ", "C:\\Users\\alice", "alice",
        [](std::string_view) -> std::optional<std::string> {
            FAIL("OneDrive is not in the machine-scoped allowlist");
            return std::nullopt;
        });
    CHECK_FALSE(result.path.has_value());
    CHECK(result.constraint == "startup_redirect_unresolved");
}

TEST_CASE("autoruns: resolve_profile_shell_folder reports startup_redirect_unresolved "
          "when an allowlisted machine token's lookup itself comes back empty, never "
          "a partial/guessed path",
          "[autoruns][parsers]") {
    const auto result = resolve_profile_shell_folder(
        "%ProgramData%\\CorpStartup", "REG_EXPAND_SZ", "C:\\Users\\alice", "alice",
        [](std::string_view) -> std::optional<std::string> { return std::nullopt; });
    CHECK_FALSE(result.path.has_value());
    CHECK(result.constraint == "startup_redirect_unresolved");
}

TEST_CASE("autoruns: resolve_profile_shell_folder reports startup_redirect_unresolved "
          "for an unterminated '%' with no closing '%' anywhere in the value "
          "(governance Gate 4 unhappy-path: an adversarial/truncated registry value "
          "shape with no valid token boundary at all)",
          "[autoruns][parsers]") {
    const auto result = resolve_profile_shell_folder(
        "%USERPROFILE%\\Startup\\%NOCLOSE", "REG_EXPAND_SZ", "C:\\Users\\alice", "alice",
        [](std::string_view) -> std::optional<std::string> {
            FAIL("no allowlisted token appears before the unterminated one");
            return std::nullopt;
        });
    CHECK_FALSE(result.path.has_value());
    CHECK(result.constraint == "startup_redirect_unresolved");
}

TEST_CASE("autoruns: resolve_profile_shell_folder reports startup_redirect_unresolved "
          "for an empty '%%' token name",
          "[autoruns][parsers]") {
    const auto result = resolve_profile_shell_folder(
        "%USERPROFILE%\\Start%%Menu", "REG_EXPAND_SZ", "C:\\Users\\alice", "alice",
        [](std::string_view) -> std::optional<std::string> {
            FAIL("no allowlisted token appears before the empty one");
            return std::nullopt;
        });
    CHECK_FALSE(result.path.has_value());
    CHECK(result.constraint == "startup_redirect_unresolved");
}

TEST_CASE("autoruns: resolve_profile_shell_folder treats REG_SZ as a literal path, "
          "no token expansion -- a stray '%' is kept verbatim",
          "[autoruns][parsers]") {
    const auto result = resolve_profile_shell_folder("C:\\CorpStartup\\100%done", "REG_SZ",
                                                      "C:\\Users\\alice", "alice",
                                                      [](std::string_view) { return std::nullopt; });
    REQUIRE(result.path.has_value());
    CHECK(*result.path == "C:\\CorpStartup\\100%done");
    CHECK(result.constraint.empty());
}

TEST_CASE("autoruns: resolve_profile_shell_folder reports startup_redirect_bad_type "
          "for a value type that isn't REG_SZ/REG_EXPAND_SZ",
          "[autoruns][parsers]") {
    const auto result = resolve_profile_shell_folder("1", "REG_DWORD", "C:\\Users\\alice",
                                                      "alice",
                                                      [](std::string_view) { return std::nullopt; });
    CHECK_FALSE(result.path.has_value());
    CHECK(result.constraint == "startup_redirect_bad_type");
}

TEST_CASE("autoruns: resolve_profile_shell_folder reports \"not configured\", not a "
          "failure, for an empty value",
          "[autoruns][parsers]") {
    const auto result = resolve_profile_shell_folder("", "REG_EXPAND_SZ", "C:\\Users\\alice",
                                                      "alice",
                                                      [](std::string_view) { return std::nullopt; });
    CHECK_FALSE(result.path.has_value());
    CHECK(result.constraint.empty()); // empty constraint == "not configured", not a failure
}

// ── 7. parse_task_xml ──────────────────────────────────────────────────────

TEST_CASE("autoruns: parse_task_xml reads command, disabled state, principal and empty "
          "triggers (sample_task.xml, real capture)",
          "[autoruns][parsers]") {
    const auto xml = read_fixture_reg_text("windows/sample_task.xml");
    const auto info = parse_task_xml(xml);
    CHECK(info.parsed_ok); // a real, well-formed <Task>-rooted capture (with the real xmlns)
    REQUIRE(info.actions.size() == 1);
    CHECK(info.actions[0].command == "%windir%\\system32\\appidpolicyconverter.exe");
    CHECK_FALSE(info.has_unmodelled_action);
    CHECK_FALSE(info.enabled);
    CHECK(info.user_id == "S-1-5-18");
    CHECK_FALSE(info.has_triggers); // <Triggers /> is self-closed
    CHECK(info.registration_date.empty()); // fixture has no <RegistrationInfo>/<Date>
}

TEST_CASE("autoruns: parse_task_xml on a truncated document reports parsed_ok=false "
          "and keeps safe defaults "
          "(RECONSTRUCTION: pins PR #4154 round 9's blocker -- a genuine parse "
          "failure must be distinguishable from a well-formed task that simply has "
          "no triggers/actions, which also has empty actions/has_triggers==false but "
          "MUST report parsed_ok=true)",
          "[autoruns][parsers]") {
    // RECONSTRUCTION negative (acceptance criterion): a Command tag opened
    // but never closed must not throw or read past the buffer.
    const std::string truncated = "<Task xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\"><Actions><Exec><Command>C:\\partial";
    const auto info = parse_task_xml(truncated);
    CHECK_FALSE(info.parsed_ok);
    CHECK(info.actions.empty());
    CHECK(info.enabled); // documented default when <Enabled> is absent
}

TEST_CASE("autoruns: parse_task_xml on empty input reports parsed_ok=false",
          "[autoruns][parsers]") {
    const auto info = parse_task_xml("");
    CHECK_FALSE(info.parsed_ok);
}

TEST_CASE("autoruns: parse_task_xml on a well-formed task with no <Triggers> and no "
          "<Actions> reports parsed_ok=true with empty lists "
          "(RECONSTRUCTION: pins PR #4154 round 9's blocker -- this is a legitimate "
          "boring task, not a parse failure, and must not be conflated with the "
          "truncated/malformed cases above that also have empty actions/has_triggers)",
          "[autoruns][parsers]") {
    const std::string xml = "<Task xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\"><RegistrationInfo><Date>2026-01-01T00:00:00</Date>"
                            "</RegistrationInfo></Task>";
    const auto info = parse_task_xml(xml);
    CHECK(info.parsed_ok);
    CHECK(info.actions.empty());
    CHECK_FALSE(info.has_triggers);
    CHECK_FALSE(info.has_unmodelled_action);
    CHECK(info.enabled); // documented default when <Settings>/<Enabled> is absent
    CHECK(info.registration_date == "2026-01-01T00:00:00");
}

TEST_CASE("autoruns: parse_task_xml reads <RegistrationInfo>/<Date> through the "
          "element tree, not a raw text scan "
          "(RECONSTRUCTION: pins PR #4154 round 9's should-fix -- a raw "
          "content.find(\"<Date>\") predates the libxml2 migration and is a "
          "comment-injection weakness: a decoy <Date> string inside an XML comment "
          "ahead of the real element would win a raw scan but must not win here)",
          "[autoruns][parsers]") {
    const std::string xml =
        "<Task xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\"><RegistrationInfo>"
        "<!-- decoy: <Date>1999-01-01T00:00:00</Date> -->"
        "<Date>2026-06-15T12:30:00</Date>"
        "</RegistrationInfo></Task>";
    const auto info = parse_task_xml(xml);
    CHECK(info.parsed_ok);
    CHECK(info.registration_date == "2026-06-15T12:30:00");
}

TEST_CASE("autoruns: parse_task_xml reads every <Exec> action, not just the first",
          "[autoruns][parsers]") {
    const std::string xml =
        "<Task xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\"><Actions Context=\"Author\">"
        "<Exec><Command>C:\\benign.exe</Command><Arguments>-a</Arguments></Exec>"
        "<Exec><Command>C:\\second.exe</Command><Arguments>-b</Arguments></Exec>"
        "</Actions></Task>";
    const auto info = parse_task_xml(xml);
    REQUIRE(info.actions.size() == 2);
    CHECK(info.actions[0].command == "C:\\benign.exe");
    CHECK(info.actions[0].arguments == "-a");
    CHECK(info.actions[1].command == "C:\\second.exe");
    CHECK(info.actions[1].arguments == "-b");
    CHECK_FALSE(info.has_unmodelled_action);
}

TEST_CASE("autoruns: parse_task_xml flags an unmodelled action type alongside a real Exec",
          "[autoruns][parsers]") {
    const std::string xml =
        "<Task xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\"><Actions Context=\"Author\">"
        "<Exec><Command>C:\\benign.exe</Command></Exec>"
        "<ComHandler><ClassId>{00000000-0000-0000-0000-000000000000}</ClassId></ComHandler>"
        "</Actions></Task>";
    const auto info = parse_task_xml(xml);
    REQUIRE(info.actions.size() == 1);
    CHECK(info.actions[0].command == "C:\\benign.exe");
    CHECK(info.has_unmodelled_action);
}

TEST_CASE("autoruns: parse_task_xml does not confuse <Actions> with a longer tag sharing "
          "its prefix",
          "[autoruns][parsers]") {
    // A hypothetical <ActionsFoo> block must not be mistaken for <Actions>.
    const std::string xml = "<Task xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\"><ActionsFoo><Exec><Command>C:\\decoy.exe</Command></Exec>"
                            "</ActionsFoo></Task>";
    const auto info = parse_task_xml(xml);
    CHECK(info.actions.empty());
}

TEST_CASE("autoruns: a raw '>' or '/>' inside a QUOTED attribute value does not defeat "
          "tag detection (RECONSTRUCTION: pins round 7's blocker -- XML 1.0 permits a raw "
          "'>' inside a quoted attribute value, only '<' and '&' must be escaped there, and "
          "Task Scheduler's trigger/action Id/id attributes are plain xs:string, so both "
          "shapes are schema-valid; the round-5 exact-'>'-scan mistook an in-quote '>' for "
          "the tag terminator (dropping a live trigger as 'truncated') and an in-quote '/>' "
          "for a genuine self-close (silently discarding the element's real content))",
          "[autoruns][parsers]") {
    SECTION("a '>' inside the quoted Id value -- must not be read as the tag terminator, "
            "and the trigger must still be found as a real (non-self-closed) element") {
        const std::string xml =
            "<Task xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\"><Triggers><LogonTrigger Id=\"a>b\"><Enabled>true</Enabled>"
            "</LogonTrigger></Triggers></Task>";
        CHECK(parse_task_xml(xml).has_triggers);
    }

    SECTION("a '/>' sequence inside the quoted id value -- must not be read as a genuine "
            "self-close, so the action's real Command/Arguments still reach the row") {
        const std::string xml =
            "<Task xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\"><Actions Context=\"Author\">"
            "<Exec id=\"a/>b\"><Command>C:\\payload.exe</Command><Arguments>-x</Arguments></Exec>"
            "</Actions></Task>";
        const auto info = parse_task_xml(xml);
        REQUIRE(info.actions.size() == 1);
        CHECK(info.actions[0].command == "C:\\payload.exe");
        CHECK(info.actions[0].arguments == "-x");
    }
}

TEST_CASE("autoruns: parse_task_xml decodes the 5 predefined XML entities in "
          "Command/Arguments (RECONSTRUCTION: pins round 5's minor finding -- get_Xml's "
          "raw markup escapes reserved characters, and leaving them un-decoded breaks "
          "exact IOC/command-string matching against the real argv)",
          "[autoruns][parsers]") {
    const std::string xml =
        "<Task xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\"><Actions Context=\"Author\">"
        "<Exec><Command>C:\\tools\\a&amp;b.exe</Command>"
        "<Arguments>--filter=\"x&lt;y&gt;z\" --tag=&apos;a&amp;b&apos;</Arguments></Exec>"
        "</Actions></Task>";
    const auto info = parse_task_xml(xml);
    REQUIRE(info.actions.size() == 1);
    CHECK(info.actions[0].command == "C:\\tools\\a&b.exe");
    CHECK(info.actions[0].arguments == "--filter=\"x<y>z\" --tag='a&b'");
}

TEST_CASE("autoruns: parse_task_xml handles XML constructs a hand-rolled scanner was "
          "never even asked about -- a real parser handles these BY CONSTRUCTION, not as "
          "individually-discovered edge cases "
          "(RECONSTRUCTION: pins the round-8 libxml2 adoption -- defensive-depth coverage "
          "beyond what any single review round's adversarial probe specifically named)",
          "[autoruns][parsers]") {
    SECTION("an XML comment containing '>' and quotes, sitting between real elements, "
            "must not confuse the real content around it") {
        const std::string xml =
            "<Task xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\"><Actions Context=\"Author\">"
            "<!-- a comment with a stray > and \"quotes\" and 'more quotes' -->"
            "<Exec><Command>C:\\real.exe</Command></Exec>"
            "</Actions></Task>";
        const auto info = parse_task_xml(xml);
        REQUIRE(info.actions.size() == 1);
        CHECK(info.actions[0].command == "C:\\real.exe");
    }

    SECTION("a real XML declaration ahead of the root element is ordinary, not an "
            "obstacle") {
        const std::string xml =
            "<?xml version=\"1.0\" encoding=\"UTF-16\"?>"
            "<Task xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\"><Triggers><LogonTrigger/></Triggers></Task>";
        CHECK(parse_task_xml(xml).has_triggers);
    }

    SECTION("a decoy element sharing a trigger-type's local name but living OUTSIDE "
            "<Triggers> must not be mistaken for a real trigger") {
        const std::string xml =
            "<Task xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\"><RegistrationInfo><LogonTrigger>decoy, not a real trigger element here"
            "</LogonTrigger></RegistrationInfo><Triggers/></Task>";
        CHECK_FALSE(parse_task_xml(xml).has_triggers);
    }

    SECTION("a DOCTYPE/DTD declaration is rejected outright, reporting parsed_ok=false "
            "and leaving TaskInfo at its documented defaults, rather than trusted "
            "(matches this repo's other untrusted-XML consumer, "
            "server/core/src/saml_provider.cpp) -- RECONSTRUCTION: pins PR #4154 "
            "round 9's blocker that this is a genuine parse failure, not a "
            "well-formed-but-boring task") {
        const std::string xml =
            "<?xml version=\"1.0\"?><!DOCTYPE Task [<!ENTITY x \"evil\">]>"
            "<Task xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\"><Triggers><LogonTrigger/></Triggers></Task>";
        const auto info = parse_task_xml(xml);
        CHECK_FALSE(info.parsed_ok);
        CHECK_FALSE(info.has_triggers);
        CHECK(info.actions.empty());
    }

    SECTION("an unexpected root element is also a genuine parse failure "
            "(RECONSTRUCTION: pins PR #4154 round 9's blocker)") {
        const std::string xml = "<NotATask><Triggers><LogonTrigger/></Triggers></NotATask>";
        const auto info = parse_task_xml(xml);
        CHECK_FALSE(info.parsed_ok);
        CHECK_FALSE(info.has_triggers);
    }
}

TEST_CASE("autoruns: parse_task_xml's has_triggers consults each trigger's own "
          "<Enabled> value, not just bare presence of a trigger element "
          "(RECONSTRUCTION: pins round 3's should-fix -- a task with only "
          "individually-disabled triggers, or a whitespace-only <Triggers> "
          "block, must not report has_triggers=true)",
          "[autoruns][parsers]") {
    SECTION("a single disabled trigger -> false") {
        const std::string xml =
            "<Task xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\"><Triggers><CalendarTrigger><Enabled>false</Enabled>"
            "</CalendarTrigger></Triggers></Task>";
        CHECK_FALSE(parse_task_xml(xml).has_triggers);
    }

    SECTION("a trigger with no <Enabled> tag at all -> true (schema default enabled)") {
        const std::string xml =
            "<Task xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\"><Triggers><CalendarTrigger><StartBoundary>2026-01-01T00:00:00</StartBoundary>"
            "</CalendarTrigger></Triggers></Task>";
        CHECK(parse_task_xml(xml).has_triggers);
    }

    SECTION("one disabled, one enabled -> true (at least one will fire)") {
        const std::string xml =
            "<Task xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\"><Triggers>"
            "<CalendarTrigger><Enabled>false</Enabled></CalendarTrigger>"
            "<TimeTrigger><Enabled>true</Enabled></TimeTrigger>"
            "</Triggers></Task>";
        CHECK(parse_task_xml(xml).has_triggers);
    }

    SECTION("all disabled -> false") {
        const std::string xml =
            "<Task xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\"><Triggers>"
            "<CalendarTrigger><Enabled>false</Enabled></CalendarTrigger>"
            "<TimeTrigger><Enabled>false</Enabled></TimeTrigger>"
            "</Triggers></Task>";
        CHECK_FALSE(parse_task_xml(xml).has_triggers);
    }

    SECTION("one explicitly-disabled trigger plus one untagged (schema-default "
            "enabled) sibling -> true (RECONSTRUCTION: pins round 4's blocker -- "
            "the round-3 fix aggregated <Enabled> tag counts across the WHOLE "
            "Triggers block instead of per trigger element, so this exact shape "
            "-- the ordinary result of disabling one of several triggers via the "
            "Task Scheduler UI -- was misclassified as no live trigger, even "
            "though the untagged sibling will fire the task)") {
        const std::string xml =
            "<Task xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\"><Triggers>"
            "<CalendarTrigger><Enabled>false</Enabled></CalendarTrigger>"
            "<TimeTrigger><StartBoundary>2026-01-01T00:00:00</StartBoundary></TimeTrigger>"
            "</Triggers></Task>";
        CHECK(parse_task_xml(xml).has_triggers);
    }

    SECTION("whitespace-only Triggers block -> false") {
        const std::string xml = "<Task xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\"><Triggers>\n   \t\n</Triggers></Task>";
        CHECK_FALSE(parse_task_xml(xml).has_triggers);
    }

    SECTION("a self-closed trigger -> true (RECONSTRUCTION: pins round 5's blocker -- "
            "LogonTrigger/BootTrigger/etc. have no required children, so a bare "
            "<LogonTrigger/> is schema-valid and live; the round-4 exact-open-tag "
            "matcher missed this shape entirely)") {
        const std::string xml = "<Task xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\"><Triggers><LogonTrigger/></Triggers></Task>";
        CHECK(parse_task_xml(xml).has_triggers);
    }

    SECTION("a self-closed trigger with a space before the slash -> true") {
        const std::string xml = "<Task xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\"><Triggers><LogonTrigger /></Triggers></Task>";
        CHECK(parse_task_xml(xml).has_triggers);
    }

    SECTION("a trigger carrying the schema's optional Id attribute -> true "
            "(RECONSTRUCTION: pins round 5's blocker -- Task Scheduler's trigger "
            "base type defines an optional Id attribute; the round-4 exact "
            "'<Tag>' match required a bare tag with no attributes)") {
        const std::string xml =
            "<Task xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\"><Triggers><BootTrigger Id=\"boot\"><Enabled>true</Enabled>"
            "</BootTrigger></Triggers></Task>";
        CHECK(parse_task_xml(xml).has_triggers);
    }

    SECTION("<Enabled>0</Enabled> (xsd:boolean lexical form) disables a trigger "
            "(RECONSTRUCTION: pins round 5's should-fix -- a bare =='false' string "
            "compare treated '0' as live)") {
        const std::string xml =
            "<Task xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\"><Triggers><CalendarTrigger><Enabled>0</Enabled></CalendarTrigger>"
            "</Triggers></Task>";
        CHECK_FALSE(parse_task_xml(xml).has_triggers);
    }

    SECTION("whitespace-padded <Enabled> false form still disables") {
        const std::string xml =
            "<Task xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\"><Triggers><CalendarTrigger><Enabled> false </Enabled></CalendarTrigger>"
            "</Triggers></Task>";
        CHECK_FALSE(parse_task_xml(xml).has_triggers);
    }
}

TEST_CASE("autoruns: parse_task_xml reads an Exec action carrying the schema's optional "
          "lowercase id attribute "
          "(RECONSTRUCTION: pins round 5's blocker -- pre-existing since round 1: "
          "<Exec id=\"...\"> was invisible to the exact '<Exec>' match, so the row's "
          "target/args came back empty even though the task has a real command)",
          "[autoruns][parsers]") {
    const std::string xml =
        "<Task xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\"><Actions Context=\"Author\">"
        "<Exec id=\"run\"><Command>C:\\real.exe</Command><Arguments>-x</Arguments></Exec>"
        "</Actions></Task>";
    const auto info = parse_task_xml(xml);
    REQUIRE(info.actions.size() == 1);
    CHECK(info.actions[0].command == "C:\\real.exe");
    CHECK(info.actions[0].arguments == "-x");
}

TEST_CASE("autoruns: parse_task_xml rejects a <Task>-named root that isn't in the Task "
          "Scheduler namespace -- schema-garbage sharing child tag names (<Settings>/"
          "<Actions>/<Triggers>) under an unrelated or absent namespace must not parse "
          "as a plausible task with no signal it came from elsewhere (#4184 AC2)",
          "[autoruns][parsers]") {
    SECTION("root element with no namespace at all") {
        const std::string xml =
            "<Task><Settings><Enabled>true</Enabled></Settings>"
            "<Actions><Exec><Command>C:\\x.exe</Command></Exec></Actions></Task>";
        const auto info = parse_task_xml(xml);
        CHECK_FALSE(info.parsed_ok);
        CHECK(info.reject == TaskReject::wrong_root);
        CHECK(info.actions.empty()); // safe defaults, not a partial/guessed parse
    }

    SECTION("root element in an unrelated namespace") {
        const std::string xml =
            "<Task xmlns=\"urn:not-task-scheduler\">"
            "<Actions><Exec><Command>C:\\x.exe</Command></Exec></Actions></Task>";
        const auto info = parse_task_xml(xml);
        CHECK_FALSE(info.parsed_ok);
        CHECK(info.reject == TaskReject::wrong_root);
    }

    SECTION("the real Task Scheduler namespace is still accepted") {
        const std::string xml =
            "<Task xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">"
            "<Actions><Exec><Command>C:\\x.exe</Command></Exec></Actions></Task>";
        const auto info = parse_task_xml(xml);
        CHECK(info.parsed_ok);
        CHECK(info.reject == TaskReject::none);
    }
}

TEST_CASE("autoruns: parse_task_xml ignores a descendant that redeclares a foreign "
          "default namespace, even under a correctly-namespaced <Task> root -- the "
          "namespace hardening at the root must not stop there, or schema-garbage "
          "nested under a genuine root is silently read as real task content",
          "[autoruns][parsers]") {
    SECTION("the whole <Actions> element redeclares a foreign namespace") {
        const std::string xml =
            "<Task xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">"
            "<Actions xmlns=\"urn:other\"><Exec><Command>C:\\foreign.exe</Command></Exec>"
            "</Actions></Task>";
        const auto info = parse_task_xml(xml);
        CHECK(info.parsed_ok); // the root itself is genuine -- not a reject case
        CHECK(info.actions.empty()); // the foreign-namespace <Actions> subtree is not read
        CHECK_FALSE(info.has_unmodelled_action);
    }

    SECTION("a genuine <Actions> element's own <Exec> child redeclares a foreign namespace") {
        const std::string xml =
            "<Task xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">"
            "<Actions><Exec xmlns=\"urn:other\"><Command>C:\\foreign.exe</Command></Exec>"
            "</Actions></Task>";
        const auto info = parse_task_xml(xml);
        CHECK(info.parsed_ok);
        CHECK(info.actions.empty()); // the foreign-namespace <Exec> itself is not read as one
        CHECK_FALSE(info.has_unmodelled_action);
    }
}

TEST_CASE("autoruns: parse_task_xml refuses an oversized document before xmlReadMemory "
          "ever sees it, distinct from an ordinary malformed rejection (#4184)",
          "[autoruns][parsers]") {
    const std::string oversized(kMaxTaskXmlBytes + 1, 'a');
    const auto info = parse_task_xml(oversized);
    CHECK_FALSE(info.parsed_ok);
    CHECK(info.reject == TaskReject::oversized);
}

TEST_CASE("autoruns: task_reject_reason_token maps TaskReject::oversized to its own "
          "'oversized' wire token, and every other rejection shape to the existing "
          "'malformed' token -- closes the coverage gap an adversarial functional "
          "review found: the win.cpp COM call site's mapping (autoruns_win.cpp) was "
          "previously an inline ternary reachable only through Windows-only code, so "
          "no test on any build host actually exercised it (#4184)",
          "[autoruns][parsers]") {
    CHECK(task_reject_reason_token(TaskReject::oversized) == "oversized");
    CHECK(task_reject_reason_token(TaskReject::malformed) == "malformed");
    CHECK(task_reject_reason_token(TaskReject::empty) == "malformed");
    CHECK(task_reject_reason_token(TaskReject::dtd) == "malformed");
    CHECK(task_reject_reason_token(TaskReject::wrong_root) == "malformed");
    CHECK(task_reject_reason_token(TaskReject::none).empty());
}

TEST_CASE("autoruns: parse_task_xml rejects a deeply-nested, DTD-free document cleanly "
          "-- a real error, not a crash or unbounded resource use (#4184 AC3). "
          "XML_PARSE_HUGE is deliberately never passed (see parse_task_xml's own "
          "banner), so libxml2's own default depth ceiling (~256 levels) is what "
          "rejects this, not an explicit depth counter in this function",
          "[autoruns][parsers]") {
    std::string open, close;
    for (int i = 0; i < 5000; ++i) {
        open += "<x>";
        close += "</x>";
    }
    const std::string xml =
        "<Task xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">" + open +
        close + "</Task>";
    const auto info = parse_task_xml(xml);
    CHECK_FALSE(info.parsed_ok);
    // Genuinely nested, not DTD/oversized -- confirms the depth ceiling
    // itself is what rejected it, not an unrelated guard firing first.
    CHECK(info.reject == TaskReject::malformed);
}

TEST_CASE("autoruns: rows_for_task emits exactly one row for a task with zero decoded "
          "actions -- whether genuinely action-less or carrying only an unmodelled "
          "action type -- rather than silently vanishing (#4184 AC1)",
          "[autoruns][parsers]") {
    SECTION("genuinely no actions at all") {
        TaskInfo info;
        info.parsed_ok = true;
        const auto rows =
            rows_for_task(info, "\\MyTask", "MyTask", "SYSTEM", 12345, Enabled::enabled);
        REQUIRE(rows.size() == 1);
        CHECK(rows[0].entry == "MyTask");
        CHECK(rows[0].target.empty());
        CHECK(rows[0].args.empty());
        CHECK(rows[0].enabled == Enabled::enabled);
        CHECK(rows[0].mtime == 12345);
    }

    SECTION("only an unmodelled action type (ComHandler, no Exec) -- the row a caller "
            "must not read as \"nothing here\"") {
        const std::string xml =
            "<Task xmlns=\"http://schemas.microsoft.com/windows/2004/02/mit/task\">"
            "<Actions><ComHandler><ClassId>{00000000-0000-0000-0000-000000000000}</ClassId>"
            "</ComHandler></Actions></Task>";
        const auto info = parse_task_xml(xml);
        REQUIRE(info.parsed_ok);
        CHECK(info.actions.empty());
        CHECK(info.has_unmodelled_action);
        const auto rows = rows_for_task(info, "\\MyTask", "MyTask", "-", 0, Enabled::unknown);
        REQUIRE(rows.size() == 1);
        CHECK(rows[0].target.empty());
        CHECK(rows[0].enabled == Enabled::unknown);
    }
}

TEST_CASE("autoruns: rows_for_task emits one row per action, index-suffixing the entry "
          "only once there's more than one",
          "[autoruns][parsers]") {
    TaskInfo info;
    info.parsed_ok = true;
    info.actions = {{"C:\\a.exe", "-a"}, {"C:\\b.exe", "-b"}};
    const auto rows = rows_for_task(info, "\\MyTask", "MyTask", "SYSTEM", 999, Enabled::enabled);
    REQUIRE(rows.size() == 2);
    CHECK(rows[0].entry == "MyTask [action 1]");
    CHECK(rows[0].target == "C:\\a.exe");
    CHECK(rows[0].args == "-a");
    CHECK(rows[1].entry == "MyTask [action 2]");
    CHECK(rows[1].target == "C:\\b.exe");
    CHECK(rows[1].args == "-b");
}

TEST_CASE("autoruns: rows_for_task's single-action case does not get an index suffix",
          "[autoruns][parsers]") {
    TaskInfo info;
    info.parsed_ok = true;
    info.actions = {{"C:\\solo.exe", ""}};
    const auto rows = rows_for_task(info, "\\MyTask", "MyTask", "-", 0, Enabled::enabled);
    REQUIRE(rows.size() == 1);
    CHECK(rows[0].entry == "MyTask");
    CHECK(rows[0].target == "C:\\solo.exe");
}

TEST_CASE("autoruns: scheduled_task_enabled_state requires both a live COM Enabled "
          "property AND a genuine parsed trigger, and reports unknown (never a "
          "fabricated definite answer) on any COM accessor failure or parse failure "
          "(RECONSTRUCTION: pins PR #4154 round 9's blocker -- extracted from the "
          "win.cpp COM call site specifically so this decision is testable on every "
          "build host, not just Windows)",
          "[autoruns][parsers]") {
    TaskInfo info_no_triggers; // parsed_ok=false, has_triggers=false (defaults)
    TaskInfo info_with_triggers;
    info_with_triggers.parsed_ok = true;
    info_with_triggers.has_triggers = true;
    TaskInfo info_no_triggers_ok; // well-formed, genuinely no triggers
    info_no_triggers_ok.parsed_ok = true;
    info_no_triggers_ok.has_triggers = false;

    SECTION("get_Enabled accessor failed -> unknown, even if the XML parsed fine "
            "with live triggers") {
        CHECK(scheduled_task_enabled_state(/*enabled_hr_ok=*/false, /*xml_hr_ok=*/true,
                                           /*com_enabled=*/true,
                                           info_with_triggers) == Enabled::unknown);
    }

    SECTION("get_Xml accessor failed -> unknown") {
        CHECK(scheduled_task_enabled_state(/*enabled_hr_ok=*/true, /*xml_hr_ok=*/false,
                                           /*com_enabled=*/true,
                                           info_with_triggers) == Enabled::unknown);
    }

    SECTION("both COM accessors succeeded but the XML genuinely failed to parse -> "
            "unknown, never fabricated as disabled from the default has_triggers=false") {
        CHECK(scheduled_task_enabled_state(/*enabled_hr_ok=*/true, /*xml_hr_ok=*/true,
                                           /*com_enabled=*/true,
                                           info_no_triggers) == Enabled::unknown);
    }

    SECTION("both COM accessors ok, XML parsed fine, task genuinely has no triggers "
            "-> disabled (a real answer, distinct from the malformed case above)") {
        CHECK(scheduled_task_enabled_state(/*enabled_hr_ok=*/true, /*xml_hr_ok=*/true,
                                           /*com_enabled=*/true,
                                           info_no_triggers_ok) == Enabled::disabled);
    }

    SECTION("both COM accessors ok, XML parsed fine, live triggers, but COM reports "
            "disabled -> disabled") {
        CHECK(scheduled_task_enabled_state(/*enabled_hr_ok=*/true, /*xml_hr_ok=*/true,
                                           /*com_enabled=*/false,
                                           info_with_triggers) == Enabled::disabled);
    }

    SECTION("both COM accessors ok, XML parsed fine, live triggers, COM reports "
            "enabled -> enabled") {
        CHECK(scheduled_task_enabled_state(/*enabled_hr_ok=*/true, /*xml_hr_ok=*/true,
                                           /*com_enabled=*/true,
                                           info_with_triggers) == Enabled::enabled);
    }
}

// ── 8. parse_wmi_subscription_triple ─────────────────────────────────────

TEST_CASE("autoruns: parse_wmi_subscription_triple joins filter/consumer/binding blocks "
          "(subscription_triple.txt, real capture)",
          "[autoruns][parsers]") {
    const auto text = read_fixture_bytes("windows/subscription_triple.txt");
    const auto triple = parse_wmi_subscription_triple(text);
    CHECK(triple.filter_found);
    CHECK(triple.consumer_found);
    CHECK(triple.binding_found);
    CHECK(triple.filter_name == "SCM Event Log Filter");
    CHECK(triple.consumer_name == "SCM Event Log Consumer");
    CHECK(triple.query == "select * from MSFT_SCMEventLogEvent");
    // This real capture's consumer is a built-in NTEventLogEventConsumer,
    // which carries none of the three known executable-target fields.
    CHECK(triple.target.empty());
}

TEST_CASE("autoruns: parse_wmi_subscription_triple resolves target from CommandLineTemplate",
          "[autoruns][parsers]") {
    // RECONSTRUCTION: a CommandLineEventConsumer subscription -- the
    // malicious shape this source exists to catch.
    const std::string text =
        "CimClass               : ROOT/subscription:__EventFilter\n"
        "Name                   : EvilFilter\n"
        "Query                  : select * from Win32_ProcessStartTrace\n"
        "\n\n"
        "CimClass               : ROOT/subscription:CommandLineEventConsumer\n"
        "Name                   : EvilConsumer\n"
        "CommandLineTemplate    : cmd.exe /c calc.exe\n"
        "\n\n"
        "CimClass               : ROOT/subscription:__FilterToConsumerBinding\n";
    const auto triple = parse_wmi_subscription_triple(text);
    CHECK(triple.target == "cmd.exe /c calc.exe");
}

TEST_CASE("autoruns: parse_wmi_subscription_triple recovers a multi-line ScriptText "
          "value through format_wmi_block's real escape round trip, exercising both "
          "the encoder and the decoder "
          "(RECONSTRUCTION: pins round 3's should-fix, strengthened per round 4's "
          "should-fix -- the original version of this test hand-supplied an "
          "already-escaped literal and never called format_wmi_block/escape_wmi_value "
          "at all, so a regression in the producer half would have left this test, "
          "and all other autoruns tests, green while live multi-line ScriptText "
          "payloads corrupted again)",
          "[autoruns][parsers]") {
    const std::string original_script = "line1\nline2\n\nline4";
    std::map<std::string, std::string> consumer_row{
        {"Name", "EvilConsumer"},
        {"ScriptText", original_script},
    };
    std::map<std::string, std::string> filter_row{
        {"Name", "EvilFilter"},
        {"Query", "select * from Win32_ProcessStartTrace"},
    };
    std::map<std::string, std::string> binding_row{};

    const std::string combined = format_wmi_block("__EventFilter", filter_row) +
                                 format_wmi_block("ROOT/subscription:ActiveScriptEventConsumer",
                                                  consumer_row) +
                                 format_wmi_block("__FilterToConsumerBinding", binding_row);
    const auto triple = parse_wmi_subscription_triple(combined);
    CHECK(triple.consumer_found);
    CHECK(triple.target == original_script);
}

// ── 9. parse_crontab ──────────────────────────────────────────────────────

TEST_CASE("autoruns: parse_crontab parses /etc/crontab's system-format lines "
          "(crontab, real capture)",
          "[autoruns][parsers]") {
    const auto text = read_fixture_bytes("linux/crontab");
    const auto result = parse_crontab(text, /*system_format=*/true);
    REQUIRE(result.entries.size() == 4);
    CHECK(result.entries[0].user == "root");
    CHECK(result.entries[0].command.rfind("cd / &&", 0) == 0);
    CHECK(result.rejected_lines == 0);
}

TEST_CASE("autoruns: parse_crontab parses a per-user crontab with no user field "
          "(user_crontab.ubuntu, real capture)",
          "[autoruns][parsers]") {
    const auto text = read_fixture_bytes("linux/user_crontab.ubuntu");
    const auto result = parse_crontab(text, /*system_format=*/false);
    REQUIRE(result.entries.size() == 1);
    CHECK(result.entries[0].user == "-");
    CHECK(result.entries[0].schedule == "15 3 * * *");
    CHECK(result.entries[0].command == "/usr/bin/true");
}

TEST_CASE("autoruns: parse_crontab rejects and counts a 4-field line", "[autoruns][parsers]") {
    // RECONSTRUCTION negative (acceptance criterion): a malformed line must
    // be rejected+counted, never silently dropped nor mis-parsed.
    const std::string text = "* * * *\troot\tcommand\n";
    const auto result = parse_crontab(text, /*system_format=*/true);
    CHECK(result.entries.empty());
    CHECK(result.rejected_lines == 1);
}

TEST_CASE("autoruns: parse_crontab recognizes @reboot in system-format text",
          "[autoruns][parsers]") {
    const std::string text = "@reboot root /usr/bin/true\n";
    const auto result = parse_crontab(text, /*system_format=*/true);
    REQUIRE(result.entries.size() == 1);
    CHECK(result.entries[0].schedule == "@reboot");
    CHECK(result.entries[0].user == "root");
    CHECK(result.entries[0].command == "/usr/bin/true");
    CHECK(result.rejected_lines == 0);
}

TEST_CASE("autoruns: parse_crontab recognizes @reboot in a per-user crontab",
          "[autoruns][parsers]") {
    const std::string text = "@reboot /usr/bin/true\n";
    const auto result = parse_crontab(text, /*system_format=*/false);
    REQUIRE(result.entries.size() == 1);
    CHECK(result.entries[0].schedule == "@reboot");
    CHECK(result.entries[0].user == "-");
    CHECK(result.entries[0].command == "/usr/bin/true");
    CHECK(result.rejected_lines == 0);
}

TEST_CASE("autoruns: parse_crontab recognizes every crontab(5) nickname and "
          "keeps a multi-word command intact",
          "[autoruns][parsers]") {
    const std::string text =
        "@yearly /usr/bin/a\n"
        "@annually /usr/bin/b\n"
        "@monthly /usr/bin/c\n"
        "@weekly /usr/bin/d\n"
        "@daily /usr/bin/e --flag arg\n"
        "@midnight /usr/bin/f\n"
        "@hourly /usr/bin/g\n";
    const auto result = parse_crontab(text, /*system_format=*/false);
    REQUIRE(result.entries.size() == 7);
    CHECK(result.entries[4].schedule == "@daily");
    CHECK(result.entries[4].command == "/usr/bin/e --flag arg");
    CHECK(result.rejected_lines == 0);
}

TEST_CASE("autoruns: parse_crontab rejects a nickname line missing its command",
          "[autoruns][parsers]") {
    // A nickname with nothing after it (or, in system format, no command
    // after the user) is still malformed and must be counted, not dropped.
    const auto result = parse_crontab("@reboot\n", /*system_format=*/false);
    CHECK(result.entries.empty());
    CHECK(result.rejected_lines == 1);
}

TEST_CASE("autoruns: parse_crontab recognizes a spaced environment-variable "
          "assignment (crontab(5) permits whitespace on either side of '=') "
          "(RECONSTRUCTION: pins the adversarial-review should-fix -- the "
          "recognizer previously only matched the tight NAME=value form, so "
          "'MAILTO = root' was misparsed as a malformed cron command line and "
          "counted into rejected_lines on an otherwise entirely valid crontab)",
          "[autoruns][parsers]") {
    SECTION("spaces on both sides of '='") {
        const auto result = parse_crontab("MAILTO = root\n", /*system_format=*/true);
        CHECK(result.entries.empty());
        CHECK(result.rejected_lines == 0);
    }

    SECTION("space only after '='") {
        const auto result = parse_crontab("MAILTO= root\n", /*system_format=*/true);
        CHECK(result.entries.empty());
        CHECK(result.rejected_lines == 0);
    }

    SECTION("space only before '='") {
        const auto result = parse_crontab("MAILTO =root\n", /*system_format=*/true);
        CHECK(result.entries.empty());
        CHECK(result.rejected_lines == 0);
    }

    SECTION("no space either side -- still valid, no regression") {
        const auto result = parse_crontab("MAILTO=root\n", /*system_format=*/true);
        CHECK(result.entries.empty());
        CHECK(result.rejected_lines == 0);
    }
}

TEST_CASE("autoruns: parse_crontab treats every spaced-assignment variant "
          "identically to the tight form across a whole file, alongside real "
          "cron entries, with zero rejected lines",
          "[autoruns][parsers]") {
    const std::string text =
        "SHELL=/bin/sh\n"
        "MAILTO = root\n"
        "PATH= /usr/bin:/bin\n"
        "HOME =/root\n"
        "17 *\t* * *\troot\tcd / && run-parts --report /etc/cron.hourly\n"
        "25 6\t* * *\troot\ttest -x /usr/sbin/anacron\n";
    const auto result = parse_crontab(text, /*system_format=*/true);
    REQUIRE(result.entries.size() == 2);
    CHECK(result.entries[0].command.rfind("cd / &&", 0) == 0);
    CHECK(result.entries[1].command.rfind("test -x", 0) == 0);
    CHECK(result.rejected_lines == 0);
}

TEST_CASE("autoruns: parse_crontab still rejects a bare identifier with no "
          "'=' anywhere on the line, spaced assignment recognition does not "
          "loosen this into a false positive",
          "[autoruns][parsers]") {
    // A lone token with no '=' at all is neither a valid assignment nor a
    // well-formed cron line -- must still be counted as rejected.
    const auto result = parse_crontab("MAILTO\n", /*system_format=*/true);
    CHECK(result.entries.empty());
    CHECK(result.rejected_lines == 1);
}

// ── 10. parse_anacrontab ──────────────────────────────────────────────────

TEST_CASE("autoruns: parse_anacrontab parses period/delay/job/command "
          "(anacrontab, real capture)",
          "[autoruns][parsers]") {
    const auto text = read_fixture_bytes("linux/anacrontab");
    const auto result = parse_anacrontab(text);
    REQUIRE(result.entries.size() == 3);
    CHECK(result.entries[0].period == "1");
    CHECK(result.entries[0].delay == "5");
    CHECK(result.entries[0].job_id == "cron.daily");
    CHECK(result.entries[2].period == "@monthly");
    CHECK(result.rejected_lines == 0);
}

TEST_CASE("autoruns: parse_anacrontab counts a malformed short line as rejected, "
          "never silently dropped (#4184 unfiled-finding cleanup: matches "
          "parse_crontab's rejected_lines contract, now actually consumed by "
          "the /etc/anacrontab collector)",
          "[autoruns][parsers]") {
    // RECONSTRUCTION negative: a line with fewer than 4 fields is rejected
    // and counted, not silently skipped nor mis-parsed into the wrong
    // columns.
    const std::string text = "1\t5\n";
    const auto result = parse_anacrontab(text);
    CHECK(result.entries.empty());
    CHECK(result.rejected_lines == 1);
}

TEST_CASE("autoruns: parse_anacrontab keeps other valid entries alongside a "
          "rejected line, never dropping the whole file",
          "[autoruns][parsers]") {
    const std::string text = "1 5 cron.daily /etc/cron.daily\nshort line\n7 25 cron.weekly "
                             "/etc/cron.weekly\n";
    const auto result = parse_anacrontab(text);
    REQUIRE(result.entries.size() == 2);
    CHECK(result.entries[0].job_id == "cron.daily");
    CHECK(result.entries[1].job_id == "cron.weekly");
    CHECK(result.rejected_lines == 1);
}

// ── 11. parse_systemd_timer / timer_enabled_from_wants ───────────────────

TEST_CASE("autoruns: parse_systemd_timer reads OnCalendar and WantedBy "
          "(apt-daily.timer, real capture)",
          "[autoruns][parsers]") {
    const auto text = read_fixture_bytes("linux/apt-daily.timer");
    const auto fields = parse_systemd_timer(text);
    CHECK(fields.on_calendar == "*-*-* 6,18:00");
    CHECK(fields.wanted_by == "timers.target");
    CHECK(fields.on_boot_sec.empty());
}

TEST_CASE("autoruns: parse_systemd_timer accepts whitespace-padded 'Key = Value' "
          "-- systemd.syntax(7) makes the whitespace ignorable, not part of a "
          "different (unrecognized, silently dropped) key",
          "[autoruns][parsers]") {
    const std::string text = "[Timer]\nOnCalendar = daily\n[Install]\nWantedBy = timers.target\n";
    const auto fields = parse_systemd_timer(text);
    CHECK(fields.on_calendar == "daily");
    CHECK(fields.wanted_by == "timers.target");
}

TEST_CASE("autoruns: timer_enabled_from_wants finds a real symlink "
          "(timers.target.wants.listing.txt, real capture)",
          "[autoruns][parsers]") {
    const auto listing = read_fixture_bytes("linux/timers.target.wants.listing.txt");
    CHECK(timer_enabled_from_wants(listing, "apt-daily.timer"));
    CHECK(timer_enabled_from_wants(listing, "dpkg-db-backup.timer"));
    CHECK(timer_enabled_from_wants(listing, "e2scrub_all.timer"));
    CHECK_FALSE(timer_enabled_from_wants(listing, "bogus.timer"));
}

TEST_CASE("autoruns: timer_enabled_from_wants does not substring-match a longer name",
          "[autoruns][parsers]") {
    // RECONSTRUCTION negative: apt-daily.timer must not false-positive
    // against apt-daily-upgrade.timer's listing entry.
    const std::string listing =
        "lrwxrwxrwx 1 root root 43 Aug 10 14:49 apt-daily-upgrade.timer -> "
        "/lib/systemd/system/apt-daily-upgrade.timer\n";
    CHECK_FALSE(timer_enabled_from_wants(listing, "apt-daily.timer"));
}

// ── 12. parse_desktop_entry ───────────────────────────────────────────────

TEST_CASE("autoruns: parse_desktop_entry on a normal entry is enabled "
          "(at-spi-dbus-bus.desktop, real capture)",
          "[autoruns][parsers]") {
    const auto text = read_fixture_bytes("linux/at-spi-dbus-bus.desktop");
    const auto entry = parse_desktop_entry(text);
    CHECK(entry.exec == "/usr/libexec/at-spi-bus-launcher --launch-immediately");
    CHECK_FALSE(entry.hidden);
    CHECK(entry.enabled == Enabled::enabled);
    CHECK_FALSE(entry.malformed);
}

TEST_CASE("autoruns: parse_desktop_entry with Hidden=true is disabled "
          "(reconstructed_hidden_onlyshowin.desktop, RECONSTRUCTION negative)",
          "[autoruns][parsers]") {
    const auto text = read_fixture_bytes("linux/reconstructed_hidden_onlyshowin.desktop");
    const auto entry = parse_desktop_entry(text);
    CHECK(entry.hidden);
    CHECK(entry.only_show_in == "GNOME;");
    CHECK(entry.enabled == Enabled::disabled);
    CHECK_FALSE(entry.malformed); // Hidden, but still a real Exec -- not malformed
}

TEST_CASE("autoruns: parse_desktop_entry flags malformed when there's no "
          "[Desktop Entry] group at all -- nothing this leg could run, must not "
          "silently report an enabled row with an empty target",
          "[autoruns][parsers]") {
    const std::string text = "[Some Other Group]\nExec=/bin/should-not-count\n";
    const auto entry = parse_desktop_entry(text);
    CHECK(entry.malformed);
    CHECK(entry.exec.empty());
}

TEST_CASE("autoruns: parse_desktop_entry flags malformed when [Desktop Entry] is "
          "present but Exec is absent or empty",
          "[autoruns][parsers]") {
    SECTION("Exec key absent entirely") {
        const std::string text = "[Desktop Entry]\nHidden=false\n";
        CHECK(parse_desktop_entry(text).malformed);
    }
    SECTION("Exec key present but empty") {
        const std::string text = "[Desktop Entry]\nExec=\n";
        CHECK(parse_desktop_entry(text).malformed);
    }
}

TEST_CASE("autoruns: parse_desktop_entry does NOT flag malformed for a "
          "DBusActivatable=true entry with no Exec -- the Desktop Entry spec "
          "requires Exec only when DBusActivatable is not true, so this is a "
          "real D-Bus-activated autostart entry, not a broken one",
          "[autoruns][parsers]") {
    const std::string text = "[Desktop Entry]\nDBusActivatable=true\n";
    const auto entry = parse_desktop_entry(text);
    CHECK_FALSE(entry.malformed);
    CHECK(entry.dbus_activatable);
    CHECK(entry.exec.empty());
}

TEST_CASE("autoruns: parse_desktop_entry still flags malformed when Exec is "
          "empty and DBusActivatable is absent or false -- DBusActivatable "
          "does not blanket-waive the target requirement",
          "[autoruns][parsers]") {
    SECTION("DBusActivatable absent") {
        const std::string text = "[Desktop Entry]\nHidden=false\n";
        CHECK(parse_desktop_entry(text).malformed);
    }
    SECTION("DBusActivatable=false") {
        const std::string text = "[Desktop Entry]\nDBusActivatable=false\n";
        CHECK(parse_desktop_entry(text).malformed);
    }
}

TEST_CASE("autoruns: parse_desktop_entry accepts whitespace-padded 'Key = Value' "
          "-- the XDG Desktop Entry spec makes the whitespace ignorable, not part "
          "of a different key ('Exec ' silently dropped, target reads empty)",
          "[autoruns][parsers]") {
    const std::string text = "[Desktop Entry]\nExec = /usr/bin/real --flag\n";
    const auto entry = parse_desktop_entry(text);
    CHECK(entry.exec == "/usr/bin/real --flag");
    CHECK_FALSE(entry.malformed);
}

// ── 13. LaunchdFields / launchd_row_from_fields ──────────────────────────

TEST_CASE("autoruns: launchd_row_from_fields uses Program and joins the remaining args "
          "(com.docker.socket.plist fields, real capture)",
          "[autoruns][parsers]") {
    // Hand-extracted from the real com.docker.socket.plist fixture (the
    // actual CFPropertyList read is P14's); grounds this pure builder in the
    // real plist's own field values without this header depending on a
    // plist library.
    LaunchdFields fields;
    fields.label = "com.docker.socket";
    fields.program = "/Library/PrivilegedHelperTools/com.docker.socket";
    fields.program_arguments = {"/Library/PrivilegedHelperTools/com.docker.socket", "alex"};
    fields.disabled_present = false;

    const auto row = launchd_row_from_fields(SourceId::mac_launchdaemons, fields,
                                             "/Library/LaunchDaemons/com.docker.socket.plist",
                                             Scope::system, 1700000000);
    CHECK(row.entry == "com.docker.socket");
    CHECK(row.target == "/Library/PrivilegedHelperTools/com.docker.socket");
    CHECK(row.args == "alex");
    CHECK(row.enabled == Enabled::enabled);
    CHECK(row.signed_state == Signed::not_checked); // /Library, not /System/Library
}

TEST_CASE("autoruns: launchd_row_from_fields falls back to ProgramArguments[0] when Program "
          "is absent, and reports a real Disabled=true",
          "[autoruns][parsers]") {
    // RECONSTRUCTION: no real capture in this catalog omits Program, and
    // none sets Disabled -- this pins both documented behaviours.
    LaunchdFields fields;
    fields.label = "com.example.disabled";
    fields.program_arguments = {"/usr/bin/example", "--flag"};
    fields.disabled_present = true;
    fields.disabled_value = true;

    const auto row = launchd_row_from_fields(SourceId::mac_system_launchdaemons, fields,
                                             "/System/Library/LaunchDaemons/com.example.plist",
                                             Scope::system, 0);
    CHECK(row.target == "/usr/bin/example");
    CHECK(row.args == "--flag");
    CHECK(row.enabled == Enabled::disabled);
    CHECK(row.signed_state == Signed::apple_system); // under /System/Library
}

// ── 14. parse_periodic_dir_listing ────────────────────────────────────────

TEST_CASE("autoruns: parse_periodic_dir_listing on a genuinely absent directory's "
          "record returns no scripts (etc_periodic.absent.txt, real capture)",
          "[autoruns][parsers]") {
    const auto text = read_fixture_bytes("macos/etc_periodic.absent.txt");
    // This host's /etc/periodic does not exist -- there is no `ls -l` output
    // to parse, only the recorded absence note. Feeding that note through
    // the parser must not manufacture a phantom script entry from its prose.
    CHECK(parse_periodic_dir_listing(text).empty());
}

TEST_CASE("autoruns: parse_periodic_dir_listing extracts script names, skipping the "
          "'total' header",
          "[autoruns][parsers]") {
    // RECONSTRUCTION: a populated /etc/periodic/daily directory, since this
    // host's is genuinely empty/absent.
    const std::string listing =
        "total 8\n"
        "-rwxr-xr-x  1 root  wheel  1234 Jan  1 00:00 999.local\n"
        "-rwxr-xr-x  1 root  wheel   543 Jan  1 00:00 500.daily\n";
    const auto scripts = parse_periodic_dir_listing(listing);
    REQUIRE(scripts.size() == 2);
    CHECK(scripts[0] == "999.local");
    CHECK(scripts[1] == "500.daily");
}

// ── 15. parse_emond_rule_plist_fields ────────────────────────────────────

TEST_CASE("autoruns: parse_emond_rule_plist_fields on a genuinely absent emond "
          "confirms no synthetic rule row can be produced from the absence note "
          "(etc_emond_rules.absent.txt, real capture) -- this case does NOT call "
          "the function under test; see comment",
          "[autoruns][parsers]") {
    const auto text = read_fixture_bytes("macos/etc_emond_rules.absent.txt");
    CHECK(text.find("ABSENT") != std::string::npos);
    // KNOWN GAP relative to the package acceptance criterion ("every parser
    // has >=1 REAL CAPTURE fixture case"): parse_emond_rule_plist_fields
    // takes an already-extracted EmondRuleFields struct, not plist bytes --
    // mirroring LaunchdFields, the CF/plist read is P14's (macOS leg), and
    // emond is removed on every host these fixtures were captured from, so
    // no real emond rule dict exists to extract fields from. A REAL CAPTURE
    // case for this parser is structurally unavailable to P11 without
    // either inventing EmondRuleFields data (against fixtures-from-real-
    // captures policy) or parsing plist XML here (an OS-leg concern, out of
    // this package's boundary). This case instead pins the real captured
    // absence-of-emond fact; the RECONSTRUCTION case below is the parser's
    // only functional coverage until P14 lands a real rule capture.
}

TEST_CASE("autoruns: parse_emond_rule_plist_fields builds a Row from a rule dict",
          "[autoruns][parsers]") {
    // RECONSTRUCTION: emond is removed on every host these fixtures were
    // captured from, so this pins the documented field mapping instead.
    EmondRuleFields fields;
    fields.name = "com.example.rule";
    fields.enabled_present = true;
    fields.enabled_value = false;
    fields.command = "/usr/local/bin/example";
    fields.args = {"--rule"};
    const auto row = parse_emond_rule_plist_fields(fields, "/etc/emond.d/rules/example.plist", 0);
    CHECK(row.entry == "com.example.rule");
    CHECK(row.target == "/usr/local/bin/example");
    CHECK(row.args == "--rule");
    CHECK(row.enabled == Enabled::disabled);
    CHECK(row.source_id == SourceId::mac_emond);
}

// ── source catalog sanity (not per-parser, but pure and cheap here) ──────

TEST_CASE("autoruns: every SourceDecl declares all three OSes and the three documented "
          "constrained exceptions hold, no more and no fewer "
          "(RECONSTRUCTION: pins round 4's should-fix -- lnx_systemd_timers_user's "
          "runtime status was downgraded to permanently Constrained in round 3 "
          "without updating its own catalog declaration, so autoruns.catalog and "
          "autoruns.list contradicted each other about the same source)",
          "[autoruns][catalog]") {
    REQUIRE(kSourceCatalog.size() == 34);
    std::size_t constrained_count = 0;
    for (const auto& decl : kSourceCatalog) {
        // Exactly one OS is not UNSUPPORTED for a native source -- the
        // catalog carries no cross-platform source in this wave.
        int native = 0;
        if (decl.linux != YUZU_SUPPORT_UNSUPPORTED) ++native;
        if (decl.macos != YUZU_SUPPORT_UNSUPPORTED) ++native;
        if (decl.windows != YUZU_SUPPORT_UNSUPPORTED) ++native;
        CHECK(native == 1);
        if (decl.linux == YUZU_SUPPORT_CONSTRAINED || decl.macos == YUZU_SUPPORT_CONSTRAINED ||
            decl.windows == YUZU_SUPPORT_CONSTRAINED)
            ++constrained_count;
    }
    CHECK(constrained_count == 3);
    const auto find = [](SourceId id) -> const SourceDecl& {
        for (const auto& d : kSourceCatalog)
            if (d.id == id) return d;
        FAIL("source not found in catalog");
        static SourceDecl dummy{};
        return dummy;
    };
    CHECK(find(SourceId::mac_login_items).macos == YUZU_SUPPORT_CONSTRAINED);
    CHECK(find(SourceId::lnx_init_d).linux == YUZU_SUPPORT_CONSTRAINED);
    CHECK(find(SourceId::lnx_systemd_timers_user).linux == YUZU_SUPPORT_CONSTRAINED);
}

// ── 16. ConstraintAccumulator ────────────────────────────────────────────

TEST_CASE("autoruns: ConstraintAccumulator starts with no failure and no reason",
          "[autoruns][parsers][constraint]") {
    yuzu::shared::ConstraintAccumulator acc;
    CHECK_FALSE(acc.any_failure());
    CHECK_FALSE(acc.incomplete());
    CHECK(acc.reason().empty());
    CHECK(acc.reason_with("").empty());
}

TEST_CASE("autoruns: ConstraintAccumulator dedups by EXACT string, not substring "
          "(RECONSTRUCTION: pins PR #4154 round 9's should-fix -- "
          "note_file_constraint's reason.find(token) dedup elsewhere in this file "
          "silently conflates 'permission_denied' with 'partial_permission_denied' "
          "since the former is a substring of the latter; this type must not repeat "
          "that defect)",
          "[autoruns][parsers][constraint]") {
    yuzu::shared::ConstraintAccumulator acc;
    acc.add_failure("permission_denied");
    acc.add_failure("partial_permission_denied");
    CHECK(acc.any_failure());
    // Both tokens survive -- neither is a false match for the other.
    CHECK(acc.reason() == "permission_denied,partial_permission_denied");
}

TEST_CASE("autoruns: ConstraintAccumulator dedups a repeated identical token and "
          "preserves insertion order",
          "[autoruns][parsers][constraint]") {
    yuzu::shared::ConstraintAccumulator acc;
    acc.add_failure("row_cap");
    acc.add_failure("eio");
    acc.add_failure("row_cap"); // repeat -- must not duplicate or reorder
    CHECK(acc.reason() == "row_cap,eio");
}

TEST_CASE("autoruns: ConstraintAccumulator.reason_with appends a permanent token "
          "after every accumulated failure, and is a no-op when empty",
          "[autoruns][parsers][constraint]") {
    yuzu::shared::ConstraintAccumulator acc;
    CHECK(acc.reason_with("narrow_search_path_coverage") == "narrow_search_path_coverage");

    acc.add_failure("eio");
    CHECK(acc.reason_with("narrow_search_path_coverage") == "eio,narrow_search_path_coverage");
    CHECK(acc.reason_with("") == "eio"); // empty permanent token: no-op
}

TEST_CASE("autoruns: ConstraintAccumulator.mark_incomplete is independent of "
          "add_failure -- a caller can flag incompleteness with no token of its own",
          "[autoruns][parsers][constraint]") {
    yuzu::shared::ConstraintAccumulator acc;
    acc.mark_incomplete();
    CHECK(acc.incomplete());
    CHECK_FALSE(acc.any_failure());
    CHECK(acc.reason().empty());
}
