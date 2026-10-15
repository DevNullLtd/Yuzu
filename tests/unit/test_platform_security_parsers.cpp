/**
 * test_platform_security_parsers.cpp -- pure coverage of platform_security_parsers.hpp.
 * No platform guard; readers/runners are INJECTED (nothing opens /sys, spawns or sleeps).
 * Fixtures (tests/unit/fixtures/wave8/platform_security/, each with a .provenance.txt):
 * REAL CAPTURE lsm.txt, absent_paths.txt (a capture of ABSENCE), the macOS pair; RECONSTRUCTION
 * SecureBoot-{on,off}.bin, lockdown.txt. Inline RECONSTRUCTION literals are non-modal or
 * malformed forms no host here produces. Assertions pin literals; each case's comment
 * names the mutation it fails under.
 */
#include <catch2/catch_test_macros.hpp>

#include "platform_security_parsers.hpp"

#include <array>
#include <cerrno>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

using namespace yuzu::platform_security;
namespace fs = std::filesystem;
using yuzu::shared::ConstraintAccumulator;
using Rows = std::vector<std::string>;

namespace {

std::string fixture(const char* sub, const char* name) {
    const fs::path p = fs::path{YUZU_TEST_FIXTURE_DIR} / "wave8" / "platform_security" / sub / name;
    std::ifstream f(p, std::ios::binary);
    REQUIRE(f.is_open()); // a missing fixture is a broken tree, never a skip
    return std::string(std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>());
}

// Literal paths (NOT read from the code's table): a typo in the table misses this lookup and
// the row reads `absent`.
const std::string kSecureBootPath =
    "/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c";
const std::string kSetupModePath =
    "/sys/firmware/efi/efivars/SetupMode-8be4df61-93ca-11d2-aa0d-00e098032b8c";

struct FakeFile {
    std::string path;
    ReadOutcome outcome;
};

/// A reader over a fixed set of files; any other path is ENOENT, as a real missing file is.
auto reader_over(std::vector<FakeFile> files) {
    return [files = std::move(files)](std::string_view path) -> ReadOutcome {
        for (const auto& f : files)
            if (f.path == path) return f.outcome;
        return {ENOENT, {}};
    };
}

Rows formatted(const std::vector<PlatformRow>& rows) {
    Rows out;
    for (const auto& r : rows) out.push_back(format_row(r));
    return out;
}

std::string bytes5(char data) { return std::string("\x06\x00\x00\x00", 4) + data; }

} // namespace

// Fails if a token is renamed/dropped or two collapse (absent/unreadable/unsupported stay distinct).
TEST_CASE("platform_security: the seven state tokens are exact and indexed by enumerator",
          "[platform_security][parsers]") {
    CHECK(kStateTokens == std::array<std::string_view, 7>{"enabled", "disabled", "partial", "unmodelled",
                                                          "absent", "unreadable", "unsupported"});
    CHECK(state_token(PlatformState::absent) == "absent");
    CHECK(state_token(PlatformState::unsupported) == "unsupported");
}

// Fails if the size check is loosened (`>= 5`) or moved, or the attribute bytes leak into the value.
TEST_CASE("platform_security: decode_efivar_bool takes exactly 4 attribute bytes + 1 data byte",
          "[platform_security][parsers][efivars]") {
    CHECK(decode_efivar_bool(bytes5('\x01')) == 1);
    CHECK(decode_efivar_bool(bytes5('\x00')) == 0);
    CHECK(decode_efivar_bool(std::string_view{"\xFF\xFF\xFF\xFF\x02", 5}) == 2); // rules interpret it
    CHECK_FALSE(decode_efivar_bool({}).has_value());
    CHECK_FALSE(decode_efivar_bool(std::string_view{"\x06\x00\x00\x00", 4}).has_value());
    CHECK_FALSE(decode_efivar_bool(bytes5('\x01') + '\x00').has_value());
    CHECK_FALSE(decode_efivar_bool(std::string(64, '\x01')).has_value());
}

// SecureBoot on / off / absent (docker case below) / unreadable are four different states. Fails
// if any pair collapses (EACCES read as absent) or SetupMode shares SecureBoot's mapping
// (SetupMode=1 must be `disabled`, an out-of-range byte `unmodelled`).
TEST_CASE("platform_security: SecureBoot on, off, absent and unreadable are four distinct states",
          "[platform_security][parsers][efivars]") {
    const std::string on = fixture("linux", "SecureBoot-on.bin");
    const std::string off = fixture("linux", "SecureBoot-off.bin");
    REQUIRE(on.size() == 5);
    REQUIRE(off.size() == 5);
    ConstraintAccumulator acc;
    CHECK(formatted(secure_boot_rows_linux(
              reader_over({{kSecureBootPath, {0, on}}, {kSetupModePath, {0, off}}}), acc)) ==
          Rows{"secure_boot|linux|secure_boot|1|enabled", "secure_boot|linux|setup_mode|0|enabled"});
    CHECK(formatted(secure_boot_rows_linux(
              reader_over({{kSecureBootPath, {0, off}}, {kSetupModePath, {0, on}}}), acc)) ==
          Rows{"secure_boot|linux|secure_boot|0|disabled", "secure_boot|linux|setup_mode|1|disabled"});
    CHECK(formatted(secure_boot_rows_linux(
              reader_over({{kSecureBootPath, {0, bytes5('\x02')}}}), acc))[0] ==
          "secure_boot|linux|secure_boot|2|unmodelled");
    CHECK_FALSE(acc.any_failure()); // values and ENOENT never add a token

    {   // EACCES injected through the reader seam: unreadable, never absent, and a denial.
        ConstraintAccumulator denied;
        const auto rows = secure_boot_rows_linux(
            reader_over({{kSecureBootPath, {EACCES, {}}}, {kSetupModePath, {0, off}}}), denied);
        CHECK(formatted(rows) == Rows{"secure_boot|linux|secure_boot|-|unreadable",
                                      "secure_boot|linux|setup_mode|0|enabled"});
        CHECK(denied.reason() == "secure_boot:eacces");
        CHECK(any_denied(rows));
    }
}

// Fails if a wrong-sized efivar is decoded anyway, reads absent, or its token loses the key.
TEST_CASE("platform_security: a wrong-sized efivar is unreadable with the constrained efivars:shape token",
          "[platform_security][parsers][efivars]") {
    ConstraintAccumulator acc;
    const auto rows = secure_boot_rows_linux(
        reader_over({{kSecureBootPath, {0, std::string("\x06\x00\x00\x00", 4)}},
                     {kSetupModePath, {0, bytes5('\x00') + '\x00'}}}),
        acc);
    CHECK(formatted(rows) == Rows{"secure_boot|linux|secure_boot|-|unreadable",
                                  "secure_boot|linux|setup_mode|-|unreadable"});
    CHECK(acc.reason() == "secure_boot:efivars:shape,setup_mode:efivars:shape");
    CHECK(select_status(acc, any_denied(rows)).status == YUZU_RESULT_STATUS_CONSTRAINED);
}

// Fails if the fixture stops driving the rows: the reader is BUILT FROM the captured lines, so a
// changed capture changes the result. The capture is all ENOENT: absent rows, OK, no token.
TEST_CASE("platform_security: the real Docker capture (no UEFI vars, no Lockdown LSM) is all absent",
          "[platform_security][parsers][fixtures]") {
    std::vector<FakeFile> files{{"/sys/kernel/security/lsm", {0, fixture("linux", "lsm.txt")}}};
    std::istringstream in(fixture("linux", "absent_paths.txt"));
    std::string line;
    while (std::getline(in, line)) {
        const auto t1 = line.find('\t');
        REQUIRE(t1 != std::string::npos);
        REQUIRE(line.compare(t1, 5, "\terr\t") == 0);
        REQUIRE(line.find("No such file or directory") != std::string::npos);
        files.push_back({line.substr(0, t1), {ENOENT, {}}});
    }
    REQUIRE(files.size() == 4);
    ConstraintAccumulator acc;
    CHECK(formatted(secure_boot_rows_linux(reader_over(files), acc)) ==
          Rows{"secure_boot|linux|secure_boot|-|absent", "secure_boot|linux|setup_mode|-|absent"});
    CHECK(formatted(code_integrity_rows_linux(reader_over(files), acc)) ==
          Rows{"code_integrity|linux|lsm|capability,bpf,landlock|disabled",
               "code_integrity|linux|lockdown|-|absent"});
    CHECK(acc.reason().empty());
    CHECK(select_status(acc, false).status == YUZU_RESULT_STATUS_OK);
}

// PR #4792 review (fjarvis, 5289352195, HIGH): a leaf ENOENT must mean "the OS definitively says
// this value is not there", never "the whole collection surface (efivarfs/securityfs) isn't
// mounted in this namespace" -- the two are indistinguishable from open()'s errno alone. The real
// fix lives in platform_security_linux.cpp's read_file, which is real-syscall code this pure-layer
// suite cannot exercise directly (per the file's own injected-reader design) -- what IS testable,
// and what the fixed read_file now depends on, is that the pure layer correctly tells a genuine
// "not there" (ENOENT) apart from a "surface unavailable" signal (any other errno, here ENODEV)
// reaching it through the SAME reader seam. This locks that contract in independently of the real
// mount-detection code, exactly mirroring the existing EACCES regression above.
TEST_CASE("platform_security: a collection-surface-unavailable errno is unreadable, never absent",
          "[platform_security][parsers][fixtures]") {
    ConstraintAccumulator acc;
    const auto rows = secure_boot_rows_linux(
        reader_over({{kSecureBootPath, {ENODEV, {}}}, {kSetupModePath, {ENODEV, {}}}}), acc);
    CHECK(formatted(rows) == Rows{"secure_boot|linux|secure_boot|-|unreadable",
                                  "secure_boot|linux|setup_mode|-|unreadable"});
    // ENODEV's numeric value isn't POSIX-mandated (this test file also builds on macOS/Windows) --
    // match the source's own "<key>:errno_<n>" construction rather than hardcode a platform value.
    const std::string tok = "errno_" + std::to_string(ENODEV);
    CHECK(acc.reason() == "secure_boot:" + tok + ",setup_mode:" + tok);
    CHECK_FALSE(any_denied(rows)); // unreadable, but not a permission denial
    CHECK(select_status(acc, false).status == YUZU_RESULT_STATUS_CONSTRAINED);

    ConstraintAccumulator ci_acc;
    const auto ci_rows = code_integrity_rows_linux(
        reader_over({{"/sys/kernel/security/lsm", {ENODEV, {}}},
                     {"/sys/kernel/security/lockdown", {ENODEV, {}}}}),
        ci_acc);
    CHECK(formatted(ci_rows) == Rows{"code_integrity|linux|lsm|-|unreadable",
                                     "code_integrity|linux|lockdown|-|unreadable"});
}

// Fails if the decision order changes: absence alone stays OK/FULL, a token beats OK, a denial
// outranks another failure (both tokens stay in provenance).
TEST_CASE("platform_security: select_status is the one decision every leg shares",
          "[platform_security][parsers][status]") {
    ConstraintAccumulator acc;
    auto s = select_status(acc, false);
    CHECK(s.status == YUZU_RESULT_STATUS_OK);
    CHECK(s.completeness == YUZU_RESULT_COMPLETENESS_FULL);
    CHECK(s.provenance.empty());
    acc.add_failure("lsm:errno_5");
    s = select_status(acc, false);
    CHECK(s.status == YUZU_RESULT_STATUS_CONSTRAINED);
    CHECK(s.completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
    CHECK(s.provenance == "lsm:errno_5");
    acc.add_failure("lockdown:eacces");
    s = select_status(acc, true);
    CHECK(s.status == YUZU_RESULT_STATUS_PERMISSION_DENIED);
    CHECK(s.completeness == YUZU_RESULT_COMPLETENESS_PARTIAL);
    CHECK(s.provenance == "lsm:errno_5,lockdown:eacces");
}

// Fails if the field order changes or an OS-supplied '|' stays unescaped (the server decoder
// would split the row).
TEST_CASE("platform_security: format_row is action|os|key|raw|state and escapes pipes",
          "[platform_security][parsers][rows]") {
    CHECK(format_row({"secure_boot", "linux", "secure_boot", "1", PlatformState::enabled}) ==
          "secure_boot|linux|secure_boot|1|enabled");
    CHECK(format_row({"code_integrity", "macos", "sip", "a|b", PlatformState::unmodelled}) ==
          "code_integrity|macos|sip|a\\|b|unmodelled");
    CHECK(format_row(unsupported_row("secure_boot", "macos", "secure_boot")) ==
          "secure_boot|macos|secure_boot|-|unsupported");
    CHECK(failure_token("k", EPERM) == "k:eacces"); // a refusal is spelled eacces whichever errno
}

// Fails if a MAC LSM goes unrecognised, a no-MAC list reads `enabled`, or malformed text is
// guessed at instead of `unmodelled`.
TEST_CASE("platform_security: the LSM list is enabled only when a MAC LSM is active",
          "[platform_security][parsers][lsm]") {
    CHECK(classify_lsm_list(fixture("linux", "lsm.txt")) == PlatformState::disabled); // REAL: no MAC LSM
    // RECONSTRUCTION: typical Ubuntu / RHEL lists and edge forms.
    for (const char* mac : {"lockdown,capability,landlock,yama,apparmor,ima,evm\n",
                            "lockdown,capability,yama,selinux,bpf", "smack", "tomoyo,capability"})
        CHECK(classify_lsm_list(mac) == PlatformState::enabled);
    CHECK(classify_lsm_list("capability") == PlatformState::disabled);
    CHECK(classify_lsm_list("") == PlatformState::disabled);
    CHECK(classify_lsm_list("capability\napparmor") == PlatformState::disabled); // first line only
    for (const char* bad : {"capability,,apparmor", "capability,", ",apparmor", "AppArmor",
                            "capability apparmor", "apparmor;selinux"})
        CHECK(classify_lsm_list(bad) == PlatformState::unmodelled);
}

// Fails if the bracketed token is not the one used, `integrity` stops being partial, or an
// unknown active token is guessed at instead of `unmodelled`.
TEST_CASE("platform_security: lockdown reads the bracketed active mode",
          "[platform_security][parsers][lockdown]") {
    // RECONSTRUCTION (kernel format; the only accessible kernel has no Lockdown LSM).
    CHECK(classify_lockdown(fixture("linux", "lockdown.txt")) == PlatformState::disabled);
    CHECK(classify_lockdown("none [integrity] confidentiality\n") == PlatformState::partial);
    CHECK(classify_lockdown("none integrity [confidentiality]\n") == PlatformState::enabled);
    for (const char* bad : {"none integrity [paranoid]\n", "none integrity confidentiality\n",
                            "[none] [integrity] confidentiality\n", "[none integrity confidentiality\n",
                            "[] integrity\n", "", "[None] integrity confidentiality"})
        CHECK(classify_lockdown(bad) == PlatformState::unmodelled);
}

// Fails if the two Linux rows are reordered/dropped or one failure hides the other.
TEST_CASE("platform_security: Linux code_integrity emits lsm then lockdown independently",
          "[platform_security][parsers][lsm][lockdown]") {
    ConstraintAccumulator acc;
    const auto rows = code_integrity_rows_linux(reader_over({{"/sys/kernel/security/lsm", {EACCES, {}}}}), acc);
    CHECK(formatted(rows) == Rows{"code_integrity|linux|lsm|-|unreadable",
                                  "code_integrity|linux|lockdown|-|absent"});
    CHECK(acc.reason() == "lsm:eacces");
    CHECK(any_denied(rows));

    ConstraintAccumulator ok;
    CHECK(formatted(code_integrity_rows_linux(
              reader_over({{"/sys/kernel/security/lsm", {0, "lockdown,capability,apparmor\n"}},
                           {"/sys/kernel/security/lockdown", {0, fixture("linux", "lockdown.txt")}}}),
              ok)) ==
          Rows{"code_integrity|linux|lsm|lockdown,capability,apparmor|enabled",
               "code_integrity|linux|lockdown|[none] integrity confidentiality|disabled"});
    CHECK_FALSE(ok.any_failure());
}

// Fails if the exact-line match is loosened to a substring or the custom-configuration form stops
// being `partial`.
TEST_CASE("platform_security: spctl and csrutil text maps to enabled, disabled, partial or unmodelled",
          "[platform_security][parsers][macos]") {
    CHECK(parse_spctl_status(fixture("macos", "spctl_status.txt")) == PlatformState::enabled); // REAL
    CHECK(parse_csrutil_status(fixture("macos", "csrutil_status.txt")) == PlatformState::enabled); // REAL
    // RECONSTRUCTION: the other documented answers and text this table does not know.
    CHECK(parse_spctl_status("assessments disabled\n") == PlatformState::disabled);
    CHECK(parse_spctl_status("\nassessments enabled\n") == PlatformState::enabled);
    for (const char* bad : {"assessments enabled (with override)\n", "Gatekeeper is enabled\n", ""})
        CHECK(parse_spctl_status(bad) == PlatformState::unmodelled);
    CHECK(parse_csrutil_status("System Integrity Protection status: disabled.\n") == PlatformState::disabled);
    CHECK(parse_csrutil_status("System Integrity Protection status: enabled (Custom Configuration).\n"
                               "\nConfiguration:\n\tApple Internal: disabled\n") == PlatformState::partial);
    for (const char* bad : {"System Integrity Protection status: unknown (Custom Configuration).\n",
                            "System Integrity Protection status: enabled\n", // no trailing period
                            "csrutil: failed to read status\n", ""})
        CHECK(parse_csrutil_status(bad) == PlatformState::unmodelled);
}

namespace {
ToolOutcome ran(std::string out, int exit_code = 0) {
    ToolOutcome o;
    o.tool_ran = true;
    o.exit_code = exit_code;
    o.output = std::move(out);
    return o;
}
} // namespace

// Fails if any run outcome maps to the wrong state/token: a spawn failure -- including ENOENT,
// a missing binary -- is unreadable + a named token, never absent (spctl/csrutil are sealed-
// system-volume binaries with no legitimate "not there" case); every incomplete run is unreadable
// + a named token; a parsed state survives a non-zero exit (spctl); an unparsed one does not; a
// refusal is a denial.
TEST_CASE("platform_security: tool_row classifies every bounded-run outcome",
          "[platform_security][parsers][macos][tool]") {
    struct Case {
        const char* what;
        ToolOutcome outcome;
        std::string row;
        std::string reason; // expected accumulator reason ("" = no failure)
        bool denied;
    };
    ToolOutcome timed = ran("assessments enabled\n");
    timed.timed_out = true;
    ToolOutcome truncated = ran("assessments enabled\n");
    truncated.output_truncated = true;
    ToolOutcome missing;
    missing.spawn_errno = ENOENT;
    ToolOutcome refused;
    refused.spawn_errno = EACCES;
    const std::string pre = "code_integrity|macos|gatekeeper|";
    const std::vector<Case> cases{
        {"clean", ran("assessments enabled\n"), pre + "assessments enabled|enabled", "", false},
        {"parsed text trusted despite exit 1", ran("assessments disabled\n", 1),
         pre + "assessments disabled|disabled", "", false},
        {"unparsed + exit 0", ran("something new\n"), pre + "something new|unmodelled", "", false},
        {"unparsed + exit 2", ran("", 2), pre + "-|unreadable", "gatekeeper:exit_2", false},
        {"signal", ran("", -1), pre + "-|unreadable", "gatekeeper:exit_signal", false},
        {"deadline", timed, pre + "-|unreadable", "gatekeeper:timeout", false},
        {"output cap", truncated, pre + "-|unreadable", "gatekeeper:output_truncated", false},
        {"not installed", missing, pre + "-|unreadable", "gatekeeper:errno_2", false},
        {"not executable", refused, pre + "-|unreadable", "gatekeeper:eacces", true},
        {"spawn failure, no errno", ToolOutcome{}, pre + "-|unreadable", "gatekeeper:spawn_failed", false},
    };
    for (const auto& c : cases) {
        INFO(c.what);
        ConstraintAccumulator acc;
        const auto r = tool_row("code_integrity", "macos", "gatekeeper", c.outcome, &parse_spctl_status, acc);
        CHECK(format_row(r) == c.row);
        CHECK(acc.reason() == c.reason);
        CHECK(r.denied == c.denied);
    }
}

// Fails if the two macOS rows are reordered, keyed wrongly, or one failure hides the other.
TEST_CASE("platform_security: macOS code_integrity emits gatekeeper then sip over the real captures",
          "[platform_security][parsers][macos]") {
    const std::string spctl = fixture("macos", "spctl_status.txt");
    const std::string csrutil = fixture("macos", "csrutil_status.txt");
    ConstraintAccumulator acc;
    CHECK(formatted(code_integrity_rows_macos([&](int w) { return ran(w == 1 ? spctl : csrutil); }, acc)) ==
          Rows{"code_integrity|macos|gatekeeper|assessments enabled|enabled",
               "code_integrity|macos|sip|System Integrity Protection status: enabled.|enabled"});
    CHECK_FALSE(acc.any_failure());

    ConstraintAccumulator acc2;
    ToolOutcome timed = ran("");
    timed.timed_out = true;    CHECK(formatted(code_integrity_rows_macos([&](int w) { return w == 1 ? timed : ran(csrutil); }, acc2)) ==
          Rows{"code_integrity|macos|gatekeeper|-|unreadable",
               "code_integrity|macos|sip|System Integrity Protection status: enabled.|enabled"});
    CHECK(acc2.reason() == "gatekeeper:timeout");
}
