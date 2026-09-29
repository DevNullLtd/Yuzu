#pragma once

// filesystem_macos_sig.hpp -- pure macOS signature/version-info mappers for
// the filesystem plugin's get_signature and get_version_info actions.
//
// Two independent, framework-free mappings live here (rather than inline in
// filesystem_plugin.cpp) so they are fixture-testable on every host platform
// without a macOS box or a real codesign/plutil binary — mirroring the
// "impure collection / pure mapping" split dex_macos_signals.hpp uses:
//
//   1. classify_codesign_result() -- `codesign --verify --deep --strict <path>`
//      exit code + captured stdout+stderr -> an HONEST macOS signature status.
//      This is a DIFFERENT vocabulary from the Windows Authenticode statuses
//      (valid/distrusted/untrusted/security_settings_blocked) that
//      filesystem_plugin.cpp emits under _WIN32 -- codesign/Gatekeeper model
//      trust differently than WinVerifyTrust, and reusing the Windows strings
//      would misrepresent a macOS result as a Windows one. See
//      filesystem_plugin.cpp do_get_signature().
//
//   2. classify_plutil_extract() -- `plutil -extract <key> raw -o - <Info.plist>`
//      exit code + captured stdout -> an optional trimmed string value. Used
//      for BOTH CFBundleShortVersionString and CFBundleVersion. plutil reads
//      binary (bplist00) AND XML property lists natively (P13 -- unlike the
//      license_scan text-plist reader at licensing_macos.cpp, which knowingly
//      skips binary plists), so this needs no bplist parsing of its own.
//
// Neither function execs anything -- filesystem_plugin.cpp owns the
// subprocess plumbing (fork/execvp, no shell) and hands this header the
// already-captured exit code + output text.

#include <string>
#include <string_view>

namespace yuzu::filesystem_macos {

// ── get_signature: codesign-output -> honest macOS signature status ────────

enum class SignatureStatus {
    valid,      // codesign --verify --deep --strict exited 0.
    not_signed, // codesign reports the code object carries no signature at all.
    invalid,    // codesign ran, exited non-zero, and reported a signature/binary
                // problem (broken seal, bad requirement, corrupt resource, etc.).
    unknown,    // codesign is missing, or exited non-zero with output that does
                // not match a recognised codesign diagnostic -- never guessed.
};

inline std::string_view to_string(SignatureStatus status) noexcept {
    switch (status) {
    case SignatureStatus::valid:
        return "valid";
    case SignatureStatus::not_signed:
        return "unsigned";
    case SignatureStatus::invalid:
        return "invalid";
    case SignatureStatus::unknown:
        break;
    }
    return "unknown";
}

// BR-005: this header was originally a verbatim salvage of a mapping that
// treated EVERY non-zero codesign exit carrying any output as `invalid`.
// That is wrong -- a TRUST failure on an otherwise well-formed, unmodified
// signature (e.g. CSSMERR_TP_NOT_TRUSTED: the seal is intact but the cert
// chain, a notarization ticket, or local policy isn't trusted) is not
// tampering, and reporting it as `invalid` produces a false "tampered"
// compliance result. Only diagnostics that actually PROVE a broken seal, a
// bad code requirement, or a corrupt/mismatched sealed resource may map to
// `invalid`; everything else non-zero (trust/policy/notarization failures,
// or any diagnostic we don't recognise) honestly falls through to
// `unknown`, per the enum's own contract above.
//
// codesign's diagnostic text is stable across macOS releases (it comes from
// Security.framework's SecStaticCode error strings).
constexpr std::string_view kInvalidDiagnostics[] = {
    "a sealed resource is missing or invalid",
    "resource envelope is obsolete",
    "code has no resources but signature indicates they must be present",
    "main executable failed strict validation",
    "the signature is invalid",
};

inline bool matches_invalid_diagnostic(std::string_view output) noexcept {
    for (auto diagnostic : kInvalidDiagnostics) {
        if (output.find(diagnostic) != std::string_view::npos)
            return true;
    }
    return false;
}

// `tool_ran` is false only when the codesign binary itself could not be
// launched (e.g. missing from PATH) -- callers signal this distinctly from a
// real codesign invocation that happened to exit non-zero. `output` is the
// COMBINED stdout+stderr codesign produced (its diagnostics go to stderr for
// a `--verify` run, so both streams must be captured for this to see them).
inline SignatureStatus classify_codesign_result(bool tool_ran, int exit_code,
                                                 std::string_view output) {
    if (!tool_ran)
        return SignatureStatus::unknown;

    // HONEST SEMANTICS: on macOS `valid` means the code signature's SEAL is
    // intact -- `codesign --verify --deep --strict` exited 0, proving the
    // Mach-O/bundle has not been modified since it was signed. It does NOT
    // mean the signer is trusted, notarized, or accepted by Gatekeeper: an
    // ad-hoc or self-signed binary passes this check. This is a WEAKER
    // assurance than Windows WinVerifyTrust's `valid`, which additionally
    // validates the Authenticode certificate chain up to a trusted root.
    // Establishing trust/notarization would require spctl (Gatekeeper
    // assessment), deliberately out of scope here -- so `valid` is reported
    // as integrity-only, never as a trust verdict.
    if (exit_code == 0)
        return SignatureStatus::valid;

    if (output.find("code object is not signed at all") != std::string_view::npos)
        return SignatureStatus::not_signed;

    // Only a recognised broken-seal/bad-requirement/corrupt-resource
    // diagnostic proves tampering. A trust failure (CSSMERR_TP_NOT_TRUSTED
    // and friends -- untrusted cert chain, missing notarization, local
    // policy) or any other unrecognised non-zero-exit diagnostic is not
    // evidence of tampering, so it stays `unknown` rather than being
    // reported as `invalid`.
    if (matches_invalid_diagnostic(output))
        return SignatureStatus::invalid;

    return SignatureStatus::unknown;
}

// ── get_version_info: plutil-output -> optional trimmed value ──────────────

struct PlutilExtractResult {
    bool available = false;
    std::string value;
};

inline std::string_view trim(std::string_view s) noexcept {
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t' || s.front() == '\n' ||
                          s.front() == '\r'))
        s.remove_prefix(1);
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t' || s.back() == '\n' ||
                          s.back() == '\r'))
        s.remove_suffix(1);
    return s;
}

// `tool_ran` is false only when plutil itself could not be launched. On
// success, plutil (with `-o -`) writes ONLY the raw value to stdout; on
// failure (missing key, missing file, not a plist at all) it writes a
// diagnostic to stderr and nothing to stdout, and exits non-zero. Both
// failure shapes fold into `available == false` -- never fabricated.
inline PlutilExtractResult classify_plutil_extract(bool tool_ran, int exit_code,
                                                    std::string_view output) {
    PlutilExtractResult result;
    if (!tool_ran || exit_code != 0)
        return result;

    auto trimmed = trim(output);
    if (trimmed.empty())
        return result;

    result.available = true;
    result.value = std::string{trimmed};
    return result;
}

} // namespace yuzu::filesystem_macos
