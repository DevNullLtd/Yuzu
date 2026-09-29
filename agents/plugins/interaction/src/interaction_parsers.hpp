#pragma once

/**
 * interaction_parsers.hpp — pure parse helpers for the interaction plugin:
 * decoding the sentinel-wrapped `osascript` output of a try/on-error
 * `display dialog` (macOS message_box) into a structured dialog outcome,
 * plus the POSIX zenity and Windows PowerShell dialog-capture exit-code/
 * runner-state classification used by the input/survey legs on every OS.
 *
 * Header-only and OS-free so the parsing is unit-tested on every host
 * (test_interaction_parsers.cpp — the licensing_parsers.hpp pattern); the
 * runner-backed shell-out in interaction_plugin.cpp is the impure shell, and
 * the operator-supplied title/message it interpolates are already run
 * through sanitize() there, so nothing attacker-controlled reaches this
 * parser.
 *
 * Honest-status invariant: an `osascript` that could not display the dialog
 * (no Aqua/GUI session on the root LaunchDaemon, a TCC denial, a missing
 * binary, or any unrecognised output) decodes to `not_reachable` — NEVER a
 * false button. The one error attributable to the user, AppleScript's -128
 * "user canceled", decodes to `cancel`; every other error is not_reachable.
 */

#include <format>
#include <string>
#include <string_view>
#include <vector>

namespace yuzu::interaction {

/// Outcome of a macOS message_box dispatch, decoded from the osascript
/// sentinel output. `not_reachable` is the fail-closed default.
enum class DialogOutcome { ok, cancel, yes, no, not_reachable };

/// Builds the argv for the try/on-error `display dialog` osascript
/// invocation that `parse_dialog_result` below decodes — one AppleScript
/// fragment per `-e` argv element, exactly as osascript's own multi-`-e`
/// form expects; no shell involved in the OUTER spawn (unlike a `-c`-style
/// interpreter, osascript takes a multi-statement script as ordinary argv
/// elements). This does NOT make it a rung-2 site: ADR-3002 Decision 5 is
/// explicit that a site's rung is set by the deepest interpreter
/// intentionally invoked, not the outer spawn API — osascript IS that
/// interpreter, so this stays a rung-3 governed-interpreter site (Decision-5
/// registration), just no longer a Decision-7 shell exception. Pulled out
/// as its own pure
/// function (rather than left inline in the .cpp) so a typo in the
/// AppleScript fragments — which would silently turn every real button
/// press into `not_reachable` — is a unit-test failure, not a runtime-only
/// regression. `safe_title`/`safe_msg` must already be sanitized by the
/// caller; this function performs no escaping of its own (each fragment is
/// its own argv element, so there is no shell-quoting surface to escape).
[[nodiscard]] inline std::vector<std::string> build_dialog_argv(std::string_view safe_title,
                                                                 std::string_view safe_msg,
                                                                 std::string_view btn_spec) {
    return {
        "-e", "try",
        "-e", std::format("display dialog \"{}\" with title \"{}\" {}", safe_msg, safe_title,
                          btn_spec),
        "-e", "return \"##BTN##\" & (button returned of result)",
        "-e", "on error errMsg number errNum",
        "-e", "return \"##ERR##\" & errNum",
        "-e", "end try",
    };
}

/// The osascript command wraps `display dialog` in try/on-error and returns
/// either `##BTN##<button>` (a real button press) or `##ERR##<errNum>` (an
/// AppleScript error). Error -128 is "user canceled"; anything else means the
/// dialog never reached a display server. Unrecognised output (empty, shell
/// error prose, a missing osascript binary) is treated as not_reachable — the
/// honest-status invariant, never a false `ok`.
[[nodiscard]] inline DialogOutcome parse_dialog_result(std::string_view out) {
    // Trim surrounding whitespace/newlines the shell may have left behind.
    while (!out.empty() && (out.front() == ' ' || out.front() == '\t' ||
                            out.front() == '\n' || out.front() == '\r'))
        out.remove_prefix(1);
    while (!out.empty() && (out.back() == ' ' || out.back() == '\t' ||
                            out.back() == '\n' || out.back() == '\r'))
        out.remove_suffix(1);

    constexpr std::string_view kBtn = "##BTN##";
    constexpr std::string_view kErr = "##ERR##";

    if (out.starts_with(kBtn)) {
        const std::string_view button = out.substr(kBtn.size());
        // `display dialog` echoes the literal button label we specified.
        if (button == "OK") return DialogOutcome::ok;
        if (button == "Cancel") return DialogOutcome::cancel;
        if (button == "Yes") return DialogOutcome::yes;
        if (button == "No") return DialogOutcome::no;
        // A label we never offered — cannot map honestly to a response.
        return DialogOutcome::not_reachable;
    }

    if (out.starts_with(kErr)) {
        const std::string_view err_num = out.substr(kErr.size());
        // -128 is AppleScript's "user canceled"; everything else (no window
        // server, not authorised, app not running, …) is a delivery failure.
        return err_num == "-128" ? DialogOutcome::cancel : DialogOutcome::not_reachable;
    }

    return DialogOutcome::not_reachable;
}

/// The (output line, return code) decision for the macOS `input`/`survey`
/// osascript-capture legs, extracted here so it is unit-testable without a
/// subprocess (qe-L2). Given the captured osascript exit code and its trimmed
/// output:
///   - a non-zero exit is a delivery failure (no reachable GUI session, TCC
///     denial, …) -> an honest `status|unavailable` line + rc 1, NEVER wrapping
///     the error text as a `response`;
///   - the `##CANCELLED##` sentinel (AppleScript -128, converted at exit 0) ->
///     `cancelled|true` + rc 0;
///   - anything else on a successful run is genuine user input -> `response|…`.
struct CaptureDecision {
    std::string output_line;
    int rc = 0;
};

inline CaptureDecision classify_input_capture(int exit_code, std::string_view output) {
    if (exit_code != 0)
        return {"status|unavailable|no reachable GUI session", 1};
    if (output == "##CANCELLED##")
        return {"cancelled|true", 0};
    return {std::format("response|{}", output), 0};
}

/// Outcome of a POSIX run_command_capture() exit-code classification for the
/// Linux zenity `--entry`/`--list` captures (input text, survey text/choice).
/// Unlike macOS's osascript (any nonzero exit is a delivery failure), zenity's
/// own contract makes a nonzero exit code a REAL domain signal (Cancel/
/// dismiss = 1, ESC/timeout = 5) -- but run_command_capture's documented -1
/// sentinel means the tool never produced a real exit status at all (spawn
/// error, deadline, or signal death; see subprocess_runner.hpp), which must
/// never be misread as the user clicking Cancel.
enum class PosixCaptureOutcome { runner_failure, cancelled, real_output };

[[nodiscard]] inline PosixCaptureOutcome classify_posix_capture(int exit_code) {
    if (exit_code == -1) return PosixCaptureOutcome::runner_failure;
    if (exit_code != 0) return PosixCaptureOutcome::cancelled;
    return PosixCaptureOutcome::real_output;
}

/// The (output line, return code, is_failure) decision for the Windows
/// input/survey PowerShell dialog legs, extracted here so it is
/// unit-testable without a subprocess (the classify_input_capture pattern).
/// Consolidates the three checks these sites must run, in order, before ever
/// parsing PowerShell's stdout as a real dialog outcome: did the process
/// launch at all (tool_ran), did it hit the deadline (timed_out), and --
/// the gap this closes -- did it exit non-zero (a ShowDialog()/InputBox()
/// exception under a non-interactive session, whose error text never
/// reaches output since merge_stderr defaults false). Any of the three is a
/// genuine runner/tool failure, never a fabricated cancel or an
/// empty-but-"successful" response.
struct WindowsDialogDecision {
    std::string output_line;
    int rc = 0;
    bool is_failure = false;
};

[[nodiscard]] inline WindowsDialogDecision classify_windows_dialog_capture(
    bool tool_ran, bool timed_out, int exit_code) {
    if (!tool_ran)
        return {"status|error|failed to launch PowerShell", 1, true};
    if (timed_out)
        return {"status|unavailable|PowerShell dialog timed out", 1, true};
    if (exit_code != 0)
        return {"status|unavailable|PowerShell dialog exited with an error", 1, true};
    return {{}, 0, false};
}

} // namespace yuzu::interaction
