/**
 * interaction_plugin.cpp — Desktop user interaction plugin for Yuzu
 *
 * Actions:
 *   "notify"      — Show a desktop notification/toast.
 *   "message_box" — Show a modal message dialog, return button clicked.
 *   "input"       — Show a text input dialog, return entered text.
 *   "survey"      — Show a multi-question survey form, collect responses.
 *   "set_dnd"     — Enable/disable Do Not Disturb mode (suppress notifications).
 *
 * Output is pipe-delimited, one field per line via write_output():
 *   key|value
 *
 * Platform support:
 *   Windows — ShellNotifyIconW, MessageBoxW, PowerShell InputBox / Forms
 *   Linux   — notify-send, zenity
 *   macOS   — osascript (display notification, display dialog)
 *
 * Input validation: title/message/prompt fields are sanitized before being
 * embedded in an osascript/PowerShell script fragment or passed as a zenity/
 * notify-send argument. Every spawn goes through the bounded argv runner
 * (yuzu::agent::run_bounded_subprocess) with clean argv end to end on every
 * OS — no shell is ever invoked. On macOS, osascript's own multi-statement
 * `-e` form carries each AppleScript fragment as its own argv element
 * (ADR-3002 Decision 5: osascript is the deepest interpreter intentionally
 * invoked and sets the rung, but the outer spawn is argv-clean, same
 * principle as PowerShell's `-Command`). On Linux, zenity/notify-send are
 * plain binaries with no interpreter role at all — ordinary rung-2 argv
 * candidates, each flag/value its own argv element. Only alphanumeric,
 * spaces, and safe punctuation are allowed through sanitize().
 */

#include <yuzu/plugin.hpp>

#include "interaction_parsers.hpp"

#include <algorithm>
#include <charconv>
#include <chrono>
#include <cstdlib>
#include <format>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <shellapi.h>
#include <win_str.hpp>  // shared yuzu::win wide<->UTF-8 helpers (#1681)
#include <yuzu/agent/runner_status.hpp>     // yuzu::agent::forward_runner_failure (ABI4 result seam)
#include <yuzu/agent/subprocess_runner.hpp> // yuzu::agent::run_bounded_subprocess / probe_tool_path (ADR-3002)
#else
#include <yuzu/agent/runner_status.hpp>     // yuzu::agent::forward_runner_failure (ABI4 result seam)
#include <yuzu/agent/subprocess_runner.hpp> // yuzu::agent::run_bounded_subprocess (arch-L1)
#endif

namespace {

// ── Input sanitization ────────────────────────────────────────────────────────

/**
 * Returns true if the character is safe for inclusion in a dialog title/
 * message/prompt. Blocks backticks, $, |, ;, &, <, >, (, ), {, }, [, ], \,
 * newlines, single quotes, double quotes, and other metacharacters.
 *
 * M13: Single and double quotes are blocked on macOS/Linux because
 * osascript's AppleScript fragments and PowerShell's `-Command` script embed
 * this text inside their own string literal syntax (`"..."`) — an
 * unescaped quote would break out of that literal into the surrounding
 * script, an AppleScript/PowerShell-syntax injection even though the outer
 * process spawn itself is clean argv with no shell involved. Allowing
 * quotes would enable exactly that break-out. On Windows notify/message_box,
 * native APIs (MessageBoxW, ShellNotifyIconW) are used so quotes are safe —
 * but we block them uniformly for defense-in-depth.
 */
bool is_safe_char(char c) {
    if (c >= 'a' && c <= 'z') return true;
    if (c >= 'A' && c <= 'Z') return true;
    if (c >= '0' && c <= '9') return true;
    // Safe punctuation: space, period, comma, hyphen, underscore, colon,
    // question mark, exclamation, slash, at, hash, percent, plus, equals.
    // Note: single quote and double quote are intentionally excluded (M13)
    // to prevent AppleScript/PowerShell string-literal injection into the
    // script fragments these values are embedded in.
    switch (c) {
    case ' ':  case '.':  case ',':  case '-':  case '_':
    case ':':  case '?':  case '!':  case '/':  case '@':
    case '#':  case '%':  case '+':  case '=':  case '\t':
        return true;
    default:
        return false;
    }
}

/**
 * Sanitize a string for safe inclusion in shell commands.
 * Replaces any unsafe character with an underscore.
 * Returns empty string if input is empty.
 */
std::string sanitize(std::string_view input) {
    std::string result{input};
    for (auto& c : result) {
        if (!is_safe_char(c)) {
            c = '_';
        }
    }
    return result;
}

/**
 * Validate that a required parameter is non-empty. Writes an error
 * to ctx and returns false if validation fails.
 */
bool require_param(yuzu::CommandContext& ctx, std::string_view value,
                   std::string_view param_name) {
    if (value.empty()) {
        ctx.write_output(std::format("status|error|missing required parameter: {}",
                                     param_name));
        return false;
    }
    return true;
}

#if defined(_WIN32)
// Same generous per-call wall-clock bound as kInteractionCmdDeadline below,
// for the single-field PowerShell InputBox site (input). Interactive and can
// legitimately block on a user, so this is deliberately long — it only fires
// on a genuinely wedged invocation.
constexpr std::chrono::seconds kInteractionCmdDeadlineWin{120};

// platform_survey builds ONE PowerShell script covering every question and
// issues a single bounded call for the whole form (unlike the POSIX legs,
// which loop and issue one osascript/zenity call PER question, so each
// question implicitly gets its own fresh deadline). A multi-question form
// can legitimately take a human several minutes combined to fill in, so this
// gets its own, longer bound rather than reusing kInteractionCmdDeadlineWin
// -- the pre-migration _popen call had no timeout at all here, so a bound
// this tight would be a newly-introduced usability regression for a
// legitimately slow-but-real multi-question response (Gate 4 finding F1).
constexpr std::chrono::seconds kInteractionSurveyCmdDeadlineWin{600};

// The stable, well-known location of Windows PowerShell 5.1 -- the only
// candidate probed (ADR-3002 "tool path probing"): probe_tool_path()
// verifies it exists and is executable at call time rather than assuming a
// hardcoded path is safe to exec unchecked.
constexpr const char* kPowerShellPath =
    "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
#endif

#if !defined(_WIN32)
// A generous per-call wall-clock bound for the interaction dialog spawns.
// osascript/zenity/notify-send calls are interactive and can legitimately
// block on a user, so this is deliberately long — it only fires on a
// genuinely wedged invocation.
constexpr std::chrono::seconds kInteractionCmdDeadline{120};

#if defined(__APPLE__)
// The stable, well-known location of osascript -- the only candidate probed
// (ADR-3002 "tool path probing"): probe_tool_path() verifies it exists and
// is executable at call time rather than assuming a hardcoded path is safe
// to exec unchecked.
constexpr const char* kOsascriptPath = "/usr/bin/osascript";
#elif defined(__linux__)
// zenity/notify-send ship at one of these paths across the mainstream
// Linux distros this agent targets.
const std::vector<std::string> kZenityPaths = {"/usr/bin/zenity", "/usr/local/bin/zenity"};
const std::vector<std::string> kNotifySendPaths = {"/usr/bin/notify-send",
                                                   "/usr/local/bin/notify-send"};

/**
 * Whether this process has a plausible GUI session to talk to. zenity fails
 * to connect ("Failed to open display", exit 1) when neither an X11 DISPLAY
 * nor a Wayland WAYLAND_DISPLAY is set -- the normal state for a headless
 * daemon, which is the ordinary deployment posture for a Linux Yuzu agent
 * (docs/agent-privilege-model.md). zenity's own exit-code contract cannot
 * distinguish that delivery failure from a real user decline -- `--info`
 * has no decline at all, so ANY nonzero exit there is a delivery failure
 * with no legitimate alternate reading, and `--question`/`--entry` collapse
 * a real Cancel/No onto the exact same exit code a display failure produces
 * (verified live: `DISPLAY= zenity --question/--info/--entry ...` -> exit 1,
 * "Failed to open display", indistinguishable from rc=1 on a real display).
 * Checking this UPFRONT, before ever spawning zenity, closes that honest-
 * status gap at its root instead of trying to infer it from an ambiguous
 * exit code after the fact.
 */
bool has_linux_display_session() {
    const char* display = std::getenv("DISPLAY");
    const char* wayland = std::getenv("WAYLAND_DISPLAY");
    return (display && *display) || (wayland && *wayland);
}
#endif

/**
 * Result of run_tool(): the captured output plus the process exit code,
 * from a single run_bounded_subprocess round trip.
 */
struct CommandResult {
    std::string output;
    int exit_code = -1;
    // Full runner result, kept alongside output/exit_code so a caller can
    // forward a genuine runner-level failure (spawn error/deadline/cancel/
    // signal death) through the ABI4 result seam (runner_status.hpp) before
    // ever trusting exit_code/output as a real dialog outcome -- see
    // classify_posix_capture in interaction_parsers.hpp.
    yuzu::agent::SubprocessResult res;
};

/**
 * Run a tool via clean argv through the bounded, fork-lock-covered,
 * CLOEXEC-pipe runner (arch-L1) -- no shell involved, so there is nothing to
 * quote or escape. `merge_stderr` folds the tool's stderr into `output`
 * (the old shell string's `2>&1`); the default (false) discards it, the
 * runner's native equivalent of the old `2>/dev/null`.
 *
 * Captures output and exit status in ONE invocation (unlike calling two
 * separate runner calls, which would run an interactive dialog -- e.g. an
 * osascript dialog -- twice), so a caller can tell "the tool ran and
 * produced this text" apart from "the tool failed" (non-zero exit, e.g. no
 * reachable GUI session for the daemon to display a dialog on) without a
 * second round trip.
 *
 * An empty argv[0] (a probe_tool_path miss) is rejected before ever
 * attempting an OS call, reporting the same shape run_bounded_subprocess
 * uses for its own runtime-reject (tool_ran=false) -- the same idiom
 * users_plugin.cpp's run_tool() uses.
 */
CommandResult run_tool(std::vector<std::string> argv, bool merge_stderr = false) {
    if (argv.empty() || argv.front().empty()) {
        return CommandResult{};
    }
    auto res = yuzu::agent::run_bounded_subprocess(
        argv, yuzu::agent::SubprocessOptions{.deadline = kInteractionCmdDeadline,
                                             .merge_stderr = merge_stderr});
    CommandResult result;
    result.output = res.output;
    result.exit_code = res.exit_code;
    while (!result.output.empty() &&
           (result.output.back() == '\n' || result.output.back() == '\r')) {
        result.output.pop_back();
    }
    result.res = std::move(res);
    return result;
}
#endif // !_WIN32

// ── Platform: notify ──────────────────────────────────────────────────────────

#ifdef _WIN32

int platform_notify(yuzu::CommandContext& ctx, const std::string& title,
                    const std::string& message, const std::string& type) {
    // Convert strings to wide
    // wide conversion via the shared win_str.hpp helper (#1681). NOTE: to_wide uses an
    // explicit length, so an embedded NUL in title/message is no longer truncated at
    // conversion -- safe here only because wtitle/wmessage are consumed via c_str() by
    // NUL-terminated Win32 APIs (MessageBoxW / Shell_NotifyIconW). A future length-aware
    // consumer of operator-supplied text would need to strip/reject embedded NULs first.
    using yuzu::win::to_wide;

    std::wstring wtitle = to_wide(title);
    std::wstring wmessage = to_wide(message);

    // Create a hidden window for the notification
    NOTIFYICONDATAW nid{};
    nid.cbSize = sizeof(nid);
    nid.hWnd = nullptr; // No window — use task tray
    nid.uID = 1;
    nid.uFlags = NIF_INFO | NIF_ICON | NIF_TIP;
    nid.dwInfoFlags = NIIF_NONE;

    // Map type to icon
    if (type == "warning") {
        nid.dwInfoFlags = NIIF_WARNING;
    } else if (type == "error") {
        nid.dwInfoFlags = NIIF_ERROR;
    } else {
        nid.dwInfoFlags = NIIF_INFO;
    }

    wcsncpy_s(nid.szInfoTitle, wtitle.c_str(), _TRUNCATE);
    wcsncpy_s(nid.szInfo, wmessage.c_str(), _TRUNCATE);
    wcsncpy_s(nid.szTip, L"Yuzu Agent", _TRUNCATE);

    // Load default application icon
    nid.hIcon = LoadIconW(nullptr, MAKEINTRESOURCEW(32516)); // IDI_INFORMATION

    Shell_NotifyIconW(NIM_ADD, &nid);
    Shell_NotifyIconW(NIM_MODIFY, &nid);

    // Brief sleep so the notification is visible, then clean up
    Sleep(100);
    Shell_NotifyIconW(NIM_DELETE, &nid);

    ctx.write_output("status|ok");
    return 0;
}

#elif defined(__APPLE__)

int platform_notify(yuzu::CommandContext& ctx, const std::string& title,
                    const std::string& message, const std::string& /*type*/) {
    std::string safe_title = sanitize(title);
    std::string safe_msg = sanitize(message);

    // sink: interaction/posix_osascript_notify#1 -- osascript given a
    // script fragment via -e; no shell is involved (ADR-3002 Decision 5:
    // rung-3 governed-interpreter site -- osascript is the deepest
    // interpreter intentionally invoked and sets the rung; the outer spawn
    // is argv-clean, not a Decision-7 shell exception -- see
    // docs/agent-spawn-sink-manifest.md).
    auto osascript_path = yuzu::agent::probe_tool_path({kOsascriptPath});
    auto result = run_tool(
        {osascript_path, "-e",
         std::format("display notification \"{}\" with title \"{}\"", safe_msg, safe_title)});

    if (result.exit_code == 0) {
        ctx.write_output("status|ok");
        return 0;
    }
    // Non-zero exit from osascript on a daemon most often means there is
    // no reachable GUI session to post the notification to. Report that
    // honestly rather than a bare "failed" (which reads like a bug in
    // this plugin rather than an environment limitation) — but still
    // return non-zero so the agent core records this command as a
    // terminal FAILURE rather than SUCCESS, since nothing was ever shown
    // to the user. forward_runner_failure is a no-op for a genuine
    // nonzero osascript exit (TerminationReason::exited) and only sets the
    // ABI4 typed status for an actual runner-level failure (spawn error,
    // deadline, signal death, or an empty probe_tool_path miss).
    yuzu::agent::forward_runner_failure(ctx, result.res);
    ctx.write_output("status|unavailable|no reachable GUI session");
    return 1;
}

#elif defined(__linux__)

int platform_notify(yuzu::CommandContext& ctx, const std::string& title,
                    const std::string& message, const std::string& type) {
    std::string safe_title = sanitize(title);
    std::string safe_msg = sanitize(message);

    // Map type to urgency
    std::string urgency = "normal";
    if (type == "error") urgency = "critical";
    else if (type == "warning") urgency = "normal";
    else urgency = "low";

    // sink: interaction/posix_notify_send#1 -- notify-send is a plain
    // binary with no interpreter role; clean argv, no shell (ADR-3002
    // Decision 1: rung-2 candidate).
    auto notify_send_path = yuzu::agent::probe_tool_path(kNotifySendPaths);
    // ADR-3002 Decision 6 argv hygiene: title/message are positional (no
    // preceding --summary/--body flag), so sanitize()'s allowed leading '-'
    // could otherwise be parsed as a notify-send option instead of data
    // (e.g. a title of "-i" reads as --icon) -- "--" ends option parsing.
    auto result = run_tool({notify_send_path, "-u", urgency, "--", safe_title, safe_msg});

    if (result.exit_code == 0) {
        ctx.write_output("status|ok");
        return 0;
    }
    // A consumer keying off the command's execution-level return code
    // (rather than parsing the status|error text) must not read a failed
    // notification as a successful command -- matches the macOS leg above.
    yuzu::agent::forward_runner_failure(ctx, result.res);
    ctx.write_output("status|error|notify-send not available or failed");
    return 1;
}

#else

int platform_notify(yuzu::CommandContext& ctx, const std::string& /*title*/,
                    const std::string& /*message*/, const std::string& /*type*/) {
    ctx.write_output("status|error|platform not supported");
    return 1;
}

#endif

// ── Platform: message_box ─────────────────────────────────────────────────────

#ifdef _WIN32

int platform_message_box(yuzu::CommandContext& ctx, const std::string& title,
                         const std::string& message, const std::string& buttons) {
    // wide conversion via the shared win_str.hpp helper (#1681). NOTE: to_wide uses an
    // explicit length, so an embedded NUL in title/message is no longer truncated at
    // conversion -- safe here only because wtitle/wmessage are consumed via c_str() by
    // NUL-terminated Win32 APIs (MessageBoxW / Shell_NotifyIconW). A future length-aware
    // consumer of operator-supplied text would need to strip/reject embedded NULs first.
    using yuzu::win::to_wide;

    UINT mb_type = MB_TOPMOST | MB_SETFOREGROUND;
    if (buttons == "okcancel") {
        mb_type |= MB_OKCANCEL;
    } else if (buttons == "yesno") {
        mb_type |= MB_YESNO;
    } else {
        mb_type |= MB_OK;
    }

    std::wstring wtitle = to_wide(title);
    std::wstring wmessage = to_wide(message);

    int result = MessageBoxW(nullptr, wmessage.c_str(), wtitle.c_str(), mb_type);

    switch (result) {
    case IDOK:     ctx.write_output("response|ok");     break;
    case IDCANCEL: ctx.write_output("response|cancel"); break;
    case IDYES:    ctx.write_output("response|yes");    break;
    case IDNO:     ctx.write_output("response|no");     break;
    default:       ctx.write_output("response|ok");     break;
    }
    return 0;
}

#elif defined(__APPLE__)

int platform_message_box(yuzu::CommandContext& ctx, const std::string& title,
                         const std::string& message, const std::string& buttons) {
    std::string safe_title = sanitize(title);
    std::string safe_msg = sanitize(message);

    std::string btn_spec;
    if (buttons == "yesno") {
        btn_spec = "buttons {\"No\", \"Yes\"} default button \"Yes\"";
    } else if (buttons == "okcancel") {
        btn_spec = "buttons {\"Cancel\", \"OK\"} default button \"OK\"";
    } else {
        btn_spec = "buttons {\"OK\"} default button \"OK\"";
    }

    // Wrap the dialog in try/on-error and return a sentinel so an unreachable
    // display server (this agent is a root LaunchDaemon with no Aqua/GUI
    // session — see docs/agent-privilege-model.md) is reported honestly as
    // not_reachable instead of a false button. The bare substring match this
    // replaced fell through to "response|ok" for ANY unrecognised output,
    // claiming the user clicked OK on a dialog that was never shown. The
    // try/on-error idiom mirrors platform_input; capturing the error NUMBER
    // keeps a genuine user-cancel (-128) distinct from an undeliverable
    // session.
    //
    // sink: interaction/posix_osascript_message_box#1 -- osascript given a
    // multi-statement script via -e flags, clean argv, no shell (ADR-3002
    // Decision 5: rung-3 governed-interpreter site -- osascript is the
    // deepest interpreter intentionally invoked and sets the rung; the
    // outer spawn is argv-clean). safe_msg/safe_title are already
    // sanitize()d (unsafe chars replaced with '_'); btn_spec and every
    // sentinel/-e fragment are fixed compile-time literals — no
    // operator-supplied text controls the argv's shape.
    auto osascript_path = yuzu::agent::probe_tool_path({kOsascriptPath});
    std::vector<std::string> argv = {osascript_path};
    auto dialog_argv = yuzu::interaction::build_dialog_argv(safe_title, safe_msg, btn_spec);
    argv.insert(argv.end(), dialog_argv.begin(), dialog_argv.end());
    auto result = run_tool(argv, /*merge_stderr=*/true);

    switch (yuzu::interaction::parse_dialog_result(result.output)) {
    case yuzu::interaction::DialogOutcome::ok:
        ctx.write_output("response|ok");
        break;
    case yuzu::interaction::DialogOutcome::cancel:
        ctx.write_output("response|cancel");
        break;
    case yuzu::interaction::DialogOutcome::yes:
        ctx.write_output("response|yes");
        break;
    case yuzu::interaction::DialogOutcome::no:
        ctx.write_output("response|no");
        break;
    case yuzu::interaction::DialogOutcome::not_reachable:
        // No GUI session / TCC denial / osascript failure — honest status,
        // never a fabricated button. forward_runner_failure is a no-op for
        // a genuine AppleScript-level error (TerminationReason::exited,
        // e.g. a real non-(-128) osascript error number) and only sets the
        // ABI4 typed status for an actual runner-level failure. Rides the
        // new `status` result column AND returns terminal FAILURE so a
        // generic success/failure consumer (the executions drawer, retry/
        // automation logic) does not read a dialog that was never shown as
        // SUCCESS. This matches the sibling actions notify/input/survey,
        // which already return 1 for the identical undeliverable-session
        // condition.
        yuzu::agent::forward_runner_failure(ctx, result.res);
        ctx.write_output("status|not_reachable");
        return 1;
    }
    return 0;
}

#elif defined(__linux__)

int platform_message_box(yuzu::CommandContext& ctx, const std::string& title,
                         const std::string& message, const std::string& buttons) {
    if (!has_linux_display_session()) {
        // Closes the round-2 review blocker at its root: zenity's own exit
        // code cannot distinguish "no display" from a real button press
        // (--info has no legitimate nonzero reading at all), so check
        // upfront rather than spawn and guess.
        ctx.write_output("status|unavailable|no reachable GUI session");
        return 1;
    }

    std::string safe_title = sanitize(title);
    std::string safe_msg = sanitize(message);
    auto zenity_path = yuzu::agent::probe_tool_path(kZenityPaths);

    // sink: interaction/posix_zenity_message_box#1 -- zenity is a plain
    // binary with no interpreter role; clean argv, no shell (ADR-3002
    // Decision 1: rung-2 candidate).
    if (buttons == "yesno") {
        auto result = run_tool({zenity_path, "--question", "--title", safe_title, "--text",
                                safe_msg});
        // zenity's own contract: 0=Yes, 1=No, 5=timeout/ESC. -1 is the
        // runner's documented sentinel for a genuine spawn error/deadline/
        // signal death -- never to be misread as the user clicking No, the
        // same honest-status gap already closed on the input/survey legs.
        if (result.exit_code == -1) {
            yuzu::agent::forward_runner_failure(ctx, result.res);
            ctx.write_output("status|unavailable|zenity dialog failed to complete");
            return 1;
        }
        ctx.write_output(result.exit_code == 0 ? "response|yes" : "response|no");
    } else if (buttons == "okcancel") {
        auto result = run_tool({zenity_path, "--question", "--title", safe_title, "--text",
                                safe_msg, "--ok-label", "OK", "--cancel-label", "Cancel"});
        if (result.exit_code == -1) {
            yuzu::agent::forward_runner_failure(ctx, result.res);
            ctx.write_output("status|unavailable|zenity dialog failed to complete");
            return 1;
        }
        ctx.write_output(result.exit_code == 0 ? "response|ok" : "response|cancel");
    } else {
        auto result = run_tool({zenity_path, "--info", "--title", safe_title, "--text",
                                safe_msg});
        if (result.exit_code == -1) {
            yuzu::agent::forward_runner_failure(ctx, result.res);
            ctx.write_output("status|unavailable|zenity dialog failed to complete");
            return 1;
        }
        // `--info` has no button to decline -- there is no legitimate
        // reading of a nonzero exit here other than a delivery failure
        // (e.g. a DISPLAY that is set but stale/unreachable, since the
        // has_linux_display_session() check above only catches the unset
        // case). Never fabricate response|ok on a dialog that may never
        // have been shown.
        if (result.exit_code != 0) {
            ctx.write_output("status|unavailable|zenity dialog did not complete");
            return 1;
        }
        ctx.write_output("response|ok");
    }
    return 0;
}

#else

int platform_message_box(yuzu::CommandContext& ctx, const std::string& /*title*/,
                         const std::string& /*message*/, const std::string& /*buttons*/) {
    ctx.write_output("status|error|platform not supported");
    return 1;
}

#endif

// ── Platform: input ───────────────────────────────────────────────────────────

#ifdef _WIN32

int platform_input(yuzu::CommandContext& ctx, const std::string& title,
                   const std::string& prompt, const std::string& default_value) {
    // Use PowerShell to show an InputBox dialog via VB interaction
    std::string safe_title = sanitize(title);
    std::string safe_prompt = sanitize(prompt);
    std::string safe_default = sanitize(default_value);

    // PowerShell script using .NET VisualBasic.Interaction (available on all Windows)
    std::string ps_script = std::format(
        "Add-Type -AssemblyName Microsoft.VisualBasic; "
        "$result = [Microsoft.VisualBasic.Interaction]::InputBox('{}', '{}', '{}'); "
        "if ($result -eq $null -or $result -eq '') {{ Write-Output '##CANCELLED##' }} "
        "else {{ Write-Output $result }}",
        safe_prompt, safe_title, safe_default);

    // interaction/input_windows#1 -- clean argv via the bounded runner instead
    // of a raw _popen shell string; the script text itself remains a single
    // argv element PowerShell interprets (ADR-3002 Decision 5: the outer
    // invocation is now argv-clean, but the deepest interpreter intentionally
    // invoked -- PowerShell -- still sets the rung, rung 3, same as before).
    auto ps_path = yuzu::agent::probe_tool_path({kPowerShellPath});
    if (ps_path.empty()) {
        ctx.write_output("status|error|failed to launch PowerShell");
        return 1;
    }

    auto res = yuzu::agent::run_bounded_subprocess(
        {ps_path, "-NoProfile", "-NonInteractive", "-Command", ps_script},
        yuzu::agent::SubprocessOptions{.deadline = kInteractionCmdDeadlineWin});

    // Consolidated runner-failure/exit-code decision (classify_windows_dialog_
    // capture, unit-tested): a killed-at-deadline dialog can still have
    // tool_ran=true with empty or partial output (subprocess_runner.hpp's
    // documented contract) -- without the timed_out check, empty output falls
    // through to the "cancelled" branch below and silently misreports a
    // timeout as a user cancel. The exit_code check closes the remaining gap:
    // a ShowDialog()/InputBox() exception under a non-interactive session
    // exits nonzero with empty output (its error text never reaches `output`
    // -- merge_stderr defaults false), which previously fell through to
    // "cancelled|true" as a fabricated user outcome. None of these three
    // cases may be reinterpreted as a real dialog response, matching
    // classify_input_capture's macOS/Linux contract.
    auto decision = yuzu::interaction::classify_windows_dialog_capture(
        res.tool_ran, res.timed_out, res.exit_code);
    if (decision.is_failure) {
        yuzu::agent::forward_runner_failure(ctx, res);
        ctx.write_output(decision.output_line);
        return decision.rc;
    }

    std::string output = std::move(res.output);
    // Trim trailing whitespace
    while (!output.empty() && (output.back() == '\n' || output.back() == '\r' ||
                                output.back() == ' ')) {
        output.pop_back();
    }

    if (output == "##CANCELLED##" || output.empty()) {
        ctx.write_output("cancelled|true");
    } else {
        ctx.write_output(std::format("response|{}", output));
    }
    return 0;
}

#elif defined(__APPLE__)

int platform_input(yuzu::CommandContext& ctx, const std::string& title,
                   const std::string& prompt, const std::string& default_value) {
    std::string safe_title = sanitize(title);
    std::string safe_prompt = sanitize(prompt);
    std::string safe_default = sanitize(default_value);

    // "on error number err_num" + re-raising every code other than -128
    // (the AppleScript "User canceled" error) ensures only a genuine Cancel
    // click is converted to the "##CANCELLED##" sentinel at exit 0; any
    // other failure (e.g. no reachable GUI session) propagates as a
    // non-zero osascript exit so it is never misreported as cancellation.
    //
    // sink: interaction/posix_osascript_input#1 -- osascript given a
    // multi-statement script via -e flags, clean argv, no shell (ADR-3002
    // Decision 5: rung-3 governed-interpreter site -- osascript is the
    // deepest interpreter intentionally invoked and sets the rung; the
    // outer spawn is argv-clean).
    auto osascript_path = yuzu::agent::probe_tool_path({kOsascriptPath});
    std::vector<std::string> argv = {
        osascript_path, "-e", "try",
        "-e",
        std::format("set result to text returned of (display dialog \"{}\" with title \"{}\" "
                    "default answer \"{}\")",
                    safe_prompt, safe_title, safe_default),
        "-e", "return result",
        "-e", "on error number err_num",
        "-e", "if err_num is -128 then return \"##CANCELLED##\"",
        "-e", "error number err_num",
        "-e", "end try",
    };
    auto result = run_tool(argv, /*merge_stderr=*/true);

    // The exit-code/output decision is the pure classify_input_capture (qe-L2,
    // unit-tested): a non-zero exit is a delivery failure reported as an honest
    // status|unavailable (never the error text wrapped as a response), the
    // ##CANCELLED## sentinel is a user cancel, everything else is real input.
    auto decision = yuzu::interaction::classify_input_capture(result.exit_code, result.output);
    if (decision.rc != 0) {
        // No-op for a genuine AppleScript-level error (TerminationReason::
        // exited); sets the ABI4 typed status only for an actual
        // runner-level failure, so a wedged/missing osascript is
        // distinguishable on the wire from an honest no-GUI-session exit.
        yuzu::agent::forward_runner_failure(ctx, result.res);
    }
    ctx.write_output(decision.output_line);
    return decision.rc;
}

#elif defined(__linux__)

int platform_input(yuzu::CommandContext& ctx, const std::string& title,
                   const std::string& prompt, const std::string& default_value) {
    if (!has_linux_display_session()) {
        ctx.write_output("status|unavailable|no reachable GUI session");
        return 1;
    }

    std::string safe_title = sanitize(title);
    std::string safe_prompt = sanitize(prompt);
    std::string safe_default = sanitize(default_value);

    // sink: interaction/posix_zenity_input#1 -- zenity is a plain binary
    // with no interpreter role; clean argv, no shell (ADR-3002 Decision 1:
    // rung-2 candidate).
    auto zenity_path = yuzu::agent::probe_tool_path(kZenityPaths);
    auto result = run_tool({zenity_path, "--entry", "--title", safe_title, "--text", safe_prompt,
                            "--entry-text", safe_default});

    switch (yuzu::interaction::classify_posix_capture(result.exit_code)) {
    case yuzu::interaction::PosixCaptureOutcome::runner_failure:
        // exit_code == -1: the runner itself never produced a real zenity
        // exit status (spawn error, deadline, or signal death) -- report it
        // honestly instead of misreading it as the user clicking Cancel.
        yuzu::agent::forward_runner_failure(ctx, result.res);
        ctx.write_output("status|unavailable|zenity dialog failed to complete");
        return 1;
    case yuzu::interaction::PosixCaptureOutcome::cancelled:
        // zenity's own contract: a real nonzero exit here is Cancel/dismiss.
        ctx.write_output("cancelled|true");
        break;
    case yuzu::interaction::PosixCaptureOutcome::real_output:
        ctx.write_output(std::format("response|{}", result.output));
        break;
    }
    return 0;
}

#else

int platform_input(yuzu::CommandContext& ctx, const std::string& /*title*/,
                   const std::string& /*prompt*/, const std::string& /*default_value*/) {
    ctx.write_output("status|error|platform not supported");
    return 1;
}

#endif

// ── Survey question types ─────────────────────────────────────────────────────

struct SurveyQuestion {
    std::string prompt;
    std::string type;  // "text", "yesno", "choice"
    std::vector<std::string> choices;
};

/**
 * Parse the questions JSON parameter.
 * Expected format: [{prompt:"...", type:"text|yesno|choice", choices:[...]}]
 *
 * Uses minimal manual parsing to avoid adding nlohmann_json as a plugin
 * dependency. The questions JSON is validated server-side before dispatch.
 */
std::vector<SurveyQuestion> parse_questions_json(std::string_view json) {
    std::vector<SurveyQuestion> result;
    // Minimal JSON array-of-objects parser
    // Find each {...} block inside the outer [...]
    size_t pos = json.find('[');
    if (pos == std::string_view::npos) return result;

    while (pos < json.size()) {
        auto obj_start = json.find('{', pos);
        if (obj_start == std::string_view::npos) break;
        auto obj_end = json.find('}', obj_start);
        if (obj_end == std::string_view::npos) break;

        auto obj = json.substr(obj_start, obj_end - obj_start + 1);
        SurveyQuestion q;

        // Extract "prompt":"..."
        auto extract_str = [&](std::string_view key) -> std::string {
            auto kpos = obj.find(key);
            if (kpos == std::string_view::npos) return {};
            auto colon = obj.find(':', kpos + key.size());
            if (colon == std::string_view::npos) return {};
            auto qstart = obj.find('"', colon + 1);
            if (qstart == std::string_view::npos) return {};
            auto qend = obj.find('"', qstart + 1);
            if (qend == std::string_view::npos) return {};
            return std::string{obj.substr(qstart + 1, qend - qstart - 1)};
        };

        q.prompt = extract_str("\"prompt\"");
        q.type = extract_str("\"type\"");
        if (q.type.empty()) q.type = "text";

        // Extract choices array if present
        if (q.type == "choice") {
            auto carr = obj.find("\"choices\"");
            if (carr != std::string_view::npos) {
                auto arr_start = obj.find('[', carr);
                auto arr_end = obj.find(']', arr_start);
                if (arr_start != std::string_view::npos && arr_end != std::string_view::npos) {
                    auto arr = obj.substr(arr_start, arr_end - arr_start + 1);
                    size_t cpos = 0;
                    while (cpos < arr.size()) {
                        auto cs = arr.find('"', cpos);
                        if (cs == std::string_view::npos) break;
                        auto ce = arr.find('"', cs + 1);
                        if (ce == std::string_view::npos) break;
                        q.choices.emplace_back(arr.substr(cs + 1, ce - cs - 1));
                        cpos = ce + 1;
                    }
                }
            }
        }

        if (!q.prompt.empty())
            result.push_back(std::move(q));

        pos = obj_end + 1;
    }
    return result;
}

// ── Platform: survey ──────────────────────────────────────────────────────────

#ifdef _WIN32

int platform_survey(yuzu::CommandContext& ctx, const std::string& title,
                    const std::vector<SurveyQuestion>& questions) {
    // Build a PowerShell script that creates a Windows.Forms dialog
    std::string ps;
    ps += "Add-Type -AssemblyName System.Windows.Forms; ";
    ps += "$form = New-Object System.Windows.Forms.Form; ";
    ps += std::format("$form.Text = '{}'; ", sanitize(title));
    ps += "$form.Width = 450; $form.StartPosition = 'CenterScreen'; ";
    ps += "$form.AutoSize = $true; $form.AutoSizeMode = 'GrowOnly'; ";
    ps += "$form.FormBorderStyle = 'FixedDialog'; $form.MaximizeBox = $false; ";
    ps += "$y = 10; $controls = @(); ";

    for (size_t i = 0; i < questions.size(); ++i) {
        const auto& q = questions[i];
        std::string safe_prompt = sanitize(q.prompt);
        std::string idx = std::to_string(i);

        // Label
        ps += std::format(
            "$lbl{} = New-Object System.Windows.Forms.Label; "
            "$lbl{}.Text = '{}'; $lbl{}.Location = New-Object System.Drawing.Point(10,$y); "
            "$lbl{}.AutoSize = $true; $form.Controls.Add($lbl{}); $y += 22; ",
            idx, idx, safe_prompt, idx, idx, idx);

        if (q.type == "yesno") {
            ps += std::format(
                "$cb{} = New-Object System.Windows.Forms.CheckBox; "
                "$cb{}.Text = 'Yes'; $cb{}.Location = New-Object System.Drawing.Point(10,$y); "
                "$form.Controls.Add($cb{}); $controls += $cb{}; $y += 30; ",
                idx, idx, idx, idx, idx);
        } else if (q.type == "choice" && !q.choices.empty()) {
            ps += std::format(
                "$cmb{} = New-Object System.Windows.Forms.ComboBox; "
                "$cmb{}.DropDownStyle = 'DropDownList'; "
                "$cmb{}.Location = New-Object System.Drawing.Point(10,$y); "
                "$cmb{}.Width = 400; ",
                idx, idx, idx, idx);
            for (const auto& ch : q.choices) {
                ps += std::format("$cmb{}.Items.Add('{}') | Out-Null; ", idx, sanitize(ch));
            }
            ps += std::format(
                "if($cmb{}.Items.Count -gt 0){{ $cmb{}.SelectedIndex = 0 }}; "
                "$form.Controls.Add($cmb{}); $controls += $cmb{}; $y += 30; ",
                idx, idx, idx, idx);
        } else {
            // text
            ps += std::format(
                "$txt{} = New-Object System.Windows.Forms.TextBox; "
                "$txt{}.Location = New-Object System.Drawing.Point(10,$y); "
                "$txt{}.Width = 400; "
                "$form.Controls.Add($txt{}); $controls += $txt{}; $y += 30; ",
                idx, idx, idx, idx, idx);
        }
    }

    // OK/Cancel buttons
    ps += "$y += 10; ";
    ps += "$ok = New-Object System.Windows.Forms.Button; $ok.Text = 'OK'; ";
    ps += "$ok.Location = New-Object System.Drawing.Point(250,$y); ";
    ps += "$ok.DialogResult = [System.Windows.Forms.DialogResult]::OK; ";
    ps += "$form.Controls.Add($ok); $form.AcceptButton = $ok; ";
    ps += "$cancel = New-Object System.Windows.Forms.Button; $cancel.Text = 'Cancel'; ";
    ps += "$cancel.Location = New-Object System.Drawing.Point(340,$y); ";
    ps += "$cancel.DialogResult = [System.Windows.Forms.DialogResult]::Cancel; ";
    ps += "$form.Controls.Add($cancel); $form.CancelButton = $cancel; ";
    ps += "$form.TopMost = $true; ";
    ps += "$result = $form.ShowDialog(); ";
    ps += "if($result -eq [System.Windows.Forms.DialogResult]::Cancel){ ";
    ps += "  Write-Output '##CANCELLED##'; exit; } ";

    // Collect results
    ps += "foreach($c in $controls){ ";
    ps += "  if($c -is [System.Windows.Forms.CheckBox]){ ";
    ps += "    if($c.Checked){ Write-Output 'yes' } else { Write-Output 'no' } ";
    ps += "  } elseif($c -is [System.Windows.Forms.ComboBox]){ ";
    ps += "    Write-Output $c.SelectedItem ";
    ps += "  } else { Write-Output $c.Text } ";
    ps += "} ";

    // interaction/survey_windows#1 -- clean argv via the bounded runner
    // instead of a raw _popen shell string; the script text itself remains a
    // single argv element PowerShell interprets (ADR-3002 Decision 5: the
    // outer invocation is now argv-clean, but the deepest interpreter
    // intentionally invoked -- PowerShell -- still sets the rung, rung 3,
    // same as before).
    auto ps_path = yuzu::agent::probe_tool_path({kPowerShellPath});
    if (ps_path.empty()) {
        ctx.write_output("status|error|failed to launch PowerShell");
        return 1;
    }

    auto res = yuzu::agent::run_bounded_subprocess(
        {ps_path, "-NoProfile", "-NonInteractive", "-Command", ps},
        yuzu::agent::SubprocessOptions{.deadline = kInteractionSurveyCmdDeadlineWin});

    // Consolidated runner-failure/exit-code decision (classify_windows_dialog_
    // capture, unit-tested): a killed-at-deadline dialog can still have
    // tool_ran=true with empty or partial output (subprocess_runner.hpp's
    // documented contract). Without the timed_out check, empty output falls
    // through to the answer-parse loop below and reports "cancelled|false" +
    // "question_count|N" with zero answer_ lines -- reading to a caller as
    // "survey completed, nothing answered" rather than the honest truth that
    // the dialog never delivered a result. The exit_code check closes the
    // remaining gap: a WinForms exception under a non-interactive session
    // (tool_ran=true, not timed out, nonzero exit, empty output) previously
    // hit that same fabricated-completion branch.
    auto decision = yuzu::interaction::classify_windows_dialog_capture(
        res.tool_ran, res.timed_out, res.exit_code);
    if (decision.is_failure) {
        yuzu::agent::forward_runner_failure(ctx, res);
        ctx.write_output(decision.output_line);
        return decision.rc;
    }

    std::string output = std::move(res.output);
    // Trim trailing whitespace
    while (!output.empty() && (output.back() == '\n' || output.back() == '\r' ||
                                output.back() == ' ')) {
        output.pop_back();
    }

    if (output == "##CANCELLED##") {
        ctx.write_output("cancelled|true");
        return 0;
    }

    // Parse line-by-line responses
    ctx.write_output("cancelled|false");
    std::istringstream iss(output);
    std::string line;
    size_t qi = 0;
    while (std::getline(iss, line) && qi < questions.size()) {
        while (!line.empty() && (line.back() == '\r' || line.back() == '\n'))
            line.pop_back();
        ctx.write_output(std::format("answer_{}|{}", qi, line));
        ++qi;
    }
    ctx.write_output(std::format("question_count|{}", questions.size()));
    return 0;
}

#elif defined(__APPLE__)

int platform_survey(yuzu::CommandContext& ctx, const std::string& title,
                    const std::vector<SurveyQuestion>& questions) {
    // macOS: sequential osascript dialogs for each question. "cancelled|false"
    // is emitted only after every question below has succeeded (see the tail
    // of this function) — emitting it up front here would contradict a later
    // "status|unavailable" or "cancelled|true" for the very same survey.
    auto osascript_path = yuzu::agent::probe_tool_path({kOsascriptPath});

    for (size_t i = 0; i < questions.size(); ++i) {
        const auto& q = questions[i];
        std::string safe_prompt = sanitize(q.prompt);
        std::string safe_title = sanitize(title);

        if (q.type == "yesno") {
            // sink: interaction/posix_osascript_survey_yesno#1 -- osascript
            // given a multi-statement script via -e flags, clean argv, no
            // shell (ADR-3002 Decision 5: rung-3 governed-interpreter
            // site -- osascript is the deepest interpreter intentionally
            // invoked and sets the rung; the outer spawn is argv-clean).
            std::vector<std::string> argv = {
                osascript_path, "-e", "try",
                "-e",
                std::format("set r to button returned of (display dialog \"{}\" with title "
                            "\"{}\" buttons {{\"No\", \"Yes\"}} default button \"Yes\")",
                            safe_prompt, safe_title),
                "-e", "return r",
                "-e", "on error number err_num",
                "-e", "if err_num is -128 then return \"##CANCELLED##\"",
                "-e", "error number err_num",
                "-e", "end try",
            };
            auto result = run_tool(argv, /*merge_stderr=*/true);
            if (result.exit_code != 0) {
                // osascript failed outright (not the AppleScript-level "on
                // error", which exits 0) — no reachable GUI session. Stop
                // the survey rather than fabricate an answer. Non-zero
                // return so the agent core records this command as a
                // terminal FAILURE rather than SUCCESS.
                yuzu::agent::forward_runner_failure(ctx, result.res);
                ctx.write_output("status|unavailable|no reachable GUI session");
                return 1;
            }
            if (result.output == "##CANCELLED##") {
                ctx.write_output("cancelled|true");
                return 0;
            }
            // The AppleScript's button set is exactly {"No", "Yes"}, so a
            // successful invocation should return exactly one of those two
            // labels. Match exactly rather than by substring — anything
            // else is unrecognized output, not a "no" answer, so it is
            // reported honestly (non-zero) instead of fabricated.
            if (result.output == "Yes") {
                ctx.write_output(std::format("answer_{}|yes", i));
            } else if (result.output == "No") {
                ctx.write_output(std::format("answer_{}|no", i));
            } else {
                ctx.write_output("status|unavailable|unrecognized osascript response");
                return 1;
            }

        } else if (q.type == "choice" && !q.choices.empty()) {
            // Build AppleScript choose from list
            std::string items;
            std::vector<std::string> safe_choices;
            safe_choices.reserve(q.choices.size());
            for (size_t ci = 0; ci < q.choices.size(); ++ci) {
                if (ci > 0) items += ", ";
                safe_choices.push_back(sanitize(q.choices[ci]));
                items += "\"" + safe_choices.back() + "\"";
            }
            // sink: interaction/posix_osascript_survey_choice#1 -- osascript
            // given a multi-statement script via -e flags, clean argv, no
            // shell (ADR-3002 Decision 5: rung-3 governed-interpreter
            // site -- osascript is the deepest interpreter intentionally
            // invoked and sets the rung; the outer spawn is argv-clean).
            std::vector<std::string> argv = {
                osascript_path, "-e", "try",
                "-e",
                "set r to choose from list {" + items + "} with title \"" + safe_title +
                    "\" with prompt \"" + safe_prompt + "\"",
                "-e", "if r is false then",
                "-e", "return \"##CANCELLED##\"",
                "-e", "else",
                "-e", "return item 1 of r",
                "-e", "end if",
                "-e", "on error number err_num",
                "-e", "if err_num is -128 then return \"##CANCELLED##\"",
                "-e", "error number err_num",
                "-e", "end try",
            };
            auto result = run_tool(argv, /*merge_stderr=*/true);
            if (result.exit_code != 0) {
                // Non-zero return so the agent core records this command
                // as a terminal FAILURE rather than SUCCESS.
                yuzu::agent::forward_runner_failure(ctx, result.res);
                ctx.write_output("status|unavailable|no reachable GUI session");
                return 1;
            }
            if (result.output == "##CANCELLED##") {
                ctx.write_output("cancelled|true");
                return 0;
            }
            // "choose from list" can only return an item from the list we
            // supplied. Confirm the output matches one of the sanitized
            // choices we offered rather than trusting it blindly — output
            // that matches none of them is unrecognized, not a genuine
            // selection, so it is reported honestly (non-zero) instead of
            // fabricated.
            bool recognized = std::find(safe_choices.begin(), safe_choices.end(),
                                        result.output) != safe_choices.end();
            if (!recognized) {
                ctx.write_output("status|unavailable|unrecognized osascript response");
                return 1;
            }
            ctx.write_output(std::format("answer_{}|{}", i, result.output));

        } else {
            // text input
            // sink: interaction/posix_osascript_survey_text#1 -- osascript
            // given a multi-statement script via -e flags, clean argv, no
            // shell (ADR-3002 Decision 5: rung-3 governed-interpreter
            // site -- osascript is the deepest interpreter intentionally
            // invoked and sets the rung; the outer spawn is argv-clean).
            std::vector<std::string> argv = {
                osascript_path, "-e", "try",
                "-e",
                std::format("set r to text returned of (display dialog \"{}\" with title \"{}\" "
                            "default answer \"\")",
                            safe_prompt, safe_title),
                "-e", "return r",
                "-e", "on error number err_num",
                "-e", "if err_num is -128 then return \"##CANCELLED##\"",
                "-e", "error number err_num",
                "-e", "end try",
            };
            auto result = run_tool(argv, /*merge_stderr=*/true);
            if (result.exit_code != 0) {
                // Non-zero return so the agent core records this command
                // as a terminal FAILURE rather than SUCCESS.
                yuzu::agent::forward_runner_failure(ctx, result.res);
                ctx.write_output("status|unavailable|no reachable GUI session");
                return 1;
            }
            if (result.output == "##CANCELLED##") {
                ctx.write_output("cancelled|true");
                return 0;
            }
            ctx.write_output(std::format("answer_{}|{}", i, result.output));
        }
    }
    // All questions completed without failure or cancellation — only now is
    // it accurate to report the survey as not cancelled.
    ctx.write_output("cancelled|false");
    ctx.write_output(std::format("question_count|{}", questions.size()));
    return 0;
}

#elif defined(__linux__)

int platform_survey(yuzu::CommandContext& ctx, const std::string& title,
                    const std::vector<SurveyQuestion>& questions) {
    // Linux: sequential zenity dialogs for each question. "cancelled|false"
    // is emitted only after every question below has succeeded (see the tail
    // of this function) — matching macOS/Windows; emitting it up front here
    // would contradict a later "status|unavailable" or "cancelled|true" for
    // the very same survey.
    if (!has_linux_display_session()) {
        ctx.write_output("status|unavailable|no reachable GUI session");
        return 1;
    }

    auto zenity_path = yuzu::agent::probe_tool_path(kZenityPaths);

    for (size_t i = 0; i < questions.size(); ++i) {
        const auto& q = questions[i];
        std::string safe_prompt = sanitize(q.prompt);
        std::string safe_title = sanitize(title);

        if (q.type == "yesno") {
            // sink: interaction/posix_zenity_survey_yesno#1 -- zenity is a
            // plain binary with no interpreter role; clean argv, no shell
            // (ADR-3002 Decision 1: rung-2 candidate).
            //
            // Not classify_posix_capture: zenity's yesno leg has a genuine
            // three-way exit-code contract (0=Yes, 1=No, 5=timeout/ESC) that
            // classifier's two-way real_output/cancelled split would collapse
            // (a real "No" click, rc=1, would misclassify as "cancelled").
            // The runner-failure sentinel is still checked explicitly first
            // -- without it, a genuine spawn/deadline failure (exit_code=-1)
            // fell into the rc!=0 branch and reported a fabricated "no" (the
            // same honest-status gap this PR closes on the sibling
            // choice/text legs below).
            auto result = run_tool({zenity_path, "--question", "--title", safe_title, "--text",
                                    safe_prompt});
            if (result.exit_code == -1) {
                yuzu::agent::forward_runner_failure(ctx, result.res);
                ctx.write_output("status|unavailable|zenity dialog failed to complete");
                return 1;
            }
            if (result.exit_code == 5) { // zenity returns 5 for timeout/ESC
                ctx.write_output("cancelled|true");
                return 0;
            }
            ctx.write_output(std::format("answer_{}|{}", i, result.exit_code == 0 ? "yes" : "no"));

        } else if (q.type == "choice" && !q.choices.empty()) {
            // sink: interaction/posix_zenity_survey_choice#1 -- zenity is a
            // plain binary with no interpreter role; clean argv, no shell
            // (ADR-3002 Decision 1: rung-2 candidate). Each choice is its own
            // trailing positional argv element (zenity --list's own contract)
            // rather than a space-joined, individually-quoted shell string.
            std::vector<std::string> argv = {zenity_path,  "--list", "--title",
                                             safe_title,   "--text", safe_prompt,
                                             "--column=Option"};
            // ADR-3002 Decision 6 argv hygiene: the choices are trailing
            // positional argv elements with no preceding flag, so a choice
            // starting with '-' (sanitize() allows a leading hyphen) could
            // otherwise be parsed as a zenity option instead of a list item
            // (e.g. "-timeout" -> "This option is not available") -- "--"
            // ends option parsing before the first positional element.
            argv.push_back("--");
            for (const auto& ch : q.choices) {
                argv.push_back(sanitize(ch));
            }
            auto result = run_tool(argv);

            switch (yuzu::interaction::classify_posix_capture(result.exit_code)) {
            case yuzu::interaction::PosixCaptureOutcome::runner_failure:
                yuzu::agent::forward_runner_failure(ctx, result.res);
                ctx.write_output("status|unavailable|zenity dialog failed to complete");
                return 1;
            case yuzu::interaction::PosixCaptureOutcome::cancelled:
                ctx.write_output("cancelled|true");
                return 0;
            case yuzu::interaction::PosixCaptureOutcome::real_output:
                ctx.write_output(std::format("answer_{}|{}", i, result.output));
                break;
            }

        } else {
            // text entry
            // sink: interaction/posix_zenity_survey_text#1 -- zenity is a
            // plain binary with no interpreter role; clean argv, no shell
            // (ADR-3002 Decision 1: rung-2 candidate).
            auto result = run_tool({zenity_path, "--entry", "--title", safe_title, "--text",
                                    safe_prompt});

            switch (yuzu::interaction::classify_posix_capture(result.exit_code)) {
            case yuzu::interaction::PosixCaptureOutcome::runner_failure:
                yuzu::agent::forward_runner_failure(ctx, result.res);
                ctx.write_output("status|unavailable|zenity dialog failed to complete");
                return 1;
            case yuzu::interaction::PosixCaptureOutcome::cancelled:
                ctx.write_output("cancelled|true");
                return 0;
            case yuzu::interaction::PosixCaptureOutcome::real_output:
                ctx.write_output(std::format("answer_{}|{}", i, result.output));
                break;
            }
        }
    }
    // All questions completed without failure or cancellation — only now is
    // it accurate to report the survey as not cancelled.
    ctx.write_output("cancelled|false");
    ctx.write_output(std::format("question_count|{}", questions.size()));
    return 0;
}

#else

int platform_survey(yuzu::CommandContext& ctx, const std::string& /*title*/,
                    const std::vector<SurveyQuestion>& /*questions*/) {
    ctx.write_output("status|error|platform not supported");
    return 1;
}

#endif

// ── ABI4 capability declarations (#2204) ────────────────────────────────────
//
// Per-OS rung split (docs/agent-spawn-sink-manifest.md is the authoritative
// evidence ledger; this table must stay consistent with it):
// linux: notify/message_box/input/survey spawn notify-send/zenity via clean
// argv through run_bounded_subprocess -- rung 2 (plain binaries, no
// interpreter role; ADR-3002 Decision 1). has_linux_display_session() checks
// DISPLAY/WAYLAND_DISPLAY upfront before ever spawning, but that is a
// runtime honest-degrade path, not a change to the platform's rung.
// macos: the same four actions spawn osascript via its own multi-`-e` argv
// form -- rung 3 (ADR-3002 Decision 5: osascript is the deepest interpreter
// intentionally invoked and sets the rung, even though the outer spawn is
// argv-clean). macOS additionally has no reachable Aqua/GUI session when
// running as a root LaunchDaemon (docs/agent-privilege-model.md); the code
// explicitly detects and reports that ("no reachable GUI session" /
// "not_reachable"), so those 4 legs are CONSTRAINED rather than SUPPORTED.
// windows: notify/message_box are native Win32 (Shell_NotifyIconW /
// MessageBoxW, rung 1); input/survey spawn powershell.exe via
// run_bounded_subprocess with clean argv (rung 3 -- an interpreter payload,
// same principle as osascript; ADR-3002 Decision 5 -- the outer invocation
// is argv-clean, but PowerShell interpreting its own -Command script is
// still the deepest interpreter intentionally invoked, so the rung is
// unchanged from the prior popen-based mechanism).
// set_dnd is a pure in-process KV-store write on every OS (rung 1).
const YuzuActionDescriptor kActionDescriptors[] = {
    {"notify",
     /* linux   = */ {YUZU_SUPPORT_SUPPORTED, 2, "notify_send", nullptr},
     /* macos   = */
     {YUZU_SUPPORT_CONSTRAINED, 3, "osascript",
      "no reachable GUI session under a headless/root LaunchDaemon"},
     /* windows = */ {YUZU_SUPPORT_SUPPORTED, 1, "shell_notifyicon", nullptr}},
    {"message_box",
     /* linux   = */ {YUZU_SUPPORT_SUPPORTED, 2, "zenity", nullptr},
     /* macos   = */
     {YUZU_SUPPORT_CONSTRAINED, 3, "osascript",
      "no reachable GUI session under a headless/root LaunchDaemon"},
     /* windows = */ {YUZU_SUPPORT_SUPPORTED, 1, "messageboxw", nullptr}},
    {"input",
     /* linux   = */ {YUZU_SUPPORT_SUPPORTED, 2, "zenity", nullptr},
     /* macos   = */
     {YUZU_SUPPORT_CONSTRAINED, 3, "osascript",
      "no reachable GUI session under a headless/root LaunchDaemon"},
     /* windows = */ {YUZU_SUPPORT_SUPPORTED, 3, "powershell_inputbox", nullptr}},
    {"survey",
     /* linux   = */ {YUZU_SUPPORT_SUPPORTED, 2, "zenity", nullptr},
     /* macos   = */
     {YUZU_SUPPORT_CONSTRAINED, 3, "osascript",
      "no reachable GUI session under a headless/root LaunchDaemon"},
     /* windows = */ {YUZU_SUPPORT_SUPPORTED, 3, "powershell_winforms", nullptr}},
    {"set_dnd",
     /* linux   = */ {YUZU_SUPPORT_SUPPORTED, 1, "local_kv_store", nullptr},
     /* macos   = */ {YUZU_SUPPORT_SUPPORTED, 1, "local_kv_store", nullptr},
     /* windows = */ {YUZU_SUPPORT_SUPPORTED, 1, "local_kv_store", nullptr}},
};

} // namespace

class InteractionPlugin final : public yuzu::Plugin {
public:
    std::string_view name() const noexcept override { return "interaction"; }
    std::string_view version() const noexcept override { return "0.3.0"; }
    std::string_view description() const noexcept override {
        return "Desktop user interaction — notifications, message boxes, input dialogs, surveys, DND";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {
            "notify", "message_box", "input", "survey", "set_dnd", nullptr};
        return acts;
    }

    const YuzuActionDescriptor* action_descriptors() const noexcept override {
        return kActionDescriptors;
    }
    size_t action_descriptor_count() const noexcept override {
        return sizeof(kActionDescriptors) / sizeof(kActionDescriptors[0]);
    }

    yuzu::Result<void> init(yuzu::PluginContext& ctx) override {
        plugin_ctx_ = ctx.raw();
        // Restore DND state from KV store
        yuzu::PluginContext wrap{plugin_ctx_};
        auto dnd_val = wrap.storage_get("dnd_enabled");
        if (dnd_val == "true") {
            dnd_enabled_ = true;
            auto exp_str = wrap.storage_get("dnd_expires_at");
            if (!exp_str.empty()) {
                int64_t exp = 0;
                std::from_chars(exp_str.data(), exp_str.data() + exp_str.size(), exp);
                dnd_expires_at_ = exp;
            }
        }
        return {};
    }

    void shutdown(yuzu::PluginContext& /*ctx*/) noexcept override {}

    int execute(yuzu::CommandContext& ctx, std::string_view action,
                yuzu::Params params) override {
        if (action == "notify")
            return do_notify(ctx, params);
        if (action == "message_box")
            return do_message_box(ctx, params);
        if (action == "input")
            return do_input(ctx, params);
        if (action == "survey")
            return do_survey(ctx, params);
        if (action == "set_dnd")
            return do_set_dnd(ctx, params);

        ctx.write_output(std::format("status|error|unknown action: {}", action));
        return 1;
    }

private:
    int do_notify(yuzu::CommandContext& ctx, yuzu::Params params) {
        // Check DND — suppress notifications when active
        if (is_dnd_active()) {
            ctx.write_output("status|suppressed|do not disturb is active");
            return 0;
        }

        auto title = params.get("title");
        auto message = params.get("message");
        auto type = params.get("type", "info");

        if (!require_param(ctx, title, "title")) return 1;
        if (!require_param(ctx, message, "message")) return 1;

        // Validate type
        if (type != "info" && type != "warning" && type != "error") {
            ctx.write_output("status|error|invalid type: must be info, warning, or error");
            return 1;
        }

        return platform_notify(ctx, sanitize(title), sanitize(message),
                               std::string{type});
    }

    int do_message_box(yuzu::CommandContext& ctx, yuzu::Params params) {
        auto title = params.get("title");
        auto message = params.get("message");
        auto buttons = params.get("buttons", "ok");

        if (!require_param(ctx, title, "title")) return 1;
        if (!require_param(ctx, message, "message")) return 1;

        // Validate buttons
        if (buttons != "ok" && buttons != "okcancel" && buttons != "yesno") {
            ctx.write_output("status|error|invalid buttons: must be ok, okcancel, or yesno");
            return 1;
        }

        return platform_message_box(ctx, sanitize(title), sanitize(message),
                                    std::string{buttons});
    }

    int do_input(yuzu::CommandContext& ctx, yuzu::Params params) {
        auto title = params.get("title");
        auto prompt = params.get("prompt");
        auto default_value = params.get("default_value", "");

        if (!require_param(ctx, title, "title")) return 1;
        if (!require_param(ctx, prompt, "prompt")) return 1;

        return platform_input(ctx, sanitize(title), sanitize(prompt),
                              sanitize(default_value));
    }

    int do_survey(yuzu::CommandContext& ctx, yuzu::Params params) {
        // Check DND
        if (is_dnd_active()) {
            ctx.write_output("status|suppressed|do not disturb is active");
            return 0;
        }

        auto title = params.get("title");
        auto questions_json = params.get("questions");

        if (!require_param(ctx, title, "title")) return 1;
        if (!require_param(ctx, questions_json, "questions")) return 1;

        auto questions = parse_questions_json(questions_json);
        if (questions.empty()) {
            ctx.write_output("status|error|no valid questions parsed from JSON");
            return 1;
        }

        return platform_survey(ctx, sanitize(title), questions);
    }

    int do_set_dnd(yuzu::CommandContext& ctx, yuzu::Params params) {
        auto enabled_str = params.get("enabled", "true");
        auto duration_str = params.get("duration_minutes", "0");

        bool enabled = (enabled_str == "true" || enabled_str == "1" || enabled_str == "yes");
        int duration_minutes = 0;
        if (!duration_str.empty()) {
            std::from_chars(duration_str.data(),
                            duration_str.data() + duration_str.size(),
                            duration_minutes);
        }

        dnd_enabled_ = enabled;

        if (enabled && duration_minutes > 0) {
            auto now = std::chrono::duration_cast<std::chrono::seconds>(
                           std::chrono::system_clock::now().time_since_epoch())
                           .count();
            dnd_expires_at_ = now + (static_cast<int64_t>(duration_minutes) * 60);
        } else {
            dnd_expires_at_ = 0;
        }

        // Persist to KV store
        if (plugin_ctx_) {
            yuzu::PluginContext wrap{plugin_ctx_};
            wrap.storage_set("dnd_enabled", enabled ? "true" : "false");
            wrap.storage_set("dnd_expires_at", std::to_string(dnd_expires_at_));
        }

        ctx.write_output(std::format("dnd_enabled|{}", enabled ? "true" : "false"));
        if (enabled && duration_minutes > 0) {
            ctx.write_output(std::format("dnd_duration_minutes|{}", duration_minutes));
            ctx.write_output(std::format("dnd_expires_at|{}", dnd_expires_at_));
        }
        ctx.write_output("status|ok");
        return 0;
    }

    // ── DND state ────────────────────────────────────────────────────────────

    bool is_dnd_active() const {
        if (!dnd_enabled_) return false;
        if (dnd_expires_at_ > 0) {
            auto now = std::chrono::duration_cast<std::chrono::seconds>(
                           std::chrono::system_clock::now().time_since_epoch())
                           .count();
            if (now >= dnd_expires_at_) {
                // DND has expired — clear it
                // const_cast because we need to update state in a const method;
                // this is safe as the agent serializes execute() calls per command.
                const_cast<InteractionPlugin*>(this)->dnd_enabled_ = false;
                const_cast<InteractionPlugin*>(this)->dnd_expires_at_ = 0;
                if (plugin_ctx_) {
                    yuzu::PluginContext wrap{const_cast<InteractionPlugin*>(this)->plugin_ctx_};
                    wrap.storage_set("dnd_enabled", "false");
                    wrap.storage_set("dnd_expires_at", "0");
                }
                return false;
            }
        }
        return true;
    }

    YuzuPluginContext* plugin_ctx_{nullptr};
    bool dnd_enabled_{false};
    int64_t dnd_expires_at_{0};  // epoch seconds, 0 = indefinite
};

YUZU_PLUGIN_EXPORT(InteractionPlugin)
