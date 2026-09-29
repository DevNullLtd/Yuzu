/**
 * test_interaction_parsers.cpp — pure interaction parse helpers
 * (interaction_parsers.hpp, macOS parity 1.3).
 *
 * The runner-backed argv spawn in interaction_plugin.cpp is the impure
 * shell; the decision-shaped decoding of the try/on-error `osascript
 * display dialog` sentinel output is header-pure and pinned here on every
 * host (the licensing_parsers.hpp pattern). The honest-status invariant is
 * the point: anything that is not an offered button or the -128 user-cancel
 * decodes to not_reachable, never a fabricated response.
 */

#include "interaction_parsers.hpp"

#include <algorithm>
#include <catch2/catch_test_macros.hpp>
#include <string_view>
#include <vector>

using namespace yuzu::interaction;

TEST_CASE("dialog: real button presses decode to their response", "[interaction]") {
    CHECK(parse_dialog_result("##BTN##OK") == DialogOutcome::ok);
    CHECK(parse_dialog_result("##BTN##Cancel") == DialogOutcome::cancel);
    CHECK(parse_dialog_result("##BTN##Yes") == DialogOutcome::yes);
    CHECK(parse_dialog_result("##BTN##No") == DialogOutcome::no);
    CHECK(parse_dialog_result("##BTN##OK\n") == DialogOutcome::ok); // trailing newline tolerated
}

TEST_CASE("dialog: -128 is user-cancel, every other error is not_reachable", "[interaction]") {
    CHECK(parse_dialog_result("##ERR##-128") == DialogOutcome::cancel);   // user canceled / escape
    CHECK(parse_dialog_result("##ERR##-1743") == DialogOutcome::not_reachable); // not authorised (TCC)
    CHECK(parse_dialog_result("##ERR##-600") == DialogOutcome::not_reachable);  // app not running
    CHECK(parse_dialog_result("##ERR##-1719") == DialogOutcome::not_reachable); // no window server
    CHECK(parse_dialog_result("##ERR##0") == DialogOutcome::not_reachable);     // any non-cancel number
}

TEST_CASE("dialog: unreachable session / missing binary / garbage is never a false button",
          "[interaction]") {
    CHECK(parse_dialog_result("") == DialogOutcome::not_reachable);
    // The daemon has no GUI session: osascript writes error prose (via 2>&1),
    // none of which starts with a sentinel.
    CHECK(parse_dialog_result(
              "execution error: Not authorized to send Apple events (-1743).") ==
          DialogOutcome::not_reachable);
    CHECK(parse_dialog_result("sh: osascript: command not found") ==
          DialogOutcome::not_reachable);
    // A sentinel prefix but a label we never offered — cannot map honestly.
    CHECK(parse_dialog_result("##BTN##Maybe") == DialogOutcome::not_reachable);
    // The pre-fix bug: bare "button returned:OK" prose no longer sneaks through
    // as ok — without a sentinel prefix it is not_reachable, and the real path
    // now emits ##BTN##OK anyway.
    CHECK(parse_dialog_result("button returned:OK") == DialogOutcome::not_reachable);
}

TEST_CASE("build_dialog_argv: exact AppleScript argv shape, pinned against a typo regression",
          "[interaction]") {
    const auto argv = build_dialog_argv("Alert", "Something happened",
                                        "buttons {\"OK\"} default button \"OK\"");
    // Title/message land in the one interpolated display-dialog fragment;
    // every other fragment (try/on-error/end-try + both sentinel returns) is
    // a fixed literal a future edit could typo without any compiler
    // diagnostic — this pins the exact source text parse_dialog_result's
    // contract depends on. One vector element per -e flag/fragment pair, no
    // shell string, no `2>&1` (stderr merge is expressed via SubprocessOptions
    // at the call site, not shell redirection).
    const std::vector<std::string> expected = {
        "-e", "try",
        "-e", "display dialog \"Something happened\" with title \"Alert\" "
              "buttons {\"OK\"} default button \"OK\"",
        "-e", "return \"##BTN##\" & (button returned of result)",
        "-e", "on error errMsg number errNum",
        "-e", "return \"##ERR##\" & errNum",
        "-e", "end try",
    };
    CHECK(argv == expected);
}

TEST_CASE("build_dialog_argv: btn_spec is threaded through verbatim per button config",
          "[interaction]") {
    auto contains_fragment = [](const std::vector<std::string>& argv, std::string_view needle) {
        return std::any_of(argv.begin(), argv.end(),
                           [&](const std::string& s) { return s.find(needle) != std::string::npos; });
    };
    CHECK(contains_fragment(build_dialog_argv("T", "M", "buttons {\"OK\"} default button \"OK\""),
                            "buttons {\"OK\"} default button \"OK\""));
    CHECK(contains_fragment(
        build_dialog_argv("T", "M", "buttons {\"Cancel\", \"OK\"} default button \"OK\""),
        "buttons {\"Cancel\", \"OK\"} default button \"OK\""));
    CHECK(contains_fragment(
        build_dialog_argv("T", "M", "buttons {\"No\", \"Yes\"} default button \"Yes\""),
        "buttons {\"No\", \"Yes\"} default button \"Yes\""));
    // The sentinel/control-flow skeleton is identical regardless of button
    // config — only the one display-dialog fragment varies.
    for (auto* spec : {"buttons {\"OK\"} default button \"OK\"",
                       "buttons {\"Cancel\", \"OK\"} default button \"OK\"",
                       "buttons {\"No\", \"Yes\"} default button \"Yes\""}) {
        const auto argv = build_dialog_argv("T", "M", spec);
        REQUIRE(argv.size() == 12);
        CHECK(argv.front() == "-e");
        CHECK(argv[1] == "try");
        CHECK(argv[10] == "-e");
        CHECK(argv[11] == "end try");
        CHECK(contains_fragment(argv, "return \"##BTN##\" & (button returned of result)"));
        CHECK(contains_fragment(argv, "on error errMsg number errNum"));
        CHECK(contains_fragment(argv, "return \"##ERR##\" & errNum"));
    }
}

TEST_CASE("interaction input/survey capture: exit-code/output decision (qe-L2)", "[interaction]") {
    using yuzu::interaction::classify_input_capture;

    SECTION("non-zero exit is an honest delivery failure, never wrapped as a response") {
        auto d = classify_input_capture(1, "no reachable GUI session");
        CHECK(d.output_line == "status|unavailable|no reachable GUI session");
        CHECK(d.rc == 1);
        // Even output that looks like a button/answer must not become a response
        // when the tool exited non-zero.
        auto d2 = classify_input_capture(2, "hello");
        CHECK(d2.output_line == "status|unavailable|no reachable GUI session");
        CHECK(d2.rc == 1);
    }
    SECTION("the ##CANCELLED## sentinel on a clean exit is a user cancel") {
        auto d = classify_input_capture(0, "##CANCELLED##");
        CHECK(d.output_line == "cancelled|true");
        CHECK(d.rc == 0);
    }
    SECTION("any other clean-exit output is genuine user input") {
        auto d = classify_input_capture(0, "Alice");
        CHECK(d.output_line == "response|Alice");
        CHECK(d.rc == 0);
        // Empty input on a clean exit is a real (empty) answer, not a cancel.
        auto d2 = classify_input_capture(0, "");
        CHECK(d2.output_line == "response|");
        CHECK(d2.rc == 0);
    }
}

TEST_CASE("classify_posix_capture: -1 is a genuine runner failure, "
          "never a fabricated zenity Cancel",
          "[interaction][runner_status]") {
    using yuzu::interaction::classify_posix_capture;
    using yuzu::interaction::PosixCaptureOutcome;

    // run_command_capture's documented sentinel for spawn error / deadline /
    // signal death -- the runner never produced a real zenity exit status.
    CHECK(classify_posix_capture(-1) == PosixCaptureOutcome::runner_failure);

    // zenity's own contract: 1 = Cancel/dismiss, 5 = ESC/timeout -- both are
    // real user outcomes, not runner failures.
    CHECK(classify_posix_capture(1) == PosixCaptureOutcome::cancelled);
    CHECK(classify_posix_capture(5) == PosixCaptureOutcome::cancelled);

    // A clean exit is genuine output the caller should parse.
    CHECK(classify_posix_capture(0) == PosixCaptureOutcome::real_output);
}

TEST_CASE("classify_windows_dialog_capture: every runner-failure branch is "
          "honest, never a fabricated cancel or completed survey",
          "[interaction][runner_status]") {
    using yuzu::interaction::classify_windows_dialog_capture;

    SECTION("the process never launched") {
        auto d = classify_windows_dialog_capture(/*tool_ran=*/false,
                                                  /*timed_out=*/false,
                                                  /*exit_code=*/0);
        CHECK(d.is_failure);
        CHECK(d.output_line == "status|error|failed to launch PowerShell");
        CHECK(d.rc == 1);
    }

    SECTION("a killed-at-deadline dialog is never a fabricated cancel") {
        auto d = classify_windows_dialog_capture(/*tool_ran=*/true,
                                                  /*timed_out=*/true,
                                                  /*exit_code=*/0);
        CHECK(d.is_failure);
        CHECK(d.output_line == "status|unavailable|PowerShell dialog timed out");
        CHECK(d.rc == 1);
        // timed_out is checked even when the killed process happens to report
        // a nonzero exit code -- it must never fall through to the exit_code
        // branch's different message.
        auto d2 = classify_windows_dialog_capture(true, true, 1);
        CHECK(d2.output_line == "status|unavailable|PowerShell dialog timed out");
    }

    SECTION("a ran-but-nonzero-exit dialog (e.g. ShowDialog() threw) is "
            "never a fabricated cancel or empty-but-successful response") {
        auto d = classify_windows_dialog_capture(/*tool_ran=*/true,
                                                  /*timed_out=*/false,
                                                  /*exit_code=*/1);
        CHECK(d.is_failure);
        CHECK(d.output_line == "status|unavailable|PowerShell dialog exited with an error");
        CHECK(d.rc == 1);
    }

    SECTION("a real, clean-exit dialog is not a failure -- caller parses output") {
        auto d = classify_windows_dialog_capture(/*tool_ran=*/true,
                                                  /*timed_out=*/false,
                                                  /*exit_code=*/0);
        CHECK_FALSE(d.is_failure);
        CHECK(d.output_line.empty());
        CHECK(d.rc == 0);
    }
}
