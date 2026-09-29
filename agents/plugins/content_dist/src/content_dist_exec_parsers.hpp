#pragma once

/// @file content_dist_exec_parsers.hpp
/// PURE decision layer for `content_dist`'s `execute_staged` action: the
/// yuzu::agent::SubprocessOptions this plugin runs every staged-file
/// invocation with, and the wire mapping of the resulting
/// yuzu::agent::SubprocessResult back onto content_dist's
/// status|/exit_code|/output| lines. No OS calls, no subprocess spawn, no
/// filesystem, no clock read — content_dist_plugin.cpp's `do_execute` is
/// the thin runner-calling shell around this header (same split as
/// firewall_parsers.hpp / content_dist_upload_parsers.hpp).
///
/// This plugin replaced its private OS-specific direct-argv spawn helpers
/// (a Windows child-process launcher and a POSIX child-process launcher)
/// with one cross-platform call to
/// yuzu::agent::run_bounded_subprocess (agents/core/src/subprocess_runner.cpp,
/// ADR-3002). The two functions below are the exact decision points a
/// reviewer needs to audit for that migration: what options the call runs
/// with, and how its result maps back onto the SAME wire lines, in the SAME
/// order, the deleted spawn paths produced.

#include <yuzu/agent/subprocess_runner.hpp>

#include <chrono>
#include <cstdint>
#include <string>
#include <string_view>
#include <system_error>
#include <utility>
#include <vector>

namespace yuzu::content_dist::exec {

/// True iff `first_bytes` begins with a shebang ("#!"). Pure decision only
/// -- `do_execute` reads the staged file's first two bytes itself (thin
/// shell, at the call site) and passes them here; this function never
/// touches the filesystem. Used to reject shebang-interpreted scripts
/// before the runner call on Linux: B6 exec_verify's fd-exec primitive
/// (execveat with O_CLOEXEC) closes the verified fd before the kernel's
/// binfmt_script handler gets a chance to re-open the interpreter path,
/// so a shebang script cannot run under fd-exec at all -- better to reject
/// it up front with an actionable message than let it spawn_error opaquely.
[[nodiscard]] inline bool is_shebang_payload(std::string_view first_bytes) {
    return first_bytes.size() >= 2 && first_bytes[0] == '#' && first_bytes[1] == '!';
}

/// True iff `arg` contains none of the shell metacharacters `do_execute`'s
/// caller-supplied `args` param is refused for: `; & | \` $ ( ) { } < > ! ~
/// ^ ' " # * ? [ ] \n \r`. `execute_staged` never invokes a shell (argv is
/// exec'd directly via yuzu::agent::run_bounded_subprocess), so this is not
/// closing a shell-injection hole that exists today -- it is a defence-in-
/// depth refusal against an operator-supplied args string that LOOKS like a
/// shell pipeline, on the theory that such a string almost certainly
/// reflects a misunderstanding of this action's no-shell contract rather
/// than a deliberate, safe argument. BR-006 (whole-branch review round 2):
/// moved here from content_dist_plugin.cpp's anonymous namespace (a pure,
/// no-I/O string predicate belongs in this header, not the impure plugin
/// TU) so both `do_execute`'s real call site and a unit test can share the
/// one definition.
[[nodiscard]] inline bool is_safe_arg(std::string_view arg) {
    for (char c : arg) {
        if (c == ';' || c == '&' || c == '|' || c == '`' || c == '$' || c == '(' || c == ')' ||
            c == '{' || c == '}' || c == '<' || c == '>' || c == '!' || c == '~' || c == '^' ||
            c == '\'' || c == '"' || c == '#' || c == '*' || c == '?' || c == '[' || c == ']' ||
            c == '\n' || c == '\r') {
            return false;
        }
    }
    return true;
}

/// Splits `args` on runs of space/tab into an argv tail -- a simple
/// whitespace split, deliberately NOT shell word-splitting (no quoting, no
/// escaping): `execute_staged` never invokes a shell, so there is no shell
/// grammar to replicate here. BR-006: moved here alongside is_safe_arg()
/// above, same reasoning.
[[nodiscard]] inline std::vector<std::string> split_args(std::string_view args) {
    std::vector<std::string> result;
    std::string current;
    for (char c : args) {
        if (c == ' ' || c == '\t') {
            if (!current.empty()) {
                result.push_back(std::move(current));
                current.clear();
            }
        } else {
            current += c;
        }
    }
    if (!current.empty())
        result.push_back(std::move(current));
    return result;
}

/// The fixed SubprocessOptions `do_execute` runs every `execute_staged`
/// invocation with. `is_linux` gates exec_verify (Linux-only fd-exec
/// TOCTOU closure); pass both `is_linux`/`is_windows` `true` only on an
/// actual matching build (`#ifdef __linux__`/`#ifdef _WIN32` at the call
/// site), never based on a runtime guess. `is_windows` did not vary the
/// result between BR-001 (inherit_parent_env made unconditional -- see that
/// field's own comment below) and BR4-007 (whole-branch review round 4,
/// below): it now also gates `no_window`, restoring the deleted Windows
/// launcher's CREATE_NO_WINDOW behaviour for this Windows-only-relevant
/// flag. The caller still MUST set `.exec_verify.expected_size` on the
/// returned options afterward, once the staged file's hash-verified size is
/// known: this function never touches the filesystem, so it cannot know
/// that size itself.
[[nodiscard]] inline yuzu::agent::SubprocessOptions build_execution_options(bool is_linux,
                                                                              bool is_windows) {
    yuzu::agent::SubprocessOptions opts;

    // BR-002 (whole-branch review correction -- supersedes an earlier
    // version of this comment, and of this migration's spec, that is WRONG
    // and must not be re-derived from): a flat 30s deadline is NOT a
    // preservation of the deleted paths' pre-migration behaviour on either
    // platform. The deleted Windows path called
    // WaitForSingleObject(pi.hProcess, 30000) but never acted on a timeout
    // -- it simply stopped waiting and read back whatever GetExitCodeProcess
    // returned (STILL_ACTIVE if the child was still running), leaving the
    // child running, undisturbed, in the background; no kill was ever sent.
    // The deleted POSIX path's waitpid() had no bound at all. So on BOTH
    // platforms, pre-migration, execute_staged actually let a staged
    // installer run to completion, however long that took. A 30s deadline
    // with soft_terminate_grace at its zero default (the runner's
    // immediate-hard-SIGKILL behaviour, subprocess_runner.hpp) is a NEW,
    // strictly worse regression this migration would otherwise introduce:
    // a real installer legitimately running past 30s -- entirely plausible
    // for content_dist's actual use case, staged package/tooling installers
    // -- gets SIGKILLed mid-transaction, which the pre-migration code never
    // did on either OS.
    //
    // execute_staged is MUTATING (it runs a staged installer that can hold
    // real state -- mid-write files, an in-flight package-manager
    // transaction) and takes no caller-supplied timeout parameter (unlike
    // script_exec's operator-set `timeout`), so this function must pick one
    // fixed, generous value that stands in for "no bound" without actually
    // being unbounded -- ADR-3002's entire migration rationale is that an
    // agent-spawned child must never be able to hang the runner forever.
    // 30 MINUTES: comfortably longer than any legitimate installer this
    // plugin stages in practice (script_exec's own operator-configurable
    // ceiling for arbitrary admin scripts tops out at 3600s/1hr -- this is
    // half that, deliberately more conservative since execute_staged runs
    // unattended, without an operator able to raise it per-call), while
    // still closing the genuine "run forever" hang risk the pre-migration
    // code left wide open. If a real deployment needs longer, that is a
    // new, explicit, reviewed exception -- not a silent unbounded default.
    opts.deadline = std::chrono::minutes(30);

    // ADR-3002 "termination semantics for mutating tools": a mutating site
    // must carry a nonzero soft-terminate grace, not just a bounded
    // deadline -- on a deadline trigger the runner sends SIGTERM to the
    // process group first (Windows: CTRL_BREAK, xplat-A2-unsupported for
    // this service-hosted agent, subprocess_runner.hpp) and waits this long
    // for a voluntary exit before escalating to the same unmodified hard
    // kill. 30s: a staged installer is the site most likely of the two
    // mutating runner call sites in this branch to be mid-write/
    // mid-transaction at the deadline (script_exec's grace, by contrast,
    // covers an arbitrary operator script with no known transactional
    // shape) -- long enough to let a well-behaved installer catch SIGTERM
    // and roll back or flush, short enough that a genuinely hung installer
    // still resolves promptly.
    opts.soft_terminate_grace = std::chrono::seconds(30);

    // Both deleted paths merged stderr into the SAME captured stream as
    // stdout: the Windows launcher pointed its error handle at the same
    // pipe as its output handle, and the POSIX launcher duplicated its
    // pipe's write end onto both the child's stdout and stderr file
    // descriptors. Preserve that.
    opts.merge_stderr = true;

    // The runner's own maximum (subprocess_runner.hpp clamps
    // output_cap_bytes to [1, 16*1024*1024]). The deleted paths captured
    // output UNBOUNDED (a plain 1024-byte read loop with no cap) -- 16 MiB
    // is the smallest behaviour delta a caller-configurable cap can produce
    // relative to "no cap at all".
    opts.output_cap_bytes = 16 * 1024 * 1024;

    // B6 TOCTOU-safe exec (subprocess_runner.hpp): Linux-only, and this MUST
    // stay Linux-only. macOS/BSD has no fd-exec syscall to close the
    // fstat-verify -> exec gap and FAILS CLOSED (spawn_error) if enabled
    // there; Windows verification isn't implemented and fails closed too.
    // Setting this unconditionally would make execute_staged spawn_error on
    // every single invocation on macOS and Windows.
    // Alex ruling (whole-branch review round 1 follow-up, then round 2 --
    // BR-001 -- superseding round 1's POSIX claim below): the deleted
    // Windows launcher passed lpEnvironment=nullptr to CreateProcessW, so a
    // staged installer inherited the agent's FULL parent environment. The
    // migrated path set neither inherit_parent_env nor extra_env, which
    // would have silently narrowed Windows children to the runner's fixed
    // default block (SystemRoot/windir/PATH/TEMP/TMP) -- an undisclosed
    // behaviour change to exactly the kind of vendor installer that reads
    // machine/proxy variables. This mirrors the identical ruling already
    // applied to script_exec's Windows leg: a convergence refactor must not
    // silently change behaviour.
    //
    // BR-001 (round 2, whole-branch re-review): round 1's comment here
    // claimed "POSIX is unaffected -- the deleted POSIX launcher inherited
    // the parent environment implicitly via execvp, which is what the
    // runner's own default-off path plus this flag's POSIX no-op preserve."
    // That claim was FLATLY WRONG and must not be re-derived from: the
    // deleted POSIX launcher DID call execvp() without ever replacing
    // `environ`, so it DID inherit the full parent environment -- exactly
    // like the Windows launcher, not "unaffected" by comparison to it. The
    // runner's A5 clear-slate (PATH/LC_ALL/optional TZ only) was therefore
    // a real, undisclosed POSIX regression too: any staged installer
    // reading HTTPS_PROXY, HOME, a licence variable, or another deployment
    // variable worked before this migration and silently stopped after it.
    //
    // The fix is the SAME primitive Windows already used, now honoured on
    // POSIX as well (subprocess_runner.cpp's POSIX backend, BR-001) --
    // inherit_parent_env is set on EVERY platform here, matching this
    // action's actual pre-migration behaviour everywhere, not just on
    // Windows. The POSIX backend additionally strips the ADR-3002 A5
    // injection class (LD_*/DYLD_*/IFS/BASH_ENV/ENV/GCONV_PATH/NLSPATH/
    // LOCPATH) from the inherited block before use -- silently, not a
    // launch failure, matching subprocess_launch_spec.hpp's
    // filter_inherited_env() contract -- which the deleted execvp() launcher
    // never did; the strip is a narrowing relative to that exact
    // pre-migration behaviour, deliberately: a staged installer that
    // genuinely needed LD_PRELOAD-class inheritance was never something
    // this migration set out to preserve. Any FURTHER tightening of the
    // environment for staged payloads beyond that strip is a separate,
    // deliberate, disclosed change -- never a side effect of this migration.
    opts.inherit_parent_env = true;

    opts.exec_verify.enabled = is_linux;

    // DELIBERATELY false -- NOT the runner's require_root_owned=true
    // default. The staging directory (`staging_dir()` in
    // content_dist_plugin.cpp) is created agent-owned 0700, never root, so
    // on a rootless agent deployment every staged file is owned by the
    // agent's own unprivileged account. require_root_owned=true would
    // fstat-reject (spawn_error) EVERY staged file on EVERY rootless agent
    // -- execute_staged would never work at all outside a root-installed
    // agent. Integrity here does not come from file ownership; it comes
    // from `do_execute`'s MANDATORY hash re-verification against agent KV
    // (#808 -- a separate SQLite DB the staging-dir attacker can't also
    // rewrite) plus this fd-exec's own TOCTOU closure, plus the runner's
    // retained not-group/other-writable check.
    opts.exec_verify.require_root_owned = false;

    // BR4-007 (whole-branch review round 4): the deleted Windows launcher
    // passed CREATE_NO_WINDOW to CreateProcessW; migrating onto this
    // runner's shared Windows backend (whose create_flags never set that
    // bit for a caller with no pre-existing behaviour to preserve) silently
    // dropped it. Windows-only significance -- see
    // SubprocessOptions::no_window's doc comment.
    //
    // BR-006 (adversarial review, HIGH): KNOWN LIMITATION -- on Windows,
    // combining this with the nonzero opts.soft_terminate_grace set above
    // makes the grace INEFFECTIVE. CREATE_NO_WINDOW gives the child no
    // console at all, and GenerateConsoleCtrlEvent (the runner's CTRL_BREAK
    // soft-termination step) can only reach a process group that shares a
    // console with the caller -- so a deadline/cancel against a staged
    // installer on Windows goes straight to TerminateJobObject, skipping
    // the configured 30s grace entirely. See SubprocessOptions::no_window's
    // doc comment (subprocess_runner.hpp) for the full Win32 contract this
    // is derived from. A real fix -- a cooperative-termination channel that
    // works against a console-less child -- is out of scope (a separate,
    // larger IPC/event design, not an extension of CTRL_BREAK delivery).
    // What IS in scope: the configuration must not claim a grace it cannot
    // deliver. Zero it on the no_window path so opts.soft_terminate_grace
    // honestly reflects what this call site actually gets on Windows --
    // an immediate hard kill on deadline/cancel, same as the zero default
    // everywhere soft_terminate_grace is never set.
    opts.no_window = is_windows;
    if (opts.no_window)
        opts.soft_terminate_grace = std::chrono::seconds(0);

    return opts;
}

/// The three status|/exit_code|/output| wire lines `do_execute` emits, in
/// that exact order. `output` already carries any truncation/termination
/// annotation this mapping adds; an empty `output` means "no output| line
/// at all" (the pre-runner code's `if (!output.empty())` guard, preserved
/// verbatim at the call site).
struct ExecutionWireResult {
    std::string status;    ///< "ok" or "error" -- content of the status| line
    int exit_code = -1;    ///< content of the exit_code| line
    std::string output;    ///< content of the output| line; empty -> line omitted
};

/// Maps a completed run_bounded_subprocess() call onto the exact
/// status|/exit_code|/output| lines the plugin's deleted OS-specific
/// spawn paths produced (content_dist_plugin.cpp, previously
/// `status|{rc==0?"ok":"error"}` / `exit_code|{rc}` / `output|{output}`),
/// for every outcome `execute_staged` can actually observe. `line_limit` is
/// excluded by construction: this plugin never sets
/// max_lines/stop_after_max_lines, so a line_limit result can never reach
/// this function.
[[nodiscard]] inline ExecutionWireResult
map_execution_result(const yuzu::agent::SubprocessResult& result) {
    // deadline/cancelled are checked BEFORE tool_ran: the runner's own
    // termination_reason priority (subprocess_runner.cpp) classifies a
    // deliberate kill by its reason EVEN IF exec was never positively
    // confirmed -- when a pre-armed cancel (or a very tight deadline) kills
    // the child on its very first poll, tool_ran can still be false (exec
    // was never confirmed) while termination_reason is correctly
    // deadline/cancelled, not spawn_error. Checking tool_ran first would
    // misreport that case as "spawn failed (errno 0: Success)" and drop the
    // deadline/cancelled reason the caller needs to pick the right retry
    // policy. A killed-at-the-boundary run may still have captured partial
    // output before the kill; report it, annotated, rather than silently
    // discarding it.
    if (result.termination_reason == yuzu::agent::TerminationReason::deadline ||
        result.termination_reason == yuzu::agent::TerminationReason::cancelled) {
        // BR-006 (whole-branch review): this branch used to collapse BOTH
        // reasons into the literal text "deadline exceeded" and return
        // before ever checking output_truncated -- so a cancel (e.g. agent
        // shutdown mid-install) read as a false "it timed out", and a run
        // that was BOTH truncated at the 16 MiB cap AND then killed lost
        // the truncation fact entirely, letting a consumer parse partial
        // output as complete. Append truncation independently of
        // termination (same as the ordinary exited/signaled path below),
        // then annotate the actual reason, not an assumed one.
        std::string output = result.output;
        if (result.output_truncated)
            output += "\n[output truncated at 16 MiB]";
        output += result.termination_reason == yuzu::agent::TerminationReason::deadline
                      ? "\n[terminated: deadline exceeded]"
                      : "\n[terminated: cancelled]";
        return ExecutionWireResult{"error", -1, std::move(output)};
    }

    // tool_ran == false is authoritative for "exec itself never positively
    // succeeded" -- spawn_error, covering both a missing/non-executable
    // binary and a B6 exec_verify rejection -- matching tool_ran's own
    // documented contract (subprocess_runner.hpp). Reached only once the
    // deadline/cancelled kill classification above has already been ruled
    // out.
    if (!result.tool_ran) {
        // BR-005 (whole-branch review round 2): SubprocessResult::spawn_errno
        // is documented (subprocess_runner.hpp) as 0 for "a non-POSIX/no-
        // report failure path" -- the Windows runner returns spawn_error
        // without ever assigning it. Formatting 0 through
        // std::generic_category().message() unconditionally produced the
        // self-contradictory "spawn failed (errno 0: Success)" on every
        // Windows CreateProcessW/setup failure, obscuring the actual
        // failure and misleading an operator or autonomous retry logic that
        // parses this text. Report honestly when there is no real errno to
        // report instead of formatting a fabricated "Success".
        if (result.spawn_errno == 0)
            return ExecutionWireResult{"error", -1, "spawn failed (OS error unavailable)"};
        return ExecutionWireResult{
            "error", -1,
            "spawn failed (errno " + std::to_string(result.spawn_errno) + ": " +
                std::generic_category().message(result.spawn_errno) + ")"};
    }

    // The ordinary `exited` case, and the residual `signaled` case (the
    // child died of a signal it received itself -- e.g. a crash -- never
    // one the runner sent; exit_code stays the runner's -1 sentinel either
    // way per SubprocessResult's contract) both resolve the same way the
    // deleted POSIX path's `WIFEXITED(status) ? WEXITSTATUS(status) : -1`
    // already collapsed them: report whatever `exit_code` the reap
    // produced, with no extra annotation beyond a truncation notice.
    std::string output = result.output;
    if (result.output_truncated)
        output += "\n[output truncated at 16 MiB]";
    return ExecutionWireResult{result.exit_code == 0 ? "ok" : "error", result.exit_code,
                               std::move(output)};
}

} // namespace yuzu::content_dist::exec
