#pragma once

/**
 * subprocess_runner.hpp -- agent-core bounded, fork-safe POSIX subprocess
 * runner (#2273 foundation), extended to the full ADR-3002 runner contract
 * (docs/adr/3002-acquisition-ladder.md:537-606) plus the best-practice
 * addendum (A1-A6, B1-B6).
 *
 * Runs a fixed argv (argv[0] MUST be an absolute path -- exec'd via execv(),
 * never execvp(), so there is no PATH search and no shell in between, hence
 * no shell-quoting/injection surface) as a child in its own process group,
 * with a hard wall-clock deadline: if the child hasn't
 * exited by then, its whole process group is SIGKILLed and reaped.
 * Callers that need to end a run early (agent shutdown, an operator
 * cancel) can cooperatively request that via request_subprocess_cancel()
 * -- an in-flight run notices on its next poll and finishes the same way
 * a deadline would -- or, for a SINGLE in-flight call without affecting any
 * other, via a per-invocation CancellationToken (SubprocessOptions::cancel_token).
 *
 * This lives in agent-core rather than as a plugin-local header because the
 * implementation spawns a DETACHED background reaper thread when a killed
 * child can't be confirmed-reaped within a short bound (see
 * subprocess_runner.cpp). That thread's code must never live in memory that
 * can be unmapped out from under it -- which rules out a plugin .dylib/.so,
 * since agent.cpp's reconnect/shutdown paths dlclose() plugins. yuzu_agent_core_lib
 * is linked directly into the yuzu-agent executable and is never dlclose'd,
 * so a helper defined here is a genuine pinned image. Declared here, DEFINED
 * OUT-OF-LINE in subprocess_runner.cpp -- same split as LocalDispatcher
 * (local_dispatcher.hpp / .cpp) -- so the fork/exec/reap machinery compiles
 * only into that pinned image, never into an including plugin.
 *
 * Now genuinely cross-platform: POSIX (fork+execve) and Windows (a real
 * suspended-create -> assign-Job-Object -> resume CreateProcessW backend,
 * replacing the previous stub) both implement the same contract below.
 */

#include <yuzu/plugin.h> // YUZU_EXPORT

#include <atomic>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace yuzu::agent {

/**
 * Why a run ended, per the ADR-3002 contract: "an explicit termination
 * reason ... is what lets an autonomous consumer distinguish 'ran and
 * failed' (retry) from 'killed at deadline' (escalate) from 'spawn error'
 * (never retry)". This enum is the runner header's alone in this PR --
 * nothing in Wave-1 maps it onto the wire (no CommandResponse/proto/plugin.h
 * edit); it is deliberately stable and documented so a later wire-mapping
 * package can adopt it unchanged.
 */
enum class TerminationReason {
    exited,      // the child ran to completion and exited on its own (any exit code)
    signaled,    // the child died from a signal it received itself (e.g. a crash) --
                 // NOT one the runner sent; exit_code stays the -1 sentinel either way
    deadline,    // the wall-clock deadline elapsed before the child exited
    cancelled,   // a cancel (process-global OR the per-invocation token) fired first
    line_limit,  // stop_after_max_lines reached its cap and the runner stopped the
                 // child deliberately -- a clean bounded stop, not a failure
    spawn_error, // exec itself never positively succeeded (relative/empty argv[0],
                 // embedded NUL, banned Windows extension, pipe/fork/CreateProcess
                 // failure, or the child reported a failed exec) -- tool_ran is false
};

/**
 * Per-invocation cooperative cancellation (ADR-3002: "a per-invocation
 * cancellation token, not only the global flag"). Distinct from, and
 * additive to, request_subprocess_cancel()/subprocess_cancel_requested()
 * below: setting THIS token only affects the one run_bounded_subprocess()
 * call it was passed to via SubprocessOptions::cancel_token, never any other
 * concurrent or future invocation. A caller that wants to cancel a single
 * in-flight run without aborting every other concurrent subprocess on the
 * endpoint constructs one of these, hands a shared_ptr to it in
 * SubprocessOptions, and calls cancel() from any thread.
 */
class CancellationToken {
public:
    void cancel() { cancelled_.store(true, std::memory_order_release); }
    bool cancelled() const { return cancelled_.load(std::memory_order_acquire); }

private:
    std::atomic<bool> cancelled_{false};
};

struct SubprocessOptions {
    std::chrono::milliseconds deadline{std::chrono::milliseconds(10000)};
    std::size_t max_lines = 0; // 0 = unlimited; caps STORED lines (not raw
                                // output) so a huge invocation (e.g. `log
                                // show`) can't grow unbounded memory.
    bool merge_stderr = false; // false: child stderr -> /dev/null (matches
                                // `2>/dev/null` log-inspection CLIs). true:
                                // stderr merged into the same captured
                                // stream as stdout (codesign/plutil write
                                // their diagnostics to stderr).
    // When true AND max_lines > 0: stop reading as soon as max_lines lines
    // have been stored, kill+reap the child's process group, and report a
    // NORMAL success (timed_out=false, output_truncated=false) rather than
    // running the child to opts.deadline. For a caller that only ever wants
    // the first N lines (e.g. `log show`), this turns "N lines available in
    // a huge stream" into a clean bounded success instead of a partial
    // result that looks like a timeout/truncation. False (default) keeps
    // the previous behaviour: max_lines only caps what's stored, the runner
    // keeps draining/discarding until the child exits or the deadline hits.
    // The resulting run's termination_reason is line_limit, and exit_code is
    // left at whatever the child's own reap produced (see SubprocessResult::
    // exit_code) -- it is NEVER fabricated to 0 for a signal-killed child.
    bool stop_after_max_lines = false;

    // Per-invocation cancel (see CancellationToken above). Left null (the
    // default) if the caller only wants the process-global cancel.
    std::shared_ptr<CancellationToken> cancel_token;

    // ADR-3002 ("make the output byte cap caller-configurable"): the sanity
    // cap on captured stdout+stderr bytes, independent of max_lines/deadline.
    // Historically a fixed ~1MB; now caller-settable up to 16 MiB (the
    // ceiling script_exec will need). Clamped to [1, 16*1024*1024] by the
    // runner -- a caller-supplied 0 or an oversized value is corrected to the
    // nearest bound, never silently ignored or treated as "unbounded".
    std::size_t output_cap_bytes = 1'000'000;

    // A6: child working directory. Unset (default) -> the runner's own safe
    // default ("/" on POSIX; a non-writable system directory on Windows) --
    // never the agent daemon's own (potentially attacker-influenced) cwd.
    std::optional<std::string> working_dir;

    // ADR-3002 ("termination semantics for mutating tools"): an optional
    // soft-terminate grace. 0 (default) is the historical behaviour --
    // immediate hard SIGKILL of the process group (CTRL_BREAK+job-close on
    // Windows is skipped too). >0: on a deadline/cancel trigger, the runner
    // sends SIGTERM to the process group (Windows: CTRL_BREAK to the process
    // group) first and waits up to this long for a voluntary exit before
    // escalating to the same unmodified hard kill -- gives a tool holding
    // real state (e.g. mid-dpkg/rpm transaction) a chance to unwind instead
    // of being SIGKILLed mid-write. Never applied to a stop_after_max_lines
    // stop (that path is a clean "got what we asked for", not an interrupt).
    //
    // xplat-A2 (Windows): soft-terminate is delivered via
    // GenerateConsoleCtrlEvent(CTRL_BREAK_EVENT, ...), which requires the
    // target process group to share the caller's console. yuzu-agent runs as
    // a Windows SERVICE with no console at all, so the call reliably fails
    // there and this grace is effectively UNSUPPORTED for a service-hosted
    // agent -- a failed delivery escalates straight to the hard kill rather
    // than waiting out the grace for a signal that can never arrive.
    std::chrono::milliseconds soft_terminate_grace{0};

    // Caller-supplied environment allow-list additions (Alex plan-gate
    // ruling, PLAN-04 option b: the runner freeze is lifted for exactly this
    // one narrowly-scoped extension). This is a DELIBERATE, BOUNDED widening
    // of ADR-3002 A5's clear-slate env policy -- the child still never
    // inherits the parent process' environment wholesale; the caller must
    // name each variable it wants forwarded explicitly, one entry at a time.
    // An entry whose name matches an existing A5 allow-list entry REPLACES
    // it in place (never appended as a second, ambiguous same-named entry);
    // an entry with a new name is appended in caller order. Empty (the
    // default) leaves every existing caller's LaunchSpec byte-identical to
    // today's -- this field changes nothing unless a caller opts in.
    //
    // FAILS CLOSED: if any entry's name is denylisted (the LD_*/DYLD_*
    // prefixes, or the exact names IFS/BASH_ENV/ENV/GCONV_PATH/NLSPATH/
    // LOCPATH) or malformed (empty name, a name containing '=' or a NUL, a
    // value containing a NUL, OR a name containing any non-ASCII byte --
    // BR-010 whole-branch review: is_malformed_env_entry rejects this on
    // EVERY platform, POSIX included, not just Windows), the ENTIRE launch
    // is refused
    // (termination_reason == spawn_error, tool_ran == false, no OS call
    // attempted) rather than proceeding with that one entry silently
    // dropped -- a silently-ignored LD_PRELOAD request would hide a caller
    // bug. See merge_launch_env() in subprocess_launch_spec.hpp for the pure
    // merge/validation logic and LaunchSpecError::denied_env_var for the
    // specific rejection reason.
    std::vector<std::pair<std::string, std::string>> extra_env;

    // A2-002 (Alex plan-gate ruling, script_exec Windows-parity escalation):
    // a SECOND, narrower widening of A5's clear-slate env policy, additive
    // to (never a replacement for) extra_env above. BR4-006 (whole-branch
    // review round 4): this point previously called the widening
    // "Windows-ONLY" -- true when this flag was introduced, but point (c)
    // below records that content_dist's migration exposed a real POSIX gap
    // and Alex extended the SAME flag to the POSIX backend rather than
    // inventing a second mechanism; the flag itself is cross-platform as of
    // that ruling, even though script_exec (the caller this paragraph is
    // about) only ever sets it on its own Windows leg -- see (c) and
    // script_exec_plugin.cpp's file-header comment for why that ONE
    // caller's POSIX leg has no gap to fill. Default
    // false, so every existing caller's launch is bit-for-bit unchanged --
    // this is covered by test_subprocess_launch_spec.cpp's default-value
    // assertion and by test_subprocess_runner.cpp's "extra_env-only, flag
    // unset" launch-spec test.
    //
    // WHY THIS EXISTS: script_exec's Windows leg (deleted CreateProcessA
    // call, pre-runner-migration) passed a null lpEnvironment, so its
    // children inherited the FULL parent environment unfiltered -- unlike
    // the POSIX leg, which always kept an explicit seven-name safe_vars
    // allow-list (PATH/HOME/USER/LANG/LC_ALL/TERM/TZ). Alex ruled AGAINST
    // narrowing that pre-existing Windows behaviour to match POSIX's seven
    // names when this runner replaced script_exec's private spawn paths.
    // extra_env alone cannot express "forward everything the parent has" --
    // it is an explicit, individually-validated, additive allow-list, by
    // design (ADR-3002 A5) -- so this flag is the one narrowly-scoped
    // exception PLAN-04/A2-002 authorizes: it exists ONLY to reproduce
    // script_exec's pre-existing Windows behaviour, not as a general-purpose
    // "give me the parent's environment" facility for any other caller.
    //
    // (a) INTERACTION WITH extra_env: when true, extra_env entries are still
    // applied ON TOP of the inherited parent-environment block, using the
    // SAME replace-in-place-never-duplicate semantics merge_launch_env()
    // always uses (subprocess_launch_spec.hpp) -- extra_env is the base
    // that's swapped from the A5 default to the live parent snapshot, not a
    // rule that stops applying. A caller combining both (as script_exec
    // does, forwarding its own seven-name allow-list on top of the full
    // inherited block) gets: full parent env, with any of those seven names
    // set to exactly the value extra_env specified, even if that differs
    // from what the live parent process itself currently holds.
    //
    // (b) SECURITY: this deliberately bypasses ADR-3002 A5's clear-slate
    // policy -- gated tightly: opt-in, default-off, cross-platform but
    // per-caller (see (c) below for the POSIX backend's own gating), and
    // every extra_env entry is STILL run through the existing
    // denylist/malformed-entry checks
    // (is_denied_env_name/is_malformed_env_entry) exactly as when this flag
    // is false -- LD_*/DYLD_*/IFS/BASH_ENV/ENV/GCONV_PATH/NLSPATH/LOCPATH
    // remain refused (the whole launch fails closed) regardless of this
    // flag's value; it only changes what UNNAMED variables the child also
    // receives, never what extra_env itself is allowed to name. This exists
    // to preserve pre-existing script_exec behaviour that PREDATES the
    // runner -- it is not, and must never become, a general-purpose "inherit
    // everything" facility for a caller with no equivalent legacy
    // requirement.
    //
    // (c) POSIX: HONOURED, as of BR-001 (whole-branch review round 2, Alex
    // ruling) -- this point previously said POSIX intentionally ignored the
    // flag; that was true only until content_dist's migration exposed a
    // real gap the reasoning below explains.
    //
    // content_dist's deleted POSIX launcher called execvp() WITHOUT ever
    // replacing `environ`, so a staged installer inherited this agent's
    // FULL live environment (HTTPS_PROXY, a licence variable, HOME,
    // whatever the deployment set) -- unlike script_exec's deleted POSIX
    // path, which already used an explicit seven-name safe_vars allow-list
    // (extra_env alone reproduces THAT one exactly, no widening needed,
    // which is why script_exec's POSIX leg still never sets this flag --
    // see script_exec_plugin.cpp). The migrated runner's A5 clear-slate
    // silently narrowed content_dist's staged installers to
    // PATH/LC_ALL(/TZ) only: an undisclosed regression, not a deliberate
    // hardening decision, and Alex ruled it must be fixed by extending this
    // flag to POSIX rather than inventing a second mechanism.
    //
    // The POSIX backend in subprocess_runner.cpp now branches on this flag
    // exactly as the Windows backend already did: reads its own live
    // environment (POSIX `environ`), strips the ADR-3002 A5 injection class
    // (LD_*/DYLD_*/IFS/BASH_ENV/ENV/GCONV_PATH/NLSPATH/LOCPATH) via
    // subprocess_launch_spec.hpp's filter_inherited_env() -- SILENTLY
    // (dropped, not fatal; see that function's own comment for why an
    // inherited variable's failure mode must differ from extra_env's
    // fail-closed one) -- then layers extra_env on top with the SAME
    // replace-never-duplicate merge_launch_env() semantics point (a)
    // above already describes for Windows. extra_env's own denylist/
    // malformed-entry checks are UNCHANGED: a denied or malformed extra_env
    // entry still fails the whole launch closed, on POSIX exactly as on
    // Windows, regardless of this flag.
    //
    // content_dist now sets this flag on EVERY platform (its pre-migration
    // behaviour was full inheritance everywhere, POSIX included -- there
    // was never a Windows-only asymmetry in what it actually did, only in
    // what this runner initially reproduced). script_exec's POSIX leg is
    // UNCHANGED and must stay that way: it already has its own curated
    // seven-name allow-list with no gap to fill, and widening it to full
    // inheritance would be an unrelated, undiscussed behaviour change this
    // flag's contract does not authorize for that caller.
    bool inherit_parent_env = false;

    // BR4-007 (whole-branch review round 4): Windows-only, no POSIX
    // equivalent (there is no console concept to suppress there, so this
    // field is simply ignored on the POSIX backend). Both script_exec's and
    // content_dist's deleted private Windows launchers passed
    // CREATE_NO_WINDOW to CreateProcessA -- migrating them onto this
    // runner's shared Windows backend (whose own create_flags never set
    // that bit, for callers with no equivalent pre-migration behaviour to
    // preserve) silently dropped it, so an interactively-run agent
    // launching either action could flash a console window a pre-migration
    // caller never saw. Default false so every existing caller's launch is
    // bit-for-bit unchanged -- opt in per call site, exactly the
    // inherit_parent_env precedent above. Session-0 SERVICE deployments are
    // unaffected either way (no console to flash); this exists for the
    // interactive/diagnostic run case. Does not disable
    // CREATE_NEW_PROCESS_GROUP or this call's soft_terminate_grace
    // CTRL_BREAK delivery -- CREATE_NO_WINDOW only suppresses the new
    // console WINDOW's visibility, it does not remove the process group or
    // its console, and xplat-A2's existing caveat (GenerateConsoleCtrlEvent
    // is already unreliable for a console-less agent SERVICE) is unchanged
    // by this flag either way.
    // BR-006 (adversarial review, HIGH -- corrects the paragraph above,
    // which is WRONG about the Win32 contract and must not be re-derived
    // from): CREATE_NO_WINDOW does not merely hide the new console WINDOW's
    // visibility -- per Microsoft's own documented contract, a process
    // created with this flag gets NO CONSOLE AT ALL (it is not attached to
    // any console, new or inherited). GenerateConsoleCtrlEvent's contract
    // requires the target process group to SHARE a console with the
    // caller; a no_window=true child has none, so CTRL_BREAK_EVENT can
    // never reach it. Concretely: for any caller that sets BOTH
    // no_window=true AND a nonzero soft_terminate_grace, the "soft"
    // termination step is a guaranteed no-op on Windows -- every
    // deadline/cancel goes straight to TerminateJobObject, silently
    // skipping the configured grace. A genuinely separate soft-IPC channel
    // compatible with a no-console child would be a new, separately-
    // designed mechanism, not an extension of CTRL_BREAK delivery, and
    // stays out of scope here. What IS in scope, and now done: a caller
    // must not CONFIGURE a grace it cannot deliver -- content_dist_exec_
    // parsers.hpp and script_exec_plugin.cpp, the two callers that set
    // no_window=true, both zero soft_terminate_grace on that path so the
    // options struct honestly reflects what Windows actually delivers.
    // This doc comment is the standing warning for any FUTURE
    // no_window=true caller: zero soft_terminate_grace alongside it, or
    // the two fields silently lie about each other. See the call-site
    // comments in content_dist_exec_parsers.hpp and script_exec_plugin.cpp.
    bool no_window = false;

    // B3: optional per-invocation resource caps, OFF (nullopt) by default --
    // RLIMIT_AS in particular breaks mmap-heavy tools like `log show`, so
    // these are opt-in per call site, never a blanket default.
    struct RlimitCaps {
        std::optional<std::uint64_t> cpu_seconds;         // RLIMIT_CPU
        std::optional<std::uint64_t> address_space_bytes; // RLIMIT_AS (or RLIMIT_DATA
                                                            // where RLIMIT_AS doesn't
                                                            // exist); Windows: Job Object
                                                            // JOBOBJECT_EXTENDED_LIMIT_INFORMATION
                                                            // process memory limit.
        std::optional<std::uint64_t> fsize_bytes;         // RLIMIT_FSIZE
        std::optional<std::uint64_t> nofile_count;        // RLIMIT_NOFILE
    };
    RlimitCaps rlimits{};

    // B6: optional TOCTOU-safe exec verification. Disabled (the default) --
    // this is a runner PRIMITIVE only in this PR; no in-tree caller enables
    // it (content_dist adopts it at PR5.1, ADR-3002:604-606 sequencing).
    // When enabled, argv[0] is opened O_NOFOLLOW, fstat-verified (regular
    // file, root-owned if require_root_owned, not group/other-writable, and
    // -- if expected_size is set -- exactly that size) and then exec'd via
    // that SAME fd via an fd-based exec syscall on Linux (execveat(), NEVER
    // glibc's fexecve() wrapper -- see subprocess_runner.cpp's comment on
    // why). macOS/BSD (and any Linux build without SYS_execveat) has no
    // equivalent fd-exec primitive to close the final TOCTOU gap between the
    // fstat-verify and the exec, so enabling this there FAILS CLOSED
    // (spawn_error) exactly like Windows (sec-8/BR-004) rather than falling
    // back to an unverified, re-resolving execve(path, ...). On WINDOWS the
    // verification is not yet implemented, so enabling it FAILS CLOSED
    // (spawn_error) rather than launching unverified (BR-004).
    struct ExecVerification {
        bool enabled = false;
        bool require_root_owned = true;
        std::optional<std::uint64_t> expected_size;
    };
    ExecVerification exec_verify{};

    // ADR-3002 ("streaming output... incremental line delivery"): called
    // synchronously, once per completed line, as output is collected --
    // IN ADDITION to (never instead of) populating result.lines/output.
    // Unlike result.lines, every line reaches this callback regardless of
    // max_lines (the cap bounds only what's STORED for the collect-at-end
    // contract; a streaming consumer wants every line as produced). A
    // caller must return promptly -- it runs on this call's own polling
    // loop, so a slow callback delays that same call's own deadline/cancel
    // responsiveness (never another concurrent invocation's). Left null
    // (the default) if the caller only wants the collect-at-end contract.
    // Runner PRIMITIVE only in this PR: no in-tree caller wires this in
    // yet -- script_exec/content_dist convergence onto it is a separate,
    // later package (ADR-3002:604-606 sequencing: convergence must not
    // precede the features it depends on).
    std::function<void(const std::string& line)> on_line;
};

struct SubprocessResult {
    // false IFF exec itself failed (binary missing at the given absolute
    // path, not executable, etc -- argv[0] is never PATH-searched).
    // Determined by a close-on-exec exec-error pipe, NOT
    // an exit-code heuristic -- a program that legitimately returns 127
    // (e.g. `sh -c 'exit 127'`) is still tool_ran=true, exit_code==127.
    // Callers treat !tool_ran as an honest "unknown", never a fabricated
    // verdict.
    bool tool_ran = false;

    // WEXITSTATUS(status) when the child was reaped via a normal exit
    // (covers both a real exit and the internal _exit(127) taken after an
    // exec failure -- tool_ran is what tells those two apart). Left at the
    // -1 sentinel when the child was signal-killed (deadline/cancel/
    // line_limit/its own crash) -- never a fabricated exit status for a
    // death by signal, in ANY case (see termination_reason for what
    // actually happened).
    int exit_code = -1;

    // True if the wall-clock deadline elapsed OR a cancel was requested
    // (process-global or per-invocation) before the child exited on its
    // own. A killed child can still have tool_ran=true (it ran and
    // produced output before being killed, e.g. a codesign call that
    // emitted diagnostics) -- callers MUST check timed_out before trusting
    // exit_code/output for a pass/fail verdict. NOT set for a
    // stop_after_max_lines stop (see termination_reason == line_limit
    // instead -- that path is a deliberate clean stop, not a timeout).
    bool timed_out = false;

    // ADR-3002: the explicit reason this run ended -- see TerminationReason.
    // Always set (never left at a stale default) once run_bounded_subprocess
    // returns.
    TerminationReason termination_reason = TerminationReason::spawn_error;

    // POSIX errno the child reported over the exec-error pipe (report_setup_
    // failure_and_exit's `err` argument) when termination_reason ==
    // spawn_error and the child positively reported a failure -- e.g. ENOENT
    // (missing binary), EACCES/EPERM (not executable, or a B6 exec_verify
    // gate rejection), ETXTBSY (B6 retries exhausted). 0 when no such report
    // was ever read (an unresolved outcome, or a non-POSIX/no-report failure
    // path) -- 0 is never itself a reported failure errno, so it is
    // unambiguous as "unknown"/not-applicable here, unlike exit_code's -1.
    int spawn_errno = 0;

    // Captured stdout (+stderr if merge_stderr), split on '\n', blank lines
    // dropped, a trailing '\r' stripped from each line. Capped at
    // opts.max_lines when nonzero.
    std::vector<std::string> lines;

    // The same captured stream as a single blob (suitable for a
    // substring/trim style check, e.g. reading a signature-verification
    // tool's diagnostic text) -- independent of the max_lines cap on
    // `lines`, bounded only by opts.output_cap_bytes.
    std::string output;

    // True once capture hit opts.output_cap_bytes (default ~1MB, clamped to
    // [1, 16MiB], independent of max_lines/deadline) before the child
    // finished. A defensive memory bound against a runaway or adversarial
    // child, not a feature callers configure for its own sake. When true,
    // `output` and possibly the tail of `lines` reflect only what was
    // captured before the cap -- capture stopped early, nothing here is
    // fabricated past that point.
    bool output_truncated = false;

    // B4: child resource usage, captured on reap (POSIX: wait4()'s rusage;
    // Windows: GetProcessTimes + GetProcessMemoryInfo before the handle is
    // closed). Left at zero when never captured (tool_ran == false, or the
    // loop's kDrainGrace escape hatch fired before a confirmed reap) --
    // zero here means "unknown", not "the child used no resources".
    std::chrono::microseconds child_user_time{0};   // ru_utime / kernel-mode-adjacent user time
    std::chrono::microseconds child_system_time{0}; // ru_stime / kernel time
    std::uint64_t child_max_rss_kb = 0;              // peak RSS in KiB, normalized across
                                                      // platforms (Linux ru_maxrss is already
                                                      // KB; macOS's byte-granularity ru_maxrss
                                                      // and Windows' PeakWorkingSetSize are
                                                      // both divided down to KiB here).
};

/**
 * Run `argv` (argv[0] MUST be an absolute path -- exec'd via execve() on
 * POSIX (never execvp(), so there is no PATH search and no shell) or
 * CreateProcessW() on Windows) as a child in its own process group / Job
 * Object, collecting output until the child exits or opts.deadline elapses /
 * a cancel is requested, whichever first. Never blocks past that bound (plus
 * a short, bounded grace period to observe the pipe close and the child
 * reap after a kill -- extended, if opts.soft_terminate_grace is set, by that
 * grace before the hard kill is even sent) and never fabricates a result --
 * an incomplete run is reported honestly via timed_out/tool_ran/
 * termination_reason.
 *
 * Runtime-rejects (termination_reason == spawn_error, tool_ran == false, no
 * OS call attempted) an empty argv, a relative or empty argv[0], an embedded
 * NUL in any argv element, and -- on the Windows shell -- a .bat/.cmd/.com
 * argv[0] (CVE-2024-24576; ADR-3002:537-606) in EVERY build type, not just
 * debug/assert builds.
 *
 * Declared here; DEFINED OUT-OF-LINE in subprocess_runner.cpp so the
 * fork/exec/reap body compiles only into the pinned agent-core image (see
 * the header comment above).
 */
YUZU_EXPORT SubprocessResult run_bounded_subprocess(const std::vector<std::string>& argv,
                                                     const SubprocessOptions& opts);

/**
 * Process-global cooperative cancel for in-flight subprocess collection.
 * run_bounded_subprocess polls subprocess_cancel_requested() each iteration
 * of its wait loop; once true it kills and reaps the child (same bounded
 * path as a deadline) and returns promptly with timed_out=true,
 * termination_reason=cancelled.
 *
 * Backed by a file-local std::atomic<bool> in subprocess_runner.cpp -- a
 * single flag shared by every in-flight run in the process, not a
 * per-call/per-connection token. For that narrower scope, use
 * SubprocessOptions::cancel_token (CancellationToken) instead -- the two are
 * independent and both checked on every poll.
 */
YUZU_EXPORT void request_subprocess_cancel(bool cancel);
YUZU_EXPORT bool subprocess_cancel_requested();

/**
 * ADR-3002 ("tool path probing"): returns the first candidate that is an
 * absolute path (same contract as run_bounded_subprocess's argv[0]) AND
 * exists AND is executable, or an empty string if none match. Useful when a
 * tool's location varies (e.g. `ip` differs across distros). "Executable"
 * is judged per backend as "this runner could spawn it": POSIX = regular
 * file + access(X_OK); Windows = not a spawn-banned .bat/.cmd/.com and a
 * real executable image (GetBinaryTypeW), K2/CDX-P2-003.
 *
 * Honestly noted (ADR-3002): this is a stat-then-exec probe, so it is still
 * a filesystem TOCTOU if an attacker can replace the probed binary between
 * the probe and the later exec -- root-owned tool directories are the
 * mitigation, not this function. For a stronger guarantee, pair the probed
 * path with SubprocessOptions::exec_verify (B6).
 */
YUZU_EXPORT std::string probe_tool_path(const std::vector<std::string>& candidates);

#ifdef _WIN32
/**
 * Whole-branch review round 3 (BR3-001): the Windows system directory,
 * resolved via GetSystemDirectoryW and cached for the process's lifetime --
 * same rationale, and the same pattern, as quarantine_plugin.cpp's
 * netsh_path(). Both this runner's own Windows default working_dir (A6,
 * below) and any caller that needs an absolute path to a well-known
 * System32 tool (e.g. script_exec's PowerShell launch) must resolve
 * through here rather than trusting a hard-coded "C:\Windows\System32"
 * literal, which is wrong on any install where Windows lives on a non-C:
 * volume -- an attacker-writable "C:\Windows\System32" tree on such a host
 * would otherwise be treated as trusted.
 *
 * Returns an EMPTY string if GetSystemDirectoryW fails. Callers MUST fail
 * closed on that (refuse the spawn), never fall back to a guessed literal.
 */
YUZU_EXPORT const std::string& windows_system_directory();
#endif

} // namespace yuzu::agent
