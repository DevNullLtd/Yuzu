/**
 * script_exec_plugin.cpp — Script/command execution plugin for Yuzu
 *
 * Actions:
 *   "exec"       — Execute a command with arguments (no shell interpretation).
 *                   Params: command (required — program path),
 *                           args (optional — space-separated arguments),
 *                           timeout (optional, default "300").
 *   "powershell" — Run a PowerShell script (Windows only).
 *                   Params: script (required), timeout (optional, default "300").
 *   "bash"       — Run a bash script (Linux/macOS only).
 *                   Params: script (required), timeout (optional, default "300").
 *
 * Security: This plugin is admin-only — the server enforces role checks
 * before dispatching commands to this plugin.
 *
 * Output is pipe-delimited, streamed per line via write_output():
 *   stdout|line_content
 *   exit_code|N
 *   status|ok/error/timeout
 *
 * All three modes route through yuzu::agent::run_bounded_subprocess
 * (agents/core/src/subprocess_runner.cpp, ADR-3002) instead of this
 * plugin's own private per-OS spawn paths (the old Win32 process-creation
 * call on Windows; a raw POSIX spawn-and-exec pair on Linux/macOS) — the
 * runner already provides no-shell argv exec, a bounded output capture, a
 * deadline, and process-wide child-launch serialization internally, so this
 * plugin no longer links against the shared launch-serialization lock
 * header at all. script_exec_parsers.hpp's resolve_executable()/
 * assemble_argv() are the pure decision layer around that call.
 *
 * ENVIRONMENT (PLAN-04, resolved — option (b), extend the runner):
 * SubprocessOptions::extra_env (a0-runner-env-allowlist) lets this plugin
 * preserve its pre-migration environment behaviour EXACTLY: the same seven
 * names the deleted POSIX spawn path's safe_vars list kept (PATH, HOME,
 * USER, LANG, LC_ALL, TERM, TZ) are read from THIS process's own
 * environment at call time (parent_env_allowlist(), below — the impure
 * shell, never the pure header) and passed through opts.extra_env on every
 * mode. A name unset in the parent is simply not forwarded — EXCEPT for
 * PATH and LC_ALL, the two names the runner's own default_launch_env()
 * bakes into every launch regardless of extra_env (subprocess_launch_spec.hpp);
 * extra_env can only REPLACE a base entry it names, so leaving those two
 * unforwarded when the parent has them unset would let the runner's fixed
 * default (PATH=/usr/bin:/bin:/usr/sbin:/sbin, LC_ALL=C) silently reappear.
 * parent_env_allowlist() forwards an explicit empty-value override for
 * those two names in that case instead, to neutralize the runner default
 * (see its own comment for why an empty value is the closest available
 * equivalent to unset here).
 *
 * One platform note, UPDATED by Alex at the A2-002 escalation (superseding
 * the paragraph this replaces): the deleted Windows spawn path passed a
 * null environment block to CreateProcessA, so its children inherited the
 * FULL parent environment unfiltered — BROADER than the POSIX safe_vars
 * list (dozens of ambient variables vs. seven curated names), not equal to
 * it. BR3-004 (whole-branch review round 3): an earlier version of this
 * comment said "narrower," backwards from the actual comparison. Alex ruled
 * AGAINST narrowing that pre-existing
 * Windows behaviour to match POSIX's seven names (an earlier draft of this
 * migration did exactly that, and it was flagged and reversed). Windows
 * instead uses the new, narrowly-scoped
 * SubprocessOptions::inherit_parent_env (subprocess_runner.hpp — read that
 * field's doc comment for the full contract, including its explicit design
 * points: extra_env interaction and security gating), set true only on
 * this plugin's Windows leg below. BR4-006 (whole-branch review round 4):
 * the field is honoured on POSIX too (subprocess_runner.hpp's own comment
 * point (c)) — this plugin's POSIX leg simply never NEEDS to set it, because
 * its seven-name safe_vars allow-list (extra_env, below) already
 * reproduces its pre-migration POSIX behaviour exactly with no widening
 * required; an earlier version of this paragraph called that a POSIX
 * "no-op," true only before content_dist's migration exposed the real
 * POSIX gap the field's own comment now documents. The net effect:
 * Windows children continue to receive the SAME full parent environment
 * they always did pre-migration, with this plugin's seven-name allow-list
 * still layered on top via extra_env exactly as on POSIX — so there is
 * NO operator-visible environment change on either platform.
 *
 * Because the child's PATH is once again the parent's real PATH (via
 * extra_env, not the runner's fixed four-directory default), do_exec's
 * bare-name resolution reads that SAME captured PATH value (parent_env_allowlist()
 * is called ONCE per action and its result reused for both resolution and
 * the launch, rather than two independent getenv() reads) and probes it via
 * resolve_executable — never the runner's own default allow-list PATH.
 */

#include <yuzu/plugin.hpp>

#include "script_exec_parsers.hpp"

#include <yuzu/agent/runner_status.hpp>     // yuzu::agent::forward_runner_failure (ABI4 result-status seam, ADR-3002)
#include <yuzu/agent/subprocess_runner.hpp>
#include <yuzu/agent/updater.hpp> // yuzu::agent::current_executable_path (BR4-003, trusted app dir)

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <format>
#include <iterator>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#include <wincrypt.h>
#pragma comment(lib, "Crypt32.lib")

#include <win_str.hpp> // yuzu::win::from_wide (agents/shared, #1681; BR4-004)
#endif

namespace {

constexpr size_t kMaxOutputBytes = 16 * 1024 * 1024; // 16 MiB hard output cap

// The cwd resolve_executable's relative-path branch joins against. Matches
// the runner's OWN default working_dir exactly (SubprocessOptions::working_dir
// is left unset by every call below, so this is genuinely what the child
// runs with) — "/" on POSIX; on Windows, subprocess_runner.cpp resolves its
// own "/" sentinel via yuzu::agent::windows_system_directory()
// (GetSystemDirectoryW, cached process-lifetime), so this function performs
// the IDENTICAL resolution rather than trusting the hard-coded literal
// "C:\Windows\System32" this used to be (BR3-001, whole-branch review round
// 3) — an install with Windows on a non-C: volume would otherwise anchor a
// relative command/PATH entry against an untrusted, attacker-populatable
// directory tree. Returns an EMPTY string on Windows if resolution fails;
// do_exec below fails the action closed in that case rather than falling
// back to the old literal.
//
// BR-009 (whole-branch review): this is a DELIBERATE, operator-visible
// compatibility break from the deleted execvp()/CreateProcessA() paths, not
// an exact preservation of their behaviour despite resolve_executable's own
// doc comment describing "the same relative-launch semantics" -- that
// claim is about the RESOLUTION ALGORITHM (how a relative path/bare PATH
// entry joins against a cwd), which is unchanged; the ANCHOR VALUE is not.
// The deleted paths resolved a relative `command`/PATH entry against the
// agent daemon's actual real working directory; this migration resolves it
// against this fixed safe sentinel instead (ADR-3002 A6: never the daemon's
// own, potentially attacker-influenced, cwd). A deployment that relied on
// `./helper`-style relative commands from a deployment-controlled agent cwd
// will see that command fail post-migration where it previously resolved.
// Recorded here rather than silently inherited: see changelog.d's
// script_exec fragment for the operator-facing note.
#ifdef _WIN32
std::string runner_default_cwd() {
    return yuzu::agent::windows_system_directory();
}
#else
std::string runner_default_cwd() {
    return "/";
}
#endif

// ── helper: parse timeout ──────────────────────────────────────────────────

int parse_timeout(yuzu::Params& params) {
    auto t = std::string(params.get("timeout"));
    if (t.empty())
        return 300;
    int val = 300;
    try {
        val = std::stoi(t);
    } catch (...) {
        val = 300;
    }
    if (val < 1)
        val = 1;
    if (val > 3600)
        val = 3600;
    return val;
}

// ── helper: parent environment allow-list (see file header) ────────────────

// PATH and LC_ALL are the two names run_bounded_subprocess's own
// default_launch_env() bakes into EVERY launch regardless of extra_env
// (POSIX: PATH=/usr/bin:/bin:/usr/sbin:/sbin, LC_ALL=C --
// subprocess_launch_spec.hpp). merge_launch_env() only REPLACES a base
// entry that extra_env names; an unset name is left alone. So simply
// omitting PATH/LC_ALL when the parent leaves them unset (this plugin's
// "unset stays unset" rule for the other five names) would let the
// runner's own default silently reappear in the child -- exactly the
// operator-visible change this allow-list exists to prevent. LC_ALL unset
// with only LANG set is the common real-world case this guards.
//
// An explicit empty-value override neutralizes the runner's default: for
// LC_ALL, POSIX/glibc's locale-resolution algorithm treats "unset" and ""
// identically (setlocale(3): an empty LC_ALL falls through to
// LC_<category>/LANG exactly as an absent one does). For PATH the
// empty-vs-unset distinction is a much narrower edge (a bare-name PATH
// search treats "" as "search cwd only" rather than falling back to an
// OS-default search path) -- but a parent process with NO PATH at all is
// already vanishingly rare, and an explicit empty override is still closer
// to "unset" than silently reintroducing the runner's fixed
// /usr/bin:/bin:/usr/sbin:/sbin default would be.
constexpr const char* kRunnerDefaultedNames[] = {"PATH", "LC_ALL"};

bool is_runner_defaulted(std::string_view name) {
    for (const char* defaulted : kRunnerDefaultedNames) {
        if (name == defaulted)
            return true;
    }
    return false;
}

// BR4-004 (whole-branch review round 4): std::getenv() is the NARROW CRT
// environment on Windows -- a separate, narrower-encoded copy the CRT
// startup code builds from the process' real (wide) environment block
// using the ACTIVE CODE PAGE, not UTF-8. A value containing a character
// outside that code page round-trips lossily (or not at all) through
// std::getenv() even though the real, wide environment block the runner
// itself reads via GetEnvironmentStringsW() (subprocess_runner.cpp,
// A2-002's inherit_parent_env branch) carries it correctly. Reading via
// GetEnvironmentVariableW() and converting the result ONCE with
// yuzu::win::from_wide() (agents/shared/win_str.hpp, CP_UTF8) gets this
// allow-list's seven captured values from the SAME encoding source the
// runner's own snapshot uses, so a name/value that resolve_executable
// probes here and the value the runner ultimately launches the child with
// are never two different byte sequences for the same character.
#ifdef _WIN32
std::optional<std::string> get_env_value(const char* name) {
    // Every kNames entry below is a compile-time ASCII literal, so a plain
    // widen (no yuzu::win::to_wide dependency needed) is exact.
    std::wstring wname(name, name + std::char_traits<char>::length(name));

    wchar_t stack_buf[256];
    DWORD len = GetEnvironmentVariableW(wname.c_str(), stack_buf,
                                        static_cast<DWORD>(std::size(stack_buf)));
    if (len == 0) {
        // ERROR_ENVVAR_NOT_FOUND (unset) and every other failure both read
        // as "not present" here -- this allow-list already treats an unset
        // name as absent-not-fatal (see parent_env_allowlist()'s call
        // site), so there is no separate error case for a caller to react
        // to.
        return std::nullopt;
    }
    if (len < std::size(stack_buf))
        return yuzu::win::from_wide(stack_buf, static_cast<int>(len));

    // Value longer than the stack buffer: len is the required size
    // INCLUDING the terminating NUL on this branch (GetEnvironmentVariableW's
    // contract), so a len-sized buffer holds it exactly.
    std::wstring buf(len, L'\0');
    DWORD len2 = GetEnvironmentVariableW(wname.c_str(), buf.data(), len);
    if (len2 == 0 || len2 >= len)
        return std::nullopt; // shrank or failed between the two calls -- treat as absent
    buf.resize(len2);
    return yuzu::win::from_wide(buf.c_str(), static_cast<int>(len2));
}
#endif

std::vector<std::pair<std::string, std::string>> parent_env_allowlist() {
    static constexpr const char* kNames[] = {"PATH", "HOME", "USER", "LANG",
                                             "LC_ALL", "TERM", "TZ"};
    std::vector<std::pair<std::string, std::string>> out;
    for (const char* name : kNames) {
#ifdef _WIN32
        if (auto val = get_env_value(name))
            out.emplace_back(name, std::move(*val));
        else if (is_runner_defaulted(name))
            out.emplace_back(name, std::string{});
#else
        if (const char* val = std::getenv(name))
            out.emplace_back(name, val);
        else if (is_runner_defaulted(name))
            out.emplace_back(name, std::string{});
#endif
    }
    return out;
}

// ── helper: real "would the runner be able to exec this" probe ─────────────

// Reuses the runner's own probe semantics (yuzu::agent::probe_tool_path,
// subprocess_runner.hpp) instead of a plugin-local existence check: POSIX =
// regular file + access(X_OK); Windows = GetBinaryTypeW, a real
// UTF-8-correct executable-image check -- not "exists and isn't a
// directory," which would accept a non-PE file that the runner could never
// actually spawn. probe_tool_path requires an ABSOLUTE candidate (mirrors
// the runner's own argv[0] contract), which every candidate resolve_executable
// probes here already is.
bool is_executable_probe(const std::string& path) {
    return !yuzu::agent::probe_tool_path({path}).empty();
}

// ── helper: run argv through the shared runner, emit the wire lines ────────

int run_via_runner(yuzu::CommandContext& ctx, const std::vector<std::string>& argv,
                   int timeout_secs,
                   std::vector<std::pair<std::string, std::string>> extra_env) {
    yuzu::agent::SubprocessOptions opts;
    opts.deadline = std::chrono::seconds(timeout_secs);
    // BR-002 (whole-branch review): this action is MUTATING (an operator-
    // named program or an operator-authored bash/PowerShell script -- either
    // can hold real state: a partially-written file, an in-flight package
    // operation invoked from within the script, etc.). ADR-3002's
    // "termination semantics for mutating tools" requires a mutating site to
    // carry a nonzero soft-terminate grace, not just a generous deadline:
    // on a deadline/cancel trigger the runner sends SIGTERM (Windows:
    // CTRL_BREAK) to the process group first and waits this long for a
    // voluntary exit before escalating to the unmodified hard kill, instead
    // of an immediate SIGKILL with zero chance to unwind.
    //
    // 10s, chosen deliberately: this plugin's own deadline (parse_timeout,
    // above) is ALREADY caller-configurable and generous (1-3600s, clamp
    // unchanged from the deleted pre-migration spawn paths -- see that
    // function's own history), so there is no deadline regression here to
    // fix, only the missing grace. Pre-migration behaviour on BOTH
    // platforms was an immediate hard kill with NO grace at all (POSIX:
    // `kill(-pid, SIGKILL)` straight to the process group; Windows: no
    // kill call existed on timeout at all -- WaitForSingleObject just
    // stopped waiting). Adding a bounded 10s unwind window is therefore a
    // strict improvement over pre-migration behaviour, not a parity
    // requirement -- kept short because, unlike content_dist's staged
    // installers (content_dist_exec_parsers.hpp), an arbitrary operator
    // script has no known "generous" unwind time to size against, and a
    // short bounded grace is cheap insurance against an immediate SIGKILL
    // without materially extending the worst-case admin-triggered runtime.
    // xplat-A2 note (subprocess_runner.hpp): on Windows this delivers via
    // GenerateConsoleCtrlEvent, which reliably fails for the console-less
    // agent SERVICE and escalates straight to the hard kill -- the grace is
    // effectively POSIX-only for this deployment shape, same caveat as
    // every other mutating site that sets it.
    opts.soft_terminate_grace = std::chrono::seconds(10);
    // Both deleted spawn paths merged the child's stderr into the SAME
    // stream as stdout (POSIX: dup2'd pipe_fd[1] onto both STDOUT_FILENO and
    // STDERR_FILENO; Windows: si.hStdError = stdout_write) — preserve that.
    opts.merge_stderr = true;
    // ADR-3002's caller-configurable ceiling — the stored-blob bound that
    // matches the caller-side on_line byte counter below.
    opts.output_cap_bytes = kMaxOutputBytes;
    // Caller-captured (see do_exec/do_bash/do_powershell) rather than read
    // here via a fresh parent_env_allowlist() call: do_exec's PATH-based
    // resolution and the env the child actually receives must observe the
    // SAME snapshot of the parent's environment, not two independent
    // getenv() reads that a concurrent environment mutation could split.
    opts.extra_env = std::move(extra_env);
#ifdef _WIN32
    // A2-002 (Alex plan-gate ruling): reproduce the deleted CreateProcessA
    // call's null-lpEnvironment behaviour -- Windows children continue to
    // receive the FULL parent environment, with opts.extra_env (the
    // seven-name allow-list above) still applying on top of it. See
    // SubprocessOptions::inherit_parent_env's doc comment for the full
    // contract; this is scoped to script_exec's Windows leg specifically
    // (the one caller with a pre-existing full-inheritance behaviour to
    // preserve), never a general default.
    // BR4-007 (whole-branch review round 4): the deleted CreateProcessA
    // call also passed CREATE_NO_WINDOW -- restore it so an interactively
    // run agent invoking exec/powershell doesn't flash a console window a
    // pre-migration caller never saw. See SubprocessOptions::no_window's
    // doc comment for the full contract. Sourced from
    // windows_runner_overrides() (script_exec_parsers.hpp) so the pairing of
    // these two Windows-only flags is testable from a pure, OS-call-free
    // header even though this call site itself only compiles on Windows.
    //
    // BR-006 (adversarial review, HIGH): KNOWN LIMITATION -- win_overrides
    // defaults no_window=true (script_exec_parsers.hpp), which combined
    // with the nonzero opts.soft_terminate_grace set above makes that grace
    // INEFFECTIVE on Windows. This is a STRICTER version of the xplat-A2
    // caveat already noted at the soft_terminate_grace assignment (which
    // only covers the console-less SERVICE deployment shape) -- a
    // no_window=true child has no console AT ALL regardless of deployment
    // shape, so GenerateConsoleCtrlEvent can never reach it even for an
    // interactively run agent. Every deadline/cancel goes straight to
    // TerminateJobObject, silently skipping the configured 10s grace. See
    // SubprocessOptions::no_window's doc comment (subprocess_runner.hpp)
    // for the full Win32 contract. The cooperative-termination channel a
    // real fix needs is out of scope; zeroing the grace below when
    // no_window is set is the in-scope fix -- the configuration must not
    // arm a grace this deployment shape can never deliver.
    auto win_overrides = yuzu::script_exec::windows_runner_overrides();
    opts.inherit_parent_env = win_overrides.inherit_parent_env;
    opts.no_window = win_overrides.no_window;
    if (opts.no_window)
        opts.soft_terminate_grace = std::chrono::seconds(0);
#endif

    // on_line delivers every line regardless of any runner-side cap
    // (subprocess_runner.hpp), INCLUDING a fully blank completed line
    // (A2-002 escalation, A2-006: the runner's store_line() now invokes
    // on_line before its blank-line early return, matching both deleted
    // spawn paths' behaviour of emitting a "stdout|" record for an empty
    // line -- only the STORED SubprocessResult::lines/byte-cap accounting
    // still excludes it), so the 16 MiB bound here is entirely caller-side:
    // once exceeded, emit the existing truncation sentinel exactly once and
    // suppress every further line while the runner drains the rest of the
    // child's output.
    bool truncated = false;
    std::size_t total_bytes = 0;
    opts.on_line = [&ctx, &truncated, &total_bytes](const std::string& line) {
        if (truncated)
            return;
        // BR-03 (whole-branch review, supersedes the reasoning this comment
        // used to carry): counting ONLY line.size() means a completed line
        // with NO content -- a blank line -- adds zero bytes to the budget.
        // A newline-only producer (e.g. `yes ''`, or any command that spams
        // blank lines under a long timeout) then never trips the cap at
        // all: total_bytes stays at 0 while an unbounded number of
        // "stdout|" RUNNING records get written to ctx/gRPC/server storage,
        // defeating the very cap this counter exists to enforce -- an
        // availability/response-volume issue, not just an off-by-one.
        // Counting `line.size() + 1` (one delimiter byte per completed
        // line) closes that gap; the previously-cited risk -- overcounting
        // an unterminated final line by one byte -- is immaterial next to
        // letting the cap be bypassed entirely.
        total_bytes += line.size() + 1;
        if (total_bytes > kMaxOutputBytes) {
            truncated = true;
            ctx.write_output("stdout|[output truncated — exceeded 16 MiB limit]");
            return;
        }
        ctx.write_output(std::format("stdout|{}", line));
    };

    auto run = yuzu::agent::run_bounded_subprocess(argv, opts);
    // BR-001: forward a runner-level failure (deadline/cancelled/signaled/
    // spawn_error) through the ABI4 CC-07 result-status seam BEFORE the
    // switch below flattens termination_reason into this plugin's own
    // status|/exit_code| wire text. Without this call the terminal
    // CommandResponse carries only PLUGIN_RESULT_UNDECLARED, and an
    // MCP/Reflex consumer can no longer distinguish "ran and failed"
    // (retry) from "killed at deadline" (escalate) from "spawn error"
    // (never retry) -- exactly ADR-3002's "Honest termination reporting"
    // requirement, and the same one-line pattern every other migrated
    // mutating plugin uses (services_plugin.cpp, network_actions_plugin.cpp,
    // interaction_plugin.cpp).
    yuzu::agent::forward_runner_failure(ctx, run);

    std::string status;
    int exit_code = run.exit_code;
    switch (run.termination_reason) {
    case yuzu::agent::TerminationReason::deadline:
    case yuzu::agent::TerminationReason::cancelled:
        // cancelled has no old-code precedent (the deleted fork/exec paths
        // had no cancellation concept at all) but is the same *shape* of
        // outcome as a deadline on this plugin's wire protocol — the runner
        // killed the child before it exited on its own — so it gets the
        // same status token rather than a fabricated third case.
        status = "timeout";
        break;
    case yuzu::agent::TerminationReason::spawn_error:
        status = "error";
        exit_code = -1;
        break;
    default: // exited, signaled, line_limit (line_limit is unreachable here:
             // this plugin never sets max_lines/stop_after_max_lines)
        status = (exit_code == 0) ? "ok" : "error";
        break;
    }

    ctx.write_output(std::format("exit_code|{}", exit_code));
    ctx.write_output(std::format("status|{}", status));
    return status == "ok" ? 0 : 1;
}

// ── exec action ────────────────────────────────────────────────────────────

int do_exec(yuzu::CommandContext& ctx, yuzu::Params params) {
    auto command = std::string(params.get("command"));
    if (command.empty()) {
        ctx.write_output("error|'command' parameter is required");
        return 1;
    }

    auto args_str = std::string(params.get("args"));
    int timeout = parse_timeout(params);

#ifdef _WIN32
    constexpr bool kWindowsRules = true;
#else
    constexpr bool kWindowsRules = false;
#endif

    // Captured ONCE and reused for both PATH-search resolution and the
    // child's env below -- two independent getenv("PATH") reads could
    // observe different values across a concurrent environment mutation,
    // resolving the binary through one PATH but launching the child with
    // another.
    auto env_allowlist = parent_env_allowlist();
    std::string_view path_value;
    for (const auto& [name, value] : env_allowlist) {
        if (name == "PATH") {
            path_value = value;
            break;
        }
    }
    auto path_entries = yuzu::script_exec::split_path_entries(path_value, kWindowsRules);

    // BR3-001: on Windows this is a real GetSystemDirectoryW resolution
    // (cached in the runner), not a compile-time literal -- fail the
    // action closed if it comes back empty rather than silently anchoring
    // against a relative/empty cwd. Always non-empty on POSIX.
    auto default_cwd = runner_default_cwd();
    if (default_cwd.empty()) {
        ctx.write_output("error|failed to resolve Windows system directory");
        ctx.write_output("status|error");
        ctx.write_output("exit_code|-1");
        return 1;
    }

#ifdef _WIN32
    // BR4-003 (whole-branch review round 4): a bare Windows `command` used
    // to search ONLY the captured PATH, narrower than the deleted
    // CreateProcessA(lpApplicationName=nullptr) call's search contract,
    // which additionally checked (in order) the calling application's own
    // directory and the system directory before ever consulting PATH --
    // breaking a helper installed beside the agent binary, or one that
    // relied on the system-directory stage, with no PATH entry added for
    // it. Explicitly reconstructs those two earlier stages -- trusted
    // application directory, then the SAME runtime-resolved system
    // directory `default_cwd` above already is on Windows (no second
    // GetSystemDirectoryW call) -- ahead of the captured PATH, while still
    // deliberately EXCLUDING the daemon's own current working directory
    // (ADR-3002 A6, BR-009: a potentially attacker-influenced value that
    // was never part of this hardening's intent to restore). Windows'
    // remaining CreateProcess search stage (the 16-bit Windows directory)
    // has no accessible resolution API and is 16-bit-application-only, so
    // it is not reconstructed -- there is no in-tree caller for which it
    // could ever matter. `current_executable_path()` (updater.hpp) is a
    // best-effort addition: if it fails to resolve, the app-directory
    // stage is simply omitted rather than failing the whole action closed
    // -- unlike default_cwd's own resolution above, a missing app
    // directory only means fewer places are searched, never a wrong or
    // untrusted one.
    // BR-007 (adversarial review, HIGH): `.string()` on a
    // std::filesystem::path narrows the native wide path through the
    // process' ACTIVE CODE PAGE, not UTF-8 -- an install path containing a
    // character outside that code page would silently corrupt or throw.
    // content_dist_exec_seam.hpp's identical app-directory-search-stage
    // problem is already solved correctly via yuzu::win::from_wide() on the
    // wide form directly (win_str.hpp, already included above); match that
    // pattern here instead of round-tripping through .string().
    std::vector<std::string> windows_search_dirs;
    if (auto app_dir_wide = yuzu::agent::current_executable_path().parent_path();
        !app_dir_wide.empty()) {
        if (auto app_dir = yuzu::win::from_wide(app_dir_wide.c_str()); !app_dir.empty())
            windows_search_dirs.push_back(std::move(app_dir));
    }
    windows_search_dirs.push_back(default_cwd); // == windows_system_directory() here
    windows_search_dirs.insert(windows_search_dirs.end(), path_entries.begin(),
                               path_entries.end());
    const std::vector<std::string>& search_dirs = windows_search_dirs;
#else
    const std::vector<std::string>& search_dirs = path_entries;
#endif

    auto resolved = yuzu::script_exec::resolve_executable(command, default_cwd, search_dirs,
                                                           is_executable_probe, kWindowsRules);
    if (!resolved) {
        // Matches the deleted paths' own early-setup-failure shape: status
        // before exit_code, unlike the post-runner-return order below.
        ctx.write_output("status|error");
        ctx.write_output("exit_code|-1");
        return 1;
    }

    // BR4-002 (whole-branch review round 4): `windows_rules` selects the
    // CRT-compatible split on Windows (split_args_windows) instead of the
    // POSIX-quoting split (split_args) -- see assemble_argv's own comment.
    auto argv = yuzu::script_exec::assemble_argv(yuzu::script_exec::ExecMode::exec, *resolved,
                                                 args_str, "", kWindowsRules);
    return run_via_runner(ctx, argv, timeout, std::move(env_allowlist));
}

// ── powershell action ──────────────────────────────────────────────────────

int do_powershell(yuzu::CommandContext& ctx, yuzu::Params params) {
#ifndef _WIN32
    ctx.write_output("error|powershell action is Windows-only");
    ctx.write_output("status|error");
    return 1;
#else
    auto script = std::string(params.get("script"));
    if (script.empty()) {
        ctx.write_output("error|'script' parameter is required");
        return 1;
    }

    int timeout = parse_timeout(params);

    // BR3-001 (whole-branch review round 3): resolved via
    // yuzu::agent::windows_system_directory() (GetSystemDirectoryW,
    // cached), not the compile-time literal this used to be -- an install
    // with Windows on a non-C: volume would otherwise trust an untrusted,
    // attacker-populatable "C:\Windows\System32" tree as the PowerShell
    // launch root. Fail the action closed on resolution failure -- never
    // fall back to a bare "powershell.exe" that would reintroduce a PATH
    // search (the exact issue this migration's absolute-path launch
    // already improved on pre-migration bare CreateProcessA(powershell.exe)).
    const std::string& sys_dir = yuzu::agent::windows_system_directory();
    if (sys_dir.empty()) {
        ctx.write_output("error|failed to resolve Windows system directory");
        ctx.write_output("status|error");
        ctx.write_output("exit_code|-1");
        return 1;
    }
    const std::string powershell_path = sys_dir + "\\WindowsPowerShell\\v1.0\\powershell.exe";

    // Use -EncodedCommand with Base64-encoded UTF-16LE to avoid all escaping issues.
    // This prevents any shell metacharacter injection.
    std::vector<uint8_t> utf16le;
    utf16le.reserve(script.size() * 2);
    for (char ch : script) {
        utf16le.push_back(static_cast<uint8_t>(ch));
        utf16le.push_back(0); // High byte (ASCII → UTF-16LE)
    }

    // Base64 encode
    DWORD b64_len = 0;
    CryptBinaryToStringA(utf16le.data(), static_cast<DWORD>(utf16le.size()),
                         CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, nullptr, &b64_len);
    std::string b64(b64_len, '\0');
    CryptBinaryToStringA(utf16le.data(), static_cast<DWORD>(utf16le.size()),
                         CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, b64.data(), &b64_len);
    b64.resize(b64_len);

    auto argv = yuzu::script_exec::assemble_argv(yuzu::script_exec::ExecMode::powershell,
                                                 powershell_path, "", b64, /*windows_rules=*/true);
    return run_via_runner(ctx, argv, timeout, parent_env_allowlist());
#endif
}

// ── bash action ────────────────────────────────────────────────────────────

int do_bash(yuzu::CommandContext& ctx, yuzu::Params params) {
#ifdef _WIN32
    ctx.write_output("error|bash action is not available on Windows");
    ctx.write_output("status|error");
    return 1;
#else
    auto script = std::string(params.get("script"));
    if (script.empty()) {
        ctx.write_output("error|'script' parameter is required");
        return 1;
    }

    int timeout = parse_timeout(params);

    // Pass script as a single argv element to bash -c (no shell expansion
    // by this outer spawn — bash itself is the interpreter, ADR-3002
    // Decision 5).
    auto argv = yuzu::script_exec::assemble_argv(yuzu::script_exec::ExecMode::bash, "", "", script,
                                                 /*windows_rules=*/false);
    return run_via_runner(ctx, argv, timeout, parent_env_allowlist());
#endif
}

// ── ABI4 capability declarations (#2204) ────────────────────────────────────
//
// exec: clean pre-split argv through yuzu::agent::run_bounded_subprocess --
// no shell interpretation of any kind -- rung 2 on every OS.
// powershell: spawns powershell.exe directly (no /bin/sh wrapper), but
// PowerShell is itself a scripting interpreter executing the caller's
// script text -- an interpreter payload, rung 3, same principle as
// interaction's osascript leg. Windows-only; the code returns an explicit
// "Windows-only" error elsewhere.
// bash: {"/bin/bash", "-c", script} through the same runner -- bash is the
// interpreter executing the caller's script text -- rung 3. Linux/macOS
// only; the code returns an explicit "not available on Windows" error there.
const YuzuActionDescriptor kActionDescriptors[] = {
    {"exec",
     /* linux   = */ {YUZU_SUPPORT_SUPPORTED, 2, "subprocess_runner:direct_argv", nullptr},
     /* macos   = */ {YUZU_SUPPORT_SUPPORTED, 2, "subprocess_runner:direct_argv", nullptr},
     /* windows = */ {YUZU_SUPPORT_SUPPORTED, 2, "subprocess_runner:direct_argv", nullptr}},
    {"powershell",
     /* linux   = */ {YUZU_SUPPORT_UNSUPPORTED, 0, nullptr, nullptr},
     /* macos   = */ {YUZU_SUPPORT_UNSUPPORTED, 0, nullptr, nullptr},
     /* windows = */
     {YUZU_SUPPORT_SUPPORTED, 3, "subprocess_runner:powershell_encodedcommand", nullptr}},
    {"bash",
     /* linux   = */ {YUZU_SUPPORT_SUPPORTED, 3, "subprocess_runner:bash_c", nullptr},
     /* macos   = */ {YUZU_SUPPORT_SUPPORTED, 3, "subprocess_runner:bash_c", nullptr},
     /* windows = */ {YUZU_SUPPORT_UNSUPPORTED, 0, nullptr, nullptr}},
};

} // namespace

class ScriptExecPlugin final : public yuzu::Plugin {
public:
    std::string_view name() const noexcept override { return "script_exec"; }
    std::string_view version() const noexcept override { return "1.1.0"; }
    std::string_view description() const noexcept override {
        return "Executes commands and scripts with streaming output (admin-only)";
    }

    const char* const* actions() const noexcept override {
        static const char* acts[] = {"exec", "powershell", "bash", nullptr};
        return acts;
    }

    const YuzuActionDescriptor* action_descriptors() const noexcept override {
        return kActionDescriptors;
    }
    size_t action_descriptor_count() const noexcept override {
        return sizeof(kActionDescriptors) / sizeof(kActionDescriptors[0]);
    }

    yuzu::Result<void> init(yuzu::PluginContext& /*ctx*/) override { return {}; }

    void shutdown(yuzu::PluginContext& /*ctx*/) noexcept override {}

    int execute(yuzu::CommandContext& ctx, std::string_view action, yuzu::Params params) override {
        if (action == "exec")
            return do_exec(ctx, params);
        if (action == "powershell")
            return do_powershell(ctx, params);
        if (action == "bash")
            return do_bash(ctx, params);

        ctx.write_output(std::format("unknown action: {}", action));
        return 1;
    }
};

YUZU_PLUGIN_EXPORT(ScriptExecPlugin)
