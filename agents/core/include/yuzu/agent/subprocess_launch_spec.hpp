#pragma once

/**
 * subprocess_launch_spec.hpp -- pure, allocation-only "what would we launch"
 * core for the agent-core subprocess runner (ADR-3002 best-practice
 * addendum, item B1).
 *
 * Mirrors the repo's `*_parsers.hpp` pattern (see e.g.
 * agents/plugins/firewall/src/firewall_parsers.hpp): every function here is a
 * pure free function over plain data -- no fork(), no CreateProcess(), no
 * filesystem/env I/O of its own -- so the argv/env validation, the Colascione
 * Windows command-line quoting, the allow-list environment shape, and the
 * rlimit/exec-verification options can all be golden-asserted on the
 * returned LaunchSpec in a unit test, without ever spawning a process
 * (CLAUDE.md test discipline: the real fork/exec bounded-real-child tests in
 * test_subprocess_runner.cpp remain the integration layer this does not
 * replace).
 *
 * subprocess_runner.cpp's run_bounded_subprocess() calls build_launch_spec()
 * to get its validated argv, its allow-list envp, and (on Windows) its
 * pre-quoted command line -- the actual fork()/execve()/CreateProcessW() call
 * and the deadline/reap/kill loop stay exactly the shipped implementation;
 * only the "what to launch" decision moves through this pure core.
 *
 * Header-only (every function is `inline`) and NOT declared YUZU_EXPORT: it
 * is included directly by subprocess_runner.cpp and by
 * test_subprocess_runner.cpp (test-only), both in-tree translation units --
 * it never needs a stable cross-DSO ABI the way subprocess_runner.hpp does,
 * and being header-only means adding it costs no new meson.build target.
 */

#include <algorithm>
#include <cctype>
#include <cstddef> // std::size_t/std::ptrdiff_t (cpp-expert A2: transitive-only via
                   // other headers today; included explicitly since this header
                   // uses both directly)
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace yuzu::agent {

/** Why build_launch_spec rejected an argv/opts pair outright (no OS call was
 *  ever attempted for one of these). */
enum class LaunchSpecError {
    none,
    empty_argv,
    relative_argv0,
    embedded_nul,
    banned_windows_extension, // .bat/.cmd/.com as argv[0] (CVE-2024-24576; ADR-3002:537-606)
    denied_env_var, // LaunchOptions::extra_env named a denylisted or malformed
                     // variable (see merge_launch_env) -- the launch is
                     // refused whole rather than proceeding with that one
                     // entry silently dropped.
};

/** One assembled environment variable, KEY and VALUE kept separate so a test
 *  can assert on either without re-parsing a "KEY=VALUE" blob. */
struct EnvVar {
    std::string key;
    std::string value;

    friend bool operator==(const EnvVar&, const EnvVar&) = default;
};

/** Everything the OS shell needs to launch a child, precomputed and
 *  validated by build_launch_spec() -- no I/O touched constructing it. */
struct LaunchSpec {
    LaunchSpecError error = LaunchSpecError::none;

    std::vector<std::string> argv; // validated; argv[0] absolute, no embedded NUL
    std::vector<EnvVar> env;        // A5: clear-and-allow-list, built here from nothing
    std::string working_dir;        // A6: resolved cwd (non-empty once error == none)
    std::uint32_t umask_value = 0077; // A6 (POSIX only; ignored by the Windows shell)
    bool merge_stderr = false;

    // A2/Windows: the fully Colascione-quoted single command-line string.
    // Precomputed unconditionally (pure string logic, no Win32 dependency) so
    // its shape is testable on every platform, even though only the Windows
    // shell ever consumes it.
    std::string windows_command_line;

    // A2-002/BR-001 (whole-branch review round 2): pure passthrough of
    // LaunchOptions::inherit_parent_env -- see that field's comment. `env`
    // above is ALWAYS computed the ordinary way regardless of this flag
    // (this header does no OS I/O to honour it); BOTH OS shells in
    // subprocess_runner.cpp now branch on it, each substituting a live-read
    // parent environment (with extra_env layered on top via the same
    // merge_launch_env() below, and -- POSIX only -- the ADR-3002 A5
    // injection class stripped via filter_inherited_env() below) for `env`
    // at the point they actually build the child's environment block.
    // Default false.
    bool inherit_parent_env = false;

    // BR4-007 (whole-branch review round 4): pure passthrough of
    // SubprocessOptions::no_window (subprocess_runner.hpp -- see that
    // field's doc comment for the full contract). Windows-only
    // significance; the POSIX shell never reads this field. Default false.
    bool no_window = false;

    // A1/Windows: which handles the shell must mark inheritable and name in
    // PROC_THREAD_ATTRIBUTE_HANDLE_LIST -- expressed as roles rather than
    // live HANDLEs (which don't exist yet at spec-build time), so a test can
    // assert the list's *shape* without ever calling into Win32.
    struct WindowsHandlePolicy {
        bool inherit_stdout_write = true;
        // True iff merge_stderr routes stderr onto the SAME pipe as stdout --
        // kept as its own bool (rather than always mirroring
        // inherit_stdout_write) so a test can assert the named handle list
        // never grows past exactly what merge_stderr requires.
        bool inherit_stderr_write = false;
    } windows_handles;

    // B3: optional per-invocation rlimit caps, all unset (off) unless the
    // caller opted in via LaunchOptions.
    struct Rlimits {
        std::optional<std::uint64_t> cpu_seconds;
        std::optional<std::uint64_t> address_space_bytes;
        std::optional<std::uint64_t> fsize_bytes;
        std::optional<std::uint64_t> nofile_count;
    } rlimits;

    // B6: TOCTOU-safe exec verification, disabled unless the caller opted in.
    // Runner primitive only -- no in-tree caller enables this in this PR.
    struct ExecVerification {
        bool enabled = false;
        bool require_root_owned = true;
        std::optional<std::uint64_t> expected_size;
    } exec_verify;
};

/** Inputs to build_launch_spec -- a deliberately narrow mirror of
 *  SubprocessOptions' launch-SHAPING fields, not its runtime-polling fields
 *  (deadline/max_lines/on_line/... stay entirely the OS shell's concern).
 *  Its own type rather than reusing SubprocessOptions so this header has
 *  zero dependency on subprocess_runner.hpp -- no include cycle, no
 *  YUZU_EXPORT need. */
struct LaunchOptions {
    std::optional<std::string> working_dir;
    bool merge_stderr = false;
    std::optional<std::string> tz; // passed through from the parent's TZ, if set
    LaunchSpec::Rlimits rlimits;
    LaunchSpec::ExecVerification exec_verify;

    // Mirror of SubprocessOptions::extra_env (subprocess_runner.hpp) -- see
    // that field's doc comment for the full contract (bounded widening of
    // A5, replace-in-place semantics, fail-closed denylist). Empty by
    // default. Merged onto the A5 allow-list by build_launch_spec() via
    // merge_launch_env() below.
    std::vector<EnvVar> extra_env;

    // A2-002/BR-001 (Alex plan-gate rulings -- script_exec's Windows-parity
    // escalation, then content_dist's whole-branch-review round-2 POSIX
    // extension): mirror of SubprocessOptions::inherit_parent_env
    // (subprocess_runner.hpp) -- see that field's doc comment for the full
    // contract. Pure PASSTHROUGH only: this header never reads the live
    // process environment (it is a pure, allocation-only core -- see the
    // file header), so build_launch_spec() below copies this flag onto
    // LaunchSpec unchanged and otherwise computes `env` exactly as it always
    // has (default_launch_env() + extra_env). The impure OS shells in
    // subprocess_runner.cpp are what actually branch on
    // spec.inherit_parent_env -- BOTH backends now (see
    // filter_inherited_env() below for the POSIX-only injection-class strip
    // that backend layers on top). Default false, matching
    // SubprocessOptions'.
    bool inherit_parent_env = false;

    // BR4-007 (whole-branch review round 4): mirror of
    // SubprocessOptions::no_window (subprocess_runner.hpp). Pure
    // PASSTHROUGH only, like inherit_parent_env above -- build_launch_spec()
    // copies it onto LaunchSpec unchanged; the Windows OS shell in
    // subprocess_runner.cpp is what actually ORs CREATE_NO_WINDOW into its
    // create_flags when set. Default false.
    bool no_window = false;
};

/** The bare outcome a Spawner reports for a LaunchSpec. Deliberately minimal
 *  (does not carry captured output/timing) -- it exists to prove the
 *  injection seam (see Spawner below) is independently testable, not to
 *  replace SubprocessResult. */
struct SpawnOutcome {
    bool tool_ran = false;
    int exit_code = -1;
    bool spawn_error = false;
};

/**
 * Injectable seam between a validated LaunchSpec and the real OS call
 * (fork()+execve() on POSIX, CreateProcessW() on Windows). Production code
 * has no concrete Spawner today -- run_bounded_subprocess's shipped
 * fork/exec/deadline/reap loop is kept exactly as-is per this package's
 * "without redoing its core" boundary, so nothing in subprocess_runner.cpp's
 * hot path is instantiated through this interface. It exists so a unit test
 * can substitute a scripted fake and exercise "does build_launch_spec's
 * output make sense to hand to a spawner" without ever creating a process;
 * see test_subprocess_runner.cpp's B1 test block for the fake in use.
 */
class Spawner {
public:
    virtual ~Spawner() = default;
    virtual SpawnOutcome spawn(const LaunchSpec& spec) = 0;
};

namespace detail {

inline bool contains_nul(const std::string& s) {
    return s.find('\0') != std::string::npos;
}

/// Explicit ASCII-only case fold: uppercases 'a'-'z' byte-wise and leaves
/// every other byte untouched. Deliberately NOT std::toupper -- that function
/// is C-locale-dependent (a global, process-wide, mutable setting) and
/// operating on a security allow/deny-list must not vary with whatever
/// locale happens to be active. This also means it is honestly ASCII-only:
/// it never claims to fold non-ASCII bytes (see is_ascii()/the ASCII-only
/// env-name restriction below for why a non-ASCII name never reaches here
/// needing a fold in the first place).
inline std::string to_upper_ascii(const std::string& s) {
    std::string out = s;
    for (char& c : out) {
        if (c >= 'a' && c <= 'z')
            c = static_cast<char>(c - ('a' - 'A'));
    }
    return out;
}

/** True iff every byte of `s` is 7-bit US-ASCII (0x00-0x7F).
 *
 *  Environment-variable NAMES are restricted to ASCII (see
 *  is_malformed_env_entry) rather than this header attempting a
 *  host-independent case-insensitive Unicode comparison for the Windows
 *  REPLACE-matching in merge_launch_env(): Windows' environment-block
 *  contract calls for locale-independent *ordinal* Unicode case folding,
 *  which byte-wise ASCII-only to_upper_ascii() cannot provide -- a non-ASCII
 *  pair like "\xc3\x85VAR" ("AVAR" with a Latin capital A-ring) and
 *  "\xc3\xa5var" (its lowercase form) would silently survive as two distinct
 *  entries, breaking the replace-never-duplicate guarantee and leaving which
 *  value the child observes ambiguous -- exactly the hazard this is a
 *  security boundary against. The only in-tree caller (the planned
 *  script_exec allow-list) uses ASCII names, so rejecting non-ASCII
 *  fail-closed through the existing malformed-entry path is the strictly
 *  smaller, more conservative choice over implementing (and testing) a full
 *  ordinal Unicode fold for a case with no current caller. If a future
 *  caller genuinely needs non-ASCII environment names, that is a deliberate
 *  widening requiring its own ordinal-fold implementation and test
 *  coverage, not a relaxation of this check. */
inline bool is_ascii(const std::string& s) {
    return std::all_of(s.begin(), s.end(),
                        [](char c) { return static_cast<unsigned char>(c) < 0x80; });
}

/** True iff `name` is refused outright by the ADR-3002 A5 strip list --
 *  default_launch_env's own comment enumerates the same set: the LD_ and
 *  DYLD_ dynamic-linker-injection prefixes, and the exact interpreter/locale-hijack
 *  names IFS, BASH_ENV, ENV, GCONV_PATH, NLSPATH, LOCPATH. Matching follows
 *  the target `windows` was built for -- exact-case on POSIX (real POSIX env
 *  names are case-sensitive, so "ld_preload" is a genuinely different
 *  variable from "LD_PRELOAD" there and rejecting it anyway would be an
 *  unspecified, unnecessary contract widening) and case-insensitive on
 *  Windows via to_upper_ascii() (matching the base/extra REPLACE matching in
 *  merge_launch_env(), which the caller below must pass the identical
 *  `windows` value into). */
inline bool is_denied_env_name(const std::string& name, bool windows) {
    // On POSIX `candidate` is `name` untouched, so these upper-case literals
    // only match a name that is ITSELF upper-case -- exact-case comparison,
    // not a case-insensitive one. On Windows `candidate` is upper-cased
    // first, so the same literals catch any casing.
    const std::string candidate = windows ? to_upper_ascii(name) : name;
    if (candidate.rfind("LD_", 0) == 0 || candidate.rfind("DYLD_", 0) == 0)
        return true;
    static constexpr std::string_view kDeniedExact[] = {"IFS",        "BASH_ENV", "ENV",
                                                         "GCONV_PATH", "NLSPATH",  "LOCPATH"};
    for (const auto& denied : kDeniedExact) {
        if (candidate == denied)
            return true;
    }
    return false;
}

/** Malformed per build_launch_spec's extra_env contract: an empty name, a
 *  name containing '=' (ambiguous once serialized as "KEY=VALUE") or a NUL,
 *  a non-ASCII byte in the name (see is_ascii() -- A0-002: this header does
 *  not implement Windows ordinal Unicode case folding, so a non-ASCII name
 *  is rejected fail-closed rather than risk two names the real OS treats as
 *  one both silently surviving merge_launch_env()), or a value containing a
 *  NUL. */
inline bool is_malformed_env_entry(const EnvVar& v) {
    if (v.key.empty())
        return true;
    if (v.key.find('=') != std::string::npos)
        return true;
    if (contains_nul(v.key))
        return true;
    if (!is_ascii(v.key))
        return true;
    if (contains_nul(v.value))
        return true;
    return false;
}

/** POSIX ('/...') or Windows ('C:\...', 'C:/...', '\\server\share') absolute
 *  path check. Shared by both platform shells so argv[0]'s "must be
 *  absolute" contract is defined exactly once. */
inline bool is_absolute_path(const std::string& p) {
    if (p.empty())
        return false;
    if (p.front() == '/')
        return true;
    if (p.size() >= 3 && std::isalpha(static_cast<unsigned char>(p[0])) != 0 && p[1] == ':' &&
        (p[2] == '\\' || p[2] == '/'))
        return true;
    if (p.size() >= 2 && p[0] == '\\' && p[1] == '\\')
        return true;
    return false;
}

inline bool ends_with_ci(const std::string& s, std::string_view suffix) {
    if (s.size() < suffix.size())
        return false;
    return std::equal(s.end() - static_cast<std::ptrdiff_t>(suffix.size()), s.end(), suffix.begin(),
                       [](char a, char b) { return std::tolower(static_cast<unsigned char>(a)) == b; });
}

/** Windows ADR-3002 ban: .bat/.cmd/.com can never be exec'd safely as
 *  argv[0] by quoting alone (CVE-2024-24576 for .bat/.cmd; .com banned
 *  alongside as defense-in-depth). Checked on every platform (cheap, and
 *  keeps the spec's validation platform-independent) even though only the
 *  Windows shell can ever actually be handed one of these. */
inline bool is_banned_windows_extension(const std::string& path) {
    return ends_with_ci(path, ".bat") || ends_with_ci(path, ".cmd") || ends_with_ci(path, ".com");
}

} // namespace detail

/// A5 clear-and-allow-list env, built from nothing for the target OS
/// (`windows == true` selects the Windows allow-list). Pure and host-agnostic
/// so both branches are unit-testable on any host -- build_launch_spec() calls
/// it with the compile target.
///
/// CDX-P2-008: Windows children must NOT receive the POSIX `PATH`
/// (`/usr/bin:...`) or `LC_ALL=C` -- those are meaningless there and a migrated
/// tool that consults PATH/locale/temp would observe nonsense. The Windows list
/// is the minimal deterministic system set: `SystemRoot`/`windir` (required by
/// many Win32 APIs), the canonical system search `PATH`, and a machine-wide
/// `TEMP`/`TMP`. Values are the canonical defaults (a `C:` system volume); a
/// future real Windows caller that must honour a relocated system root threads
/// the actual paths through `opts` rather than reading the parent environment
/// (which A5's clear-slate forbids). Locale is left to the system default -- no
/// LC_ALL analogue is imposed.
inline std::vector<EnvVar> default_launch_env(bool windows,
                                              const std::optional<std::string>& tz) {
    std::vector<EnvVar> env;
    if (windows) {
        env.push_back({"SystemRoot", "C:\\Windows"});
        env.push_back({"windir", "C:\\Windows"});
        env.push_back({"PATH", "C:\\Windows\\system32;C:\\Windows;C:\\Windows\\System32\\Wbem"});
        env.push_back({"TEMP", "C:\\Windows\\Temp"});
        env.push_back({"TMP", "C:\\Windows\\Temp"});
    } else {
        // LD_*/DYLD_*/IFS/BASH_ENV/GCONV_PATH are stripped by construction
        // (never added, so there is nothing to strip from).
        env.push_back({"PATH", "/usr/bin:/bin:/usr/sbin:/sbin"});
        env.push_back({"LC_ALL", "C"});
    }
    if (tz && !tz->empty())
        env.push_back({"TZ", *tz});
    return env;
}

/** Outcome of merge_launch_env(): the merged environment (accepted entries
 *  only), plus the names of any `extra` entries that were refused outright.
 *  build_launch_spec() treats a non-empty `rejected` as fatal -- see
 *  LaunchSpecError::denied_env_var -- but the merge itself still reports
 *  which name(s) triggered it rather than just a bool, so a caller/test can
 *  pin down exactly what was refused. */
struct EnvMergeResult {
    std::vector<EnvVar> env;
    std::vector<std::string> rejected;
};

/// Merges `extra` (caller-supplied, e.g. SubprocessOptions::extra_env) onto
/// `base` (e.g. default_launch_env()'s A5 allow-list): an extra entry whose
/// name matches an existing base entry REPLACES it in place -- base order is
/// otherwise preserved, and a same-named entry is NEVER appended as a second,
/// duplicate entry (duplicate env names are ambiguous to execve/
/// CreateProcessW alike); an entry with a new name is appended in caller
/// order. Every `extra` entry is validated first (see is_denied_env_name/
/// is_malformed_env_entry) -- a denylisted or malformed entry is NOT applied
/// and its name is added to the returned `rejected` list instead; the caller
/// (build_launch_spec) is expected to treat any non-empty `rejected` as
/// fatal for the WHOLE launch (fail closed), never apply the other,
/// individually-valid entries as a partial success.
///
/// `windows` selects the REPLACE-matching rule, and must match the target
/// default_launch_env() was built for: real POSIX environment names are
/// case-sensitive (an extra "path" would coexist alongside a base "PATH" as
/// two distinct variables), so POSIX matching is exact-case; real Windows
/// environment blocks are case-insensitive (MSDN: CreateProcess's
/// lpEnvironment "must be sorted alphabetically... case-insensitively", and
/// the OS itself treats "Path"/"PATH" as the same variable), so leaving a
/// Windows merge case-sensitive would let an extra "Path" survive alongside
/// base "PATH" as two entries in spec.env that the real OS collapses to one
/// on the other side of CreateProcessW -- silently ambiguous in exactly the
/// way the "replace, never duplicate" contract exists to prevent. Windows
/// matching here is therefore case-insensitive, matching the OS it targets.
inline EnvMergeResult merge_launch_env(const std::vector<EnvVar>& base, const std::vector<EnvVar>& extra,
                                       bool windows) {
    EnvMergeResult result;
    result.env = base;
    for (const auto& entry : extra) {
        if (detail::is_malformed_env_entry(entry) || detail::is_denied_env_name(entry.key, windows)) {
            result.rejected.push_back(entry.key);
            continue;
        }
        auto it = std::find_if(result.env.begin(), result.env.end(), [&](const EnvVar& existing) {
            if (windows)
                return detail::to_upper_ascii(existing.key) == detail::to_upper_ascii(entry.key);
            return existing.key == entry.key;
        });
        if (it != result.env.end())
            it->value = entry.value; // replace in place -- never a second, ambiguous same-named entry
        else
            result.env.push_back(entry); // new name -- appended in caller order
    }
    return result;
}

/** Outcome of filter_inherited_env(): the accepted entries, plus the names
 *  of any that were stripped (for caller-side logging). */
struct EnvInheritResult {
    std::vector<EnvVar> env;
    std::vector<std::string> stripped;
};

/// BR-001 (whole-branch review round 2, Alex ruling): filters a LIVE parent-
/// environment snapshot (`parent_env`, e.g. read from POSIX `environ` or
/// Windows' GetEnvironmentStringsW()) down to everything EXCEPT the
/// ADR-3002 A5 injection class -- reusing the exact same
/// detail::is_denied_env_name() predicate default_launch_env()'s comment
/// and merge_launch_env()'s extra_env check already share, so there is one
/// place, not three, that knows what that class is.
///
/// Deliberately NOT the same failure mode as merge_launch_env()'s handling
/// of extra_env: a denylisted NAME here is silently DROPPED from `env` (and
/// recorded in `stripped`) rather than treated as fatal for the whole
/// launch. extra_env is caller-authored -- a denied name there is the
/// caller's own mistake to fix, so failing the launch closed is the right
/// call. An INHERITED parent-environment variable is different: it is this
/// AGENT's own live environment, not something the caller supplied or
/// controls, so refusing to run every `inherit_parent_env` launch on a host
/// that happens to have `LD_PRELOAD` set in its environment would be
/// absurd -- the correct response is to withhold exactly that one variable
/// from the child and let the launch proceed. Silent here means "no
/// LaunchSpecError raised BY THIS FUNCTION" -- callers are expected to
/// still log `stripped` (see subprocess_runner.cpp's POSIX backend) so the
/// behaviour remains observable, just not launch-refusing.
inline EnvInheritResult filter_inherited_env(const std::vector<EnvVar>& parent_env, bool windows) {
    EnvInheritResult result;
    result.env.reserve(parent_env.size());
    for (const auto& entry : parent_env) {
        if (detail::is_denied_env_name(entry.key, windows)) {
            result.stripped.push_back(entry.key);
            continue;
        }
        result.env.push_back(entry);
    }
    return result;
}

/**
 * Colascione backslash-before-quote argv-element quoting: the algorithm the
 * Microsoft CRT's own command-line parser (and every parser that follows its
 * rules) expects. Operates byte-wise over the UTF-8 form directly -- '"' and
 * '\\' are single-byte ASCII in UTF-8 and never appear as a continuation
 * byte of a multi-byte sequence, so no decoding is needed to quote correctly.
 * Exposed standalone (not just inlined into build_launch_spec) so a unit
 * test can drive the edge vectors -- empty arg, embedded quote, trailing
 * backslash run, spaces, Unicode -- directly.
 */
inline std::string quote_windows_arg(const std::string& arg) {
    const bool needs_quotes = arg.empty() || arg.find_first_of(" \t\n\v\"") != std::string::npos;
    if (!needs_quotes)
        return arg;

    std::string out = "\"";
    std::size_t i = 0;
    while (true) {
        std::size_t backslashes = 0;
        while (i < arg.size() && arg[i] == '\\') {
            ++backslashes;
            ++i;
        }
        if (i == arg.size()) {
            // Backslashes immediately before the closing quote must be
            // doubled so the CRT parser doesn't read the last one as
            // escaping our terminator.
            out.append(backslashes * 2, '\\');
            break;
        }
        if (arg[i] == '"') {
            out.append(backslashes * 2 + 1, '\\');
            out += '"';
            ++i;
        } else {
            out.append(backslashes, '\\');
            out += arg[i];
            ++i;
        }
    }
    out += '"';
    return out;
}

/**
 * Pure validation + assembly: rejects exactly what run_bounded_subprocess's
 * runtime checks reject (empty argv, a non-absolute argv[0], an embedded NUL
 * in any element, a banned .bat/.cmd/.com extension) and, for a valid argv,
 * builds the full allow-list environment, the Colascione-quoted Windows
 * command line, and the handle-list/rlimit/exec-verify shape the OS shell
 * uses verbatim. No syscall; the only allocation is ordinary
 * std::string/std::vector growth -- safe to call, and to unit-test, without
 * ever spawning a process.
 */
inline LaunchSpec build_launch_spec(const std::vector<std::string>& argv, const LaunchOptions& opts) {
    LaunchSpec spec;

    // A5: clear-and-allow-list env target for this compile (CDX-P2-008:
    // Windows must not inherit the POSIX shape) -- computed here, ahead of
    // EVERY check below (BR-009 moved this up from just below the argv[0]
    // extension check, which used to run unconditionally on every target),
    // so both that check, the extra_env pre-check, and the later
    // default_launch_env()/merge_launch_env() calls share the one
    // definition.
#ifdef _WIN32
    constexpr bool kWindowsEnv = true;
#else
    constexpr bool kWindowsEnv = false;
#endif

    if (argv.empty()) {
        spec.error = LaunchSpecError::empty_argv;
        return spec;
    }
    if (!detail::is_absolute_path(argv.front())) {
        spec.error = LaunchSpecError::relative_argv0;
        return spec;
    }
    for (const auto& a : argv) {
        if (detail::contains_nul(a)) {
            spec.error = LaunchSpecError::embedded_nul;
            return spec;
        }
    }
    // BR-009 (whole-branch review round 2): is_banned_windows_extension's
    // CVE-2024-24576 rationale is a Windows cmd.exe/CreateProcess quoting
    // hazard specifically -- .bat/.cmd/.com are ordinary filename bytes on
    // POSIX, where execve() never re-interprets an argv[0] suffix at all.
    // Checking this unconditionally on every compile target (the previous
    // behaviour) made a genuine POSIX ELF/Mach-O binary that happened to be
    // named e.g. "agent.com" spawn_error on Linux/macOS for a Windows-only
    // reason. Gate on the SAME kWindowsEnv this function's env target uses,
    // not a runtime guess -- only a Windows-targeted build can ever hand
    // this argv[0] to CreateProcess in the first place.
    if (kWindowsEnv && detail::is_banned_windows_extension(argv.front())) {
        spec.error = LaunchSpecError::banned_windows_extension;
        return spec;
    }

    // Bounded widening of A5 (Alex plan-gate ruling, PLAN-04 option b):
    // pre-validate opts.extra_env BEFORE populating anything else on spec,
    // so a denied/malformed entry fails closed with the SAME clean, bare
    // spec (only .error set) every other rejection above returns -- never a
    // spec left half-populated from work this function abandons. The base
    // passed here is irrelevant to what gets rejected (is_denied_env_name/
    // is_malformed_env_entry look only at each `extra` entry), so an empty
    // placeholder base is fine; the real merge against the actual A5
    // allow-list happens again below once we know every entry is clean.
    if (!opts.extra_env.empty() &&
        !merge_launch_env({}, opts.extra_env, kWindowsEnv).rejected.empty()) {
        spec.error = LaunchSpecError::denied_env_var;
        return spec;
    }

    spec.argv = argv;
    spec.merge_stderr = opts.merge_stderr;
    spec.working_dir = opts.working_dir.value_or(std::string("/"));
    spec.umask_value = 0077;
    spec.rlimits = opts.rlimits;
    spec.exec_verify = opts.exec_verify;
    spec.inherit_parent_env = opts.inherit_parent_env; // pure passthrough -- see field comment
    spec.no_window = opts.no_window; // pure passthrough -- see field comment (BR4-007)

    // The per-OS allow-list lives in the pure, host-testable
    // default_launch_env(); extra_env (already validated above -- nothing
    // here can be rejected) is merged onto it, replacing same-named entries
    // in place. Skipped entirely when empty so every existing caller's
    // spec.env is untouched byte-for-byte (required no-regression
    // contract).
    spec.env = default_launch_env(kWindowsEnv, opts.tz);
    if (!opts.extra_env.empty())
        spec.env = merge_launch_env(spec.env, opts.extra_env, kWindowsEnv).env;

    for (std::size_t i = 0; i < spec.argv.size(); ++i) {
        if (i)
            spec.windows_command_line += ' ';
        spec.windows_command_line += quote_windows_arg(spec.argv[i]);
    }
    spec.windows_handles.inherit_stdout_write = true;
    spec.windows_handles.inherit_stderr_write = opts.merge_stderr;

    return spec;
}

} // namespace yuzu::agent
