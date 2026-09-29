#pragma once

// macos_console_user.hpp -- pure helpers for reaching the current macOS
// console (GUI) user's per-user session from a root/LaunchDaemon-context
// process, plus the certificates plugin's store->keychain mapping.
//
// Background: the agent's macOS process has no login keychain of its own --
// today it runs as root (no `UserName` key in com.yuzu.agent.plist; see
// docs/agent-privilege-model.md's TL;DR), and the target least-privilege
// `_yuzu` account (tracked as future hardening, #1455) would not have one
// either. `security` invoked directly therefore only ever sees the SYSTEM
// keychains, never the interactively-logged-in user's login keychain --
// that requires running the read INSIDE that user's per-user launchd/Aqua
// session: `[sudo -n -- ]launchctl asuser <uid> sudo -n -u <user> -- security ...`
// (see build_login_keychain_read_argv()'s own comment for exactly when
// the outer sudo applies).
//
// Every function here is pure (string parsing/validation/formatting only --
// no subprocess calls, no platform APIs), so the unit test
// (tests/unit/test_certificates_macos.cpp) exercises the exact logic the
// certificates plugin runs against fixture strings, without needing a real
// console session, `security`, or even to run on macOS at all -- same
// header-for-testability pattern as
// agents/plugins/installed_apps/src/installed_apps_inventory.hpp. The
// certificates_plugin.cpp .cpp file keeps the bounded-runner calls (stat/
// launchctl/sudo/security, all routed through
// yuzu::agent::run_bounded_subprocess -- see run_bounded_checked()) and the
// console-user RESOLUTION (whose device-owner half does need a subprocess;
// its uid/home half is a bounded passwd lookup since #3406, no longer the
// `id -u` spawn this line used to list); this header only ever sees strings
// it's handed.
//
// Deliberately framework-free: no SystemConfiguration
// (SCDynamicStoreCopyConsoleUser), so a CLT-only box still compiles this
// (matches the batch's no-new-framework convention).
//
// Injection guard: every value that ends up in the pre-split argv vector
// run_bounded_subprocess execs directly (no shell anywhere since #3406
// argv-ized this leg) -- console username, uid, home directory -- MUST pass
// is_valid_username / is_valid_uid / is_valid_home_dir here BEFORE use.
// With no shell there is no shell-metacharacter surface, but the allowlists
// are kept as ARGUMENT-injection defence (an option-shaped username like
// "-G" must never be read as a flag by sudo) and as defence in depth
// should a future caller regress the transport. build_login_keychain_
// read_argv() re-validates defensively and returns an empty vector on
// failure, so a missed guard upstream can never manufacture an executable
// command from unsafe input; the caller must treat an empty return as "do
// not run this."
//
// Owned solely by A-1.11 (mac-parity batch): the users (1.13) and
// interaction (1.22) plugins were already in flight when this header was
// authored and were deliberately NOT wired to it, so there is no
// cross-package collision today. A future package MAY reuse the
// console-user resolution helpers (parse_console_user_output /
// is_no_console_user / is_valid_username / is_valid_uid) for its own
// per-user-session needs; the store/keychain mapping below
// (KeychainStore / StorePlan / resolve_store_plan /
// resolve_delete_keychain_path) is certificates-plugin-specific and not
// intended for reuse as-is.

#include <cstdlib>
#include <format>
#include <optional>
#include <string>
#include <string_view>
#include <memory>
#include <type_traits>
#include <vector>

#include <sudo_argv.hpp> // yuzu::shared::sudo_wrap -- THE canonical sudo argv form

// SystemConfiguration is pulled in ONLY for console_user() below, and ONLY when the
// consuming plugin's meson defines YUZU_HAVE_SYSTEMCONFIGURATION (users plugin does; the
// certificates plugin does NOT -> it stays framework-free and console_user() compiles to the
// std::nullopt fallback there, which it never calls).
#if defined(__APPLE__) && defined(YUZU_HAVE_SYSTEMCONFIGURATION)
#include <CoreFoundation/CoreFoundation.h>
#include <SystemConfiguration/SystemConfiguration.h>
#endif

namespace yuzu::macos {

// ── Console user: parse + validate ──────────────────────────────────────────

// A resolved, VALIDATED console user. Constructing one outside
// resolve_console_user()-style call sites (which validate before
// populating this) is the caller's responsibility -- this struct itself
// does not re-check its fields.
struct ConsoleUser {
    std::string username;
    std::string uid;
    // The account's home directory, from the SAME passwd lookup that produced
    // `uid` (#3406). EMPTY means the lookup succeeded but returned a pw_dir
    // that is not a usable absolute path -- the console user is still validly
    // identified (username + uid are good), only the login-keychain leg is
    // unavailable, and the caller must emit an honest sentinel for that leg
    // rather than guessing a path. Never treat empty as "use the default".
    std::string home_dir;
};

namespace detail {

inline bool is_ascii_space(char c) {
    return c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v';
}

} // namespace detail

// Trim leading/trailing whitespace from the raw `stat -f%Su /dev/console`
// stdout. Defensive against both a trailing newline (the common case) and
// any incidental leading/trailing blanks -- independent of whatever
// trimming the caller's subprocess helper already does, so this is
// meaningfully testable against a RAW fixture string.
inline std::string parse_console_user_output(std::string_view raw_stat_output) {
    size_t begin = 0;
    size_t end = raw_stat_output.size();
    while (begin < end && detail::is_ascii_space(raw_stat_output[begin]))
        ++begin;
    while (end > begin && detail::is_ascii_space(raw_stat_output[end - 1]))
        --end;
    return std::string(raw_stat_output.substr(begin, end - begin));
}

// True when the parsed console-user string means "no interactive console
// session" (login window / headless / stat failure). `stat -f%Su
// /dev/console` reports the owner "root" for the login-window / no-session
// case (root is never a real interactively-logged-in console user on a
// supported endpoint) -- an empty string (e.g. `/dev/console` missing, or
// the subprocess itself failing) is treated the same way, honestly, rather
// than risking a later validation step silently accepting it.
inline bool is_no_console_user(std::string_view username) {
    return username.empty() || username == "root";
}

// Injection guard for the console username: a safe-identifier
// allowlist, NOT a full macOS-username-spec validator (macOS usernames
// technically allow a broader POSIX set) -- narrower is safer here. The
// value lands in a pre-split argv element (`sudo -u <username> ...`)
// execed directly with no shell (#3406), so the load-bearing half today is
// the leading-'-' argument-injection check below; the metacharacter
// allowlist is kept because every character outside it is otherwise
// unnecessary for any username this mechanism needs to support, and it
// stays defence in depth should a future caller regress the transport.
inline bool is_valid_username(std::string_view username) {
    if (username.empty())
        return false;
    // The first character may not be '-' (or '.'): a leading '-' would let
    // an option-like username (e.g. "--help", "-G") be misread as a flag by
    // `id -u <username>` rather than looked up as an account name -- this is
    // argument injection, distinct from (and in addition to) the
    // shell-metacharacter allowlist below. Real macOS account names always
    // start with a letter/digit/underscore in practice.
    const char first = username.front();
    const bool first_ok = (first >= 'A' && first <= 'Z') || (first >= 'a' && first <= 'z') ||
                          (first >= '0' && first <= '9') || first == '_';
    if (!first_ok)
        return false;
    for (char c : username) {
        const bool ok = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                        (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-';
        if (!ok)
            return false;
    }
    return true;
}

// Injection guard for the console user's uid: numeric-only, non-empty.
// (uid 0 would mean the console user is root, which is_no_console_user()
// already excludes upstream via the username check -- this function is
// purely a SYNTACTIC guard, not a semantic one.) Since #3406 the uid is a
// decimal format of getpwnam_r's pw_uid rather than the output of an
// `/usr/bin/id -u <username>` subprocess, so it is digits by construction
// and this guard is defensive; it is kept deliberately, because it is the
// shared gate every value entering the argv must pass and a future change
// to how the uid is sourced must not silently bypass it.
inline bool is_valid_uid(std::string_view uid) {
    if (uid.empty())
        return false;
    for (char c : uid) {
        if (c < '0' || c > '9')
            return false;
    }
    return true;
}

// ── Store -> keychain mapping ────────────────────────────────────────────────

// Named kDefault* (not kSystemKeychainPath) -- that identifier collides with
// a macro of the same name in Security/cssmapple.h
// (kSystemKeychainPath == kSystemKeychainDir kSystemKeychainName), which
// mangles this declaration wherever both headers are visible.
inline constexpr const char* kDefaultSystemKeychainPath = "/Library/Keychains/System.keychain";
inline constexpr const char* kRootKeychainPath =
    "/System/Library/Keychains/SystemRootCertificates.keychain";

// Test-only overrides (#4374), mirroring the YUZU_KEYCHAIN_PROBE_PATH hidden-
// probe precedent (tests/unit/test_keychain_read.cpp:332-336): read per call
// by design (never cached), so a single test process can point successive
// dispatches at different fixtures. Consulted by the READ paths only --
// list_certs_macos and details_cert_macos -- `delete` deliberately does not
// consult them (see resolve_delete_keychain_path below). A relative value is
// ignored, never resolved against the daemon cwd (same rule as
// is_valid_home_dir).
inline std::string system_keychain_path() {
    if (const char* override_path = std::getenv("YUZU_CERTIFICATES_SYSTEM_KEYCHAIN_PATH_OVERRIDE");
        override_path != nullptr && override_path[0] == '/') {
        return override_path;
    }
    return kDefaultSystemKeychainPath;
}

inline std::string root_keychain_path() {
    if (const char* override_path = std::getenv("YUZU_CERTIFICATES_ROOT_KEYCHAIN_PATH_OVERRIDE");
        override_path != nullptr && override_path[0] == '/') {
        return override_path;
    }
    return kRootKeychainPath;
}

// Guard for a caller-resolved home directory: absolute and non-empty.
// There is no shell anywhere downstream (the value lands in one pre-split
// argv element execed directly), so this is not a metacharacter allowlist
// -- it rejects only values that could never be a real macOS home
// directory (empty / relative), which would otherwise make `security`
// resolve a path against the daemon's own cwd.
inline bool is_valid_home_dir(std::string_view home_dir) {
    return !home_dir.empty() && home_dir.front() == '/';
}

// The console user's login keychain path, built from that user's HOME
// DIRECTORY as resolved by the caller (getpwnam_r -- see the certificates
// plugin's resolve_login_home()). That is the SAME directory-services
// lookup a POSIX shell performs for `~username` tilde expansion, so a
// relocated/mobile/network-home account resolves to the identical path the
// previous mechanism produced. (Historical note, #3406: this used to
// return a literal `~<username>/...` string and rely on an outer
// `/bin/sh -c` hop to expand it -- tilde expansion was the ONE feature the
// shell was retained for, and resolving the home in-process is what let
// the whole read become a pre-split rung-2 argv.) `home_dir` MUST already
// be validated (is_valid_home_dir) before reaching here, same as every
// other value this header places into an argv element.
//
// Returns std::nullopt -- never a string -- when `home_dir` fails
// is_valid_home_dir, so this FAILS CLOSED like every other guard in this
// header rather than handing back a path built from a rejected value. The
// optional return is also deliberate API hygiene: #3406 changed this
// function's PARAMETER MEANING (it took a USERNAME before, and built a
// `~username/...` string for a shell to expand) without changing its
// arity or its string_view type, so a stale caller still passing a
// username would otherwise have compiled silently and produced the
// RELATIVE path "alice/Library/Keychains/login.keychain-db" -- resolved
// against the daemon's own cwd, exactly the failure is_valid_home_dir
// exists to prevent. Returning an optional breaks any such caller at
// compile time instead.
inline std::optional<std::string> login_keychain_path(std::string_view home_dir) {
    if (!is_valid_home_dir(home_dir))
        return std::nullopt;
    return std::format("{}/Library/Keychains/login.keychain-db", home_dir);
}

// What a `list`/`details` request should query, resolved from the
// `store` parameter plus whether a console user is currently available.
// All-false-and-not-sentinel never happens -- every branch below sets at
// least one of the three want_* flags or sentinel_required.
struct StorePlan {
    bool want_system = false;
    bool want_root = false;
    bool want_login = false;
    // True only when the request is UNFULFILLABLE outright: store=login was
    // explicitly requested and there is no console user to read it from.
    // Never set for "all" -- there the login keychain is simply omitted
    // (System + root are still valid, real results), never a hard failure.
    bool sentinel_required = false;
};

// Pure resolver: store keyword (+ console-user availability) -> which
// keychain(s) list/details should enumerate.
//
//   "login" -> the console user's login keychain only; UNFULFILLABLE (sets
//              sentinel_required) if there is no console user.
//   "System" -> /Library/Keychains/System.keychain only.
//   "root"   -> SystemRootCertificates.keychain only.
//   "all", or anything else (the shared dispatcher's own "all" default, an
//   unrecognized value, or a Windows-flavoured store name like "MY" a
//   caller passed out of habit) -> the legacy unfiltered behaviour (both
//   fixed system stores), extended to also include the login keychain
//   when a console user happens to be available.
//
// The "anything else" branch is an intentional compatibility contract, not
// an oversight: before this package, macOS ignored `store` entirely (see
// the certificates plugin's objective comment) and always enumerated every
// readable store, so any value -- garbage, a Windows store name, a typo --
// already meant "everything" pre-A-1.11. Preserving that for unrecognized
// input keeps existing callers' behaviour unchanged while "login"/"System"/
// "root" gain real filtering for the first time. This is deliberately
// asymmetric with resolve_delete_keychain_path() below, which REJECTS any
// value it doesn't recognize: a read that broadens on a typo costs a caller
// nothing they weren't already entitled to (the same caller could always
// ask for "all" outright, and the read-only stores are keyed to the
// caller's own privilege, not the store name); a destructive delete acting
// on the wrong keychain because of a typo is a different risk class
// entirely, so it fails closed instead.
inline StorePlan resolve_store_plan(std::string_view store, bool has_console_user) {
    StorePlan plan;
    if (store == "login") {
        if (has_console_user)
            plan.want_login = true;
        else
            plan.sentinel_required = true;
        return plan;
    }
    if (store == "System") {
        plan.want_system = true;
        return plan;
    }
    if (store == "root") {
        plan.want_root = true;
        return plan;
    }
    plan.want_system = true;
    plan.want_root = true;
    plan.want_login = has_console_user;
    return plan;
}

// `delete` acts on exactly one keychain, so it gets its own (simpler)
// mapping rather than StorePlan. Returns std::nullopt when the requested
// store CANNOT be honoured for delete -- the caller MUST treat that as "do
// not delete anything" and reject the request; a destructive action must
// never silently redirect to a keychain the caller didn't ask for.
// Recognized:
//   "root"                  -> SystemRootCertificates.keychain.
//   unset/"MY" (the cross-platform default the shared execute() dispatcher
//   passes when no store was given at all) or "System"
//                            -> System.keychain, preserving today's
//                               unconditional behaviour.
//   "login"                  -- not supported for delete in this package
//                                (would need the same asuser/sudo dance as
//                                list/details, with its own destructive-
//                                path test coverage): rejected, not
//                                silently redirected.
//   "all", or any other/unrecognized value -- no single-keychain meaning
//                                for a destructive op: rejected.
// Resolves to the LITERAL paths (kRootKeychainPath / kDefaultSystemKeychainPath),
// never the override-aware system_keychain_path()/root_keychain_path()
// accessors above: destructive resolution stays literal so that a daemon
// started with a test-only override set can never delete from a substituted
// keychain -- the same fail-closed stance this comment already takes for an
// unrecognised store name.
inline std::optional<std::string> resolve_delete_keychain_path(std::string_view store) {
    if (store == "root")
        return kRootKeychainPath;
    if (store == "MY" || store == "System")
        return kDefaultSystemKeychainPath;
    return std::nullopt;
}

// ── Command construction ─────────────────────────────────────────────────────

// Build the `[sudo -n -- ]launchctl asuser <uid> sudo -n -u <username> -- security
// find-certificate -a -p <login keychain>` invocation that reads the console
// user's login keychain from inside their per-user launchd/Aqua session
// (see the file banner) -- as a PRE-SPLIT argv vector for
// yuzu::agent::run_bounded_subprocess, no shell anywhere (#3406, rung 2
// under ADR-3002). This replaces the former single-string `/bin/sh -c`
// form (rung 3, Decision-7 governed-shell exception), whose shell did
// exactly two jobs, both now performed without it: `~username` tilde
// expansion (the caller resolves the home via getpwnam_r and passes
// `home_dir`) and a `2>/dev/null` redirect (the runner's default,
// merge_stderr=false, already sends child stderr to /dev/null).
// Defensively re-validates every interpolated value even though callers
// are expected to have already validated them (uid/username via a
// successful resolve_console_user(), home_dir at resolution) -- returns an
// EMPTY vector on failure so a missed guard upstream can never produce an
// executable command; the caller must treat an empty return as "do not run
// this" (never fall back to running it anyway, never treat it as an
// empty-but-safe command).
//
// `--` END-OF-OPTIONS TERMINATOR on both sudo invocations, per ADR-3002
// Decision 8's canonical privileged-argv form. History worth keeping, because
// the reasoning was corrected twice (#3406 adversarial review): this site
// originally OMITTED `--` on the theory that inserting an argument the dormant
// #1455 sudoers grant does not name might silently stop that grant matching.
// That theory is WRONG, on two independently verified grounds:
//   * For the OUTER sudo, `--` is sudo's OWN option and is consumed during its
//     option parsing -- `man sudo`: "The -- is used to delimit the end of the
//     sudo options." What sudoers matches is the COMMAND after it, so the
//     grant string never sees the terminator at all.
//   * For the INNER sudo, `--` DOES sit inside the command string the outer
//     grant is matched against -- but sudoers wildcards are fnmatch-based and
//     `man sudoers` is explicit that `*` "Matches any set of zero or more
//     characters (including white space)", so `-u *` absorbs `<user> --`
//     regardless. (The grant text below is nonetheless written with the
//     terminators spelled out, so matching does not RELY on that subtlety.)
// Verified empirically on this host: `sudo -n -- <cmd>` and
// `sudo -n -u <user> -- <cmd>` both parse and reach the credential check
// exactly as the bare forms do.
//
// Note what `--` does and does not buy here, so a later reader does not
// over-credit it: the only values it protects are the COMMAND NAMES that
// follow it (`/bin/launchctl`, `/usr/bin/security`), and both are
// compile-time literals. Every caller-derived value on this line sits in an
// option-ARGUMENT slot (`asuser <uid>`, `-u <username>`, `-p <path>`) that a
// terminator cannot guard. Those are guarded instead by ADR-3002 Decision 6's
// named alternative, which this header satisfies independently: is_valid_uid
// (digits only), is_valid_username (rejects a leading '-'), and
// is_valid_home_dir (forces a leading '/'). So `--` is defence in depth and
// canonical-form conformance, NOT the control that closes option injection.
//
// `caller_is_root` mirrors the sudo_prefix() idiom already established in
// quarantine_plugin.cpp (geteuid() == 0 -> no sudo round-trip needed) --
// passed in rather than queried here via geteuid() so this function stays a
// PURE argv builder the unit test can exercise with a literal true/false
// fixture, matching every other function in this header (the .cpp does the
// actual geteuid() call -- see the certificates plugin's caller_is_root()).
// `launchctl asuser` itself requires root privileges (`man launchctl`), so
// a caller that ISN'T already root (the target `_yuzu` least-privilege
// account, future hardening #1455 -- NOT yet applied on macOS: per
// docs/agent-privilege-model.md's TL;DR the shipped LaunchDaemon still runs
// as root today, so caller_is_root() is true in production right now and
// this branch is dormant until #1455 lands) MUST escalate through its own
// outer `sudo -n` first -- without it, the sudoers grant this needs
// (`_yuzu ALL=(root) NOPASSWD: /bin/launchctl asuser * /usr/bin/sudo -n -u *
// -- /usr/bin/security find-certificate -a -p *` -- handed to
// F-pf-provisioning as this package's provisioning note, to add when #1455
// narrows the macOS agent off root; not required for this package's
// acceptance criteria today) could never be exercised, because the command
// that's supposed to use it would never invoke sudo at all. The
// INNER `sudo -n -u <username>` is unconditional regardless of
// caller_is_root: `launchctl asuser` moves the launchd BOOTSTRAP CONTEXT
// into the target user's session but does not itself change the running
// UID, so dropping to that specific user is always a separate step. `-n`
// on both sudo calls is critical: non-interactive mode fails fast with a
// clear error if a grant is missing, rather than blocking the daemon on a
// password prompt it can never answer (mirrors quarantine_plugin.cpp's
// sudo_prefix() comment).
//
// Absolute paths throughout (/bin/launchctl, /usr/bin/sudo,
// /usr/bin/security -- not the bare `security` the pre-existing
// System/root reads elsewhere in the plugin use) -- this is new code, so
// it matches the PATH-injection-hardened convention
// docs/agent-privilege-model.md documents for sudoers entries ("required
// to prevent PATH-injection attacks") and mirrors that doc's own
// illustrative grant exactly, which simplifies writing the eventual
// sudoers rule if/when #1455 narrows the macOS agent off root (see the
// exact grant text in the comment above, on the `caller_is_root` paragraph).
inline std::vector<std::string> build_login_keychain_read_argv(std::string_view uid,
                                                               std::string_view username,
                                                               std::string_view home_dir,
                                                               bool caller_is_root) {
    if (!is_valid_uid(uid) || !is_valid_username(username))
        return {};
    auto keychain = login_keychain_path(home_dir); // re-validates home_dir, fails closed
    if (!keychain)
        return {};
    // The OUTER hop goes through yuzu::shared::sudo_wrap -- THE single builder
    // for every sudo-governed rung-2 site in the tree (quarantine, services,
    // network_actions), whose exact form is pinned by its own unit test and
    // matched by the sudoers grants install-agent-user.sh writes. Hand-rolling
    // a second copy here would be the drift class CLAUDE.md warns about: a
    // later change to the canonical form would update sudo_argv.hpp and its
    // pinning test while this site silently fell out of grant-match.
    // The INNER `sudo -n -u <user> --` is NOT sudo_wrap's shape (it targets a
    // non-root user and is unconditional), so it stays explicit.
    std::vector<std::string> inner{"/bin/launchctl", "asuser",     std::string(uid),
                                   "/usr/bin/sudo",  "-n",         "-u",
                                   std::string(username), "--",    "/usr/bin/security",
                                   "find-certificate", "-a",       "-p",
                                   *keychain};
    return yuzu::shared::sudo_wrap(std::move(inner), caller_is_root);
}


// --- Merged from the users-plugin console-user helper (C-1.13) at integration ---
// SCDynamicStore-based accessor used by the users plugin; A-1.11's certificates path
// uses the pure stat-based resolution above instead. Distinct, non-overlapping symbols.
// Returns the login name of the user currently at the console (the GUI/
// Aqua session), or std::nullopt if there isn't one -- nobody logged in,
// sitting at the loginwindow, or (defensively) reported as "root". Never
// fabricates a value: any failure to determine a real console user, or a
// build without SystemConfiguration, yields std::nullopt rather than a
// guess.
// saf3-1 (governance A0 fix round, NICE): unlike most of this header, a
// caller missing -DYUZU_HAVE_SYSTEMCONFIGURATION for this ONE function gets
// no build-time signal at all -- it compiles clean and console_user()
// silently returns nullopt forever, indistinguishable at the call site from
// "genuinely no console user right now". Latent only today (the sole
// caller, the users plugin, does define the macro) but worth knowing before
// adding a second caller: verify the macro reaches your TU, don't assume a
// missing definition would be loud.
inline std::optional<std::string> console_user() {
#if defined(__APPLE__) && defined(YUZU_HAVE_SYSTEMCONFIGURATION)
    // Own the CFStringRef via unique_ptr from the moment it's acquired so a
    // throw during std::string construction below (or any future addition
    // to this scope) still releases it -- CFRelease is not RAII-safe on its
    // own against C++ stack unwinding.
    struct CfStringReleaser {
        void operator()(CFStringRef value) const noexcept {
            if (value)
                CFRelease(value);
        }
    };
    std::unique_ptr<std::remove_pointer_t<CFStringRef>, CfStringReleaser> name(
        SCDynamicStoreCopyConsoleUser(nullptr, nullptr, nullptr));
    if (!name)
        return std::nullopt;

    std::string result;
    CFIndex len = CFStringGetLength(name.get());
    if (len > 0) {
        CFIndex max_size = CFStringGetMaximumSizeForEncoding(len, kCFStringEncodingUTF8) + 1;
        std::string buf(static_cast<size_t>(max_size), '\0');
        if (CFStringGetCString(name.get(), buf.data(), max_size, kCFStringEncodingUTF8)) {
            result.assign(buf.c_str());
        }
    }

    if (result.empty() || result == "loginwindow" || result == "root")
        return std::nullopt;
    return result;
#else
    return std::nullopt;
#endif
}

// --- Appended for the certificates plugin's macOS delete path (#2274 DELETE half) ---
// `security delete-certificate` can exit 0 without the certificate actually
// being removed (ACL/SIP quirks, an unexpected keychain state), so the
// certificates plugin's macOS delete never trusts a zero exit status alone
// -- it re-enumerates the target keychain afterward and only reports
// "deleted" on a POSITIVELY-PROVEN absence (see delete_cert_macos() in
// certificates_plugin.cpp). This enum + classifier factor that decision out
// of the bounded-runner-calling .cpp into a pure function the unit test can
// exercise with fixture int/optional<bool> inputs, without forking
// `security` -- same header-for-testability split as every other symbol in
// this file.

// The four possible outcomes of a macOS certificate delete request whose
// thumbprint and target keychain already passed validation (invalid
// thumbprints, a SIP-sealed root store, and unsupported stores are all
// rejected earlier, before a delete is ever attempted -- this classifier
// only covers what happens once `security delete-certificate` has actually
// been run).
enum class DeleteVerdict {
    // The delete subprocess itself did not exit 0 (WEXITSTATUS != 0, or it
    // could not be spawned at all) -- an operational failure. Never
    // "deleted", never "absent": a failing command proves nothing about
    // the certificate's presence.
    kCommandFailed,
    // The delete subprocess exited 0, but the post-delete re-enumeration
    // used to verify the outcome could not read the target keychain at all
    // (locked, permission denied, missing, a `security` failure, ...). An
    // unreadable keychain MUST NOT be reported as "absent"/"deleted".
    kVerifyUnreadable,
    // The delete subprocess exited 0, AND the post-delete re-enumeration
    // successfully read the keychain but still found the thumbprint --
    // exactly the false-success this package exists to catch.
    kStillPresent,
    // The delete subprocess exited 0, AND the post-delete re-enumeration
    // positively proved the thumbprint is gone. The only verdict that may
    // report a completed delete.
    kDeleted,
};

// Pure decision: did the delete command exit 0 (`delete_exit_code`, from
// run_bounded_checked's CheckedCommandResult::exit_code -- itself copied
// from run_bounded_subprocess's SubprocessResult when the child actually
// ran; 0 for a clean successful exit, a positive POSIX exit code for a
// clean failure, or -1 if the child could not be spawned (exec failure) or
// did not exit normally (signaled -- e.g. killed at the deadline/cancel)),
// and -- ONLY when it did -- did the post-delete re-enumeration succeed in
// reading the keychain, and if so was the thumbprint still present
// (`still_present`)?
//
// Takes the raw exit code rather than a pre-collapsed bool so this pure
// decision is directly fixture-testable against representative rc values
// (zero, a representative nonzero exit, and the -1 exec-failure/signal-kill
// sentinel) without needing to fork a real subprocess to reach them. The
// WIFEXITED/WEXITSTATUS extraction itself deliberately stays in
// subprocess_runner.cpp (agents/core/src/subprocess_runner.cpp): those
// macros are POSIX-only (<sys/wait.h>), so they cannot live in this header,
// which is framework-free by design and compiles on every host including
// MSVC (see the file banner and test_certificates_macos.cpp's own doc
// comment).
//
// `still_present` is std::nullopt in exactly one situation: the delete
// succeeded (`delete_exit_code == 0`) but the verification re-enumeration
// itself could not read the target keychain. When `delete_exit_code != 0`
// the delete already failed outright, so no re-enumeration should have
// been attempted and `still_present` is ignored regardless of what it
// holds.
inline DeleteVerdict classify_delete_verdict(int delete_exit_code,
                                              std::optional<bool> still_present) {
    if (delete_exit_code != 0)
        return DeleteVerdict::kCommandFailed;
    if (!still_present.has_value())
        return DeleteVerdict::kVerifyUnreadable;
    return *still_present ? DeleteVerdict::kStillPresent : DeleteVerdict::kDeleted;
}

} // namespace yuzu::macos
