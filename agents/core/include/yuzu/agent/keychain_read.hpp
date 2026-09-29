#pragma once

/**
 * keychain_read.hpp -- bounded, raw SecItem keychain read for the agent
 * (#3246, #2318a).
 *
 * WHY THIS LIVES IN AGENT-CORE AND NOT IN THE PLUGIN THAT NEEDS IT
 * ---------------------------------------------------------------
 * The only consumer today is the macOS `certificates` plugin, which reads a
 * keychain's certificates via SecItemCopyMatching. The obvious implementation
 * -- call `yuzu::shared::bounded_call()` straight from the plugin -- is
 * UNSAFE, and the tree already says so in as many words. `bounded_call` runs
 * its callable on a DETACHED thread and abandons it at the deadline; if that
 * callable's code lives in a plugin's shared object, the agent can
 * `dlclose()` the plugin while the detached thread is still executing inside
 * it, and the process dies on unmapped text. See
 * agents/core/include/yuzu/agent/passwd_lookup.hpp:8-24 for the identical
 * argument made in full for the sibling seam this file mirrors.
 *
 * So the bounded read lives here, in agent-core, for exactly the same reason
 * passwd_lookup's does: agent-core is never unloaded, so a late-arriving
 * result from an abandoned thread is simply discarded instead of racing an
 * unload.
 *
 * THE OUTSTANDING-CALL CEILING IS PER IMAGE, NOT PER PROCESS
 * ------------------------------------------------------------
 * `bounded_call_ex` claims a slot on bounded_wait.hpp's 64-slot
 * `kMaxOutstandingBoundedCalls` ceiling. That counter is an `inline`
 * variable compiled under `-fvisibility=hidden` (root meson.build), so each
 * linked image holds its own copy -- it is NOT coalesced across a dylib/
 * executable boundary. Agent-core's copy is shared by this seam,
 * passwd_lookup's own getpwnam_r resolution, and server_address_resolver's
 * reconnect-time getaddrinfo; every plugin `.so`/`.dylib` carries its own,
 * separate copy. A sustained black hole in one consumer can therefore starve
 * the others IN THE SAME IMAGE, which degrade to their own Rejected/nullopt
 * rather than a wrong answer. Note a wedged securityd now costs up to TWO
 * agent-core slots per certificates action: this seam's own keychain read,
 * plus the console-user passwd resolution the plugin performs alongside it.
 * passwd_lookup.hpp:126-137 makes the same overclaim about this ceiling's
 * reach; that predates this observation and is corrected separately.
 *
 * `KeychainReadStatus::Rejected` is kept distinct from `TimedOut` rather than
 * folded together (unlike passwd_lookup's single `kTimeout`) because it is
 * the cross-subsystem exhaustion signal: Rejected means this call's `fn` was
 * NEVER invoked and no thread was ever created, whereas TimedOut means a
 * detached thread may still be running against the keychain. A caller (or an
 * operator reading logs) that cannot tell those apart cannot tell "securityd
 * itself is wedged" from "the agent's whole bounded-call budget is currently
 * spent on something else".
 *
 * OPEN RISK, NOT RULED OUT: A WEDGED securityd COULD SERIALIZE FUTURE CALLS
 * ---------------------------------------------------------------------------
 * The outstanding-call ceiling bounds how many concurrent detached threads
 * this seam will start; it does NOT bound what those threads do once
 * running. If SecItemCopyMatching/SecKeychainOpen internally hold a
 * process-wide Security-framework or securityd XPC connection lock, a
 * wedged call could serialize -- not just occupy a slot from -- every
 * subsequent keychain read in this agent process, long after the bounded
 * wrapper has "returned" TimedOut to its own caller. This has not been
 * measured (the BR-01 probe below exercises single, sequential calls, never
 * a wedge concurrent with a fresh read) and is not ruled out by anything in
 * this file. Treat it as an accepted, disclosed risk pending that
 * measurement, not as a closed question.
 */

#include <chrono>
#include <cstdint>
#include <functional>
#include <string>
#include <vector>

#include <bounded_wait.hpp> // yuzu::shared::bounded_call_ex (agents/shared) -- detail::bounded_keychain_call below is built on it
#include <yuzu/plugin.h> // YUZU_EXPORT

namespace yuzu::agent {

/// Hard cap on how many certificates a single bounded keychain read will
/// convert to DER before the result is reported Truncated rather than
/// Completed.
inline constexpr std::size_t kMaxKeychainReadCerts = 2000;

/// Why a bounded keychain read did not produce a complete, usable result.
enum class KeychainReadStatus {
    Completed,   ///< the read finished and every found item converted to DER
    Truncated,   ///< the read finished but hit kMaxKeychainReadCerts or a
                 ///< per-item conversion failure -- certs_der holds what
                 ///< DID convert
    NotReadable, ///< the keychain query came back empty AND the keychain's
                 ///< own status bits say it is not readable -- #2318a: this
                 ///< is what disambiguates an empty errSecItemNotFound
                 ///< answer from a genuinely-empty, readable keychain
    OpenFailed,  ///< SecKeychainOpen/SecKeychainGetStatus or a CoreFoundation
                 ///< allocation failed outright
    TimedOut,    ///< the read did not ARRIVE within the budget; a detached
                 ///< thread may still be running against the keychain
    Rejected,    ///< this image's outstanding-call ceiling refused the call;
                 ///< the read was NEVER started
};

struct KeychainReadResult {
    KeychainReadStatus status = KeychainReadStatus::OpenFailed;
    std::vector<std::vector<unsigned char>> certs_der;
    std::string detail;

    bool ok() const {
        return status == KeychainReadStatus::Completed || status == KeychainReadStatus::Truncated;
    }
};

/// The raw read, exposed so tests can inject one that fails, times out, or
/// never returns at all.
using KeychainReadFn = std::function<KeychainReadResult(const std::string& keychain_path)>;

/// == kSecReadPermStatus (SecKeychainGetStatus's readable-permission bit).
/// Named locally rather than pulled from Security.h so the pure helpers
/// below compile on every platform, including where Security.h does not
/// exist; the .cpp asserts the two stay equal under the Apple guard.
inline constexpr std::uint32_t kKeychainReadPermBit = 2;

/// PURE -- no syscall, no state -- so the readability check is unit-testable
/// without a real keychain to provoke it.
inline bool keychain_status_readable(std::uint32_t bits) {
    return (bits & kKeychainReadPermBit) != 0;
}

/// #2318a: SecItemCopyMatching's errSecItemNotFound is ambiguous on its own
/// -- it is the answer for both a genuinely empty keychain AND one this
/// process cannot read. The keychain's own status bits are what disambiguate
/// it; they are consulted ONLY for this ambiguous empty-query answer, never
/// for a populated read.
inline KeychainReadStatus classify_empty_query(bool readable) {
    return readable ? KeychainReadStatus::Completed : KeychainReadStatus::NotReadable;
}

/// Fold a read's item count against the conversion cap into a status:
/// Completed iff every found item is within the cap AND converted; Truncated
/// if the cap was exceeded or any item failed to convert.
inline KeychainReadStatus fold_read_cap(std::size_t found, std::size_t converted, std::size_t cap) {
    return (found <= cap && converted == found) ? KeychainReadStatus::Completed
                                                 : KeychainReadStatus::Truncated;
}

namespace detail {

/// Status-mapping core of read_keychain_bounded / _for_test. Header-only so a
/// unit test can instantiate it IN ITS OWN IMAGE and saturate the ceiling that
/// instantiation consults (see "THE OUTSTANDING-CALL CEILING IS PER IMAGE").
/// Production instantiates it in keychain_read.cpp with a TU-local lambda, so
/// every byte the detached thread runs is still agent-core text.
///
/// DO NOT call this template from a plugin .cpp. Being header-only, it would
/// compile Fn's call and the detached-thread machinery around it directly
/// into the plugin's own .dylib -- reintroducing, for whatever Fn a plugin
/// author supplied, the exact dlclose()-during-a-wedged-call hazard this
/// whole seam exists to keep out of plugin code (see the module banner
/// above). A plugin wanting a keychain read calls the exported
/// read_keychain_bounded / read_keychain_bounded_for_test below instead,
/// which stay resident in agent-core no matter who links against them.
template <typename Fn>
KeychainReadResult bounded_keychain_call(std::chrono::milliseconds timeout, Fn fn) {
    KeychainReadResult timed_out;
    timed_out.status = KeychainReadStatus::TimedOut;
    if (timeout <= std::chrono::milliseconds::zero())
        return timed_out; // budget already spent -- don't start what we can't wait for

    auto r = yuzu::shared::bounded_call_ex(timeout, std::move(fn));
    switch (r.status) {
    case yuzu::shared::BoundedCallStatus::Completed:
        return *r.value;
    case yuzu::shared::BoundedCallStatus::TimedOut:
        return timed_out;
    case yuzu::shared::BoundedCallStatus::Rejected:
        break;
    }
    KeychainReadResult rejected;
    rejected.status = KeychainReadStatus::Rejected;
    return rejected;
}

} // namespace detail

/// Declared here; DEFINED OUT-OF-LINE in keychain_read.cpp so the body --
/// and in particular the detached thread detail::bounded_keychain_call's
/// TU-local lambda runs on -- compiles only into the pinned agent-core
/// image, never into a dlclose()-able plugin. Same reason passwd_lookup.cpp
/// keeps its body out of line (passwd_lookup.hpp:107-114).
///
/// The real SecItemCopyMatching-backed read. Synchronous and potentially
/// blocking -- call it through read_keychain_bounded() rather than directly.
YUZU_EXPORT KeychainReadResult secitem_keychain_read(const std::string& keychain_path);

/**
 * Read `keychain_path`'s certificates, giving up after `timeout`.
 *
 * On timeout the underlying read is ABANDONED, not cancelled (there is no
 * portable way to cancel a SecItemCopyMatching call) -- it finishes on its
 * own detached thread and its result is discarded. See passwd_lookup.hpp:
 * 116-137 for the full argument, including the per-image outstanding-call
 * ceiling (see above) this shares with every other bounded_call_ex consumer
 * in the same image.
 */
YUZU_EXPORT KeychainReadResult read_keychain_bounded(const std::string& keychain_path,
                                                     std::chrono::milliseconds timeout);

/// Injectable variant, FOR TESTS ONLY. NOTE THE MISSING DEFAULT ARGUMENT,
/// which is load-bearing rather than stylistic -- see passwd_lookup.hpp:
/// 143-168 for the full argument. Production callers must use the
/// two-argument overload.
YUZU_EXPORT KeychainReadResult read_keychain_bounded_for_test(const std::string& keychain_path,
                                                               std::chrono::milliseconds timeout,
                                                               const KeychainReadFn& read);

} // namespace yuzu::agent
