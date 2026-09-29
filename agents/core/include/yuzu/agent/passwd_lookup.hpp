#pragma once

/**
 * passwd_lookup.hpp -- bounded, POSIX passwd-database resolution for the agent
 * (#3406).
 *
 * WHY THIS LIVES IN AGENT-CORE AND NOT IN THE PLUGIN THAT NEEDS IT
 * ---------------------------------------------------------------
 * The only consumer today is the macOS `certificates` plugin, which resolves
 * the console user's uid + home directory before reading their login keychain.
 * The obvious implementation -- call `yuzu::shared::bounded_call()` straight
 * from the plugin -- is UNSAFE, and the tree already says so in as many words.
 * `bounded_call` runs its callable on a DETACHED thread and abandons it at the
 * deadline; if that callable's code lives in a plugin's shared object, the
 * agent can `dlclose()` the plugin while the detached thread is still executing
 * inside it, and the process dies on unmapped text. See
 * agents/core/src/server_address_resolver.cpp, which uses the same primitive
 * and documents the constraint explicitly: safe there "specifically because
 * this whole translation unit lives in agent-core, never dlclose()'d ... the
 * risk this exact shape would carry inside a PLUGIN."
 *
 * So the bounded lookup lives here, in agent-core, for exactly the same reason
 * subprocess_runner's reaper thread does: agent-core is never unloaded, so a
 * late-arriving result from an abandoned thread is simply discarded instead of
 * racing an unload.
 *
 * WHY IT IS BOUNDED AT ALL
 * ------------------------
 * `getpwnam_r` is not a local-file read on a directory-joined Mac -- it can do
 * a blocking network Directory Services / NSS lookup with no caller-supplied
 * timeout, a hazard this repo already records at
 * agents/plugins/tar/src/tar_proc_es.cpp ("getpwuid_r -- which can do a
 * blocking network NSS lookup on a directory-joined Mac"). Before #3406 the
 * certificates plugin obtained this same information through CHILD PROCESSES
 * (`/bin/sh -c` performing `~user` tilde expansion, and `/usr/bin/id -u`), both
 * of which the bounded subprocess runner could SIGKILL at a deadline. Moving
 * the lookup in-process removed that kill boundary: an uncancellable blocking
 * call on the agent's bounded ThreadPool can pin a worker indefinitely, and
 * enough of them exhaust the pool and stall unrelated commands
 * (agents/shared/bounded_wait.hpp's own rationale). Bounding the WAIT here
 * restores the property the child process used to provide.
 */

#include <cerrno>
#include <chrono>
#include <functional>
#include <string>

#include <yuzu/plugin.h> // YUZU_EXPORT

namespace yuzu::agent {

/// One passwd record, reduced to the fields the agent consumes.
struct PasswdRecord {
    std::string uid;      ///< pw_uid, decimal-formatted. Always digits.
    std::string home_dir; ///< pw_dir verbatim; EMPTY if the record had none.
};

/// Why a bounded passwd resolution did not produce a record. Callers must
/// distinguish these: a TIMEOUT is a degraded-service condition and must be
/// reported honestly, whereas NOT_FOUND is a definite negative answer.
enum class PasswdLookupStatus {
    kOk,       ///< record resolved
    kNotFound, ///< the lookup completed and the account does not exist
    kError,    ///< the lookup completed and failed (nonzero rc, or ERANGE twice)
    kTimeout,  ///< the lookup did not ARRIVE: the budget expired, the budget was
               ///< already spent before the call, the bounded-call thread ceiling
               ///< was reached, or the lookup THREW (bounded_call catches inside
               ///< its detached thread, so a throw presents as a non-arrival).
               ///< Deliberately one value -- to every caller these mean the same
               ///< thing, "no answer came back", and none is a definite negative
};

struct PasswdLookupResult {
    PasswdLookupStatus status = PasswdLookupStatus::kError;
    PasswdRecord record{};

    bool ok() const { return status == PasswdLookupStatus::kOk; }
};

/// The raw lookup, exposed so tests can inject one that fails, returns no
/// record, or never returns at all. Returns the resolved record, or a status
/// explaining why it could not. Never kTimeout -- timing out is the bounded
/// WRAPPER's job, not the lookup's.
using PasswdLookupFn = std::function<PasswdLookupResult(const std::string& username)>;

/// Classify a `getpwnam_r` return code into a lookup status. PURE -- no
/// syscall, no state -- so the platform divergence below is unit-testable
/// without a passwd database to provoke it.
///
/// POSIX says "no such user" is `rc == 0` with a null result pointer, and
/// macOS does exactly that. glibc does NOT always: getpwnam(3) documents
/// ENOENT, ESRCH, EBADF and EPERM as ALSO meaning the user was not found.
/// Reporting those as kError would turn a definite negative into a lookup
/// failure on Linux, which is the one distinction this enum exists to keep.
/// EBADF/EPERM are deliberately NOT folded in: unlike ENOENT/ESRCH they also
/// occur for genuine faults, and misreporting a fault as an authoritative
/// "no such account" is the more dangerous direction.
inline PasswdLookupStatus classify_getpwnam_rc(int rc, bool have_result) {
    if (rc == 0)
        return have_result ? PasswdLookupStatus::kOk : PasswdLookupStatus::kNotFound;
    if (rc == ENOENT || rc == ESRCH)
        return PasswdLookupStatus::kNotFound;
    return PasswdLookupStatus::kError;
}

/// Declared here; DEFINED OUT-OF-LINE in passwd_lookup.cpp so the body -- and
/// in particular bounded_call's detached thread -- compiles only into the
/// pinned agent-core image, never into a dlclose()-able plugin. Same reason
/// subprocess_runner.cpp keeps its fork/exec/reap body out of line.
///
/// The real getpwnam_r-backed lookup. Synchronous and potentially blocking --
/// call it through resolve_passwd_bounded() rather than directly.
YUZU_EXPORT PasswdLookupResult getpwnam_lookup(const std::string& username);

/**
 * Resolve `username` against the passwd database, giving up after `timeout`.
 *
 * On timeout the underlying lookup is ABANDONED, not cancelled (there is no
 * portable way to cancel it) -- it finishes on its own detached thread and its
 * result is discarded. The caller is never blocked past `timeout`. A
 * non-positive `timeout` returns kTimeout without starting a lookup at all.
 *
 * On timeout the underlying lookup is ABANDONED, not cancelled, and its
 * detached thread occupies one of `bounded_call`'s PROCESS-GLOBAL
 * `kMaxOutstandingBoundedCalls` slots until it finishes. That counter is shared
 * with every other bounded_call consumer in the agent -- notably
 * `server_address_resolver`'s reconnect-time `getaddrinfo` and discovery's
 * reverse-DNS -- so a sustained directory-services black hole here can consume
 * slots those need, and they degrade to their own nullopt (for the resolver, a
 * spurious "could not resolve" at reconnect). Degraded-but-correct in every
 * case, never a wrong answer, but it is a cross-subsystem coupling worth
 * knowing about before raising this call's timeout or its call rate. Note the
 * ceiling is reached SILENTLY today -- `bounded_call` neither logs nor counts a
 * refusal -- so exhaustion presents as unrelated subsystems degrading at once.
 * Fixing that belongs in `OutstandingCallGuard::try_acquire`, one site covering
 * all three consumers, not here.
 */
YUZU_EXPORT PasswdLookupResult resolve_passwd_bounded(const std::string& username,
                                                      std::chrono::milliseconds timeout);

/// Injectable variant, FOR TESTS ONLY -- and named so, because on this branch
/// a documented-but-unenforced constraint has already been violated once.
///
/// NOTE THE MISSING DEFAULT ARGUMENT, which is load-bearing rather than
/// stylistic. This was originally ONE function with `lookup = getpwnam_lookup`
/// as a default, and that silently defeated the whole agent-core placement: a
/// default argument is evaluated in the CALLER's translation unit, so the
/// `std::function` was constructed inside the certificates plugin, and
/// constructing it instantiated libc++'s type-erasure thunks (`__func::__clone`
/// / `__destroy` / the invoker) as vague-linkage symbols emitted into the
/// PLUGIN's .so. No agent-core TU constructed that target type, so nothing
/// existed for the loader to coalesce onto and the resolved code address was
/// plugin-resident. The detached thread then invoked and destroyed through
/// plugin text -- exactly the use-after-`dlclose()` this file's placement is
/// supposed to prevent, and confirmed by `nm` on the built plugin before the
/// split. Two out-of-line overloads keep every byte the detached thread
/// touches inside agent-core. Do not reintroduce a default argument here.
/// The `_for_test` suffix is the enforcement. A PLUGIN calling this would
/// reproduce the very defect the split above fixed: the injected
/// `std::function`'s own `__func<F>::destroy` is emitted wherever the CALLER
/// constructed it, so a plugin-built callable is still destroyed through
/// plugin text on the detached thread. Tests are linked into a binary that is
/// never `dlclose()`d, so they are safe; production callers must use the
/// two-argument overload.
YUZU_EXPORT PasswdLookupResult resolve_passwd_bounded_for_test(const std::string& username,
                                                               std::chrono::milliseconds timeout,
                                                               const PasswdLookupFn& lookup);

} // namespace yuzu::agent
