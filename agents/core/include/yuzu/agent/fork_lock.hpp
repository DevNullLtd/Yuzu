#pragma once

/**
 * fork_lock.hpp -- process-wide serialization for the POSIX
 * pipe()-through-fork() window (BR-001).
 *
 * macOS/BSD has no pipe2() (no way to create a pipe with O_CLOEXEC already
 * set), so every raw pipe()+fork() launcher sets FD_CLOEXEC via a separate
 * fcntl() call *after* pipe() returns. Between those two calls the new fds
 * are plain, inheritable descriptors: if ANY thread in the process calls
 * fork() while that window is open -- whether via another raw pipe()+fork()
 * launcher or via popen(), which does the same dance internally -- the
 * concurrent child inherits copies of these not-yet-CLOEXEC fds. Depending
 * on which fd leaks, that can wedge the original launcher's read side open
 * (a false timeout, since EOF never arrives while the leaked copy survives)
 * or hand an unrelated child process a live pipe end into this process.
 *
 * The fix is serialization, not atomicity: every launcher takes this ONE
 * process-global lock across its own [pipe()..fork()] (or, for popen(),
 * across the popen() call itself, since it forks internally) so no two
 * fork-creating operations are ever mid-flight at once. Once fork() returns
 * in the parent, FD_CLOEXEC is already set (or the fds are irrelevant to
 * every other launcher's next spin), so the lock is released immediately --
 * it must NEVER be held across the child's execution, a blocking read/
 * write/waitpid/pclose, or any other I/O. Holding it longer than the
 * create-to-fork window serializes unrelated subprocess launches across the
 * whole agent for no safety benefit and risks a deadlock if a launcher ever
 * blocks while holding it.
 *
 * The child inherits the lock already held (fork() duplicates the parent's
 * address space, mutex state included) and must never touch it -- it always
 * _exit()s or exec()s out without running C++ destructors, so the lock
 * simply stays locked and irrelevant in the child's own (about-to-be-
 * replaced) address space. Only the parent branch unlocks.
 *
 * Residual: this closes the window ONLY for sites that actually take the
 * lock. There is no atfork() enforcement, so a new fork()/popen() site that
 * forgets to take it silently reopens the race for itself and for every
 * other launcher it can collide with. Sites covered as of BR-001:
 *   - agents/core/src/subprocess_runner.cpp   (run_bounded_subprocess)
 *   - agents/core/src/trigger_engine.cpp (query_service_status, macOS popen)
 * (filesystem_plugin.cpp's compute_hash_unix no longer forks directly -- it
 * now routes through the shared bounded runner, which is the first site above.
 * The bitlocker, content_dist, msi_packages, script_exec, services, users,
 * network_config, interaction, wifi, certificates, and event_logs plugins
 * likewise route ALL of their POSIX shell-outs through run_bounded_subprocess,
 * so they are covered transitively
 * via the first site -- their only remaining popen() calls are Windows _popen(),
 * which does not fork and so cannot race this lock. This ledger is verified
 * against the code: an earlier revision listed `services` here while
 * services_plugin.cpp still had two raw POSIX popen() sites (the Linux
 * enumerate + the shared run_command_exit), and wifi/certificates/event_logs
 * still had raw POSIX popen() in their Linux shell-out helpers -- all were
 * migrated to run_bounded_subprocess so the list now matches reality.)
 * The remaining popen() call sites scattered across the plugin directories
 * (the single-shot `popen(cmd, "r")` info-gathering plugins -- hardware,
 * discovery, os_info, vuln_scan, ioc, network_diag, license_scan, and others --
 * plus the tar mapdrive/service collectors) are NOT migrated and NOT covered;
 * any of them can still race a locked launcher's window until they are migrated
 * too. The Linux branch of trigger_engine.cpp's query_service_status has its
 * own, separate popen() call and is not covered either -- only the macOS branch
 * was in scope for BR-001.
 *
 * Non-forking pipe creators are exposed too, symmetrically: anything that
 * calls raw pipe() without also holding this lock across its own
 * pipe()-to-CLOEXEC window (e.g. shutdown_watcher.hpp's self-pipe) can
 * still have its fds inherited by a concurrent LOCKED launcher's child --
 * the lock only prevents fork-creating operations from overlapping with
 * each other, not with an unguarded bystander's pipe(). Out of scope here.
 */

#include <yuzu/plugin.h> // YUZU_EXPORT

#include <mutex>

namespace yuzu::agent {

/**
 * The process-global fork lock. Take it as a std::lock_guard immediately
 * before the first pipe()/popen() call of a launch and release it (drop the
 * guard, or unlock explicitly) in the PARENT as soon as fork() returns --
 * see the file header for the full contract.
 */
YUZU_EXPORT std::mutex& global_fork_lock();

} // namespace yuzu::agent
