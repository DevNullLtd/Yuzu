# Resource Ledger: process_introspect plugin macOS leg (libproc `proc_pidinfo`, `proc_pid_rusage` and `kern.bootsessionuuid`)

New owned resources introduced by `agents/plugins/process_introspect/src/process_introspect_macos.cpp`
and the OS-free `inspect_macos` in `process_introspect_legs.hpp`. Every path (normal return,
early return, `bad_alloc` unwind) releases exactly the resource listed.

## Resources

### `proc_bsdinfo` stack buffer
- **Site:** `read_snapshot` in `agents/core/src/proc_snapshot_read.cpp` (agent-core, never
  unloaded), reached through `read_proc_snapshot_bounded` from the `bsdinfo` callable in `run_macos`
  (`process_introspect_macos.cpp`); called at most once per dispatch by `inspect_macos` (once for
  `sched`; the five unsupported facets answer before any read).
- **Allocated by:** the stack frame of `read_snapshot` (a zero-initialised `struct proc_bsdinfo`),
  filled by `proc_pidinfo(pid, PROC_PIDTBSDINFO, ...)`, and a zero-initialised
  `struct rusage_info_v0` filled by `proc_pid_rusage(pid, RUSAGE_INFO_V0, ...)` in the same worker
  (UP-3: only `ri_proc_start_abstime`, the monotonic start stamp, is copied out).
- **Owner type:** the stack frame. Only numbers (start seconds, start microseconds, nice, the monotonic start stamp) are
  copied out into `ProcSnapshot` and then `MacBsdInfo`; the process name bytes in the struct are
  never copied and die with the frame.
- **Release point:** `read_snapshot`'s return.
- **Transfer:** never. `ProcSnapshot` is returned by value through the bounded call's shared state.

### Bounded-call worker (one detached thread, agent-core)
- **Site:** `detail::bounded_proc_snapshot` (`proc_snapshot_read.hpp`), instantiated only in
  `proc_snapshot_read.cpp`, over `yuzu::shared::bounded_call_ex`.
- **Owner type:** the worker thread owns its reader copy and a shared result state; the
  process-wide `std::atomic_flag` (static storage, agent-core) records "a read is in flight".
- **Release point:** the worker's `Releaser` clears the flag when the read returns or throws, even
  long after the caller gave up. A Rejected admission (the worker never ran) is cleared by the
  caller.
- **At the deadline:** the worker is abandoned, not cancelled (a blocked kernel call cannot be);
  the flag stays set, so the next dispatch answers `abandoned_call_pending` and starts nothing.
  At most ONE such thread exists at a time. It runs only agent-core text, so unloading the plugin
  cannot unmap code under it.
- **Transfer:** never.

### Boot-session sysctl buffer
- **Site:** the `boot_session` callable in `run_macos`, called at most once per dispatch.
- **Allocated by:** a 64-byte stack buffer filled by `sysctlbyname("kern.bootsessionuuid", ...)`.
- **Owner type:** the stack frame; the text is copied into the returned `RawRead` string, sized
  with `strnlen` (the kernel length includes the terminating NUL).
- **Release point:** the callable's return.
- **Transfer:** never.

### Callable captures
- **Owner:** the two `std::function` members of the stack-local `MacSource` in `run_macos`;
  captures are by value (the pid as an `int`), destroyed when `run_macos` returns.

## Not introduced
No file descriptor, handle, socket, thread, subprocess, temp path, library handle or Mach port
(`task_for_pid` and every Mach VM call are banned and pinned by
`tests/test_process_introspect_no_task_port_lexical.py`).

The libproc call is bounded (SRE-1), not unbounded. Neither call takes the target's VM map lock.
`proc_pidinfo` does take a reference on the target through `proc_find`, which waits uninterruptibly
while the target is inside the exec switch (after the new image is loaded), so a third thread that
holds a reference on the target and is itself blocked at that instant could stall the call. That is
read from the public XNU source (xnu-12377.1.9: `kern_proc.c` `proc_ref_wait_for_exec`,
`kern_exec.c` `proc_exec_switch_task`), not the kernel on a test host, and was not reproduced. The
wait is shared by every `proc_find` caller (`ps`, `kill`). The bound is agent-core's, because a
detached thread in a plugin that can be unloaded is a use-after-unload
(`agents/core/include/yuzu/agent/passwd_lookup.hpp`): one owned worker, a 5 second deadline, one
in-flight flag (the abandoned-worker state), the module never involved. The deadline is a
documented plugin choice (libproc answers in microseconds), not a measured value. The cost of an
abandoned worker is one blocked agent thread that is not a command-pool worker.
