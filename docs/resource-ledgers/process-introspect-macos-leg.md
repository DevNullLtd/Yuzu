# Resource Ledger: process_introspect plugin macOS leg (libproc `proc_pidinfo` and `kern.bootsessionuuid`)

New owned resources introduced by `agents/plugins/process_introspect/src/process_introspect_macos.cpp`
and the OS-free `inspect_macos` in `process_introspect_legs.hpp`. Every path (normal return,
early return, `bad_alloc` unwind) releases exactly the resource listed.

## Resources

### `proc_bsdinfo` stack buffer
- **Site:** the `bsdinfo` callable in `run_macos` (`process_introspect_macos.cpp`), called exactly
  once per dispatch by `inspect_macos`.
- **Allocated by:** the stack frame of the callable (a zero-initialised `struct proc_bsdinfo`),
  filled by `proc_pidinfo(pid, PROC_PIDTBSDINFO, ...)`.
- **Owner type:** the stack frame. Only three numbers (start seconds, start microseconds, nice)
  are copied out into `MacBsdInfo`; the process name bytes in the struct are never copied and die
  with the frame.
- **Release point:** the callable's return.
- **Transfer:** never. `MacBsdInfo` is returned by value.

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
`tests/test_process_introspect_no_task_port_lexical.py`). Neither call takes the target's VM map
lock, so no deadline wrapper is needed.
