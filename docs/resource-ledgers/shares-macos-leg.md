# Resource Ledger: shares plugin macOS leg (`sharing -l -f json` and `/etc/exports`)

New owned resources introduced by `agents/plugins/shares/src/shares_macos.cpp` and the OS-free
`list_macos` in `shares_legs.hpp`. Every path (normal return, early return, `bad_alloc` unwind)
releases exactly the resource listed.

## Resources

### Child process and its output pipe
- **Site:** the `run` boundary in `run_macos` (`shares_macos.cpp`), one call per dispatch.
- **Allocated by:** `yuzu::agent::run_bounded_subprocess` (execve of `/usr/sbin/sharing -l -f json`,
  a compile-time literal argv with an absolute path; no shell, no PATH search).
- **Owner type:** the runner itself. It owns the pipe descriptors and the child's process group.
- **Release point:** inside the runner before it returns: a normal exit is reaped; a deadline
  (5 s), a cancel or the 2 MiB output cap kills the process group and reaps it (a detached
  reaper pinned in agent core finishes a reap the bounded grace period did not observe). The
  plugin never holds a pid or descriptor; the result is a value (`output` is copied out).
- **Transfer:** never. `SubprocessResult` is returned by value into `list_macos`.
- **Failure cleanup:** a spawn failure leaves nothing allocated (`tool_ran` false).

### `/etc/exports` descriptor
- **Site:** `read_no_follow` (`shares_posix_fs.hpp`), called first by `list_macos`.
- **Allocated by:** `yuzu::shared::read_file_no_follow` (`O_NOFOLLOW`, regular-file check, 256 KiB
  cap).
- **Owner type:** the shared reader's scoped descriptor, closed on every exit including a read
  error and `bad_alloc`; the file's bytes are copied into the returned string.
- **Transfer:** never.

### Parse state
- **Owner:** `list_macos` and the parsers' stack frames: the joined-entry string, the per-line
  distinct path list and the `Share` vectors, bounded by the shared 512-row / 1 MiB budget
  (charged before a `Share` is built) plus the 256 KiB file and 2 MiB output inputs.

## Not introduced
No thread, socket, temp path, callback context or library handle. The `/etc/exports` read has no
deadline of its own, like every `posix_secure_read` consumer (#4875); the tool is bounded by its
deadline and output cap.
