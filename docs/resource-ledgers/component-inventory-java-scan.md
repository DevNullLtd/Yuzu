# Resource Ledger: component_inventory plugin (Java archive scan, Linux and macOS legs)

New owned resources introduced by `agents/plugins/component_inventory/` (`component_fs_posix.cpp`,
`component_scan.hpp`, `component_inventory_plugin.cpp`) and the shared `ScopedFile` owner and
`openat_retry` helper in `agents/shared/posix_secure_read.hpp`. Every path (normal return, early
return, `bad_alloc` unwind) releases exactly the resource listed.

## Resources

### Directory descriptor and `DIR*`
- **Site:** `PosixFs::acquire` and `PosixFs::list` (`component_fs_posix.cpp`), one open per path
  component, from "/" down, no link followed.
- **Allocated by:** `yuzu::shared::open_dir_no_follow_at` (`openat` with `O_NOFOLLOW|O_DIRECTORY`,
  retried on `EINTR` by `detail::openat_retry`, then `fdopendir`).
- **Owner type:** the existing `ScopedDir`; the raw descriptor is handed to `fdopendir` at once and
  the `DIR*` owns it from then on (`finish_dir_open` closes it exactly once on failure).
- **Release point:** destructor (`closedir`); a hop's parent is released when the next hop replaces it.
- **Transfer:** move-only.

### Archive file descriptor
- **Site:** `PosixFs::open_file`, once per candidate archive; every later read goes through that one
  `FileView`.
- **Allocated by:** `yuzu::shared::open_file_no_follow_at` (`openat`, same `EINTR` retry; the
  descriptor is `fstat`ed for "regular file", size and mtime).
- **Owner type:** the new move-only `ScopedFile`, held in a `shared_ptr<FileOpen>` captured by the
  `FileView`'s read and `unchanged` closures.
- **Release point:** destructor (`close`) when the last copy of the `FileView` is dropped, at the end
  of the archive's read in `scan`.
- **Transfer:** `ScopedFile` is non-copyable; move-assign closes the descriptor it replaces (tested).

### `z_stream` (raw inflate of a version entry)
- **Site:** `inflate_raw_capped` (`component_scan.hpp`), at most two small entries per archive.
- **Allocated by:** `inflateInit2` over a function-local `z_stream`; the output buffer is allocated
  BEFORE `inflateInit2`, so a `bad_alloc` strands no zlib state.
- **Release point:** `inflateEnd` on every path after a successful init; one exit path.
- **Transfer:** never.

### Buffers (central directory up to 16 MiB, entries up to 64 KiB, tail)
- **Owner:** `std::string` / `std::vector`, scope end; the directory buffer is the largest.
  Parsed entry names are views into it and do not outlive the archive's read.

### Mount table snapshot
- **Site:** `read_network_mounts` (`/proc/<pid>/mountinfo` on Linux, `getmntinfo_r_np` on macOS).
- **Owner:** the Linux read goes through a `ScopedFile`; the macOS buffer is freed by the caller-side
  `unique_ptr`. The result is a value (`vector<string>`) held in `Targets`.

## Not introduced
No thread, socket, temp path, callback context outliving a call, library handle, `FILE*`,
subprocess, SQLite or OpenSSL object. The plugin context pointer is stored in `init` and cleared in
`shutdown`; `execute` is one `try/catch(...)` at the ABI seam.
