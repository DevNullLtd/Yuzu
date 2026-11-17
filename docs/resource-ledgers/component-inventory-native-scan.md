# Resource Ledger: component_inventory plugin (`native` action: shared libraries, Linux and macOS legs)

What the `native` action adds to `agents/plugins/component_inventory/` and to the server. It reuses
every owner of the Java scan (`component-inventory-java-scan.md`): the directory descriptor and
`DIR*` (`ScopedDir`), the per-candidate file descriptor (`ScopedFile` inside the `FileView`), the mount
table snapshot and the `try/catch(...)` at the plugin ABI seam. It adds no new owner of its own except
the one table row below; every path (normal return, early return, `bad_alloc` unwind) releases exactly
what is listed.

## Bounds (one `native` run)

- **Walk:** at most 400,000 directory entries, 45 seconds (one deadline for the walk and the file
  reads, checked between directories and between files; a blocked read is not interrupted), 32
  directory levels, 50,000 entries per listing, 3,000 rows per application folder, **5,000 rows in
  all**. The walk does not enter an excluded directory (macOS `/usr/local/Cellar`,
  `/opt/homebrew/Cellar`); each is counted, not silently skipped.
- **Per library:** one open, then only header reads through that descriptor, never the whole file:
  at most 128 ELF program headers of exactly the format's own entry size (56 or 32 bytes, so up to
  7 KiB; any other `e_phentsize` is `unreadable`), 64 KiB of dynamic section, a 256-byte name read, and
  for Mach-O at most 16 fat slices (up to 512 bytes of architecture table), 4,096 load commands in at
  most 256 KiB, a 255-byte name (at most 256 bytes copied out of the command buffer). Every offset plus
  length is checked against the file size (inside a fat file, the slice size) with overflow-safe
  arithmetic before a read; a count or size past a bound is `unreadable` for that file, never a partial
  answer.
- **Memory:** the buffers above are `std::string` owned by the parser's frame, freed at scope end. The
  worst case for one file, summed from the ceilings: about 74 KiB for ELF (16-byte identification,
  64-byte header, 7 KiB of program headers, 64 KiB of dynamic section, a 256-byte name, and at most 128
  program-header summaries of 24 bytes) and about 257 KiB for Mach-O (a 512-byte fat architecture
  table, a 32-byte thin header, 256 KiB of load commands, a 256-byte name). The rows are bounded by
  count (5,000) and hold paths of at most 32 levels. No allocation persists between runs.
- **No subprocess, no thread, no socket, no temp file, no mapped file, no `FILE*`.** The plugin
  context pointer is the one stored in `init` and cleared in `shutdown`, as for `scan`; `native`
  writes no heartbeat key.

## Server side

- **One new kill-switch row** (`plugin_config_store.kill_switches`, scope key
  `component_inventory.native`): written once at boot by `seed_action_kill_switch_default_off` through
  one pooled connection lease (`kWriteTimeout`), one parameterised `INSERT ... ON CONFLICT DO NOTHING`
  whose `PgResult` is the RAII wrapper. Failure (no lease, a failed statement) returns `false` and the
  boot refuses to start, like the plugin-level seeds. The INSERT is shared with the plugin-level seed
  through one private helper, so there is one statement, not two.
- **No new table, index, migration, metric, thread or background job.**
