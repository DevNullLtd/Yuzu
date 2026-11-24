# Resource Ledger: Homebrew receipts and user-owned prefixes (`pkg_inventory` macOS `packages`, `network_fstype.hpp`, `macos_user_home_entry.hpp`)

Resources introduced or re-homed by reading Homebrew install receipts under the machine prefixes and walking
the user-owned prefixes (`~/homebrew`, `~/.homebrew`) of each real `/Users` home, without running `brew`. The
walk is one action (`packages`) behind the existing per-action `WalkSlot`; every resource below is a local of
that walk, so every exit path (normal, early return, `walk_budget` stop, exception unwind) releases exactly the
resource listed. The owner type of every descriptor is `posix::Dir` (move-only RAII over a `DIR*`, closed in
`~Dir`, `pkg_inventory_legs.hpp:162`) or `yuzu::shared::ScopedFile` (`posix_secure_read.hpp:116`). Nothing here
calls `close`, `closedir` or `free` by hand. Receipts are read for machine-prefix formulae only: a user version
directory is stat-ed and never opened, so no file descriptor is ever held on a file under a user-owned prefix.

All paths are in `agents/plugins/pkg_inventory/src/pkg_inventory_macos_parsers.hpp` unless stated.

## Resources

### Home directory descriptor (`append_user_prefix_rows`, `home`)
- **Site:** `:605`, `auto home = posix::open_dir_no_follow_at(users.dir, name.c_str())`, one per real `/Users`
  entry (a directory, uid at or above `min_home_uid`, not a symlink, not under a network mount).
- **Allocated by:** `openat(O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)` then `fdopendir`, inside
  `finish_dir_open` (`pkg_inventory_legs.hpp:199`). A `yuzu::agent::ScopedFd` owns the raw fd until `fdopendir`
  succeeds and `release()` hands it to the `DIR*`.
- **Owner type:** `OpenDirResult::dir`, a `posix::Dir`.
- **Release point:** end of the loop iteration (`~Dir` on `home`), including the `continue` and `return` paths.
- **Transfer:** none. `append_home_prefix_rows` receives `home.dir` as a `const posix::Dir&` and the owner uid
  as a value (`dir_owner(home.dir)`, an `fstat` on the held descriptor); it never stores or moves it.
- **Failure cleanup:** a failed `openat` returns no descriptor (`absent` or a constraint token); a failed
  `fdopendir` closes the raw fd through the `ScopedFd` (errno is read first); the owner `fstat` failing leaves
  the `Dir` to its destructor and records `io_error`.

### `/Users` directory descriptor (`append_user_prefix_rows`, `users`)
- **Site:** `:579`, `auto users = posix::open_dir_no_follow(under(root, "Users"))`: the one open by path (the
  final component is not followed; a symlinked `/Users` is refused as `user_homes:not_a_directory`).
- **Allocated by / owner type / transfer:** as for the home descriptor. Held while `list_names` and
  `classify_entry` run on it and while each home is opened from it.
- **Release point:** end of `append_user_prefix_rows` (`~Dir`), on every `return`, including the
  `walk_budget` and prefix-error returns.
- **Failure cleanup:** as above. The network-mount and `mounts_unreadable` guards return before this open, so a
  guarded run allocates nothing.

### Prefix and container descriptors (`append_home_prefix_rows`, `prefix`, `top`)
- **Site:** `:532`, `auto prefix = posix::open_dir_no_follow_at(home, cand.c_str())` for each of the two
  candidates; `:547`, `auto top = posix::open_dir_no_follow_at(prefix.dir, ...)` for `Cellar` and `Caskroom`.
  A symlink or plain file at a candidate is classified first (`classify_entry`, `fstatat` with
  `AT_SYMLINK_NOFOLLOW`) and skipped without an open; a symlinked `Cellar` fails `openat` with `ELOOP`.
- **Owner type:** `posix::Dir` (as above).
- **Release point:** `top` at the end of its container iteration, `prefix` at the end of its candidate
  iteration; the `owner_mismatch`, `owner_name_unsupported`, `walk_budget` and `continue` exits all run
  `~Dir`.
- **Transfer:** `top.dir` is lent to `append_package_rows_from` by `const&`. The owner check compares
  `dir_owner(prefix.dir)` (the held descriptor) with the home's uid before anything below is opened.
- **Failure cleanup:** as above; a refused owner closes the prefix descriptor with nothing below it open.

### Id-directory descriptor (`append_package_rows_from`, `id_dir`)
- **Site:** `:430`, `auto id_dir = posix::open_dir_no_follow_at(top, id.c_str())`. The site predates this
  change; the diff adds the receipt read below it and the `rs.scope == BrewScope::machine` condition at `:458`.
- **Owner type / release point:** `posix::Dir`, closed at the end of the id iteration. Shared by the machine
  and the user walks; under a user prefix its children are only `classify_entry`-ed.
- **Failure cleanup:** unchanged: the `walk_budget`, `row_cap` and `byte_cap` returns unwind through `~Dir`.

### Version-directory descriptor (`receipt_for_version`, `vdir`)
- **Site:** `:395`, `const auto vdir = posix::open_dir_no_follow_at(id_dir, version.c_str())`. Reached only for
  `kind == formula && rs.scope == BrewScope::machine` (`:458`), so only under `/opt/homebrew` and `/usr/local`.
- **Allocated by:** `finish_dir_open`, as above. **Owner type:** `posix::Dir` local of `receipt_for_version`.
- **Release point:** the end of `receipt_for_version`, on the invalid-descriptor, unknown-owner and normal
  returns.
- **Transfer:** `vdir.dir.fd()` is lent (a borrowed int, not a transfer) to the receipt read below; the
  `Dir` is never moved out.
- **Failure cleanup:** an invalid descriptor returns an empty receipt (the row is still emitted, with `-`
  fields); `dir_owner` failing returns an empty receipt and the `Dir` closes in its destructor.

### Receipt file descriptor (`read_brew_receipt`, `read_file_no_follow_at`)
- **Site:** `:386`, `yuzu::shared::read_file_no_follow_at(vdir.fd(), "INSTALL_RECEIPT.json", kMaxBrewReceiptBytes)`,
  a 64 KiB cap. The helper lives in `agents/shared/posix_secure_read.hpp` (unchanged by this diff); this is its
  new call site in the plugin.
- **Allocated by:** `openat(O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_NOCTTY | O_CLOEXEC)` with `EINTR` retried
  (`openat_retry`). `O_NONBLOCK` means a FIFO at the receipt name cannot block the walk.
- **Owner type:** `ScopedFile closer{fd}` as the first statement of `read_open_fd`
  (`posix_secure_read.hpp:223`), so the descriptor has an owner from the moment it exists.
- **Release point:** the end of `read_open_fd` (`~ScopedFile`) on the not-regular, `fstat` failure, read error,
  oversized and success returns alike. No descriptor outlives the call; the caller receives a `FileRead` value
  (bytes, owner uid, mode), not a handle.
- **Transfer:** none. The result is returned by value; `read_brew_receipt` compares `owner_uid` with the
  version directory's owner and parses the bytes only on a match (the bytes are read before the owner is
  known: a foreign file's bytes are dropped unparsed).
- **Failure cleanup:** every failure (symlink, FIFO, directory, oversized, unreadable, foreign owner) yields an
  empty `BrewReceipt` and a closed descriptor. A failed receipt never fails the row.
- **Peak descriptors:** machine walk four (container, id directory, version directory, receipt file); user
  walk five (`/Users`, home, prefix, container, id directory). The fd-balance test asserts the process's open
  fd count is unchanged across every early-return shape.

### Network-mount snapshot (`production_user_prefix_config`)
- **Site:** `:717`, `production_user_prefix_config(read_mounts = &read_macos_network_mounts)`, called once per
  `packages` dispatch from `run_macos` (`pkg_inventory_macos.cpp:21`), `__APPLE__` only.
- **Allocated by:** `getmntinfo_r_np(&raw, MNT_NOWAIT)` in `agents/shared/macos_network_mounts.hpp:55` (the helper
  is unchanged by this diff). It `malloc`s a `statfs` table and the caller must `free` it.
- **Owner type:** `const std::unique_ptr<struct statfs, decltype(&::free)> mnt{raw, &::free}`, constructed on the
  next line, so the buffer has an owner before any branch.
- **Release point:** the end of `read_macos_network_mounts`, on the failed (`n <= 0` or null) and success
  returns. The mount-on paths are copied into `std::string`s (`macos_network_mount_points`) before the buffer
  is freed; nothing keeps a pointer into it.
- **Transfer:** the copy is `UserPrefixConfig::network_mounts`, a `std::vector<std::string>` owned by the
  config value. `run_macos` passes the prvalue to `run_macos_guarded` as a `const&`; the temporary lives to the
  end of the full-expression that contains the whole walk. The walk only reads it.
- **Failure cleanup:** an unreadable table returns `nullopt`, which sets `mounts_unreadable`: the user walk is
  skipped with a token and nothing under `/Users` is opened. It is never an empty guard.

### Pure helpers (no resource)
- `under_network_mount` and `touches_network_mount` (`network_fstype.hpp:91`, `:103`), `is_user_home_entry`
  and `home_name_eligible` (`macos_user_home_entry.hpp`), `dir_owner` (`pkg_inventory_legs.hpp:280`, an `fstat`
  on a held descriptor), the `classify_entry` `uid` field (an `fstatat` result), `parse_brew_receipt`
  (`pkg_inventory_parsers.hpp`) and the row adapter in `agents/core/src/sync_source_installed_software.cpp`
  hold no descriptor, handle, allocation or lock.

### Tests (`tests/unit/test_pkg_inventory_macos_parsers.cpp` unless stated)
- **`yuzu::test::TempDir`** (`tests/unit/test_helpers.hpp:141`), prefix `yuzu_test_`: every new test case that
  builds a tree owns one by value; `~TempDir` runs `remove_all` on every exit, including a `REQUIRE` unwind.
  Symlinks, the FIFO (`mkfifo`, `:991`) and the receipt files written through scoped `std::ofstream` blocks
  (closed at block end) all live inside it.
- **`ModeGuard`** (`pkg_inventory_test_support.hpp:60`, an unchanged helper): used at `:873`, `:1383`, `:1402`
  after the `chmod(0000)` that makes a home, prefix or receipt unreadable. It is declared after its `TempDir`, so
  the mode is restored before the tree is removed. Those cases `SKIP` when the process is root (the mode would
  be no barrier).
- **`chown` to another uid** (root-only case, `:1307`): the `chown_to` lambda changes the owner of files inside
  a `TempDir` only. The case `SKIP`s unless `geteuid() == 0` and when a probe `chown` fails with `EPERM` or
  `EINVAL` (a rootless container); `~TempDir` removes the chowned tree as root.
- **Direct descriptors** (`:905`, `:1026`, `:1280`): `posix::open_dir_no_follow` results held as block-scoped
  `Dir` locals, closed at block end. `open_fd_count()` (`:891`, `:924`) compares the process's open fd count
  before and after the whole sweep.
- **Python** (`tests/test_pkg_inventory_no_brew_lexical.py`): reads source files with `Path.read_text`
  (closed on return); starts no subprocess. `test_network_fstype_mounts.cpp`, `test_pkg_inventory_parsers.cpp`,
  `test_inventory_sync.cpp` and `test_pkg_inventory_local_dispatcher.cpp` additions are pure (fixture strings
  and value structs).

## Not introduced

No new thread, subprocess, callback context, socket, `FILE*`, `HANDLE`, SQLite object, OpenSSL or BCrypt
object, mapped library, allocated C string, raw `new`/`malloc`/`free` in plugin or agent code, temp file outside
a `yuzu_test_` `TempDir`, mutex, or lock. The `WalkSlot` that single-flights the action is unchanged. `brew` is
never run (`tests/test_pkg_inventory_no_brew_lexical.py` and `scripts/ci/check-plugin-spawn-lexical.sh` pin
it). The plugin-local open helpers do not retry `EINTR` (the shared helper does): they fail closed with a
constraint token, and migrating `pkg_inventory` to the shared helper is still owed (governance row
`cs-2-plugin-local-open-helpers-no-eintr-retry`).
