# SAM-48 Linux JVM flavour from bin/javac: Resource Ledger (governance Gate 1)

Production-code ledger for `feat/sam-48-jdk-flavour-linux` at `74e98d93fe`. Files: `agents/plugins/runtimes/src/runtimes_linux_parsers.hpp`, `runtimes_parsers.hpp`, `runtimes_plugin.cpp` (descriptor note string only).

## Resource Ledger (C++)

- **One new owned resource: a directory handle for `<home>/bin`.** Acquired in `home_has_javac` by `open_child(home, "bin")` (`O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC`, relative to the already-open home `DIR*`). Owner: the local `Opened o`, whose `DirHandle` is move-only RAII (`closedir` once, null-guarded). Released at scope exit on every return path (absent, alias, failed, `fstatat` failure, ENOENT, final bool). Never transferred. On open failure no handle exists (`Opened::dir` stays null) and the failure is recorded in the `ConstraintAccumulator` (`symlink_refused`, `not_a_directory`, `permission_denied`, `open_failed`). The handle is closed before `home_has_java_binary` runs, so peak open descriptors stay at five (`jvm_dir`, home, `bin`, `jre`, `jre/bin`).
- **`struct stat st{}`** is stack-local; `fstatat(dirfd(bin), "javac", &st, AT_SYMLINK_NOFOLLOW)` never opens, reads or follows `javac`.
- **Borrowed data.** `o.token` is a `string_view` onto the `constexpr kTok*` literals (static storage); `acc.add_failure` copies it.
- **Pre-existing, reused unchanged.** `flavour_from_bin` calls `home_has_java_binary` (RAII; its `bin` open is a second, sequential open of the same fixed name). `WalkBudget::entries_left` is charged one unit before the probe; exhaustion records `row_cap`, sets `exhausted` and stops the walk.
- **No** new fd, `FILE*`, thread, subprocess, shell string, mapped library, temp-file path, callback context, SQLite or OpenSSL object, or cast in production code. Nothing is executed or read from the JVM tree beyond directory entries and the existing bounded `release` read.
- **Tests (harness only).** All new cases use `TempDir` with `yuzu_test_` prefixes (`runtimes_javac_`, `runtimes_flavour_`, `runtimes_flavour_perm_`, `runtimes_flavour_cap_`); the permission case restores modes with `PermRestore` and skips as euid 0.
