# Resource Ledger: UP-14 agent PR (boot epoch and emit sequence, GuardianInstanceLock)

Range `d460f7618..1e4244b17` (branch `fix/up14-agent-emit-seq-boot-epoch`). The ledger below covers the
C++ resources the change adds or touches. Later fix rounds (905bb8e80 to 1e4244b17) changed comments,
documents and the lexical gate only, so no row was added after 905bb8e80 except the exits of
`try_lock_once`, which the second round listed explicitly. The lexical gate
(`tests/test_guardian_emit_stamp_lexical.py`) holds a process-lifetime `functools.lru_cache` of its own
inputs (84 MB peak in the one test process, memoised in 8a21f7182); that is Python, not a C++ resource.

| resource | owner | acquire | release | transfer | failure cleanup |
|---|---|---|---|---|---|
| `std::shared_ptr<GuardianEmitSeqSource>` | `GuardianEngine::emit_seq_source_` (declared BEFORE `legacy_sink_executor_` so it destructs after it) | engine ctor `make_shared` | engine dtor / last shared ref | copied (shared) into legacy executor Config/State and Spark runtime Config | none needed; no raw resource |
| `std::atomic<uint64_t> last` | the source object | n/a | n/a | n/a | n/a |
| KV read/write of `meta:boot_epoch` | `IJournalStore*` borrowed (non-owning, valid for the duration of the `claim_guardian_boot_epoch` call only) | `claim_guardian_boot_epoch` at agent boot | n/a (single read + single write) | n/a | every failure -> `Outcome` + epoch 0 (pair 0/0), `noexcept` |
| lock file descriptor (POSIX) / lock `HANDLE` (Windows) | `GuardianInstanceLock` (move-only RAII; member `AgentImpl::guardian_instance_lock_`, declared after `kv_store_`, before `guardian_`) | `try_lock_once`: POSIX `ScopedFd` around `open(O_RDWR\|O_CREAT\|O_CLOEXEC\|O_NOFOLLOW\|O_NOCTTY)` then `fstat`, `flock(LOCK_EX\|LOCK_NB)`, path re-`stat` identity check; Windows `CreateFileW` share mode 0 | `release()` / dtor / move-assign (closes the fd or HANDLE, which drops the lock); process exit | `ScopedFd::release()` into `handle_` only after every check passed; move ctor/assign steal and reset the source | every failure path (open error, non-regular file, flock failure, replaced file) returns with the `ScopedFd` closing the fd; Windows has no step between `CreateFileW` and the store |
| lock file `guardian_boot_epoch.lock` in `data_dir` | created by `open(O_CREAT)` / `OPEN_ALWAYS`; never deleted by the agent | first acquire | not removed (empty, regenerable) | n/a | n/a |
| borrowed test-hook pointer `const std::function<void()>*` (POSIX) | none (borrowed): points at the caller's `const std::function&` for the duration of `acquire_for_test` only; `acquire()` passes nullptr | `acquire_for_test` takes the address | not owned, never stored, the returned lock keeps no reference | n/a | a throwing hook is caught inside `try_lock_once` (noexcept) -> `Failed`/EINVAL, the `ScopedFd` closes the fd |
| `GuardianInstanceLock` member in `AgentImpl` | `AgentImpl::guardian_instance_lock_` (declared after `kv_store_`, before `guardian_`; destroyed after the engine, before the store) | `acquire()` assignment in `run()` (move-assign releases any previous holder) | member dtor at process teardown; kernel drop at exit/crash | move only | n/a (no failure after the assignment) |
| try_lock_once exits (POSIX) | one local `ScopedFd` | `open` (EINTR loop) | scope exit on every return: open/fstat failure, non-regular file, flock failure, hook throw, stat failure other than ENOENT (Failed with its errno), ENOENT or dev/ino mismatch (Replaced) | `fd.release()` into `handle_` as the last statement of Held | each of the listed exits returns with the `ScopedFd` closing the fd, which drops any flock |
