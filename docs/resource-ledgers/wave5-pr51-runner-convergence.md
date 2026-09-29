# Resource Ledger — Wave 5 PR5.1 runner convergence (`script_exec`/`content_dist` onto `run_bounded_subprocess`)

This ledger documents the new/modified owned C resources this branch introduces,
on both the Windows leg and the Linux B6 verified-exec primitive `content_dist`
now reaches (`exec_verify.enabled = is_linux`). Reviewers must verify that every
code path (normal fall-through, early exit, and exception unwind) releases
exactly the listed resource.

---

## Resources

### `LPWCH` — `GetEnvironmentStringsW()` parent-environment snapshot
- **Site:** `agents/core/src/subprocess_runner.cpp`, Windows `run_bounded_subprocess`
  (the `spec.inherit_parent_env` branch — script_exec's Windows-parity leg,
  `SubprocessOptions::inherit_parent_env`, A2-002).
- **Allocated by:** `GetEnvironmentStringsW()`.
- **Released by:** `std::unique_ptr<wchar_t, EnvironmentStringsDeleter>` (a
  local, file-scoped deleter struct calling `FreeEnvironmentStringsW`),
  constructed IMMEDIATELY on acquisition, before the parse loop that walks the
  returned block runs.
- **Scope:** local to the `inherit_parent_env` branch; the `unique_ptr` goes
  out of scope (and releases) at the end of that `if` block, whether the loop
  completes normally or an exception (allocation failure in `std::wstring`
  construction/append, or `parent_env.push_back()`) unwinds through it.
- **BR-004 (whole-branch review, fixed):** the original code held the raw
  `LPWCH` in a plain local and called `FreeEnvironmentStringsW` in a
  lexically-paired statement AFTER the parse loop. Lexical pairing is not an
  ownership proof — every operation between acquisition and that free
  (`std::wstring` construction/append, `push_back`) is NOT `noexcept`, so an
  exception thrown anywhere in the loop skipped the free and leaked the
  block; the agent's plugin exception firewall then let the process survive
  to leak it again on the next `inherit_parent_env` call. Fixed by wrapping
  the pointer in the RAII owner above at the point of acquisition.
- **All paths covered:** normal loop completion ✓ · null return from
  `GetEnvironmentStringsW` (BR3-005, whole-branch review round 3: BR-008
  is FIXED, not merely tracked-separately as an earlier version of this
  line said — a null return now fails the spawn closed,
  `result.termination_reason = TerminationReason::spawn_error`, before the
  parse loop or the RAII owner above is ever reached, so there is nothing
  for that owner to release on this path; the `unique_ptr` remains safely
  null-constructed and its destructor is a no-op) ✓ · exception unwinding
  through the parse loop ✓
- **Platform note:** this code path is Windows-only (`#else // _WIN32` block,
  `agents/core/src/subprocess_runner.cpp`); verified by compile only on this
  host (macOS) — no Windows runtime evidence was collected for this fix.

---

### `int` fd — B6 verified-exec's `open()` of the payload, transferred by `execveat`
- **Site:** `agents/core/src/subprocess_runner.cpp`, `toctou_verified_exec`
  (the async-signal-safe post-`fork()` path taken when
  `LaunchSpec::ExecVerification::enabled`; `content_dist`'s
  `execute_verified_payload` is the in-tree caller, Linux leg only).
- **Allocated by:** `open(c_argv[0], O_RDONLY | O_NOFOLLOW)`.
- **Released by:** every FAILURE path closes it explicitly — a failed
  `fstat`, a failed verification check (`!regular || !root_owned ||
  !not_group_other_writable || !size_ok`), an `ETXTBSY` retry (closed before
  the bounded backoff sleep, reopened fresh next attempt), and the final
  `errno` path when `execveat` itself fails or retries are exhausted. The
  SUCCESS path is deliberately different and does NOT release the fd: a
  successful `execveat(fd, "", c_argv, c_envp, AT_EMPTY_PATH)` replaces the
  process image but, absent `O_CLOEXEC`, carries the fd forward into that
  new image rather than closing it — there is no `close()` after a
  successful exec because this code never runs again in that process
  (the call is `[[noreturn]]`), and the fd's actual lifetime from this point
  is the exec'd child's to manage. See the transfer note below for why that
  is accepted rather than fixed.
- **Deliberately NOT `O_CLOEXEC`, and this is a transfer, not a leak:** this
  is the exact fd meant to be exec'd, not one that should be hidden from the
  child, so it is intentionally left open across the exec so the kernel can
  read the target binary through it during the transition — CLOEXEC would
  tear the fd down as part of that same transition, before the kernel could
  use it, and empirically (gcc-15/Linux 7.x, forked child, isolated
  per-flag-combination) `O_CLOEXEC` makes `execveat(..., AT_EMPTY_PATH)` fail
  every attempt with `ENOENT` — see the comment above
  `toctou_verified_exec`'s definition for the full reproduction. The
  content_dist seam's shebang-rejection message previously claimed the
  opposite (that CLOEXEC closes this fd) — corrected in
  `content_dist_exec_seam.hpp` in the same change that added this entry, so
  operator-facing text and this ledger now agree with the runner's actual
  behavior.
- **All paths covered:** successful `execveat` — the fd is NOT closed by the
  exec transition; without `O_CLOEXEC` it transfers into the new process
  image and survives there, inheritable, exactly as the "deliberate
  transfer" framing above says (reproduced directly: the exec'd child's
  `/proc/self/fd` lists it as still open). This is accepted, not
  overlooked — the child already has an equally-capable path to the same
  file via `/proc/self/exe`, and the fd is read-only and `O_NOFOLLOW`, so a
  surviving handle to its own executable discloses nothing the child
  couldn't already reach ✓ · `fstat` failure (closed) ✓ · any
  verification-check failure (closed) ✓ · `ETXTBSY` retry (closed,
  reopened) ✓ · final `execveat` failure after retries exhausted (closed) ✓.
- **Platform note:** Linux-only (`#if defined(__linux__) && defined(SYS_execveat)`);
  runtime-verified on this branch's own CI (the comment above the function
  records this was "the first Linux CI run of this code path to ever
  actually execute past compile time").

---

## Known limitations

### `no_window=true` makes `soft_terminate_grace` ineffective on Windows (BR-006)
- **Sites:** `content_dist_exec_parsers.hpp::build_execution_options` and
  `script_exec_plugin.cpp`'s Windows leg — the only two callers that set
  `no_window=true`.
- **Cause:** `CREATE_NO_WINDOW` gives the child no console at all (not merely
  a hidden window) — Microsoft's own documented contract for
  `GenerateConsoleCtrlEvent` requires the target process group to share a
  console with the caller, which a `no_window=true` child never has. Every
  deadline/cancel against a `no_window=true` child therefore skips CTRL_BREAK
  delivery entirely and goes straight to `TerminateJobObject`.
- **Status:** the real fix (a cooperative-termination channel that works
  against a console-less child) is confirmed out of scope — a separate,
  larger design (a dedicated IPC/event mechanism), not an extension of
  CTRL_BREAK delivery — and stays a known limitation, confirmed by the
  documented Win32 API contract (adversarial review, HIGH), not
  runtime-verified (no Windows host available to this branch's authoring
  session). **What IS fixed (Gate-8 remediation):** both call sites
  previously ALSO set a nonzero `soft_terminate_grace` (30s / 10s) alongside
  `no_window=true`, arming a grace the platform can never deliver — pure
  configuration dishonesty, since the option struct claimed a soft-unwind
  step that was a guaranteed no-op. Both sites now zero
  `soft_terminate_grace` on the `no_window=true` path, so the configuration
  matches what Windows actually delivers (an immediate hard kill on
  deadline/cancel). Documented at `SubprocessOptions::no_window`'s doc
  comment (`subprocess_runner.hpp`) and both call sites above.
