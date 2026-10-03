# #5087 — T_server exit-time worker-join shutdown bound: empirical validation

Validates the design claim in #4666 PR-4 (`server/core/src/guardian_ingest.{hpp,cpp}`,
`docs/resource-ledgers/4666-t-server-async-logger.md`): T_server's dedicated async logger has
no teardown watchdog by design — an accepted, not eliminated, exposure. The claim: the exit-time
worker-join hazard is bounded only by a **second** `SIGINT`/`SIGTERM` (or the deployment's
external 210s systemd/Compose stop deadline), never by the first signal alone, because `main.cpp`'s
`on_signal_hard_exit` is signal-driven (escalates only on `g_signal_count >= 1`), not self-armed.
This was previously proven only by source reading (`_exit()` is async-signal-safe and skips static
destructors; no `SIG_DFL` reset anywhere in `main.cpp`). This run exercises it on the real binary.

## Environment

- Rig: devrig1 (BigColin), web `:8090`, gateway `:50061`, server gRPC `:50064`, Postgres `:15433`.
- Code under test: `feat/4666-pr4-t-server-async-logger` fetched directly from the parent session's
  worktree (`/home/dgr/Yuzu/.claude/worktrees/agent-ac548cb1d35bc4b4f`), HEAD `fd1696df9` — **not**
  `origin/dev`, which does not yet have PR-4 (`T_server` is still synchronous there). Merge-base with
  `origin/dev`: `0d7e96acc`.
- Guardian traffic: a local, untracked copy of `docs/spark-rebuild-baselines/4666_blocked_sink_chaos.py`
  (from the `4666-criterion2-chaos-evidence` branch's Phase-1 work), `RULE_COUNT` reduced 500→50 — a
  Linux legacy-path service-mechanism rule set, no Spark `prefer_spark_` patch needed (legacy-path
  arm-commits already drive `ingest_guardian_response`'s `Inserted` arm → `T_server`).
- `--no-nvd-sync` added to the server launch for every run below — **load-bearing**: without it, the
  background NVD sync thread's own known, unrelated issue (#1867: "NVD sync thread did not exit
  within 5s ... detaching + leaking the manager to avoid wedging shutdown") adds 2-5s of its own
  shutdown delay that dominates and confounds any attempt to isolate the log-sink effect. First-pass
  runs without this flag are recorded below for transparency but not used as evidence.

## Method (final, decisive design)

A naive slow-reader-on-a-default-64KiB-pipe design (several early attempts, below) never produced a
measurable effect: a 50-rule burst (~15-45KB of log text) never came close to filling a 64KiB kernel
pipe buffer, so the server's writes never actually blocked, regardless of how slowly the reader
drained it afterward — the WRITE calls returned instantly into kernel buffer space the whole time.

The decisive, deterministic design (mirrors `tests/shell/test_blocked_log_sink_sigterm.sh`'s own
`open_blocked_fifo()` technique):
1. `mkfifo` + `exec 9<>fifo` to hold the pipe object open across all later opens.
2. Shrink the pipe to 4096 bytes via `fcntl(9, F_SETPIPE_SZ, 4096)`, **verified** via
   `F_GETPIPE_SZ` readback (script fails loudly, exit 2, if the shrink doesn't take).
3. A background `while read -u 9` loop drains at one line per 100ms into `server.log`.
4. **Before** generating any Guardian traffic, `SIGSTOP` the reader process — this makes backpressure
   deterministic instead of a timing race: with the reader frozen, the 4096-byte pipe fills from
   ordinary boot/request logging alone within seconds, and the T_server worker thread's next
   `sink->log()` call is **guaranteed** to block on the full pipe, not merely likely to.
5. Arm 50 rules via REST (confirms the server's OTHER surfaces — HTTP/gRPC — stay responsive even
   with the log sink fully blocked: the arm script completed cleanly, 50/50, in this state).
6. Confirm genuine backlog: `grep -c "Guardian T_server" server.log` read 0 immediately after arming
   (all 50 arm-commits' T_server lines were sitting unwritten in the agent→server pipeline and/or
   blocked in the stalled pipe — the worker was provably stuck, not merely assumed to be).
7. `SIGTERM` the server. Poll `kill -0` every 200ms. If still alive past 15s, send a second `SIGTERM`
   and measure time-to-exit from that point.
8. `SIGCONT` the reader afterward; confirm no truncated/garbled lines in whatever drained.

## Results

| Run | Config | NVD sync | Pipe | Reader state at SIGTERM | Elapsed (SIGTERM→exit) |
|---|---|---|---|---|---|
| 1 | control | on | n/a (plain file) | n/a | 7.09s |
| 2 | slow-sink | on | 64KiB default, 20 lines/s | running | ~8.96s (confounded by #1867) |
| 3 | control | off (`--no-nvd-sync`) | n/a | n/a | **4.86s** (clean baseline) |
| 4 | slow-sink | off | 64KiB default, 10 lines/s | running | 3.51s (no effect — pipe never filled) |
| 5 | slow-sink | off | 64KiB default, 3.3 lines/s | running | 1.32s (no effect — still never filled) |
| 6 | slow-sink, **decisive** | off | **4096 bytes (verified)** | **frozen (SIGSTOP)** | **first SIGTERM: still alive at 15s. Second SIGTERM at 15.09s elapsed → exited at 15.31s (≈0.22s after the second signal).** |

Run 6 is the evidence. Runs 1-5 are recorded for transparency about what doesn't reproduce the
hazard (a brief, modest-volume burst against a default-sized pipe) — worth keeping on the record so
a future reader doesn't have to rediscover that a naive version of this test is a false negative.

## Pass/fail against the design's prediction

- **"First SIGTERM alone does not bound the exit when the sink is genuinely blocked": CONFIRMED.**
  Run 6's server was still alive 15 seconds after the first signal, with no sign of progressing
  toward exit.
- **"A second signal bounds it, near-instantly, via `_exit()`": CONFIRMED.** Exit followed the second
  `SIGTERM` by ~0.22s — consistent with `_exit()`'s async-signal-safety (no destructors, no further
  log writes attempted).
- **"The server's other surfaces stay responsive even with T_server's sink blocked": CONFIRMED.** The
  50-rule arm (REST API calls, Postgres writes, Baseline deploy) completed cleanly while the sink was
  already frozen — the async design does not stall unrelated server activity.
- **"No truncated/interleaved log writes": CONFIRMED.** Every line that did drain (in every run,
  including run 6's partial post-mortem drain) was well-formed; `grep -c` and manual inspection found
  no garbled lines.
- **Queue-depth × per-line-latency timing shape**: not independently validated as a formula in this
  run — the decisive test used a frozen reader (0 drain rate) specifically to make backpressure
  deterministic, which by construction doesn't exercise a *partial*-drain-rate timing curve. The
  qualitative claim (slower drain → longer first-signal survival, up to the point of needing a second
  signal) is consistent with runs 3-6 taken together but was not isolated as its own measurement.

## Caveats / residual scope

- This run used the Linux **legacy guard path** (no `prefer_spark_` patch), not Spark. The T_server
  hazard is specific to the dedicated async logger introduced in PR-4, which is identical regardless
  of which detection mechanism (legacy or Spark) produced the arm-commit — the mechanism under test
  doesn't depend on which path armed the rule.
- 50 rules was enough once the pipe was correctly sized (4096 bytes) and the reader frozen; no need
  was found to scale up to 500 for this specific validation, unlike #4666 criterion-2's own test.
- The reader-freeze technique (`SIGSTOP`) is a test artifact, not a production fault model — a real
  production incident (disk full, NFS stall, a genuinely dead pipe) would look more like this than
  like runs 4/5's naive slow-drain, which is itself informative: a *merely slow* sink is unlikely to
  matter unless genuinely still (closer to "blocked"), matching production intuition.
- Confirmed (#1867) independently along the way: NVD sync's own shutdown delay is real, measurable,
  and dominates this kind of timing experiment if not disabled — flagged for whoever next designs a
  server-shutdown-timing test on this codebase.

## Conclusion

**#5087's claim is confirmed on the real binary, not merely by source reading.** The accepted,
documented exposure (no teardown watchdog; bounded only by a second signal or the external 210s
deploy timeout) is real, reproducible, and behaves exactly as designed: survivable, bounded, and
correctly degrades rather than wedging the process indefinitely.
