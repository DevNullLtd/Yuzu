# #4658 Windows evidence (independent re-run of the File worker pass-failure backoff)

What this is: raw output of an independent verification run of the #4658 change on a Windows 11
laptop (MSVC 19.44, the project's Windows dev rig), plus an A/B of a known load-sensitive test
against the pre-change code. Captured 2026-09-21 (UTC+1). Not a governance adjudication.

Who ran it, honestly: the orchestrating Claude session (Sonnet 5) for #4658, over SSH, with a
git bundle transferred to a clean worktree and a sha hard-gate (a run aborts unless the checked-out
HEAD equals the wanted sha). It is NOT the implementing agent's own run (those logs are separate,
self-reported and not committed), and it is NOT a run by a human operator. Treat it as evidence
from the same session, independent of the implementer.

Tree under test: `9a3b7abb9f313e73029682d33e8b1b67612517c0` (branch
`fix/spark-4658-file-worker-pass-failure-backoff`); the four changed C++ files hash to the values in
`final-head/4658.sha256.dgrhp`. Production code (`agents/core/src/spark_file.cpp`) is identical to
the tree the earlier runs used; only test files and docs changed after it. Those four hashes equal
the git blobs at `9a3b7abb9` and at the branch head this README was committed on.

The `.log` files below are force-added: the repository's `.gitignore` excludes `*.log`, and an
earlier commit of this directory silently lost them.

## final-head/
- `pf_1..3.log`: the `[spark][mechanism][windows][passfail]` filter, three runs: all passed
  (16 cases, 176 assertions).
- `sw_1.log`, `sw_2.log`: the `[spark][windows]` filter twice: run 1 failed on the known storm
  assertion `CHECK( max_active <= kTestLaneCap )  9 <= 8` (issues #4279 and #4660), run 2 passed
  (145 cases, 1830 assertions).
- `mut_*.log` / `restore_*.log`: five mutants applied to the DGRHP copy only, never committed,
  each followed by a restore, rebuild and green rerun:
  - `M_old_floor` (the pre-fix wake floor): PF-11 and PF-12 fail.
  - `M_min` (`wake = min(wake, pass_backoff_until_)`): PF-1 and PF-9 fail, on their CPU-time assertions.
  - `M_dispatch` (`if (!dispatched) ok = false;` in both catch blocks): PF-15 and PF-15b fail.
  - `M_first` (first catch only): PF-15 fails alone. `M_second` (second catch only): PF-15b fails alone.
- `run-summary.txt`: the driver's own summary lines (counts only; which tests failed is in the
  `.log` files). `full_1` and `full_2` at its end exited 1, not 42 (the code every Catch2 failure
  above exits with). Their logs were not retained and their cause is not attributed here; they are
  superseded by the direct full-suite runs in `ab/`.
- `passfail_list.txt`: the names of the 16 `[passfail]` cases.
- `4658.sha256.dgrhp`: nine lines. The first four are the sha256 of the four changed C++ files as
  built on DGRHP; the next five repeat the `spark_file.cpp` hash. The driver script is not
  committed and this README does not attribute those five lines.

## ab/
Interleaved A/B on the same box, saved binaries (`binaries.sha256`): the pre-change code
(`09e738db5`, the four changed files checked out from it) against the tree above.
- Isolated storm test, 30 pairs: head 29 pass / 1 fail, pre-change 27 pass / 3 fail.
- Full agent suite (`~[tsan-heavy]`, run directly, no meson timeout), 4 pairs: head 4 of 4 passed
  (3485 cases, 3481 passed, 4 skipped); pre-change 2 of 4 passed, the two failures being the storm
  assertion (`full_base_*-summary.txt`).
- Reading: the flake is present in the pre-change code and the change does not make it more
  frequent in this sample; the samples are small and the rate depends on machine load.
  `ab-summary.txt` has the per-run lines; the four failing isolated runs' logs are
  `ab/iso_base_10.log`, `iso_base_23.log`, `iso_base_30.log` and `iso_head_2.log`, and each shows
  the storm assertion `CHECK( max_active <= kTestLaneCap )` (line 7053 in the pre-change test file,
  8065 in the head one). The full-suite runs are summarised in `full_*_summary.txt`; their raw logs
  are not committed.

## promql/
The `promtool` check the flip-gate section 5 entry for #4685 refers to. `rules-4685.yml` holds the two
published expressions (File and Registry) exactly as they appear there; `test-4685.yml` is a
`promtool test rules` unit test over synthetic series (it includes the absent-mechanism-series case);
`test-4685-negctl.yml` is the same test with flipped expectations, so promtool must FAIL it. Run from
this directory. Re-run by the orchestrating session on 2026-09-21 with promtool 3.13.2
(`prom/prometheus:latest` container, no network): `test-4685.yml` exits 0 (SUCCESS) and
`test-4685-negctl.yml` exits 1. Synthetic series only: nothing here measures a real fleet.

## Limits (do not read more into this than it says)
- One machine, one session, small samples. No non-author human ran it.
- A first independent full-suite attempt at an earlier commit timed out at 240 s because another
  process was building and testing in the same worktree; it is not included and proves nothing.
- Paths in the logs were rewritten (`C:\Users\<user>`). The `.log` files are otherwise as
  captured; the small text summaries additionally had trailing whitespace and carriage returns
  stripped so `git diff --check` passes.
- The implementing agent's own self-reported logs (RED/GREEN/mutation per round) are not committed.
