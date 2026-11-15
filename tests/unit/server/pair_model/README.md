# Census pair-order oracle

This directory holds the executable model the census pair-order tests are checked against. It is
the delivery plan's model of 2026-11-09 (UP-14 server PR B): a Python program that decides, for a
schedule of deliveries to one agent, which verdict each census row holds, which events stay pending,
what the agent's order row and its counters read, and which decision label each delivery counts.

It is the oracle for `tests/unit/server/test_census_pair_harness.cpp`, which ports it to C++, replays
the same schedules through the real `GuaranteedStateStore`, and compares after every delivery. It is
not a dependency of the build and no meson target runs it; it is here so the digest table in the
harness can be regenerated and a model change reviewed in the open.

Files:

- `model.py` is the base model (rows, events, the agent order row, the ordering key).
- `ext.py` is the schedule generator `gen2` (clock steps, losses, late and lower-epoch deliveries).
- `pend.py` is the pending-evidence extension: `Store("plan", REC2)` is the model the tests use and
  `gen_actions` turns a seed into a schedule (first deliveries, failed census writes, redeliveries).
- `harness_digests.py` prints one line per seed, `<seed> <schedule digest> <trace digest>`, FNV-1a
  digests of the canonical schedule and model-trace text that `schedule_text` and `snap_text` in the
  harness reproduce.

To regenerate the digest table (Python 3.14.4 was used; any Python 3 gives the same output, the
generator only uses `random.Random(<int>)`):

    python3 -I tests/unit/server/pair_model/harness_digests.py 64

The 64 lines must equal the 64 pairs of `kPythonDigests` in the harness. A change to the model is a
change to that table: regenerate it, never edit a digest by hand. The check in the harness (the case
"census pair harness: the C++ port agrees with the Python model") needs no database.

Run the scripts from the repo; they locate each other through their own directory.
