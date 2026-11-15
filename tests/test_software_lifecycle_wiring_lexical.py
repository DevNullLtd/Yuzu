#!/usr/bin/env python3
"""SAM-23 lexical gate: the software lifecycle store stays wired and fail-closed.

Nothing exercises ServerImpl's boot block in a unit test, and a dropped line fails silently:

  * each refusal arm (store open, seed parse, empty seed, seed load) must set startup_failed_,
    or the server boots with no lifecycle rules and every lookup reads unknown;
  * /readyz must report a lifecycle store that failed to open, and HealthRoutes must be handed it;
  * stop() must drop the store ahead of the pool.

Each requirement reads the source text and fails with its id.
"""

import sys
from pathlib import Path

SRC = Path(__file__).resolve().parent.parent / "server" / "core" / "src"

# R1..R4: every refusal arm logs, then sets startup_failed_ within the same statement block.
ARMS = (
    "Refusing to start: software lifecycle store migration/open",
    "Refusing to start: embedded software lifecycle seed is",
    "Refusing to start: embedded software lifecycle seed has",
    "Refusing to start: software lifecycle seed load failed",
)
SERVER_NEEDLES = (
    ("R5: HealthRoutes Deps wiring", ".software_lifecycle_store = software_lifecycle_store_.get()"),
    ("R6: the empty-seed check", "seed->empty()"),
    ("R7: stop() resets the store", "software_lifecycle_store_.reset()"),
)


def main() -> int:
    server = (SRC / "server.cpp").read_text(encoding="utf-8")
    problems = []
    for n, arm in enumerate(ARMS, 1):
        at = server.find(arm)
        if at < 0:
            problems.append(f"R{n}: server.cpp lacks the refusal '{arm}'")
        elif "startup_failed_ = true" not in server[at : at + 400]:
            problems.append(f"R{n}: the refusal '{arm}' does not set startup_failed_")
    for rid, needle in SERVER_NEEDLES:
        if needle not in server:
            problems.append(f"{rid}: server.cpp lacks '{needle}'")
    if '"software_lifecycle_store"' not in (SRC / "health_routes.cpp").read_text(encoding="utf-8"):
        problems.append("R8: health_routes.cpp lacks the software_lifecycle_store /readyz row")
    for p in problems:
        print(p, file=sys.stderr)
    if problems:
        return 1
    print("software lifecycle wiring: ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
