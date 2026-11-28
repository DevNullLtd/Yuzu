#!/usr/bin/env python3
"""SAM-33 lexical gate: the installed-software v3 read routes and their fleet snapshot stay wired.

Nothing exercises ServerImpl's wiring in a unit test, and each failure here is silent:

  * httplib dispatches in registration order with full-match regexes, so the two-segment paths
    (hosts, changes, summary, plugin-health) are taken by the generic
    GET /api/v1/inventory/{a}/{b} unless SoftwareReadRoutes registers first; a composed-sink unit
    test would pick its own order and prove nothing about this file;
  * an unattached snapshot holder leaves every globally admitted summary and plugin-health call at
    `omitted=building` forever and the facet gauges (which drive both alerts) unpopulated, with
    every route and rollup test still green.

Each requirement below reads server.cpp and fails with the requirement id.

  R1  SoftwareReadRoutes{}.register_routes( precedes rest_api_v1_->register_routes(;
  R2  the rollup is handed the snapshot holder, and before it starts;
  R3  the routes' snapshot_fn reads that same holder.

A match must be a statement on its own line, so a comment that quotes the call cannot satisfy it.
"""

import re
import sys
from pathlib import Path

SRC = Path(__file__).resolve().parent.parent / "server" / "core" / "src"

READ_ROUTES = re.compile(r"^[ \t]*SoftwareReadRoutes\{\}\.register_routes\(", re.MULTILINE)
REST_ROUTES = re.compile(r"^[ \t]*rest_api_v1_->register_routes\(", re.MULTILINE)
HOLDER = re.compile(
    r"^[ \t]*software_catalog_rollup_->set_snapshot_holder\(&software_fleet_snapshot_\);",
    re.MULTILINE,
)
ROLLUP_START = re.compile(r"^[ \t]*software_catalog_rollup_->start\(\);", re.MULTILINE)
SNAPSHOT_FN = re.compile(
    r"^[ \t]*\.snapshot_fn\s*=\s*\[this\]\s*\{\s*return\s+software_fleet_snapshot_\.get\(\);\s*\}",
    re.MULTILINE,
)


def check(text: str) -> list:
    problems: list = []
    read_routes = READ_ROUTES.search(text)
    rest_routes = REST_ROUTES.search(text)
    if read_routes is None:
        problems.append("R1: server.cpp does not register SoftwareReadRoutes")
    if rest_routes is None:
        problems.append("R1: server.cpp does not contain a rest_api_v1_->register_routes( call")
    if read_routes is not None and rest_routes is not None and read_routes.start() > rest_routes.start():
        problems.append(
            "R1: SoftwareReadRoutes registers later than rest_api_v1_->register_routes; the generic "
            "GET /api/v1/inventory/{a}/{b} would take /software/hosts, /changes, /summary and "
            "/plugin-health"
        )

    holder = HOLDER.search(text)
    start = ROLLUP_START.search(text)
    if holder is None:
        problems.append(
            "R2: server.cpp does not call software_catalog_rollup_->set_snapshot_holder("
            "&software_fleet_snapshot_); every fleet summary and plugin-health call would stay "
            "omitted=building"
        )
    if start is None:
        problems.append("R2: server.cpp does not contain a software_catalog_rollup_->start() call")
    if holder is not None and start is not None and holder.start() > start.start():
        problems.append(
            "R2: software_catalog_rollup_->set_snapshot_holder runs after "
            "software_catalog_rollup_->start(); the holder must be attached before the thread starts"
        )

    if SNAPSHOT_FN.search(text) is None:
        problems.append(
            "R3: the SoftwareReadRoutes snapshot_fn does not return software_fleet_snapshot_.get(); "
            "the routes would never see the rollup's snapshot"
        )
    return problems


def main() -> int:
    problems = check((SRC / "server.cpp").read_text(encoding="utf-8"))
    for p in problems:
        print(p, file=sys.stderr)
    if problems:
        return 1
    print("software read wiring: ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
