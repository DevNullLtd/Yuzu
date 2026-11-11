#!/usr/bin/env python3
"""SAM-17 lexical gate: the software lookup routes' hostname source stays wired.

The `hostname` field of GET /api/v1/inventory/software[/components] reads the device-table roster
through RestApiV1::set_hostnames_fn. An unset function leaves every hostname null, a silent
degradation: the route tests inject their own roster and nothing unit-tests ServerImpl's wiring.

Each requirement below reads server.cpp and fails with the requirement id.

  R1  the roster function is handed to rest_api_v1_;
  R2  that call precedes rest_api_v1_->register_routes( (the setter's contract in rest_api_v1.hpp:
      BEFORE register_routes()).

A match must be a statement on its own line, so a comment that quotes the call cannot satisfy it.
"""

import re
import sys
from pathlib import Path

SRC = Path(__file__).resolve().parent.parent / "server" / "core" / "src"

SETTER = re.compile(r"^[ \t]*rest_api_v1_->set_hostnames_fn\(hw_hostnames_fn\);", re.MULTILINE)
REGISTER = re.compile(r"^[ \t]*rest_api_v1_->register_routes\(", re.MULTILINE)


def check(text: str) -> list:
    problems: list = []
    setter = SETTER.search(text)
    register = REGISTER.search(text)
    if setter is None:
        problems.append(
            "R1: server.cpp does not call rest_api_v1_->set_hostnames_fn(hw_hostnames_fn); "
            "every software lookup row would carry hostname null"
        )
    if register is None:
        problems.append("R2: server.cpp does not contain a rest_api_v1_->register_routes( call")
    if setter is not None and register is not None and setter.start() > register.start():
        problems.append(
            "R2: rest_api_v1_->set_hostnames_fn runs after rest_api_v1_->register_routes; "
            "the setter must precede it"
        )
    return problems


def main() -> int:
    problems = check((SRC / "server.cpp").read_text(encoding="utf-8"))
    for p in problems:
        print(p, file=sys.stderr)
    if problems:
        return 1
    print("software lookup wiring: ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
