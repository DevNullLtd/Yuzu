#!/usr/bin/env python3
"""SAM-23 lexical gate: the software lifecycle store stays wired, fail-closed and observable.

Nothing exercises ServerImpl's boot block in a unit test (docs/testing/unit-test-conventions.md;
no unit test boots ServerImpl for any fail-closed store), and a dropped or inverted line fails
silently:

  * each refusal arm (store open, seed parse, empty seed, seed load) must set startup_failed_, and
    the empty-seed arm must refuse an EMPTY seed, or the server boots with no lifecycle rules and
    every lookup reads unknown (R1-R4, R6);
  * HealthRoutes must be handed the store and /readyz must report its real open state, not a
    constant (R5, R8);
  * stop() must drop the store ahead of the pool (R7);
  * both degrade families must be pre-seeded at boot with every reason the store can count, so the
    first degrade reads as an increase from 0 (R9, R10).

problems() is a pure function over the source text. The mutation table below applies each defect
in memory and requires problems() to name the matching requirement; a mutation whose pattern no
longer matches the source fails as a stale pattern, never passes vacuously.

Usage: python3 tests/test_software_lifecycle_wiring_lexical.py
"""

import re
import sys
import unittest
from pathlib import Path

SRC = Path(__file__).resolve().parent.parent / "server" / "core" / "src"

# R1..R4: every refusal arm logs, then sets startup_failed_ within the same statement block.
ARMS = (
    "Refusing to start: software lifecycle store migration/open",
    "Refusing to start: embedded software lifecycle seed is",
    "Refusing to start: embedded software lifecycle seed has",
    "Refusing to start: software lifecycle seed load failed",
)
FLAG = "startup_failed_ = true"
FLAG_WINDOW = 400

DEPS_WIRING = ".software_lifecycle_store = software_lifecycle_store_.get()"
# The whole condition: the bare 'seed->empty()' is also a substring of '!seed->empty()'.
EMPTY_SEED_ARM = "else if (seed->empty())"
STORE_RESET = "software_lifecycle_store_.reset();"
POOL_RESET = "pg_pool_.reset();"  # the only occurrence with a semicolon; the rest are comments
READYZ_ROW = '"software_lifecycle_store"'
READYZ_EXPR = "deps.software_lifecycle_store && deps.software_lifecycle_store->is_open()"
FAMILIES = (
    "yuzu_server_software_lifecycle_store_read_degrade_total",
    "yuzu_server_software_lifecycle_store_write_degrade_total",
)
STORE_REASON = re.compile(r'constexpr const char\* kReason\w+ = "([^"]+)";')


def preseed_loops(server: str, family: str):
    """The reason lists of the `for (const char* reason : {...}) metrics_.counter(family, ...)` loops."""
    pat = (
        r"for \(const char\* reason :\s*\{([^}]*)\}\)\s*metrics_\.counter\(\s*\"" + re.escape(family) + r"\""
    )
    return [re.findall(r'"([^"]+)"', body) for body in re.findall(pat, server)]


def problems(server: str, health: str, store: str) -> list:
    """One message per violated requirement; [] when clean."""
    out = []
    for n, arm in enumerate(ARMS, 1):
        at = server.find(arm)
        if at < 0:
            out.append(f"R{n}: server.cpp lacks the refusal '{arm}'")
        elif FLAG not in server[at : at + FLAG_WINDOW]:
            out.append(f"R{n}: the refusal '{arm}' does not set startup_failed_")
    if DEPS_WIRING not in server:
        out.append(f"R5: server.cpp lacks '{DEPS_WIRING}' (HealthRoutes Deps wiring)")
    if EMPTY_SEED_ARM not in server:
        out.append(f"R6: server.cpp lacks the empty-seed refusal condition '{EMPTY_SEED_ARM}'")
    reset, pool = server.find(STORE_RESET), server.find(POOL_RESET)
    if reset < 0:
        out.append(f"R7: stop() lacks '{STORE_RESET}'")
    elif pool < 0:
        out.append(f"R7: server.cpp lacks '{POOL_RESET}', so the store's reset order cannot be pinned")
    elif reset > pool:
        out.append("R7: stop() resets the lifecycle store after the pool; it must drop first")
    flat = re.sub(r"\s+", " ", health)
    if READYZ_ROW not in flat:
        out.append("R8: health_routes.cpp lacks the software_lifecycle_store /readyz row")
    if READYZ_EXPR not in flat:
        out.append(f"R8: the /readyz row is not '{READYZ_EXPR}'")

    reasons = STORE_REASON.findall(store)
    if not reasons:
        out.append("R10: software_lifecycle_store.cpp declares no kReason* literal to pin")
    seeded = set()
    for fam in FAMILIES:
        loops = preseed_loops(server, fam)
        if not loops:
            out.append(f"R9: server.cpp does not pre-seed {fam} reason by reason")
        for loop in loops:
            seeded.update(loop)
    for reason in sorted(set(reasons) - seeded):
        out.append(f"R10: reason '{reason}' of the store is not pre-seeded in server.cpp")
    return out


def drop_flag(arm: str):
    def mutate(server: str) -> str:
        at = server.find(arm)
        j = server.find(FLAG, at) if at >= 0 else -1
        if j < 0 or j - at >= FLAG_WINDOW:
            return server
        return server[:j] + "(void)0" + server[j + len(FLAG) :]

    return mutate


def reset_after_pool(server: str) -> str:
    if STORE_RESET not in server or POOL_RESET not in server:
        return server
    server = server.replace(STORE_RESET, "", 1)
    return server.replace(POOL_RESET, POOL_RESET + "\n" + STORE_RESET, 1)


def remove_preseed(family: str):
    pat = (
        r"for \(const char\* reason :\s*\{[^}]*\}\)\s*metrics_\.counter\(\s*\""
        + re.escape(family)
        + r"\"[^;]*;"
    )
    return lambda server: re.sub(pat, "", server, count=1)


# (label, target file, mutation, requirement id that must be reported)
MUTATIONS = [
    *(
        (f"arm {n} no longer sets startup_failed_", "server", drop_flag(arm), f"R{n}")
        for n, arm in enumerate(ARMS, 1)
    ),
    ("Deps wiring dropped", "server", lambda t: t.replace(DEPS_WIRING, ".x = nullptr", 1), "R5"),
    (
        "empty-seed condition inverted",
        "server",
        lambda t: t.replace(EMPTY_SEED_ARM, "else if (!seed->empty())", 1),
        "R6",
    ),
    ("store reset dropped", "server", lambda t: t.replace(STORE_RESET, "", 1), "R7"),
    ("store reset moved after the pool", "server", reset_after_pool, "R7"),
    ("readyz row removed", "health", lambda t: t.replace(READYZ_ROW, '"other_store"', 1), "R8"),
    ("readyz row hardcoded true", "health", lambda t: t.replace(READYZ_EXPR, "true", 1), "R8"),
    ("read pre-seed loop removed", "server", remove_preseed(FAMILIES[0]), "R9"),
    ("write pre-seed loop removed", "server", remove_preseed(FAMILIES[1]), "R9"),
    (
        "a reason added to the store with no seed",
        "store",
        lambda t: t + '\nconstexpr const char* kReasonBrandNew = "brand_new_reason";\n',
        "R10",
    ),
]


def read(name: str) -> str:
    return (SRC / name).read_text(encoding="utf-8")


class SoftwareLifecycleWiringLexical(unittest.TestCase):
    def setUp(self):
        self.src = {
            "server": read("server.cpp"),
            "health": read("health_routes.cpp"),
            "store": read("software_lifecycle_store.cpp"),
        }

    def test_source_is_clean(self):
        p = problems(self.src["server"], self.src["health"], self.src["store"])
        for m in p:
            print(f"::error::software lifecycle wiring: {m}", file=sys.stderr)
        self.assertEqual(p, [])

    def test_mutations_are_caught(self):
        for label, target, mutate, rid in MUTATIONS:
            with self.subTest(mutation=label):
                mutated = dict(self.src)
                mutated[target] = mutate(self.src[target])
                self.assertNotEqual(mutated[target], self.src[target], "mutation changed nothing (stale pattern)")
                found = problems(mutated["server"], mutated["health"], mutated["store"])
                self.assertTrue(
                    any(m.startswith(rid + ":") for m in found),
                    f"{rid} was not reported; got {found}",
                )


if __name__ == "__main__":
    sys.exit(0 if unittest.main(exit=False).result.wasSuccessful() else 1)
