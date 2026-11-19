#!/usr/bin/env python3
"""SAM-23 wiring + SAM-24 routes lexical gate: the software lifecycle store stays wired, fail-closed and observable.

Nothing exercises ServerImpl's boot block in a unit test (docs/testing/unit-test-conventions.md;
no unit test boots ServerImpl for any fail-closed store), and a dropped or inverted line fails
silently:

  * each refusal arm (store open, seed parse, empty seed, seed load) must set startup_failed_ as an
    uncommented statement, and the open, parse and load arms must be entered on the right
    condition (each joined to its own log line, since a bare `if (!seed) {` also guards the product
    registry); the empty-seed arm must refuse an EMPTY seed. Otherwise the server boots with no
    lifecycle rules and every lookup reads unknown (R1-R4, R6);
  * HealthRoutes must be handed the store and /readyz must report its real open state, not a
    constant (R5, R8);
  * stop() must drop the store ahead of the pool (R7);
  * the REST routes (SAM-24) must be registered ahead of RestApiV1::register_routes, with the real
    store and both gates, or the import, list and clear routes answer 503 forever or fall to the
    generic inventory GET (R11);
  * each degrade family must be pre-seeded at boot with every reason the store counts under THAT
    family (taken from its note_degrade call sites), so the first degrade reads as an increase
    from 0 (R9, R10).

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
# (condition that enters the arm, log line). The condition is matched joined to its own log line
# on whitespace-flattened text. The empty-seed arm has none: a comment sits between its condition
# and its log line, and R6 pins that condition instead.
ARM_LOG = 'spdlog::error("[PG] '
ARMS = (
    ("if (!software_lifecycle_store_->is_open()) {", "Refusing to start: software lifecycle store migration/open"),
    ("if (!seed) {", "Refusing to start: embedded software lifecycle seed is"),
    (None, "Refusing to start: embedded software lifecycle seed has"),
    ("!loaded) {", "Refusing to start: software lifecycle seed load failed"),
)
FLAG = "startup_failed_ = true"
# A statement at the start of a line: a `//`-commented flag does not count.
FLAG_STMT = re.compile(r"^[ \t]*" + re.escape(FLAG) + ";", re.M)
FLAG_WINDOW = 400
ROUTES_WINDOW = 400  # the Deps initialiser that follows the register_routes( call

DEPS_WIRING = ".software_lifecycle_store = software_lifecycle_store_.get()"
# The whole condition: the bare 'seed->empty()' is also a substring of '!seed->empty()'.
EMPTY_SEED_ARM = "else if (seed->empty())"
STORE_RESET = "software_lifecycle_store_.reset();"
POOL_RESET = "pg_pool_.reset();"  # the only occurrence with a semicolon; the rest are comments
READYZ_ROW = '"software_lifecycle_store"'
READYZ_EXPR = "deps.software_lifecycle_store && deps.software_lifecycle_store->is_open()"
ROUTES_REGISTER = "SoftwareLifecycleRoutes{}.register_routes("
REST_REGISTER = "rest_api_v1_->register_routes("
# The statement, not a comment that names it: only a line that starts with the call counts.
REST_STMT = re.compile(r"^[ \t]*" + re.escape(REST_REGISTER), re.M)
ROUTES_DEPS = (".perm_fn = perm_fn", ".audit_fn = audit_fn", ".store = software_lifecycle_store_.get()")
FAMILIES = (
    "yuzu_server_software_lifecycle_store_read_degrade_total",
    "yuzu_server_software_lifecycle_store_write_degrade_total",
)
STORE_CONST = re.compile(r'constexpr const char\* (k\w+) = "([^"]+)";')
# The (family, reason) pairs the store really counts: note_degrade(metrics_, kXFamily, kReasonY).
STORE_DEGRADE = re.compile(r"note_degrade\(\s*metrics_,\s*(k\w+Family),\s*(kReason\w+)\s*\)")


def preseed_loops(server: str, family: str):
    """The reason lists of the `for (const char* reason : {...}) metrics_.counter(family, ...)` loops."""
    pat = (
        r"for \(const char\* reason :\s*\{([^}]*)\}\)\s*metrics_\.counter\(\s*\"" + re.escape(family) + r"\""
    )
    return [re.findall(r'"([^"]+)"', body) for body in re.findall(pat, server)]


def problems(server: str, health: str, store: str) -> list:
    """One message per violated requirement; [] when clean."""
    out = []
    flat_server = re.sub(r"\s+", " ", server)
    for n, (cond, arm) in enumerate(ARMS, 1):
        at = server.find(arm)
        if at < 0:
            out.append(f"R{n}: server.cpp lacks the refusal '{arm}'")
            continue
        if not FLAG_STMT.search(server, at, at + FLAG_WINDOW):
            out.append(f"R{n}: the refusal '{arm}' does not set startup_failed_")
        if cond and f"{cond} {ARM_LOG}{arm}" not in flat_server:
            out.append(f"R{n}: the refusal '{arm}' is not entered on '{cond}'")
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

    routes_at = server.find(ROUTES_REGISTER)
    if routes_at < 0:
        out.append(f"R11: server.cpp lacks '{ROUTES_REGISTER}'")
    else:
        rest = REST_STMT.search(server)
        if rest is None or routes_at > rest.start():
            out.append("R11: the lifecycle routes must register ahead of rest_api_v1_->register_routes")
        window = server[routes_at : routes_at + ROUTES_WINDOW]
        for dep in ROUTES_DEPS:
            if dep not in window:
                out.append(f"R11: the lifecycle routes Deps lack '{dep}'")

    consts = dict(STORE_CONST.findall(store))
    reasons = [v for k, v in consts.items() if k.startswith("kReason")]
    if not reasons:
        out.append("R10: software_lifecycle_store.cpp declares no kReason* literal to pin")
    pairs = set()
    for fam, reason in STORE_DEGRADE.findall(store):
        if fam in consts and reason in consts:
            pairs.add((consts[fam], consts[reason]))
        else:
            out.append(f"R10: note_degrade({fam}, {reason}) names a constant the store does not declare")
    if not pairs:
        out.append("R10: software_lifecycle_store.cpp has no note_degrade call site to pin")
    seeded = {}
    for fam in FAMILIES:
        loops = preseed_loops(server, fam)
        if not loops:
            out.append(f"R9: server.cpp does not pre-seed {fam} reason by reason")
        seeded[fam] = {reason for loop in loops for reason in loop}
    for reason in sorted(set(reasons).difference(*seeded.values())):
        out.append(f"R10: reason '{reason}' of the store is not pre-seeded in server.cpp")
    for fam, reason in sorted(pairs):
        if reason not in seeded.get(fam, ()):
            out.append(f"R10: reason '{reason}' of {fam} is not in that family's pre-seed loop in server.cpp")
    return out


def edit_flag(arm: str, edit):
    """Apply `edit` to the startup_failed_ assignment that follows `arm`."""

    def mutate(server: str) -> str:
        at = server.find(arm)
        j = server.find(FLAG, at) if at >= 0 else -1
        if j < 0 or j - at >= FLAG_WINDOW:
            return server
        return server[:j] + edit(FLAG) + server[j + len(FLAG) :]

    return mutate


def invert_condition(cond: str, arm: str):
    """Drop the `!` of `cond`, the nearest occurrence of it before `arm`'s log line."""

    def mutate(server: str) -> str:
        at = server.find(arm)
        j = server.rfind(cond, 0, at) if at >= 0 else -1
        if j < 0:
            return server
        return server[:j] + cond.replace("!", "", 1) + server[j + len(cond) :]

    return mutate


def drop_reason(family: str, reason: str):
    """Remove `reason` from `family`'s pre-seed loop only."""
    pat = (
        r"(for \(const char\* reason :\s*\{)([^}]*)(\}\)\s*metrics_\.counter\(\s*\""
        + re.escape(family)
        + r"\")"
    )
    return lambda server: re.sub(
        pat,
        lambda m: m.group(1) + re.sub(rf'"{reason}",?\s*', "", m.group(2), count=1) + m.group(3),
        server,
        count=1,
    )


def edit_routes_dep(dep: str, replacement: str):
    """Replace `dep` inside the lifecycle routes' Deps initialiser only (other blocks share the names)."""

    def mutate(server: str) -> str:
        at = server.find(ROUTES_REGISTER)
        j = server.find(dep, at) if at >= 0 else -1
        if j < 0 or j - at >= ROUTES_WINDOW:
            return server
        return server[:j] + replacement + server[j + len(dep) :]

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
        (f"arm {n} no longer sets startup_failed_", "server", edit_flag(arm, lambda f: "(void)0"), f"R{n}")
        for n, (_, arm) in enumerate(ARMS, 1)
    ),
    *(
        (f"arm {n} sets startup_failed_ only in a comment", "server", edit_flag(arm, lambda f: "// " + f), f"R{n}")
        for n, (_, arm) in enumerate(ARMS, 1)
    ),
    *(
        (f"arm {n} entered on the inverted condition", "server", invert_condition(cond, arm), f"R{n}")
        for n, (cond, arm) in enumerate(ARMS, 1)
        if cond
    ),
    (
        "routes registration dropped",
        "server",
        lambda t: t.replace(ROUTES_REGISTER, "SoftwareLifecycleRoutesGone{}.register_routes(", 1),
        "R11",
    ),
    (
        "routes registered after the generic inventory GET",
        "server",
        lambda t: t.replace(ROUTES_REGISTER, REST_REGISTER + ");\n        " + ROUTES_REGISTER, 1),
        "R11",
    ),
    *(
        (f"routes Deps lose '{dep}'", "server", edit_routes_dep(dep, dep.split(" = ")[0] + " = nullptr"), "R11")
        for dep in ROUTES_DEPS
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
    # A reason both families count, dropped from one family's loop while the other still seeds it.
    ("read pre-seed loop lacks a shared reason", "server", drop_reason(FAMILIES[0], "pool_acquire_timeout"), "R10"),
    ("write pre-seed loop lacks a shared reason", "server", drop_reason(FAMILIES[1], "pool_acquire_timeout"), "R10"),
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
