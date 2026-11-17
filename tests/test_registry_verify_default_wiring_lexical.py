#!/usr/bin/env python3
"""Static lexical gate: the Registry path verification is OFF unless the operator opts in (REG-15-I2).

The Registry mechanism's periodic path verification opens every watched key by path once per
interval; on a key with an auditing SACL each open writes a Security-log event (#5719 item 5,
#7836). It is OFF by default and opt-in at boot through --spark-registry-path-verify-interval
(env YUZU_AGENT_SPARK_REGISTRY_PATH_VERIFY_INTERVAL). The Catch2 cases observe the FACTORY default
(make_registry_mechanism(counter)) and the Config field default and its clamp, but nothing unit
tests the two links that carry the operator's value (or its absence) into the factory: main.cpp's
option and agent.cpp's call. A refactor that defaulted the option to 5 or passed a literal to the
factory would compile and leave every behavioural test green. Pinned here:

  1. agents/core/src/main.cpp: the option `--spark-registry-path-verify-interval` is bound to
     `cfg.spark_registry_path_verify_interval_s`, its chain carries `->default_val(0)` and the env
     name, and it carries NO validator (`->check(`, `CLI::Range`, `->transform(`): CLI11 runs a
     validator on an ENVIRONMENT value and silently drops a value that fails it, so an
     out-of-range env setting would be ignored without a word. The range is checked after
     `CLI11_PARSE(app, argc, argv);` with `< 0 ||` and `> 86400`, refusing with EXIT_FAILURE.
  2. agents/core/src/agent.cpp: exactly one statement
     `const auto <name> = clamp_registry_path_verify(cfg_.spark_registry_path_verify_interval_s);`
     and exactly one `make_registry_mechanism(` call, whose arguments are exactly
     `spark_detached_workers_, <name>` (the two-argument overload with that clamped local).
  3. agents/core/include/yuzu/agent/agent.hpp: the field default is
     `int spark_registry_path_verify_interval_s{0};` exactly once.

Robustness: comments are stripped (string literals kept) and whitespace collapsed before matching,
so a comment quoting a pattern cannot satisfy it. Carries an in-memory mutation self-test; a
mutation whose pattern no longer matches fails loudly (stale pattern) rather than passing
vacuously. WHAT THIS CANNOT PROVE: it is lexical. It does not run the CLI parser (so it cannot see a
default installed by some other route, such as a config file layer), it does not follow a second
construction of the Registry mechanism added in another file, and it cannot see control flow that
keeps the tokens but changes which value reaches the call. The comment stripper is a
single-pass regex, so a char literal holding a double quote could confuse it (none is in the three
files today; the clean-tree test would go red, not green).

Usage: python3 tests/test_registry_verify_default_wiring_lexical.py
"""
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MAIN_CPP = ROOT / "agents" / "core" / "src" / "main.cpp"
AGENT_CPP = ROOT / "agents" / "core" / "src" / "agent.cpp"
AGENT_HPP = ROOT / "agents" / "core" / "include" / "yuzu" / "agent" / "agent.hpp"
HINT = (" (this gate pins the Registry verification default-off wiring; if the files were"
        " legitimately restructured, update the patterns AND the MUTATIONS in"
        " tests/test_registry_verify_default_wiring_lexical.py)")

OPT = "--spark-registry-path-verify-interval"
FIELD = "spark_registry_path_verify_interval_s"
ENV = "YUZU_AGENT_SPARK_REGISTRY_PATH_VERIFY_INTERVAL"

_TOKEN = re.compile(r'"(?:\\.|[^"\\\n])*"|//[^\n]*|/\*.*?\*/', re.S)


def normalise(src):
    """Strip comments (string literals kept) and collapse whitespace."""
    def keep(m):
        return m.group(0) if m.group(0).startswith('"') else " "
    return re.sub(r"\s+", " ", _TOKEN.sub(keep, src))


def statement_from(t, start):
    """The text from `start` to the first `;` that is outside a string literal."""
    i = start
    while i < len(t):
        c = t[i]
        if c == '"':
            m = re.compile(r'"(?:\\.|[^"\\])*"').match(t, i)
            i = m.end() if m else i + 1
            continue
        if c == ";":
            return t[start:i + 1]
        i += 1
    return t[start:]


def main_problems(src):
    t = normalise(src)
    out = []
    starts = [m.start() for m in re.finditer(re.escape('app.add_option("' + OPT + '"'), t)]
    if len(starts) != 1:
        return ["main.cpp does not declare the option %s exactly once (found %d)%s"
                % (OPT, len(starts), HINT)]
    stmt = statement_from(t, starts[0])
    if not re.search(r'^app\.add_option\("' + re.escape(OPT) + r'", cfg\.' + FIELD + r",", stmt):
        out.append("the option is no longer bound to cfg.%s%s" % (FIELD, HINT))
    if "->default_val(0)" not in stmt:
        out.append("the option's chain no longer carries ->default_val(0): the default is not "
                   "off" + HINT)
    if '->envname("' + ENV + '")' not in stmt:
        out.append("the option's chain no longer names the env var " + ENV + HINT)
    for banned in ("->check(", "CLI::Range", "->transform(", "->each(", "->expected("):
        if banned in stmt:
            out.append("the option carries `%s`: CLI11 silently drops an environment value that "
                       "fails a validator, so the range must be checked after the parse%s"
                       % (banned, HINT))
    parse = t.find("CLI11_PARSE(app, argc, argv);")
    check = re.search(
        r"if \( ?cfg\." + FIELD + r" < 0 \|\| cfg\." + FIELD + r" > 86400 ?\) \{"
        r"[^{}]*return EXIT_FAILURE; ?\}", t)
    if parse < 0:
        out.append("main.cpp no longer calls CLI11_PARSE(app, argc, argv)" + HINT)
    elif not check:
        out.append("the post-parse 0..86400 range check (refusing with EXIT_FAILURE) is gone or "
                   "changed" + HINT)
    elif check.start() < parse:
        out.append("the range check no longer follows CLI11_PARSE" + HINT)
    return out


def agent_problems(src):
    t = normalise(src)
    out = []
    decls = re.findall(
        r"const auto (\w+) = clamp_registry_path_verify\( ?cfg_\." + FIELD + r" ?\);", t)
    calls = re.findall(r"make_registry_mechanism\(", t)
    if len(decls) != 1:
        out.append("agent.cpp does not hold exactly one `const auto <x> = "
                   "clamp_registry_path_verify(cfg_.%s);` (found %d)%s"
                   % (FIELD, len(decls), HINT))
    if len(calls) != 1:
        out.append("agent.cpp does not call make_registry_mechanism( exactly once (found %d): a "
                   "second construction site is a second default%s" % (len(calls), HINT))
    if len(decls) == 1 and len(calls) == 1:
        want = r"make_registry_mechanism\( ?spark_detached_workers_, ?%s ?\)" % re.escape(decls[0])
        if not re.search(want, t):
            out.append("the make_registry_mechanism call no longer passes exactly "
                       "(spark_detached_workers_, %s), the clamped operator value%s"
                       % (decls[0], HINT))
    return out


def hpp_problems(src):
    t = normalise(src)
    n = len(re.findall(r"\bint " + FIELD + r"\{0\};", t))
    if n != 1:
        return ["agent.hpp does not declare `int %s{0};` exactly once (found %d)%s"
                % (FIELD, n, HINT)]
    return []


def problems(main_src, agent_src, hpp_src):
    return main_problems(main_src) + agent_problems(agent_src) + hpp_problems(hpp_src)


# (name, file key, old text, new text). Each `old` must occur exactly once in its file.
MUTATIONS = [
    ("main.cpp default 0 -> 5", "main", "->default_val(0)\n        // The range is checked",
     "->default_val(5)\n        // The range is checked"),
    ("main.cpp gains a CLI::Range validator", "main",
     "->default_val(0)\n        // The range is checked",
     "->default_val(0)->check(CLI::Range(0, 86400))\n        // The range is checked"),
    ("main.cpp env name dropped", "main",
     '->envname("YUZU_AGENT_SPARK_REGISTRY_PATH_VERIFY_INTERVAL");\n\n    // SLE',
     ';\n\n    // SLE'),
    ("main.cpp ceiling widened", "main",
     "cfg.spark_registry_path_verify_interval_s > 86400", "cfg.spark_registry_path_verify_interval_s > 864000"),
    ("main.cpp range check removed", "main",
     "cfg.spark_registry_path_verify_interval_s < 0 ||", "false ||"),
    ("main.cpp option bound to another field", "main",
     'app.add_option("--spark-registry-path-verify-interval",\n                   cfg.spark_registry_path_verify_interval_s,',
     'app.add_option("--spark-registry-path-verify-interval",\n                   cfg.spark_disable,'),
    ("agent.cpp passes a literal to the factory", "agent",
     "make_registry_mechanism(spark_detached_workers_,\n                                                     registry_path_verify)",
     "make_registry_mechanism(spark_detached_workers_,\n                                                     std::chrono::milliseconds{5000})"),
    ("agent.cpp factory called with one argument", "agent",
     "make_registry_mechanism(spark_detached_workers_,\n                                                     registry_path_verify)",
     "make_registry_mechanism(spark_detached_workers_)"),
    ("agent.cpp clamps another field", "agent",
     "clamp_registry_path_verify(\n                    cfg_.spark_registry_path_verify_interval_s);",
     "clamp_registry_path_verify(\n                    cfg_.spark_disable);"),
    ("agent.cpp real call commented out, quoted in a comment", "agent",
     "                try_register(SparkType::Registry,\n                             make_registry_mechanism(spark_detached_workers_,\n                                                     registry_path_verify));",
     "                // make_registry_mechanism(spark_detached_workers_, registry_path_verify)\n                try_register(SparkType::Registry, nullptr);"),
    ("agent.hpp field default 0 -> 5", "hpp",
     "int spark_registry_path_verify_interval_s{0};", "int spark_registry_path_verify_interval_s{5};"),
]


class RegistryVerifyDefaultWiring(unittest.TestCase):
    srcs = {
        "main": MAIN_CPP.read_text(encoding="utf-8"),
        "agent": AGENT_CPP.read_text(encoding="utf-8"),
        "hpp": AGENT_HPP.read_text(encoding="utf-8"),
    }

    def test_clean(self):
        self.assertEqual(problems(self.srcs["main"], self.srcs["agent"], self.srcs["hpp"]), [])

    def test_mutations_are_caught(self):
        for name, key, old, new in MUTATIONS:
            with self.subTest(name):
                self.assertEqual(self.srcs[key].count(old), 1, "stale mutation pattern: " + name)
                mutated = dict(self.srcs)
                mutated[key] = self.srcs[key].replace(old, new)
                self.assertTrue(problems(mutated["main"], mutated["agent"], mutated["hpp"]),
                                "mutation not caught: " + name)


if __name__ == "__main__":
    sys.exit(unittest.main(verbosity=1))
