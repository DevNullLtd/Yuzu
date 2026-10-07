#!/usr/bin/env python3
"""Docs lint: advice to restart the gateway after a peer-authorization refusal stays CONDITIONAL.

A gateway restart disconnects every agent the node holds, and on agent builds without the #5183
fix (no release carries it yet) released agents then stay wedged. So every place that tells an
operator to restart the gateway in the context of gateway-upstream peer authorization must carry
its caveat in the SAME paragraph, table row or alert annotation, not in a different section:

  1. a conditional marker (`only if` or `unless`), and
  2. the `5183` caveat token (the agent-side reconnect fix the restart depends on).

Scope. The files are the operator-facing ones that carry the runbook text:
docs/user-manual/server-admin.md, docs/user-manual/upgrading.md, docs/operations/troubleshooting.md
and docs/prometheus/yuzu-alerts.yml. The phrase is `restart(ing) [the] gateway` (case-insensitive:
`restart the gateway`, `Restart gateway nodes`). Every occurrence is checked in server-admin.md,
troubleshooting.md and the alert rules. In upgrading.md a paragraph is checked only when it also
concerns peer authorization (it mentions `peer`, a `pin`, or `not_pinned`): that file also contains
the unrelated, deliberate "restart the gateway to deploy" advice for the #1197 reconcile change
(a different decision, with its own caveats), which this lint must not rewrite.

A second assertion: the expiry-cliff runbook paragraph in server-admin.md ("Certificate expiry")
must say that a gateway REDIAL is required before a renewed certificate is presented, because the
guard's validity check is per call but a long-lived TLS connection checks the certificate once.

Paragraph model: a markdown table row is its own paragraph; otherwise a paragraph runs between
blank lines and a list item starts a new one. In the YAML a paragraph is one key (an annotation
scalar and its continuation lines) or one run of comment lines.

On failure it prints file:line of each offending paragraph. Python, one process on every OS.

Usage: python3 tests/test_gateway_peer_restart_advice_lint.py
"""
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FILES = (
    "docs/user-manual/server-admin.md",
    "docs/user-manual/upgrading.md",
    "docs/operations/troubleshooting.md",
    "docs/prometheus/yuzu-alerts.yml",
)
PEER_SCOPED_ONLY = ("docs/user-manual/upgrading.md",)  # elsewhere every occurrence is checked
RESTART = re.compile(r"\brestart(?:ing)?\s+(?:the\s+)?gateway\b", re.I)
PEER_CONTEXT = re.compile(r"\bpeer\b|\bpins?\b|\bpinned\b|\bnot_pinned\b", re.I)
CONDITIONAL = re.compile(r"\bonly\s+if\b|\bunless\b", re.I)
CAVEAT = re.compile(r"5183")
LIST_ITEM = re.compile(r"^\s*(?:[-*+]|\d+[.)])\s")
YAML_KEY = re.compile(r"^\s*(?:-\s+)?[A-Za-z_][\w-]*:(?:\s|$)")


def paragraphs(text, is_yaml):
    """Yield (first_line_number, joined_text) for each paragraph of the file."""
    cur, start = [], 0

    def flush():
        nonlocal cur, start
        if cur:
            out.append((start, " ".join(s.strip() for s in cur)))
        cur, start = [], 0

    out = []
    prev_comment = False
    for n, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if not stripped:
            flush()
            prev_comment = False
            continue
        if is_yaml:
            is_comment = stripped.startswith("#")
            if YAML_KEY.match(line) or is_comment != prev_comment:
                flush()
            prev_comment = is_comment
        else:
            if stripped.startswith("|") or LIST_ITEM.match(line):
                flush()
        if not cur:
            start = n
        cur.append(line)
        if not is_yaml and stripped.startswith("|"):
            flush()
    flush()
    return out


def violations(path, text):
    """One message per offending paragraph in `text`; [] when clean."""
    out = []
    for n, para in paragraphs(text, path.endswith(".yml")):
        if not RESTART.search(para):
            continue
        if path in PEER_SCOPED_ONLY and not PEER_CONTEXT.search(para):
            continue
        missing = []
        if not CONDITIONAL.search(para):
            missing.append("a conditional marker (`only if` / `unless`)")
        if not CAVEAT.search(para):
            missing.append("the `5183` caveat")
        if missing:
            m = RESTART.search(para)
            out.append(f"{path}:{n}: tells the operator to restart the gateway ('{para[max(0, m.start() - 20):m.end() + 30]}') "
                       f"without {' and '.join(missing)} in the same paragraph")
    return out


def expiry_violations(path, text):
    for n, para in paragraphs(text, False):
        if para.lstrip("* ").startswith("Certificate expiry"):
            if not re.search(r"\bredial", para, re.I):
                return [f"{path}:{n}: the certificate-expiry runbook paragraph does not state that a gateway "
                        "redial is required before a renewed certificate is presented"]
            return []
    return [f"{path}: the certificate-expiry runbook paragraph ('**Certificate expiry ...') was not found"]


class GatewayPeerRestartAdviceLint(unittest.TestCase):
    def test_restart_advice_is_conditional(self):
        problems, seen = [], 0
        for rel in FILES:
            text = (ROOT / rel).read_text(encoding="utf-8")
            seen += sum(1 for _, p in paragraphs(text, rel.endswith(".yml"))
                        if RESTART.search(p) and (rel not in PEER_SCOPED_ONLY or PEER_CONTEXT.search(p)))
            problems += violations(rel, text)
        for m in problems:
            print(f"::error::{m}", file=sys.stderr)
        self.assertEqual(problems, [])
        # A lint that matches nothing is a lint that rotted (the docs were reworded away from the
        # phrase): fail loudly instead of passing vacuously.
        self.assertGreaterEqual(seen, 6, "no restart-the-gateway paragraphs found: update this lint's patterns")

    def test_expiry_runbook_says_redial(self):
        rel = "docs/user-manual/server-admin.md"
        problems = expiry_violations(rel, (ROOT / rel).read_text(encoding="utf-8"))
        for m in problems:
            print(f"::error::{m}", file=sys.stderr)
        self.assertEqual(problems, [])

    def test_the_lint_can_fail(self):
        good = "5. Only if agents have not reappeared, restart gateway nodes (see #5183).\n"
        self.assertEqual(violations("x.md", good), [])
        self.assertTrue(violations("x.md", "5. Restart gateway nodes after fixing the pin.\n"))
        self.assertTrue(violations("x.md", "| a | Restart the gateway after the pin fix; only if lost. |\n"))  # no 5183
        self.assertTrue(violations("x.md", "| a | Restart the gateway after the pin fix, see #5183. |\n"))  # no conditional
        # The caveat in a DIFFERENT paragraph does not count.
        self.assertTrue(violations("x.md", "Restart the gateway for the peer pin.\n\nOnly if #5183 unless.\n"))
        # Unrelated restart advice (no peer-authorization context) is out of scope in upgrading.md only.
        self.assertEqual(violations("docs/user-manual/upgrading.md", "Restart the gateway to deploy the new build.\n"), [])
        self.assertTrue(violations("x.md", "Restart the gateway to deploy the new build.\n"))
        yml = ("      annotations:\n        description: >-\n          pin refused. Restart gateway nodes.\n"
               "        runbook_url: x\n")
        self.assertTrue(violations("x.yml", yml))
        self.assertTrue(expiry_violations("x.md", "**Certificate expiry (the cliff).** Renew early.\n"))
        self.assertEqual(expiry_violations("x.md", "**Certificate expiry (the cliff).** A redial is needed.\n"), [])


if __name__ == "__main__":
    sys.exit(0 if unittest.main(exit=False).result.wasSuccessful() else 1)
