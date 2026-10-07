#!/usr/bin/env python3
"""Docs lint: advice to restart the gateway after a peer-authorization refusal stays CONDITIONAL.

A gateway restart disconnects every agent the node holds, and on agent builds without the #5183
fix (no release carries it yet) released agents then stay wedged. So every place that tells an
operator to restart a gateway must carry its caveat next to the instruction, not in a different
section:

  1. the `5183` caveat token (the agent-side reconnect fix the restart depends on) somewhere in the
     SAME paragraph, table row, list item or alert annotation, and
  2. a conditional marker (`only if` or `unless`) in the SAME SENTENCE as the restart phrase or in
     the IMMEDIATELY FOLLOWING sentence of that paragraph. A conditional in an unrelated sentence
     of the paragraph does not count; neither does a conditional in the sentence before.

What counts as a restart instruction (case-insensitive), one match per occurrence:

  * a verb (`restart`, `re-start`, `bounce`, `cycle`, `roll`, with -s/-ed/-ing), then up to three
    determiners/prepositions (`the`, `each`, `of`, ...), then up to two modifier words that are not
    clause words, then `gateway`, `gateways` or `yuzu-gateway` (so `restart the gateway`,
    `Restart gateway nodes`, `bounce each gateway`, `systemctl restart yuzu-gateway`, `rolling
    restart of the gateways`, `restart the production gateway`). `a restarted server reports the
    gateway ...` and `rolling back the gateway` do not match (determiners must come first);
  * `kubectl rollout restart` followed within 80 characters by `gateway`;
  * `gateway` (or `gateway nodes`) followed by an auxiliary (`should be`, `must be`, `is`, `gets`,
    ...) and then `restarted`, `re-started`, `bounced`, `cycled` or `rolled` (`the gateway should
    be restarted`; `the restarted server ...` is an adjective use and does not match);
  * `restart it`, `restart them`, `restart the node(s)`, `restart that/each node` (or the
    bounce/cycle/roll forms) within 120 characters after a `gateway` mention (`restart that
    gateway node`'s pronoun form: `restart the gateway, then restart it again`).

A noun use (`a gateway restart disconnects ...`, `after the gateway restarts on its own`) is a
description of consequences, not an instruction, and is not matched.

Scope. The operator-facing files that carry the runbook text are listed in FILES. In upgrading.md
a paragraph is checked only when it also concerns peer authorization (it mentions `peer`, a `pin`,
`not_pinned`, `gateway-upstream` or a `refusal`): that file also contains the unrelated, deliberate
"restart the gateway to deploy" advice for the #1197 reconcile change (a different decision, with
its own caveats), which this lint must not rewrite.

Each file also has a pinned MINIMUM number of matching paragraphs (MIN_MATCHES) so a runbook
paragraph that is reworded away from every pattern fails loudly instead of silently dropping out
of the lint's reach. Raise the number when a paragraph is added; lowering it needs a stated reason.

A second assertion: the expiry-cliff runbook paragraph in server-admin.md ("Certificate expiry")
must say that a gateway REDIAL is required before a renewed certificate is presented, because the
guard's validity check is per call but a long-lived TLS connection checks the certificate once.

Paragraph model: a markdown table row is its own paragraph; otherwise a paragraph runs between
blank lines and a list item starts a new one. In YAML and systemd units a paragraph is one key
(an annotation scalar and its continuation lines) or one run of comment lines, with the leading
`#` removed. Sentences end at `.`, `!` or `?` followed by whitespace and a capital letter, digit,
backtick, bracket, quote or asterisk, and at a table cell boundary (`|`).

On failure it prints file:line of each offending paragraph. Python, one process on every OS.

Usage: python3 -I tests/test_gateway_peer_restart_advice_lint.py
"""
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# file -> pinned minimum number of restart-instruction paragraphs the lint must find in it.
# Counted as paragraphs (a paragraph with several instructions counts once). See the module docstring.
MIN_MATCHES = {
    "docs/user-manual/server-admin.md": 8,
    "docs/user-manual/upgrading.md": 2,
    "docs/operations/troubleshooting.md": 2,
    "docs/pki-architecture.md": 3,
    "docs/security-reviews/gateway-peer-authz-minimal-2026-10-07.md": 2,
    "changelog.d/0000-gateway-peer-authz.security.md": 1,
    "docs/prometheus/yuzu-alerts.yml": 3,
    "deploy/docker/docker-compose.reference-gateway.yml": 0,  # comments carry no restart advice today
    "deploy/systemd/yuzu-server.service": 0,                  # (listed so a future one is checked)
}
FILES = tuple(MIN_MATCHES)
PEER_SCOPED_ONLY = ("docs/user-manual/upgrading.md",)  # elsewhere every occurrence is checked
COMMENT_MODE = (".yml", ".yaml", ".service")  # `#` comment runs and key lines, not markdown

_VERB = r"(?:restart|re-start|bounce|cycle|roll)(?:s|ed|d|ing)?"
_GW = r"(?:yuzu-)?gateways?"
# Between the verb and the gateway: up to three determiners/quantifiers/prepositions, then up to two
# modifier words that are not themselves clause words. The structure (determiners BEFORE
# modifiers) is what keeps `a restarted server reports the gateway ...` and `rolling back the
# gateway` from reading as instructions while `restart the production gateway` still matches.
_DET = r"(?:the|a|an|each|every|all|any|both|that|this|these|those|your|our|its|one|of|on|to|for)"
_STOP = (r"(?:the|a|an|while|when|if|as|and|but|so|then|after|before|until|because|where|which|that|"
         r"is|are|was|were|stays?|to|for|of|on|with|in|at|by|back|out)")
_MOD = rf"(?!{_STOP}\b)[\w/-]+"
RESTART_PATTERNS = (
    # verb, determiners, modifiers, then the gateway (restart the gateway / bounce each gateway node)
    re.compile(rf"\b{_VERB}(?:\s+{_DET}\b){{0,3}}(?:\s+{_MOD}){{0,2}}\s+{_GW}\b", re.I),
    re.compile(rf"\bkubectl\s+rollout\s+restart\b[^\n]{{0,80}}?{_GW}\b", re.I),
    # the gateway should be restarted / gateway nodes must be bounced
    re.compile(rf"\b{_GW}(?:\s+nodes?)?(?:\s+(?:should|must|needs?\s+to|has\s+to|have\s+to|will|would|can|may|"
               rf"is|are|gets?|be|being|been|then|also|first|\w+ly)){{1,3}}\s+(?:restarted|re-started|bounced|cycled|rolled)\b",
               re.I),
    # restart it / restart the node, shortly after a gateway mention
    re.compile(rf"\b{_GW}\b[^\n]{{0,120}}?\b{_VERB}\s+(?:it|them|the\s+nodes?|each\s+node|that\s+node)\b", re.I),
)
PEER_CONTEXT = re.compile(r"\bpeer\b|\bpins?\b|\bpinned\b|\bnot_pinned\b|\bgateway-upstream\b|\brefus\w*", re.I)
CONDITIONAL = re.compile(r"\bonly\s+if\b|\bunless\b", re.I)
CAVEAT = re.compile(r"5183")
LIST_ITEM = re.compile(r"^\s*(?:[-*+]|\d+[.)])\s")
YAML_KEY = re.compile(r"^\s*(?:-\s+)?(?:[A-Za-z_][\w-]*:(?:\s|$)|[A-Za-z_][\w-]*=)")
SENTENCE_END = re.compile(r"(?<=[.!?])\s+(?=[A-Z0-9`(\[\"'*_])|\s*\|\s*")


def paragraphs(text, comment_mode):
    """Return [(first_line_number, joined_text)] for each paragraph of the file."""
    out, cur, start = [], [], 0
    prev_comment = False

    def flush():
        nonlocal cur, start
        if cur:
            out.append((start, " ".join(cur)))
        cur, start = [], 0

    for n, line in enumerate(text.splitlines(), 1):
        stripped = line.strip()
        if not stripped:
            flush()
            prev_comment = False
            continue
        piece = stripped
        if comment_mode:
            is_comment = stripped.startswith("#")
            if YAML_KEY.match(line) or is_comment != prev_comment:
                flush()
            prev_comment = is_comment
            if is_comment:
                piece = stripped.lstrip("#").strip()
                if not piece:  # a bare `#` separator line ends the run
                    flush()
                    continue
        elif stripped.startswith("|") or LIST_ITEM.match(line):
            flush()
        if not cur:
            start = n
        cur.append(piece)
        if not comment_mode and stripped.startswith("|"):
            flush()
    flush()
    return out


def restart_matches(para):
    """Start offsets of every restart instruction in `para`, merged across the pattern families."""
    spans = sorted({(m.start(), m.end()) for rx in RESTART_PATTERNS for m in rx.finditer(para)})
    out = []
    for s, e in spans:
        if not out or s >= out[-1][1]:
            out.append((s, e))
    return out


def sentence_index(para, offset):
    """Return (index of the sentence holding `offset`, list of sentence strings)."""
    bounds, last = [], 0
    for m in SENTENCE_END.finditer(para):
        bounds.append((last, m.start()))
        last = m.end()
    bounds.append((last, len(para)))
    sentences = [para[a:b] for a, b in bounds]
    for i, (a, b) in enumerate(bounds):
        if a <= offset <= b:
            return i, sentences
    return len(sentences) - 1, sentences


def checked_paragraphs(path, text):
    comment_mode = path.endswith(COMMENT_MODE)
    for n, para in paragraphs(text, comment_mode):
        if not restart_matches(para):
            continue
        if path in PEER_SCOPED_ONLY and not PEER_CONTEXT.search(para):
            continue
        yield n, para


def violations(path, text):
    """One message per offending restart instruction in `text`; [] when clean."""
    out = []
    for n, para in checked_paragraphs(path, text):
        has_caveat = bool(CAVEAT.search(para))
        for s, e in restart_matches(para):
            idx, sentences = sentence_index(para, s)
            near = " ".join(sentences[idx:idx + 2])
            missing = []
            if not CONDITIONAL.search(near):
                missing.append("a conditional marker (`only if` / `unless`) in the same or the next sentence")
            if not has_caveat:
                missing.append("the `5183` caveat in the paragraph")
            if missing:
                out.append(f"{path}:{n}: tells the operator to restart the gateway "
                           f"('{para[max(0, s - 20):e + 30]}') without {' and '.join(missing)}")
    return out


def match_count(path, text):
    return sum(1 for _ in checked_paragraphs(path, text))


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
        problems = []
        for rel in FILES:
            problems += violations(rel, (ROOT / rel).read_text(encoding="utf-8"))
        for m in problems:
            print(f"::error::{m}", file=sys.stderr)
        self.assertEqual(problems, [])

    def test_every_file_still_has_its_restart_paragraphs(self):
        # A lint that matches nothing is a lint that rotted (the docs were reworded away from the
        # phrases): fail loudly instead of passing vacuously.
        problems = []
        for rel, floor in MIN_MATCHES.items():
            seen = match_count(rel, (ROOT / rel).read_text(encoding="utf-8"))
            if seen < floor:
                problems.append(f"{rel}: found {seen} restart-instruction paragraphs, expected at least {floor}: "
                                "a runbook paragraph was reworded out of this lint's reach (update the patterns "
                                "or MIN_MATCHES, with a reason)")
        for m in problems:
            print(f"::error::{m}", file=sys.stderr)
        self.assertEqual(problems, [])

    def test_expiry_runbook_says_redial(self):
        rel = "docs/user-manual/server-admin.md"
        problems = expiry_violations(rel, (ROOT / rel).read_text(encoding="utf-8"))
        for m in problems:
            print(f"::error::{m}", file=sys.stderr)
        self.assertEqual(problems, [])

    def test_the_lint_can_fail(self):
        # Accepted forms.
        good = "5. Only if agents have not reappeared, restart gateway nodes (see #5183).\n"
        self.assertEqual(violations("x.md", good), [])
        same = "Restart the gateway only if the cause is on the gateway side. Agents on builds without #5183 wedge.\n"
        self.assertEqual(violations("x.md", same), [])
        nxt = "Restart that gateway node. Do this only if the certificate expired; see #5183 for the agent caveat.\n"
        self.assertEqual(violations("x.md", nxt), [])
        # Plain failures.
        self.assertTrue(violations("x.md", "5. Restart gateway nodes after fixing the pin.\n"))
        self.assertTrue(violations("x.md", "| a | Restart the gateway after the pin fix; only if lost. |\n"))  # no 5183
        self.assertTrue(violations("x.md", "| a | Restart the gateway after the pin fix, see #5183. |\n"))  # no conditional
        # The caveat in a DIFFERENT paragraph does not count.
        self.assertTrue(violations("x.md", "Restart the gateway for the peer pin.\n\nOnly if #5183 unless.\n"))
        # Unrelated restart advice (no peer-authorization context) is out of scope in upgrading.md only.
        self.assertEqual(violations("docs/user-manual/upgrading.md", "Restart the gateway to deploy the new build.\n"), [])
        self.assertTrue(violations("docs/user-manual/upgrading.md", "After a refusal window, restart the gateway.\n"))
        self.assertTrue(violations("x.md", "Restart the gateway to deploy the new build.\n"))
        # Evasion: other verbs, other shapes.
        for phrase in ("Bounce the gateway after the fix.",
                       "Cycle every gateway node afterwards.",
                       "Roll the gateways one at a time.",
                       "Perform a rolling restart of the gateways.",
                       "Re-start the gateway.",
                       "Run `systemctl restart yuzu-gateway` on each node.",
                       "Run `kubectl rollout restart deployment/yuzu-gateway`.",
                       "The gateway should be restarted once the pin is fixed.",
                       "The gateway nodes must be bounced.",
                       "Fix the pin, then on the gateway host restart it.",
                       "Take the gateway out of rotation and restart the node."):
            self.assertTrue(violations("x.md", phrase + "\n"), phrase)
            self.assertEqual(violations("x.md", phrase + " Only if the cert expired, see #5183.\n"), [], phrase)
        # The conditional in an UNRELATED sentence (two sentences away, or before) does not count.
        self.assertTrue(violations("x.md", "Restart the gateway. It is quick. Do this only if you must; see #5183.\n"))
        self.assertTrue(violations("x.md", "Only if the pin is wrong, edit it. Restart the gateway. See #5183.\n"))
        # A table cell boundary is a sentence boundary: the NEXT cell counts, a cell two away does not.
        self.assertEqual(violations("x.md", "| Restart the gateway | only if wrong | 5183 |\n"), [])
        self.assertTrue(violations("x.md", "| Restart the gateway | note | only if wrong, see #5183 |\n"))
        # Nouns describing consequences are not instructions.
        self.assertEqual(violations("x.md", "A gateway restart disconnects its agents.\n"), [])
        # YAML annotations and comment runs.
        yml = ("      annotations:\n        description: >-\n          pin refused. Restart gateway nodes.\n"
               "        runbook_url: x\n")
        self.assertTrue(violations("x.yml", yml))
        yml_ok = ("      annotations:\n        description: >-\n          pin refused. Restart gateway nodes only if the\n"
                  "          certificate expired (#5183).\n        runbook_url: x\n")
        self.assertEqual(violations("x.yml", yml_ok), [])
        unit = "# Cause fixed? Then bounce the gateway.\n# That is all.\nExecStart=/bin/true\n"
        self.assertTrue(violations("x.service", unit))
        # Vanishing paragraphs are counted.
        self.assertEqual(match_count("x.md", "Restart the gateway.\n\nNothing here.\n"), 1)
        self.assertEqual(match_count("x.md", "Nothing here.\n"), 0)
        self.assertTrue(expiry_violations("x.md", "**Certificate expiry (the cliff).** Renew early.\n"))
        self.assertEqual(expiry_violations("x.md", "**Certificate expiry (the cliff).** A redial is needed.\n"), [])


if __name__ == "__main__":
    sys.exit(0 if unittest.main(exit=False).result.wasSuccessful() else 1)
