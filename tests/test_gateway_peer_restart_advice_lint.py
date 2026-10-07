#!/usr/bin/env python3
"""Docs lint: advice to restart the gateway after a peer-authorization refusal stays CONDITIONAL.

A gateway restart disconnects every agent the node holds, and on agent builds without the #5183
fix (in no release yet) released agents then stay wedged. So every place that tells an operator to
restart a gateway must carry its caveat next to the instruction, not in a different section:

  1. the `5183` caveat token (the agent-side reconnect fix the restart depends on, matched with
     digit boundaries so `15183` does not count) somewhere in the SAME paragraph, table row, list
     item or alert annotation, and
  2. a conditional marker (`only if` or `unless`) in the SAME SENTENCE as the restart phrase or in
     the IMMEDIATELY FOLLOWING sentence of that paragraph. A conditional in an unrelated sentence
     of the paragraph does not count; neither does a conditional in the sentence before.

Text is matched after markdown marks are stripped (`**the gateway**`, `` `yuzu-gateway` ``,
`_gateway_`, `[gateway](url)` all read as plain words), case-insensitively, one match per
occurrence.

What counts as a restart instruction:

  * a restart verb, then up to five determiners/quantifiers/prepositions (`the`, `each`, `of`,
    `three`, ...), then up to two modifier words that are not clause words, then `gateway`,
    `gateways` or `yuzu-gateway` (so `restart the gateway`, `Restart gateway nodes`, `bounce each
    gateway`, `systemctl restart yuzu-gateway`, `rolling restart of the gateways`, `restart the
    production gateway`, `restart three of the gateways`). The verbs are restart/re-start, bounce,
    cycle (so `power-cycle` too), roll, reboot, redeploy/re-deploy, recycle and `stop and start`, in the base,
    -s and -ing forms. A past participle directly before the noun is an adjective, not an
    instruction (`a restarted gateway`), and `gateway-facing` is not the gateway. `a restarted
    server reports the gateway ...` and `rolling back the gateway` do not match;
  * the coordinated form `Restart the server, then the gateway` (a second object joined by
    `and`, `then`, `followed by`, `before` or `after`);
  * the noun form with a carrying verb: `perform|do|issue|run|trigger|force|schedule a gateway
    restart`;
  * the command forms `service yuzu-gateway restart`, `rc-service yuzu-gateway restart`,
    `/etc/init.d/yuzu-gateway restart`, `kubectl rollout restart ... gateway` and
    `docker compose up --force-recreate ... gateway` (the gateway as a whitespace-delimited
    argument: `reference-gateway.yml` is a file name, and `a rolling gateway upgrade` is a
    compound noun, not an instruction);
  * `gateway` (or `gateway nodes`) followed by an auxiliary (`should be`, `must be`, `is`, `gets`,
    ...) and then `restarted`, `re-started`, `bounced`, `cycled`, `rolled`, `rebooted`,
    `redeployed` or `recycled` (`the gateway should be restarted`), except when the participle is
    followed by the cause (`is restarted by systemd`: a description, not an instruction);
  * `restart it`, `restart them`, `restart the node(s)`, `restart that/each node` (or the other
    verbs) within 120 characters after a `gateway` mention (the pronoun form: `restart the
    gateway, then restart it again`).

NEGATED advice is inert: a negation word (`not`, `n't`, `never`, `without`, `avoid`, `cannot`) within
three words before the restart verb, with no clause punctuation between them, makes that match not
an instruction (`Do not restart the gateway`, `without restarting the gateway`). A comma, semicolon,
colon, dash or parenthesis between the negation and the verb ends the negation's reach
(`do not wait; restart the gateway` is still advice).

A noun use (`a gateway restart disconnects ...`, `after the gateway restarts on its own`) is a
description of consequences, not an instruction, and is not matched.

Scope. The operator-facing files that carry the runbook text are listed in FILES. Three narrowings:
  * upgrading.md: a paragraph is checked only when it also concerns peer authorization (it
    mentions `peer`, a `pin`, `not_pinned`, `gateway-upstream`, a `refusal`, a `redial` or a
    `class A/B/C`): that file also contains the unrelated, deliberate "restart the gateway to
    deploy" advice for the #1197 reconcile change (a different decision, with its own caveats),
    which this lint must not rewrite.
  * server-admin.md: every paragraph is checked EXCEPT those under a heading that names the
    multi-cluster gateway mode (the #4669 "Rollout window" text, an unrelated deliberate decision):
    a legitimate edit to that section cannot fail a peer-authorization count. The exclusion is by
    heading (EXCLUDED_HEADINGS), not by wording, so a peer-authorization paragraph cannot opt out
    by avoiding a word.
  * every other docs/**/*.md file (those not in FILES) is swept as well, restricted to paragraphs
    with the same peer-authorization context as upgrading.md, so a NEW page that carries
    peer-authorization restart advice is held to the same rule. SWEEP_EXEMPT names the pages the
    task owner deliberately left untouched, each with its reason.

Each FILES entry also has a pinned MINIMUM number of matching paragraphs (MIN_MATCHES) so a runbook
paragraph that is reworded away from every pattern fails loudly instead of silently dropping out
of the lint's reach; a mismatch prints the line number of every surviving match. Raise the number
when a paragraph is added; lowering it needs a stated reason.

A second assertion: the expiry-cliff runbook paragraph in server-admin.md ("Certificate expiry")
must say that a gateway REDIAL is required before a renewed certificate is presented, because the
guard's validity check is per call but a long-lived TLS connection checks the certificate once.

Paragraph model: a markdown table row is its own paragraph; otherwise a paragraph runs between
blank lines and a list item starts a new one. In YAML and systemd units a paragraph is one key
(an annotation scalar and its continuation lines) or one run of comment lines, with the leading
`#` removed. Sentences end at `.`, `!` or `?` followed by whitespace and a capital letter, digit,
bracket, quote or opening parenthesis, and at a table cell boundary (`|`).

On failure it prints file:line of each offending paragraph. Python, one process on every OS.

Usage: python3 -I tests/test_gateway_peer_restart_advice_lint.py
"""
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# file -> pinned minimum number of restart-instruction paragraphs the lint must find in it.
# Counted as paragraphs (a paragraph with several instructions counts once), AFTER the negation
# rule (a `do not restart the gateways first` paragraph is inert and not counted) and the
# server-admin multi-cluster heading exclusion. See the module docstring.
MIN_MATCHES = {
    "docs/user-manual/server-admin.md": 6,
    "docs/user-manual/upgrading.md": 2,
    "docs/operations/troubleshooting.md": 2,
    "docs/pki-architecture.md": 3,
    "docs/security-reviews/gateway-peer-authz-minimal-2026-10-07.md": 3,
    "changelog.d/0000-gateway-peer-authz.security.md": 1,
    "docs/prometheus/yuzu-alerts.yml": 3,
    "deploy/docker/docker-compose.reference-gateway.yml": 0,  # comments carry no restart advice today
    "deploy/systemd/yuzu-server.service": 0,                  # (listed so a future one is checked)
}
FILES = tuple(MIN_MATCHES)
PEER_SCOPED_ONLY = ("docs/user-manual/upgrading.md",)  # only paragraphs with peer-authorization context
# file -> regex over a markdown heading: paragraphs under a matching heading are not checked.
EXCLUDED_HEADINGS = {
    "docs/user-manual/server-admin.md": re.compile(r"multi-cluster gateway mode", re.I),
}
# docs/**/*.md pages outside FILES that the sweep skips, with the reason (none today).
SWEEP_EXEMPT = {
}
COMMENT_MODE = (".yml", ".yaml", ".service")  # `#` comment runs and key lines, not markdown

# Restart verbs: base, -s and -ing forms only. A past participle directly before the noun is an
# adjective (`a restarted gateway`) and is handled by _PART in the passive pattern alone.
_VERB = (r"(?:re-?start(?:s|ing)?|bounc(?:e|es|ing)|cycl(?:e|es|ing)|roll(?:s|ing)?|reboot(?:s|ing)?|"
         r"re-?deploy(?:s|ing)?|recycl(?:e|es|ing)|"
         r"(?:stop|stops|stopping)(?:\s+and\s+|\s*/\s*|\s*,\s*(?:then\s+)?|\s+then\s+)(?:start|starts|starting))")
_PART = r"(?:re-?started|bounced|cycled|rolled|rebooted|re-?deployed|recycled)"
_NOUN = r"(?:re-?start|bounce|cycle|reboot|re-?deploy|recycle)"
_GW = r"(?:yuzu-)?gateways?"
# `gateway-facing` is not the gateway, and `a rolling gateway upgrade` is a compound noun, not a restart.
_GWB = rf"{_GW}\b(?!-[A-Za-z])(?!\s+(?:upgrades?|updates?|rollouts?|deployments?|releases?)\b)"
# A gateway named as a command-line argument (whitespace-delimited): `reference-gateway.yml` is a file name.
_GWARG = rf"(?<![\w./-]){_GW}(?![\w./-])"
# Between the verb and the gateway: up to five determiners/quantifiers/prepositions, then up to two
# modifier words that are not themselves clause words. The structure (determiners BEFORE
# modifiers) is what keeps `a restarted server reports the gateway ...` and `rolling back the
# gateway` from reading as instructions while `restart the production gateway` still matches.
_DET = (r"(?:the|a|an|each|every|all|any|both|that|this|these|those|your|our|its|one|two|three|four|five|six|"
        r"seven|eight|nine|ten|\d+|several|some|many|most|half|another|of|on|to|for)")
_STOP = (r"(?:the|a|an|while|when|if|as|and|but|so|then|after|before|until|because|where|which|that|"
         r"is|are|was|were|stays?|to|for|of|on|with|in|at|by|back|out)")
_MOD = rf"(?!{_STOP}\b)[\w/-]+"
_CARRY = (r"(?:perform(?:s|ing)?|do(?:es|ing)?|issu(?:e|es|ing)|run(?:s|ning)?|execut(?:e|es|ing)|"
          r"trigger(?:s|ing)?|forc(?:e|es|ing)|initiat(?:e|es|ing)|schedul(?:e|es|ing)|carry(?:ing)?\s+out|carries\s+out)")
_CAUSE = (r"(?!\s+(?:automatically\s+)?by\s+(?:systemd|docker|kubernetes|k8s|supervisord|"
          r"(?:the|its)\s+(?:init|supervisor|orchestrator|scheduler|container|service)))")
# Patterns with a named group `v` have the restart verb at that group; the others (the passive,
# command and noun forms) are anchored at the match start for the negation check.
RESTART_PATTERNS = (
    # verb, determiners, modifiers, then the gateway (restart the gateway / bounce each gateway node)
    re.compile(rf"\b(?P<v>{_VERB})(?:\s+{_DET}\b){{0,5}}(?:\s+{_MOD}){{0,2}}\s+{_GWB}", re.I),
    re.compile(rf"\b(?P<v>kubectl\s+rollout\s+restart)\b[^\n]{{0,80}}?{_GWB}", re.I),
    # the gateway should be restarted / gateway nodes must be bounced (not `is restarted by systemd`)
    re.compile(rf"\b{_GW}(?:\s+nodes?)?(?:\s+(?:should|must|needs?\s+to|has\s+to|have\s+to|will|would|can|may|"
               rf"is|are|gets?|be|being|been|then|also|first|\w+ly)){{1,3}}\s+{_PART}\b{_CAUSE}", re.I),
    # restart it / restart the node, shortly after a gateway mention
    re.compile(rf"\b{_GW}\b[^\n]{{0,120}}?\b(?P<v>{_VERB})\s+(?:it|them|the\s+nodes?|each\s+node|that\s+node)\b", re.I),
    # coordinated object: `Restart the server, then the gateway`
    re.compile(rf"\b(?P<v>{_VERB})(?:\s+{_DET}\b){{0,5}}(?:\s+{_MOD}){{0,2}}\s*[,;]?\s+"
               rf"(?:and\s+then|and|then|followed\s+by)(?:\s+{_DET}\b){{0,2}}\s+{_GWB}", re.I),
    # noun form behind a carrying verb: `perform a gateway restart`
    re.compile(rf"\b(?P<v>{_CARRY})\s+(?:a|an|the|another|one|that|this)\s+(?:[\w-]+\s+){{0,2}}?{_GW}"
               rf"(?:\s+nodes?)?\s+{_NOUN}\b", re.I),
    # command forms: service yuzu-gateway restart / rc-service ... / /etc/init.d/yuzu-gateway restart
    re.compile(rf"\b(?:service|rc-service)\s+{_GW}\s+(?:re-?start|bounce|cycle|reboot)\w*\b"
               rf"|/init\.d/{_GW}\s+re-?start\b", re.I),
    re.compile(rf"--force-recreate\b[^\n]{{0,60}}?{_GWARG}|{_GWARG}[^\n]{{0,60}}?--force-recreate\b", re.I),
)
PEER_CONTEXT = re.compile(r"\bpeer\b|\bpins?\b|\bpinned\b|\bnot_pinned\b|\bgateway-upstream\b|\brefus\w*|"
                          r"\bredial\w*|\bclass [ABC]\b", re.I)
CONDITIONAL = re.compile(r"\bonly\s+if\b|\bunless\b", re.I)
CAVEAT = re.compile(r"(?<!\d)5183(?!\d)")
NEGATIONS = frozenset(("not", "never", "without", "avoid", "avoiding", "cannot"))
CLAUSE_BREAK = re.compile(r"[.;:!?,()\[\]|]|\s[-\u2013\u2014]+\s|[\u2013\u2014]")
LIST_ITEM = re.compile(r"^\s*(?:[-*+]|\d+[.)])\s")
YAML_KEY = re.compile(r"^\s*(?:-\s+)?(?:[A-Za-z_][\w-]*:(?:\s|$)|[A-Za-z_][\w-]*=)")
HEADING = re.compile(r"^#{1,6}\s+(.*?)\s*#*\s*$")
SENTINEL = "\x01"  # marks a sentence that began with a markdown mark, so cleaning keeps the boundary
SENTENCE_END = re.compile(r"(?<=[.!?])\s+(?=[A-Z0-9(\[\"'\x01])|\s*\|\s*")


def clean_markup(text):
    """Strip markdown marks so `**the gateway**`, `` `yuzu-gateway` ``, `_gateway_` and `[gateway](url)` read as words.

    A sentence that begins with a mark keeps a sentinel so SENTENCE_END still sees its boundary."""
    text = re.sub(r"(?<=[.!?])(\s+)(?=[`*_])", lambda m: m.group(1) + SENTINEL, text)
    text = re.sub(r"!?\[([^\]]*)\]\([^)]*\)", r"\1", text)
    text = re.sub(r"\[([^\]]*)\]\[[^\]]*\]", r"\1", text)
    text = text.replace("`", "").replace("*", "")
    return re.sub(r"(?<![A-Za-z0-9])_+|_+(?![A-Za-z0-9])", "", text)


def paragraphs(text, comment_mode):
    """Return [(first_line_number, cleaned_joined_text)] for each paragraph of the file."""
    out, cur, start = [], [], 0
    prev_comment = False

    def flush():
        nonlocal cur, start
        if cur:
            out.append((start, clean_markup(" ".join(cur))))
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


def negated(para, verb_start):
    """True when a negation word is within three words before the verb and no clause break lies between."""
    segment = CLAUSE_BREAK.split(para[:verb_start])[-1]
    words = re.findall(r"[\w'\u2019-]+", segment.lower())[-3:]
    return any(w in NEGATIONS or w.endswith(("n't", "n\u2019t")) for w in words)


def restart_matches(para):
    """(start, end) of every restart instruction in `para`, merged across the pattern families.

    A match whose verb is negated (`do not restart the gateway`) is not an instruction and is dropped."""
    spans = set()
    for rx in RESTART_PATTERNS:
        for m in rx.finditer(para):
            verb_start = m.start("v") if "v" in rx.groupindex else m.start()
            if not negated(para, verb_start):
                spans.add((m.start(), m.end()))
    out = []
    for s, e in sorted(spans):
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


def heading_titles(text):
    """[(line number, title)] of every markdown heading outside a fenced code block."""
    out, fenced = [], False
    for n, line in enumerate(text.splitlines(), 1):
        if line.lstrip().startswith("```"):
            fenced = not fenced
        elif not fenced and (m := HEADING.match(line)):
            out.append((n, m.group(1)))
    return out


def checked_paragraphs(path, text, peer_only=None):
    """Paragraphs of `path` that hold a restart instruction and are in the lint's scope."""
    comment_mode = path.endswith(COMMENT_MODE)
    if peer_only is None:
        peer_only = path in PEER_SCOPED_ONLY
    excluded = EXCLUDED_HEADINGS.get(path)
    heads = heading_titles(text) if excluded and not comment_mode else []
    for n, para in paragraphs(text, comment_mode):
        if not restart_matches(para):
            continue
        if peer_only and not PEER_CONTEXT.search(para):
            continue
        if heads:
            title = next((t for ln, t in reversed(heads) if ln <= n), "")
            if excluded.search(title):
                continue
        yield n, para


def violations(path, text, peer_only=None):
    """One message per offending restart instruction in `text`; [] when clean."""
    out = []
    for n, para in checked_paragraphs(path, text, peer_only):
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
                snippet = para[max(0, s - 20):e + 30].replace(SENTINEL, "")
                out.append(f"{path}:{n}: tells the operator to restart the gateway "
                           f"('{snippet}') without {' and '.join(missing)}")
    return out


def match_lines(path, text):
    return [n for n, _ in checked_paragraphs(path, text)]


def match_count(path, text):
    return len(match_lines(path, text))


def floor_problem(path, text, floor):
    """A message when `path` has fewer restart-instruction paragraphs than its pinned floor, else None."""
    lines = match_lines(path, text)
    if len(lines) >= floor:
        return None
    return (f"{path}: found {len(lines)} restart-instruction paragraphs (at lines {lines or 'none'}), expected at "
            f"least {floor}: a runbook paragraph was reworded out of this lint's reach (update the patterns "
            "or MIN_MATCHES, with a reason)")


def sweep_files():
    """docs/**/*.md pages outside FILES (and not exempt): swept for peer-authorization restart advice."""
    found = sorted(p.relative_to(ROOT).as_posix() for p in (ROOT / "docs").glob("**/*.md"))
    return [r for r in found if r not in FILES and r not in SWEEP_EXEMPT]


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

    def test_docs_sweep_has_no_unconditional_peer_authorization_restart_advice(self):
        # Pages outside FILES: only paragraphs with peer-authorization context are checked.
        pages = sweep_files()
        self.assertGreater(len(pages), 50, "the docs sweep found almost nothing: ROOT is wrong")
        problems = []
        for rel in pages:
            problems += violations(rel, (ROOT / rel).read_text(encoding="utf-8", errors="replace"), peer_only=True)
        for m in problems:
            print(f"::error::{m}", file=sys.stderr)
        self.assertEqual(problems, [])

    def test_every_file_still_has_its_restart_paragraphs(self):
        # A lint that matches nothing is a lint that rotted (the docs were reworded away from the
        # phrases): fail loudly instead of passing vacuously.
        problems = [m for m in (floor_problem(rel, (ROOT / rel).read_text(encoding="utf-8"), floor)
                                for rel, floor in MIN_MATCHES.items()) if m]
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
        # Evasion: other verbs, other shapes. Each fails bare and passes with the caveat and a conditional.
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
                       "Take the gateway out of rotation and restart the node.",
                       # new forms
                       "Perform a gateway restart.",
                       "Do a gateway restart now.",
                       "Issue a gateway restart on each node.",
                       "Run service yuzu-gateway restart on the host.",
                       "Run rc-service yuzu-gateway restart on the host.",
                       "Run /etc/init.d/yuzu-gateway restart on the host.",
                       "Run docker compose up -d --force-recreate gateway on the host.",
                       "Run docker compose up gateway --force-recreate on the host.",
                       "Reboot the gateway.",
                       "Redeploy the gateway.",
                       "Recycle the gateway nodes.",
                       "Power-cycle the gateway.",
                       "Restart the server, then the gateway.",
                       "Restart the server and the gateway.",
                       "Stop and start the gateway.",
                       "Stopping and starting the gateway helps.",
                       "Restart three of the gateways.",
                       "Restart 2 of the gateways.",
                       "Restart two of the three gateways.",
                       "Bouncing the gateway clears it.",
                       "Cycling the gateway clears it."):
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

    def test_negated_advice_is_inert_but_clause_breaks_end_the_negation(self):
        for phrase in ("Do not restart the gateway.",
                       "Don't restart the gateway.",
                       "Never bounce the gateway.",
                       "Avoid restarting the gateway.",
                       "You can fix this without restarting the gateway.",
                       "It is not necessary to restart the gateway.",
                       "You should not simply restart the gateway.",
                       "Do not restart the server, nor the gateway.",
                       "A node cannot restart the gateway itself."):
            self.assertEqual(violations("x.md", phrase + "\n"), [], phrase)
            self.assertEqual(match_count("x.md", phrase + "\n"), 0, phrase)
        # A negation more than three words away, or separated by a clause break, does not reach the verb.
        for phrase in ("Do not wait; restart the gateway.",
                       "Do not panic, restart the gateway.",
                       "Do not panic - restart the gateway.",
                       "Do not restart the server; restart the gateway.",
                       "(do not delay) Restart the gateway.",
                       "Not one two three restart the gateway.",
                       "Restart the gateway, not the server."):
            self.assertTrue(violations("x.md", phrase + "\n"), phrase)

    def test_markdown_marks_do_not_hide_the_noun(self):
        for phrase in ("**Restart the gateway** after the fix.",
                       "Restart **the gateway** after the fix.",
                       "Restart `yuzu-gateway` after the fix.",
                       "Restart the [gateway](https://example.test/gw) after the fix.",
                       "Restart the [gateway][gw] after the fix.",
                       "Restart _the gateway_ after the fix.",
                       "Restart the _gateway_ after the fix.",
                       "`systemctl` **restart** `yuzu-gateway`."):
            self.assertTrue(violations("x.md", phrase + "\n"), phrase)
        # A sentence that begins with a mark is still a sentence: the conditional two sentences away fails.
        self.assertTrue(violations("x.md", "Restart the gateway. `yuzu_x` is quick. Only if you must; see #5183.\n"))
        self.assertEqual(violations("x.md", "Restart the gateway. **Only if** the cert expired; see #5183.\n"), [])
        # Identifiers keep their underscores.
        self.assertEqual(match_count("x.md", "The not_pinned reason names the gateway_peer metric.\n"), 0)

    def test_caveat_token_needs_digit_boundaries(self):
        base = "Restart the gateway only if the cert expired"
        self.assertEqual(violations("x.md", base + ", see #5183.\n"), [])
        self.assertEqual(violations("x.md", base + ", see 5183.\n"), [])
        self.assertTrue(violations("x.md", base + ", see #15183.\n"))
        self.assertTrue(violations("x.md", base + ", see #51830.\n"))
        self.assertTrue(violations("x.md", base + ", see PR 51839.\n"))

    def test_adjectival_and_descriptive_uses_are_not_instructions(self):
        for phrase in ("A restarted gateway presents the new certificate.",
                       "The restarted server reports the gateway healthy.",
                       "The gateway-facing listener is unchanged.",
                       "Restart the gateway-facing listener first.",
                       "The gateway is restarted by systemd on failure.",
                       "The gateway is automatically restarted by the supervisor.",
                       "Rolling back the gateway image is not covered here.",
                       "The pin set is safe across a rolling gateway upgrade.",
                       "Run docker compose -f docker-compose.reference-gateway.yml up -d --force-recreate agent.",
                       "Restart the server after the gateway has been fixed.",
                       "After the gateway restarts on its own the agents reconnect."):
            self.assertEqual(match_count("x.md", phrase + "\n"), 0, phrase)
        # ... but the passive instruction without a cause is still one.
        self.assertTrue(violations("x.md", "The gateway is restarted.\n"))
        self.assertTrue(violations("x.md", "The gateway should be restarted by hand.\n"))

    def test_scope_rules(self):
        # upgrading.md: peer context now includes a redial and the class A/B/C labels.
        up = "docs/user-manual/upgrading.md"
        self.assertTrue(violations(up, "- Class B: restart the gateway after the key change.\n"))
        self.assertTrue(violations(up, "Restart the gateway once agents redial.\n"))
        self.assertEqual(violations(up, "Restart the gateway to deploy the new build.\n"), [])
        # server-admin.md: every paragraph is checked, except under the multi-cluster heading.
        sa = "docs/user-manual/server-admin.md"
        self.assertTrue(violations(sa, "### Rotation\n\nRestart the gateway to apply.\n"))
        multi = ("### vNEXT: multi-cluster gateway mode binds each agent\n\nRestart the gateway to apply.\n\n"
                 "### Peer authorization runbook\n\nRestart the gateway to apply.\n")
        found = violations(sa, multi)
        self.assertEqual(len(found), 1, found)
        self.assertIn(":7:", found[0])
        # The exclusion is by heading: a fenced `#` line is not a heading.
        fenced = "```\n# multi-cluster gateway mode\n```\n\nRestart the gateway to apply.\n"
        self.assertTrue(violations(sa, fenced))
        # The docs sweep applies the peer-context filter.
        self.assertTrue(violations("docs/new.md", "After a peer refusal restart the gateway.\n", peer_only=True))
        self.assertEqual(violations("docs/new.md", "Restart the gateway to deploy.\n", peer_only=True), [])
        self.assertIn("docs/user-manual/server-admin.md", MIN_MATCHES)
        self.assertNotIn("docs/user-manual/server-admin.md", sweep_files())
        self.assertIn("docs/user-manual/gateway.md", sweep_files())

    def test_floor_mismatch_names_the_surviving_lines(self):
        text = "Nothing.\n\nRestart the gateway.\n\nMore.\n\nBounce the gateway.\n"
        self.assertIsNone(floor_problem("x.md", text, 2))
        msg = floor_problem("x.md", text, 3)
        self.assertIn("found 2", msg)
        self.assertIn("[3, 7]", msg)
        self.assertIn("none", floor_problem("x.md", "Nothing.\n", 1))


if __name__ == "__main__":
    sys.exit(0 if unittest.main(exit=False).result.wasSuccessful() else 1)
