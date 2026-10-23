#!/usr/bin/env python3
"""Every `runbook_url` in docs/prometheus/yuzu-alerts.yml that points at a repository markdown
file WITH a `#fragment` must name a heading that exists in that file.

An alert whose runbook link anchors to a renamed or deleted heading still parses and still fires,
but the on-call lands at the top of a long page instead of the procedure. Nothing else notices:
the rule file is valid YAML and the page is valid markdown. This test closes that gap.

Scope: URLs of the form https://github.com/<owner>/<repo>/blob/<ref>/<path>.md#<fragment> (the
repository's own docs). URLs on other hosts (the docs.yuzu.io runbook site) are not repository
files and are skipped; so are URLs with no fragment (nothing to resolve, and the file's existence
is not this test's concern).

The anchor of a heading follows GitHub's rendering: inline markup is reduced to its text, the
text is lowercased, every character other than a letter, digit, space, hyphen or underscore is
dropped, spaces become hyphens (so a dropped character between two spaces leaves two hyphens,
for example an em dash), and the second and later headings with the same anchor get -1, -2, ...
Headings inside fenced code blocks are not headings.

Usage:
  python3 -I tests/test_alert_runbook_anchors.py
  python3 -I tests/test_alert_runbook_anchors.py --repo-root DIR
"""
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ALERTS = Path("docs") / "prometheus" / "yuzu-alerts.yml"
TAG = "test_alert_runbook_anchors"

_URL = re.compile(r"""runbook_url:\s*["']?(?P<url>[^"'\s]+)""")
_BLOB = re.compile(r"^https://github\.com/[^/]+/[^/]+/blob/[^/]+/(?P<path>[^#?]+\.md)#(?P<frag>.+)$")
_FENCE = re.compile(r"^\s{0,3}(`{3,}|~{3,})")
_ATX = re.compile(r"^\s{0,3}#{1,6}[ \t]+(?P<text>.*?)(?:[ \t]+#+)?[ \t]*$")
_LINK = re.compile(r"!?\[([^\]]*)\]\([^)]*\)")
_HTML_TAG = re.compile(r"<[^>]*>")


def slug_text(heading):
    """The anchor GitHub gives one heading's text, before duplicate suffixes."""
    t = _LINK.sub(r"\1", heading)
    t = _HTML_TAG.sub("", t)
    t = t.lower()
    kept = []
    for ch in t:
        if ch.isalnum() or ch in "-_" or ch == " ":
            kept.append(ch)
    return "".join(kept).strip(" ").replace(" ", "-")


def heading_anchors(markdown):
    """The set of anchors a markdown document exposes (duplicates suffixed -1, -2, ...)."""
    seen = {}
    out = set()
    fence = None
    for line in markdown.splitlines():
        f = _FENCE.match(line)
        if f:
            marker = f.group(1)
            if fence is None:
                fence = marker[0]
            elif marker[0] == fence:
                fence = None
            continue
        if fence is not None:
            continue
        m = _ATX.match(line)
        if not m:
            continue
        base = slug_text(m.group("text"))
        n = seen.get(base, 0)
        seen[base] = n + 1
        out.add(base if n == 0 else f"{base}-{n}")
    return out


def rule_urls(alerts_text):
    """(line number, url) for every runbook_url in the rule file."""
    out = []
    for no, line in enumerate(alerts_text.splitlines(), 1):
        m = _URL.search(line)
        if m:
            out.append((no, m.group("url")))
    return out


def problems(root, alerts_text=None, read_doc=None):
    """Problems for every repository-markdown runbook_url that carries a fragment. `read_doc`
    maps a repo-relative path to its text (or None when absent); injectable for the self-test."""
    root = Path(root)
    if alerts_text is None:
        alerts_text = (root / ALERTS).read_text(encoding="utf-8")
    if read_doc is None:
        def read_doc(rel):
            p = root / rel
            return p.read_text(encoding="utf-8") if p.is_file() else None
    cache = {}
    out = []
    checked = 0
    for no, url in rule_urls(alerts_text):
        m = _BLOB.match(url)
        if not m:
            continue
        rel, frag = m.group("path"), m.group("frag").lower()
        checked += 1
        if rel not in cache:
            doc = read_doc(rel)
            cache[rel] = None if doc is None else heading_anchors(doc)
        anchors = cache[rel]
        where = f"{ALERTS.as_posix()}:{no}"
        if anchors is None:
            out.append(f"{where}: runbook_url points at {rel}, which does not exist")
        elif frag not in anchors:
            out.append(f"{where}: runbook_url anchor #{frag} matches no heading in {rel}")
    return out, checked


class AlertRunbookAnchors(unittest.TestCase):
    root = ROOT

    def test_every_runbook_anchor_resolves(self):
        out, checked = problems(self.root)
        self.assertGreater(checked, 0, "no repository runbook_url with a fragment was found: "
                                       "the URL pattern no longer matches the rule file")
        for m in out:
            print(f"\n::error::{TAG}: {m}", file=sys.stderr)
        self.assertEqual(out, [])


class CheckerSelfTest(unittest.TestCase):
    """The checker itself: a fake heading set, so a regression in the anchor rules is caught
    here and not only when a shipped rule happens to break."""

    DOC = (
        "# Title\n"
        "## vNext \u2014 behind a reverse proxy: declare it (#2537)\n"
        "## Storage\n"
        "## Storage\n"
        "### `code` and emphasis and [a link](http://x/y)\n"
        "```\n"
        "## Not a heading\n"
        "```\n"
        "## Trailing hashes ##\n"
    )

    def test_anchor_rules(self):
        a = heading_anchors(self.DOC)
        self.assertIn("vnext--behind-a-reverse-proxy-declare-it-2537", a)
        self.assertIn("storage", a)
        self.assertIn("storage-1", a)
        self.assertNotIn("storage-2", a)
        self.assertIn("code-and-emphasis-and-a-link", a)
        self.assertNotIn("not-a-heading", a)
        self.assertIn("trailing-hashes", a)

    def test_missing_anchor_and_missing_file_fail(self):
        yml = ('  - alert: A\n'
               '    annotations:\n'
               '      runbook_url: "https://github.com/o/r/blob/main/docs/x.md#storage"\n'
               '      runbook_url: "https://github.com/o/r/blob/main/docs/x.md#renamed-away"\n'
               '      runbook_url: "https://github.com/o/r/blob/main/docs/gone.md#storage"\n'
               '      runbook_url: "https://docs.yuzu.io/runbooks/other#anything"\n'
               '      runbook_url: "https://github.com/o/r/blob/main/docs/x.md"\n')
        docs = {"docs/x.md": self.DOC}
        out, checked = problems(".", alerts_text=yml, read_doc=docs.get)
        self.assertEqual(checked, 3)
        self.assertEqual(len(out), 2, out)
        self.assertIn("yuzu-alerts.yml:4", out[0])
        self.assertIn("#renamed-away", out[0])
        self.assertIn("yuzu-alerts.yml:5", out[1])
        self.assertIn("does not exist", out[1])

    def test_duplicate_suffix_is_required(self):
        yml = '      runbook_url: "https://github.com/o/r/blob/main/docs/x.md#storage-2"\n'
        out, _ = problems(".", alerts_text=yml, read_doc={"docs/x.md": self.DOC}.get)
        self.assertEqual(len(out), 1, out)


def main(argv):
    args = list(argv[1:])
    rest = []
    while args:
        a = args.pop(0)
        if a == "--repo-root" and args:
            AlertRunbookAnchors.root = Path(args.pop(0))
        else:
            rest.append(a)
    result = unittest.main(argv=[argv[0]] + rest, exit=False).result
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
