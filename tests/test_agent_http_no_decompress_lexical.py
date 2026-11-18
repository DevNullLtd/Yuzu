#!/usr/bin/env python3
"""WP14-A lexical gate: every httplib client in agents/ refuses to decode Content-Encoding.

The agent build defines CPPHTTPLIB_BROTLI_SUPPORT globally, so any httplib client decodes
Brotli by default inside the long-lived agent process, from a peer the operator chose. Invariant: every
client construction is followed, INSIDE ITS OWN BRACE SCOPE, by `VAR.set_decompress(false)` (or
`VAR->...`) and that call precedes the first request call (Get/Post/Put/Patch/Delete/Head/
Options/send/open_stream) on VAR. The window ends at the scope close or the next client
construction, whichever is first, so a sibling leg's same-named call never satisfies it.
`open_stream(` is BANNED in agents/: a StreamHandle decodes regardless of decompress_.
Unrecognised construction forms and `using namespace httplib` / type aliases FAIL the gate
(fail closed). Comments and string literals are blanked, offsets preserved.

Lexical only; the behavioural proof for the download path is test_content_dist_actions.cpp
([wp14a]). The self-test removes each site's call individually and requires that site flagged.
"""
import pathlib
import re
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
TYPE = r"(?:httplib::)(?:SSLClient|ClientImpl|Client)\b"
ANY = re.compile(TYPE)
DIRECT = re.compile(TYPE + r"\s+(\w+)\s*[({=;]")
SMART_MAKE = re.compile(r"(\w+)\s*=\s*(?:std::)?make_(?:unique|shared)\s*<\s*" + TYPE + r"\s*>")
SMART_DECL = re.compile(r"(?:unique_ptr|shared_ptr)\s*<\s*" + TYPE + r"\s*>\s*(\w+)")
NEW = re.compile(r"(\w+)\s*=\s*new\s+" + TYPE)
ALIAS = re.compile(r"using\s+namespace\s+httplib\b|using\s+\w+\s*=\s*(?:httplib::)?(?:SSLClient|ClientImpl|Client)\b"
                   r"|typedef\s+httplib::")
REQ = r"(?:Get|Post|Put|Patch|Delete|Head|Options|send|Send|open_stream)"


def blank(text):
    def keep_nl(m):
        return re.sub(r"[^\n]", " ", m.group(0))
    text = re.sub(r"/\*.*?\*/", keep_nl, text, flags=re.S)
    text = re.sub(r"//[^\n]*", keep_nl, text)
    return re.sub(r'"(?:\\.|[^"\\\n])*"', keep_nl, text)


def sources():
    out = {}
    for ext in ("*.cpp", "*.hpp", "*.mm", "*.h"):
        for p in (ROOT / "agents").rglob(ext):
            out[str(p.relative_to(ROOT))] = p.read_text(encoding="utf-8", errors="replace")
    return out


def sites(text):
    """Yield (var, ctor_end, kind) for each construction; kind 'ERR:..' for unrecognised."""
    text = blank(text)
    res, claimed = [], set()
    for rx in (DIRECT, SMART_MAKE, SMART_DECL, NEW):
        for m in rx.finditer(text):
            t = ANY.search(text, m.start())
            claimed.add(t.start())
            res.append((m.group(1), m.end(), None))
    for m in ANY.finditer(text):
        if m.start() in claimed:
            continue
        after = text[m.end(): m.end() + 3].lstrip()
        before = text[max(0, m.start() - 12): m.start()]
        if after[:1] in ("&", "*", ",", ")", ">") and "make_" not in before and "<" not in before[-3:]:
            continue          # reference/pointer/parameter use: not a construction
        if after[:2] == "::" or before.rstrip().endswith("<") and "ptr" not in before:
            continue
        res.append(("?", m.end(), "ERR: unrecognised httplib client construction form"))
    if ALIAS.search(text):
        res.append(("?", 0, "ERR: using-namespace/alias/typedef of httplib client type"))
    return text, sorted(res, key=lambda r: r[1])


def check(text):
    """Return list of (var, problem|None, call_span|None) for each site."""
    text, ss = sites(text)
    out = []
    ends = [s[1] for s in ss if s[2] is None]
    for var, end, err in ss:
        if err:
            out.append((var, err, None))
            continue
        depth, stop = 0, len(text)
        for i in range(end, len(text)):
            c = text[i]
            if c == "{":
                depth += 1
            elif c == "}":
                depth -= 1
                if depth < 0:
                    stop = i
                    break
        nxt = [e for e in ends if e > end]
        if nxt:
            stop = min(stop, nxt[0])
        win = text[end:stop]
        v = re.escape(var)
        setm = re.search(r"\b" + v + r"\s*(?:\.|->)\s*set_decompress\s*\(\s*false\s*\)", win)
        reqm = re.search(r"\b" + v + r"\s*(?:\.|->)\s*" + REQ + r"\s*\(", win)
        if not setm:
            out.append((var, "no set_decompress(false) in the construction's own scope", None))
        elif reqm and reqm.start() < setm.start():
            out.append((var, "set_decompress(false) comes AFTER a request on the client", None))
        else:
            out.append((var, None, (end + setm.start(), end + setm.end())))
    return out


OPEN_STREAM = re.compile(r"\bopen_stream\s*\(")


def problems(srcs):
    found, total = [], 0
    for name, text in sorted(srcs.items()):
        if OPEN_STREAM.search(blank(text)):
            found.append(f"{name}: open_stream() is banned (a StreamHandle decodes regardless of decompress_)")
        for var, prob, _ in check(text):
            total += 1
            if prob:
                found.append(f"{name}: `{var}`: {prob}")
    if total == 0:
        found.append("no httplib client constructions found: stale pattern")
    return found


class NoDecompress(unittest.TestCase):
    def test_every_client_disables_decompression(self):
        self.assertEqual(problems(sources()), [])

    def test_selftest_each_site_removal_is_caught(self):
        srcs, hit = {k: v for k, v in sources().items() if "httplib" in v}, 0
        for name, text in srcs.items():
            for idx, (var, prob, span) in enumerate(check(text)):
                if prob:
                    continue
                # blank the text exactly as check() does so offsets line up, then cut this call
                b = blank(text)
                mutated = b[:span[0]] + " " * (span[1] - span[0]) + b[span[1]:]
                p = [v2 for v2, pr, _ in check(mutated) if pr]
                self.assertIn(var, p, (name, var, idx))
                hit += 1
        self.assertGreater(hit, 11)

    def test_selftest_blind_spot_shapes(self):
        bad = {
            "sibling": "void f(){ if(a){ httplib::SSLClient cli(h); res=cli.Get(p);}"
                       " else { httplib::Client cli(h); cli.set_decompress(false); } }",
            "after":   "void f(){ httplib::Client c(h); c.Get(p); c.set_decompress(false); }",
            "make":    "void f(){ auto c = std::make_unique<httplib::Client>(h); c->Get(p); }",
            "brace":   "void f(){ httplib::Client c{h}; c.Get(p); }",
            "new":     "void f(){ auto* c = new httplib::SSLClient(h); c->Get(p); }",
            "impl":    "void f(){ httplib::ClientImpl c(h); c.Get(p); }",
            "alias":   "using namespace httplib; void f(){ Client c(h); c.Get(p); }",
        }
        for k, v in bad.items():
            self.assertTrue(problems({k: v}), k)
        self.assertTrue(problems({"os": "void f(){ httplib::Client c(h); c.set_decompress(false); c.open_stream(m,p); }"}))
        good = ("void f(){ if(a){ httplib::SSLClient c(h); c.set_decompress(false); c.Get(p);}"
                " else { httplib::Client c(h); c.set_decompress(false); c.Get(p);} }")
        self.assertEqual(problems({"ok": good}), [])


if __name__ == "__main__":
    sys.exit(unittest.main(argv=[sys.argv[0]]) or 0)
