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
    """Blank comments and string/char literals in ONE left-to-right pass (offsets and newlines kept).

    A single pass is required: separate regexes for comments then strings let a `//` inside a
    string (`"http://x"`) swallow the rest of the line, and a quote inside a comment open a string.
    """
    out, i, n = [], 0, len(text)

    def blank_span(a, b):
        out.append(re.sub(r"[^\n]", " ", text[a:b]))

    while i < n:
        c = text[i]
        if c == "/" and text.startswith("//", i):
            j = text.find("\n", i)
            j = n if j < 0 else j
            blank_span(i, j)
            i = j
        elif c == "/" and text.startswith("/*", i):
            j = text.find("*/", i + 2)
            j = n if j < 0 else j + 2
            blank_span(i, j)
            i = j
        elif c in "\"'":
            j = i + 1
            while j < n and text[j] != c and text[j] != "\n":
                j += 2 if text[j] == "\\" else 1
            j = min(j + 1, n) if j < n and text[j] == c else j
            blank_span(i, j)
            i = j
        else:
            out.append(c)
            i += 1
    return "".join(out)


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


# --- `get` wiring pin -------------------------------------------------------------------------
# The pure decision (http_client_get_output.hpp) is unit-tested, but nothing executes do_get (the
# SSRF filter refuses loopback), so a do_get that stopped consulting it would stay green. Pin the
# shape lexically: http_get collects EVERY Content-Encoding line (equal_range) in the response
# handler, and do_get applies encoding_refusal_row to what it collected BEFORE its first `body|`.
PLUGIN = "agents/plugins/http_client/src/http_client_plugin.cpp"


def func_body(text, signature_rx):
    m = re.search(signature_rx, text)
    if not m:
        return None
    i = text.index("{", m.end())
    depth = 0
    for j in range(i, len(text)):
        if text[j] == "{":
            depth += 1
        elif text[j] == "}":
            depth -= 1
            if depth == 0:
                return text[i:j + 1]
    return None


def wiring_problems(raw):
    t = blank(raw)
    out = []
    hg = func_body(t, r"std::string\s+http_get\s*\(")
    if hg is None:
        return ["http_get not found"]
    rawhg = func_body(raw, r"std::string\s+http_get\s*\(") or ""
    if not re.search(r'equal_range\s*\(\s*"Content-Encoding"\s*\)', rawhg):
        out.append("http_get must read every Content-Encoding line with equal_range")
    dg = func_body(t, r"int\s+do_get\s*\(")
    if dg is None:
        return out + ["do_get not found"]
    refuse = dg.find("encoding_refusal_row")
    if refuse < 0:
        out.append("do_get does not call encoding_refusal_row")
    if "http_get(" not in dg or "content_encodings" not in dg:
        out.append("do_get must pass the collected content_encodings from http_get to the refusal")
    # `body|` is a string literal, so it is blank in `t`; find it in the raw text of do_get.
    rawdg = func_body(raw, r"int\s+do_get\s*\(") or ""
    body_at = rawdg.find('"body|')
    ref_raw = rawdg.find("encoding_refusal_row")
    if body_at < 0:
        out.append("do_get no longer writes a body| row: pin is stale")
    elif ref_raw < 0 or ref_raw > body_at:
        out.append("do_get writes body| before applying encoding_refusal_row")
    if len(re.findall(r'"body\|', rawdg)) != 1:
        out.append("do_get must write the body through exactly one body| site")
    return out


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
        # 8 construction sites at the time of writing (http_client's run_pinned folds its legs into
        # two); a drop below that means the discovery regex stopped seeing sites, not that sites went.
        self.assertGreaterEqual(hit, 8)

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

    def test_get_wiring(self):
        raw = (ROOT / PLUGIN).read_text(encoding="utf-8")
        self.assertEqual(wiring_problems(raw), [])

    def test_selftest_wiring_mutations_are_caught(self):
        raw = (ROOT / PLUGIN).read_text(encoding="utf-8")
        muts = {
            "refusal call deleted": raw.replace("encoding_refusal_row(content_encodings)", "std::string{}", 1),
            "only first header": raw.replace("equal_range(", "find_first_of(", 1),
            "body before refusal": raw.replace("ctx.write_output(std::format(\"status|{}\", status));\n        // The client",
                                               "ctx.write_output(std::format(\"status|{}\", status));\n        ctx.write_output(\"body|x\");\n        // The client", 1),
        }
        for name, m in muts.items():
            self.assertNotEqual(m, raw, name + ": mutation did not apply")
            self.assertTrue(wiring_problems(m), name)

    def test_blank_single_pass(self):
        # a `//` inside a string must not hide the rest of the line; a quote in a comment opens nothing
        t = blank('x = "http://a"; httplib::Client c(h); // it\'s "q"\nY')
        self.assertIn("httplib::Client c(h)", t)
        self.assertNotIn("http:", t)
        self.assertTrue(t.endswith("\nY"))
        self.assertEqual(len(t), len('x = "http://a"; httplib::Client c(h); // it\'s "q"\nY'))


if __name__ == "__main__":
    sys.exit(unittest.main(argv=[sys.argv[0]]) or 0)
