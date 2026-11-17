#!/usr/bin/env python3
"""WP14-A lexical gate: every httplib client in agents/ refuses to decode Content-Encoding.

The agent build defines CPPHTTPLIB_BROTLI_SUPPORT globally, so an `httplib::Client` /
`httplib::SSLClient` decodes Brotli (and whatever else is compiled in) by default, inside a
root/SYSTEM process, from a peer the operator chose (a brotli decoder CVE reaches it).
Downloads are hash-verified files: nothing wants transparent decoding. Invariant: every
construction `httplib::Client NAME(` / `httplib::SSLClient NAME(` in agents/**/*.cpp|hpp is
followed, within the same function, by `NAME.set_decompress(false);`.

Lexical only (comments stripped): it cannot prove the call precedes the request, only that it is
present within WINDOW characters of the construction; review enforces the order. The behavioural
proof for the download path is test_content_dist_actions.cpp ([wp14a]). The self-test mutates the
sources in memory and requires problems() to go non-empty.
"""
import pathlib
import re
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parent.parent
CTOR = re.compile(r"\bhttplib::(?:SSL)?Client\s+(\w+)\s*\(")
WINDOW = 600


def strip_comments(text):
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    return re.sub(r"//[^\n]*", "", text)


def sources():
    out = {}
    for ext in ("*.cpp", "*.hpp"):
        for p in (ROOT / "agents").rglob(ext):
            out[str(p.relative_to(ROOT))] = p.read_text(encoding="utf-8", errors="replace")
    return out


def problems(srcs):
    found = []
    total = 0
    for name, text in sorted(srcs.items()):
        text = strip_comments(text)
        for m in CTOR.finditer(text):
            total += 1
            var = m.group(1)
            tail = text[m.end(): m.end() + WINDOW]
            if not re.search(r"\b" + re.escape(var) + r"\s*\.\s*set_decompress\s*\(\s*false\s*\)", tail):
                found.append(f"{name}: httplib client `{var}` has no set_decompress(false)")
    if total == 0:
        found.append("no httplib client constructions found: stale pattern")
    return found


class NoDecompress(unittest.TestCase):
    def test_every_client_disables_decompression(self):
        self.assertEqual(problems(sources()), [])

    def test_selftest_mutation_is_caught(self):
        srcs = sources()
        hit = 0
        for name, text in srcs.items():
            if "set_decompress(false)" in text:
                mutated = dict(srcs)
                mutated[name] = text.replace("set_decompress(false)", "set_decompress(true)")
                self.assertTrue(problems(mutated), name)
                hit += 1
        self.assertGreater(hit, 0)


if __name__ == "__main__":
    sys.exit(unittest.main(argv=[sys.argv[0]]) or 0)
