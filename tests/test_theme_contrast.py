#!/usr/bin/env python3
"""WCAG 4.5:1 contrast gate for the light colour schemes in yuzu.css.

Base = the :root block's hex declarations; each html[data-theme="light*"]
block is overlaid on it, so a token a light block forgets to redefine is
judged at its (dark-tuned) :root value and fails. Stdlib only.
A new light scheme must be added to LIGHT below, or it is not gated.
"""
import re
import sys
from pathlib import Path

CSS = Path(__file__).resolve().parent.parent / "server/core/static/yuzu.css"
MIN = 4.5
LIGHT = ("light", "light-baby", "light-hot")
DECL = re.compile(r"(--[\w-]+)\s*:\s*(#[0-9a-fA-F]{6}|var\(--[\w-]+\))\s*;")
P = "--mds-color-theme-"
SURFACES = [P + "background-canvas", P + "background-solid-primary",
            P + "background-solid-secondary", "--raise"]
TEXTS = [P + "text-primary", P + "text-secondary", P + "text-tertiary", "--faint"]
CHARTS = ["--mds-color-chart-%d" % i for i in range(1, 13)]
ACCENTS = [P + "accent-primary-" + s for s in ("normal", "hover", "active")]


TRACKED = re.compile(r"--mds-color-[\w-]+|--c[1-5]|--mut|--faint|--ink2|--bg|--raise")
ANY_DECL = re.compile(r"(--[\w-]+)\s*:\s*([^;]+);")


def block(css, selector, strict=False):
    m = re.search(re.escape(selector) + r"\s*\{(.*?)\n\}", css, re.S)
    if not m:
        raise SystemExit("FAIL: block not found: " + selector)
    body = re.sub(r"/\*.*?\*/", "", m.group(1), flags=re.S)
    if strict:
        # A closer not at column 0 runs this match into the next block.
        if "{" in body:
            raise SystemExit("FAIL: nested '{' in block (indented closer?): " + selector)
        # A colour this parser cannot read would silently fall back to :root.
        for name, val in ANY_DECL.findall(body):
            if TRACKED.fullmatch(name) and not DECL.fullmatch("%s: %s;" % (name, val.strip())):
                raise SystemExit("FAIL: unparsed colour declaration in %s: %s: %s"
                                 % (selector, name, val.strip()))
    return dict(DECL.findall(body))


def resolve(tokens, name):
    v = tokens[name]
    if v.startswith("var("):
        v = tokens[v[4:-1]]
    return v


def lum(hexv):
    c = [int(hexv[i:i + 2], 16) / 255 for i in (1, 3, 5)]
    c = [x / 12.92 if x <= 0.03928 else ((x + 0.055) / 1.055) ** 2.4 for x in c]
    return 0.2126 * c[0] + 0.7152 * c[1] + 0.0722 * c[2]


def ratio(a, b):
    la, lb = sorted((lum(a), lum(b)), reverse=True)
    return (la + 0.05) / (lb + 0.05)


def failures(css):
    base = block(css, ":root")
    out = []
    for scheme in LIGHT:
        t = dict(base)
        t.update(block(css, 'html[data-theme="%s"]' % scheme, strict=True))
        pairs = [(fg, bg) for fg in TEXTS for bg in SURFACES]
        pairs += [(c, bg) for c in CHARTS for bg in SURFACES[:2]]
        pairs += [("--mds-color-text-on-accent", a)
                  for a in ACCENTS]
        # Fleet-view label plates: alias text and the --c4 port label on the --bg plate.
        pairs += [("--ink2", "--bg"), ("--c4", "--bg")]
        for fg, bg in pairs:
            r = ratio(resolve(t, fg), resolve(t, bg))
            if r < MIN:
                out.append("%s: %s on %s = %.2f:1 (< %.1f)" % (scheme, fg, bg, r, MIN))
    return out


def main():
    css = CSS.read_text(encoding="utf-8")
    # Self-check: an un-overridden dark token must be caught.
    probe = css.replace('--mds-color-chart-1: #1d5fc2;', '--mds-color-chart-1: #4c9aff;', 1)
    assert any("light: --mds-color-chart-1" in f for f in failures(probe)), \
        "gate did not catch a dark chart token on a light scheme"
    # Self-check: a token a light block forgets to redefine is judged at its :root value.
    # The first --mds-color-chart-7 override is html[data-theme="light"]'s (:root's is #ff9f43).
    probe2 = css.replace('--mds-color-chart-7: #a04d00;', '', 1)
    assert any("light: --mds-color-chart-7" in f for f in failures(probe2)), \
        "gate did not catch a chart token a light block fails to redefine"
    # Self-check: a light-block colour in a notation the parser cannot read must fail loudly.
    for bad_decl in ("rgb(1,2,3)", "#fff", "#0e6fa8cc"):
        probe3 = css.replace('--mds-color-chart-6: #0e6fa8;', '--mds-color-chart-6: %s;' % bad_decl, 1)
        try:
            failures(probe3)
        except SystemExit as e:
            assert "unparsed colour declaration" in str(e), e
        else:
            raise AssertionError("gate ignored an unparsed light colour: " + bad_decl)
    # Self-check: an indented closer must not let one block swallow the next.
    try:
        block('html[data-theme="x"] {\n --a: #000000;\n  }\nhtml[data-theme="y"] {\n --a: #ffffff;\n}\n',
              'html[data-theme="x"]', strict=True)
    except SystemExit as e:
        assert "nested" in str(e), e
    else:
        raise AssertionError("gate accepted an indented block closer")
    bad = failures(css)
    for f in bad:
        print("FAIL " + f)
    if bad:
        return 1
    print("ok: %d light schemes pass %.1f:1" % (len(LIGHT), MIN))
    return 0


if __name__ == "__main__":
    sys.exit(main())
