#!/usr/bin/env python3
"""WCAG 4.5:1 contrast gate for the light colour schemes in yuzu.css.

Base = the :root block's hex declarations; each html[data-theme="light*"]
block is overlaid on it, so a token a light block forgets to redefine is
judged at its (dark-tuned) :root value and fails. Stdlib only.
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


def block(css, selector):
    m = re.search(re.escape(selector) + r"\s*\{(.*?)\n\}", css, re.S)
    if not m:
        raise SystemExit("FAIL: block not found: " + selector)
    return dict(DECL.findall(re.sub(r"/\*.*?\*/", "", m.group(1), flags=re.S)))


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
        t.update(block(css, 'html[data-theme="%s"]' % scheme))
        pairs = [(fg, bg) for fg in TEXTS for bg in SURFACES]
        pairs += [(c, bg) for c in CHARTS for bg in SURFACES[:2]]
        pairs += [("--mds-color-text-on-accent", a)
                  for a in ACCENTS]
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
    bad = failures(css)
    for f in bad:
        print("FAIL " + f)
    if bad:
        return 1
    print("ok: %d light schemes pass %.1f:1" % (len(LIGHT), MIN))
    return 0


if __name__ == "__main__":
    sys.exit(main())
