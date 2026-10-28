#!/usr/bin/env python3
"""Behavioural check of the Tokens page's two Rotate dialogs (yuzu-tokens-actions.js).

test_access_tokens_actions_js.cpp pins the script's text; this runs it. The real file is
loaded under node against a minimal fake DOM and a fake YuzuDialog that records the form each
click builds, then asserts what an operator would be offered: which overlap periods the Rotate
dialog lists and which one it defaults to, for a credential or token with a finite life left,
one that never expires (data-expires-at "0"), and one with no expiry attribute at all.

Rules under test (the server rejects an overlap longer than the predecessor's remaining life):
  - only overlaps that fit are listed; one day is always kept; the default is the longest up
    to 7 days;
  - "0" is a never-expires marker, not a negative life: all five choices, default 7 days;
  - the principal detail carries the server clock, so the engine dialog is sized when the token
    list never loads (a caller without ApiToken:Read has no #tokens-root at all).

Skips (77) when `node` is not on PATH. Stdlib only.
"""
import os
import pathlib
import shutil
import subprocess
import sys

JS = pathlib.Path(__file__).resolve().parents[1] / "server/core/static/yuzu-tokens-actions.js"

DRIVER = r"""
const src = require('fs').readFileSync(process.env.YUZU_TOKENS_JS, 'utf8');
const DAY = 86400;
const NOW = 1.8e9;
let forms = [];
const L = { doc: {}, body: {}, win: {} };
const mk = id => ({ id, textContent: '', hidden: false, children: [], dataset: {}, attrs: {},
  setAttribute(k, v) { this.attrs[k] = v; }, appendChild(c) { this.children.push(c); return c; },
  querySelector() { return null; }, focus() {} });
const ids = {};
for (const i of ['flash', 'reveal', 'reveal-secret', 'reveal-title', 'reveal-msg', 'reveal-btns'])
  ids[i] = mk(i);
globalThis.window = { YuzuDialog: { form: spec => { forms.push(spec); return Promise.resolve(null); },
                                    request: () => Promise.resolve({ ok: false, status: 0 }) },
                      addEventListener: (t, f) => { L.win[t] = f; } };
globalThis.document = {
  body: { addEventListener: (t, f) => { L.body[t] = f; } },
  addEventListener: (t, f) => { L.doc[t] = f; },
  getElementById: i => ids[i] || null, querySelector: () => null,
  createElement: t => mk(t) };
globalThis.navigator = {};
const realNow = Date.now;
let wall = NOW * 1000;
Date.now = () => wall;
(0, eval)(src);

// Deliver the server clock the way htmx does: a swap into `target` whose fragment carries data-now.
function swap(target, nowSecs) {
  const root = { dataset: { now: String(nowSecs) } };
  if (target === 'tokens-body') ids['tokens-root'] = root;  // only the token list brings #tokens-root
  const t = { id: target, querySelector: s => (s === '[data-now]' ? root : null) };
  L.body['htmx:afterSwap']({ detail: { target: t } });
}
function click(tk, dataset) {
  const b = { dataset: Object.assign({ tk }, dataset), disabled: false };
  L.doc.click({ target: { closest: () => b } });
}
const opts = () => forms[forms.length - 1].fields[0];
const days = f => f.options.map(o => Number(o.value) / DAY);
const fails = [];
const ok = (c, m) => { if (!c) fails.push(m); };
const eq = (a, b, m) => ok(JSON.stringify(a) === JSON.stringify(b), m + ': got ' + JSON.stringify(a) + ' want ' + JSON.stringify(b));

(async () => {
  // --- engine credential, clock delivered by the principal detail only (no #tokens-root exists) ---
  ok(!ids['tokens-root'], 'precondition: no token list on the page');
  swap('side-principal', NOW);
  const rot = left => { click('principal-rotate', { principalId: 'engine:bot', expiresAt: String(NOW + left) }); return opts(); };
  let f = rot(2 * DAY);
  eq(days(f), [1], 'two days left: only one day fits (3 days + margin does not)');
  eq(f.value, String(DAY), 'two days left: default one day');
  f = rot(5 * DAY);
  eq(days(f), [1, 3], 'five days left: 1 and 3');
  eq(f.value, String(3 * DAY), 'five days left: default 3 days');
  f = rot(30 * DAY);
  eq(days(f), [1, 3, 7, 14], 'thirty days left: 30 does not fit under the margin');
  eq(f.value, String(7 * DAY), 'thirty days left: default capped at 7 days');
  f = rot(90 * DAY);
  eq(days(f), [1, 3, 7, 14, 30], 'ninety days left: all five');

  // --- never expires: "0" is truthy as a string but is not a negative life ---
  click('principal-rotate', { principalId: 'engine:bot', expiresAt: '0' });
  eq(days(opts()), [1, 3, 7, 14, 30], 'engine "0": all five choices');
  eq(opts().value, String(7 * DAY), 'engine "0": default 7 days');
  click('principal-rotate', { principalId: 'engine:bot' });
  eq(days(opts()), [1, 3, 7, 14, 30], 'engine, no attribute: all five choices');

  // --- human token dialog uses the same rule ---
  click('token-rotate', { tokenId: 'abc', name: 'ci', expiresAt: '0' });
  eq(days(opts()), [1, 3, 7, 14, 30], 'token "0": all five choices (was only one day)');
  eq(opts().value, String(7 * DAY), 'token "0": default 7 days');
  click('token-rotate', { tokenId: 'abc', name: 'ci', expiresAt: String(NOW + 2 * DAY) });
  eq(days(opts()), [1], 'token, two days left: one day');

  // --- one day is always offered, even when the remaining life is a hair over a day ---
  eq(days(rot(DAY + 30)), [1], 'a day and 30 s left: the one-day choice is kept');

  // --- the clock keeps running: time elapsed on the page shortens the remaining life ---
  wall += 3 * DAY * 1000;
  eq(days(rot(4 * DAY)), [1], 'three days elapsed on the page: four days left is one day now');

  // --- a later swap that carries no usable clock keeps the earlier base ---
  swap('side-principal', 0);
  eq(days(rot(10 * DAY)), [1, 3], 'a zero clock in a later swap keeps the earlier base (7 days left: 1 and 3)');

  // --- the token list also delivers the clock (its own swap target) ---
  swap('tokens-body', NOW + 3 * DAY);
  click('token-rotate', { tokenId: 'abc', name: 'ci', expiresAt: String(NOW + 5 * DAY) });
  eq(days(opts()), [1], 'token list clock: five days from then is two days left');

  console.log(fails.length ? 'FAIL\n' + fails.join('\n') : 'OK');
  process.exit(fails.length ? 1 : 0);
})();
"""


def main() -> int:
    node = shutil.which("node")
    if not node:
        print("SKIP: node is not on PATH")
        return 77
    # YUZU_TOKENS_JS may point at a mutated copy of the script (mutation checks).
    env = dict(os.environ, YUZU_TOKENS_JS=os.environ.get("YUZU_TOKENS_JS", str(JS)))
    r = subprocess.run([node, "-e", DRIVER], capture_output=True, text=True, timeout=30, env=env)
    sys.stdout.write(r.stdout)
    sys.stderr.write(r.stderr)
    return r.returncode


if __name__ == "__main__":
    sys.exit(main())
