# tests/puppeteer

Headless-browser checks against a running Yuzu dashboard.

| Script | Role |
|---|---|
| `ui-smoke.mjs` | The gate. Run by `/test` Phase 5 as "Browser smoke"; exit 1 fails the gate. |
| `lib/harness.mjs` | Shared helpers: launch, login, error collection, CSP and layout assertions, request stubs. |
| everything else | Older one-off probes. Not gates; `dashboard-help-test.mjs` is the warn-only "Puppeteer" gate. |

## Install

```bash
(cd tests/puppeteer && npm ci)
```

`node_modules` is not committed and `/test` never installs it: without it the gate records SKIP.
If the browser download is skipped, point `PUPPETEER_EXECUTABLE_PATH` at a Chrome for Testing binary.

## Run

```bash
node tests/puppeteer/ui-smoke.mjs
```

| Variable | Default |
|---|---|
| `YUZU_BASE_URL` | `http://localhost:8080` |
| `YUZU_UI_USER` | `admin` |
| `YUZU_UI_PASSWORD` | `YuzuUatAdmin1!` |

The defaults match `scripts/start-UAT.sh`. The server needs no agent or gateway; the dashboard
pages are enough. One line is printed per check.

```bash
node tests/puppeteer/ui-smoke.mjs --selftest
```

The selftest needs only puppeteer: no server, database or login. It serves a fake shell from a
local `127.0.0.1` fixture and bends it one way per case, asserting that the real crawl and
overflow checks fail for the right reason: a nav without `/`, an href outside `EXPECTED`, errors
raised after load, a missing or `unsafe-eval` CSP, a submit button outside its form, a form with
no submit control, and a 404 route. A baseline case first proves the clean fixture passes. `/test`
runs it before the live run, and a selftest failure fails the gate. Add a case when you add a check.

## What it checks

1. Nav crawl: every route the shell links to answers 200 with the CSP header and no page error.
   The discovered set must equal `EXPECTED` in `ui-smoke.mjs`; adding or removing a nav entry in
   `app_shell.cpp` means editing that list in the same change.
2. Overflow: submit controls on the plugin upload form, the add-user dialog and the new-token
   dialog stay inside their form or dialog and the viewport at 1400x900 and 1024x768.
3. Scenarios, each forcing its own precondition (writes are answered by a request stub, so none
   reaches the server):
   upload rollout percentage and a failing upload, add user, the Ctrl+K guard on a focused field,
   and the PKI audit-failed banner and load-error text.

It does not check: WebGL scenes (the Fleet and Host maps), non-administrator roles, a write that
really reaches the server, or any route the shell does not link to. The nav list it compares
against is hand-copied, so a new nav entry fails the smoke until `EXPECTED` is edited. Needs
Node 22.12 or newer (the pinned `puppeteer` requires it); run `(cd tests/puppeteer && npm ci)`
once.

## Writing a scenario

Use the harness; do not sleep. Wait on `settled(page)` or `page.waitForFunction`, and call
`quiesce(page)` before reading a `watch()` collector. Install a `stub()` before the request it
answers is issued (a write nobody stubbed is aborted, never sent), and assert on DOM facts and on
the request log. Match a toast by its exact text: error toasts do not auto-remove.
Create temporary files under `os.tmpdir()` with a `yuzu_test_` prefix, never in the tree.
