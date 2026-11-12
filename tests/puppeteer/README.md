# tests/puppeteer

Headless-browser checks against a running Yuzu dashboard.

| Script | Role |
|---|---|
| `ui-smoke.mjs` | The gate. Run by `/test` Phase 5 as "Browser smoke"; exit 1 fails the gate. |
| `lib/harness.mjs` | Shared helpers: launch, login, error collection, CSP and layout assertions, request stubs. |
| everything else | Older one-off probes. Not gates; `dashboard-help-test.mjs` is the warn-only "Puppeteer" gate. |

## Install

```bash
bash scripts/test/ensure-puppeteer.sh
```

`node_modules` and the browser are not committed. `/test` runs this script itself (Phase 0b, default
and `--full` modes) and aborts the run if it cannot finish, so the gates never skip for a missing
install. It is idempotent: on a ready machine it only verifies, including that Chrome launches
headless. By hand it is `PUPPETEER_SKIP_DOWNLOAD=1 npm ci --ignore-scripts` in `tests/puppeteer` plus
`npx puppeteer browsers install chrome`; the script adds timeouts, a lock and the repairs below.

Needs: Node 22.12 or newer, and network access to registry.npmjs.org and Google's Chrome for Testing
CDN (about 400 MB per browser build, in `~/.cache/puppeteer`, shared by every worktree; old builds are
not pruned). The Chrome archive is not hash-verified (no checksum is published). Standard proxy and CA
variables (`HTTPS_PROXY`, `NODE_EXTRA_CA_CERTS`, `npm_config_registry`) reach npm and the downloader.

If no Chrome for Testing build exists for your platform (for example Linux arm64) or the box has no
route to the download, point `PUPPETEER_EXECUTABLE_PATH` at an existing Chrome for Testing binary. That
variable only skips the browser download: `npm ci` still runs unless `node_modules` was installed by the
script from the current `package-lock.json` (it records the lockfile's SHA-256 in
`node_modules/.yuzu-package-lock.sha256`; a missing or different stamp reinstalls).

### Recovery

An interrupted install repairs itself on the next run: a partial Chrome download, or a Linux (ELF) binary
that is demonstrably incomplete (a truncated extract), inside puppeteer's own cache is removed and fetched
again once. A browser that is structurally complete but fails to run or to start is never deleted, and
neither is a macOS (Mach-O) or Windows (PE) one: there is no completeness check for those, so a truncated
macOS browser needs the manual step below. If it still fails:

- `cd tests/puppeteer && npx puppeteer browsers clear` removes ALL cached browsers (shared by every
  project that uses puppeteer), then re-run the script.
- `rm -rf tests/puppeteer/node_modules` and re-run, if node cannot load puppeteer.
- A browser that is complete but will not start headless is not reinstalled: look at the output above
  the error (an unwritable `TMPDIR`, a memory limit or address-space limit, or a sandbox restriction is
  the usual cause); on Linux missing shared libraries are listed by name.
- Timeouts can be raised with `YUZU_ENSURE_NPM_TIMEOUT`, `YUZU_ENSURE_BROWSER_TIMEOUT` and
  `YUZU_ENSURE_LAUNCH_TIMEOUT` (seconds).
- Run by hand from a terminal, Ctrl-C waits for the current step to finish or time out (the timeout
  kills the whole step so nothing is left running); `kill -TERM -<pgid>` stops it sooner.

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
3. Scenarios, six in all. Five force their own precondition (writes are answered by a request
   stub, so none reaches the server): upload rollout percentage and a failing upload, add user,
   the Ctrl+K guard on a focused field, the PKI audit-failed banner and load-error text, and the
   Engine Principals audit-failed notice. The sixth is the DEX Apps tab: a live half (the tab
   opens and a platform chip is pressed from the keyboard) and a golden half (the committed
   `apps__versions.html` is served through a GET stub, so the version expander, the score
   decomposition and a long application name are exercised on every run whatever the stack
   holds).

It does not check: WebGL scenes (the Fleet and Host maps), non-administrator roles, a write that
really reaches the server, or any route the shell does not link to. The nav list it compares
against is hand-copied, so a new nav entry fails the smoke until `EXPECTED` is edited. Needs
Node 22.12 or newer (the pinned `puppeteer` requires it); `scripts/test/ensure-puppeteer.sh` checks it.

## Writing a scenario

Use the harness; do not sleep. Wait on `settled(page)` or `page.waitForFunction`, and call
`quiesce(page)` before reading a `watch()` collector. Install a `stub()` before the request it
answers is issued (a write nobody stubbed is aborted, never sent), and assert on DOM facts and on
the request log. Match a toast by its exact text: error toasts do not auto-remove.
Create temporary files under `os.tmpdir()` with a `yuzu_test_` prefix, never in the tree.
