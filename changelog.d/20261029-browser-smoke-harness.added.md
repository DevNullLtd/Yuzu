- **Browser smoke gate in `/test`.** `tests/puppeteer/ui-smoke.mjs`, built on a new shared
  `tests/puppeteer/lib/harness.mjs`, crawls every route the dashboard nav links to (200, the
  `Content-Security-Policy` header, no page error), fails on nav drift in either direction,
  checks that submit controls stay inside their form or dialog at two viewport sizes, and runs
  stubbed write scenarios: the plugin upload rollout percentage, add user, the Ctrl+K guard on a
  focused field, and the PKI audit-failed banner and load-error text. A failure records FAIL;
  without the `npm ci` install the gate records SKIP. `ui-smoke.mjs --selftest` runs first and
  needs no stack: a local fixture proves each crawl and layout check fails when it should.
