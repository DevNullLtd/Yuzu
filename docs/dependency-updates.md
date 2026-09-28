# Dependency Updates

This doc is the strategy reference for keeping Yuzu's pinned third-party
dependencies current. It closes the acceptance criteria for #363: every
ecosystem has a clear update path, a staleness query, and a visible merge
latency. If you're adding a new pinned dependency, this is the file that
tells you where it belongs.

## What is pinned, where, and how it gets updated

| Ecosystem         | Source of truth                               | Update path                                                                                  |
|-------------------|-----------------------------------------------|----------------------------------------------------------------------------------------------|
| GitHub Actions    | `uses: ...@vX` in every `.github/workflows/*` | Dependabot (weekly) — `.github/dependabot.yml` `github-actions` entry                         |
| Windows SDK       | `10.0.26100.0` in the Windows build/provisioning contract | Deliberate reviewed PR; `tests/test_windows_sdk_contract.py` prevents drift (Dependabot tracks the MSVC action, not its `with.sdk` input) |
| Docker base images| `FROM` in `deploy/docker/*`                   | Dependabot (weekly) — `.github/dependabot.yml` `docker` entry                                 |
| Python tooling    | `requirements-ci.txt` (repo root)             | Dependabot (weekly) — `.github/dependabot.yml` `pip` entry                                    |
| npm tooling       | `package-lock.json` in `site/`, `tests/puppeteer/`, `deploy/docker/cedar-vale/app/` | Dependabot (weekly, grouped per directory) — `.github/dependabot.yml` `npm` entry; see "npm tooling" below |
| vcpkg baseline    | `vcpkg.json` `builtin-baseline`               | Scheduled workflow — `.github/workflows/vcpkg-baseline-update.yml` (monthly PR, hands-off)     |
| rebar3 deps       | `gateway/rebar.config`                        | **Manual quarterly review** — see "Rebar3 review checklist" below                              |
| Git submodules    | —                                             | No submodules; nothing to track                                                               |

## Update tiers — what carries a remediation SLA

Not everything Dependabot tracks ships to customers. Two tiers, and the
tier — not the tracking mechanism — decides the remediation posture:

- **Tier 1 — product.** Anything compiled into or shipped alongside the
  server, agent, or gateway: vcpkg deps, Docker base images, rebar3 deps,
  and the vendored JS assets embedded into the server binary. Security
  advisories here follow the vulnerability-management commitments in
  `docs/enterprise-readiness-soc2-first-customer.md` (Workstream C).
- **Tier 2 — repo tooling.** Build/test/docs/demo tooling that never
  ships in a product artifact: the three npm directories and the pip CI
  tooling. Advisories are tracked, surfaced, and auto-patched through the
  same Dependabot flow, but are triaged case-by-case and carry **no
  product SLA** — a DoS in the demo deck server is not a product CVE.

This tiering is the story SOC 2 evidence cites: Tier 2 surfaces are
in-scope for *tracking* (advisories cannot accumulate silently anywhere
in the repo) and explicitly out of scope for product remediation SLAs.
If a Tier 2 surface's output starts shipping in a product artifact, it
moves to Tier 1 with its whole ecosystem.

### Base branch

Every Dependabot entry sets `target-branch: dev`. Yuzu's release flow is
feature work → `dev` → reconcile PR → `main`, which means `main` lags
`dev` for hours-to-days at a time. Opening dependency PRs against
`main` races the reconcile cadence and repeatedly fails CI against a
stale base — the LNK2038 Windows fix lived on `dev` for ~24h before the
reconcile PR, during which every open Dependabot PR targeting `main`
kept failing Windows CI. Targeting `dev` eliminates the race.

## Python tooling (meson, etc.)

Yuzu's CI pipeline pins meson because subtle backend rewrites between
meson minor releases have bitten us on ninja dyndep ordering. The pin
is stored in two files at the repo root:

- **`requirements-ci.in`** — human-edited source-of-truth (one
  `package==version` per line).
- **`requirements-ci.txt`** — hash-pinned lock file auto-generated from
  `.in` via `pip-compile --generate-hashes`. Required by OpenSSF
  Scorecard's Pinned-Dependencies check.

These are consumed by:

- `.github/workflows/ci.yml` — all six jobs `pip3/pip/pipx install` from it
  (with `--require-hashes` so a tampered package breaks the install).
- `.github/workflows/release.yml` — Windows and macOS release builds.

`scripts/setup.sh` assumes a `meson` binary is already on PATH and does
not install one — local developers are responsible for matching the
pinned version themselves (`pip install --require-hashes -r requirements-ci.txt`
in a venv is the easiest path).

### Bumping meson

```bash
# 1. Edit requirements-ci.in
$EDITOR requirements-ci.in

# 2. Regenerate the hash-pinned lock file
pip install pip-tools      # if not already installed
pip-compile --generate-hashes --strip-extras requirements-ci.in \
            -o requirements-ci.txt

# 3. Commit both files together
git add requirements-ci.in requirements-ci.txt
```

Dependabot opens a PR bumping `requirements-ci.txt` whenever a newer
meson is released. Accepting a Dependabot bump: pull the branch locally,
re-run `pip-compile` to refresh the lock file hashes against the bumped
version in `.in`, amend-commit and push. (Dependabot doesn't know about
the `.in` file so it only updates the `.txt`; keep them in lockstep.)

### Known duplication — Dockerfile meson pins

`deploy/docker/Dockerfile.{agent,server,ci,ci-linux,runner-linux}` each
hardcode `meson==1.9.2` as part of the build-stage apt+pip RUN command.
These are **not** auto-tracked by Dependabot and will drift from
`requirements-ci.txt` if Dependabot bumps meson. This is a known
follow-up — centralizing them on `COPY requirements-ci.txt` is tracked
implicitly by #363 and can be done in a follow-up PR. Until then, when
merging a Dependabot meson bump, also bump the literal `meson==X.Y.Z`
string in those 5 Dockerfiles. Grep `meson==` under `deploy/docker/` to
find them:

```bash
grep -rn 'meson==' deploy/docker/
```

## npm tooling (docs site, UAT harness, demo app)

Three npm-managed directories, all Tier 2 (nothing here ships in a
product artifact):

| Directory | What it is | Exercised by |
|---|---|---|
| `site/` | Astro docs site (GitHub Pages) | `docs-site.yml` build job on every PR touching it |
| `tests/puppeteer/` | Puppeteer UAT harness | manual / UAT runs only — **no CI coverage** |
| `deploy/docker/cedar-vale/app/` | Cedar & Vale demo deck server (Express + pg; built only by the viz-UAT rig) | local `docker-compose.viz-uat.yml` builds |

Each directory commits a `package-lock.json` and is listed in the
`npm` entry of `.github/dependabot.yml`. Minor+patch bumps ride one
grouped weekly PR per directory; **majors arrive as separate
single-dependency PRs** (the group filters on `update-types`) so a
breaking major — Astro N+1, express 5, a puppeteer line bump — never
dams the patch stream behind a red migration PR. Astro majors are
validated by the docs-site build job; **puppeteer majors get a manual
UAT-harness smoke before approval**, because nothing in CI exercises
that harness. The docs site pins its toolchain floor in
`site/package.json` `engines` (mirrors Astro's own floor — currently
Node ≥ 22.12.0, npm ≥ 9.6.5; the docs-site job runs Node 22).

**Standing convention — puppeteer launch args.** Every script in
`tests/puppeteer/` passes `--no-sandbox` in its `puppeteer.launch` args (all
seven do, as of the fix that closed this gap). On hosts where user-namespace/
AppArmor restrictions block Chromium's own sandbox, its absence is an
outright launch failure — not a puppeteer-version problem — which is exactly
what blocked the manual pre-approval smoke this doc mandates above for
puppeteer majors: four of the seven scripts silently diverged from the other
three and none of them could launch a browser at all until the flag was
added back. A new script in this directory must carry the flag from
creation.

**Standing convention — new npm directories.** A directory gaining a
`package.json` ships, in the same PR: a committed `package-lock.json`,
an entry in the `npm` block's `directories:` list in
`.github/dependabot.yml` (the list is explicit; there is no
auto-discovery), and `npm ci` — never `npm install` — in any Dockerfile
that consumes it, so images get exactly the committed, audited tree and
manifest/lockfile drift fails the build loudly. A lone `package.json`
has an unpinned transitive tree that is invisible to Dependabot,
`npm audit`, and OSV alike — exactly the hole PR #1877 closed for the
cedar-vale app, where the unpinned tree was carrying a live
high-severity ReDoS.

## vcpkg baseline

Dependabot does not understand vcpkg. We evaluated three options in #363:

1. **Renovate Bot with vcpkg regex managers** — more flexibility, but
   adds a second bot to the repo and the regex configuration is its own
   maintenance burden.
2. **Scheduled workflow that bumps the baseline and opens a PR** —
   simpler, uses GitHub Actions native tools, visible in the normal PR
   feed.
3. **Manual bump during release prep** — zero automation, relies on
   memory.

We chose **option 2**. `.github/workflows/vcpkg-baseline-update.yml`
runs at 10:00 UTC on the 1st of each month (and is
`workflow_dispatch`able). It:

1. Resolves `git ls-remote https://github.com/microsoft/vcpkg.git HEAD`
   to get the current master SHA.
2. Reads `vcpkg.json` `builtin-baseline` via `jq`.
3. If they match, exits silently.
4. Otherwise, `sed -i`s the new SHA into every **active** tracked reference.
   Historical `docs/reviews/` evidence is immutable and deliberately keeps the
   baseline that was reviewed at the time. The workflow file keeps the
   authoritative active list and fails loudly if a listed file still has the
   old SHA after the sed.
5. Opens a PR via `peter-evans/create-pull-request@v7` with label
   `dependencies,ci`.

CI on the PR re-resolves every downstream vcpkg port against the new
baseline — if anything breaks, the PR is left open for manual
investigation instead of silently merging a broken build.

When adding a new active file that pins the vcpkg baseline SHA (e.g., a new CI
workflow or Dockerfile), **add it to the `files` array in
`.github/workflows/vcpkg-baseline-update.yml`**. Do not add immutable
`docs/reviews/` evidence. The post-sed verifier checks listed files, while the
toolchain-contract inventory test finds an unlisted active reference.

## Rebar3 deps review checklist

`rebar3` has no dependabot ecosystem. `rebar3 update` only refreshes the
package cache — it does not bump the pins in `rebar.config`. Automating
rebar3 bumps requires custom per-dep logic (hex.pm API for hex deps,
`git ls-remote --tags` for git deps) that isn't worth the complexity for
a project with 7 gateway dependencies that change a few times a year.

**We review `gateway/rebar.config` manually every quarter**, or whenever
a gateway change is blocked on an upstream fix. Checklist:

1. `cd gateway && source ../scripts/ensure-erlang.sh`
2. For each hex dep in `rebar.config`, check the latest stable release:
   - `grpcbox` — https://github.com/tsloughter/grpcbox/tags
   - `gpb` — https://hex.pm/packages/gpb
   - `telemetry` — https://hex.pm/packages/telemetry
   - `prometheus` — https://hex.pm/packages/prometheus
   - `prometheus_httpd` — https://hex.pm/packages/prometheus_httpd
   - `recon` — https://hex.pm/packages/recon
   - `gproc` — https://hex.pm/packages/gproc
   - `meck` (test profile) — https://hex.pm/packages/meck
   - `proper` (test profile) — https://hex.pm/packages/proper
3. For each git-pinned dep (`grpcbox_plugin`), `git ls-remote --tags`.
4. Bump any dep whose latest stable is > 1 minor version ahead of the
   pin, or any dep with a known security advisory (check GitHub
   Security Advisories for the repo).
5. Run `/test --quick` (unit + eunit + dialyzer + synthetic UAT) after
   each bump — do not batch bumps without testing in between.
6. Commit the `rebar.config` change with a conventional
   `build(deps): bump <dep> to <version>` message.

## Vendored JavaScript assets

Yuzu embeds third-party JavaScript at build time via `embed_js.py` (chunked raw-string-literal output to fit MSVC's 16,380-byte C2026 limit). These files are **not** tracked by Dependabot and must be refreshed manually. Each upstream version is pinned in `tests/unit/server/test_static_js_bundle.cpp` by exact byte count + canary substring; a silent CDN substitution fails the test loud.

| Asset | Vendor file | Symbol | Upstream | Current pin |
|---|---|---|---|---|
| HTMX runtime | `server/core/src/static_js_bundle.cpp` (chunked at hand) | `kHtmxJs` | https://unpkg.com/htmx.org@2.0.4/dist/htmx.min.js | 2.0.4, 50,918 bytes |
| HTMX SSE extension | same TU | `kSseJs` | https://unpkg.com/htmx-ext-sse@2.2.2/sse.js | 2.2.2, 8,897 bytes |
| Apache ECharts | `server/core/vendor/echarts.min.js` | `kEChartsJs` | unpkg.com/echarts/dist/echarts.min.js | 5.6.0, 1,034,102 bytes |
| Inter variable webfont | `server/core/vendor/inter/InterVariable.woff2` | `kInterVariableWoff2` | https://github.com/rsms/inter | 4.0, 345,588 bytes |
| Three.js (ES module) | `server/core/vendor/three.module.min.js` | `kThreeJs` | https://unpkg.com/three@0.168.0/build/three.module.min.js | r168, 685,408 bytes |
| Three.js OrbitControls | `server/core/vendor/three-orbit-controls.js` | `kThreeOrbitJs` | https://unpkg.com/three@0.168.0/examples/jsm/controls/OrbitControls.js | r168, 32,134 bytes |
| Yuzu chart adapter | `server/core/src/charts_js_bundle.cpp` (hand-written) | `kYuzuChartsJs` | first-party | n/a |
| Yuzu fleet renderer | `yuzu_viz_js_bundle.cpp` (generated at build time from `server/core/static/yuzu-viz.js`) | `kYuzuVizJs` | first-party | n/a |

### Refresh procedure (vendored vendor JS only)

For HTMX / ECharts / Three.js / OrbitControls — anything we did NOT author:

1. Download the new file from the upstream `unpkg.com/<pkg>@<version>/...` URL into the matching `server/core/vendor/` path. Keep the same filename.
2. Update the corresponding NOTICE file at `server/core/vendor/<pkg>-NOTICE.txt` if the upstream license header changed.
3. Update the top-level `NOTICE` row if the version naming changed.
4. Update `tests/unit/server/test_static_js_bundle.cpp`:
   - Bump the byte-count constant (`kExpectedFooBytes`).
   - Bump the version-token canary if upstream changed it (e.g. for Three.js, the bundle exposes `REVISION = "<n>"` once — pin the quoted form per gov R4 QA-B1).
5. Build with `meson compile -C build-{linux,macos,windows}`. The `embed_js.py` chunking + DELIM-collision check runs at build time; a refresh that smuggles in the close-delimiter token `)ECHARTSEMBED"` fails build cleanly.
6. Run `yuzu_server_tests "[static-js]"` to confirm pinned invariants pass.
7. Commit with a `chore(deps): bump <pkg> to <version>` message and reference the upstream changelog.

For Three.js specifically: r150+ is ES-module-only upstream. The OrbitControls module's top-level `import { ... } from 'three'` MUST resolve through the importmap declared in `viz_page_ui.cpp`. A refresh that splits OrbitControls into multiple files (e.g. PR-bundled with TransformControls) requires extending the importmap in lockstep. The `[viz][page]` test pins `from 'three'` and `class OrbitControls` substrings in the vendored file as a refresh canary.

For Inter font: a binary `.woff2` refresh follows the same pattern but uses `embed_binary.py`, not `embed_js.py`.

### Why these aren't in Dependabot

These are flat vendored files embedded into the server binary at build time — there is no `package.json` describing them, so Dependabot's npm ecosystem has nothing to parse. (The repo's actual npm-managed directories — `site/`, `tests/puppeteer/`, `deploy/docker/cedar-vale/app/` — **are** Dependabot-tracked; see "npm tooling" above.) The cost of a manual quarterly review against the pinned byte counts is small relative to the cost of converting the embedded-JS flow to an npm toolchain just for staleness tracking. If the vendored JS surface grows past 8–10 packages, reconsider.

## Staleness query — "what's the oldest pinned dep?"

- **Dependabot-tracked** (`github-actions`, `docker`, `pip`, `npm`) — open the
  "Dependency updates" tab on the GitHub UI, or
  `gh pr list --label dependencies --state open`. An open Dependabot PR
  with an old `createdAt` is the staleness signal; merge latency is
  visible directly.
- **vcpkg** — the scheduled workflow either finds a new HEAD (PR opens)
  or it doesn't. If a PR from `.github/workflows/vcpkg-baseline-update.yml`
  is open and older than a week, that's the staleness signal. Additionally,
  the pinned SHA's age can be measured directly:
  `git -C /tmp/vcpkg show -s --format='%ci' <sha>` after a
  `git clone --bare https://github.com/microsoft/vcpkg.git /tmp/vcpkg`.
- **rebar3** — the manual quarterly review is the staleness check.
  If the last commit touching `gateway/rebar.config` is more than 90
  days old, the review is overdue.

## CODEOWNERS auto-assignment

Dependabot can auto-assign PR reviewers via CODEOWNERS. This requires
`.github/CODEOWNERS` to exist, which is tracked in #366 (currently
blocked). Once #366 lands, add `codeowners: true`-style routing to the
dependabot entries so dependency PRs automatically ping the right
reviewer group.
