# Pre-flight readiness checks (`/auto`)

The **Pre-flight** page is an operator surface for a **go/no-go check across a
device cohort before a fleet change** (a rollout, a patch, an upgrade). You pick a
scope and a set of thresholds, run it, and get a result grouped by device. It is
reached at **`/auto`** by URL — it is deliberately not a navigation tab yet, and
the same checks are intended to be driven headless by an orchestrator later.

## The checks

Each run dispatches up to five **read-only** checks to the in-scope devices and
applies your thresholds server-side:

| Check | Threshold | Passes when |
|---|---|---|
| **Target App** | app name + min / max version (optional) | the named app is installed and its version is within `[min, max]` |
| **OS version** | minimum OS version | the device OS version is at or above the floor |
| **Arch** | required architecture (`x86_64` / `arm64` / `any`) | the device architecture matches |
| **Free disk** | minimum free GiB (+ optional volume) | free space on the volume is at or above the floor |
| **Pending reboot** | block or warn | no reboot is pending (a pending reboot fails when *block*, or warns when *warn*) |

The Target App check only runs when you give it an app name; the rest always run.

## Reading the result

Devices are grouped by outcome, with a run-level summary and per-device check
badges:

- **Pass** — every blocking check passed.
- **Failed** — at least one blocking check failed (the device is **no-go**). The
  *Failed by* chips let you filter the failed group by which check failed.
- **Warn-only** — warnings (e.g. a pending reboot under the *warn* policy) but no
  blocking failure.
- **Incomplete** — the device has not answered every check yet (or never answers).

Click a device name to open its per-device view.

## Run window and offline devices

A run keeps re-trying for its **window** (the "catch offline" minutes). A device
that is offline at dispatch still reports if it **reconnects within the window**;
a device that never answers stays **Incomplete**. The page itself pauses polling
after a few minutes, but the run continues server-side for the whole window —
reopen it from **Recent runs** to refresh.

## Persistence and retention

Runs are **saved** and listed in the **Recent runs** rail; reopen one to revisit
its result (a completed run reads its stored grid, so it survives even after the
underlying responses are pruned). Saved runs are **kept 14 days**, then pruned
automatically. Delete a run from the rail (you are asked to confirm first).

Runs are **owner-scoped**: you only see and can delete your own runs, and opening
another operator's run is indistinguishable from a run that does not exist.

If the run store's schema cannot be initialized at boot (for example, after a
conflicting manual schema alteration in Postgres), the server **refuses to start**
and logs `[PG] Refusing to start`. Treat this like any other Postgres migration
failure — restore the schema or redeploy from a clean database. (A *transient*
store error while the server is already running just degrades `/auto` to an
"unavailable" note; it does not take the server down.)

A **transient failure reading the response store** while a run is still going
(separate from the run store above — this is the store holding each check's
agent results) shows a "temporarily unavailable, retrying" banner on the result
page and keeps showing the last state that was actually confirmed; it never
shows a device as newly failed or incomplete just because a read hiccuped, and
it retries automatically on the next poll. This matters because a device's
result also feeds **Deploy**'s go/no-go cohort (see below): a device that has
genuinely passed pre-flight stays counted as passed through a momentary read
failure, rather than dropping out of the cohort until the run is manually
re-checked.

## Verify — before / after performance

The **Verify** stage at the bottom of `/auto` answers a different question from
pre-flight: *after* an upgrade, **did it change how the same machines perform?**
Pick a cohort (a management group), an application, the **baseline** version (what
they ran before) and the **candidate** version (what was installed), and a window,
then **Compare**.

The comparison is **cohort-paired**. For each machine that ran *both* versions in
the window, Verify takes that machine's own baseline-version performance and its own
candidate-version performance and computes the difference *per machine*, then
aggregates those differences. The window is anchored to **each machine's own version
history**, not to a fixed "last N days", so a rollout where different machines
upgraded at different times still pairs correctly. A machine that ran only one of the
two versions in the window is **excluded and counted** (never guessed at). This
matters: a fleet-wide "version A vs version B" average would compare *different
machines* and could blame the build for a difference that is really just a different
population — pairing on the machine removes that.

Verify is **evidence, not a verdict.** It shows the measured shift — CPU and
working-set before→after means, the typical (median) per-machine change, the spread
across machines (p95), and how many machines went up / stayed flat / went down — and
**lets you judge**. It never labels a build "bad" or "regressed", and there is no
pass/fail gate (unlike pre-flight's go/no-go). An AI colleague driving the rollout
reads the same numbers over MCP and makes the call.

Real canaries are small — two or three devices — so Verify deliberately has **no
minimum cohort size**: a small paired set is shown with an *"indicative"* note rather
than hidden. Because that means reading a handful of named machines' data, the
comparison is **recorded in the audit log**. The aggregate is shown without any
per-machine identity; the **per-machine pairs** are behind a separate *"Show
per-machine pairs"* click, so opening that view is a deliberate, separately-audited
action.

**Prerequisite:** Verify reads the retained per-device performance history, which only
exists if **per-application performance collection is enabled** on the devices (it is
opt-in and off by default). Without it, every Verify comparison returns *insufficient*
with no data — pick the cohort accordingly. Even with collection on, a just-upgraded
candidate version only appears once the upgraded machines have reported it (the next
daily report after the upgrade), so running Verify immediately after a deploy may show
*insufficient* until the cohort reports back. Verify dispatches nothing to the devices.

You pick the cohort (a management group) manually; automatically pre-filling it from the
ACT/deploy stage is a planned future convenience, not yet available — as is a live
measure-after-deploy mode (Verify today reads only the retained daily history). Very large cohorts
(thousands of devices) can exceed the read cap, in which case Verify shows a *truncated*
warning and the numbers are unreliable — narrow the group or shorten the window.

The same comparison is available to automation: REST `GET /api/v1/dex/perf/compare`
and MCP `compare_app_perf_versions` return the aggregate (no per-machine identity).

## Deploying to the go-cohort

Pre-flight is the **assess** half of a change; the **act** half lives on the same
page. As soon as a run has a go-cohort — at least one device in **Pass** or
**Warn-only** — a **Deploy go-cohort** button appears on the result. **The run does
not need to finish first**; the button's count grows as more devices clear. It opens
a deploy panel where you give an **artifact** — a download **URL**, a **filename**,
the expected **SHA-256**, and optional silent-install **arguments** — and confirm.
The server validates the artifact before any dispatch: the filename against a safe
charset, the SHA-256 as exactly 64 hex chars, the URL as http(s), and the arguments
for shell metacharacters — a spec failing any of these is rejected outright.
The deployment targets the devices that had cleared **at the moment you clicked
Deploy** (the cohort is frozen then). On those devices it:

1. **Stages** the installer — the agent downloads it and verifies the SHA-256 (a
   hash mismatch fails the device; the file is never executed).
2. **Executes** the staged installer once the hash is confirmed, and records the
   exit code.

The progress view is **aggregate-first**: a count strip (targeted / succeeded /
executing / in-flight / failed / skipped) and a progress bar are the headline, with
the per-device list below, problem-first. A device is **Succeeded** on exit 0,
**Failed** on a stage error, a non-zero exit, being quarantined, or the dispatched
plugin being absent from its reported inventory (the last two are permanent — a
retry will not help), and **Skipped** if you no longer have scope to it when the
step is dispatched — it is never run. A device is **not** shown as Failed for a
device that was offline or unreachable at dispatch time, or for a transient
containment-gate degradation — see below.

Two safety properties matter because executing an installer changes the endpoint:

- **Run-once.** The execute step is claimed before it is dispatched, so an
  installer runs **at most once per device** even if you reload the page, several
  tabs poll at once, or the server restarts mid-deployment.
- **Re-authorization.** Every tick re-checks the devices you can currently see. A
  device that has dropped out of your scope since the pre-flight run is **skipped**,
  not executed.

**Approval governance (#1398).** The stage/execute dispatches this pipeline makes are
`content_dist` actions — some of which a compiled per-pair gate marks as requiring an
admin caller or a redeemed approval ticket on every OTHER dispatch surface (raw
`/api/command`, MCP, schedules). Deploy is exempt from minting its own ticket: this
pipeline's own re-authorization (above), run-once claim, and full audit trail are
accepted as the equivalent control, so a non-admin operator with `SoftwareDeployment:Execute`
can deploy without a separate approval step. This is a deliberate design choice, not a
gap — see `docs/security-reviews/1398-dispatch-approval-gate-design.md`, Decision 5.

**Deploying mid-run, and covering later devices.** Because you can deploy before
the run finishes, a deployment only covers the devices that had cleared when you
clicked. Devices that clear **afterward** are not added to the running deployment —
clicking **Deploy go-cohort** again while it is still running just re-attaches to
that same deployment. Once it **completes**, click **Deploy go-cohort** again to
cover the newly-cleared (and any **Failed**) devices: the new deployment automatically
**excludes devices an earlier deployment already installed successfully**, so the
installer is never run twice on one device across the run.

A deployment is driven by the open page today (there is no background runner in
this slice). Closing the page — or the page reaching its automatic poll limit
after roughly ten minutes — **pauses** the deployment: its state is durably saved,
but it does not advance while no page is polling it. To **resume**, re-open the
deploy panel for the same pre-flight run and click **Deploy go-cohort** again — the
server detects the in-flight deployment and re-attaches to it rather than starting
a second one. A device that is offline (or a fail-closed containment-gate read) when
its stage or execute step is dispatched is retried automatically on a later tick,
while the page keeps polling — no need to delete and re-deploy; the device is
released back to in-flight (not Failed) so a later tick reclaims and redispatches
it, until it either reaches the agent or you close the page. A device that is
quarantined or is missing the `content_dist` plugin is a permanent condition and
fails immediately instead — those need an operator action (release the
quarantine, install the plugin) before a re-deploy will help. The same engine is
designed to be driven headless by an automation worker later.

## Permissions

| Action | Permission |
|---|---|
| View the page / a result / the rail | `Infrastructure:Read` |
| Run a pre-flight | `Infrastructure:Read` + `Execution:Execute` |
| Delete a saved run | `Execution:Execute` (and you must be the owner) |
| Open the deploy config panel for a run | `SoftwareDeployment:Read` |
| Deploy to a go-cohort (create + first advance) | `Infrastructure:Read` + `SoftwareDeployment:Execute` |
| View / track a deployment — each poll also advances the engine | `SoftwareDeployment:Read` + `SoftwareDeployment:Execute` |
| Delete a deployment | `SoftwareDeployment:Execute` |
| Open the Verify form | `Infrastructure:Read` |
| Run a Verify comparison / open the per-machine drill | `GuaranteedState:Read` |

The route-level permissions above gate *whether* you can open/advance a deployment at all. Each
advance additionally dispatches per device through the same chokepoint every other operator
surface uses, which applies **two further, per-action checks** you don't request directly: staging
an artifact on a device requires `SoftwareDeployment:Write`, and executing it requires
`Execution:Execute` — confined to your `Execution:Execute`-**visible** device set, the same
per-device confinement `Execution:Execute` enforces everywhere else (e.g. running a pre-flight,
above). A device outside that visible set is skipped, never executed on, regardless of whether
it's in the go-cohort. A global `Execution:Execute` grant is unaffected; a management-group-scoped
one confines deployment execution the same way it confines everything else.

Deployments are **owner-scoped** (viewing, advancing, resuming, and deleting all
require you to be the creator; another operator's deployment reads as not-found).
The result poll requires `Execute` as well as `Read` because the same request
**advances the mutating engine**, not just renders — a read-only operator cannot
drive a deployment.

Pre-flight runs and deletes are recorded in the [audit log](audit-log.md) as
`preflight.run` and `preflight.run.delete`; deployments as `deployment.create`
(result `success` / `resumed` / `no_devices`), `deployment.advance`, and
`deployment.delete`. A Verify aggregate comparison is recorded as
`dex.app_perf.compare`; opening the per-machine pairs carries its own
`dex.app_perf.compare.drill` verb so per-machine access stays separately countable.
(Over MCP, `compare_app_perf_versions` is recorded under the generic
`mcp.compare_app_perf_versions` tool-call audit.)

## REST / MCP access

The saved-runs rail (`GET /fragments/auto`'s runs half) and the deploy-config go/warn preview
(`GET /fragments/auto/deploy`) are also reachable as versioned REST + MCP twins — see
[`rest-api.md`](rest-api.md#pre-flight--deploy) and [`mcp-server.md`](../mcp-server.md) for the
full request/response shapes. Both twins are **owner-scoped** (your own runs only) and read-only —
they never create a run or a deployment.

- `GET /api/v1/preflight/runs` / MCP `list_preflight_runs` — your saved runs. The config-options
  half of the fragment (available management groups for the scope dropdown) is deliberately **not**
  duplicated here — that catalogue already has its own twin, `GET /api/v1/management-groups` /
  `list_management_groups`, gated `ManagementGroup:Read`. Denial of a service-scoped API token is
  audited under `preflight.run.view` — a distinct verb from `preflight.run` (the run-**creation**
  verb) so a denied list read can never be mistaken for a run being created.
- `GET /api/v1/deployments/preview?run={id}` / MCP `get_deployment_preview` — the go/warn preview
  for one pre-flight run, gated `SoftwareDeployment:Read`. Reuses the existing `deployment.config.view`
  verb (already distinct from `deployment.create`).

Both REST routes are unaudited on a successful read (the response is run scope/lifecycle metadata,
not per-agent behavioural PII, matching the fragments' own posture) but audit a service-scoped-token
denial under their own verb. Their MCP twins instead call the generic
`mcp.list_preflight_runs`/`mcp.get_deployment_preview` success audit, matching the majority
convention for MCP read tools in this codebase — the two transports deliberately diverge here; see
`docs/api-twin-recipe.md` §4 for why REST/MCP/dashboard audit postures are not required to agree.
