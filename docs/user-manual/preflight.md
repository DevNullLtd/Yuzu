# Deployments and pre-flight readiness checks (`/auto`)

The **Deployments** page (formerly called **Pre-flight**) checks software
rollouts first, deploys them, then verifies the result. Its first stage is an
operator surface for a **go/no-go check across a device cohort before a fleet
change** (a rollout, a patch, an upgrade). You pick a scope and a set of
thresholds, run it, and get a result grouped by device. It is reached from
**Software > Deployments** in the sidebar, or at **`/auto`** by URL, and the
same checks are intended to be driven headless by an orchestrator later.

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

## Numeric thresholds are validated

The run form reads **minimum free GiB** (`min_gib`) and the **window** (`window`, in minutes)
strictly. Each must be empty or one whole base-10 number. Anything else (`10abc`, `0x10`, `1.5`,
a leading `+`, whitespace, or a value too large for a signed 64-bit integer) is answered with
`400`, an error toast ("Pre-flight thresholds must be whole numbers, and versions dotted numbers such as 4.2.0") and an A4 error body (`invalid threshold parameter`); no run
is created and nothing is dispatched. A negative `min_gib` is refused the same way. An empty field
keeps its default: a minimum of 0 GiB free, and a 30-minute window. A `window` of zero or below
also uses the 30-minute default, and a larger value is clamped to 1 to 2880 minutes, clamped as a
64-bit value so a huge number cannot wrap into a different window. Before this check a malformed
`min_gib` read as 0, which let every device pass the free-disk check.

The version thresholds (**minimum version** `app_min`, **maximum version** `app_max` and **minimum
OS version** `os_min`) are checked the same way. Each must be empty (no threshold) or a
dotted-decimal version such as `4.2.0`, `10.0.19045` or `5.5`, optionally followed by a pre-release or
build suffix of letters, digits and `-` / `+` with no dot (`4.2.0-beta`, `4.2.0-rc1`,
`4.2.0+build5`); the suffix is accepted and ignored by the comparison. Anything else (`abc`,
`v4.2.0`, `4.2.x`, `1..2`, `-1`, `4.2.0-beta.1`, a component longer than 15 digits) is answered with
`400` with that same error toast (one message covers both the numeric and the version thresholds) and A4 error body, and no run is created. A malformed threshold used to read as version
0, so a minimum of `abc` passed every device and the go/no-go gate that feeds Deploy failed open.

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

**A check's responses can outgrow the read window.** Each check reads its newest 50,000
responses for the run (the window slides; it keeps the newest). On a very large cohort with a
lot of re-dispatch the window can fill, and a device that is absent from it is then
**ambiguous**: it may not have answered, or it may have answered and been pushed out of the
window. Such a device is never shown as passing. A device with **no row at all** in a full
window has its cell read **"inconclusive: response cap reached"**; a device whose in-progress
row is still in the window is simply pending and is not labelled. Either way the device stays
**Incomplete** (so it is not in Deploy's go cohort), and the server stops re-dispatching that
run's checks, because every extra reply would push another device's answer out of the window.
The run still completes at its deadline. A saturated window can only lose devices to eviction; it never gives a device a false go. A reply already in flight when dispatching stops can still land and be recorded, so a device's cell can change after the window fills.

What fills the window: a device that gave a terminal error answer (verdict unknown) is still
incomplete, so it is re-dispatched on every tick and each dispatch adds rows; the window
evicts the **oldest** rows first, which are the **earliest** answerers. On a large cohort,
with a long window (up to 2,880 minutes) and a cohort near its 20,000-device cap, devices that
passed early can therefore flip to "inconclusive" before the deadline. To resolve those
devices, re-run the pre-flight against a smaller group. Changing the re-dispatch rule, and
per-device paging of the response read, are known limitations that this release does not address.

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
minimum cohort size**: a paired set of any size is shown with its exact figures (no
"indicative" label is rendered at the one-device floor). Because that means reading
named machines' data, the comparison is **recorded in the audit log**. The aggregate is shown without any
per-machine identity; the **per-machine pairs** are behind a separate *"Show
per-machine pairs"* click, so opening that view is a deliberate, separately-audited
action.

**Prerequisite:** Verify reads the retained per-device performance history, which only
exists if **per-application performance collection** (`procperf_enabled`, on by default)
has not been disabled on the devices. Without it, every Verify comparison returns *insufficient*
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
**Failed** on a stage error, a non-zero exit, being quarantined, the dispatched
plugin being absent from its reported inventory, or a per-OS kill switch
withholding the plugin from that device's OS (the last three are permanent — a
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
a second one. A device that is offline (or a fail-closed containment-gate or per-OS gate read) when
its stage or execute step is dispatched is retried automatically on a later tick,
while the page keeps polling — no need to delete and re-deploy; the device is
released back to in-flight (not Failed) so a later tick reclaims and redispatches
it, until it either reaches the agent or you close the page. A device that is
quarantined, is missing the `content_dist` plugin, or is on an OS the plugin's
per-OS kill switch withholds is a permanent condition and fails immediately
instead — those need an operator action (release the quarantine, install the
plugin, turn the per-OS switch back on) before a re-deploy will help. The same engine is
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

- `GET /api/v1/deployments` and `GET /api/v1/deployments/{id}` / MCP `list_deployments` and
  `get_deployment` — your deployments and one deployment's device grid, gated
  `SoftwareDeployment:Read`. These are the read-only way to see a rollout: unlike the page's
  result poll (`/fragments/auto/deploy/result`) they never advance the engine and write no per-poll audit row
  (the REST reads are unaudited; an MCP call records the generic `mcp.<tool>` success row). A deployment shows **Running** or **Complete**; a finished one says how many devices
  failed or were skipped ("Complete, 2 failed"). There is no staged, cancelled or rolled-back state
  in this pipeline. The installer URL and arguments are never shown, only whether arguments are set.
  A service-scoped token is denied under `deployment.list.view` / `deployment.detail.view`.

- **Deployments tab** — on the Deployments page (`/auto`), the **Deployments** tab beside
  **Pre-flight and deploy** lists your deployments from the last 14 days, newest first. Select a
  deployment's name to see its device grid below the list. The tab is read-only: it never advances
  a running deployment, so counts for a **Running** deployment are as of the last advance, and a
  running deployment advances only while its deploy results view (Pre-flight and deploy, then
  Deploy) is open. Reading the list and detail needs `SoftwareDeployment:Read`; without it the tab
  says so in place. `/auto#deployments` opens the tab directly.

The REST routes above are unaudited on a successful read (the response is run scope/lifecycle metadata,
not per-agent behavioural PII, matching the fragments' own posture) but audit a service-scoped-token
denial under their own verb. Their MCP twins instead call the generic
`mcp.list_preflight_runs`/`mcp.get_deployment_preview` (and, for the two deployment reads above,
`mcp.list_deployments`/`mcp.get_deployment`) success audit, matching the majority
convention for MCP read tools in this codebase — the two transports deliberately diverge here; see
`docs/api-twin-recipe.md` §4 for why REST/MCP/dashboard audit postures are not required to agree.
