# Apps: application stability and the score policy

DEX (Digital Employee Experience) application stability ranks the applications
on your devices by how often they crash and hang, shows how many devices each
one affects, and scores each application against tiers that you control.

[Back to the hub](README.md) | [Surface map](surfaces.md)

## What it is

- The **Apps** tab lists one row per application, keyed on the process image
  name, ranked by crashes plus hangs. Each application expands to its versions.
- The **application drill-down** shows one application's blast radius across the
  fleet: the faulting modules, the exception codes and the devices affected.
- The **stability score** rates each application from 0 to 100 and gives it a
  tier name. The score shows its working: named deductions for breadth, crashes,
  hangs and regression.
- The **Scoring** tab holds the **score policy**: the tier edges and names, the
  weights and the per-application overrides that every score is computed under.

## Why it is useful

- **Fix the right thing first.** An application that crashes on a few hundred
  devices matters more than one that crashes often on a single device. Share
  affected and rate per 1,000 devices put that on one page.
- **Honest scores.** A score is withheld, with the reason in words, when it
  cannot be trusted: some affected devices are offline, there is no population
  to score against, or the counts disagree.
- **Small numbers are labelled.** A share or rate built on fewer than 20
  affected devices or events carries a tag saying so.
- **Your own bar.** The score policy lets you decide what "Excellent" or "Poor"
  means for your estate, and give a critical application its own thresholds.

## What feeds it and how to enable it

Crash and hang observations come from the agent's DEX observer, on by default
(see [collectors and plugins](collectors-and-plugins.md#the-dex-observer)). The
Apps tab states, under its title, which crash sources are complete or partial
for the platform in scope: complete on Windows, partial on Linux and macOS. An
empty list on a partial platform is not proof of stability.

The page also shows live observer state per platform: how many of the devices
online now have the observer **armed**, **not armed** or **not reporting**. A
device that runs with `--dex-disable` is counted as not reporting. The server
exposes the fleet total of not-armed devices as the metric
`yuzu_fleet_agents_dex_observer_disarmed`.

The score policy is stored in the server's runtime configuration; nothing needs
enabling on agents.

## Using it in the dashboard

1. Open **DEX**, then **Apps**. Choose a platform (All, Windows, macOS, Linux)
   and a window (`24h`, `7d`, `30d`, `All`).
2. Read the population line under the title: the devices in scope online now,
   which crash sources are complete or partial, and the score policy in force.
3. Read the columns: Application, Score, Crashes, Hangs, Devices affected, Share
   affected, Rate per 1,000 and Last seen. An `override` tag marks an
   application whose score a per-application override changes.
4. Click the score chip to see the named deductions. Regression always reads
   "not assessed" on this page, because the list has no per-version exposure to
   compare.
5. Expand an application to see its versions, or click its name for the
   drill-down.

Share, rate and score use only the devices online now. Crashes, hangs, devices
affected and last seen cover every device in the window. A note under the table
explains that the two can differ. The page lists up to 100 applications and up
to 20 versions each, and says so when it cuts either list.

If a read fails, the page shows an error panel with the cause, never an empty
list. The user manual lists each cause and what to do:
[DEX Apps](../user-manual/dex.md#apps).

### The score policy

Open the **Scoring** tab.

- **Policy in force** shows whether the shipped defaults or a custom policy
  apply, the revision, and the reason if a stored policy was refused.
- **Tiers** sets the lowest displayed score of Excellent, Good and Fair; Poor is
  everything below Fair. Tier names are 1 to 24 printable characters.
- **Weights** sets the four deduction weights, which sum to at most 100.
- **Model** sets the per-device event cap, the regression ratios and the
  interval confidence level.
- **Application overrides** sets up to 200 per-application overrides keyed by
  image name. An override changes only the fields it sets.

**Preview tier changes** is a dry run that lists which of the top applications
would change tier. **Save** writes the policy; **Reset to defaults** removes it
and every override. If someone else saves while you are editing, your save is
refused and nothing is overwritten.

Do not save or reset the policy during a rolling upgrade or rollback of the
server; see [upgrading](../user-manual/upgrading.md).

## REST

- `GET /api/v1/dex/apps` returns the stability list, including per-version
  figures, intervals, the score with its working and the policy in force.
  Takes `window` and `platform`. An unknown value is a `400`.
- `GET /api/v1/dex/app` returns one application's blast radius. Takes `name`
  (required) and `window`.
- `GET /api/v1/dex/score-policy` returns the policy in force, its revision and
  source, and a fault note if a stored policy was refused. The revision is
  also the `ETag`.
- `PUT /api/v1/dex/score-policy` replaces the policy. It requires an `If-Match`
  header carrying the revision you read (`default` when none was ever written).
  `dry_run=true` validates without storing. A stale revision is a `409`, a
  missing header a `428`.
- `DELETE /api/v1/dex/score-policy` removes the policy, returning to the
  shipped defaults. It also requires `If-Match`.

Edit a policy in three steps: read it (`GET`), change the document, send it
back with `If-Match` set to the revision you read.

## MCP

| Tool | Does | Needs |
|---|---|---|
| `list_dex_apps` | The stability list. | Read |
| `get_dex_app` | One application's blast radius. | Read |
| `get_dex_score_policy` | The policy in force and its revision. | Read, any tier |
| `set_dex_score_policy` | Replaces the policy, or validates it with `dry_run`. | Supervised-tier token, `Infrastructure:Write` and Read |
| `reset_dex_score_policy` | Removes the stored policy. | Supervised-tier token, `Infrastructure:Delete`, Read and an approval ticket |

Both write tools require `if_match`, the revision from `get_dex_score_policy`.
The reset tool answers with an approval request first; after a person approves,
repeat the same call with the approval id.

## Permissions and audit

| Action | Permission | Audit |
|---|---|---|
| View the Apps list | `GuaranteedState:Read` | Not audited. It is an aggregate with no device identity. |
| Open one application | `GuaranteedState:Read` | `dex.app.view` on REST and MCP; the dashboard drill-down writes no row. REST refuses to answer if the row cannot be stored. |
| Read the policy | `GuaranteedState:Read` (held outright) | Not audited. |
| Edit or reset the policy | `Infrastructure:Write` on REST and the Scoring tab; the tab also needs Read | `dex.score_policy.update`, `dex.score_policy.reset`, and `dex.score_policy.validate` for a dry run. A real write records an attempted row first and fails closed if it cannot be stored. |

Anyone who can view Scoring without `Infrastructure:Write` sees the page with
every control disabled and a note naming the grant. A service-scoped token is
refused on every read and write on this page. See
[surfaces](surfaces.md#the-rest-api).

## Limits and privacy

- The Apps list carries no device identity. The application drill-down names
  devices, which is why the REST and MCP reads are audited.
- The score is not a verdict. A score of Poor on a few devices is a flag to
  look, not a finding.
- The stored policy has no history. To go back, save the earlier document
  again; each update's audit row records the whole document.
- A stored policy that fails validation is not half-applied. The shipped
  defaults score instead, and a warning names the reason.
- The Apps tab covers crash and hang signals only.

## Platform coverage

Crash sources are complete on Windows and partial on Linux and macOS, by design.
The page states this and also counts observers armed per platform, so a quiet
Linux or macOS list is read with that in mind. See
[signals](signals.md#platform-coverage).

## Related pages

- [Signals](signals.md): the observations behind crashes and hangs.
- [App performance](app-performance.md): CPU and memory per application
  version, linked from the application drill-down.
- [Alerts](alerts.md): be told when one failure spreads across devices.
- [DEX in the user manual](../user-manual/dex.md#scoring): full Scoring tab
  reference.
