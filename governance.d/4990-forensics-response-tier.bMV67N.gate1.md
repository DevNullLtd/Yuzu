# Gate 1 declaration: 4990-forensics-response-tier (range origin/dev..fix/4990-forensics-response-read-tier)

This file is the declared envelope of the change (Gate 1 of `.claude/skills/governance/SKILL.md`),
revised on 2026-10-28 so that the scope decision of 2026-10-24 is stated where Test 2 requires it.
It states the declared behaviour and security impact; the severity and disposition of every finding
are in `4990-forensics-response-tier.bMV67N.jsonl`, not here. It is written by the change's author
and carries no adjudication.

## Declared behaviour

- Stored responses of the five Forensics-tier plugins (`app_usage`, `browser_inventory`,
  `execution_artifacts`, `privacy_permissions`, `remote_access_audit`) are served only to a caller
  holding a global `Forensics:Read` in addition to `Response:Read`, on the REST, MCP and dashboard
  read paths and the server's own consumers of those rows.
- A read whose authority cannot be determined is refused with a retryable error, never a partial
  result.
- The plugin a stored response belongs to is the one the server recorded at dispatch
  (`command_execution.plugin`), not the plugin named in an id echoed back by an agent.
- Failure text of a Forensics-tier plugin is reduced to a bounded token before it is copied into the
  derived sinks (execution records, the event outbox and stream, notifications, analytics events,
  webhook and offload payloads). This applies to text written after this change.
- A new built-in role `ForensicsAnalyst` carries the four read grants needed to read these rows.

## Deployment contract (the scope decision)

The project owner stated in a working session on 2026-10-24: "we're doing a hard cutover - an upgrade
path is not needed". That is recorded as a scope decision, not as an acceptance of any residual
risk, and no retrievable artefact exists for a spoken statement beyond the recorder's transcription
of it. The change is therefore declared for an initial deployment into a freshly provisioned
database only: no data imported from earlier builds, every server writer and serving replica on this
build, earlier binaries excluded from the database, recovery by rolling forward or restoring this
build's own backups into a fresh deployment. The executable does not enforce this (it does not
verify the provenance of the database it opens), so it is a procedural control. A boot guard that
would enforce it is a P1 follow-up that is not in this change and is not yet filed.

## Claim withdrawn from the declared impact

The envelope the findings were first raised against carried this claim: stored data written by
earlier builds is protected when read. It is WITHDRAWN. This change declares nothing about what an
earlier build stored, or about a database that holds such data, and it describes no upgrade path.
Failure text copied into tracker rows past the 24 hour correlation window, notification rows,
analytics events and webhook and offload payloads before the reduction existed is outside the
declared scope; payloads already delivered to external sinks cannot be recalled by the server.

The withdrawn claim was removed from, and the contract is stated in:

- `docs/user-manual/upgrading.md` ("Deployment contract (hard cutover)" and the Known limits that
  follow it);
- `docs/authz-model.md` section 4;
- `docs/executions-history-ladder.md`;
- `docs/enterprise-readiness-soc2-first-customer.md` (the inventory);
- clause 8 of the Forensics-tier row of `.claude/routed-concerns-software-estate.md`;
- the changelog fragments `changelog.d/4990-forensics-response-tier.security.md` and
  `changelog.d/4990-forensics-analyst-role.added.md`.

## Declared security impact

- Closes the read tier for the paths listed above (I1 in the findings' vocabulary).
- Introduces no new unauthenticated surface and no new credential or network call.
- Not claimed: protection of data written by earlier builds; any statement that an owner accepted a
  retained-copy exposure; any statement that the contract is enforced by the executable; per-device
  or management-group scoped Forensics reads (there is no scoped tier).
- For a deployment OUTSIDE the contract the retained-copy exposure is recorded at its derived band
  (HIGH, BLOCKING) on the finding `g8p2-comp-1b-residual` and its siblings, with the disposition
  `re-cut`; that band is not lowered by the scope decision.
