---
status: proposed
date: 2026-10-06
owner: "@Doomgoose (Alex Young)"
deciders: >-
  @Doomgoose (author and product owner for this decision). Ratified by PR approval from the
  engineering colleagues under the dev-branch protection rule (at least one non-author approval).
effective: >-
  Binding on merge as the direction for every change to how agent capabilities are shipped,
  enabled and disabled. Nothing in the product changes on merge: the existing kill switch,
  capture-source flags and default-off seeds stay as they are until the work that replaces them
  lands, and that work is sequenced in a separate roadmap.
scope: >-
  agent and server — what an installation contains, the default state of every plugin, action,
  capture source and other agent-run collector, and how a customer switches them off for an
  operating system or for a targeted set of endpoints
builds-on: >-
  ADR-3005 (plugin configuration plane and kill switch), ADR-0016 (agent daily-sync framework),
  ADR-0021 (Spark), the Guardian rule distribution design, the scope language
amends: >-
  ADR-3005 (the kill switch becomes one layer of this model). Supersedes the default-state parts
  of ADR-0015 Amendment 1 and of ADR-0020 (which capture sources ship off). Departs from the
  2026-09-04 ruling that a default-on change applies at upgrade.
related: ["3005-plugin-config-store", "0015-tar-arp-dns-capture-sources", "0020-tar-netqual-windows-retrospective", "0016-agent-daily-sync-framework"]
context-refs: ["#5294", "#5355", "#5371", "#5372", "#5373", "#5374", "#5375", "#4867", "#4915", "#4975"]
---

# 3006 — Capability enablement: what ships, and how it is switched off

## Summary

Yuzu ships with everything in the box and everything switched on. Every plugin is installed on
every endpoint, and every capture source and collector is running, unless the customer says
otherwise. What a customer switches off is their choice, and they can make it at three moments:
when they deploy the server, when they install an agent, and at any time afterwards on a live
fleet.

Switching off is granular. A customer can switch off a whole plugin, one action, one capture
source or one collector; for the whole fleet, for one operating system, or for any set of
endpoints they can describe (by hostname, address, tag, installed application, and whatever
else is added later). The rules that do this only ever switch things off, and if any rule says
off, it is off.

"Off" means the endpoint does not do the work. The server decides what is off for each endpoint
and the agent enforces it, including while offline.

This ADR records the direction and the reasons. It does not contain a schema, a protocol or a
delivery plan; those belong to the roadmap that follows it.

## Context

### Where we are

The product has grown six separate ways to turn something on or off, each with its own reach,
permission and audit trail:

- **A server-side kill switch** (ADR-3005) keyed by plugin, action and, since #5355, operating
  system. It is checked when a command is dispatched. A missing entry means on. It has no way
  to target a group, a tag or any other subset of endpoints.
- **Per-agent capture-source flags** for the activity recorder (TAR). Each agent keeps its own
  flags, and the only way to change them is to send that agent an instruction.
- **Three agent start-up flags** that switch off, all-or-nothing, the daily inventory sync, the
  DEX signals and the Spark engine. They are set when the agent is deployed.
- **Guardian rules**, which carry their own enabled flag, operating-system target and scope.
- **Per-definition and per-schedule enabled flags** on the server.
- **Installer choices** on Windows only.

Four facts about this arrangement drive the decision.

1. **The kill switch does not stop the endpoint doing the work.** It stops the server sending a
   command. The agent has no idea that anything is off. Work the agent starts by itself — every
   capture source, the daily sync, the DEX signals — carries on regardless. The daily sync even
   calls plugins directly on the endpoint, which the kill switch cannot see.
2. **Capture-source settings have no desired state.** The server does not hold what each
   endpoint should be collecting. An instruction sent today does not reach an endpoint that is
   offline, or one that enrols tomorrow. Nothing reconciles.
3. **Defaults are inconsistent.** Three plugins that read per-user forensic data are seeded off
   on every server. Eight of the recorder's sixteen capture sources ship off (ADR-0015, ADR-0020)
   and eight ship on, three of them by a ruling on 2026-09-04 that pointed towards default-on.
   One Forensics-class plugin already ships on. A customer cannot learn the rule, because there
   is not one.
4. **"What ships" differs by platform.** Linux, macOS and container packages install every
   plugin. The Windows installer offers a reduced set and, by oversight, omits several plugins
   altogether (#4867). The server treats a missing plugin as a fault rather than a choice.

#5355 delivered the per-operating-system kill switch explicitly as a mechanism with no policy
behind it. Its follow-up issues (#5371 to #5375, #4975) describe the cost of that: a hard
ceiling on fleet size, no way to list what is switched off, a refusal that reads to the operator
as "permission denied" or "no agents", and a degraded store that looks like an operator's
decision.

### What the customer needs

- To know, before deploying, exactly what the product will do on an endpoint, and to be able to
  rule parts of it out before it ever runs.
- To switch a capability off for the endpoints it does not suit — a server estate, a country,
  the machines that run a fragile application — without redeploying.
- To be able to answer "what is this endpoint collecting, and why is that one thing off?" from
  one place.
- For "off" to be true on the endpoint, not only in the console.

### The position this ADR starts from

The product owner's direction, given on 2026-10-06, is that Yuzu ships with all plugins and all
capture sources on, that the customer can disable plugins and capture sources at a granular
level, that this includes the operating-system level and further levels such as hostname,
address, tag and installed application through a modular mechanism, and that the choice of what
is off must be available at deployment and not only on a live fleet. Departing from current
practice is accepted; existing behaviour is retrofitted to match.

## Terminology

- **Capability** — something the agent can do on an endpoint, on request or by itself.
- **Unit** — the smallest thing that can be switched: a plugin, an action of a plugin, a
  capture source, a look-back, a sync source, a signal, an engine.
- **Catalogue** — the single list of units, what contains what, and what requires what.
- **Shipped default** — the state a unit has when nobody has made a choice. It is on.
- **Off-rule** — a customer's statement that named units are off for the endpoints a selector
  matches. There is no on-rule.
- **Provenance** — where an off-rule came from: written by an operator, carried over from an
  earlier release, carried from an install, or awaiting a decision.
- **Selector** — an expression in the scope language that picks endpoints.
- **Attribute provider** — a registered source of one kind of fact about an endpoint that a
  selector can test, together with how fresh that fact is.
- **Undetermined** — a selector cannot be evaluated for an endpoint because a fact it needs is
  not known yet.
- **Starting state** — what an agent treats as off from its first second, given to it at
  install or enrolment as a named preset or a list.
- **Desired state** — the set of units the server has resolved as off for one endpoint, with a
  version.
- **Effective state** — what the agent is actually enforcing, with the version it reports.
- **Pending** — the server's desired state is newer than the agent's effective state.
- **Not installed** — the unit's code is not on the endpoint. Different from off.
- **Not applicable** — the unit does not exist for that operating system.
- **Awaiting decision** — a unit that arrived in a release and is held off until the customer
  decides.
- **Switching on** — any change after which some endpoint does more than before: removing or
  narrowing an off-rule, or accepting a unit that was awaiting decision.
- **Purge** — deleting what a unit already stored on the endpoint.

## Decision

### D1 — Everything ships

Every installer, on every operating system, installs every plugin. A customer may deliberately
leave plugins out at install. The server shows a left-out plugin as *not installed*, which is a
state in its own right and is never confused with *off* or with a fault, and an upgrade respects
the omission. Removing a plugin from the product has a defined retirement step on every
platform, so that an old copy is not left behind and loaded.

*Rejected:* delivering plugins to endpoints on demand when something targets them. It makes the endpoint's contents depend on server state at a moment in time, and it
removes the customer's ability to review, before deployment, exactly what will be on the
machine.

### D2 — Everything is on by default

When nobody has made a choice, every unit is on: every plugin and action is available, and
every capture source and collector is running. This applies equally to the units that ship off
today.

"On" means available or collecting. It does not mean ungated. The checks made when an operator
runs an action — permission, approval where an action requires it, the single-endpoint rule for
forensic reads, and audit — are untouched by this ADR. Enablement is not an access control and
must never be argued as one.

*Rejected:* keeping some categories off inside an otherwise-on product. It is a defensible
position, but it leaves the customer to discover which things are in which category, and it is
not the product direction. The risks it would have reduced are addressed instead by D8, D9 and
D10.

### D3 — One catalogue of switchable units

Plugins, their actions, capture sources, look-backs, daily-sync sources, DEX signals and the
Spark engine are all units in one catalogue, governed by one kind of rule, recorded in one audit
trail and visible in one place. The catalogue records containment (a plugin contains its
actions) and requirements (one unit needs another).

- Switching off a container switches off what it contains.
- A unit whose requirement is off is itself off, and says so ("requires X").
- Work the agent starts by itself obeys the same state as work an operator requests. There is
  no internal route around an off unit.
- A unit that an operating system cannot support is *not applicable* there. It is absent from
  that operating system's view, not shown as off.
- Reading history from before a source was switched on is a unit of its own (a *look-back*),
  on by default like everything else and switched off in the same way.

The existing start-up flags remain as a local shortcut and are reported as off-rules with their
own provenance, so that they are visible.

*Rejected:* leaving each mechanism its own switch. That is today's arrangement, and it is why
nobody can answer what an endpoint is collecting.

### D4 — Rules only switch off, and off wins

A rule names units and a selector, and its only effect is off. If any rule that matches an
endpoint says a unit is off, it is off, whatever other rules exist and in whatever order they
were written. An exception is written into the rule's own selector ("Linux, except the lab
machines"), never as a second rule that switches something back on.

*Rejected:* a fixed order of tiers in which the narrowest rule wins, and an ordered priority
list in which the first match decides. Both allow an exception to be a separate rule, and both
let a later or narrower rule quietly defeat a switch-off made higher up. Both also make the
answer depend on order, which is the usual source of "why is this still on?".

### D5 — Targeting is the scope language, extended by attribute providers

Endpoints are selected with the scope language the product already uses to target instructions
and policies. It is not a second language. Fleet-wide and per-operating-system rules are simply
the two most common selectors.

The language is extended by registering attribute providers. Address and subnet, installed
application and management-group membership are the first additions; anything later is another
provider, never a new kind of rule. Each provider states how fresh its fact is, and that
freshness is shown wherever a rule depends on it.

When a selector cannot be evaluated for an endpoint because a fact is not yet known, the rule
is treated as matching, the unit is off, and the state is reported as *undetermined* rather
than as a decision.

*Rejected:* a fixed list of criteria (it cannot be extended without changing the product); a
separate selector language for enablement (two languages to learn and keep
consistent); and treating an unknown fact as "does not match" (an endpoint would collect before
anyone could tell whether a rule covers it).

### D6 — The server decides, the agent enforces

The server resolves, for each endpoint, which units are off, and sends that to the agent as
versioned desired state — the same pattern Guardian rules already use. The agent stores it,
enforces it and reports the version it is enforcing.

- A unit runs only where both the server and the agent say it is on.
- The agent's reported state is the record of what actually ran.
- While the agent is behind, the server shows the endpoint as *pending*, with its age.
- An agent too old to enforce is shown as protected by the server-side check only.
- The check at dispatch stays, so an operator gets an immediate answer, and the server neither
  asks for nor accepts data from a unit it has resolved as off.

*Rejected:* agents evaluating the rules themselves. It handles facts only the endpoint knows and reacts fastest, but it puts every rule on every
endpoint, limits selectors to what an endpoint can see, and leaves the server unable to say why
something is off without asking. Also rejected: a server-side check alone, which is today's
kill switch and cannot stop anything the agent does by itself.

### D7 — Off means the endpoint does not do the work

When a unit is switched off the agent stops doing it, at once, without a restart. The state
survives a restart and holds while the endpoint is offline.

What the unit already stored on the endpoint stays readable and keeps expiring under its normal
retention period, so it is gone within one period with no further action. Deleting it
immediately is a separate, explicit choice. Switching a unit back on never fills in the time it
was off.

*Rejected:* a switch-off that only refuses new requests; purging automatically on every
switch-off (a mistaken or temporary switch-off would destroy history that cannot be recovered);
and today's behaviour, in which a disabled capture source stops expiring its data and keeps it
until someone purges each endpoint by hand.

### D8 — What is off can be chosen at deployment

A customer does not have to let the product run before restricting it. The choice is available
at two points before anything is collected:

- **When the server is deployed.** Off-rules can be in place before the first agent enrols, so
  every agent receives them at first contact.
- **When an agent is installed or enrolled.** The install can carry a starting state — a named
  preset or a list of units to keep off — which the agent enforces from its first second,
  before it has spoken to the server.

A starting state does not lapse at first contact. The server adopts it as an ordinary, visible
off-rule marked as carried from the install, and from then on the server is the single
authority; undoing it is an ordinary switch-on.

Switching things off on a live fleet remains available. It is the second way to do it, not the
only one.

*Rejected:* everything on with no input at install (a customer could only ever say "stopped
shortly after", never "did not run"); holding all collection back until first contact (not on
by default for an endpoint that cannot reach the server); and a permanent local override on the
endpoint (two authorities, and no central answer).

### D9 — An upgrade starts nothing and stops nothing

Upgrading to a release that follows this ADR does not change what any existing endpoint does.
Whatever is off at the moment of upgrade — because it shipped off, or because an operator
turned it off — stays off, as off-rules the customer owns and can see, marked as carried over.
Whatever was on stays on. New installations get the shipped default.

This departs from the 2026-09-04 ruling, under which a move to default-on applied at upgrade.
The reason is the same one behind D8: collection must not begin on a customer's endpoints
because of something we did.

*Rejected:* switching the shipped-off units on at upgrade; and holding the upgrade until an
administrator answers a prompt.

### D10 — New capabilities follow the customer's setting

When a later release adds a unit, it arrives in the state a single fleet-level setting says:
on, which is how the setting ships, or off. When it is off, additions are listed as *awaiting
decision* until the customer accepts or keeps them off. A release that materially widens what
an existing unit collects, or brings a unit to a new operating system, counts as an addition.
Every release states what it adds.

*Rejected:* additions always on (every upgrade could widen collection with no customer
action); and plugins on but new capture sources off (two defaults to explain again).

### D11 — Suitably privileged accounts make the change, and every change is audited

Changing enablement is a permission of its own. An account that holds it changes enablement
directly, on or off. Every change is audited, and a change that cannot be audited is refused.
Before a change that switches something on, or that purges stored data, is applied, the
operator is shown what will turn on or be deleted, and where.

There is no second-person approval in this model.

*Rejected:* two-person approval, whether mandatory or optional. It was considered and ruled out
by the product owner: a suitably privileged account should be able to do this.

### D12 — Change that comes from the endpoint is accepted and recorded

Because rules select endpoints by their attributes, a unit can come on without any rule being
edited: a tag is removed, an application is uninstalled, a machine moves subnet. This is
accepted as what targeting by attribute means. Each such change is recorded with the endpoint,
the unit and the attribute that changed, and wherever a rule is written the product shows who
is able to change the attributes it depends on.

*Rejected:* requiring the enablement permission to change any attribute a rule refers to (it
ties everyday tagging to enablement and cannot cover facts that change by themselves); and
holding such changes for review (a queue nobody could keep up with at fleet size).

### D13 — Every answer explains itself

For any unit on any endpoint the product can say what its state is, why, and which rules bear
on it. The reason comes from a closed list: on by default, off by rule, off because a
requirement is off, undetermined, pending, not installed, not applicable, awaiting decision,
control plane unavailable. Because off-rules combine, the answer lists every matching rule
with its provenance rather than naming a single deciding one. A fault in the control plane is
always reported as a fault and never as an operator's decision.

*Rejected:* reporting a single deciding rule (under D4 removing one matching rule may change
nothing); and letting each surface word a refusal its own way, which is how a switched-off
action came to read as "permission denied".

### D14 — Failure directions are fixed

- If the server cannot read its own enablement state, it refuses to dispatch, pushes no partial
  state and says the control plane is unavailable.
- If an agent cannot reach the server, it keeps enforcing the last state it had.
- If an agent cannot read its stored state, it falls back to its starting state and reports
  that its state was lost.

An endpoint that stays offline for a long time therefore keeps doing what was last on, and a
switch-off made in the meantime does not reach it until it reconnects. This is accepted and
shown, not hidden.

*Rejected:* failing open on the server; and having an agent switch everything off when its
state grows old (it turns an outage of the control plane into an outage of the product).

### D15 — Cost follows change, not fleet size

Resolving enablement is work done when a rule, an attribute or an enrolment changes. A fleet
with no rules does no enablement work. No fleet size may cause enablement to refuse or fail:
the present per-operating-system layer refuses above a fixed number of endpoints (#5371), and
that class of limit does not carry forward.

*Rejected:* evaluating rules afresh on every dispatch.

## Scope and non-goals

In scope: what an installation contains; the default state of every unit; switching units off
by fleet, operating system and selector; how that state reaches and is enforced on the
endpoint; who may change it and how it is recorded and explained.

Not in scope, and not changed by this ADR:

- **Who may read collected data.** That is access control. Enablement governs whether
  something is collected or available; access control governs who may read it; both must
  permit.
- **The checks made when an action is run** — permission, approval where an action requires
  it, the single-endpoint rule, audit.
- **Preventing a local administrator from interfering with the agent.** A difference between
  desired and effective state is detected and shown; it is not prevented.
- **Second-person approval of enablement changes** (ruled out in D11).
- **Signing the desired state separately from the channel that carries it**, and expiry of
  state held by an agent.
- **Schedules and time-limited rules**, and enablement per user rather than per endpoint.
- **Retention periods.**
- **Tuning a unit beyond on and off.**
- **Rules written by operators who are confined to a management group.** Enablement is a
  fleet-level permission in this ADR. Collection switches scoped to a management group remain
  an open item for a later decision.
- **Schemas, protocol, user interface and delivery order.** These belong to the roadmap.

## Consequences

### What changes for customers

- A new installation does more out of the box than it does today. The release that delivers
  this must say so plainly, and must be delivered together with the deployment-time choice in
  D8, not before it.
- An existing installation does exactly what it did before, and gains a visible list of what
  it has switched off and why.
- "Off" becomes true on the endpoint.
- One screen and one interface answer what an endpoint is doing.

### What changes in the product

The following existing behaviour is replaced or brought into line. The list is the starting
point for the roadmap, which decides order and grouping.

- The three plugins seeded off at server start, the tests and documents that pin that state,
  and the invariants that cite "default-off" as a safeguard.
- The eight capture sources that ship off, and the seven-day look-back default.
- Capture-source flags held only on each agent, changed only by instruction.
- The freeze on expiry when a capture source is disabled.
- The three all-or-nothing agent start-up flags.
- The Windows installer's reduced set and its missing plugins; plugin retirement on every
  platform.
- The scope language: new attributes for address and installed application, a defined result
  when a fact is unknown, and group membership that stays current.
- The server's knowledge of which plugins an agent holds, which is kept in memory per server
  today.
- The kill switch's known defects: the fleet-size ceiling, no way to list what is off,
  refusals that read as something else, and a degraded store that reads as a decision.
- The product's published list of units, which must state for each one what it collects, its
  default and its retention.

### Risks of shipping everything on, and what answers each

| Risk | Answer |
|---|---|
| Collection starts at install, before the customer has decided what they want running | D8: the choice is available at server deployment and at agent install |
| An upgrade begins collection on existing endpoints | D9: an upgrade starts nothing |
| A later release quietly adds collection | D10: the customer's setting decides, and each release states what it adds |
| A source that is on reads history from before it was switched on | D3: look-back is its own unit and can be off from the start |
| A switch-off that is not real | D6 and D7: enforced on the endpoint, immediately |
| Nobody can show what an endpoint collects and why | D13 and the published list of units |

The safeguards that the three forensic plugins rely on today were written with "off by
default" as one of them. Before those plugins come on for new installations, each such
argument must be made again on the safeguards that remain — permission, approval, the
single-endpoint rule, audit and bounded reads.

### Accepted residuals

- An endpoint that is offline keeps doing what was last on.
- A host-state fact such as an installed application is only as fresh as its provider, so a
  rule that depends on it takes effect after that provider next reports.
- An endpoint whose facts are not yet known has the affected units off until they are.
- A local administrator can stop the agent collecting; that is detected, not prevented.
- Until the retrofit completes, old and new mechanisms coexist. The roadmap must keep the
  period in which both exist short and must not ship the new defaults ahead of the new
  controls.

## Verification

The decision is being followed when all of the following are true.

1. On a fresh installation with no customer choices, every unit applicable to the endpoint's
   operating system is on, and the product can list them.
2. A unit switched off for an endpoint does no work there: no rows are stored, no action runs,
   and work the agent starts by itself stops too. This holds across an agent restart and while
   the endpoint is offline.
3. An agent installed with a starting state never runs the units it names, including before
   its first contact with the server.
4. Off-rules set on the server before any agent enrols are in force on each agent from its
   first contact.
5. Upgrading an existing installation changes what no endpoint does.
6. For any unit on any endpoint, the product gives a state, a reason from the closed list and
   every matching rule. A fault in the control plane is never reported as a decision.
7. Two rules that disagree always resolve to off, in any order.
8. A new kind of selector can be added by registering an attribute provider, with no change to
   the rules.
9. Every change to enablement appears in the audit trail, and a change that cannot be audited
   does not happen.
10. Enablement behaves the same at any fleet size the product supports.

## Open questions

- Whether collection switches scoped to a management group, set by operators confined to that
  group, should follow, and how they would combine with fleet-level rules.
- Which presets ship for the starting state, and what each contains.
- Whether plugin signature enforcement (#4915) should become a precondition for a plugin being
  on.
