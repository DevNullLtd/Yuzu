---
status: proposed
date: 2026-10-06
owner: "@Doomgoose (Alex Young)"
deciders: >-
  @Doomgoose (author and product owner for this decision). Ratified by PR approval from the
  engineering colleagues under the dev-branch protection rule (at least one non-author
  approval).
effective: >-
  Binding on merge as the direction for every change to how agent capabilities are shipped,
  enabled and disabled. Nothing in the product changes on merge: the existing kill switch,
  capture-source flags and default-off seeds stay as they are until the work that replaces them
  lands, and that work is sequenced in a separate roadmap. The new defaults are not delivered
  ahead of enforcement on the endpoint, the deployment-time choice and carry-over (D2).
scope: >-
  agent and server — what an installation contains, the default state of every plugin, action,
  capture source and other unit that runs by itself, and how a customer switches them off for an
  operating system or for a targeted set of endpoints
builds-on: >-
  ADR-3005 (plugin configuration plane and kill switch), ADR-0016 (agent daily-sync framework),
  ADR-0021 (Spark), the Guardian rule distribution design, the scope language
amends: >-
  ADR-3005 (the kill switch becomes one layer of this model). Supersedes the default-state parts
  of ADR-0015 Amendment 1 and of ADR-0020 (which capture sources ship off). Amends ADR-0016
  (the start-up flag stops being the collection toggle) and ADR-0021 Decision 11 with the Spark
  rollback ruling (the start-up flag stops being the only rollback lever). Departs from the
  2026-09-04 ruling that a default-on change applies at upgrade.
related: ["3005-plugin-config-store", "0015-tar-arp-dns-capture-sources", "0020-tar-netqual-windows-retrospective", "0016-agent-daily-sync-framework", "0021-spark-reflex-architecture"]
context-refs: ["#5294", "#5355", "#5371", "#5372", "#5373", "#5374", "#5375", "#4867", "#4915", "#4975", "#5057", "docs/yuzu-guardian-design-v1.1.md", "docs/asset-tagging-guide.md", "docs/tar-implementer.md"]
---

# 3006 — Capability enablement: what ships, and how it is switched off

## Summary

This ADR sets a direction. It is not current behaviour: nothing described here is in the product
until the retrofit it calls for lands (see `effective` above, and D2).

Yuzu will ship with everything in the box and everything switched on. Every plugin will be
installed on every endpoint, and every capture source and every other unit that runs by itself
will be running, unless the customer says otherwise. What a customer switches off is their
choice, and they can make it at three moments: when they deploy the server, when they install an
agent, and at any time afterwards on a live fleet.

Switching off is granular. A customer can switch off a whole plugin, one action, one capture
source or any other unit; for the whole fleet, for one operating system, or for any set of
endpoints they can describe (by hostname, address, tag, installed application, and whatever
else is added later). The rules that do this only ever switch things off, and if any rule says
off, it is off.

On an agent that enforces state, "off" means the endpoint does not do the work: the server
decides what is off for each endpoint and the agent enforces it, including while offline.

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
3. **Defaults are inconsistent.** Three plugins that read forensic data are seeded off
   on every server. Eight of the recorder's sixteen capture sources ship off (ADR-0015, ADR-0020)
   and eight ship on, three of them by a ruling on 2026-09-04 that pointed towards default-on.
   One Forensics-class plugin already ships on. A customer cannot learn the rule, because there
   is not one.
4. **"What ships" differs by platform.** Linux, macOS and container packages install every
   plugin. The Windows installer offers a reduced set and, by oversight, omits several plugins
   altogether (#4867). The server treats a missing plugin as a fault rather than a choice.

#5355 delivered the per-operating-system kill switch explicitly as a mechanism with no policy
behind it. Its follow-up issues (#5371, #5373, #5374 and #4975) describe the cost of that: a hard
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
- **Enablement catalogue** — the single list of units, what contains what, and what requires what.
- **Shipped default** — the state a unit has when nobody has made a choice. It is on.
- **Off-rule** — a customer's statement that named units are off for the endpoints a selector
  matches. There is no on-rule.
- **Provenance** — where an off-rule came from: written by an operator, carried over from an
  earlier release, or carried from an install.
- **Selector** — an expression in the scope language that picks endpoints.
- **Attribute provider** — a registered source of one kind of fact about an endpoint that a
  selector can test, together with how fresh that fact is.
- **Undetermined** — a selector cannot be evaluated for an endpoint because a fact it needs is
  not known yet.
- **Starting state** — what an agent treats as off from its first second, given to it at
  install or enrolment as a named preset or a list; for an agent upgraded from before this
  model, its existing flags.
- **Desired state** — the set of units the server has resolved as off for one endpoint, with a
  version.
- **Effective state** — what the agent is actually enforcing, with the version it reports.
- **Pending** — the server's desired state is newer than the agent's effective state.
- **Not installed** — the unit's code is not on the endpoint. Different from off.
- **Not applicable** — the unit does not exist for that operating system.
- **Awaiting decision** — a unit that arrived in a release and is held off until the customer
  decides. It is held by the additions setting, not by an off-rule.
- **Additions setting** — the one fleet-level setting that says whether a unit added by a
  release arrives on or awaiting decision (D10).
- **Protective state** — a state that an action has put an endpoint into so that it stays
  contained or protected until the state is lifted, such as the network containment of a device.
- **Control channel** — what the model itself rides on: registration, delivery of state,
  delivery of updates, and signature verification. It is not a unit.
- **Failed to load** — a plugin's code is on the endpoint and the agent refused to load it.
- **Enforced at the server only** — the agent is too old to enforce state. The server's check
  at dispatch applies, and the agent may still do work on its own.
- **State lost** — an agent that has held state cannot read it (D14).
- **Control plane unavailable** — the server cannot read its own enablement state (D14).
- **Switching on** — any change after which some endpoint does more than before: removing or
  narrowing an off-rule, or accepting a unit that was awaiting decision.
- **Purge** — deleting what a unit already stored on the endpoint.

## Decision

### D1 — Everything ships

Every installer, on every operating system, contains every plugin and installs all of them unless
told otherwise. A customer may deliberately leave plugins out at install. The server shows a
left-out plugin as *not installed*, which is a state in its own right and is never confused with
*off* or with a fault, and an upgrade respects the omission. A plugin an installation was never
offered, such as the plugins the Windows installer omits today, arrives under D10 as an addition.
A plugin whose code is present but which the agent refuses to load is *failed to load*, not *not
installed*. Removing a plugin from the product has a defined retirement step on every platform,
so that an old copy is not left behind and loaded.

*Rejected:* delivering plugins to endpoints on demand when something targets them. It makes the
endpoint's contents depend on server state at a moment in time, and it removes the customer's
ability to review, before deployment, exactly what will be on the machine.

### D2 — Everything is on by default

When nobody has made a choice, every unit is on: every plugin and action is available, and
every capture source and other unit that runs by itself is running. This applies equally to the
units that ship off today.

"On" means available or collecting. It does not mean ungated. The checks made when an operator
runs an action — permission, approval where an action requires it, the single-endpoint rule for
forensic reads, and audit — are untouched by this ADR. Enablement is not an access control and
must never be argued as one.

The new defaults are delivered only together with what makes them safe: enforcement on the
endpoint (D6, D7), the choice at deployment (D8) and carry-over for existing installations
(D9). No release ships a default of on ahead of any of them.

*Rejected:* keeping some categories off inside an otherwise-on product. It is a defensible
position, but it leaves the customer to discover which things are in which category, and it is
not the product direction. The risks it would have reduced are addressed instead by D8, D9 and
D10.

### D3 — One enablement catalogue of switchable units

Plugins, their actions, capture sources, look-backs, daily-sync sources, DEX signals and the
Spark engine are all units in one enablement catalogue, governed by one kind of rule, recorded in
one audit trail and visible in one place. The catalogue records containment (a plugin contains its
actions) and requirements (one unit needs another).

- Switching off a container switches off what it contains.
- A unit whose requirement is off is itself off, and says so ("requires X").
- Work the agent starts by itself obeys the same state as work an operator requests. There is
  no internal route around an off unit.
- A unit that an operating system cannot support is *not applicable* there. It is absent from
  that operating system's view, not shown as off.
- Reading history from before a source was switched on is a unit of its own (a *look-back*),
  on by default like everything else and switched off in the same way. It applies to a source's
  first baseline on an endpoint (D7), and this ADR does not change how far back it reads.
- A rule cannot switch off a unit that supplies a fact its own selector reads. Otherwise the
  rule could never be released.
- Off stops new protective action. Lifting, inspecting or repairing a protective state that is
  already in force — releasing a contained device is the case that matters — is never a unit,
  and neither is the control channel. An off-rule that would stop a protective state being
  re-applied is shown in the preview (D11), and the endpoint reports why.
- Retention and purge of what a unit stored are not work of that unit. They carry on when the
  unit is off or not installed (D7).

The existing start-up flags (inventory, DEX, Spark) become one-time starting-state inputs, and so
do the capture flags each agent already holds (D9). They seed the endpoint's starting state, the
server adopts them as off-rules with their own provenance (D8), and from then on they are not an
independent veto: removing the off-rule switches the unit on, and a flag still present at restart
supplies only the starting state of an agent that has never received state (D14).

*Rejected:* leaving each mechanism its own switch, which is today's arrangement and the reason
nobody can answer what an endpoint is collecting; and making every capability switchable without
exception, since a switch-off that strands a contained device, or removes the channel that would
carry the switch back on, defeats its own purpose.

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

The language is extended by registering attribute providers. Address and subnet and installed
application are the first additions, and management-group membership becomes an attribute a
selector can combine with the others; anything later is another provider, never a new kind of
rule. Each provider states how fresh its fact is, and that freshness is shown wherever a rule
depends on it.

A selector is undetermined for an endpoint only when the facts that are known do not settle it.
A condition that is false settles an AND, a condition that is true settles an OR, and the
negation of an unknown is still unknown, whichever order the operands are written in. A rule
whose selector is undetermined is treated as matching: the unit is off, and the state is
reported as *undetermined* rather than as a decision.

A fact is unknown only until its provider has reported. A provider that has answered "none" —
no tag is set, no such application is installed — has answered. A fact that was known and has
gone stale keeps its last value, shown with its age. A provider that cannot be read is a fault
in the control plane (D13, D14), never "undetermined" and never "does not match".

*Rejected:* a fixed list of criteria (it cannot be extended without changing the product); a
separate selector language for enablement (two languages to learn and keep
consistent); treating an unknown fact as "does not match" (an endpoint would collect before
anyone could tell whether a rule covers it); and treating any unknown anywhere in a selector as
a match (a rule written for Windows would switch units off on every Linux endpoint until an
irrelevant fact arrived).

### D6 — The server decides, the agent enforces

The server resolves, for each endpoint, which units are off, and sends that to the agent as
versioned desired state — the same pattern Guardian rules already use, with one version per
endpoint rather than Guardian's single fleet-wide counter. The agent stores it, enforces it and
reports the version it is enforcing.

- A unit runs only where both the server and the agent say it is on.
- The agent's reported state is what the server records as enforced.
- While the agent is behind, the server shows the endpoint as *pending*, with its age.
- An agent too old to enforce is shown as *enforced at the server only*. It is never reported as
  off, because it may still be doing the work on its own.
- The check at dispatch stays, so an operator gets an immediate answer. The server neither asks
  for nor accepts data from a unit it has resolved as off, apart from the record that an action
  already running, or one that cannot be undone, completed under the earlier state (D7). For a
  daily-sync source the refusal is acknowledged and does not ask the agent for a full resend.
- Every server replica answers from the same durable desired state, never from its own memory,
  and the server reports itself not ready while it cannot read it.
- An agent that reconnects reports the version it holds, and one that already holds the current
  version is sent nothing. Full state is delivered at a pace the server sets and the agent
  jitters, and delivery cannot starve the read that dispatch depends on.

*Rejected:* agents evaluating the rules themselves. It handles facts only the endpoint knows and
reacts fastest, but it puts every rule on every endpoint, limits selectors to what an endpoint can
see, and leaves the server unable to say why something is off without asking. Also rejected: a
server-side check alone, which is today's kill switch and cannot stop anything the agent does by
itself.

### D7 — Off means the endpoint does not do the work

When a unit is switched off the agent stops doing it, at once, without a restart. The state
survives a restart and holds while the endpoint is offline. This describes an agent that can
enforce state; an older agent is covered by the server's check only (D6) and is reported that way.

Once the agent has adopted a state that switches a unit off, no new work for that unit starts.
Work already running is cancelled where it can be cancelled safely. Work that cannot be
cancelled finishes, and what it produces is discarded rather than stored. An action that cannot
be undone completes and is recorded as having run under the earlier state.

What the unit already stored on the endpoint stays readable and keeps expiring under its normal
retention period, so it is gone within one period with no further action. Retention is
housekeeping, not work of the unit: it carries on while the unit is off or not installed, and an
agent whose state is lost prunes nothing until it has state again. For a daily-sync source the
stored data is the central copy, which is kept and marked as not collected since the switch-off;
an off source is reported as off, never as stale or silent.

Deleting what was stored is a separate, explicit choice. It is not an enablement change: it is
the existing destructive action, with its own permission, targeting and confirmation (D11).

Switching a unit back on does not recover the time it was off. The one exception is a look-back
(D3) that is itself on. It reads history the operating system retained, for a source's first
baseline on an endpoint and for a source that already recovers a paused window that way (the
connection source does today). Re-enabling a source, or recovering from a lost position in a
log, otherwise resumes from the present and records the gap.

*Rejected:* a switch-off that only refuses new requests; purging automatically on every
switch-off (a mistaken or temporary switch-off would destroy history that cannot be recovered);
and today's behaviour, in which a disabled capture source stops expiring its data and keeps it
until someone purges each endpoint by hand.

### D8 — What is off can be chosen at deployment

A customer does not have to let the product run before restricting it. The choice is available
at two points:

- **When the server is deployed.** Off-rules can be in place before the first agent enrols, so
  every agent receives them at first contact.
- **When an agent is installed or enrolled.** The install can carry a starting state — a named
  preset or a list of units to keep off — which the agent enforces from its first second,
  before it has spoken to the server.

The two are one choice. The server can export its current off-rules as the starting state an
install or enrolment carries, so a customer decides once. An agent installed without a starting
state runs the shipped-on units until its first contact with the server, which is why a customer
who needs a unit never to run carries the starting state.

Every route by which an agent is installed or enrolled can carry a starting state; a route that
cannot is a defect against this ADR.

A starting state does not lapse at first contact. The server adopts it as an ordinary, visible
off-rule marked as carried from the install, and from then on the server is the single
authority; undoing it is an ordinary switch-on. Adoption happens once, at the agent's first
contact with a server that runs this model. The
adopted rule covers the endpoint that presented it, can only switch units off, is labelled as
asserted by the install, and never overrides an operator's rule; only an enrolment the server
itself issued can carry a rule for more than one endpoint. A restart never adopts it again, so
once the operator has removed the rule the unit stays on.

Switching things off on a live fleet remains available. It is the second way to do it, not the
only one.

*Rejected:* everything on with no input at install (a customer could only ever say "stopped
shortly after", never "did not run"); holding all collection back until first contact (not on
by default for an endpoint that cannot reach the server); and a permanent local override on the
endpoint (two authorities, and no central answer).

### D9 — An upgrade changes nothing that already exists

Upgrading an existing installation — to the release that introduces this model and to every
later one — does not change what any existing unit does on any existing endpoint. Whatever is
off at the moment of upgrade — because it shipped off, or because an operator turned it off —
stays off, as off-rules the customer owns and can see, marked as carried over. Whatever was on
stays on. New installations get the shipped default. A unit that a release adds, or whose
collection a release widens, is not a change to an existing unit; it is governed by D10.

Carry-over is of each endpoint's actual state, not of the shipped defaults. The server does not
hold the state of capture sources that operators have set on individual agents, so it is taken
from the agent itself: on its first run as an agent that enforces state, the agent's existing
flags are its starting state, and the server adopts them through the path D8 describes. Until an
endpoint has done so it is left exactly as it was, and the server shows how many endpoints have
not yet been carried over. An endpoint that is reimaged or enrolled again is a new installation
and gets the shipped default, unless its install carries a starting state or a rule selects it.
Enablement state written by a newer version is tolerated by an older one, and a server replica
still on the older version never dispatches on a view weaker than the one an agent holds. Going
back to the previous mechanism stays possible until carry-over has completed.

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

This is the one way an upgrade can start something, and only for a customer who has left the
setting on and been told what the release adds. The release that introduces this model is the
exception: no customer has yet been able to set the setting, so what it adds to an existing
installation arrives awaiting decision.

- Switching the setting from off to on never switches on a unit that is awaiting decision; each
  stays held until it is accepted.
- A widening is delivered as a new unit beneath the one it widens, so that it can be held and
  decided separately.
- State covers a stated catalogue. Once an agent holds state, it runs a unit it knows only if
  that state covers it, and holds any other until a state that covers it arrives, so a unit
  newer than the server that resolved the state is never on by omission. Before it holds any
  state, an agent runs the shipped defaults of its own catalogue, or its starting state.

*Rejected:* additions always on (every upgrade could widen collection with no customer
action); and plugins on but new capture sources off (two defaults to explain again).

### D11 — Suitably privileged accounts make the change, and every change is audited

Changing enablement is a permission of its own, held by administrators and by any other role
the customer grants it to. An account that holds it changes enablement directly, on or off.
Where the product's access control is not enabled, changing enablement needs an administrator,
as changing plugin configuration does today. Reading enablement state follows the product's
existing read gating.

Every change is audited, and an operator's change that cannot be audited is refused. The record
names the account and the surface it came through, the units, the selector and the number of
endpoints it resolved to, what changed from and to, when, the reason the operator gave, and what
the preview showed. Changes that no operator made — carry-over, adoption of an install's
starting state, additions, a change that follows an attribute (D12), lost state — are recorded
with the system as the actor and a link to the event that caused them. If one of those cannot be
audited, it resolves toward less collection and never silently toward more. The history of
rules, of attribute-driven changes and of the state version each endpoint adopted is kept at
least as long as the audit trail, so that "what was this endpoint set to collect on that date"
can be answered.

Before a change that switches something on, or that deletes stored data, is applied, the
operator is shown what will turn on or be deleted, and where, and the change applies the set
that was shown or is shown again. The preview also lists any protective state that an off-rule
would stop being re-applied (D3).

Deleting stored data is not an enablement change. It is the existing destructive action, with
its own permission, its own targeting rules and its own confirmation, and the enablement
permission neither grants nor replaces them.

There is no second-person approval in this model.

*Rejected:* two-person approval, whether mandatory or optional. It was considered and ruled out
by the product owner: a suitably privileged account should be able to do this. Also rejected:
letting an operator's change proceed while it cannot be audited (switching off while audit is
unavailable is an open question below).

### D12 — Change that comes from the endpoint is accepted and audited

Because rules select endpoints by their attributes, a unit can come on, or go off, without any
rule being edited: a tag is removed, an application is uninstalled, a machine moves subnet. This
is accepted as what targeting by attribute means. Each such change is audited with its cause
(D11): the endpoint, the unit, the attribute that changed, where that attribute came from (set
on the server, or reported by the endpoint itself) and the event behind it. The actor is the
system, never the author of the rule. Wherever a rule is written the product shows who is able
to change the attributes it depends on, and which of them the endpoint itself can influence.

*Rejected:* requiring the enablement permission to change any attribute a rule refers to (it
ties everyday tagging to enablement and cannot cover facts that change by themselves); and
holding such changes for review (a queue nobody could keep up with at fleet size).

### D13 — Every answer explains itself

For any unit on any endpoint the product can say what its state is, why, and which rules bear on
it. The reason comes from a closed list: on by default, off by rule, off because a requirement
is off, undetermined, not installed, failed to load, not applicable, awaiting decision.
Alongside the reason the answer carries any status that applies: pending, enforced at the server
only, state lost, control plane unavailable. Because off-rules combine, the answer lists every
matching rule with its provenance rather than naming a single deciding one. A fault in the
control plane is always reported as a fault and never as an operator's decision.

The same answers are available in aggregate: counts by reason, unit class and operating system,
and how many endpoints are pending and for how long, split by connected and offline. Everything
the product shows, lists, previews, explains or audits under this model is also available to an
authenticated external principal through the versioned REST API and MCP, as ADR-1005 requires;
the console is one consumer of that interface.

*Rejected:* reporting a single deciding rule (under D4 removing one matching rule may change
nothing); and letting each surface word a refusal its own way, which is how a switched-off
action came to read as "permission denied".

### D14 — Failure directions are fixed

- If the server cannot read its own enablement state, it refuses to dispatch any unit, pushes no
  partial state and says the control plane is unavailable. Recovering a protective state (D3)
  does not depend on that state and is not refused. The refusal is a retryable cause: it uses up
  no schedule, approval or retry budget, and data refused for that reason is retried later,
  neither dropped nor answered with a request for a full resend. An agent that holds no state
  and reaches the server in this condition is told so and runs no switchable unit until it has
  state.
- If an agent cannot reach the server, it keeps enforcing the last state it had.
- An agent that has received state from the server has held state. It records that fact with its
  enrolment, and the server records it too, so that the fact survives anything that happens to
  the agent's state files. It keeps a second durable copy of the last state it adopted. If it
  cannot read either copy, whether they are damaged or missing, it does not fall back to
  everything on: it runs no switchable unit until it has the full state from the server again,
  reports that its state was lost, and asks for it. Only an agent that has never received state
  uses its starting state, which for an agent upgraded from before this model is its existing
  flags (D9).
- A server whose enablement state is behind what its agents report — restored from an older
  backup, or rebuilt empty while enrolled agents hold newer state — switches nothing on, says
  that the store has regressed, and waits for an operator's decision. It never pushes a weaker
  view over a stronger one. The enablement state is part of what the server backs up.

An endpoint that stays offline for a long time therefore keeps doing what was last on, and a
switch-off made in the meantime does not reach it until it reconnects. This is accepted and
shown, not hidden. Lost state is the opposite case and is deliberately handled the other way:
an endpoint that has lost its record of what the customer switched off prefers doing too little
to doing what the customer switched off.

*Rejected:* failing open on the server; falling back to the starting state on lost state (an
install without one would turn back on everything the customer had switched off); treating a
restored store as authoritative (a restore would switch on everything the customer had since
switched off); and having an agent switch everything off when its state merely grows old (it
turns an outage of the control plane into an outage of the product).

### D15 — Cost follows change, not fleet size

Resolving enablement is work done when a rule, an attribute or an enrolment changes. A fleet
with no rules does no enablement work. No fleet size may cause enablement to refuse or fail:
the present per-operating-system layer refuses above a fixed number of endpoints (#5371), the
scope evaluator's presence read has the same kind of limit and is not reused as it stands, and
that class of limit does not carry forward.

Change-driven resolution runs as a paced, resumable background job with visible progress, never
inside an operator's request. An endpoint is pushed and audited only when its resolved set
actually changes, and rapid repeated changes to one endpoint are coalesced. The preview in D11
is not a synchronous, capped read of the fleet.

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
- **Authored content.** Guardian rules and the per-definition and per-schedule enabled flags are
  authored policy, not shipped capabilities. They keep their own switches.
- **Schemas, protocol, user interface and delivery order.** These belong to the roadmap.

## Consequences

### What changes for customers

- A new installation will do more out of the box than it does today. The release that delivers
  this must say so plainly, and must deliver it together with what D2 requires, not before it.
- An existing installation will do exactly what it did before, and will gain a visible list of
  what it has switched off and why.
- "Off" will be true on the endpoint, on every agent that enforces state.
- One console view and one API will answer what an endpoint is doing.

### What changes in the product

The following existing behaviour is replaced or brought into line. The list is the starting
point for the roadmap, which decides order and grouping.

- The three plugins seeded off at server start, the tests and documents that pin that state,
  and the invariants that cite "default-off" as a safeguard.
- Every document, definition and statement that describes a source as opt-in, off by default or
  a deploy-time opt-out: the TAR implementer guide and dashboard (including the
  retention-paused frame, which this ADR retires), the user-manual pages, the TAR definition,
  plugin READMEs and their generated documentation, the OS capability matrix, the daily-sync and
  Spark design notes and rulings, and the SOC 2 data inventory.
- The eight capture sources that ship off, the seven-day look-back default, and the way the
  connection source recovers a paused window.
- Capture-source flags held only on each agent, changed only by instruction.
- The freeze on expiry when a capture source is disabled.
- The three all-or-nothing agent start-up flags.
- The agent's engines (Spark and the activity recorder): a runtime way to arm and disarm them
  that does not use the engine's sticky stop, and the amended rulings for their start-up flags
  (ADR-0016, ADR-0021).
- The Windows installer's fixed set of plugins and its missing plugins (custom and minimal
  installs stay a supported choice, D1); plugin retirement on every platform.
- The scope language: new attributes for address and installed application; a registry of
  attribute providers that reports whether a fact is known and how fresh it is; a defined
  result when a fact is unknown (D5); group membership as an attribute that combines with the
  others and stays current; and a resolver that works per endpoint, over every enrolled
  endpoint, as changes occur. Today's evaluator is a fleet scan that drops offline endpoints and
  gives up above a fixed number of presence rows.
- The server's knowledge of which plugins an agent holds, which is kept in memory per server
  today.
- The kill switch's known defects: the fleet-size ceiling, no way to list what is off,
  refusals that read as something else, and a degraded store that reads as a decision.
- The enablement catalogue, published with what each unit collects, its default and its
  retention, and the operator upgrade guide and release notes that state what changes.

### Risks of shipping everything on, and what answers each

| Risk | Answer |
|---|---|
| Collection starts at install, before the customer has decided what they want running | D8: the choice is available at server deployment and at agent install |
| An upgrade begins collection on existing endpoints | D9: an upgrade changes nothing that already exists; D10: new units follow the customer's setting and are stated |
| A later release quietly adds collection | D10: the customer's setting decides, and each release states what it adds |
| A source that is on reads history from before it was switched on | D3: look-back is its own unit and can be off from the start |
| A switch-off that is not real | D6 and D7: enforced on the endpoint as soon as the agent adopts the state |
| A switch-off strands a protected device, or removes the means to switch back on | D3: recovering a protective state and the control channel are never units |
| A restored or lost state turns back on what the customer had switched off | D14: a regressed store switches nothing on; an agent that has lost state runs nothing until it is resynchronised |
| Nobody can show what an endpoint collects and why | D13 and the enablement catalogue |

The safeguards that the three forensic plugins rely on today were written with "off by
default" as one of them. Before those plugins come on for new installations, each such
argument must be made again on the safeguards that remain — permission, approval, the
single-endpoint rule, audit and bounded reads — in the same change that amends the invariants
and READMEs which cite "default-off", and that change is reviewed for security. The same applies
to the capture sources that ship off today and can be read through the query actions, which
carry neither an approval nor a single-endpoint rule. A known unbounded read in one of the three
plugins (#5057) is closed first.

### Accepted residuals

- An endpoint that is offline keeps doing what was last on.
- A host-state fact such as an installed application is only as fresh as its provider, so a
  rule that depends on it takes effect after that provider next reports.
- An endpoint whose facts are not yet known has the affected units off until they are.
- A local administrator can stop the agent collecting; that is detected, not prevented.
- An agent whose state is lost while it cannot reach the server stays quiet until it reconnects.
- An agent too old to enforce state keeps doing its own work after a switch-off; it is shown as
  enforced at the server only.
- An agent installed without a starting state runs the shipped-on units until it first contacts
  the server.
- Switching a unit off starts the expiry of what it stored, whoever or whatever caused the
  switch-off, including a change that follows an attribute and an undetermined selector. There
  is no hold: where evidence must be kept, it is exported or protected before the switch-off.
- While audit is unavailable no operator can change enablement, in either direction.
- Delegated administration by management group is not yet possible (see the open questions).
- Until the retrofit completes, old and new mechanisms coexist. The roadmap must keep the
  period in which both exist short and must not ship the new defaults ahead of the controls D2
  names.

## Verification

The decision is being followed when all of the following are true.

1. On a fresh installation with no customer choices, every unit applicable to the endpoint's
   operating system is on, and the product can list them.
2. On an agent that enforces state, a unit switched off for an endpoint does no work there: no
   rows are stored, no action runs, and work the agent starts by itself stops too. This holds
   across an agent restart, while the endpoint is offline, and when the agent's stored state is
   lost (it then runs nothing until resynchronised). Work already running when the switch-off
   arrives produces nothing that is stored, except the record that an action which could not be
   undone completed.
3. An agent installed with a starting state does not run the units it names, including before
   its first contact with the server, until the customer switches them on.
4. Off-rules set on the server before any agent enrols are in force on each agent from its
   first contact; an agent installed with the matching starting state is covered from its
   first second.
5. Upgrading an existing installation changes what no existing unit does on any endpoint; a
   unit added by the release, or whose collection the release widens, arrives in the state the
   additions setting says (awaiting decision, in the release that introduces the model).
6. For any unit on any endpoint, the product gives a state, a reason from the closed list and
   every matching rule. A fault in the control plane is never reported as a decision.
7. Two rules that disagree always resolve to off, in any order.
8. A new kind of selector can be added by registering an attribute provider, with no change to
   the rules.
9. Every change to enablement appears in the audit trail with the account and surface, the
   units, the selector and the number of endpoints, what changed, the reason and the preview; an
   operator's change that cannot be audited does not happen, and one that no operator made and
   that cannot be audited resolves toward less collection.
10. Enablement behaves the same at any fleet size.
11. A plugin left out at install stays out across upgrades and is shown as not installed.
12. After a source is switched off its stored rows keep expiring under normal retention, and
    deleting them is a separate, audited act.
13. With the additions setting off, a unit added by a release is listed as awaiting decision and
    does not run.
14. An account holding the enablement permission changes enablement directly, on or off, with no
    second approver.
15. A unit that comes on or goes off because an endpoint's attribute changed is audited with
    the endpoint, the unit, the attribute and where the attribute came from.
16. A device in a protective state can always be released, whatever the enablement state says,
    and the control channel is never off.
17. An agent that has held state and whose stored state is missing behaves as an agent that has
    lost state. A server whose store is behind what its agents report switches nothing on and
    says so.
18. Deleting stored data uses the existing destructive action's permission, targeting and
    confirmation; the enablement permission confers none of them.
19. A selector that the known facts settle is never undetermined, in any operand order, and one
    they do not settle matches and leaves the unit off.
20. The new defaults are not delivered ahead of enforcement on the endpoint, the deployment-time
    choice and carry-over.
21. The history of rules, attribute-driven changes and adopted state versions is kept at least
    as long as the audit trail.

## Open questions

- Whether collection switches scoped to a management group, set by operators confined to that
  group, should follow, and how they would combine with fleet-level rules.
- Whether an operator may switch a unit off while audit is unavailable, with the record made
  when audit recovers.
- Which presets ship for the starting state, and what each contains.
- Whether plugin signature enforcement (#4915) should become a precondition for a plugin being
  on.
