# Contributing to the DEX guide

This guide is a wiki-style set of pages under `docs/dex/`. Anyone who ships or
changes a DEX (Digital Employee Experience) capability should add or update a
page in the same change. This page says where things go and what the rules are.

[Back to the hub](README.md)

## Where things go

- **A new area** gets a new file in `docs/dex/`, named in lower case with
  hyphens, for example `device-health.md`.
- **One row in the hub.** Add the page to the table in [the hub](README.md#pages)
  in the same change. The table is append-only: add rows, do not reorder them.
- **Map rows.** Add a row for every new REST route and MCP tool to
  [the capability map](surfaces.md#the-capability-map), under the heading
  that fits, and keep the row in step when a route or tool is renamed or
  removed. No automated check does this for you, so do it by hand.
- **Collectors.** If a new collector or plugin feeds the area, add a section to
  [collectors and plugins](collectors-and-plugins.md) and link it from your page.
- **Detail stays in the references.** Link to
  [DEX in the user manual](../user-manual/dex.md), the
  [REST reference](../user-manual/rest-api.md#dex-digital-employee-experience) and
  the [MCP guide](../user-manual/mcp.md) for full tables and shapes.

## Page template

Copy this skeleton. A section with nothing shipped says so in one line, for
example "There is no MCP tool", instead of being left out.

```markdown
# <Area name>: <one-line purpose>

DEX (Digital Employee Experience) <what this area is, in a sentence>.

[Back to the hub](README.md) | [Surface map](surfaces.md)

## What it is
## Why it is useful
## What feeds it and how to enable it
## Using it in the dashboard
## REST
## MCP
## Permissions and audit
## Limits and privacy
## Platform coverage
## Related pages
```

## Rules

1. **Shipped behaviour only, verified in code.** State what the code does today.
   Read the handler, the permission check and the plugin source before you write
   a permission, an audit verb, a default or a platform claim. Where existing
   documentation and the code disagree, the code wins, and the disagreement is
   worth a fix or an issue.
2. **Spell out the term.** Write "DEX (Digital Employee Experience)" at first use
   on every page.
3. **Link, do not copy.** Do not copy tables from the user manual, the REST
   reference or the signal catalogue. Describe the shape in a sentence and link.
4. **No counts.** Do not write how many signals, routes, tools or families there
   are. They go stale. Link the registry or table instead.
5. **Plain English.** Short sentences, bullets, no marketing language.
6. **Examples are placeholders.** Use `yuzu.example.com` and made-up identifiers.
   No real host names, addresses, user names or paths from a machine.
7. **No personal data and no vendor or competitor names.**
8. **Area pages say only what exists.** Do not describe unshipped work on an
   area page or in the capability map, and give no dates. If something is not
   available, say it is not available. Planned work, if a team wants to record
   it, goes on its own page that is clearly marked as planned and linked from
   the hub.
9. **Name the off switch exactly.** Anything about turning collection off must say
   what stops and what keeps running. See
   [collectors and plugins](collectors-and-plugins.md#what---dex-disable-stops).

## Checks to run before you push

From the repository root:

```bash
python3 -I scripts/ci/check-docs-drift.py
python3 -I scripts/ci/check-personal-data.py --strict-baseline --ratchet
python3 -I tests/test_gateway_peer_restart_advice_lint.py
python3 -I tests/test_legacy_quarantine_plugin_removed_lexical.py
python3 tests/test_issue_docs.py
python3 scripts/assemble-changelog.py --check
```

The two lexical tests scan every Markdown page under `docs/`, so they cover this
guide as well.

The personal-data check reads committed content, so run it after you commit.
If your change touches DEX code, also run
`python3 -I scripts/ci/check-docs-drift.py --touch <base> HEAD`, which lists the
documentation the change must update. Its `dex` rule names
`docs/user-manual/dex.md`, `docs/dex-signal-catalog.md` and
`docs/user-manual/rest-api.md`, not `docs/dex/`, so a change that updates only
this guide does not satisfy it. Update one of those pages as well, or put a
`doc-coupling-exempt: dex — <why the docs are still accurate>` line in the pull
request body.
