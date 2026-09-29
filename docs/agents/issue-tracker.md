# Issue Tracker

Issues and PRDs for this repo live in GitHub Issues at `github.com/Tr3kkR/Yuzu`.

Use GitHub tooling from inside the clone so the repository is inferred from `origin`.

**All filing, labelling, and closing is governed by [`issue-standard.md`](issue-standard.md)** —
duplicate search before filing is mandatory, bodies carry four sections, and automation never
closes `security`-labelled or `do-not-close` issues. This file is the command crib only.

## Common Operations

- Create: `gh issue create --repo Tr3kkR/Yuzu --title "..." --body-file <draft>.md --label <type> --label <P0|P1|P2> --label <triage-state>`
- Read: `gh issue view <number> --repo Tr3kkR/Yuzu --comments`
- List: `gh issue list --repo Tr3kkR/Yuzu --state open --json number,title,body,labels,comments`
- Comment: `gh issue comment <number> --repo Tr3kkR/Yuzu --body "..."`
- Label: `gh issue edit <number> --repo Tr3kkR/Yuzu --add-label "..."`
- Close (needs evidence per the standard): `gh issue close <number> --repo Tr3kkR/Yuzu --reason completed --comment "Fixed by #<PR> (<merge-sha>): <one line>"`
- Close as not planned: `gh issue close <number> --repo Tr3kkR/Yuzu --reason "not planned" --comment "<wontfix|obsolete|duplicate of #N|below-standard>: <why>"`

## Duplicate-search probes (run before every create)

```bash
gh issue list --repo Tr3kkR/Yuzu --state open --search "<file-or-symbol>" --json number,title
gh search issues --repo Tr3kkR/Yuzu --state open "<two or three keywords>" --json number,title --limit 20
```

## Canonical queries

- Active backlog: `gh issue list --repo Tr3kkR/Yuzu --state open --search "-label:roadmap" --limit 1000`
- Agent work queue: add `label:ready-for-agent` to the search string

When a skill says "publish to the issue tracker", create a GitHub issue in `Tr3kkR/Yuzu` per the
standard. When a skill says "fetch the relevant ticket", read the GitHub issue with comments and
labels.
