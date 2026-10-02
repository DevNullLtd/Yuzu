# changelog.d/ — changelog fragments

**Never edit `CHANGELOG.md` in a PR.** Unreleased changes are recorded here as
one small file per change, and assembled into `CHANGELOG.md` at release time.

Why: two PRs adding bullets to the same `[Unreleased]` section can never
auto-merge — the second one to land always conflicted, and the rebase push
voided the PR's approvals (the dev ruleset requires approval of the most
recent push). Fragments are uniquely-named **new** files, so they can never
conflict with each other. This directory exists to kill that friction.

## What your PR adds

Exactly one new file (more only if the change genuinely spans sections):

```
changelog.d/<PR-or-issue-number>-<short-slug>.<section>.md
```

- `<PR-or-issue-number>` — the PR number if you have it, else the issue
  number. Its only job is uniqueness, so a date works too if neither exists.
- `<short-slug>` — 2–5 words, kebab-case, describing the change.
- `<section>` — where the entry belongs in [Keep a
  Changelog](https://keepachangelog.com/en/1.1.0/) terms, one of:
  `added` | `changed` | `deprecated` | `removed` | `fixed` | `security`

**The file body is the finished changelog entry** — one or more markdown
bullets starting with `- `, written exactly as they should appear under
`### Added` (etc.) in `CHANGELOG.md`. Multi-line and multi-paragraph bullets
are fine; match the voice and detail level of existing `CHANGELOG.md` entries.
Do not put `##`/`###` headers in the file — the section comes from the
filename.

### Example

`changelog.d/1832-inventory-devices-tab.added.md`:

```markdown
- **`/inventory` Devices tab shows real device-CI data.** The Serial/Model/CPU-RAM
  columns (previously greyed placeholders) now read from `DeviceInventoryStore`, and
  the per-device drill grows a full CI-record panel.
```

## Rules

1. **Add** your own fragment; **never modify or delete** anyone else's — only
   the release promote removes fragments.
2. Never touch `CHANGELOG.md` itself. A committed Claude Code hook denies the
   edit, and the `Changelog fragments` CI job fails any PR whose diff changes
   the `[Unreleased]` section (the failure message explains how to fix it).
3. Not every PR needs a fragment — pure refactors, CI plumbing, and test-only
   changes with no operator-visible effect can skip it. If an operator or
   agent would notice the change, write one.
4. Lint locally before pushing: `python3 scripts/assemble-changelog.py --check`

## For AI coding agents

If you are an agent (Claude Code, etc.) preparing a change in this repo: when
your instructions, a reviewer, or a checklist says "update the changelog",
that means **create a fragment file here** using the naming scheme above. Do
not open or edit `CHANGELOG.md`. Write the bullet in the same style as
existing `CHANGELOG.md` entries: bolded lead phrase, then the operator-facing
substance, referencing issue/PR numbers like `(#1832)` where relevant.

## Converting a branch that already edited CHANGELOG.md

PRs opened before this convention (or agents that edited `CHANGELOG.md` out of
habit) convert with one short recipe, run from the repo root on the PR branch
(the checkout line brings the tooling onto pre-convention branches):

```bash
git fetch origin dev
git checkout origin/dev -- scripts/assemble-changelog.py changelog.d/README.md
python3 scripts/assemble-changelog.py --extract origin/dev --id <PR#>
```

It moves the bullets your branch added to `[Unreleased]` into correctly-named
fragment files and restores `CHANGELOG.md` to dev's version (so it can no
longer conflict). Review, then commit the new fragment(s) **together with**
the restored `CHANGELOG.md`, and push.

## Release time (operator / release skill only)

`python3 scripts/assemble-changelog.py promote X.Y.Z` merges any legacy
`[Unreleased]` content plus every fragment into a new `## [X.Y.Z] - <date>`
section, resets `[Unreleased]`, and deletes the fragment files; commit the
result. `scripts/release-preflight.sh` fails if unpromoted fragments remain
at tag time. The `/release` skill runs this as part of its pre-tag checklist.

### Fixes that land after a version was promoted

A version is promoted at its first release candidate, so a fix that lands on
`main` for a later candidate (a hotfix) leaves its fragment in `changelog.d/`,
and a plain `promote X.Y.Z` refuses because the section already exists. Write
the fragment as usual. Preflight check 4b fails any tag while fragments
remain, so before tagging each later candidate, and the final release, fold
them into the existing section:

    python3 scripts/assemble-changelog.py promote X.Y.Z --append                    # a later RC
    python3 scripts/assemble-changelog.py promote X.Y.Z --append --date YYYY-MM-DD  # the final

Each fragment's bullets are appended to the end of their `###` subsection in
`## [X.Y.Z]` (a missing subsection is created in canonical order), the
fragment files are deleted, and the header takes the given date (omit
`--date` to keep the existing one; pass it only at the final release).
Commit the result. It refuses if `[Unreleased]` still holds legacy
subsections, if there is nothing to append, if `X.Y.Z` is not the newest
released section (so a mistyped version cannot fold fragments into an older
release; `--allow-older-section` overrides), if more than one `## [X.Y.Z]`
header exists, or if a fragment's whole text already appears in the section
(an interrupted earlier append: compare it with the section before deleting
the fragment). Everything on `main` at tag time ships in `X.Y.Z`.
