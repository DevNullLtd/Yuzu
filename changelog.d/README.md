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

## Reading unreleased changes (following `dev`)

Fragments are only collated into `CHANGELOG.md` at release. To see what a
`git pull` of `dev` just brought, run this after the pull:

```bash
python3 scripts/whats-new.py                          # since your last pull
python3 scripts/whats-new.py --since v0.15.0          # since a tag, branch or commit
python3 scripts/whats-new.py --since "2 weeks ago"    # or YYYY-MM-DD
python3 scripts/whats-new.py --full                   # whole bullets, every dependency bump
python3 scripts/whats-new.py --versions               # version bumps, rebuild notes, Docker image bumps (see below)
```

On Windows, where `python3` is often not on `PATH`, use the launcher:
`py -3 scripts\whats-new.py`. The script uses only the standard library
(Python 3.9 or later, for `str.removeprefix`) and needs `git` on `PATH`.

The header counts the entries that start `**Breaking` (a `Breaking` line,
shown only when there are some), so you see them before reading further.
`--versions` prints that header, the version bumps, the rebuild / redeploy
notes and the Docker image bumps. It leaves out the changelog entries, and
shows the other dependency bumps only as a count (`--full` lists them under
their own heading). It is a quick look at what may need a rebuild, not a
proof that nothing does: the rebuild notes watch `vcpkg`, `proto/`,
`gateway/`, `sdk/` and the deploy files, and say nothing about `server/`,
`agents/` or `common/` source changes, which only the file counts in the
header show. Fragments the script could not read or list still get their
`!` line in `--versions` mode, because the `Breaking` count leaves them out.

It prints, in this order:

- **Version bumps:** the project version, the plugin ABI, the vcpkg baseline
  and dependency constraints (including per-feature ones), the gateway
  packages, and the latest released `CHANGELOG.md` version.
- **Rebuild / redeploy:** the surfaces the range touched that may need a
  rebuild (vcpkg, `proto/`, `gateway/`, `sdk/`, deploy and compose files).
- **Dependency bumps:** commits titled `build(deps):` or `chore(deps):`.
  Dockerfile and compose bumps are listed; the rest (workflows, pip, npm) are
  counted, and `--full` lists them.
- **Changelog entries:** the fragments this range adds, grouped security,
  removed, deprecated, changed, added, fixed. The heading counts them, and
  says how many are already released and how many are breaking. An entry a
  release inside the range moved into `CHANGELOG.md` ends `[released X.Y.Z]`
  when its first line sits under one `## [X.Y.Z]` heading at `HEAD`, and
  `[released]` when the version cannot be told (usually the release editorial
  pass reworded the line; also a line under two versions, or `CHANGELOG.md`
  gone). No marker means no release in the range moved the entry, the usual
  case for a pull of `dev`. Headings are read as `scripts/assemble-changelog.py`
  reads them, so a sample heading inside a code fence counts as one. The marker
  is a reading aid, not release evidence. Each shows its first line, cut at
  200 characters (a marker follows the cut). Security, removed and deprecated entries, and entries starting
  `**Breaking` (in any case), are shown whole, continuation lines included;
  other entries show their continuation lines only with `--full`. A fragment
  replaced, reworded or withdrawn inside the range is shown once in its final
  form, or not at all. A fragment that reached its path only through renames
  git saw as identical, from a path you already had, and still has those exact
  bytes is not new (a rename into `security`, `removed` or `deprecated` is a
  reclassification and is listed); one renamed and then edited is listed, and so
  is an identical fragment added in a different commit from the deletion of the
  old one. A fragment added after your base and since promoted by a release is
  shown, under its last path and section, when its first line is a line a commit
  in the range added to `CHANGELOG.md`, even if the line was edited by hand after
  the release; a name a release promoted twice in the range is shown each time
  (once, if the two texts are identical). A promoted entry shows the fragment's
  wording as it was promoted, not a later hand edit of the release text, so a
  note says so and `CHANGELOG.md` has the final text. A release that deletes a
  fragment and adds a similar one in the same commit still counts as promoting
  the first unless the new file keeps its first bullet.
  A path you had and edited is not listed, nor is its promotion. A path you had,
  that a release promoted and that was added back with different text, is
  listed; added back with identical text, it is not. A fragment you had, moved
  out of `changelog.d/` and back, is listed again only if its text changed.
  Fragments are read the way `promote` reads them (line endings normalised,
  outer whitespace dropped). A release finished by a merge commit (a release
  branch that merges `dev` and removes the fragments there) counts as promoting
  them, shown with the wording last committed before the merge; one the merge
  itself reworded, or one that was withdrawn, matches no `CHANGELOG.md` line and
  is named on a `!` line instead. A fragment file over 1 MiB is not read.
  A file added under `changelog.d/` whose name is not a fragment name (or that
  is in a subdirectory), a fragment name that is a submodule, and a fragment
  file over the size limit are each named on a `!` line (at most 20 names, then
  a count) and are not listed. Only the top-level `changelog.d/README.md` and
  `changelog.d/.gitkeep` are exempt. Releases rewrite `CHANGELOG.md` by hand
  too, so a bullet that never had a fragment does not appear; fragments began on
  2026-07-04, so a base before that cannot show entries written straight into
  `CHANGELOG.md`. A `!` line anywhere in the report means that part could not be
  read or compared; it is never "no change".

"Your last pull" is read from the reflog of the branch you are on: the newest
`git pull` that names no source or names that branch's upstream (or, when the
branch has no upstream, the branch itself; `dev:dev` counts as `dev`, `:x` does
not), or `git merge <upstream>` after a fetch (`git merge -s ours` and
`git pull -s ours` take none of the upstream and are not counted), and the
commit the branch was on before it. The `Via` line prints the reflog entry used. A pull on another branch is in that branch's reflog, and
`checkout`, a local `merge`, `reset`, `git pull <other branch>` and a merge of a
different branch (`origin/dev-hotfix` is not `origin/dev`) are not counted, so
none of them can move the base later. A pull the script does not recognise, such
as one that stopped on a conflict and was finished by hand, only makes the range
start earlier, at the pull before it: the range may then include changes you
already read. A fresh clone, a new branch, a detached `HEAD` or an expired
reflog has no pull to read, so pass `--since`. A `git pull` that finds nothing
new writes no reflog entry, so the range then still starts at the earlier pull
that did (the `Base` and `Via` lines show which). After `git pull --rebase` the
range starts at the common ancestor, so your own local commits, replayed by the
rebase, and any fragments they add are in it too.

`--since` with a date picks the first commit git finds that was made at or before that
moment, by commit date (history with skewed commit dates can make that an older or newer commit than
you meant), in local time. A bare `YYYY-MM-DD` means 00:00 that day;
`YYYY-MM-DD HH:MM[:SS]` (or with a `T`) is that moment; an absolute date must fall from 3 January
1970 to 31 December 2099 (git can read a moment on 1 January 1970 as "now" east of UTC, so earlier dates are refused);
`yesterday` and `N <unit> ago` count back from now (a day is 24 hours). `N` is one to four digits, the unit is lowercase
(`second`, `minute`, `hour`, `day`, `week`, `month`, `year`, singular or plural)
and a month or year is a calendar month or year. Anything else is refused,
because git would read a typo as "now".

The script only reads (in a partial clone, git itself may fetch objects the range
needs). Text from fragments and commit messages is printed with control characters
(newline and tab aside) and invisible format characters (zero-width joiners and non-joiners, variation
selectors, bidi marks) replaced by `?`, so an emoji sequence can show a `?`;
a fragment's continuation lines are indented. Changes that skipped a fragment (rule 3) do not
appear in the entries; `git log --first-parent --oneline <base>..HEAD` lists
every merged PR, with `<base>` the commit the `Base` line prints.

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
fragment files are deleted, and the header takes the given date (omit `--date`
to keep the existing one; pass it only at the final release). If an earlier RC
already folded every fragment, the final still needs its date: with no
fragments, `--append --date YYYY-MM-DD` re-dates the header and changes
nothing else. Commit the result. It refuses if `[Unreleased]` is missing or
still holds legacy subsections, if there is nothing to append (and no
`--date`), if `X.Y.Z` is not the newest released section (so a mistyped
version cannot fold fragments into an older release; `--allow-older-section`
overrides), if more than one `## [X.Y.Z]` header exists, or if a fragment's
whole text already appears in the section (an interrupted earlier append:
compare it with the section before deleting the fragment). Everything on
`main` at tag time ships in `X.Y.Z`.
