- **CI: the release/LTO legs run daily on `dev` instead of on every `dev` push.** A merge into `dev`
  now runs the debug legs only. The four release legs (Linux gcc-15 LTO, Linux clang-21, Windows MSVC
  LTO, macOS LTO) run on every push to `main` and from a daily dispatch of `ci.yml` on `dev`'s tip
  (`release-legs-daily.yml`). A failing dispatch opens a `release-legs-broken` issue
  (`release-legs-alert.yml`), and the release skill checks for one before tagging. Contributor-facing:
  `ci.yml` gains a `workflow_dispatch` trigger (`legs=release|all`), accepted on `dev` and `main` only;
  its required-check jobs are renamed (` [dispatch]`) or never skipped so a dispatch never posts a misleading
  required check. The cron and
  the alert go live once the files reach `main`. Details: `docs/ci-architecture.md`, Tier 2b.
