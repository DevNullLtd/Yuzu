#!/usr/bin/env python3
"""Changelog fragment tooling — lint, guard, and release-time assembly.

Yuzu records unreleased changes as one-file-per-change *fragments* under
``changelog.d/`` instead of editing CHANGELOG.md's ``[Unreleased]`` section
directly. Two PRs adding bullets at the same spot in CHANGELOG.md conflicted
every time, and the conflict-resolution push voided the PR's approvals
(`require_last_push_approval`). Fragments are uniquely-named new files, so
they can never conflict. Convention: changelog.d/README.md.

Modes:

  python3 scripts/assemble-changelog.py --check
      Lint every fragment in changelog.d/ (filename pattern, body format).
      Run by the `Changelog fragments` docs-lint CI job on every PR/push.

  python3 scripts/assemble-changelog.py --guard <base-sha>
      Fail if the working tree's CHANGELOG.md [Unreleased] *section content*
      (### subsections + bullets) differs from <base-sha>'s — unless the same
      range also deletes changelog.d/ fragments (that's the release promote).
      Preamble prose changes under [Unreleased] are allowed. CI-only mode; it
      assumes the working tree is the PR merge commit.

  python3 scripts/assemble-changelog.py promote <X.Y.Z> [--date YYYY-MM-DD]
      Release-time assembly: merge any legacy [Unreleased] subsections plus
      all fragments into a new `## [X.Y.Z] - <date>` section inserted after
      [Unreleased], reset [Unreleased] to its preamble, and DELETE the
      fragment files. Run by the /release skill before tagging; commit the
      result.

  python3 scripts/assemble-changelog.py promote <X.Y.Z> --append [--date YYYY-MM-DD] [--allow-older-section]
      For a fix that lands after <X.Y.Z> was already promoted (a release
      candidate hotfix): append every fragment's bullets to the EXISTING
      `## [X.Y.Z]` section, each at the end of its ### subsection (a missing
      subsection is created in canonical order), and DELETE the fragment
      files. Existing bullets and any non-canonical subsections are left as
      they are. The header date is kept unless --date is given; pass the
      final release date when folding fragments in before tagging the final.
      Refuses if [Unreleased] is missing or still holds legacy subsections (run a plain
      promote of the next version for those), if <X.Y.Z> is not the newest
      released section (override: --allow-older-section), if more than one
      `## [X.Y.Z]` header exists, or if a fragment's whole text already
      appears in the section (an interrupted earlier append).

  python3 scripts/assemble-changelog.py --extract <base-ref> --id <PR#>
      Convert a branch that edited CHANGELOG.md directly (e.g. a PR opened
      before the fragment convention): the bullets this branch ADDED to
      [Unreleased] (relative to `git merge-base HEAD <base-ref>`) are written
      out as changelog.d/<PR#>-<slug>.<section>.md fragments, and CHANGELOG.md
      is restored to <base-ref>'s version so it matches the base branch
      exactly (merge conflicts become impossible). Review, then commit the
      new fragments together with the restored CHANGELOG.md.

Exit codes: 0 = OK, 1 = check/guard/promote failure, 2 = usage error.
"""

from __future__ import annotations

import argparse
import datetime as _dt
import os
import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

# Keep a Changelog canonical section order.
CANONICAL_SECTIONS = ["Added", "Changed", "Deprecated", "Removed", "Fixed", "Security"]
SECTION_KEYS = [s.lower() for s in CANONICAL_SECTIONS]

FRAGMENT_NAME_RE = re.compile(
    r"^(?P<stem>[A-Za-z0-9][A-Za-z0-9._-]*)"
    r"\.(?P<section>added|changed|deprecated|removed|fixed|security)\.md$"
)
UNRELEASED_RE = re.compile(r"^## \[unreleased\]\s*$", re.IGNORECASE)
ANY_VERSION_HEADER_RE = re.compile(r"^## \[")
SUBSECTION_RE = re.compile(r"^### +(?P<name>.+?)\s*$")

HOW_TO_FIX = """\
How to fix (for humans and AI agents alike):

  1. Revert your CHANGELOG.md edit (`git checkout origin/dev -- CHANGELOG.md`
     or equivalent — restore the file to its base-branch state).
  2. Put the same bullet(s) in ONE new file instead:

         changelog.d/<PR-or-issue-number>-<short-slug>.<section>.md

     where <section> is one of: added | changed | deprecated | removed |
     fixed | security, and the file body is the finished bullet(s) starting
     with "- ", written exactly as they should appear in the changelog.
     Example: changelog.d/1832-inventory-devices-tab.added.md

Both steps in ONE recipe (run from the repo root on your PR branch; the
checkout line brings the tooling onto branches opened before this convention):

    git fetch origin dev
    git checkout origin/dev -- scripts/assemble-changelog.py changelog.d/README.md
    python3 scripts/assemble-changelog.py --extract origin/dev --id <PR#>

then review, commit the new changelog.d/ file(s) together with the restored
CHANGELOG.md, and push.

Full convention: changelog.d/README.md. CHANGELOG.md is rewritten only at
release time by `python3 scripts/assemble-changelog.py promote X.Y.Z`."""


def read_text(path: Path) -> str:
    """Read a file as UTF-8, normalizing CRLF so Windows edits never leak \\r."""
    return path.read_text(encoding="utf-8", errors="replace").replace("\r\n", "\n").replace("\r", "\n")


def fragment_files(fragments_dir: Path) -> list[Path]:
    if not fragments_dir.is_dir():
        return []
    return sorted(
        p for p in fragments_dir.iterdir()
        if p.is_file() and p.name not in ("README.md", ".gitkeep")
    )


def check_fragments(fragments_dir: Path) -> list[str]:
    """Return lint errors for every fragment file (empty list = pass)."""
    errors: list[str] = []
    for path in fragment_files(fragments_dir):
        rel = path.relative_to(REPO_ROOT) if path.is_relative_to(REPO_ROOT) else path
        m = FRAGMENT_NAME_RE.match(path.name)
        if not m:
            errors.append(
                f"{rel}: filename must match <id-or-slug>.<section>.md with"
                " <section> one of added|changed|deprecated|removed|fixed|security"
                " (e.g. 1832-inventory-devices-tab.added.md)"
            )
            continue
        body = read_text(path).strip()
        if not body:
            errors.append(f"{rel}: fragment is empty — body must be the finished changelog bullet(s)")
            continue
        first = body.splitlines()[0]
        if not first.startswith("- "):
            errors.append(
                f"{rel}: body must start with a markdown bullet ('- ') — write the"
                " entry exactly as it should appear under its section in CHANGELOG.md"
            )
        for i, line in enumerate(body.splitlines(), start=1):
            if ANY_VERSION_HEADER_RE.match(line) or SUBSECTION_RE.match(line):
                errors.append(
                    f"{rel}:{i}: fragment must not contain '##'/'###' headers —"
                    " the section comes from the filename suffix"
                )
                break
    return errors


def parse_unreleased(lines: list[str]) -> tuple[int, int, list[str], list[tuple[str, list[str]]]]:
    """Locate [Unreleased] and split its body.

    Returns (header_idx, end_idx, preamble_lines, [(section_name, body_lines)]).
    end_idx is the index of the next `## [` header (or len(lines)).
    """
    header_idx = next((i for i, l in enumerate(lines) if UNRELEASED_RE.match(l)), None)
    if header_idx is None:
        raise ValueError("CHANGELOG.md has no `## [Unreleased]` section")
    end_idx = next(
        (i for i in range(header_idx + 1, len(lines)) if ANY_VERSION_HEADER_RE.match(lines[i])),
        len(lines),
    )
    preamble: list[str] = []
    sections: list[tuple[str, list[str]]] = []
    current: list[str] | None = None
    for line in lines[header_idx + 1:end_idx]:
        m = SUBSECTION_RE.match(line)
        if m:
            current = []
            sections.append((m.group("name"), current))
        elif current is None:
            preamble.append(line)
        else:
            current.append(line)
    return header_idx, end_idx, preamble, sections


def normalized_section_content(text: str) -> str:
    """The [Unreleased] subsection content of a CHANGELOG, normalized for compare.

    Preamble prose (anything before the first `###`) is deliberately excluded:
    it holds the standing do-not-edit note and may change without penalty.
    Missing file / missing section normalize to "".
    """
    if not text:
        return ""
    try:
        _, _, _, sections = parse_unreleased(text.split("\n"))
    except ValueError:
        return ""
    out: list[str] = []
    for name, body in sections:
        out.append(f"### {name.strip().lower()}")
        out.extend(l.rstrip() for l in body if l.strip())
    return "\n".join(out)


def git(*args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=REPO_ROOT, check=True,
        capture_output=True, text=True,
    ).stdout


def cmd_check(fragments_dir: Path) -> int:
    errors = check_fragments(fragments_dir)
    if errors:
        for e in errors:
            print(e, file=sys.stderr)
        print(f"\nChangelog fragment lint FAILED ({len(errors)} issue(s)).", file=sys.stderr)
        print(f"\n{HOW_TO_FIX}", file=sys.stderr)
        return 1
    n = len(fragment_files(fragments_dir))
    print(f"Changelog fragment lint OK — {n} fragment(s)")
    return 0


def cmd_guard(base_sha: str, changelog: Path, fragments_dir: Path) -> int:
    try:
        old = git("show", f"{base_sha}:CHANGELOG.md")
    except subprocess.CalledProcessError:
        old = ""  # no CHANGELOG at base — nothing to guard
    new = read_text(changelog) if changelog.is_file() else ""
    if normalized_section_content(old) == normalized_section_content(new):
        print("CHANGELOG guard OK — [Unreleased] section content unchanged")
        return 0
    deleted = git(
        "diff", "--name-only", "--diff-filter=D", base_sha, "HEAD", "--",
        str(fragments_dir.relative_to(REPO_ROOT)),
    ).strip()
    if deleted:
        print(
            "CHANGELOG guard OK — [Unreleased] changed but changelog.d/ fragments"
            " were deleted in the same range (release promote)"
        )
        return 0
    print(
        "CHANGELOG guard FAILED: this PR edits the `## [Unreleased]` section of"
        " CHANGELOG.md directly.\n\n"
        "That section is a merge-conflict hotspot — every PR editing it conflicts"
        " with whichever PR merges first, and the rebase push voids approvals."
        " This repo therefore records unreleased changes as fragment files.\n\n"
        f"{HOW_TO_FIX}",
        file=sys.stderr,
    )
    return 1


def section_bullets(text: str) -> dict[str, list[str]]:
    """Map canonical section name -> list of bullet blocks in [Unreleased].

    A bullet block starts at a `- ` line and runs until the next `- ` line or
    the end of the subsection, trailing blank lines stripped.
    """
    out: dict[str, list[str]] = {name: [] for name in CANONICAL_SECTIONS}
    if not text:
        return out
    try:
        _, _, _, sections = parse_unreleased(text.split("\n"))
    except ValueError:
        return out
    for name, body in sections:
        canon = name.strip().capitalize()
        if canon not in out:
            continue
        current: list[str] | None = None
        for line in body:
            if line.startswith("- "):
                if current:
                    out[canon].append("\n".join(current).rstrip())
                current = [line]
            elif current is not None:
                current.append(line)
        if current:
            out[canon].append("\n".join(current).rstrip())
    return out


def slugify(bullet: str, max_len: int = 40) -> str:
    """First few words of a bullet -> kebab-case filename slug."""
    text = re.sub(r"[`*_\[\]()#]", "", bullet.splitlines()[0].lstrip("- ").strip())
    words = re.findall(r"[A-Za-z0-9]+", text.lower())
    slug = ""
    for w in words:
        if slug and len(slug) + 1 + len(w) > max_len:
            break
        slug = f"{slug}-{w}" if slug else w
    return slug or "entry"


def cmd_extract(base_ref: str, pr_id: str, changelog: Path, fragments_dir: Path) -> int:
    if not re.fullmatch(r"[A-Za-z0-9._-]+", pr_id):
        print(f"extract: --id '{pr_id}' must be a PR/issue number or plain slug token", file=sys.stderr)
        return 2
    try:
        merge_base = git("merge-base", "HEAD", base_ref).strip()
        base_text = git("show", f"{base_ref}:CHANGELOG.md")
        mb_text = git("show", f"{merge_base}:CHANGELOG.md")
    except subprocess.CalledProcessError as exc:
        print(f"extract: git failed: {exc.stderr.strip()}", file=sys.stderr)
        return 1
    work_text = read_text(changelog)

    mb_bullets = section_bullets(mb_text)
    work_bullets = section_bullets(work_text)

    def norm(b: str) -> str:
        return " ".join(b.split())

    wrote = 0
    for section in CANONICAL_SECTIONS:
        known = {norm(b) for b in mb_bullets[section]}
        added = [b for b in work_bullets[section] if norm(b) not in known]
        if not added:
            continue
        name = f"{pr_id}-{slugify(added[0])}.{section.lower()}.md"
        path = fragments_dir / name
        if path.exists():
            print(f"extract: {path.relative_to(REPO_ROOT)} already exists — refusing to overwrite", file=sys.stderr)
            return 1
        fragments_dir.mkdir(exist_ok=True)
        path.write_text("\n\n".join(added) + "\n", encoding="utf-8")
        print(f"extract: wrote {path.relative_to(REPO_ROOT)} ({len(added)} bullet(s))")
        wrote += 1
        # Bullets this branch DELETED or REWORDED (present at merge-base,
        # gone from the worktree) can't be represented as a fragment.
        removed = [b for b in mb_bullets[section] if norm(b) not in {norm(x) for x in work_bullets[section]}]
        for b in removed:
            print(
                f"extract: WARNING — [{section}] bullet present at merge-base but not on this"
                f" branch (deleted or reworded?): {b.splitlines()[0][:80]}",
                file=sys.stderr,
            )

    if wrote == 0:
        print("extract: no added [Unreleased] bullets found relative to the merge-base — nothing to do", file=sys.stderr)
        return 1

    changelog.write_text(base_text, encoding="utf-8")
    print(f"extract: restored CHANGELOG.md to {base_ref}'s version (now identical to the base branch)")
    print("extract: review the fragments, then commit them together with CHANGELOG.md.")
    errors = check_fragments(fragments_dir)
    if errors:
        for e in errors:
            print(e, file=sys.stderr)
        print("extract: WARNING — lint issues above; fix before pushing", file=sys.stderr)
    return 0


def cmd_promote(version: str, date_str: str | None, changelog: Path, fragments_dir: Path) -> int:
    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        print(f"promote: '{version}' is not a base semver (X.Y.Z — no leading 'v', no -rcN)", file=sys.stderr)
        return 2
    errors = check_fragments(fragments_dir)
    if errors:
        for e in errors:
            print(e, file=sys.stderr)
        print("\npromote aborted — fix the fragment lint errors above first.", file=sys.stderr)
        return 1

    text = read_text(changelog)
    lines = text.split("\n")
    if any(re.match(rf"^## \[{re.escape(version)}\]", l) for l in lines):
        print(f"promote: CHANGELOG.md already has a ## [{version}] section — for fixes that landed "
              f"after it was promoted, use: promote {version} --append (add --date YYYY-MM-DD only at the final release)", file=sys.stderr)
        return 1
    header_idx, end_idx, preamble, legacy_sections = parse_unreleased(lines)

    # Ordered canonical map, seeded with legacy [Unreleased] subsection bodies.
    merged: dict[str, list[str]] = {name: [] for name in CANONICAL_SECTIONS}
    extras: list[tuple[str, list[str]]] = []
    for name, body in legacy_sections:
        canon = name.strip().capitalize()
        chunk = [l for l in body]
        # trim leading/trailing blank lines per chunk
        while chunk and not chunk[0].strip():
            chunk.pop(0)
        while chunk and not chunk[-1].strip():
            chunk.pop()
        if not chunk:
            continue
        if canon in merged:
            merged[canon].extend(chunk + [""])
        else:
            extras.append((name.strip(), chunk))

    frags = fragment_files(fragments_dir)
    for path in frags:
        section = CANONICAL_SECTIONS[SECTION_KEYS.index(FRAGMENT_NAME_RE.match(path.name).group("section"))]
        merged[section].extend(read_text(path).strip().split("\n") + [""])

    if not frags and all(not v for v in merged.values()) and not extras:
        print("promote: nothing to promote — no fragments and no legacy [Unreleased] content", file=sys.stderr)
        return 1

    if date_str and not valid_date(date_str):
        print(f"promote: --date '{date_str}' is not a valid YYYY-MM-DD date", file=sys.stderr)
        return 2
    date = date_str or _dt.date.today().isoformat()
    new_section: list[str] = [f"## [{version}] - {date}", ""]
    for name in CANONICAL_SECTIONS:
        if merged[name]:
            new_section.append(f"### {name}")
            new_section.append("")
            body = merged[name]
            while body and not body[-1].strip():
                body.pop()
            new_section.extend(body)
            new_section.append("")
    for name, chunk in extras:
        print(f"promote: WARNING — non-canonical [Unreleased] subsection '### {name}' carried over verbatim", file=sys.stderr)
        new_section.extend([f"### {name}", ""] + chunk + [""])

    while preamble and not preamble[-1].strip():
        preamble.pop()
    while preamble and not preamble[0].strip():
        preamble.pop(0)
    rebuilt = (
        lines[:header_idx + 1]
        + ([""] + preamble if preamble else [])
        + [""]
        + new_section
        + lines[end_idx:]
    )
    write_atomic(changelog, "\n".join(rebuilt))

    for path in frags:
        path.unlink()
        print(f"promote: deleted {path.relative_to(REPO_ROOT) if path.is_relative_to(REPO_ROOT) else path}")
    print(
        f"promote: assembled {len(frags)} fragment(s)"
        f"{' + legacy [Unreleased] content' if legacy_sections else ''}"
        f" into ## [{version}] - {date}"
    )
    print("promote: review the diff, then commit CHANGELOG.md and the deleted fragments together.")
    return 0


def valid_date(date_str: str) -> bool:
    """A real YYYY-MM-DD calendar date (2026-02-30 is not)."""
    if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", date_str):
        return False
    try:
        _dt.date.fromisoformat(date_str)
    except ValueError:
        return False
    return True


def write_atomic(path: Path, text: str) -> None:
    """Replace path in one step, so a failure mid-write never leaves it truncated."""
    tmp = path.with_name(path.name + ".tmp")
    try:
        tmp.write_text(text, encoding="utf-8")
        os.replace(tmp, path)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise


def contains_block(haystack: list[str], block: list[str]) -> bool:
    """True if block appears in haystack as consecutive whole lines (trailing whitespace ignored)."""
    hay = [l.rstrip() for l in haystack]
    blk = [l.rstrip() for l in block]
    n = len(blk)
    return n > 0 and any(hay[i:i + n] == blk for i in range(len(hay) - n + 1))


def cmd_promote_append(version: str, date_str: str | None, changelog: Path, fragments_dir: Path,
                       allow_older: bool = False) -> int:
    if not re.fullmatch(r"\d+\.\d+\.\d+", version):
        print(f"promote --append: '{version}' is not a base semver (X.Y.Z)", file=sys.stderr)
        return 2
    if date_str and not valid_date(date_str):
        print(f"promote --append: --date '{date_str}' is not a valid YYYY-MM-DD date", file=sys.stderr)
        return 2
    errors = check_fragments(fragments_dir)
    if errors:
        for e in errors:
            print(e, file=sys.stderr)
        print("\npromote --append aborted — fix the fragment lint errors above first.", file=sys.stderr)
        return 1

    lines = read_text(changelog).split("\n")
    try:
        _, _, _, legacy_sections = parse_unreleased(lines)
    except ValueError as e:
        print(f"promote --append: {e}", file=sys.stderr)
        return 1
    if any(any(l.strip() for l in body) for _, body in legacy_sections):
        print("promote --append: [Unreleased] holds legacy subsections; they belong to the next "
              "version, so --append refuses rather than fold them into an existing release", file=sys.stderr)
        return 1
    header_re = re.compile(rf"^## \[{re.escape(version)}\](?P<rest>.*)$")
    matches = [i for i, l in enumerate(lines) if header_re.match(l)]
    if not matches:
        print(f"promote --append: CHANGELOG.md has no ## [{version}] section to append to. "
              f"If {version} is a NEW version, run a plain `promote {version}`; otherwise check "
              f"the version number", file=sys.stderr)
        return 1
    if len(matches) > 1:
        print(f"promote --append: CHANGELOG.md has {len(matches)} ## [{version}] headers (lines "
              + ", ".join(str(i + 1) for i in matches) + "); fix that by hand first", file=sys.stderr)
        return 1
    start = matches[0]
    end = next((i for i in range(start + 1, len(lines)) if ANY_VERSION_HEADER_RE.match(lines[i])), len(lines))

    # The target must be the newest released section (the first one below
    # [Unreleased]): a mistyped version would otherwise fold every fragment,
    # disclosures included, into an older release and delete them.
    unreleased_idx = next((i for i, l in enumerate(lines) if UNRELEASED_RE.match(l)), None)
    newest = next((i for i in range((unreleased_idx or -1) + 1, len(lines))
                   if ANY_VERSION_HEADER_RE.match(lines[i]) and not UNRELEASED_RE.match(lines[i])), None)
    if newest != start:
        newest_header = lines[newest] if newest is not None else "(none)"
        if not allow_older:
            print(f"promote --append: ## [{version}] is not the newest released section "
                  f"(that is: {newest_header}); refusing. Pass --allow-older-section if this "
                  f"really belongs to an older release.", file=sys.stderr)
            return 1
        print(f"promote --append: WARNING — appending to ## [{version}], which is older than "
              f"{newest_header} (--allow-older-section)", file=sys.stderr)

    frags = fragment_files(fragments_dir)
    if not frags:
        print("promote --append: nothing to append — no fragments in changelog.d/", file=sys.stderr)
        return 1
    additions: dict[str, list[str]] = {name: [] for name in CANONICAL_SECTIONS}
    already = []
    for path in frags:
        section = CANONICAL_SECTIONS[SECTION_KEYS.index(FRAGMENT_NAME_RE.match(path.name).group("section"))]
        body = read_text(path).strip().split("\n")
        # A re-run after an interrupted append (CHANGELOG written, fragment
        # not deleted) would otherwise duplicate the bullets. Only the WHOLE
        # fragment, as consecutive whole lines, counts as already present.
        if contains_block(lines[start:end], body):
            already.append(path.name)
        additions[section].extend(([""] if additions[section] else []) + body)
    if already:
        print("promote --append: the full text of these fragments already appears in ## [" + version + "] "
              "(a previous append interrupted before deleting them?) — refusing so nothing is duplicated. "
              "A short fragment can also match an existing line by coincidence, so compare each with the "
              "section (e.g. `git diff CHANGELOG.md`) before deleting it: "
              + ", ".join(already), file=sys.stderr)
        return 1

    # Split the existing section body into its preamble and ### subsections.
    body = lines[start + 1:end]
    preamble: list[str] = []
    subs: list[tuple[str, list[str]]] = []
    for line in body:
        m = SUBSECTION_RE.match(line)
        if m:
            subs.append((m.group("name").strip(), []))
        elif subs:
            subs[-1][1].append(line)
        else:
            preamble.append(line)

    def trimmed(chunk: list[str]) -> list[str]:
        chunk = list(chunk)
        while chunk and not chunk[0].strip():
            chunk.pop(0)
        while chunk and not chunk[-1].strip():
            chunk.pop()
        return chunk

    existing = {name.capitalize(): i for i, (name, _) in enumerate(subs)}
    for name in CANONICAL_SECTIONS:
        if not additions[name]:
            continue
        if name in existing:
            i = existing[name]
            subs[i] = (subs[i][0], trimmed(subs[i][1]) + [""] + additions[name])
        else:
            # Insert before the first existing canonical subsection that sorts
            # after it, else after the last canonical one (non-canonical
            # subsections stay last, as plain promote writes them).
            later = [existing[n] for n in CANONICAL_SECTIONS[CANONICAL_SECTIONS.index(name) + 1:] if n in existing]
            canon_idx = [j for j, (n, _) in enumerate(subs) if n.capitalize() in CANONICAL_SECTIONS]
            pos = min(later) if later else (max(canon_idx) + 1 if canon_idx else 0)
            subs.insert(pos, (name, additions[name]))
            existing = {n.capitalize(): j for j, (n, _) in enumerate(subs)}

    old_header = lines[start]
    header = f"## [{version}] - {date_str}" if date_str else old_header
    rebuilt_section: list[str] = [header, ""]
    pre = trimmed(preamble)
    if pre:
        rebuilt_section += pre + [""]
    for name, chunk in subs:
        rebuilt_section += [f"### {name}", ""] + trimmed(chunk) + [""]
    rebuilt = lines[:start] + rebuilt_section + lines[end:]
    write_atomic(changelog, "\n".join(rebuilt))

    for path in frags:
        path.unlink()
        print(f"promote --append: deleted {path.relative_to(REPO_ROOT) if path.is_relative_to(REPO_ROOT) else path}")
    print(f"promote --append: appended {len(frags)} fragment(s) to {header}"
          + (f" (header was: {old_header})" if header != old_header else ""))
    print("promote --append: review the diff, then commit CHANGELOG.md and the deleted fragments together.")
    return 0


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--changelog", type=Path, default=REPO_ROOT / "CHANGELOG.md", help=argparse.SUPPRESS)
    parser.add_argument("--fragments-dir", type=Path, default=REPO_ROOT / "changelog.d", help=argparse.SUPPRESS)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--check", action="store_true", help="lint changelog.d/ fragments")
    group.add_argument("--guard", metavar="BASE_SHA", help="fail on direct [Unreleased] edits vs BASE_SHA (CI)")
    group.add_argument("--extract", metavar="BASE_REF", help="convert this branch's direct [Unreleased] edits into fragments (requires --id)")
    group.add_argument("promote", nargs="?", metavar="promote", help="'promote' — assemble fragments into a release section")
    parser.add_argument("version", nargs="?", help="X.Y.Z (promote mode)")
    parser.add_argument("--date", help="override release date (YYYY-MM-DD, promote mode)")
    parser.add_argument("--append", action="store_true",
                        help="promote mode: append fragments to an EXISTING ## [X.Y.Z] section")
    parser.add_argument("--allow-older-section", action="store_true",
                        help="with --append: allow a section that is not the newest release")
    parser.add_argument("--id", help="PR or issue number for the fragment filename (extract mode)")
    args = parser.parse_args(argv[1:])

    if args.append and args.promote != "promote":
        parser.error("--append is only valid with promote")
    if args.allow_older_section and not args.append:
        parser.error("--allow-older-section is only valid with promote --append")
    if args.check:
        return cmd_check(args.fragments_dir)
    if args.guard:
        return cmd_guard(args.guard, args.changelog, args.fragments_dir)
    if args.extract:
        if not args.id:
            parser.error("--extract requires --id <PR-or-issue-number>")
        return cmd_extract(args.extract, args.id, args.changelog, args.fragments_dir)
    if args.promote != "promote" or not args.version:
        parser.error("usage: assemble-changelog.py promote <X.Y.Z> [--append [--allow-older-section]] [--date YYYY-MM-DD]")
    if args.append:
        return cmd_promote_append(args.version, args.date, args.changelog, args.fragments_dir,
                                  args.allow_older_section)
    return cmd_promote(args.version, args.date, args.changelog, args.fragments_dir)


if __name__ == "__main__":
    sys.exit(main(sys.argv))
