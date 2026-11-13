#!/usr/bin/env python3
"""What changed on dev since I last pulled?

Prints, for the range OLD..HEAD of the current checkout:

  1. version bumps  - project version, plugin ABI, vcpkg baseline and
                      dependency constraints (top level and per feature), gateway
                      (rebar3) packages, latest released CHANGELOG section;
  2. surfaces touched that may need a rebuild or redeploy;
  3. dependency bumps: commits titled `build(deps):` / `chore(deps):` (Dependabot's
     title convention), which add no fragment and touch none of the files in 1;
  4. the changelog.d/ fragments added in the range, grouped by section.

Unreleased changes are recorded as fragments (changelog.d/README.md) and only
assembled into CHANGELOG.md at release, so this is the way to read them
collated before a release.

  python3 scripts/whats-new.py                 # since your last pull
  python3 scripts/whats-new.py --since v0.15.0 # since a tag, branch or commit
  python3 scripts/whats-new.py --since "2 weeks ago"   # ISO date or "N <unit> ago"
  python3 scripts/whats-new.py --full          # whole bullets; every CI/tooling dep bump

"Your last pull" is read from the HEAD reflog: the newest `pull` entry, or a
`merge <remote>/<branch>` entry after a manual fetch, and the commit HEAD was on
before it. Unlike ORIG_HEAD it is not overwritten by `checkout`, a local `merge`
or `reset`; a later action can only make the range start earlier, never later. The
reflog is local and expires, so a fresh clone has none: pass --since.

Read-only: it runs `git` queries and writes nothing. All repository-sourced text
is printed with control characters replaced. Stdlib only.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path

# Breaking / operator-visible first. The grammar below mirrors scripts/assemble-changelog.py
# (FRAGMENT_NAME_RE, CANONICAL_SECTIONS); tests/test_whats_new.py asserts they agree.
SECTION_ORDER = ["security", "removed", "deprecated", "changed", "added", "fixed"]
FRAGMENT_RE = re.compile(
    r"^(?P<stem>[A-Za-z0-9][A-Za-z0-9._-]*)\.(?P<section>" + "|".join(SECTION_ORDER) + r")\.md$"
)
FRAGMENT_DIR = "changelog.d"
BRIEF_MAX = 200
# Sections whose entries are never cut: dropping the tail of a breaking or security
# entry drops the step the reader has to take.
NEVER_TRUNCATE = {"security", "removed", "deprecated"}
DEPS_SUBJECT = r"^(build|chore)\(deps[^)]*\):"
# git's date parser accepts any string (a typo silently becomes "now"), so only
# unambiguous forms are passed to it.
DATE_RE = re.compile(
    r"^(\d{4}-\d{2}-\d{2}([ T]\d{2}:\d{2}(:\d{2})?)?"
    r"|yesterday"
    r"|\d+ (second|minute|hour|day|week|month|year)s? ago)$"
)
# A reflog entry written by one step of a rebase, e.g. "pull --rebase origin dev (pick): msg".
REBASE_STEP_RE = re.compile(r"^(pull|rebase)\b[^:]*\((start|pick|finish|continue|fixup|squash|reword|edit|drop|abort)\b")
# Terminal control characters other than \n and \t (ESC, CR, BEL, C1 controls, DEL).
CONTROL_RE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f]")


class GitError(Exception):
    pass


def clean(text: str) -> str:
    """Replace terminal control characters in repository-sourced text."""
    return CONTROL_RE.sub("?", text)


class Repo:
    def __init__(self, root: Path):
        self.root = root

    def _run(self, *args: str) -> subprocess.CompletedProcess:
        try:
            return subprocess.run(
                ["git", "-c", "core.quotepath=off", *args],
                cwd=self.root, capture_output=True, text=True, encoding="utf-8", errors="replace",
            )
        except FileNotFoundError as exc:
            raise GitError("git was not found on PATH") from exc

    def git(self, *args: str) -> str:
        proc = self._run(*args)
        if proc.returncode != 0:
            raise GitError(proc.stderr.strip() or f"git {' '.join(args)} failed")
        return proc.stdout

    def ok(self, *args: str) -> bool:
        return self._run(*args).returncode == 0

    def show(self, ref: str, path: str) -> str | None:
        """File content at ref; None only when the path does not exist there.

        Any other failure (a missing object in a partial clone, a damaged repository)
        raises: reading it as "absent" would print "nothing changed".
        """
        proc = self._run("show", f"{ref}:{path}")
        if proc.returncode == 0:
            return proc.stdout
        if "does not exist" in proc.stderr or "exists on disk, but not in" in proc.stderr:
            return None
        raise GitError(f"could not read {path} at {ref[:10]}: {proc.stderr.strip()}")

    def resolves(self, rev: str) -> str | None:
        proc = self._run("rev-parse", "--verify", "--quiet", f"{rev}^{{commit}}")
        return proc.stdout.strip() or None

    def names(self, *args: str) -> list[str]:
        """NUL-separated path list from a git command run with -z."""
        return [n.strip() for n in self.git(*args).split("\0") if n.strip()]


# --- choosing the base ---------------------------------------------------------

def last_pull_base(repo: Repo) -> str:
    """The commit HEAD was on before the newest pull/fetch-merge recorded in the reflog."""
    remotes = [r for r in repo.git("remote").split() if r]
    merge_re = re.compile(r"^merge (?:" + "|".join(re.escape(r) for r in remotes) + r")/") if remotes else None
    entries = []
    for line in repo.git("reflog", "show", "--format=%H%x09%gs", "HEAD").splitlines():
        sha, _, subject = line.partition("\t")
        entries.append((sha, subject))

    def is_pull(subject: str) -> bool:
        return subject.startswith("pull") or bool(merge_re and merge_re.match(subject))

    for i, (_, subject) in enumerate(entries):
        if is_pull(subject):
            j = i + 1
            if REBASE_STEP_RE.match(subject):
                # `pull --rebase` writes a run of pull/rebase step entries; the base precedes all of them.
                while j < len(entries) and REBASE_STEP_RE.match(entries[j][1]):
                    j += 1
            if j < len(entries):
                return entries[j][0]
            break
    raise GitError(
        "no pull is recorded in this checkout's reflog (a fresh clone or worktree has none); "
        "pass --since <ref|date>"
    )


def resolve_base(repo: Repo, since: str | None, head: str) -> tuple[str, str]:
    """(base commit, how it was chosen)."""
    if since is None:
        old, how = last_pull_base(repo), "your last pull"
    else:
        old = repo.resolves(since)
        how = since
        if not old:
            if not DATE_RE.match(since):
                raise GitError(
                    f"--since {since!r} is not a ref in this repository; for a date use YYYY-MM-DD "
                    f"or \"N days ago\" (days, weeks, months and so on)"
                )
            old = repo.git("rev-list", "-1", f"--before={since}", head).strip()
            if not old:
                hint = " (this is a shallow clone: history before the cut-off is missing)" \
                    if repo.git("rev-parse", "--is-shallow-repository").strip() == "true" else ""
                raise GitError(f"no commit is older than {since!r}{hint}")
    if old == head:
        raise GitError(f"{how}: HEAD has not moved since then, so there is nothing to compare; pass --since to look further back")
    if not repo.ok("merge-base", "--is-ancestor", old, head):
        if since is not None:
            raise GitError(f"{old[:10]} ({since}) is not an ancestor of HEAD; pick a ref on this branch's history")
        # After `git pull --rebase` the old tip is not an ancestor; the merge-base is what was shared.
        base = repo.git("merge-base", old, head).strip()
        if not base:
            raise GitError("the commit before your last pull shares no history with HEAD; pass --since")
        old, how = base, "your last pull (rebased onto it; range starts at the common ancestor)"
    return old, how


# --- version extractors: each returns {label: value} for one ref ----------------
# A parse problem raises ValueError, reported as a line of its own; it never reads as "no change".

def meson_version(repo: Repo, ref: str) -> dict[str, str]:
    text = repo.show(ref, "meson.build") or ""
    m = re.search(r"\bversion:\s*'([^']+)'", text)
    return {"project version (meson.build)": m.group(1)} if m else {}


def plugin_abi(repo: Repo, ref: str) -> dict[str, str]:
    text = repo.show(ref, "sdk/include/yuzu/plugin.h") or ""
    return {f"plugin ABI ({n})": v for n, v in re.findall(r"#define\s+(YUZU_PLUGIN_ABI_VERSION(?:_MIN)?)\s+(\d+)", text)}


def released_version(repo: Repo, ref: str) -> dict[str, str]:
    text = repo.show(ref, "CHANGELOG.md") or ""
    m = re.search(r"^## \[(\d[^\]]*)\]", text, re.M)
    return {"latest released CHANGELOG section": m.group(1)} if m else {}


def _vcpkg_deps(deps: object, where: str, out: dict[str, str]) -> None:
    """Add dependencies to `out`; one that appears in several places has all its places in the value."""
    if not isinstance(deps, list):
        raise ValueError(f"vcpkg.json {where or 'dependencies'} is not a list")
    for dep in deps:
        if isinstance(dep, str):
            name, constraint = dep, ""
        elif isinstance(dep, dict) and "name" in dep:
            name, constraint = str(dep["name"]), str(dep.get("version>=", ""))
        else:
            raise ValueError(f"vcpkg.json {where or 'dependencies'} has an entry that is neither a name nor an object with a name")
        value = (f">={constraint}" if constraint else "(unconstrained)") + where
        key = f"vcpkg dependency {name}"
        out[key] = f"{out[key]}, {value}" if key in out else value


def vcpkg(repo: Repo, ref: str) -> dict[str, str]:
    text = repo.show(ref, "vcpkg.json")
    if text is None:
        return {}
    try:
        data = json.loads(text)
    except json.JSONDecodeError as exc:
        raise ValueError(f"vcpkg.json is not valid JSON ({exc.msg})") from exc
    if not isinstance(data, dict):
        raise ValueError("vcpkg.json top level is not an object")
    out = {"vcpkg builtin-baseline": str(data.get("builtin-baseline", ""))[:10]}
    _vcpkg_deps(data.get("dependencies") or [], "", out)
    features = data.get("features") or {}
    if not isinstance(features, dict):
        raise ValueError("vcpkg.json features is not an object")
    for fname, feat in features.items():
        if isinstance(feat, dict) and feat.get("dependencies"):
            _vcpkg_deps(feat["dependencies"], f" [feature {fname}]", out)
    for ov in data.get("overrides") or []:
        if not isinstance(ov, dict):
            raise ValueError("vcpkg.json overrides has a non-object entry")
        ver = next((str(ov[k]) for k in ("version", "version-string", "version-semver", "version-date") if k in ov), "")
        out[f"vcpkg override {ov.get('name', '?')}"] = ver
    return out


def rebar_lock(repo: Repo, ref: str) -> dict[str, str]:
    text = repo.show(ref, "gateway/rebar.lock")
    if text is None:
        return {}
    pkgs = {f"gateway package {n}": v for n, v in re.findall(r'\{pkg,<<"([^"]+)">>,<<"([^"]+)">>\}', text)}
    if text.strip() and not pkgs:
        raise ValueError("gateway/rebar.lock has no package entries in a format this script recognises")
    return pkgs


EXTRACTORS = [meson_version, released_version, plugin_abi, vcpkg, rebar_lock]


def version_changes(repo: Repo, old: str, new: str) -> list[str]:
    lines: list[str] = []
    for fn in EXTRACTORS:
        try:
            before, after = fn(repo, old), fn(repo, new)
        except ValueError as exc:
            # Compared as a whole or not at all: half a comparison would print the whole file as added or removed.
            lines.append(f"  ! {fn.__name__} not compared: {exc}")
            continue
        for key in sorted(set(before) | set(after)):
            b, a = before.get(key), after.get(key)
            if b == a:
                continue
            if b is None:
                lines.append(f"  + {key}: {a}  (new)")
            elif a is None:
                lines.append(f"  - {key}: {b}  (removed)")
            else:
                lines.append(f"  ~ {key}: {b} -> {a}")
    return lines


# --- touched surfaces --------------------------------------------------------

def surface_notes(files: list[str]) -> list[str]:
    def under(*prefixes: str) -> list[str]:
        return [f for f in files if f.startswith(prefixes)]

    notes = []
    if under("vcpkg.json", "vcpkg-configuration.json", "triplets/"):
        notes.append("vcpkg manifest or triplets changed: vcpkg_installed/ may be stale; re-run the setup script, "
                     "with --wipe if a library version does not update (docs/build-guide.md)")
    for prefix, text in (
        ("proto/", "`proto/` changed (server, agent and gateway consume it): rebuild all three"),
        ("gateway/", "`gateway/` changed: rebuild the Erlang gateway (docs/erlang-gateway-build.md)"),
        ("sdk/", "`sdk/` changed: plugins build against it"),
    ):
        n = len(under(prefix))
        if n:
            notes.append(f"{text} ({n} files)")
    deploy = under("deploy/", "docker-compose")
    if deploy:
        notes.append(f"deploy/compose files changed ({len(deploy)} files): re-read them before redeploying")
    return notes


def top_level_summary(files: list[str]) -> str:
    counts = Counter(f.split("/", 1)[0] if "/" in f else "(root)" for f in files)
    return ", ".join(f"{d} {n}" for d, n in counts.most_common(8))


# --- dependency bumps ----------------------------------------------------------

def _is_image_file(path: str) -> bool:
    base = path.rsplit("/", 1)[-1]
    return path.startswith("deploy/") and (base.startswith(("Dockerfile", "docker-compose")) or base.endswith(".Dockerfile"))


def dependency_bumps(repo: Repo, old: str, new: str) -> tuple[list[str], list[str]]:
    """(images, other) subjects of `build(deps)` / `chore(deps)` commits in old..new.

    Images = the commit changes a Dockerfile or compose file under deploy/. Dependabot does not
    manage vcpkg or rebar3; those bumps come from version_changes().
    """
    out = repo.git(
        "log", "--no-merges", "-E", f"--grep={DEPS_SUBJECT}", "--name-only",
        "--pretty=format:%x00%s", f"{old}..{new}",
    )
    images: list[str] = []
    other: list[str] = []
    for block in out.split("\x00")[1:]:
        subject, *paths = block.splitlines()
        if not re.match(DEPS_SUBJECT, subject):
            continue
        (images if any(_is_image_file(p) for p in paths) else other).append(subject)
    return images, other


# --- fragments ---------------------------------------------------------------

def _fragment_path_ok(path: str) -> bool:
    d, _, base = path.rpartition("/")
    return d == FRAGMENT_DIR and bool(FRAGMENT_RE.match(base))


def section_of(path: str) -> str:
    return FRAGMENT_RE.match(path.rsplit("/", 1)[-1]).group("section")  # type: ignore[union-attr]


def bullets(body: str) -> list[str]:
    """Split a fragment body into its '- ' bullets (continuation lines kept)."""
    items: list[list[str]] = []
    for line in body.splitlines():
        if line.startswith("- "):
            items.append([line])
        elif items:
            items[-1].append(line)
    return ["\n".join(b).rstrip() for b in items]


def _squash(text: str) -> str:
    return " ".join(text.split())


def added_fragments(repo: Repo, old: str, new: str) -> dict[str, str]:
    """{path: body} for the fragments this range adds.

    A fragment counts when it exists at `new` and did not at `old` (the net diff, so renames,
    rewordings and reverts inside the range cannot list one change twice or list a withdrawn
    one), or when a release promoted it inside the range: it is gone at `new`, its last body
    appears in `new`'s CHANGELOG.md, and it was added after `old`.
    """
    net = [p for p in repo.names("diff", "-z", "--no-renames", "--diff-filter=A", "--name-only", old, new, "--", FRAGMENT_DIR + "/")
           if _fragment_path_ok(p)]
    found: dict[str, str] = {}
    for path in net:
        body = repo.show(new, path)
        if body is not None:
            found[path] = body

    # -m so adds made inside merge commits (conflict resolutions, evil merges) are seen too.
    ever = repo.names("log", "-m", "-z", "--no-renames", "--diff-filter=A", "--name-only", "--format=", f"{old}..{new}", "--", FRAGMENT_DIR + "/")
    gone = [p for p in dict.fromkeys(ever) if _fragment_path_ok(p) and p not in found and repo.show(new, p) is None]
    if gone:
        changelog = _squash(repo.show(new, "CHANGELOG.md") or "")
        for path in gone:
            deleter = repo.git("log", "-1", "--no-renames", "--diff-filter=D", "--format=%H", f"{old}..{new}", "--", path).strip()
            if not deleter:
                continue
            body = repo.show(deleter + "^", path)
            first = bullets(body)[:1] if body else []
            if first and _squash(first[0]) in changelog:
                found[path] = body  # type: ignore[assignment]
    return found


def render_fragments(frags: dict[str, str], full: bool) -> tuple[list[str], int, list[str]]:
    """(lines, bullet count, names of fragments that yielded no '- ' bullet)."""
    by_section: dict[str, list[str]] = {s: [] for s in SECTION_ORDER}
    seen: set[tuple[str, str]] = set()
    empty: list[str] = []
    total = 0
    for path, body in sorted(frags.items()):
        section = section_of(path)
        items = bullets(body)
        if not items:
            empty.append(path.rsplit("/", 1)[-1])
            continue
        for b in items:
            if (section, b) in seen:
                continue
            seen.add((section, b))
            total += 1
            first = b.splitlines()[0]
            cut = not full and section not in NEVER_TRUNCATE and not first.startswith("- **Breaking")
            by_section[section].append(
                b if full else (first[: BRIEF_MAX - 3].rstrip() + "..." if cut and len(first) > BRIEF_MAX else first)
            )
    lines: list[str] = []
    for section in SECTION_ORDER:
        if by_section[section]:
            lines.append(f"{section.capitalize()} ({len(by_section[section])})")
            lines.extend(by_section[section])
            lines.append("")
    return lines, total, empty


def build_report(repo: Repo, since: str | None, full: bool) -> list[str]:
    head = repo.git("rev-parse", "HEAD").strip()
    old, how = resolve_base(repo, since, head)
    count = repo.git("rev-list", "--count", f"{old}..{head}").strip()
    files = repo.names("diff", "-z", "--name-only", old, head)
    base_line = repo.git("log", "-1", "--format=%h %cs %s", old).strip()
    out = [
        f"Changes since {how}: {count} commits, {len(files)} files ({top_level_summary(files)})",
        f"Base {base_line}",
        f"Head {repo.git('log', '-1', '--format=%h %cs %s', head).strip()}",
        "",
    ]

    versions = version_changes(repo, old, head)
    out.append("Version bumps")
    out.extend(versions if versions else ["  none of the tracked versions changed"])
    out.append("")

    notes = surface_notes(files)
    if notes:
        out.append("Rebuild / redeploy")
        out.extend(f"  * {n}" for n in notes)
        out.append("")

    images, other = dependency_bumps(repo, old, head)
    if images or other:
        out.append(f"Dependency bumps (build(deps)/chore(deps) commits): {len(images)} Docker image, {len(other)} other")
        out.extend(f"  {s}" for s in images)
        if full:
            out.extend(f"  {s}" for s in other)
        elif other:
            out.append(f"  + {len(other)} other bumps (workflows, pip, npm); --full lists them")
        out.append("")

    lines, total, empty = render_fragments(added_fragments(repo, old, head), full)
    if lines:
        out.append(f"Changelog entries added ({total})")
        out.append("")
        out.extend(lines)
    else:
        out.append("No changelog fragments were added in this range (refactors, CI and test-only changes may skip them;")
        out.append("`git log --first-parent --oneline` lists every merged PR).")
    if empty:
        out.append(f"! {len(empty)} fragment(s) had no '- ' bullet and are not summarised: {', '.join(empty)}")
    return out


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="Summarise what changed in this checkout since the last pull.")
    ap.add_argument("--since", help="ref, tag or commit, or a date (YYYY-MM-DD, \"N days ago\"); default: your last pull")
    ap.add_argument("--full", action="store_true",
                    help="print whole bullets (not first lines) and list every non-image dependency bump")
    ap.add_argument("--repo", type=Path, default=None, help=argparse.SUPPRESS)
    args = ap.parse_args(argv)

    try:
        sys.stdout.reconfigure(errors="replace")  # type: ignore[union-attr]
    except (AttributeError, ValueError):
        pass
    try:
        top = Repo(args.repo or Path.cwd())
        root = top.git("rev-parse", "--show-toplevel").strip()
        report = build_report(Repo(Path(root)), args.since, args.full)
    except GitError as exc:
        print(f"whats-new: {clean(str(exc))}", file=sys.stderr)
        return 2
    try:
        print("\n".join(clean(line) for line in report).rstrip())
        sys.stdout.flush()
    except BrokenPipeError:  # `| head`
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
