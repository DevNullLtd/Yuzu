#!/usr/bin/env python3
"""What changed on dev since I last pulled?

Prints, for the range OLD..HEAD of the current checkout:

  1. version bumps  - project version, plugin ABI, vcpkg baseline and
                      dependency constraints, gateway (rebar3) packages,
                      latest released CHANGELOG section;
  2. surfaces touched that usually need a rebuild or redeploy;
  3. dependency bumps merged by Dependabot (`build(deps)` / `chore(deps)` commits),
     which add no fragment and touch none of the files in 1;
  4. the changelog.d/ fragments added in the range, grouped by section.

Unreleased changes are recorded as fragments (changelog.d/README.md) and only
assembled into CHANGELOG.md at release, so this is the way to read them
collated before a release.

  python3 scripts/whats-new.py                 # since ORIG_HEAD (the last pull/merge)
  python3 scripts/whats-new.py --since v0.15.0 # since a tag, branch or commit
  python3 scripts/whats-new.py --since "2 weeks ago"
  python3 scripts/whats-new.py --full          # whole fragment bodies; every CI/tooling dep bump

Read-only: it runs `git` queries and writes nothing. ORIG_HEAD is set by
`git pull`, `merge`, `rebase` and `reset`, so run this straight after the pull;
a later reset or rebase overwrites it, and then pass --since explicitly.
Stdlib only.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from collections import Counter
from pathlib import Path

# Breaking / operator-visible first.
SECTION_ORDER = ["security", "removed", "deprecated", "changed", "added", "fixed"]
FRAGMENT_RE = re.compile(r"^(?P<stem>.+)\.(?P<section>" + "|".join(SECTION_ORDER) + r")\.md$")
BRIEF_MAX = 200


class GitError(Exception):
    pass


class Repo:
    def __init__(self, root: Path):
        self.root = root

    def git(self, *args: str, check: bool = True) -> str:
        proc = subprocess.run(
            ["git", "-c", "core.quotepath=off", *args],
            cwd=self.root, capture_output=True, text=True, encoding="utf-8", errors="replace",
        )
        if check and proc.returncode != 0:
            raise GitError(proc.stderr.strip() or f"git {' '.join(args)} failed")
        return proc.stdout if proc.returncode == 0 else ""

    def show(self, ref: str, path: str) -> str | None:
        """File content at ref, or None when it does not exist there."""
        proc = subprocess.run(
            ["git", "show", f"{ref}:{path}"],
            cwd=self.root, capture_output=True, text=True, encoding="utf-8", errors="replace",
        )
        return proc.stdout if proc.returncode == 0 else None

    def resolves(self, rev: str) -> str | None:
        out = self.git("rev-parse", "--verify", "--quiet", f"{rev}^{{commit}}", check=False).strip()
        return out or None


def resolve_since(repo: Repo, since: str | None, head: str) -> str:
    if since is None:
        old = repo.resolves("ORIG_HEAD")
        if not old:
            raise GitError("no ORIG_HEAD in this checkout (nothing pulled or merged yet); pass --since <ref|date>")
        if old == head:
            raise GitError("ORIG_HEAD equals HEAD (the last pull brought nothing new); pass --since <ref|date> to look further back")
    else:
        old = repo.resolves(since)
        if not old:
            # Not a ref: treat as a date expression ("2 weeks ago", "2026-11-01").
            old = repo.git("rev-list", "-1", f"--before={since}", head, check=False).strip()
            if not old:
                raise GitError(f"--since {since!r} is neither a ref nor a date with commits before it")
    if subprocess.run(["git", "merge-base", "--is-ancestor", old, head], cwd=repo.root).returncode != 0:
        raise GitError(
            f"{old[:10]} is not an ancestor of HEAD (ORIG_HEAD is overwritten by reset/rebase); pass --since explicitly"
        )
    return old


# --- version extractors: each returns {label: value} for one ref ----------------

def meson_version(repo: Repo, ref: str) -> dict[str, str]:
    text = repo.show(ref, "meson.build") or ""
    m = re.search(r"\bversion:\s*'([^']+)'", text)
    return {"project version (meson.build)": m.group(1)} if m else {}


def plugin_abi(repo: Repo, ref: str) -> dict[str, str]:
    text = repo.show(ref, "sdk/include/yuzu/plugin.h") or ""
    out = {}
    for name, val in re.findall(r"#define\s+(YUZU_PLUGIN_ABI_VERSION(?:_MIN)?)\s+(\d+)", text):
        out[f"plugin ABI ({name})"] = val
    return out


def released_version(repo: Repo, ref: str) -> dict[str, str]:
    text = repo.show(ref, "CHANGELOG.md") or ""
    m = re.search(r"^## \[(\d[^\]]*)\]", text, re.M)
    return {"latest released CHANGELOG section": m.group(1)} if m else {}


def vcpkg(repo: Repo, ref: str) -> dict[str, str]:
    text = repo.show(ref, "vcpkg.json")
    if not text:
        return {}
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return {"vcpkg.json": "unparseable at this ref"}
    out = {"vcpkg builtin-baseline": str(data.get("builtin-baseline", ""))[:10]}
    for dep in data.get("dependencies", []):
        name, constraint = (dep, "") if isinstance(dep, str) else (dep.get("name", "?"), dep.get("version>=", ""))
        out[f"vcpkg dependency {name}"] = f">={constraint}" if constraint else "(unconstrained)"
    for ov in data.get("overrides", []):
        out[f"vcpkg override {ov.get('name', '?')}"] = str(ov.get("version", ov.get("version-string", "")))
    return out


def rebar_lock(repo: Repo, ref: str) -> dict[str, str]:
    text = repo.show(ref, "gateway/rebar.lock") or ""
    return {f"gateway package {n}": v for n, v in re.findall(r'\{pkg,<<"([^"]+)">>,<<"([^"]+)">>\}', text)}


EXTRACTORS = [meson_version, released_version, plugin_abi, vcpkg, rebar_lock]


def version_changes(repo: Repo, old: str, new: str) -> list[str]:
    before: dict[str, str] = {}
    after: dict[str, str] = {}
    for fn in EXTRACTORS:
        before.update(fn(repo, old))
        after.update(fn(repo, new))
    lines = []
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
    def any_under(*prefixes: str) -> list[str]:
        return [f for f in files if f.startswith(prefixes)]

    notes = []
    dep_files = any_under("vcpkg.json", "vcpkg-configuration.json", "triplets/")
    if dep_files:
        notes.append("vcpkg manifest/triplets changed: the dependency tree under vcpkg_installed/ is stale (docs/build-guide.md)")
    for prefix, text in (
        ("proto/", "`proto/` changed (server, agent and gateway consume it): rebuild all three"),
        ("gateway/", "`gateway/` changed: rebuild the Erlang gateway (docs/erlang-gateway-build.md)"),
        ("sdk/", "`sdk/` changed: plugins build against it"),
    ):
        n = len(any_under(prefix))
        if n:
            notes.append(f"{text} ({n} files)")
    deploy = any_under("deploy/", "docker-compose")
    if deploy:
        notes.append(f"deploy/compose files changed ({len(deploy)} files): re-read them before redeploying")
    return notes


def top_level_summary(files: list[str]) -> str:
    counts = Counter(f.split("/", 1)[0] if "/" in f else "(root)" for f in files)
    return ", ".join(f"{d} {n}" for d, n in counts.most_common(8))


# --- dependency bumps (Dependabot) -------------------------------------------

DEPS_SUBJECT = r"^(build|chore)\(deps[^)]*\):"


def dependency_bumps(repo: Repo, old: str, new: str) -> tuple[list[str], list[str]]:
    """(runtime, tooling) subjects of `build(deps)` / `chore(deps)` commits in old..new.

    Runtime = the commit touches something under deploy/ (Docker base images, compose); the rest
    is CI/tooling (workflows, pip, npm). Dependabot does not manage vcpkg or rebar3, so those
    bumps come from version_changes(), not from here.
    """
    out = repo.git(
        "log", "--no-merges", "-E", f"--grep={DEPS_SUBJECT}", "--name-only",
        "--pretty=format:%x00%s", f"{old}..{new}",
    )
    runtime: list[str] = []
    tooling: list[str] = []
    for block in out.split("\x00")[1:]:
        subject, *paths = block.splitlines()
        if not re.match(DEPS_SUBJECT, subject):
            continue
        (runtime if any(p.startswith("deploy/") for p in paths) else tooling).append(subject)
    return runtime, tooling


# --- fragments ---------------------------------------------------------------

def added_fragments(repo: Repo, old: str, new: str) -> dict[str, str]:
    """{path: body} for fragments added in old..new, even if a release later removed them.

    --no-renames so a renamed fragment (placeholder id -> PR number) lists its new name as
    an add; bodies are de-duplicated afterwards.
    """
    out = repo.git(
        "log", "--no-renames", "--diff-filter=A", "--name-only", "--pretty=format:%x00%H",
        f"{old}..{new}", "--", "changelog.d/",
    )
    adds: dict[str, str] = {}  # path -> commit that added it (newest first, keep the first seen)
    commit = ""
    for line in out.splitlines():
        if line.startswith("\x00"):
            commit = line[1:]
        elif line.strip():
            adds.setdefault(line.strip(), commit)
    bodies: dict[str, str] = {}
    for path, commit in adds.items():
        if not FRAGMENT_RE.match(Path(path).name):
            continue  # README.md and anything else that is not a fragment
        body = repo.show(new, path)
        if body is None:
            body = repo.show(commit, path)
        if body and body.strip():
            bodies[path] = body.strip()
    seen: set[str] = set()
    unique: dict[str, str] = {}
    for path, body in bodies.items():
        if body not in seen:
            seen.add(body)
            unique[path] = body
    return unique


def bullets(body: str) -> list[str]:
    """Split a fragment body into its '- ' bullets (continuation lines kept)."""
    items: list[list[str]] = []
    for line in body.splitlines():
        if line.startswith("- "):
            items.append([line])
        elif items:
            items[-1].append(line)
    return ["\n".join(b).rstrip() for b in items]


def brief(bullet: str) -> str:
    first = bullet.splitlines()[0]
    return first if len(first) <= BRIEF_MAX else first[: BRIEF_MAX - 3].rstrip() + "..."


def render_fragments(frags: dict[str, str], full: bool) -> list[str]:
    by_section: dict[str, list[str]] = {s: [] for s in SECTION_ORDER}
    for path, body in sorted(frags.items()):
        section = FRAGMENT_RE.match(Path(path).name).group("section")  # type: ignore[union-attr]
        for b in bullets(body):
            by_section[section].append(b if full else brief(b))
    lines: list[str] = []
    for section in SECTION_ORDER:
        if by_section[section]:
            lines.append(f"{section.capitalize()} ({len(by_section[section])})")
            lines.extend(by_section[section])
            lines.append("")
    return lines


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="Summarise what changed in this checkout since the last pull.")
    ap.add_argument("--since", help="ref, tag, commit or date expression (default: ORIG_HEAD, set by the last pull/merge)")
    ap.add_argument("--full", action="store_true", help="print whole fragment bullets, not just their first line")
    ap.add_argument("--repo", type=Path, default=None, help=argparse.SUPPRESS)
    args = ap.parse_args(argv)

    start = args.repo or Path.cwd()
    try:
        root = Path(subprocess.run(
            ["git", "rev-parse", "--show-toplevel"], cwd=start, capture_output=True, text=True, check=True,
        ).stdout.strip())
        repo = Repo(root)
        head = repo.git("rev-parse", "HEAD").strip()
        old = resolve_since(repo, args.since, head)
    except (GitError, subprocess.CalledProcessError) as exc:
        print(f"whats-new: {exc}", file=sys.stderr)
        return 2

    count = repo.git("rev-list", "--count", f"{old}..{head}").strip()
    files = [f for f in repo.git("diff", "--name-only", f"{old}..{head}").splitlines() if f]
    print(f"Changes {old[:10]}..{head[:10]}: {count} commits, {len(files)} files ({top_level_summary(files)})")
    print()

    versions = version_changes(repo, old, head)
    print("Version bumps")
    print("\n".join(versions) if versions else "  none of the tracked versions changed")
    print()

    notes = surface_notes(files)
    if notes:
        print("Rebuild / redeploy")
        print("\n".join(f"  * {n}" for n in notes))
        print()

    runtime, tooling = dependency_bumps(repo, old, head)
    if runtime or tooling:
        print(f"Dependency bumps (Dependabot): {len(runtime)} runtime image, {len(tooling)} CI/tooling")
        print("\n".join(f"  {s}" for s in runtime))
        if args.full:
            print("\n".join(f"  {s}" for s in tooling))
        elif tooling:
            print(f"  + {len(tooling)} CI/tooling bumps (workflows, pip, npm); --full lists them")
        print()

    frags = added_fragments(repo, old, head)
    rendered = render_fragments(frags, args.full)
    if rendered:
        print(f"Changelog fragments added ({len(frags)})")
        print()
        print("\n".join(rendered).rstrip())
    else:
        print("No changelog fragments were added in this range (refactors, CI and test-only changes may skip them;")
        print("`git log --first-parent` lists every merged PR).")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
