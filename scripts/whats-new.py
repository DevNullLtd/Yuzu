#!/usr/bin/env python3
"""What changed on dev since I last pulled?

Prints, for the range OLD..HEAD of the current checkout:

  1. version bumps  - project version, plugin ABI, vcpkg baseline and
                      dependency constraints (top level and per feature), gateway
                      (rebar3) packages, latest released CHANGELOG section;
  2. surfaces touched that may need a rebuild or redeploy;
  3. dependency bumps: commits titled `build(deps):` / `chore(deps):` (Dependabot's
     title convention), which normally add no fragment and touch none of the files in 1;
  4. the changelog.d/ fragments added in the range, grouped by section.

Unreleased changes are recorded as fragments (changelog.d/README.md) and only
assembled into CHANGELOG.md at release, so this is the way to read them
collated before a release.

  python3 scripts/whats-new.py                 # since your last pull
  python3 scripts/whats-new.py --since v0.15.0 # since a tag, branch or commit
  python3 scripts/whats-new.py --since "2 weeks ago"   # ISO date or "N <unit> ago"
  python3 scripts/whats-new.py --full          # whole bullets; every non-image dep bump

"Your last pull" is read from the reflog of the branch you are on: the newest `pull`
entry that names no source or names this branch's upstream, or a `merge <upstream>`
entry after a manual fetch, and the commit the branch was on before it. `checkout`, a
local `merge` and `reset` write no pull entry, a pull on another branch is in that
branch's reflog, and `git pull <other branch>` or a merge of a different branch is not
counted, so none of them can move the base later. A pull this script does not recognise
(one stopped by a conflict and finished by hand, say) only makes the range start earlier.
The reflog is local and expires: a fresh clone has none, so pass --since.

Read-only: it runs `git` queries and changes no ref, index or file (in a partial clone, git itself may
fetch objects the range needs). All repository-sourced text
is printed with control characters replaced. Stdlib only.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import unicodedata
from collections import Counter
from datetime import datetime, timedelta
from pathlib import Path

# Breaking / operator-visible first. The grammar below mirrors scripts/assemble-changelog.py
# (FRAGMENT_NAME_RE, CANONICAL_SECTIONS); tests/test_whats_new.py asserts they agree.
SECTION_ORDER = ["security", "removed", "deprecated", "changed", "added", "fixed"]
FRAGMENT_RE = re.compile(
    r"^(?P<stem>[A-Za-z0-9][A-Za-z0-9._-]*)\.(?P<section>" + "|".join(SECTION_ORDER) + r")\.md$"
)
FRAGMENT_DIR = "changelog.d"
BRIEF_MAX = 200
# Sections whose entries are shown whole: the tail of a breaking or security entry is the
# step the reader has to take.
NEVER_TRUNCATE = {"security", "removed", "deprecated"}
DEPS_SUBJECT = r"^(build|chore)\(deps[^)]*\):"
# git's date parser accepts any string (a typo silently becomes "now"), so only unambiguous
# forms are passed to it, and an absolute date is checked against the calendar here.
DATE_RE = re.compile(
    r"^(?P<day>[0-9]{4}-[0-9]{2}-[0-9]{2})(?P<time>[ T][0-9]{2}:[0-9]{2}(:[0-9]{2})?)?$"
    r"|^(?P<yesterday>yesterday)$"
    r"|^(?P<n>[0-9]{1,4}) (?P<unit>second|minute|hour|day|week|month|year)s? ago$"
)
SHA_RE = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
# A reflog entry written by one step of a rebase, e.g. "pull --rebase origin dev (pick): msg".
REBASE_STEP_RE = re.compile(r"^(pull|rebase)\b[^:]*\((start|pick|finish|continue|fixup|squash|reword|edit|drop|abort)\b")
# Text that is not shown but can steer a terminal or hide text: control characters except \n and
# \t, and everything Unicode files under format (Cf: zero-width, bidi overrides and isolates, soft
# hyphen, word joiner, tag characters, BOM), surrogate, line and paragraph separator, plus a few
# invisible code points Unicode files elsewhere (variation selectors, fillers, combining grapheme
# joiner, object replacement).
# Variables that point git at some other repository (a hook exports them); the --repo directory
# decides which repository is read.
REPO_LOCATING_ENV = {"GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_COMMON_DIR", "GIT_OBJECT_DIRECTORY",
                     "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_NAMESPACE", "GIT_PREFIX"}
HIDDEN_CATEGORIES = {"Cc", "Cf", "Cs", "Zl", "Zp"}
HIDDEN_EXTRA_RE = re.compile(
    "[\u034f\u115f\u1160\u17b4\u17b5\u180b-\u180f\u2800\u3164\ufe00-\ufe0f\uffa0\ufffc"
    "\U000e0000-\U000e007f\U000e0100-\U000e01ef]"
)


class GitError(Exception):
    pass


def clean(text: str) -> str:
    """Replace terminal control and hidden characters in repository-sourced text."""
    return "".join(
        "?" if ch not in "\n\t" and (unicodedata.category(ch) in HIDDEN_CATEGORIES or HIDDEN_EXTRA_RE.match(ch)) else ch
        for ch in text
    )


def lines_of(text: str) -> list[str]:
    """Split on newline only. str.splitlines() also splits on \\v, \\f, \\x1c-\\x1e, \\x85 and
    U+2028/9, which lets repository text forge a record boundary."""
    return text.split("\n")


class Repo:
    def __init__(self, root: Path):
        self.root = root

    def _run(self, *args: str, stdin: str | None = None, binary: bool = False) -> subprocess.CompletedProcess:
        # Bytes in, bytes out, decoded here: text mode would turn a lone CR into a newline before
        # clean() could see it.
        try:
            # Pinned so a user's git config cannot change what is parsed (colour codes, signature
            # lines in `log`, quoted paths) and git's messages are not translated (see show()).
            proc = subprocess.run(["git", "-c", "core.quotepath=off", "-c", "color.ui=false",
                                   "-c", "log.showSignature=false", "-c", "i18n.logOutputEncoding=UTF-8", *args],
                                  cwd=self.root, capture_output=True, input=stdin.encode() if stdin is not None else None,
                                  env={**{k: v for k, v in os.environ.items() if k not in REPO_LOCATING_ENV},
                                       "LC_ALL": "C", "LANGUAGE": "C"})
        except FileNotFoundError as exc:
            if not self.root.is_dir():
                raise GitError(f"{self.root} is not a directory") from exc
            raise GitError("git was not found on PATH") from exc
        except OSError as exc:
            raise GitError(f"could not run git in {self.root}: {exc.strerror or exc}") from exc
        if not binary:
            proc.stdout = proc.stdout.decode("utf-8", "replace")
            proc.stderr = proc.stderr.decode("utf-8", "replace")
        return proc

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

    def blobs(self, specs: list[str]) -> dict[str, str | None]:
        """Contents of `<rev>:<path>` specs in one process; None for a missing one."""
        if not specs:
            return {}
        proc = self._run("cat-file", "--batch", stdin="\n".join(specs) + "\n", binary=True)
        if proc.returncode != 0:
            raise GitError(proc.stderr.decode("utf-8", "replace").strip() or "git cat-file --batch failed")
        out: dict[str, str | None] = {}
        data, pos = proc.stdout, 0
        for spec in specs:
            end = data.index(b"\n", pos)
            header = data[pos:end].decode("utf-8", "replace")
            pos = end + 1
            if header.endswith(" missing"):
                out[spec] = None
                continue
            try:
                size = int(header.rsplit(" ", 1)[1])
            except ValueError as exc:
                raise GitError(f"unexpected reply from git cat-file --batch: {header!r}") from exc
            out[spec] = data[pos:pos + size].decode("utf-8", "replace")
            pos += size + 1
        return out

    def resolves(self, rev: str) -> str | None:
        proc = self._run("rev-parse", "--verify", "--quiet", f"{rev}^{{commit}}")
        return proc.stdout.strip() or None

    def names(self, *args: str) -> list[str]:
        """NUL-separated path list from a git command run with -z."""
        return [n.strip() for n in self.git(*args).split("\0") if n.strip()]


# --- choosing the base ---------------------------------------------------------

# `git pull` options whose value is a separate argument.
PULL_VALUE_OPTIONS = {
    "-s", "--strategy", "-X", "--strategy-option", "-o", "--server-option", "-j", "--jobs", "--depth", "--deepen",
    "--cleanup", "--upload-pack", "--shallow-since", "--shallow-exclude", "--negotiation-tip", "--refmap",
}
STEP_MARK_RE = re.compile(r"\s+\((?:start|pick|finish|continue|fixup|squash|reword|edit|drop|abort)[^)]*\)\s*$")


def last_pull_base(repo: Repo) -> tuple[str, str]:
    """(commit, reflog subject) of the branch's state before its newest pull of its own upstream.

    A `pull` entry counts when it names no source, or names this branch's upstream (or, with no
    upstream configured, the branch's own name on a remote); `git pull origin fix/foo` and
    `git merge origin/dev-hotfix` do not.
    """
    ref = repo._run("symbolic-ref", "-q", "HEAD").stdout.strip()
    if not ref:
        raise GitError("HEAD is detached, so there is no branch reflog to read; pass --since <ref|date>")
    name = ref.removeprefix("refs/heads/")
    upstream = repo._run("rev-parse", "--abbrev-ref", "--symbolic-full-name", "@{upstream}").stdout.strip()
    remote = repo._run("config", f"branch.{name}.remote").stdout.strip()
    merge_ref = repo._run("config", f"branch.{name}.merge").stdout.strip().removeprefix("refs/heads/")
    own = merge_ref or name  # the branch a bare `git pull <remote>` or `git pull <remote> <branch>` must name
    entries = []
    for line in lines_of(repo.git("reflog", "show", "--format=%H%x09%gs", ref)):
        sha, _, subject = line.partition("\t")
        if SHA_RE.fullmatch(sha):
            entries.append((sha, subject))

    def is_pull(subject: str) -> bool:
        head, _, message = subject.partition(": ")  # git writes "<action and arguments>: <message>"
        if "'ours' strategy" in message:
            return False  # `-s ours` records the merge but takes none of the upstream's content
        if head.startswith("merge "):
            return bool(upstream) and head[len("merge "):] == upstream  # a merge of exactly the upstream
        if not (head == "pull" or head.startswith("pull ")):
            return False
        head = STEP_MARK_RE.sub("", head)
        positional, skip, after_dashes = [], False, False
        for token in head.split()[1:]:
            if skip:
                skip = False
            elif after_dashes or not token.startswith("-"):
                positional.append(token)
            elif token == "--":
                after_dashes = True
            elif token in PULL_VALUE_OPTIONS:
                skip = True  # the next token is this option's value, not a repository or branch
        if len(positional) > 2:
            return False
        if positional and remote and positional[0] != remote:
            return False
        # A refspec `src:dst` merges `src`; `:dst` merges the remote's HEAD, which is not this branch.
        return len(positional) < 2 or positional[1].split(":", 1)[0].removeprefix("refs/heads/") == own

    for i, (_, subject) in enumerate(entries):
        if is_pull(subject):
            j = i + 1
            if REBASE_STEP_RE.match(subject):
                # `pull --rebase` writes a run of step entries ending at its "(start)"; the base
                # precedes all of them. An earlier pull's "(finish)" ends the run.
                while j < len(entries) and REBASE_STEP_RE.match(entries[j][1]) and "(finish)" not in entries[j][1]:
                    started = "(start)" in entries[j][1]
                    j += 1
                    if started:
                        break
            if j < len(entries):
                return entries[j][0], subject
            break
    raise GitError(
        "no pull is recorded for this branch (a fresh clone, a new branch or an expired reflog has none); "
        "pass --since <ref|date>, for example --since v0.15.0 or --since \"2 weeks ago\""
    )


def _minus_months(moment: datetime, months: int) -> datetime:
    total = moment.year * 12 + (moment.month - 1) - months
    year, month = divmod(total, 12)
    if year < 1970:
        raise GitError("that date is before 1970, earlier than any commit")
    month += 1
    # Clamp the day (31 March minus one month is the last day of February).
    for day in (moment.day, 30, 29, 28):
        try:
            return moment.replace(year=year, month=month, day=day)
        except ValueError:
            continue
    raise GitError("that date is not representable")  # unreachable


def _back(now: datetime, delta: timedelta) -> datetime:
    """`now` minus an elapsed duration: absolute time, so a daylight-saving change inside the span
    counts as the hour it is (naive wall-clock subtraction would be an hour out)."""
    try:
        return (now.astimezone() - delta).astimezone().replace(tzinfo=None)
    except (OSError, OverflowError, ValueError) as exc:  # before the epoch (Windows), or out of range
        raise GitError("that date is before 1970, earlier than any commit") from exc


def date_cutoff(since: str, now: datetime | None = None) -> str:
    """The argument for `git rev-list --before=` for a validated date expression.

    A relative form is worked out here, against `now`, so git's own parser (which reads
    anything it cannot parse as "now") never sees it.
    """
    m = DATE_RE.fullmatch(since)
    if not m:
        raise GitError(
            f"--since {since!r} is not a ref in this repository; for a date use YYYY-MM-DD, "
            "\"YYYY-MM-DD HH:MM\", yesterday or \"N days ago\" (N up to 4 digits; seconds, minutes, hours, "
            "days, weeks, months or years)"
        )
    if m.group("day"):
        if not 1970 <= int(m.group("day")[:4]) <= 2099:
            raise GitError(f"--since {since!r}: git dates the history between 1970 and 2099")
        text = since.replace("T", " ")
        for fmt in ("%Y-%m-%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d"):
            try:
                parsed = datetime.strptime(text, fmt)
                break
            except ValueError:
                continue
        else:
            raise GitError(f"--since {since!r} is not a real calendar date or time")
        if parsed < datetime(1970, 1, 3):
            # East of UTC the first days of 1970 are a negative timestamp, which git reads as "now".
            raise GitError(f"--since {since!r} is earlier than any commit")
        # git fills a missing time of day with the current clock time; a bare date means its start.
        return since if m.group("time") else since + " 00:00:00"
    now = now or datetime.now()
    if m.group("yesterday"):
        moment = _back(now, timedelta(days=1))
    else:
        n, unit = int(m.group("n")), m.group("unit")
        if unit in ("month", "year"):
            moment = _minus_months(now, n * (12 if unit == "year" else 1))  # calendar arithmetic, as git does
        else:
            moment = _back(now, timedelta(**{unit + "s": n}))
    if moment.year < 1970:
        raise GitError(f"--since {since!r} is before 1970, earlier than any commit")
    return moment.strftime("%Y-%m-%d %H:%M:%S")


def resolve_base(repo: Repo, since: str | None, head: str) -> tuple[str, str, str | None]:
    """(base commit, how it was chosen, the reflog entry it came from when it was the last pull)."""
    via = None
    if since is None:
        (old, via), how = last_pull_base(repo), "your last pull"
    else:
        old, how = repo.resolves(since), since
        if not old:
            old = repo.git("rev-list", "-1", f"--before={date_cutoff(since)}", head).strip()
            if not old:
                shallow = repo.git("rev-parse", "--is-shallow-repository").strip() == "true"
                raise GitError(f"no commit is older than {since!r}"
                               + (" (this is a shallow clone: history before the cut-off is missing)" if shallow else ""))
    if not repo.ok("merge-base", "--is-ancestor", old, head):
        if since is not None:
            raise GitError(f"{old[:10]} ({since}) is not an ancestor of HEAD; pick a ref on this branch's history")
        # After `git pull --rebase` the old tip is not an ancestor; the merge-base is what was shared.
        base = repo.git("merge-base", old, head).strip()
        if not base:
            raise GitError("the commit before your last pull shares no history with HEAD; pass --since")
        old, how = base, "your last pull (rebased onto it; range starts at the common ancestor)"
    if old == head:
        raise GitError(f"{how}: HEAD has not moved since then, so there is nothing to compare; "
                       + ("use an earlier --since" if since is not None else "pass --since to look further back"))
    return old, how, via


# --- version extractors: each returns {label: value} for one ref ----------------
# A parse problem raises ValueError, reported as a line of its own; it never reads as "no change".

def meson_version(repo: Repo, ref: str) -> dict[str, str]:
    text = repo.show(ref, "meson.build") or ""
    m = re.search(r"\bversion:\s*'([^'\n]+)'", text)
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
        except (ValueError, RecursionError) as exc:
            # Compared as a whole or not at all: half a comparison would print the whole file as added or removed.
            reason = str(exc) if isinstance(exc, ValueError) else "nested too deeply"
            lines.append(f"  ! {fn.__name__} not compared: {reason}")
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
        subject, *paths = lines_of(block)
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
    # As `assemble-changelog.py promote` reads a fragment (read_text().strip()): universal
    # newlines, outer whitespace dropped. Only then split on "\n".
    for line in lines_of(body.replace("\r\n", "\n").replace("\r", "\n").strip()):
        if line.startswith("- "):
            items.append([line])
        elif items:
            items[-1].append(line)
    return ["\n".join(b).rstrip() for b in items]


def _rename_pairs(repo: Repo, old: str, new: str) -> dict[str, tuple[str, int]]:
    """{destination: (source, similarity)} for every fragment rename a commit in old..new made.

    Read from the history, not the net diff: a net diff pairs a deletion in one commit with an
    unrelated addition in another when their bytes match, and then a genuinely new fragment would
    read as a rename of the deleted one.
    """
    out = repo.git("log", "-m", "-z", "-M", "--diff-filter=R", "--name-status", "--format=",
                   f"{old}..{new}", "--", FRAGMENT_DIR + "/")
    toks = [t.lstrip("\n") for t in out.split("\x00")]
    pairs: dict[str, tuple[str, int]] = {}
    i = 0
    while i + 2 < len(toks) and toks[i][:1] == "R":
        score = int(toks[i][1:] or 0) if toks[i][1:].isdigit() else 0
        src, dst = toks[i + 1], toks[i + 2]
        if dst not in pairs or score > pairs[dst][1]:
            pairs[dst] = (src, score)
        i += 3
    return pairs


def added_fragments(repo: Repo, old: str, new: str) -> dict[str, str]:
    """{path: body} for the fragments this range adds.

    A fragment counts when it exists at `new` and did not at `old` (the net diff, so a rewording
    or revert inside the range cannot list one change twice or list a withdrawn one). A fragment
    that only reached `new` through commits that each renamed it UNCHANGED (git's 100% similarity)
    from a path that existed at `old` is not an add: the reader already has that entry. A deletion
    in one commit and a byte-identical addition in another is not a rename, so that addition counts.

    A fragment a release promoted inside the range counts too: it was added after `old`, is gone
    at `new`, and its last body's first line is a line this range added to CHANGELOG.md. A path
    that existed at `old`, was deleted and added back with different text counts as added.
    """
    pathspec = FRAGMENT_DIR + "/"
    net = [p for p in repo.names("diff", "-z", "--no-renames", "--diff-filter=A", "--name-only", old, new, "--", pathspec)
           if _fragment_path_ok(p)]
    # -m so adds made inside merge commits are seen too. A fragment that already existed at `old`
    # can show up here (a merge diffs against its side parent), so each is checked against both ends.
    ever = [p for p in dict.fromkeys(repo.names("log", "-m", "-z", "--no-renames", "--diff-filter=A", "--name-only",
                                                "--format=", f"{old}..{new}", "--", pathspec))
            if _fragment_path_ok(p)]
    changed = [p for p in repo.names("diff", "-z", "--no-renames", "--diff-filter=M", "--name-only", old, new, "--", pathspec)
               if _fragment_path_ok(p) and p in ever]
    if not (net or ever or changed):
        return {}
    tree_old = set(lines_of(repo.git("ls-tree", "-r", "--name-only", old, "--", pathspec)))
    tree_new = set(lines_of(repo.git("ls-tree", "-r", "--name-only", new, "--", pathspec)))
    renames = _rename_pairs(repo, old, new) if (net or ever) else {}

    def old_root(path: str) -> str | None:
        """The path at `old` that `path` reached by renames git saw as 100% identical, if any."""
        seen = {path}
        while True:
            pair = renames.get(path)
            if pair is None or pair[1] != 100 or pair[0] in seen:
                return None
            path = pair[0]
            if path in tree_old:
                return path
            seen.add(path)

    # A fragment that is byte-for-byte what a renamed-from path held at `old` is the entry the reader
    # already has; one reworded after the rename is not.
    roots = {p: r for p in net if (r := old_root(p)) is not None}
    old_bodies = repo.blobs([f"{old}:{r}" for r in set(roots.values())])
    found: dict[str, str] = {}
    for spec, body in repo.blobs([f"{new}:{p}" for p in net]).items():
        path = spec.split(":", 1)[1]
        if body is not None and not (path in roots and old_bodies.get(f"{old}:{roots[path]}") == body):
            found[path] = body

    gone = [p for p in ever if p not in tree_old and p not in tree_new]
    if not (gone or changed):
        return found
    # The newest deleting commit of each path, in one pass.
    deleter: dict[str, str] = {}
    for block in repo.git("log", "--no-renames", "--diff-filter=D", "--name-only", "--format=%x00%H",
                          f"{old}..{new}", "--", pathspec).split("\x00")[1:]:
        sha, *paths = lines_of(block)
        for p in paths:
            if p:
                deleter.setdefault(p, sha)
    # A path that existed at `old`, was deleted in the range and is back with different text.
    readded = [p for p in changed if p in deleter and p not in found]
    for spec, body in repo.blobs([f"{new}:{p}" for p in readded]).items():
        if body is not None:
            found[spec.split(":", 1)[1]] = body

    # A renamed fragment is represented by the path it ended at, so one that was renamed on is
    # never a candidate itself (else a rename plus an edit lists it twice, or under two sections).
    renamed_on = {src for src, _ in renames.values()}
    gone = [p for p in gone if p not in renamed_on]
    if not gone:
        return found
    changelog_added = {
        line[1:].rstrip() for line in lines_of(repo.git("diff", "-U0", "--text", "--no-color", "--no-ext-diff", "--no-textconv", old, new, "--", "CHANGELOG.md"))
        if line.startswith("+") and not line.startswith("+++")
    }
    specs = {p: f"{deleter[p]}^:{p}" for p in gone if p in deleter}
    bodies = repo.blobs(list(specs.values()))
    gone_roots = {p: r for p in specs if (r := old_root(p)) is not None}
    gone_old = repo.blobs([f"{old}:{r}" for r in set(gone_roots.values())])
    for path, spec in specs.items():
        body = bodies.get(spec)
        if path in gone_roots and gone_old.get(f"{old}:{gone_roots[path]}") == body:
            continue  # promoted unchanged since the rename: the reader had it at `old`
        first = bullets(body)[:1] if body else []
        line = first[0].split("\n")[0].rstrip() if first else ""
        if line and line in changelog_added:
            found[path] = body
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
            first = b.split("\n")[0]
            if full or section in NEVER_TRUNCATE or first.lower().startswith("- **breaking"):
                shown = b
            elif len(first) > BRIEF_MAX:
                shown = first[: BRIEF_MAX - 3].rstrip() + "..."
            else:
                shown = first
            by_section[section].append(shown)
    lines: list[str] = []
    for section in SECTION_ORDER:
        if by_section[section]:
            lines.append(f"{section.capitalize()} ({len(by_section[section])})")
            lines.extend(by_section[section])
            lines.append("")
    return lines, total, empty


def build_report(repo: Repo, since: str | None, full: bool) -> list[str]:
    head = repo.git("rev-parse", "HEAD").strip()
    old, how, via = resolve_base(repo, since, head)
    count = repo.git("rev-list", "--count", f"{old}..{head}").strip()
    files = repo.names("diff", "-z", "--no-renames", "--name-only", old, head)
    out = [
        f"Changes since {how}: {count} commits, {len(files)} files ({top_level_summary(files)})",
        f"Base {repo.git('log', '-1', '--format=%h %cs %s', old).strip()}",
        f"Head {repo.git('log', '-1', '--format=%h %cs %s', head).strip()}",
    ]
    if via is not None:
        out.append(f"Via  reflog entry: {via}")
    out.append("")

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
        out.append(f"Dependency bumps (build(deps)/chore(deps) commits): {len(images)} Docker "
                   f"image{'' if len(images) == 1 else 's'}, {len(other)} other")
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
        out.append(f"`git log --first-parent --oneline {old[:10]}..HEAD` lists every merged PR).")
    if empty:
        out.append(f"! {len(empty)} fragment(s) had no '- ' bullet and are not summarised: {', '.join(empty)}")
    return out


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="Summarise what changed in this checkout since the last pull.")
    ap.add_argument("--since", help="ref, tag or commit, or a date (YYYY-MM-DD[ HH:MM], yesterday, \"N days ago\"); default: your last pull")
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
    if sys.stdout is None:  # started with stdout closed (`>&-`)
        return 0
    try:
        print("\n".join(clean(line) for line in report).rstrip())
        sys.stdout.flush()
    except BrokenPipeError:  # `| head`
        os.dup2(os.open(os.devnull, os.O_WRONLY), sys.stdout.fileno())
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
