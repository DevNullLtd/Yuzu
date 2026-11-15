#!/usr/bin/env python3
"""What changed on dev since I last pulled?

Prints, for the range OLD..HEAD of the current checkout:

  1. version bumps  - project version, plugin ABI, vcpkg baseline and
                      dependency constraints (top level and per feature), gateway
                      (rebar3) packages, latest released CHANGELOG section;
  2. surfaces touched that may need a rebuild or redeploy;
  3. dependency bumps: commits titled `build(deps):` / `chore(deps):` (Dependabot's
     title convention), which normally add no fragment and touch none of the files in 1;
  4. the changelog.d/ fragments added in the range, grouped by section. The header counts the entries
     that start `**Breaking`; the heading counts those a release in the range already moved into
     CHANGELOG.md, and each of those ends `[released X]` (the version section its line is under at HEAD)
     or `[released]` (that version cannot be told, say because the release notes were reworded).
     An entry with no marker was not moved by a release in the range.

`--versions` prints the header, 1, 2 and the Docker image bumps, and still prints a `!` line for any
fragment it could not read.

Unreleased changes are recorded as fragments (changelog.d/README.md) and only
assembled into CHANGELOG.md at release, so this is the way to read them
collated before a release.

  python3 scripts/whats-new.py                 # since your last pull
  python3 scripts/whats-new.py --since v0.15.0 # since a tag, branch or commit
  python3 scripts/whats-new.py --since "2 weeks ago"   # ISO date or "N <unit> ago"
  python3 scripts/whats-new.py --full          # whole bullets; every non-image dep bump
  python3 scripts/whats-new.py --versions      # only version bumps, rebuild notes and Docker image bumps

"Your last pull" is read from the reflog of the branch you are on: the newest `pull`
entry that names no source or names this branch's upstream, or a `merge <upstream>`
entry after a manual fetch, and the commit the branch was on before it. `checkout`, a
local `merge` and `reset` write no pull entry, a pull on another branch is in that
branch's reflog, and `git pull <other branch>` or a merge of a different branch is not
counted, nor is a merge or pull made with `-s ours`, so none of them can move the base later.
A pull this script does not recognise (one stopped by a conflict and finished by hand, say)
only makes the range start earlier. A `git pull` that finds nothing new writes no entry, so
the range then still starts at the earlier pull that did. The reflog is local and expires: a
fresh clone has none, so pass --since.

Read-only: it runs `git` queries and changes no ref, index or file (in a partial clone, git itself may
fetch objects the range needs). All repository-sourced text is printed with control characters
(other than newline and tab) and invisible format characters (zero-width joiners, variation
selectors, bidi marks) replaced by `?`, so an emoji sequence can show one. Stdlib only, Python 3.9 or later.
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
    r"^(?P<stem>[A-Za-z0-9][A-Za-z0-9._-]*)\.(?P<section>" + "|".join(SECTION_ORDER) + r")\.md\Z"
)
FRAGMENT_DIR = "changelog.d"
# A fragment is a few lines; a larger file is not read (a hostile history could otherwise make this allocate without bound).
MAX_FRAGMENT_BYTES = 1 << 20
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
# Variables that point git at some other repository (a hook exports them); the working directory
# (or the hidden --repo option) decides which repository is read.
REPO_LOCATING_ENV = {"GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_COMMON_DIR", "GIT_OBJECT_DIRECTORY",
                     "GIT_ALTERNATE_OBJECT_DIRECTORIES", "GIT_NAMESPACE", "GIT_PREFIX"}
# Text that is not shown but can steer a terminal or hide text: control characters except \n and
# \t, and everything Unicode files under format (Cf: zero-width, bidi overrides and isolates, soft
# hyphen, word joiner, tag characters, BOM), surrogate, line and paragraph separator, plus a few
# invisible code points Unicode files elsewhere (variation selectors, fillers, combining grapheme
# joiner, object replacement) and the unassigned code points in the default-ignorable blocks.
HIDDEN_CATEGORIES = {"Cc", "Cf", "Cs", "Zl", "Zp"}
HIDDEN_EXTRA_RE = re.compile(
    "[\u034f\u115f\u1160\u17b4\u17b5\u180b-\u180f\u2065\u2800\u3164\ufe00-\ufe0f\uffa0"
    "\ufff0-\ufff8\ufffc\U000e0000-\U000e0fff]"
)


class GitError(Exception):
    pass


def clean(text: str) -> str:
    """Replace terminal control and hidden characters in repository-sourced text."""
    return "".join(
        "?" if ch not in "\n\t" and (unicodedata.category(ch) in HIDDEN_CATEGORIES or HIDDEN_EXTRA_RE.match(ch)) else ch
        for ch in text
    )


def one(text: str) -> str:
    """Repository-sourced text for a single output line: a newline in it would start a line the
    report did not write (a forged heading or an all-clear line)."""
    return text.replace("\n", "?")


def lines_of(text: str) -> list[str]:
    """Split on newline only. str.splitlines() also splits on \\v, \\f, \\x1c-\\x1e, \\x85 and
    U+2028/9, which lets repository text forge a record boundary."""
    return text.split("\n")


class Repo:
    def __init__(self, root: Path):
        self.root = root
        # Paths `blobs` found to be something other than a file (a submodule, a tree): never listed.
        self.not_regular: list[str] = []
        # Fragment files over MAX_FRAGMENT_BYTES, which `blobs` does not read.
        self.too_big: list[str] = []

    def _run(self, *args: str, stdin: str | None = None, binary: bool = False) -> subprocess.CompletedProcess:
        # Bytes in, bytes out, decoded here: text mode would turn a lone CR into a newline before
        # clean() could see it.
        try:
            # Pinned so a user's git config cannot change what is parsed (colour codes, signature
            # lines in `log`, quoted paths) and git's messages are not translated (see show()).
            proc = subprocess.run(["git", "-c", "core.quotepath=off", "-c", "color.ui=false",
                                   "-c", "log.showSignature=false", "-c", "log.mailmap=false", "-c", "i18n.logOutputEncoding=UTF-8", *args],
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

    def blobs(self, specs: list[str], required: bool = True) -> dict[str, str | None]:
        """Contents of `<rev>:<path>` specs; None for something that is not a file, or too big to read.

        Every caller names an object the history says exists, so a missing one (a damaged
        repository, a partial clone that may not fetch) raises: skipping it would print "nothing
        changed". `required=False` returns None for it instead. The sizes are asked for first
        and each distinct object is read once, so a fragment added and deleted many times, or a
        huge one, cannot make this read an unbounded amount.
        """
        if not specs:
            return {}
        proc = self._run("cat-file", "--batch-check", stdin="\n".join(specs) + "\n", binary=True)
        if proc.returncode != 0:
            raise GitError(proc.stderr.decode("utf-8", "replace").strip() or "git cat-file --batch-check failed")
        headers = proc.stdout.decode("utf-8", "replace").split("\n")
        if len(headers) < len(specs):
            raise GitError("unexpected reply from git cat-file --batch-check")
        out: dict[str, str | None] = {spec: None for spec in specs}
        oids: dict[str, str] = {}
        for spec, header in zip(specs, headers):
            path = spec.split(":", 1)[1]
            if header.endswith(" missing"):
                if required:
                    raise GitError(f"could not read {path} at {spec.split(':', 1)[0][:10]}: object missing")
                continue
            fields = header.split(" ")
            if len(fields) == 2 and fields[1] == "submodule":  # a gitlink: no content
                self.not_regular.append(path)
                continue
            try:
                size = int(fields[-1])
            except ValueError as exc:
                raise GitError(f"unexpected reply from git cat-file --batch-check: {header!r}") from exc
            if len(fields) == 3 and fields[1] != "blob":  # a tree or a commit where a file was expected
                self.not_regular.append(path)
            elif size > MAX_FRAGMENT_BYTES:
                self.too_big.append(path)
            else:
                oids[spec] = fields[0]
        if not oids:
            return out
        distinct = list(dict.fromkeys(oids.values()))
        proc = self._run("cat-file", "--batch", stdin="\n".join(distinct) + "\n", binary=True)
        if proc.returncode != 0:
            raise GitError(proc.stderr.decode("utf-8", "replace").strip() or "git cat-file --batch failed")
        texts: dict[str, str] = {}
        data, pos = proc.stdout, 0
        for oid in distinct:
            end = data.index(b"\n", pos)
            header = data[pos:end].decode("utf-8", "replace")
            pos = end + 1
            try:
                size = int(header.split(" ")[-1])
            except ValueError as exc:
                raise GitError(f"unexpected reply from git cat-file --batch: {header!r}") from exc
            texts[oid] = data[pos:pos + size].decode("utf-8", "replace")
            pos += size + 1
        for spec, oid in oids.items():
            out[spec] = texts[oid]
        return out

    def resolves(self, rev: str) -> str | None:
        proc = self._run("rev-parse", "--verify", "--quiet", f"{rev}^{{commit}}")
        return proc.stdout.strip() or None

    def names(self, *args: str) -> list[str]:
        """NUL-separated path list from a git command run with -z."""
        # Not stripped: a path may end in a newline, and a stripped name is a path that does not exist.
        # The newline git puts at the start of a record is not part of a path.
        return [n for n in (t.lstrip("\n") for t in self.git(*args).split("\0")) if n]


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
        raise GitError("--since: that date is before 3 January 1970, earlier than any commit")
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
        raise GitError("--since: that date is before 3 January 1970, earlier than any commit") from exc


def date_cutoff(since: str, now: datetime | None = None) -> str:
    """The argument for `git rev-list --before=` for a validated date expression.

    A relative form is worked out here, against `now`, so git's own parser (which reads
    anything it cannot parse as "now") never sees it.
    """
    m = DATE_RE.fullmatch(since)
    if not m:
        raise GitError(
            f"--since {since!r} is not a ref in this repository; for a date use YYYY-MM-DD, "
            "\"YYYY-MM-DD HH:MM\", yesterday or \"N days ago\" (N up to 4 digits; the unit is lowercase: seconds, "
            "minutes, hours, days, weeks, months or years)"
        )
    if m.group("day"):
        if not 1970 <= int(m.group("day")[:4]) <= 2099:
            raise GitError(f"--since {since!r}: the year must be 1970 to 2099")
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
            # East of UTC a moment early on 1 January 1970 is a negative timestamp, which git can read as
            # "now"; the floor is two days later to stay clear of every time zone.
            raise GitError(f"--since {since!r} is before 3 January 1970, earlier than any commit")
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
    if moment < datetime(1970, 1, 3):
        raise GitError(f"--since {since!r} is before 3 January 1970, earlier than any commit")
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
        raise GitError((f"{how} is HEAD itself" if since is not None and repo.resolves(since) == head else f"{how}: HEAD has not moved since then")
                       + ", so there is nothing to compare; "
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


RELEASED_KEY = "latest released CHANGELOG section"


def released_version(repo: Repo, ref: str) -> dict[str, str]:
    text = repo.show(ref, "CHANGELOG.md") or ""
    m = re.search(r"^## \[(\d[^\]\n]*)\]", text, re.M)
    return {RELEASED_KEY: m.group(1)} if m else {}


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
EXTRACTOR_LABELS = {"meson_version": "meson.build version", "released_version": "CHANGELOG.md release header",
                    "plugin_abi": "sdk/include/yuzu/plugin.h", "vcpkg": "vcpkg.json", "rebar_lock": "gateway/rebar.lock"}


def version_changes(repo: Repo, old: str, new: str) -> list[str]:
    lines: list[str] = []
    for fn in EXTRACTORS:
        try:
            before, after = fn(repo, old), fn(repo, new)
        except (ValueError, RecursionError) as exc:
            # Compared as a whole or not at all: half a comparison would print the whole file as added or removed.
            reason = str(exc) if isinstance(exc, ValueError) else "nested too deeply"
            lines.append(f"  ! {EXTRACTOR_LABELS.get(fn.__name__, fn.__name__)} not compared: {one(reason)}")
            continue
        for key in sorted(set(before) | set(after)):
            b, a = before.get(key), after.get(key)
            if b == a:
                continue
            # A version heading is repository text of any length: compared whole, cut only for display.
            show = cut_version if key == RELEASED_KEY else one
            key = one(key)
            if b is None:
                lines.append(f"  + {key}: {show(a)}  (new)")
            elif a is None:
                lines.append(f"  - {key}: {show(b)}  (removed)")
            else:
                lines.append(f"  ~ {key}: {show(b)} -> {show(a)}")
    return lines


# --- touched surfaces --------------------------------------------------------

def plural(n: int, word: str) -> str:
    return f"{n} {word}{'' if n == 1 else 's'}"


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
            notes.append(f"{text} ({plural(n, 'file')})")
    deploy = under("deploy/", "docker-compose")
    if deploy:
        notes.append(f"deploy/compose files changed ({plural(len(deploy), 'file')}): re-read them before redeploying")
    return notes


def top_level_summary(files: list[str]) -> str:
    counts = Counter(f.split("/", 1)[0] if "/" in f else "(root)" for f in files)
    return ", ".join(f"{one(d)} {n}" for d, n in counts.most_common(8))


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
    return FRAGMENT_RE.match(path.split("#", 1)[0].rsplit("/", 1)[-1]).group("section")  # type: ignore[union-attr]


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


def _records(out: str) -> list[tuple[str, list[str], list[str]]]:
    """[(commit sha, parent shas, NUL-separated tokens)] from `git log -z --format=%x01%H %P`.

    With -m a merge commit appears once per parent, each time with the changes against that parent."""
    recs: list[tuple[str, list[str], list[str]]] = []
    for tok in out.split("\0"):
        if tok[:1] == "\x01":
            sha, _, rest = tok[1:].partition(" ")
            parents = rest.split()
            if SHA_RE.fullmatch(sha) and all(SHA_RE.fullmatch(x) for x in parents):
                recs.append((sha, parents, []))
                continue
        if recs:
            recs[-1][2].append(tok.lstrip("\n") if not recs[-1][2] else tok)
    return recs


def _rename_pairs(repo: Repo, old: str, new: str) -> tuple[dict[str, tuple[str, int]], dict[tuple[str, str], tuple[str, int]]]:
    """({destination: (source, similarity)}, {(commit, source): (destination, similarity)}) for every
    fragment rename a commit in old..new made.

    Read from the history, not the net diff: a net diff pairs a deletion in one commit with an
    unrelated addition in another when their bytes match, and then a genuinely new fragment would
    read as a rename of the deleted one. The (commit, source) map says which deletions were the
    source half of a rename, so a path that is later reused is not mistaken for the renamed one.
    A name that is not a fragment name on either side is not a fragment rename: the reader never
    had a fragment under it.
    """
    out = repo.git("log", "--full-history", "-m", "-z", "-M", "--diff-filter=R", "--name-status", "--format=%x01%H %P",
                   f"{old}..{new}", "--", FRAGMENT_DIR + "/")
    # (commit, source, destination) -> the similarity it had against each parent that showed it.
    seen: dict[tuple[str, str, str], list[int]] = {}
    parent_count: dict[str, int] = {}
    for sha, parents, toks in _records(out):
        parent_count[sha] = max(len(parents), 1)
        i = 0
        while i + 2 < len(toks):
            if toks[i][:1] != "R":
                i += 1
                continue
            score = int(toks[i][1:]) if toks[i][1:].isdigit() else 0
            src, dst = toks[i + 1], toks[i + 2]
            i += 3
            if _fragment_path_ok(src) and _fragment_path_ok(dst):
                seen.setdefault((sha, src, dst), []).append(score)
    pairs: dict[str, tuple[str, int]] = {}
    sources: dict[tuple[str, str], tuple[str, int]] = {}
    for (sha, src, dst), scores in seen.items():
        # A merge's diff against one parent can pair a deletion with an addition that other parent
        # already had; only a rename that every parent's diff shows is the merge's own.
        if len(scores) < parent_count[sha]:
            continue
        score = min(scores)
        if (sha, src) not in sources or score > sources[(sha, src)][1]:
            sources[(sha, src)] = (dst, score)
        if dst not in pairs or score > pairs[dst][1]:
            pairs[dst] = (src, score)
    return pairs, sources


def unrecognised_names(repo: Repo, old: str, new: str) -> list[str]:
    """Files this range adds under changelog.d/ that are not named like fragments (README.md and
    .gitkeep aside)."""
    pathspec = FRAGMENT_DIR + "/"
    return [p for p in repo.names("diff", "-z", "--no-renames", "--diff-filter=A", "--name-only", old, new, "--", pathspec)
            if not _fragment_path_ok(p) and p not in (f"{FRAGMENT_DIR}/README.md", f"{FRAGMENT_DIR}/.gitkeep")]


class Fragments(dict):
    """{key: body}; `promoted` holds the keys of entries a release moved into CHANGELOG.md, and `released` maps
    each to {first line of a bullet the release carried: the version section it sits under at the end of the
    range ("" when that is not findable)}. A bullet the release editor dropped is not in it."""

    def __init__(self) -> None:
        super().__init__()
        self.promoted: set[str] = set()
        self.released: dict[str, dict[str, str]] = {}
        # Fragments a merge-commit release removed whose text matched no line the range added to CHANGELOG.md.
        self.unmatched: list[str] = []


def release_sections(changelog: str | None) -> dict[str, str | None]:
    """{line: version} for the lines of a CHANGELOG.md, the version being that of the `## [X]` heading above it.

    None when the line is only under `[Unreleased]`, where nothing has been released. "" when the version cannot
    be told: the line is before any heading, under a column-0 `#` or `##` heading that is not `## [X]`, or under
    more than one version (a generic bullet repeated across releases). Headings are read the way
    scripts/assemble-changelog.py reads them, so a sample heading inside a code fence counts as a heading."""
    sections: dict[str, str | None] = {}
    version: str | None = ""
    for line in lines_of((changelog or "").removeprefix("\ufeff")):
        if re.match(r"#{1,2}(?:[ \t\r]|$)", line):
            m = re.match(r"## \[([^\]\n]*)\]", line)
            name = m.group(1).strip() if m else ""
            version = None if name.lower() == "unreleased" else name
            continue
        if line.strip():
            key = line.rstrip()
            if key not in sections:
                sections[key] = version
            elif sections[key] != version:
                sections[key] = ""
    return sections


def added_fragments(repo: Repo, old: str, new: str) -> dict[str, str]:
    """{path: body} for the fragments this range adds.

    A fragment counts when it exists at `new` and did not at `old` (the net diff, so a rewording
    or revert inside the range cannot list one change twice or list a withdrawn one). A fragment
    that only reached `new` through commits that each renamed it UNCHANGED (git's 100% similarity)
    from a path that existed at `old` is not an add: the reader already has that entry. A deletion
    in one commit and a byte-identical addition in another is not a rename, so that addition counts.

    A fragment a release promoted inside the range counts too: the commit that deleted it is not the
    source half of a rename, and its body's first line is a line a commit in the range added to
    CHANGELOG.md. Every life of a path is considered, so a name reused after a promotion is listed
    each time. A path that existed at `old`, was deleted and added back with different text counts
    as added; its first life is the entry the reader already has. A key of the result is the path,
    or `path#<commit>` for a second life of the same path.
    """
    pathspec = FRAGMENT_DIR + "/"
    # A and T: a name that was a submodule or a link at `old` and is a file now is a type change.
    net = [p for p in repo.names("diff", "-z", "--no-renames", "--diff-filter=AT", "--name-only", old, new, "--", pathspec)
           if _fragment_path_ok(p)]
    # -m so adds made inside merge commits are seen too. A fragment that already existed at `old`
    # can show up here (a merge diffs against its side parent), so each is checked against both ends.
    ever: set[str] = set()
    # path -> the newest ordinary commit (one parent) of the range that added it / that added or changed it. A merge
    # "adds" whatever the parent it is diffed against lacks, and a root commit (a shallow clone's boundary) adds the
    # whole tree, so neither counts.
    added_by: dict[str, str] = {}
    touched_by: dict[str, str] = {}
    for sha, parents, toks in _records(repo.git("log", "--full-history", "-m", "-z", "--no-renames", "--diff-filter=AMT", "--name-status",
                                                "--format=%x01%H %P", f"{old}..{new}", "--", pathspec)):
        for i in range(0, len(toks) - 1, 2):
            status, p = toks[i][:1], toks[i + 1]
            if not _fragment_path_ok(p):
                continue
            if status in "AT":
                ever.add(p)
            if len(parents) == 1:
                touched_by.setdefault(p, sha)
                if status in "AT":
                    added_by.setdefault(p, sha)
    changed = [p for p in repo.names("diff", "-z", "--no-renames", "--diff-filter=MT", "--name-only", old, new, "--", pathspec)
               if _fragment_path_ok(p) and p in ever]
    # Every commit that deleted a fragment path, newest first. Not -m: a merge of a stale branch
    # "deletes" every fragment that branch still has and the trunk already released.
    deleters: dict[str, list[str]] = {}
    parents_of: dict[str, list[str]] = {}
    for sha, parents, toks in _records(repo.git("log", "--full-history", "-z", "--no-renames", "--diff-filter=D", "--name-only",
                                                "--format=%x01%H %P", f"{old}..{new}", "--", pathspec)):
        parents_of[sha] = parents
        for p in toks:
            if p and _fragment_path_ok(p) and sha not in deleters.setdefault(p, []):
                deleters[p].append(sha)
    if not (net or changed or deleters or ever):
        return {}
    tree_old = set(repo.names("ls-tree", "-r", "-z", "--name-only", old, "--", pathspec))
    renames, rename_sources = _rename_pairs(repo, old, new)
    renamed_away = {src for _, src in rename_sources}
    # Added in the range, gone at its end, and no commit deleted it: a merge commit removed it (a release
    # branch that merges `dev`, promotes and drops the fragments in the merge). Its text is read from the newest ordinary
    # commit that changed it, which is the wording a release promoted unless the merge itself reworded it.
    orphans = {p: touched_by[p] for p in added_by
               if p not in net and p not in tree_old and p not in deleters and p not in renamed_away}

    def old_root(path: str) -> str | None:
        """The path at `old` that `path` reached by renames git saw as 100% identical, if any.

        A rename into security, removed or deprecated is a reclassification the reader has not
        seen, so it ends the chain; a move between the other sections is the same entry."""
        seen = {path}
        while True:
            pair = renames.get(path)
            if pair is None or pair[1] != 100 or pair[0] in seen or (section_of(pair[0]) != section_of(path) and section_of(path) in NEVER_TRUNCATE):
                return None
            path = pair[0]
            if path in tree_old:
                return path
            seen.add(path)

    def reference(path: str) -> str | None:
        """The path whose text at `old` the reader already has for `path`, if there is one."""
        return path if path in tree_old else old_root(path)

    found = Fragments()
    net_refs = {p: r for p in net if (r := reference(p)) is not None}
    # What the reader already has under a renamed-from path is not new; a rename plus a reword is.
    old_bodies = repo.blobs([f"{old}:{r}" for r in set(net_refs.values())])
    for spec, body in repo.blobs([f"{new}:{p}" for p in net]).items():
        path = spec.split(":", 1)[1]
        if body is not None and not (path in net_refs and old_bodies[f"{old}:{net_refs[path]}"] == body):
            found[path] = body

    # A path that existed at `old`, was deleted in the range and is back with different text.
    readded = [p for p in changed if p in deleters and p not in found]
    for spec, body in repo.blobs([f"{new}:{p}" for p in readded]).items():
        if body is not None:
            found[spec.split(":", 1)[1]] = body

    # Promoted: a life of a path ended by a deletion that was not the source half of a rename.
    # The first life of a path that existed at `old` is the reader's own entry, so its deletion is skipped.
    # A deletion that git paired with an addition at less than 100% similarity is a rename only when
    # the addition kept the first bullet: a release that deletes a fragment and adds a similar one
    # in the same commit is a promotion (checked below), not a rename.
    ended: list[tuple[str, str]] = []
    inexact: dict[tuple[str, str], str] = {}
    for p, shas in deleters.items():
        for sha in (shas[:-1] if p in tree_old else shas):
            hit = rename_sources.get((sha, p))
            if hit is None:
                ended.append((p, sha))
            elif hit[1] != 100:
                inexact[(p, sha)] = hit[0]
    ended.extend(orphans.items())
    if not (ended or inexact):
        return found
    # Lines a commit of the range added to CHANGELOG.md, so a line polished after its release still matches.
    changelog_added = {
        line[1:].rstrip() for line in lines_of(repo.git("diff", "-U0", "--text", "--no-color", "--no-ext-diff", "--no-textconv", old, new, "--", "CHANGELOG.md"))
        if line.startswith("+") and not line.startswith("+++")
    }
    for line in lines_of(repo.git("log", "--full-history", "-p", "-U0", "--text", "--no-color", "--no-ext-diff", "--no-textconv", "--format=",
                                  f"{old}..{new}", "--", "CHANGELOG.md")):
        if line.startswith("+") and not line.startswith("+++"):
            changelog_added.add(line[1:].rstrip())
    # The text a deleting commit removed is in the parent that had the path: the only parent of an
    # ordinary commit, one or more of a merge's.
    specs = {(p, sha): [f"{sha}:{p}"] if orphans.get(p) == sha else [f"{par}:{p}" for par in parents_of[sha]]
             for p, sha in [*ended, *inexact]}
    single = [v[0] for v in specs.values() if len(v) == 1]
    multi = [x for v in specs.values() if len(v) > 1 for x in v]
    found_bodies = {**repo.blobs(single), **repo.blobs(multi, required=False)}
    bodies = {key: next((b for x in v if (b := found_bodies.get(x)) is not None), None) for key, v in specs.items()}
    kept = repo.blobs([f"{sha}:{dst}" for (_, sha), dst in inexact.items()], required=False)

    def first_line(body: str | None) -> str:
        first = bullets(body or "")[:1]
        return first[0].split("\n")[0].rstrip() if first else ""

    sections = release_sections(repo.show(new, "CHANGELOG.md"))
    refs = {p: r for p, _ in specs if (r := reference(p)) is not None}
    ref_bodies = repo.blobs([f"{old}:{r}" for r in set(refs.values())])
    for (path, sha) in specs:
        body = bodies[(path, sha)]
        if body is None:
            continue
        if path in refs and ref_bodies[f"{old}:{refs[path]}"] == body:
            continue  # the text the reader had at `old`
        line = first_line(body)
        if (path, sha) in inexact and line == first_line(kept.get(f"{sha}:{inexact[(path, sha)]}")):
            continue  # renamed and edited, the first bullet kept: the same entry
        if line and line in changelog_added:
            key = path if path not in found else f"{path}#{sha[:10]}"
            found[key] = body
            found.promoted.add(key)
            # Per bullet: one the release editor dropped was never added to CHANGELOG.md. Under [Unreleased]
            # nothing is released; a line the changelog no longer carries (reworded after) is still known to
            # have been released, just not in which version.
            for item in bullets(body):
                bl = item.split("\n")[0].rstrip()
                if bl in changelog_added and sections.get(bl, "") is not None:
                    found.released.setdefault(key, {})[bl] = sections.get(bl) or ""
        elif orphans.get(path) == sha:
            found.unmatched.append(path)
    return found


def render_fragments(frags: dict[str, str], full: bool) -> tuple[list[str], int, list[str], int, int]:
    """(lines, bullet count, names of fragments that yielded no '- ' bullet, the number of bullets that
    start `**Breaking`, the number of bullets a release in the range already moved into CHANGELOG.md).
    BRIEF_MAX cuts the bullet's own text; a `[released X]` tag follows the cut."""
    released = getattr(frags, "released", {})
    breaking = already = 0
    by_section: dict[str, list[str]] = {s: [] for s in SECTION_ORDER}
    seen: set[tuple[str, str]] = set()
    empty: list[str] = []
    total = 0
    for path, body in sorted(frags.items()):
        section = section_of(path)
        items = bullets(body)
        if not items:
            empty.append(path.split("#", 1)[0].rsplit("/", 1)[-1])
            continue
        for b in items:
            if (section, b) in seen:
                continue
            seen.add((section, b))
            total += 1
            first = b.split("\n")[0]
            is_breaking = first.lower().startswith("- **breaking")
            breaking += is_breaking
            tag = ""
            marks = released.get(path, {})
            if first.rstrip() in marks:
                already += 1
                tag = tag_for(marks[first.rstrip()])
            if full or section in NEVER_TRUNCATE or is_breaking:
                # Continuation lines are indented so that none starts at column 0, where text taken
                # from a fragment could pass for one of this report's own headings.
                shown = "\n".join([first + tag, *(("    " + rest) if rest.strip() else "" for rest in b.split("\n")[1:])])
            elif len(first) > BRIEF_MAX:
                shown = first[: BRIEF_MAX - 3].rstrip() + "..." + tag
            else:
                shown = first + tag
            by_section[section].append(shown)
    lines: list[str] = []
    for section in SECTION_ORDER:
        if by_section[section]:
            lines.append(f"{section.capitalize()} ({len(by_section[section])})")
            lines.extend(by_section[section])
            lines.append("")
    return lines, total, empty, breaking, already


TAG_VERSION_MAX = 40


def cut_version(version: str) -> str:
    """A version heading is repository text of any length; it is printed in the version bumps and once per
    entry in a `[released X]` tag, so it is cut."""
    v = one(version)
    return v[:TAG_VERSION_MAX - 3] + "..." if len(v) > TAG_VERSION_MAX else v


def tag_for(version: str) -> str:
    """The `[released X]` suffix of an entry; empty when the version cannot be told."""
    return f"  [released {cut_version(version)}]" if version else "  [released]"


def name_list(names: list[str], limit: int = 20) -> str:
    """The names on a `!` line, repo text made safe for one line, cut at `limit` so a flood of them stays short."""
    shown = ", ".join(one(n) for n in names[:limit])
    return shown + (f", and {len(names) - limit} more" if len(names) > limit else "")


def build_report(repo: Repo, since: str | None, full: bool, versions_only: bool = False) -> list[str]:
    head = repo.resolves("HEAD")
    if head is None:
        raise GitError("this repository has no commits")
    old, how, via = resolve_base(repo, since, head)
    count = repo.git("rev-list", "--count", f"{old}..{head}").strip()
    files = repo.names("diff", "-z", "--no-renames", "--name-only", old, head)
    out = [
        f"Changes since {how}: {plural(int(count), 'commit')}, {plural(len(files), 'file')}"
        + (f" ({top_level_summary(files)})" if files else ""),
        f"Base {repo.git('log', '-1', '--format=%h %cs %s', old).strip()}",
        f"Head {repo.git('log', '-1', '--format=%h %cs %s', head).strip()}",
    ]
    if via is not None:
        out.append(f"Via  reflog entry: {via}")
    frags = added_fragments(repo, old, head)
    lines, total, empty, breaking, released_count = render_fragments(frags, full)
    if breaking:
        out.append(f"Breaking  {breaking} changelog {'entry' if breaking == 1 else 'entries'} marked **Breaking"
                   + (" (run without --versions to read them)" if versions_only else " (listed below)"))
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

    odd = unrecognised_names(repo, old, head)
    not_regular = sorted(set(repo.not_regular))
    too_big = sorted(set(repo.too_big))
    unmatched = sorted(set(getattr(frags, "unmatched", [])))
    # Fragments that were not read or not listed. They are printed in every mode: the Breaking count in the
    # header is only complete if none of them is missing, and --versions must not read as an all-clear.
    notices: list[str] = []
    if unmatched:
        notices.append(f"! {plural(len(unmatched), 'fragment')} removed by a merge commit matched no line added to CHANGELOG.md "
                       f"(withdrawn, or reworded in the merge), not listed: {name_list(unmatched)}; read CHANGELOG.md for the release text")
    if empty:
        notices.append(f"! {plural(len(empty), 'fragment')} with no '- ' bullet, not summarised: {name_list(empty)}")
    if odd:
        notices.append(f"! {plural(len(odd), 'file')} added under {FRAGMENT_DIR}/ not named like fragments (or not directly in it), "
                       f"not listed: {name_list(odd)}")
    if not_regular:
        notices.append(f"! {plural(len(not_regular), 'path')} named like fragments but not regular files (a submodule), "
                       f"not listed: {name_list(not_regular)}")
    if too_big:
        notices.append(f"! {plural(len(too_big), 'fragment file')} over {MAX_FRAGMENT_BYTES // 1024} KiB, not read: {name_list(too_big)}")

    images, other = dependency_bumps(repo, old, head)
    if versions_only:
        if images:
            out.append(f"Docker image bumps ({len(images)})")
            out.extend(f"  {s}" for s in images)
            out.append("")
        if full and other:
            out.append(f"Other dependency bumps ({len(other)})")
            out.extend(f"  {s}" for s in other)
            out.append("")
        elif other:
            out.append(f"+ {plural(len(other), 'other dependency bump')} (workflows, pip, npm); --full lists them")
        if notices:
            if out and out[-1]:
                out.append("")
            out.append("Fragments the report could not use, which the Breaking count leaves out (run without --versions for the full report):")
            out.extend(notices)
        return out
    if images or other:
        out.append(f"Dependency bumps (build(deps)/chore(deps) commits): {plural(len(images), 'Docker image')}, {len(other)} other")
        out.extend(f"  {s}" for s in images)
        if full:
            out.extend(f"  {s}" for s in other)
        elif other:
            out.append(f"  + {plural(len(other), 'other bump')} (workflows, pip, npm); --full lists them")
        out.append("")

    if lines:
        counts = [str(total)]
        if released_count:
            counts.append(f"{released_count} already released")
        if breaking:
            counts.append(f"{breaking} breaking")
        out.append(f"Changelog entries added ({', '.join(counts)})")
        out.append("")
        out.extend(lines)
        if getattr(frags, "promoted", None):
            out.append("Note: entries a release inside this range moved into CHANGELOG.md show the fragment's wording as it was")
            out.append("promoted; CHANGELOG.md has the release text, which may differ.")
    elif empty or odd or not_regular or too_big or unmatched:
        out.append("No changelog entries could be listed for this range (see the ! lines below).")
    else:
        out.append("No changelog fragments were added in this range (refactors, CI and test-only changes may skip them;")
        out.append(f"`git log --first-parent --oneline {old[:10]}..HEAD` lists every merged PR).")
    out.extend(notices)
    return out


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description="Summarise what changed in this checkout since the last pull.", allow_abbrev=False)
    ap.add_argument("--since", help="ref, tag or commit, or a date (YYYY-MM-DD[ HH:MM[:SS]], yesterday, \"N days ago\"); default: your last pull")
    ap.add_argument("--full", action="store_true",
                    help="print whole bullets (not first lines) and list every non-image dependency bump")
    ap.add_argument("--versions", action="store_true",
                    help="only the version bumps, rebuild/redeploy notes and Docker image bumps (the header still counts **Breaking entries, and a `!` line names any fragment that could not be read or listed)")
    ap.add_argument("--repo", type=Path, default=None, help=argparse.SUPPRESS)
    args = ap.parse_args(argv)

    try:
        sys.stdout.reconfigure(errors="replace")  # type: ignore[union-attr]
    except (AttributeError, ValueError):
        pass
    try:
        top = Repo(args.repo or Path.cwd())
        proc = top._run("rev-parse", "--show-toplevel", binary=True)
        if proc.returncode != 0:
            raise GitError(proc.stderr.decode("utf-8", "replace").strip() or "git rev-parse --show-toplevel failed")
        # Exactly the newline git adds, no more: a directory name may end in a space, and may not be UTF-8.
        root = os.fsdecode(proc.stdout.removesuffix(b"\n"))
        report = build_report(Repo(Path(root)), args.since, args.full, args.versions)
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
