#!/usr/bin/env python3
"""Checks scripts/ci/image-vuln-gate.sh delegates to (WP15/S9). Stdlib only.

Three subcommands, each failing CLOSED (exit 1) on anything it cannot read:

  ignore-file PATH
      Validate .trivyignore.yaml by parsing it, not by counting lines. Only a
      strict block-style subset of YAML is accepted, so this parser and Trivy
      read the file the same way:

        vulnerabilities:
          - id: CVE-2025-68121         first key of every entry
            paths:                     `paths` and/or `purls`: required, so an
              - "usr/local/bin/gosu"   entry never hides a CVE everywhere
            statement: >-              required: why, with the evidence
              ...
            expired_at: 2027-02-15     required, at most MAX_EXPIRY_DAYS out
            approved_by: some-login    required: the GitHub login that
                                       accepted the finding

      Refused: any other top-level or entry key, flow style (`{`, `[`),
      anchors, aliases and tags, tabs, a duplicate key, a plain scalar that
      continues on the next line, a quoted scalar with an escape, and a value
      followed by a comment. An entry that has already expired is valid (Trivy
      stops honouring it, so the finding fails the gate again); an entry that
      expires within WARN_DAYS is reported as a warning.

  db-age METADATA_JSON
      Read Trivy's DB metadata.json, print UpdatedAt, DownloadedAt and the age,
      and fail when UpdatedAt is older than MAX_DB_AGE_HOURS (the published DB
      is rebuilt every few hours; the mirror lagging a day is normal), lies
      more than an hour in the future, or is unreadable.

  coverage REPORT_JSON NAME NOT_COVERED_FILE
      Read a Trivy JSON report and print the OS and its OS package count. An
      image whose OS package scan found no package at all (no OS detected, no
      os-pkgs result, or a result with zero packages) was not scanned for OS
      vulnerabilities, so the gate fails unless NAME is listed in
      NOT_COVERED_FILE with a reason. Prints `coverage=<covered|not-covered>`,
      `os=...` and `os_packages=N` lines for the caller.
"""

import datetime as dt
import json
import re
import sys

MAX_EXPIRY_DAYS = 92
WARN_DAYS = 21
MAX_DB_AGE_HOURS = 72

ENTRY_KEYS = ("id", "paths", "purls", "statement", "expired_at", "approved_by")
LIST_KEYS = ("paths", "purls")
# A GitHub login: 1-39 alphanumerics or single hyphens, not starting with one.
LOGIN = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9]|-(?=[A-Za-z0-9])){0,38}$")
VULN_ID = re.compile(r"^(CVE-\d{4}-\d{4,}|GHSA(-[23456789cfghjmpqrvwx]{4}){3}|[A-Z][A-Z0-9]*-[A-Za-z0-9.:_-]+)$")
DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")


class Bad(Exception):
    pass


def plain_scalar(raw, where):
    """A single-line scalar: plain, or double/single quoted without escapes."""
    v = raw.strip()
    if not v:
        raise Bad(f"{where}: empty value")
    if v[0] in "{[&*!|>%@`":
        raise Bad(f"{where}: flow style, anchor, alias, tag or block scalar not allowed here")
    if v[0] in "\"'":
        q = v[0]
        if len(v) < 2 or v[-1] != q or q in v[1:-1] or "\\" in v:
            raise Bad(f"{where}: quoted value must be one plain quoted string without escapes")
        return v[1:-1]
    if " #" in v or "\t" in v:
        raise Bad(f"{where}: a comment after a value is not allowed")
    if v.startswith("- ") or ": " in v or v.endswith(":"):
        raise Bad(f"{where}: value looks like YAML structure")
    return v


def parse_ignore(text):
    lines = text.split("\n")
    entries = []
    top_seen = False
    i = 0
    n = len(lines)

    def skip(line):
        s = line.strip()
        return s == "" or s.startswith("#")

    while i < n:
        line = lines[i]
        where = f"line {i + 1}"
        if "\t" in line:
            raise Bad(f"{where}: tab character")
        if skip(line):
            i += 1
            continue
        indent = len(line) - len(line.lstrip(" "))
        body = line.strip()
        if indent == 0:
            if body != "vulnerabilities:":
                raise Bad(f"{where}: only a `vulnerabilities:` key is allowed at the top level")
            if top_seen:
                raise Bad(f"{where}: second `vulnerabilities:` key")
            top_seen = True
            i += 1
            continue
        if not top_seen:
            raise Bad(f"{where}: content before `vulnerabilities:`")
        if indent != 2 or not body.startswith("- "):
            raise Bad(f"{where}: expected an entry `  - id: ...` at indentation 2")
        # One entry: "  - id: X" then keys at indentation 4.
        first = body[2:]
        m = re.match(r"^([a-z_]+):(?:\s+(.*))?$", first)
        if not m or m.group(1) != "id":
            raise Bad(f"{where}: every entry starts with `- id:`")
        entry = {"_line": i + 1, "id": plain_scalar(m.group(2) or "", where)}
        i += 1
        while i < n:
            line = lines[i]
            where = f"line {i + 1}"
            if "\t" in line:
                raise Bad(f"{where}: tab character")
            if skip(line):
                i += 1
                continue
            indent = len(line) - len(line.lstrip(" "))
            if indent < 4:
                break
            if indent != 4:
                raise Bad(f"{where}: unexpected indentation {indent} (entry keys sit at 4)")
            m = re.match(r"^([a-z_]+):(?:[ ]+(.*))?$", line.strip())
            if not m:
                raise Bad(f"{where}: expected `key: value`")
            key, raw = m.group(1), (m.group(2) or "")
            if key not in ENTRY_KEYS or key == "id":
                raise Bad(f"{where}: key `{key}` is not allowed in an entry")
            if key in entry:
                raise Bad(f"{where}: duplicate key `{key}`")
            i += 1
            if key in LIST_KEYS:
                if raw.strip():
                    raise Bad(f"{where}: `{key}` must be a block list (`- \"...\"` lines at indentation 6)")
                items = []
                while i < n:
                    line = lines[i]
                    if "\t" in line:
                        raise Bad(f"line {i + 1}: tab character")
                    if skip(line):
                        i += 1
                        continue
                    ind = len(line) - len(line.lstrip(" "))
                    if ind <= 4:
                        break
                    if ind != 6 or not line.strip().startswith("- "):
                        raise Bad(f"line {i + 1}: `{key}` items are `- \"...\"` at indentation 6")
                    items.append(plain_scalar(line.strip()[2:], f"line {i + 1}"))
                    i += 1
                if not items:
                    raise Bad(f"{where}: `{key}` is empty")
                entry[key] = items
            elif key == "statement" and raw.strip() in (">", ">-", "|", "|-"):
                parts = []
                while i < n:
                    line = lines[i]
                    if "\t" in line:
                        raise Bad(f"line {i + 1}: tab character")
                    if line.strip() == "":
                        parts.append("")
                        i += 1
                        continue
                    ind = len(line) - len(line.lstrip(" "))
                    if ind <= 4:
                        break
                    parts.append(line.strip())
                    i += 1
                text_ = " ".join(p for p in parts if p).strip()
                if not text_:
                    raise Bad(f"{where}: empty statement")
                entry[key] = text_
            else:
                v = plain_scalar(raw, where)
                # A plain scalar continuing on a more-indented next line would be
                # folded into it by YAML; refuse rather than guess.
                j = i
                while j < n and lines[j].strip() == "":
                    j += 1
                if j < n and not lines[j].strip().startswith("#"):
                    nind = len(lines[j]) - len(lines[j].lstrip(" "))
                    if nind > 4:
                        raise Bad(f"line {j + 1}: continuation of `{key}`; use `statement: >-` for long text")
                entry[key] = v
        entries.append(entry)
    if not top_seen:
        raise Bad("no `vulnerabilities:` key")
    return entries


def cmd_ignore_file(path):
    try:
        with open(path, encoding="utf-8") as f:
            text = f.read()
    except (OSError, UnicodeDecodeError) as e:
        print(f"{path}: unreadable: {e}", file=sys.stderr)
        return 1
    try:
        entries = parse_ignore(text)
    except Bad as e:
        print(f"{path}: {e}", file=sys.stderr)
        return 1
    today = dt.datetime.now(dt.timezone.utc).date()
    errors = 0
    seen = set()
    for e in entries:
        tag = f"{path}:{e['_line']}: {e['id']}"
        if not VULN_ID.match(e["id"]):
            print(f"{tag}: id is not a vulnerability id", file=sys.stderr)
            errors += 1
        for k in ("statement", "expired_at", "approved_by"):
            if k not in e:
                print(f"{tag}: no `{k}`", file=sys.stderr)
                errors += 1
        if "paths" not in e and "purls" not in e:
            print(f"{tag}: no `paths` or `purls` scope (never a bare id: it would hide the CVE in every package)", file=sys.stderr)
            errors += 1
        if "approved_by" in e and not LOGIN.match(e["approved_by"]):
            print(f"{tag}: approved_by must be the approver's GitHub login", file=sys.stderr)
            errors += 1
        key = (e["id"], tuple(e.get("paths", ())), tuple(e.get("purls", ())))
        if key in seen:
            print(f"{tag}: duplicate entry", file=sys.stderr)
            errors += 1
        seen.add(key)
        if "expired_at" in e:
            exp = None
            if DATE.match(e["expired_at"]):
                try:
                    exp = dt.date.fromisoformat(e["expired_at"])
                except ValueError:
                    exp = None
            if exp is None:
                print(f"{tag}: expired_at must be a YYYY-MM-DD date", file=sys.stderr)
                errors += 1
            else:
                left = (exp - today).days
                if left > MAX_EXPIRY_DAYS:
                    print(f"{tag}: expired_at {exp} is {left} days out; the maximum is {MAX_EXPIRY_DAYS}", file=sys.stderr)
                    errors += 1
                elif left < 0:
                    print(f"note: {tag}: expired on {exp}; Trivy no longer honours it, so the finding fails the gate again")
                elif left <= WARN_DAYS:
                    print(f"warning: {tag}: expires on {exp} ({left} days); re-review it before a release fails on it")
    if errors:
        return 1
    print(f"{path}: {len(entries)} accepted finding(s), each with a scope, a statement, an expiry and an approver")
    return 0


def parse_time(s):
    # Trivy writes RFC 3339 with up to nanoseconds; Python takes microseconds.
    m = re.match(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(\.\d+)?(Z|[+-]\d{2}:\d{2})$", s or "")
    if not m:
        raise ValueError(f"not an RFC 3339 time: {s!r}")
    frac = (m.group(2) or ".0")[:7]
    tz = "+00:00" if m.group(3) == "Z" else m.group(3)
    return dt.datetime.fromisoformat(m.group(1) + frac + tz)


def cmd_db_age(path):
    try:
        with open(path, encoding="utf-8") as f:
            meta = json.load(f)
        updated = parse_time(meta["UpdatedAt"])
        downloaded = meta.get("DownloadedAt", "?")
    except (OSError, ValueError, KeyError, TypeError) as e:
        print(f"Trivy DB metadata {path} is missing or unreadable ({e}); refusing to scan with a DB of unknown age", file=sys.stderr)
        return 1
    now = dt.datetime.now(dt.timezone.utc)
    age_h = (now - updated).total_seconds() / 3600
    print(f"trivy_db_updated_at={meta['UpdatedAt']}")
    print(f"trivy_db_downloaded_at={downloaded}")
    print(f"trivy_db_age_hours={age_h:.1f}")
    if age_h < -1:
        print(f"Trivy DB UpdatedAt {meta['UpdatedAt']} is in the future; refusing it", file=sys.stderr)
        return 1
    if age_h > MAX_DB_AGE_HOURS:
        print(f"Trivy DB was built {age_h:.0f} hours ago (UpdatedAt {meta['UpdatedAt']}), more than "
              f"{MAX_DB_AGE_HOURS}; a stale DB misses recent fixes, so the gate does not pass on it", file=sys.stderr)
        return 1
    return 0


def read_not_covered(path):
    listed = {}
    with open(path, encoding="utf-8") as f:
        for no, line in enumerate(f, 1):
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            name, sep, reason = s.partition(":")
            name, reason = name.strip(), reason.strip()
            if not sep or not re.match(r"^[a-z0-9][a-z0-9._-]*$", name) or len(reason) < 20:
                raise Bad(f"{path}:{no}: expected `<image name>: <reason of at least 20 characters>`")
            if name in listed:
                raise Bad(f"{path}:{no}: {name} listed twice")
            listed[name] = reason
    return listed


def cmd_coverage(report, name, not_covered):
    try:
        with open(report, encoding="utf-8") as f:
            d = json.load(f)
        listed = read_not_covered(not_covered)
    except (OSError, ValueError) as e:
        print(f"coverage: cannot read {e}", file=sys.stderr)
        return 1
    except Bad as e:
        print(str(e), file=sys.stderr)
        return 1
    if not isinstance(d, dict):
        print(f"coverage: {report} is not a Trivy JSON report", file=sys.stderr)
        return 1
    meta = d.get("Metadata") or {}
    os_ = meta.get("OS") or {}
    os_desc = f"{os_.get('Family', '')} {os_.get('Name', '')}".strip() or "none detected"
    results = d.get("Results") or []
    os_results = [r for r in results if isinstance(r, dict) and r.get("Class") == "os-pkgs"]
    count = sum(len(r.get("Packages") or []) for r in os_results)
    lang = sum(len(r.get("Packages") or []) for r in results
               if isinstance(r, dict) and r.get("Class") == "lang-pkgs")
    print(f"os={os_desc}")
    print(f"os_packages={count}")
    print(f"language_packages={lang}")
    if count > 0:
        if name in listed:
            print(f"warning: {name} is listed in {not_covered} as not covered, but Trivy found {count} OS "
                  f"packages; remove it from the list so a later regression to zero fails")
        print("coverage=covered")
        return 0
    if name and name in listed:
        print("coverage=not-covered")
        print(f"reason={listed[name]}")
        return 0
    print(f"{name or report}: Trivy found no OS package ({os_desc}), so its OS packages were NOT scanned for "
          f"vulnerabilities. Make the package database visible to the scanner, or list the image in "
          f"{not_covered} with the reason (a reviewed, documented exception)", file=sys.stderr)
    return 1


def main(argv):
    if len(argv) == 2 and argv[0] == "ignore-file":
        return cmd_ignore_file(argv[1])
    if len(argv) == 2 and argv[0] == "db-age":
        return cmd_db_age(argv[1])
    if len(argv) == 4 and argv[0] == "coverage":
        return cmd_coverage(argv[1], argv[2], argv[3])
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
