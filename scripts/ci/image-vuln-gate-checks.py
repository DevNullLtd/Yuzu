#!/usr/bin/env python3
"""Checks scripts/ci/image-vuln-gate.sh delegates to (WP15/S9). Stdlib only.

Every subcommand fails CLOSED (exit 1) on anything it cannot read.

  ignore-file PATH [--emit OUT] [--require-approved]
      Validate .trivyignore.yaml by parsing it, not by counting lines. Only a
      strict block-style subset of YAML is accepted:

        vulnerabilities:
          - id: CVE-2025-68121         first key of every entry
            paths:                     `paths` and/or `purls`: required, so an
              - "usr/local/bin/gosu"   entry never hides a CVE everywhere
            statement: >-              required: why, with the evidence
              ...
            expired_at: 2027-02-15     required, at most MAX_EXPIRY_DAYS out
            approved_by: some-login    required: who accepted the finding
            approved_on: 2026-11-18    required unless approval_ref is pending
            approval_ref: "#1234"      required: the pull request that approved
                                       it (`#N` or its URL), or `pending`

      A `paths` item must be one concrete relative path: no empty string, no
      whitespace, no glob character (`* ? [ ] { } !`), no backslash, no leading
      `/`, no `.`/`..`/empty component. Trivy matches `paths` as doublestar
      globs, and an OS package has an empty path, so `**`, `*` or `""` would
      suppress the CVE in every package. A `purls` item must be a full package
      URL with a type, a name and an `@version` (Trivy matches a purl without
      a version against every version), with no glob character.

      Refused: any other top-level or entry key, flow style (`{`, `[`),
      anchors, aliases and tags, tabs, a duplicate key, a plain scalar that
      continues on the next line, a quoted scalar with an escape, and a value
      followed by a comment.

      With --emit OUT it writes the entries that are IN FORCE to OUT, in a
      canonical form, and that file, never PATH, is what Trivy reads. So
      Trivy reads exactly what was validated, as YAML whatever PATH is named.
      Not in force: an expired entry (Trivy would not honour it either), and,
      with --require-approved (the release gate), an entry whose approval_ref
      is `pending`. Prints `in_force=N` and `pending=M` for the caller.

  not-covered PATH [--require-approved]
      Validate scripts/ci/image-vuln-gate-not-covered.txt (same approval
      fields; format in that file's header).

  db-age METADATA_JSON [--downloaded-after EPOCH]
      Read Trivy's DB metadata.json, print UpdatedAt, DownloadedAt and the age,
      and fail when UpdatedAt is older than MAX_DB_AGE_HOURS, lies more than an
      hour in the future, or is unreadable; with --downloaded-after, also when
      DownloadedAt is earlier than EPOCH (the DB was not downloaded by this run).

  resolve-digest REPOSITORY:TAG
      Resolve a registry tag to its manifest digest (anonymous OCI registry
      API), so the DB download can be pinned to it and the digest recorded.

  coverage TRIVY_REPORT_JSON NAME NOT_COVERED_FILE [--require-approved]
      Read a TRIVY JSON report (SchemaVersion 2; another scanner's report is
      refused, never read as "no packages"). Prints `verdict=`, `os_family=`,
      `os_name=`, `os=` and `os_packages=` lines. Fails (exit 1) when:
        - the OS package scan found no package (no OS detected, no os-pkgs
          result, or zero packages), unless NAME is listed, in force, in
          NOT_COVERED_FILE (exact name match);
        - Trivy marks the OS release end of service life (Metadata.OS.EOSL);
        - the OS family is not one the gate can prove has advisory data
          (CANARY_FAMILIES; see canary-rootfs).

  canary-rootfs DIR FAMILY OS_NAME
      Write a minimal root filesystem that Trivy detects as FAMILY OS_NAME,
      holding two packages (openssl, zlib) at a version older than every fix.
      Scanning it against the run's DB proves the DB holds advisory data for
      that exact OS release: Trivy matches nothing for an OS release with no
      advisory bucket (Debian sid/testing, Alpine edge, an Ubuntu devel series
      Trivy reads as Debian sid), so an image on one would otherwise read as
      scanned and clean.

  canary-check REPORT_JSON FAMILY OS_NAME
      Fail unless the canary scan detected FAMILY OS_NAME and matched at least
      one vulnerability.
"""

import datetime as dt
import hashlib
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

MAX_EXPIRY_DAYS = 92
WARN_DAYS = 21
MAX_DB_AGE_HOURS = 72

ENTRY_KEYS = ("id", "paths", "purls", "statement", "expired_at", "approved_by",
              "approved_on", "approval_ref")
LIST_KEYS = ("paths", "purls")
# A GitHub login: 1-39 alphanumerics or single hyphens, not starting with one.
LOGIN = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9]|-(?=[A-Za-z0-9])){0,38}$")
# A CVE or GHSA id must be well formed; another vendor id (DLA-, ALAS-, ...)
# may not be a malformed CVE/GHSA id passing as a vendor one.
VULN_ID = re.compile(r"^(CVE-\d{4}-\d{4,}|GHSA(-[23456789cfghjmpqrvwx]{4}){3}|(?!CVE-|GHSA-)[A-Z][A-Z0-9]*-[A-Za-z0-9.:_-]+)$")
DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
# The pull request that approved an acceptance: `#N` or its URL; or `pending`.
APPROVAL_REF = re.compile(r"^(#[1-9][0-9]{0,6}|https://github\.com/[A-Za-z0-9-]+/[A-Za-z0-9._-]+/pull/[1-9][0-9]{0,6})$")
PENDING = "pending"
# One path component of a concrete path: no glob, whitespace, quote or escape.
PATH_COMPONENT = re.compile(r"^[A-Za-z0-9._+@=,:~%-]+$")
GLOB_CHARS = set("*?[]{}!")
# pkg:type/[namespace/...]name@version[?qualifiers]; no subpath, no glob.
PURL = re.compile(
    r"^pkg:[a-z][a-z0-9.+-]*/"
    r"(?:[A-Za-z0-9._~%+-]+/)*"
    r"[A-Za-z0-9._~%+-]+"
    r"@[A-Za-z0-9._~%+:-]+"
    r"(?:\?[A-Za-z0-9._~%+-]+=[A-Za-z0-9._~%+:/-]+(?:&[A-Za-z0-9._~%+-]+=[A-Za-z0-9._~%+:/-]+)*)?$")
IMAGE_NAME = re.compile(r"^[a-z0-9][a-z0-9._-]*$")

# OS families the gate has a canary for (canary-rootfs). Every image the
# release publishes is on one of these; another family fails the gate until a
# canary is added for it.
CANARY_FAMILIES = ("debian", "ubuntu", "alpine")
OS_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/+~-]{0,63}$")


class Bad(Exception):
    pass


def today():
    return dt.datetime.now(dt.timezone.utc).date()


def plain_scalar(raw, where):
    """A single-line scalar: plain, or double/single quoted without escapes."""
    v = raw.strip()
    if not v:
        raise Bad(f"{where}: empty value")
    if v[0] in "{[&*!|>%@`":
        raise Bad(f"{where}: flow style, anchor, alias, tag or block scalar not allowed here")
    if v[0] == "#":
        raise Bad(f"{where}: YAML reads a plain value starting with '#' as a comment; quote it")
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
                    items.append(list_item(line.strip()[2:], f"line {i + 1}"))
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
                if key in ("expired_at", "approved_on") and raw.strip()[:1] in "\"'":
                    # Trivy refuses a quoted date (FATAL), so the checker does too.
                    raise Bad(f"{where}: `{key}` is an unquoted YYYY-MM-DD date")
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


def list_item(raw, where):
    """A `paths`/`purls` item: plain_scalar, but an empty quoted string is refused
    here too (plain_scalar returns "" for `""`)."""
    v = plain_scalar(raw, where)
    if v == "":
        raise Bad(f"{where}: empty string")
    return v


def path_problem(p):
    """Why `p` is not one concrete relative path, or None."""
    if p != p.strip() or any(c.isspace() for c in p):
        return "contains whitespace"
    if any(c in GLOB_CHARS for c in p):
        return "contains a glob character (* ? [ ] { } !): Trivy matches paths as globs"
    if "\\" in p:
        return "contains a backslash"
    if p.startswith("/"):
        return "starts with '/': Trivy's package paths are relative (usr/local/bin/gosu)"
    for comp in p.split("/"):
        if comp in ("", ".", ".."):
            return "has an empty, '.' or '..' component"
        if not PATH_COMPONENT.match(comp):
            return f"component {comp!r} has a character outside [A-Za-z0-9._+@=,:~%-]"
    return None


def purl_problem(p):
    if any(c.isspace() for c in p) or any(c in "*[]{}!" for c in p):
        return "contains whitespace or a glob character"
    if not PURL.match(p):
        return ("is not a full package URL `pkg:<type>/[<namespace>/]<name>@<version>` "
                "(a purl without a version matches every version)")
    return None


def parse_date(v):
    if not DATE.match(v or ""):
        return None
    try:
        return dt.date.fromisoformat(v)
    except ValueError:
        return None


def check_approval(tag, by, on, ref, errors_out):
    """Shared approval rules for an ignore entry and a not-covered line. Returns
    True when the approval is pending."""
    if by is None or not LOGIN.match(by):
        errors_out.append(f"{tag}: approved_by must be the approver's GitHub login")
    if ref is None:
        errors_out.append(f"{tag}: no approval_ref (the approving pull request, `#N` or its URL, or `pending`)")
        return False
    if ref == PENDING:
        if on not in (None, "-"):
            errors_out.append(f"{tag}: approved_on is set but approval_ref is pending")
        return True
    if not APPROVAL_REF.match(ref):
        errors_out.append(f"{tag}: approval_ref {ref!r} must be `#N` or https://github.com/<owner>/<repo>/pull/N")
    d = parse_date(on)
    if d is None:
        errors_out.append(f"{tag}: approved_on must be the YYYY-MM-DD date of the approval")
    elif d > today():
        errors_out.append(f"{tag}: approved_on {d} is in the future")
    return False


def emit_trivy_yaml(entries, out):
    """The in-force entries in the canonical form Trivy reads. Every value is
    either restricted by the checks above or JSON-encoded (a JSON string is a
    valid YAML double-quoted scalar), so this file says exactly what was
    validated."""
    lines = ["# Generated by image-vuln-gate-checks.py from the validated ignore file.",
             "vulnerabilities:"]
    for e in entries:
        lines.append(f"  - id: {e['id']}")
        for k in LIST_KEYS:
            if k in e:
                lines.append(f"    {k}:")
                lines += [f"      - {json.dumps(v)}" for v in e[k]]
        lines.append(f"    statement: {json.dumps(e['statement'])}")
        lines.append(f"    expired_at: {e['expired_at']}")
    if not entries:
        lines[-1] = "vulnerabilities: []"
    with open(out, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


def cmd_ignore_file(path, emit=None, require_approved=False):
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
    now = today()
    errors = []
    seen = set()
    in_force, pending_excluded, pending_honoured = [], 0, 0
    for e in entries:
        tag = f"{path}:{e['_line']}: {e['id']}"
        if not VULN_ID.match(e["id"]):
            errors.append(f"{tag}: id is not a vulnerability id")
        for k in ("statement", "expired_at"):
            if k not in e:
                errors.append(f"{tag}: no `{k}`")
        if "paths" not in e and "purls" not in e:
            errors.append(f"{tag}: no `paths` or `purls` scope (never a bare id: it would hide the CVE in every package)")
        for p in e.get("paths", ()):
            why = path_problem(p)
            if why:
                errors.append(f"{tag}: paths item {p!r} {why}")
        for p in e.get("purls", ()):
            why = purl_problem(p)
            if why:
                errors.append(f"{tag}: purls item {p!r} {why}")
        pending = check_approval(tag, e.get("approved_by"), e.get("approved_on"), e.get("approval_ref"), errors)
        key = (e["id"], tuple(e.get("paths", ())), tuple(e.get("purls", ())))
        if key in seen:
            errors.append(f"{tag}: duplicate entry")
        seen.add(key)
        expired = False
        if "expired_at" in e:
            exp = parse_date(e["expired_at"])
            if exp is None:
                errors.append(f"{tag}: expired_at must be a YYYY-MM-DD date")
            else:
                left = (exp - now).days
                if left > MAX_EXPIRY_DAYS:
                    errors.append(f"{tag}: expired_at {exp} is {left} days out; the maximum is {MAX_EXPIRY_DAYS}")
                elif left < 0:
                    expired = True
                    print(f"note: {tag}: expired on {exp}; not in force, so the finding fails the gate again")
                elif left <= WARN_DAYS:
                    print(f"warning: {tag}: expires on {exp} ({left} days); re-review it before a release fails on it")
        if expired:
            continue
        if pending:
            if require_approved:
                pending_excluded += 1
                print(f"NOT IN FORCE: {tag}: approval_ref is pending; a release gate honours only an approved "
                      f"acceptance (set approval_ref and approved_on from the approving pull request)")
                continue
            pending_honoured += 1
            print(f"warning: {tag}: approval_ref is pending; honoured here, but the release gate "
                  f"(--release) does not honour it")
        in_force.append(e)
    if errors:
        for m in errors:
            print(m, file=sys.stderr)
        return 1
    if emit:
        try:
            emit_trivy_yaml(in_force, emit)
        except OSError as e:
            print(f"cannot write {emit}: {e}", file=sys.stderr)
            return 1
    print(f"{path}: {len(entries)} entry(ies), each with a concrete scope, a statement, an expiry and an approval record")
    print(f"in_force={len(in_force)}")
    print(f"pending={pending_excluded + pending_honoured}")
    print(f"pending_not_honoured={pending_excluded}")
    return 0


def parse_time(s):
    # Trivy writes RFC 3339 with up to nanoseconds; Python takes microseconds.
    m = re.match(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(\.\d+)?(Z|[+-]\d{2}:\d{2})$", s or "")
    if not m:
        raise ValueError(f"not an RFC 3339 time: {s!r}")
    frac = (m.group(2) or ".0")[:7]
    tz = "+00:00" if m.group(3) == "Z" else m.group(3)
    return dt.datetime.fromisoformat(m.group(1) + frac + tz)


def cmd_db_age(path, downloaded_after=None):
    try:
        with open(path, encoding="utf-8") as f:
            meta = json.load(f)
        updated = parse_time(meta["UpdatedAt"])
        downloaded_raw = meta.get("DownloadedAt", "?")
        downloaded = parse_time(downloaded_raw) if downloaded_after is not None else None
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as e:
        print(f"Trivy DB metadata {path} is missing or unreadable ({e}); refusing to scan with a DB of unknown age",
              file=sys.stderr)
        return 1
    now = dt.datetime.now(dt.timezone.utc)
    age_h = (now - updated).total_seconds() / 3600
    print(f"trivy_db_updated_at={meta['UpdatedAt']}")
    print(f"trivy_db_downloaded_at={downloaded_raw}")
    print(f"trivy_db_age_hours={age_h:.1f}")
    if age_h < -1:
        print(f"Trivy DB UpdatedAt {meta['UpdatedAt']} is in the future; refusing it", file=sys.stderr)
        return 1
    if age_h > MAX_DB_AGE_HOURS:
        print(f"Trivy DB was built {age_h:.0f} hours ago (UpdatedAt {meta['UpdatedAt']}), more than "
              f"{MAX_DB_AGE_HOURS}; a stale DB misses recent fixes, so the gate does not pass on it", file=sys.stderr)
        return 1
    if downloaded is not None and downloaded.timestamp() < downloaded_after - 5:
        print(f"Trivy DB DownloadedAt {downloaded_raw} is before this run started; the gate only uses a DB it "
              f"downloaded itself", file=sys.stderr)
        return 1
    return 0


# ── resolve-digest ───────────────────────────────────────────────────────────
MANIFEST_ACCEPT = ", ".join([
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
])
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")


def _bearer_challenge(header):
    m = re.match(r"^\s*Bearer\s+(.*)$", header or "", re.I)
    if not m:
        return None
    return dict(re.findall(r'(\w+)="([^"]*)"', m.group(1)))


def cmd_resolve_digest(ref, timeout=30):
    m = re.match(r"^([a-z0-9.-]+(?::[0-9]+)?)/([a-z0-9._/-]+):([A-Za-z0-9._-]+)$", ref)
    if not m:
        print(f"resolve-digest: {ref!r} is not REGISTRY/REPOSITORY:TAG", file=sys.stderr)
        return 1
    host, repo, tag = m.groups()
    url = f"https://{host}/v2/{repo}/manifests/{tag}"
    headers = {"Accept": MANIFEST_ACCEPT}
    try:
        for attempt in (1, 2):
            req = urllib.request.Request(url, headers=headers, method="GET")
            try:
                with urllib.request.urlopen(req, timeout=timeout) as r:
                    body = r.read(4 * 1024 * 1024 + 1)
                    digest = r.headers.get("Docker-Content-Digest", "")
                break
            except urllib.error.HTTPError as e:
                ch = _bearer_challenge(e.headers.get("WWW-Authenticate", ""))
                if e.code != 401 or attempt == 2 or not ch or "realm" not in ch:
                    raise
                q = {k: v for k, v in ch.items() if k in ("service", "scope")}
                q.setdefault("scope", f"repository:{repo}:pull")
                realm = ch["realm"]
                if not realm.startswith("https://"):
                    raise ValueError(f"token realm {realm!r} is not https")
                with urllib.request.urlopen(realm + "?" + urllib.parse.urlencode(q), timeout=timeout) as r:
                    tok = json.load(r)
                token = tok.get("token") or tok.get("access_token")
                if not token:
                    raise ValueError("token endpoint returned no token")
                headers["Authorization"] = f"Bearer {token}"
    except (OSError, ValueError, urllib.error.URLError) as e:
        print(f"resolve-digest: {ref}: {e}", file=sys.stderr)
        return 1
    if len(body) > 4 * 1024 * 1024:
        print(f"resolve-digest: {ref}: manifest larger than 4 MiB", file=sys.stderr)
        return 1
    computed = "sha256:" + hashlib.sha256(body).hexdigest()
    if digest and digest != computed:
        print(f"resolve-digest: {ref}: registry digest {digest} does not match the manifest's {computed}",
              file=sys.stderr)
        return 1
    print(computed)
    return 0


# ── not-covered list ─────────────────────────────────────────────────────────
NOT_COVERED_LINE = re.compile(
    r"^(?P<name>[^:\s]+): approved_by=(?P<by>\S+) approved_on=(?P<on>\S+) approval_ref=(?P<ref>\S+)"
    r" expires=(?P<exp>\S+) reason=(?P<reason>.*)$")
MIN_REASON = 20


def read_not_covered(path, require_approved=False, notes=None):
    """{name: (reason, in_force, why_not)} for every listed image. Raises Bad on
    any malformed line (the whole list is refused, so a typo cannot quietly
    drop or keep an exception)."""
    listed = {}
    now = today()
    with open(path, encoding="utf-8") as f:
        for no, line in enumerate(f, 1):
            s = line.rstrip("\n")
            if not s.strip() or s.lstrip().startswith("#"):
                continue
            tag = f"{path}:{no}"
            m = NOT_COVERED_LINE.match(s)
            if not m:
                raise Bad(f"{tag}: expected `<image name>: approved_by=<login> approved_on=<YYYY-MM-DD|-> "
                          f"approval_ref=<#N|URL|pending> expires=<YYYY-MM-DD> reason=<at least {MIN_REASON} characters>`")
            name, reason = m.group("name"), m.group("reason").strip()
            if not IMAGE_NAME.match(name):
                raise Bad(f"{tag}: {name!r} is not an image name")
            if len(reason) < MIN_REASON:
                raise Bad(f"{tag}: the reason must be at least {MIN_REASON} characters")
            if name in listed:
                raise Bad(f"{tag}: {name} listed twice")
            errs = []
            pending = check_approval(f"{tag}: {name}", m.group("by"), m.group("on"), m.group("ref"), errs)
            exp = parse_date(m.group("exp"))
            if exp is None:
                errs.append(f"{tag}: expires must be a YYYY-MM-DD date")
            elif (exp - now).days > MAX_EXPIRY_DAYS:
                errs.append(f"{tag}: expires {exp} is more than {MAX_EXPIRY_DAYS} days out")
            if errs:
                raise Bad("; ".join(errs))
            in_force, why = True, ""
            if exp < now:
                in_force, why = False, f"its listing expired on {exp}"
            elif pending and require_approved:
                in_force, why = False, "its listing's approval_ref is pending (a release honours only an approved listing)"
            elif notes is not None:
                if (exp - now).days <= WARN_DAYS:
                    notes.append(f"warning: {tag}: {name}'s listing expires on {exp}; re-review it")
                if pending:
                    notes.append(f"warning: {tag}: {name}'s listing approval is pending; the release gate does not honour it")
            listed[name] = (reason, in_force, why)
    return listed


def cmd_not_covered(path, require_approved=False):
    notes = []
    try:
        listed = read_not_covered(path, require_approved, notes)
    except (OSError, UnicodeDecodeError) as e:
        print(f"{path}: unreadable: {e}", file=sys.stderr)
        return 1
    except Bad as e:
        print(str(e), file=sys.stderr)
        return 1
    for n in notes:
        print(n)
    print(f"{path}: {len(listed)} listed, {sum(1 for v in listed.values() if v[1])} in force")
    return 0


# ── coverage ────────────────────────────────────────────────────────────────
def load_trivy_report(report):
    with open(report, encoding="utf-8") as f:
        d = json.load(f)
    if not isinstance(d, dict) or d.get("SchemaVersion") != 2 or "ArtifactName" not in d \
            or not isinstance(d.get("Metadata", {}), dict) or not isinstance(d.get("Results", []) or [], list):
        raise ValueError(f"{report} is not a Trivy JSON report (SchemaVersion 2); the coverage check reads "
                         f"Trivy's report only")
    return d


def cmd_coverage(report, name, not_covered, require_approved=False):
    try:
        d = load_trivy_report(report)
        listed = read_not_covered(not_covered, require_approved)
    except (OSError, ValueError) as e:
        print("verdict=unreadable")
        print(f"coverage: cannot read {e}", file=sys.stderr)
        return 1
    except Bad as e:
        print("verdict=unreadable")
        print(str(e), file=sys.stderr)
        return 1
    meta = d.get("Metadata") or {}
    os_ = meta.get("OS") or {}
    if not isinstance(os_, dict):
        os_ = {}
    family = str(os_.get("Family") or "")
    os_name = str(os_.get("Name") or "")
    os_desc = f"{family} {os_name}".strip() or "none detected"
    results = d.get("Results") or []
    os_results = [r for r in results if isinstance(r, dict) and r.get("Class") == "os-pkgs"]
    count = sum(len(r.get("Packages") or []) for r in os_results)
    lang = sum(len(r.get("Packages") or []) for r in results
               if isinstance(r, dict) and r.get("Class") == "lang-pkgs")
    print(f"os={os_desc}")
    print(f"os_family={family}")
    print(f"os_name={os_name}")
    print(f"os_packages={count}")
    print(f"language_packages={lang}")
    # Exact match only: a prefix or substring of a listed name is not listed.
    entry = listed.get(name) if name else None
    if count > 0:
        if entry is not None:
            print(f"warning: {name} is listed in {not_covered} as not covered, but Trivy found {count} OS "
                  f"packages; remove it from the list so a later regression to zero fails")
        if os_.get("EOSL") is True:
            print("verdict=eosl")
            print(f"{name or report}: Trivy marks {os_desc} as end of service life: its advisories are no longer "
                  f"maintained, so a clean scan proves nothing. Move the image to a supported release",
                  file=sys.stderr)
            return 1
        if family not in CANARY_FAMILIES:
            print("verdict=unsupported-os")
            print(f"{name or report}: OS family {family or 'none'} is not one the gate can prove has advisory "
                  f"data ({', '.join(CANARY_FAMILIES)}); add a canary for it in image-vuln-gate-checks.py",
                  file=sys.stderr)
            return 1
        if not OS_NAME.match(os_name):
            print("verdict=unsupported-os")
            print(f"{name or report}: OS version {os_name!r} is not one the gate can name", file=sys.stderr)
            return 1
        print("verdict=covered")
        print("coverage=covered")
        return 0
    if entry is not None and entry[1]:
        print("verdict=not-covered")
        print("coverage=not-covered")
        print(f"reason={entry[0]}")
        return 0
    print("verdict=unscanned")
    why = f" It is listed, but {entry[2]}." if entry is not None else ""
    print(f"{name or report}: Trivy found no OS package ({os_desc}), so its OS packages were NOT scanned for "
          f"vulnerabilities.{why} Make the package database visible to the scanner, or list the image in "
          f"{not_covered} with the reason and an approval (a reviewed, documented exception)", file=sys.stderr)
    return 1


# ── advisory canary ─────────────────────────────────────────────────────────
DPKG_STATUS = """\
Package: openssl
Status: install ok installed
Priority: optional
Section: utils
Installed-Size: 1
Maintainer: image-vuln-gate canary
Architecture: amd64
Source: openssl
Version: 0.9.0-1
Description: advisory canary

Package: zlib1g
Status: install ok installed
Priority: optional
Section: libs
Installed-Size: 1
Maintainer: image-vuln-gate canary
Architecture: amd64
Source: zlib
Version: 1:1.0.0-1
Description: advisory canary
"""
APK_INSTALLED = "P:openssl\nV:0.9.0-r0\nA:x86_64\no:openssl\n\nP:zlib\nV:1.0.0-r0\nA:x86_64\no:zlib\n\n"


def cmd_canary_rootfs(root, family, os_name):
    if family not in CANARY_FAMILIES or not OS_NAME.match(os_name):
        print(f"canary-rootfs: no canary for {family!r} {os_name!r}", file=sys.stderr)
        return 1
    try:
        os.makedirs(os.path.join(root, "etc"), exist_ok=False)

        def put(rel, text):
            p = os.path.join(root, rel)
            os.makedirs(os.path.dirname(p), exist_ok=True)
            with open(p, "w", encoding="utf-8") as f:
                f.write(text)

        if family == "debian":
            put("etc/debian_version", os_name + "\n")
            put("var/lib/dpkg/status", DPKG_STATUS)
        elif family == "ubuntu":
            put("etc/lsb-release", f"DISTRIB_ID=Ubuntu\nDISTRIB_RELEASE={os_name}\n"
                                   f"DISTRIB_CODENAME=canary\nDISTRIB_DESCRIPTION=\"Ubuntu {os_name}\"\n")
            put("var/lib/dpkg/status", DPKG_STATUS)
        else:  # alpine
            put("etc/alpine-release", os_name + "\n")
            put("lib/apk/db/installed", APK_INSTALLED)
    except OSError as e:
        print(f"canary-rootfs: {e}", file=sys.stderr)
        return 1
    return 0


def cmd_canary_check(report, family, os_name):
    try:
        d = load_trivy_report(report)
    except (OSError, ValueError) as e:
        print(f"canary: cannot read {e}", file=sys.stderr)
        return 1
    os_ = (d.get("Metadata") or {}).get("OS") or {}
    got = (os_.get("Family"), os_.get("Name"))
    if got != (family, os_name):
        print(f"canary: Trivy detected {got[0]} {got[1]} in the canary, not {family} {os_name}", file=sys.stderr)
        return 1
    n = sum(len(r.get("Vulnerabilities") or []) for r in d.get("Results") or [] if isinstance(r, dict))
    print(f"canary_advisories={n}")
    if n < 1:
        print(f"the Trivy DB holds no advisory for {family} {os_name}: a package years older than every fix "
              f"matched nothing, so a scan of an image on this OS release reads clean whatever it ships "
              f"(an unreleased or rolling release: Debian testing/sid, Alpine edge, an Ubuntu devel series). "
              f"Build on a released OS version", file=sys.stderr)
        return 1
    return 0


def main(argv):
    def flags(rest, allowed):
        out, pos = {}, []
        it = iter(rest)
        for a in it:
            if a in allowed:
                if allowed[a]:
                    out[a] = next(it, None)
                    if out[a] is None:
                        raise SystemExit(2)
                else:
                    out[a] = True
            elif a.startswith("--"):
                raise SystemExit(2)
            else:
                pos.append(a)
        return pos, out

    try:
        if argv and argv[0] == "ignore-file":
            pos, f = flags(argv[1:], {"--emit": True, "--require-approved": False})
            if len(pos) == 1:
                return cmd_ignore_file(pos[0], f.get("--emit"), bool(f.get("--require-approved")))
        elif argv and argv[0] == "not-covered":
            pos, f = flags(argv[1:], {"--require-approved": False})
            if len(pos) == 1:
                return cmd_not_covered(pos[0], bool(f.get("--require-approved")))
        elif argv and argv[0] == "db-age":
            pos, f = flags(argv[1:], {"--downloaded-after": True})
            if len(pos) == 1:
                after = f.get("--downloaded-after")
                return cmd_db_age(pos[0], int(after) if after is not None else None)
        elif len(argv) == 2 and argv[0] == "resolve-digest":
            return cmd_resolve_digest(argv[1])
        elif argv and argv[0] == "coverage":
            pos, f = flags(argv[1:], {"--require-approved": False})
            if len(pos) == 3:
                return cmd_coverage(pos[0], pos[1], pos[2], bool(f.get("--require-approved")))
        elif len(argv) == 4 and argv[0] == "canary-rootfs":
            return cmd_canary_rootfs(argv[1], argv[2], argv[3])
        elif len(argv) == 4 and argv[0] == "canary-check":
            return cmd_canary_check(argv[1], argv[2], argv[3])
    except (SystemExit, ValueError):
        pass
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
