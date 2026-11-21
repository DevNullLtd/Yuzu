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

      approved_by, approved_on and approval_ref are a RECORDED REFERENCE:
      checked for format only (a login, a past date, `#N` or a pull-request
      URL). Nothing here asks GitHub whether the pull request exists or was
      approved by approved_by; the control is review of the change that adds
      the entry (docs/ci-architecture.md "Recording an approval").

      A `paths` item must be one concrete relative path to a file in the
      image: it contains a `/`, and has no empty string, no whitespace, no glob
      character (`* ? [ ] { } !`), no backslash, no leading `/`, no
      `.`/`..`/empty component, and is not a Trivy result target, class or
      type name (TRIVY_RESULT_NAMES). Trivy matches `paths` as doublestar
      globs against a package's path AND its result's target, and an OS
      package has an empty path, so `**`, `*`, `""` or `Python` would
      suppress the CVE in every package (of the image, or of a language). A `purls` item must be a full package
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

  grype-ignore-file PATH [--emit OUT] [--require-approved]
      Validate .grypeignore.yaml, the acceptances for the gate's second
      scanner (grype), with the same parser, the same statement, expiry and
      approval rules and the same in-force rules as ignore-file. Only the
      scope differs, because grype matches a package, not a path or a purl:

        vulnerabilities:
          - id: CVE-2026-1234          first key of every entry
            package_name: erlang       required: grype's package name, exact
            package_version: 28.5.0.2  required: a rule without a version
                                       would accept every version
            package_type: binary       optional: grype's package type
            statement: >-              ... then statement, expired_at,
                                       approved_by, approved_on and
                                       approval_ref, exactly as ignore-file

      No glob character in any scope field. With --emit OUT it writes the
      entries in force as a grype config holding only `ignore:` rules
      (vulnerability, package name, version and type); grype reads that
      file (`-c`), never PATH. Prints in_force=, pending= and
      pending_not_honoured= like ignore-file, and waivers_in_force=.

      The file may also hold one optional `provider_waivers:` section, parsed
      by the same parser under the same shape rules:

        provider_waivers:
          - provider: nvd              first key: nvd, alpine, debian or ubuntu
            statement: >-              required: why, with the evidence that
              ...                      the upstream source is stalled
            expired_at: 2026-11-30     required, at most MAX_WAIVER_DAYS out
            approved_by, approved_on, approval_ref: as for an entry

      A waiver lets grype-db-providers admit that provider's capture when it
      is older than MAX_DB_AGE_HOURS, and nothing else. A duplicate provider,
      an unknown one, an expiry more than MAX_WAIVER_DAYS out, and an EXPIRED
      waiver refuse the whole file (an expired entry is only not in force);
      with --require-approved a pending one is not in force. With
      --emit-waivers OUT it writes the waivers in force (JSON, without the
      statement) for grype-db-providers --waivers.

  not-covered PATH [--require-approved]
      Validate scripts/ci/image-vuln-gate-not-covered.txt (same approval
      fields; format in that file's header).

  pending IGNORE_FILE NOT_COVERED_FILE GRYPE_IGNORE_FILE
      The release skills' pre-tag check: validate the three files and fail
      (exit 1) when any ignore entry (of either scanner), provider waiver or
      not-covered listing that is not expired still
      has approval_ref `pending`, when any of them has EXPIRED or expires
      within RELEASE_WINDOW_DAYS (each publish leg re-reads the date, so one
      lapsing during the release fails the legs that have not run yet), or
      when either file is malformed. A release gate does not honour a pending
      or an expired one, so a tag cut with one fails at that image's publish
      leg after the other legs have pushed. One expiring within WARN_DAYS is
      printed as a warning.

  db-age METADATA_JSON [--downloaded-after EPOCH]
      Read Trivy's DB metadata.json, print UpdatedAt, DownloadedAt and the age,
      and fail when UpdatedAt is older than MAX_DB_AGE_HOURS, lies more than an
      hour in the future, or is unreadable; with --downloaded-after, also when
      DownloadedAt is earlier than EPOCH (the DB was not downloaded by this run).

  resolve-digest REPOSITORY:TAG [--deadline SECONDS]
      Resolve a registry tag to its manifest digest (anonymous OCI registry
      API), so the DB download can be pinned to it and the digest recorded.
      The whole lookup (token and manifest requests) has one overall deadline
      (default RESOLVE_DEADLINE): the per-request timeout alone restarts on
      every byte, so a registry trickling bytes could hold it indefinitely.

  coverage TRIVY_REPORT_JSON NAME NOT_COVERED_FILE [--require-approved]
      Read a TRIVY JSON report (SchemaVersion 2; another scanner's report is
      refused, never read as "no packages"). Prints `verdict=`, `os_family=`,
      `os_name=`, `os=` and `os_packages=` lines. Fails (exit 1) when:
        - the OS package scan found no package (no OS detected, no os-pkgs
          result, or zero packages), unless NAME is listed, in force, in
          NOT_COVERED_FILE (exact name match);
        - Trivy marks the OS release end of service life (Metadata.OS.EOSL);
        - the OS family is not one the gate can prove has advisory data
          (CANARY_FAMILIES; see canary-rootfs);
        - the OS version is a pre-release (`verdict=pre-release`: a marker
          such as `_alpha`, `_rc`, `~`, `-rc`; PRERELEASE_MARKER) or not a
          released version number (`verdict=unsupported-os`). Trivy trims a
          pre-release version into the released advisory set (Alpine
          3.24.0_alpha... reads as 3.24, Debian 13.0~rc1 as 13), so a canary
          would match and the image would read as covered without advisory
          data for what it ships.

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

  grype-db-listing LISTING_JSON
      Read grype's DB listing (latest.json: status, schemaVersion, built,
      path, checksum) and print path=, checksum=, built= and schema= for the
      gate, which downloads that archive and checks its sha256 before grype
      imports it. Fails unless the status is `active`, the schema is v6, the
      path is a bare archive name, the checksum is a sha256, and `built` is
      at most MAX_DB_AGE_HOURS old and not more than an hour in the future.
      The listing is not signed upstream: TLS to the listing's host and the
      recorded checksum are the evidence of which DB was used.

  grype-db-status STATUS_JSON --built BUILT --schema SCHEMA
      Read `grype db status -o json` after the import and fail unless grype
      reports the DB valid, with the listing's `built` and schemaVersion, and
      at most MAX_DB_AGE_HOURS old: the DB grype will scan with is the one the
      gate downloaded and verified.

  grype-db-providers PROVIDERS_JSON [--waivers WAIVERS_JSON] PROVIDER...
      Read `grype db providers -o json` and fail unless every named provider
      is listed with a dateCaptured at most MAX_DB_AGE_HOURS old (and not more
      than an hour in the future). The DB's own `built` time says when it was
      assembled, not how fresh each source in it is: a provider whose capture
      went stale would otherwise read as current. With --waivers (the file
      grype-ignore-file --emit-waivers wrote), a provider with a waiver in
      force whose readable capture is merely older than MAX_DB_AGE_HOURS
      passes, with a `waiver: ...` line naming its age and the waiver; a
      missing provider, an unreadable or future capture time, or an
      unreadable waivers file still fails.

  grype-components CYCLONEDX_JSON NAME[=VERSION]...
      Read grype's CycloneDX output (every catalogued component) and fail
      unless each NAME is a component with a version identified by grype
      itself (purl pkg:generic/NAME@VERSION), not an OS package of that name;
      with =VERSION, grype must report exactly that version. Used for an image whose
      point in running grype is a component Trivy cannot see (the gateway's
      Erlang/OTP runtime, `erlang`): grype's JSON report lists only matches, so
      a runtime grype never catalogued would otherwise read as clean.

  grype-report REPORT_JSON
      Read a GRYPE JSON report (another scanner's report is refused) and print
      grype_version=, image_id=, distro_family=, distro_version=, matches=,
      ignored=, fixable_critical= (in matches: not accepted) and
      fixable_critical_accepted= (in ignoredMatches: accepted) lines.
"""

import datetime as dt
import hashlib
import json
import os
import re
import signal
import sys
import urllib.error
import urllib.parse
import urllib.request

MAX_EXPIRY_DAYS = 92
WARN_DAYS = 21
# The pre-tag check fails an acceptance expiring sooner than this (today or
# tomorrow): a release, re-runs included, can run past midnight.
RELEASE_WINDOW_DAYS = 2
MAX_DB_AGE_HOURS = 72
# A provider waiver (`provider_waivers:` in .grypeignore.yaml) admits one grype
# DB provider whose capture is older than MAX_DB_AGE_HOURS, for a release that
# cannot wait for a stalled upstream. It waives that one freshness check and
# nothing else (not a missing provider, not an unreadable or future capture
# time, not the DB's own age, checksum or status, not a finding), so its expiry
# is far tighter than an acceptance's. The providers are a closed set: NVD (the
# OTP runtime's matches) and the canary families' OS providers.
MAX_WAIVER_DAYS = 14
WAIVABLE_PROVIDERS = ("nvd", "alpine", "debian", "ubuntu")
WAIVER_KEYS = ("provider", "statement", "expired_at", "approved_by", "approved_on", "approval_ref")

ENTRY_KEYS = ("id", "paths", "purls", "statement", "expired_at", "approved_by",
              "approved_on", "approval_ref")
LIST_KEYS = ("paths", "purls")
GRYPE_ENTRY_KEYS = ("id", "package_name", "package_version", "package_type", "statement", "expired_at",
                    "approved_by", "approved_on", "approval_ref")
# grype 0.121.3 matches an ignore rule's package version and type by equality,
# but its package NAME as an anchored regular expression: checked 2026-11-20
# against a real match, `er+lang`, `erl[a]ng`, `erlang|zzz`, `e\wlang` and
# `^erlang$` all suppressed package `erlang`, `erlang++` (an invalid pattern)
# suppressed nothing, while `e.lang`, `rlang` and `erlan` did not match (`.` is
# read literally). So a name may hold only characters grype reads literally:
# no `+`, brackets, `|`, `\`, `^`, `$`, `*`, `?`, parentheses or braces. A
# package whose name needs one (libstdc++) cannot be accepted here; its finding
# fails the gate until it is fixed. No field may hold whitespace either, so an
# entry cannot be read as wider than one package version.
GRYPE_PACKAGE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:@/-]{0,213}$")
GRYPE_PACKAGE_VERSION = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+:~-]{0,127}$")
GRYPE_PACKAGE_TYPE = re.compile(r"^[a-z][a-z0-9-]{0,31}$")
GRYPE_DB_PATH = re.compile(r"^vulnerability-db_v6\.[0-9]+\.[0-9]+_[0-9TZ:.-]+_[0-9]+\.tar\.(?:zst|gz|xz)$")
GRYPE_DB_SCHEMA = re.compile(r"^v6\.[0-9]+\.[0-9]+$")
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

# Names Trivy gives a scan result (Target, Class or Type) rather than a file.
# Trivy matches an entry's `paths` against the result's Target as well as the
# package's path, so a `paths` item equal to an aggregate target such as
# `Python` hides the CVE in every Python package of the image (chaos-verified
# with Trivy 0.70.0, G8P3-security-guardian-1). Every `paths` item must also
# contain a '/', which already refuses each name below; this list states the
# reason. Sources: the Class/Type values Trivy 0.70.0's JSON reports for the
# published images (os-pkgs, lang-pkgs; debian, ubuntu, alpine, gobinary,
# checked 2026-11-18; their os-pkgs targets hold a space and are refused as
# whitespace), the aggregate language targets, and Trivy's documented OS and
# language package types.
TRIVY_RESULT_NAMES = frozenset(n.casefold() for n in (
    # result classes
    "os-pkgs", "lang-pkgs", "config", "secret", "license", "license-file", "custom",
    # aggregate language targets (one result for all packages of a language)
    "Python", "Conda", "Node.js", "Java", "Ruby", "Rust", "Go", ".NET", "PHP", "Dart",
    "Elixir", "Swift", "Julia", "C++", "Bitnami",
    # OS types
    "alma", "alpine", "amazon", "azurelinux", "bottlerocket", "cbl-mariner", "centos", "chainguard",
    "coreos", "debian", "echo", "fedora", "minimos", "opensuse", "opensuse.leap",
    "opensuse.tumbleweed", "oracle", "photon", "redhat", "rocky", "sles", "sl-micro", "ubuntu",
    "wolfi",
    # language package types
    "bundler", "gemspec", "cargo", "composer", "composer-vendor", "npm", "yarn", "pnpm", "bun",
    "node-pkg", "javascript", "nuget", "dotnet-core", "packages-props", "pip", "pipenv", "poetry",
    "uv", "python-pkg", "conda-pkg", "conda-environment", "jar", "pom", "gradle", "sbt",
    "gobinary", "gomod", "rustbinary", "conan", "cocoapods", "swift", "pub", "hex", "bitnami",
    "julia",
))

# OS families the gate has a canary for (canary-rootfs). Every image the
# release publishes is on one of these; another family fails the gate until a
# canary is added for it.
# The gate's grype OS cross-check compares these names with grype's
# distro.name, which uses the same three spellings; a family added here must be
# checked against grype's name for it, or every image of that family is refused.
CANARY_FAMILIES = ("debian", "ubuntu", "alpine")
OS_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/+~-]{0,63}$")
# A pre-release marker in an OS version: Alpine `_alpha`/`_beta`/`_pre`/`_rc`/
# `_git` (edge reports 3.25.0_alpha20260101), Debian's `~` (13.0~rc1), and the
# `-rc`/`.rc`/`+beta` spellings. Trivy keeps only the leading release of such a
# version when it looks up advisories (Alpine major.minor, Debian major), so a
# pre-release reads as covered by the released set (G8P3-unhappy-path-1).
PRERELEASE_MARKER = re.compile(
    r"~|[._+-](?:alpha|beta|pre|rc|git|svn|cvs|hg|dev|snapshot)|(?:sid|testing|edge|devel)$", re.I)
# The released version shapes the canary families use: Debian 12.15, Ubuntu
# 26.04, Alpine 3.23.8.
RELEASED_VERSION = re.compile(r"^[0-9]+(?:\.[0-9]+){0,2}$")


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


def parse_sections(text, sections):
    """The one parser of an acceptance file: {section: [entries]} for each
    top-level block list named in `sections`, {name: (first key, entry keys,
    list keys)}: for .trivyignore.yaml `vulnerabilities` with ENTRY_KEYS and
    LIST_KEYS; for .grypeignore.yaml `vulnerabilities` with GRYPE_ENTRY_KEYS
    and no list key, and `provider_waivers` with WAIVER_KEYS (the schemas'
    sixth field). `vulnerabilities` is required; another section is optional,
    each at most once. Every section's entries follow the same shape rules."""
    lines = text.split("\n")
    out = {}
    section = None
    i = 0
    n = len(lines)
    names = ", ".join(f"`{s}:`" for s in sections)

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
            if not body.endswith(":") or body[:-1] not in sections:
                raise Bad(f"{where}: only {names} allowed at the top level")
            if body[:-1] in out:
                raise Bad(f"{where}: second `{body}` key")
            section = body[:-1]
            out[section] = []
            i += 1
            continue
        if section is None:
            raise Bad(f"{where}: content before {names}")
        first_key, entry_keys, list_keys = sections[section]
        if indent != 2 or not body.startswith("- "):
            raise Bad(f"{where}: expected an entry `  - {first_key}: ...` at indentation 2")
        # One entry: "  - id: X" (or "  - provider: X") then keys at indentation 4.
        first = body[2:]
        m = re.match(r"^([a-z_]+):(?:\s+(.*))?$", first)
        if not m or m.group(1) != first_key:
            raise Bad(f"{where}: every `{section}` entry starts with `- {first_key}:`")
        entry = {"_line": i + 1, first_key: plain_scalar(m.group(2) or "", where)}
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
            if key not in entry_keys or key == first_key:
                raise Bad(f"{where}: key `{key}` is not allowed in an entry")
            if key in entry:
                raise Bad(f"{where}: duplicate key `{key}`")
            i += 1
            if key in list_keys:
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
        out[section].append(entry)
    if "vulnerabilities" not in out:
        raise Bad("no `vulnerabilities:` key")
    for s in sections:
        out.setdefault(s, [])
    return out


def list_item(raw, where):
    """A `paths`/`purls` item: plain_scalar, but an empty quoted string is refused
    here too (plain_scalar returns "" for `""`)."""
    v = plain_scalar(raw, where)
    if v == "":
        raise Bad(f"{where}: empty string")
    return v


def path_problem(p):
    """Why `p` is not one concrete relative path to a file in the image, or None."""
    if p != p.strip() or any(c.isspace() for c in p):
        return "contains whitespace"
    if any(c in GLOB_CHARS for c in p):
        return "contains a glob character (* ? [ ] { } !): Trivy matches paths as globs"
    if "\\" in p:
        return "contains a backslash"
    if p.startswith("/"):
        return "starts with '/': Trivy's package paths are relative (usr/local/bin/gosu)"
    if p.casefold() in TRIVY_RESULT_NAMES:
        return ("is a Trivy result target, class or type name, not a path: Trivy matches `paths` against a "
                "result's target too, so it would hide the CVE in every package of that result")
    if "/" not in p:
        return ("is not a path inside the image (it has no '/'): write the file's path, e.g. "
                "usr/local/bin/gosu; a one-word value can match a Trivy target such as `Python`")
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


def trivy_scope_errors(tag, e, errors):
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
    return (e["id"], tuple(e.get("paths", ())), tuple(e.get("purls", ())))


def grype_scope_errors(tag, e, errors):
    for k, rx, what in (("package_name", GRYPE_PACKAGE_NAME, "grype's package name"),
                        ("package_version", GRYPE_PACKAGE_VERSION, "the package version")):
        v = e.get(k)
        if v is None:
            errors.append(f"{tag}: no `{k}` ({what}; never a bare id: an entry is one package version)")
        elif not rx.match(v):
            errors.append(f"{tag}: {k} {v!r} must be {what}, with no whitespace, glob or regular-expression "
                          f"character (grype reads a package name as a regular expression)")
    t = e.get("package_type")
    if t is not None and not GRYPE_PACKAGE_TYPE.match(t):
        errors.append(f"{tag}: package_type {t!r} must be a grype package type (lower-case, e.g. apk, binary)")
    return (e["id"], e.get("package_name"), e.get("package_version"), e.get("package_type"))


def emit_grype_yaml(entries, out):
    """The in-force entries as a grype config holding only `ignore:` rules.
    Every value is JSON-encoded (a JSON string is a valid YAML double-quoted
    scalar), so this file says exactly what was validated and nothing else."""
    lines = ["# Generated by image-vuln-gate-checks.py from the validated grype ignore file.",
             "ignore:"]
    for e in entries:
        lines.append(f"  - vulnerability: {json.dumps(e['id'])}")
        lines.append("    package:")
        lines.append(f"      name: {json.dumps(e['package_name'])}")
        lines.append(f"      version: {json.dumps(e['package_version'])}")
        if e.get("package_type"):
            lines.append(f"      type: {json.dumps(e['package_type'])}")
    if not entries:
        lines[-1] = "ignore: []"
    with open(out, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


TRIVY_SCHEMA = (ENTRY_KEYS, LIST_KEYS, trivy_scope_errors, emit_trivy_yaml,
                "a concrete scope, a statement, an expiry and approval fields (format-checked only)",
                {"vulnerabilities": ("id", ENTRY_KEYS, LIST_KEYS)})
GRYPE_SCHEMA = (GRYPE_ENTRY_KEYS, (), grype_scope_errors, emit_grype_yaml,
                "a package name and version, a statement, an expiry and approval fields (format-checked only)",
                {"vulnerabilities": ("id", GRYPE_ENTRY_KEYS, ()),
                 "provider_waivers": ("provider", WAIVER_KEYS, ())})


def read_ignore_sections(path, schema):
    """({section: entries}, None) or (None, message) for an unreadable or
    unparsable file."""
    try:
        with open(path, encoding="utf-8") as f:
            text = f.read()
    except (OSError, UnicodeDecodeError) as e:
        return None, f"{path}: unreadable: {e}"
    try:
        return parse_sections(text, schema[5]), None
    except Bad as e:
        return None, f"{path}: {e}"


def check_waivers(path, waivers, require_approved, errors, excluded, pending_all):
    """The in-force provider waivers of a grype acceptance file, and the
    problems with any, into `errors`. An expired waiver, or one more than
    MAX_WAIVER_DAYS out, is an ERROR that refuses the whole file (an expired
    acceptance merely stops being in force): a waiver is a temporary exception
    to a hard check, and one left behind must not linger in the tree. With
    `require_approved` (the release gate) a pending one is not in force."""
    now = today()
    seen = set()
    in_force = []
    for w in waivers:
        prov = w["provider"]
        tag = f"{path}:{w['_line']}: provider waiver {prov}"
        if prov not in WAIVABLE_PROVIDERS:
            errors.append(f"{tag}: provider must be one of {', '.join(WAIVABLE_PROVIDERS)}")
        if prov in seen:
            errors.append(f"{tag}: duplicate provider waiver")
        seen.add(prov)
        if "statement" not in w:
            errors.append(f"{tag}: no `statement` (why, with the evidence that the upstream source is stalled)")
        pending = check_approval(tag, w.get("approved_by"), w.get("approved_on"), w.get("approval_ref"), errors)
        exp = parse_date(w.get("expired_at"))
        if "expired_at" not in w or exp is None:
            errors.append(f"{tag}: expired_at must be a YYYY-MM-DD date")
            continue
        left = (exp - now).days
        if left > MAX_WAIVER_DAYS:
            errors.append(f"{tag}: expired_at {exp} is {left} days out; the maximum for a provider waiver is "
                          f"{MAX_WAIVER_DAYS}")
            continue
        if left < 0:
            errors.append(f"{tag}: expired on {exp}; an expired provider waiver refuses the file: remove it "
                          f"(or renew it with a new review and approval)")
            continue
        if pending:
            pending_all.append(w)
        if pending and require_approved:
            excluded.append(w)
            print(f"NOT IN FORCE: {tag}: approval_ref is pending; a release gate honours only a provider waiver "
                  f"whose approval is recorded (docs/ci-architecture.md \"Recording an approval\")")
            continue
        if pending:
            print(f"warning: {tag}: approval_ref is pending; honoured here, but the release gate "
                  f"(--release) does not honour it")
        print(f"note: {tag}: in force until {exp}: an image may be judged with grype DB provider {prov} "
              f"older than {MAX_DB_AGE_HOURS} hours, and its report then says so; a release judged with it "
              f"must say so in its release notes")
        in_force.append(w)
    return in_force


def emit_waivers_json(path, waivers, out):
    """The in-force provider waivers, for grype-db-providers --waivers. Every
    value written has passed the format checks above (the statement is left
    out: it is free text, and the reports and logs name the file line)."""
    rows = [{"provider": w["provider"], "expired_at": w["expired_at"], "approved_by": w["approved_by"],
             "approval_ref": w["approval_ref"], "approved_on": w.get("approved_on") or "-",
             "where": f"{os.path.basename(path)}:{w['_line']}"} for w in waivers]
    with open(out, "w", encoding="utf-8") as f:
        json.dump(rows, f)
        f.write("\n")


def cmd_ignore_file(path, emit=None, require_approved=False, schema=TRIVY_SCHEMA, emit_waivers=None):
    sections, why = read_ignore_sections(path, schema)
    if sections is None:
        print(why, file=sys.stderr)
        return 1
    entries = sections["vulnerabilities"]
    waiver_errors, waivers_excluded, waivers_pending = [], [], []
    waivers_in_force = check_waivers(path, sections.get("provider_waivers", []), require_approved,
                                     waiver_errors, waivers_excluded, waivers_pending)
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
        key = schema[2](tag, e, errors)
        pending = check_approval(tag, e.get("approved_by"), e.get("approved_on"), e.get("approval_ref"), errors)
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
                print(f"NOT IN FORCE: {tag}: approval_ref is pending; a release gate honours only an acceptance "
                      f"whose approval is recorded (set approval_ref and approved_on from the approving pull "
                      f"request: docs/ci-architecture.md \"Recording an approval\")")
                continue
            pending_honoured += 1
            print(f"warning: {tag}: approval_ref is pending; honoured here, but the release gate "
                  f"(--release) does not honour it")
        in_force.append(e)
    errors += waiver_errors
    if errors:
        for m in errors:
            print(m, file=sys.stderr)
        return 1
    try:
        if emit:
            schema[3](in_force, emit)
        if emit_waivers:
            emit_waivers_json(path, waivers_in_force, emit_waivers)
    except OSError as e:
        print(f"cannot write the generated file: {e}", file=sys.stderr)
        return 1
    print(f"{path}: {len(entries)} entry(ies), each with {schema[4]}")
    print(f"in_force={len(in_force)}")
    print(f"pending={pending_excluded + pending_honoured}")
    print(f"pending_not_honoured={pending_excluded}")
    if "provider_waivers" in schema[5]:
        print(f"waivers_in_force={len(waivers_in_force)}")
        print(f"waivers_pending={len(waivers_pending)}")
        print(f"waivers_pending_not_honoured={len(waivers_excluded)}")
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


RESOLVE_DEADLINE = 90


class Deadline(Exception):
    pass


def _alarm(signum, frame):
    raise Deadline()


def cmd_resolve_digest(ref, timeout=30, deadline=RESOLVE_DEADLINE):
    if not 1 <= deadline <= 3600:
        print(f"resolve-digest: deadline {deadline} is outside 1..3600 seconds", file=sys.stderr)
        return 1
    old = signal.signal(signal.SIGALRM, _alarm)
    signal.alarm(deadline)
    try:
        return _resolve_digest(ref, timeout)
    except Deadline:
        print(f"resolve-digest: {ref}: no answer within the {deadline}s deadline", file=sys.stderr)
        return 1
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, old)


def _resolve_digest(ref, timeout):
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


def cmd_pending(ignore_path, not_covered_path, grype_path):
    """Exit 1 when any file is malformed or anything in force is pending."""
    found = []
    files = []
    waivers = []
    for path, schema in ((ignore_path, TRIVY_SCHEMA), (grype_path, GRYPE_SCHEMA)):
        sections, why = read_ignore_sections(path, schema)
        if sections is None:
            print(why, file=sys.stderr)
            return 1
        if cmd_ignore_file(path, schema=schema) != 0:
            return 1
        files.append((path, sections["vulnerabilities"]))
        waivers += [(path, w) for w in sections.get("provider_waivers", [])]
    now = today()

    def check_expiry(tag, exp):
        left = (exp - now).days
        if left < 0:
            found.append(f"{tag}: expired on {exp}: not in force, so a release fails on what it accepted; "
                         f"renew it (a new review and approval) or remove it")
        elif left < RELEASE_WINDOW_DAYS:
            found.append(f"{tag}: expires on {exp}, within {RELEASE_WINDOW_DAYS} days: it can lapse during the "
                         f"release and fail the legs that run after; renew it or remove it")
        elif left <= WARN_DAYS:
            print(f"warning: {tag}: expires on {exp} ({left} days)")

    for path, entries in files:
        for e in entries:
            exp = parse_date(e.get("expired_at"))
            tag = f"{path}:{e['_line']}: {e['id']}"
            if exp is not None:
                check_expiry(tag, exp)
            if e.get("approval_ref") == PENDING and exp is not None and exp >= now:
                found.append(f"{tag}: approval_ref is pending")
    for path, w in waivers:
        # Validation above already refused an expired or too-distant waiver.
        tag = f"{path}:{w['_line']}: provider waiver {w['provider']}"
        check_expiry(tag, parse_date(w["expired_at"]))
        if w.get("approval_ref") == PENDING:
            found.append(f"{tag}: approval_ref is pending")
    try:
        listed = read_not_covered(not_covered_path, require_approved=True)
        with open(not_covered_path, encoding="utf-8") as f:
            nc_lines = f.read().split("\n")
    except (OSError, UnicodeDecodeError, Bad) as e:
        print(f"{not_covered_path}: {e}", file=sys.stderr)
        return 1
    for no, line in enumerate(nc_lines, 1):
        m = NOT_COVERED_LINE.match(line)
        if m and not line.lstrip().startswith("#"):
            check_expiry(f"{not_covered_path}:{no}: {m.group('name')}", parse_date(m.group("exp")))
    for name, (_, in_force, why) in listed.items():
        if not in_force and "pending" in why:
            found.append(f"{not_covered_path}: {name}: approval_ref is pending")
    for m in found:
        print(m, file=sys.stderr)
    if found:
        print(f"{len(found)} problem(s) above: a release gate does not honour a pending or expired acceptance "
              f"or listing, so record each approving pull request and date, and renew or remove what expires, "
              f"before tagging", file=sys.stderr)
        return 1
    print("no pending, expired or expiring acceptance or listing")
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
        if PRERELEASE_MARKER.search(os_name):
            print("verdict=pre-release")
            print(f"{name or report}: {os_desc} is a pre-release, and there is no advisory data for a "
                  f"pre-release: Trivy reads it against the released version's advisories, so a clean scan "
                  f"proves nothing. Build on a released OS version", file=sys.stderr)
            return 1
        if not RELEASED_VERSION.match(os_name):
            print("verdict=unsupported-os")
            print(f"{name or report}: OS version {os_name!r} is not a released version number "
                  f"(N, N.N or N.N.N), so the gate cannot show advisory data exists for it", file=sys.stderr)
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


# ── grype: the DB listing, the imported DB, the report ─────────────────────
def _db_age(what, built_raw):
    """(kind, why, age_hours): kind None (usable), "unreadable", "future" or
    "stale" (older than MAX_DB_AGE_HOURS). Only "stale" is ever waivable, and
    only for a grype DB provider (cmd_grype_db_providers)."""
    try:
        built = parse_time(built_raw)
    except (ValueError, TypeError):
        return "unreadable", f"{what}: built {built_raw!r} is not an RFC 3339 time", None
    age_h = (dt.datetime.now(dt.timezone.utc) - built).total_seconds() / 3600
    if age_h < -1:
        return "future", f"{what}: built {built_raw} is in the future", age_h
    if age_h > MAX_DB_AGE_HOURS:
        return "stale", (f"{what}: built {age_h:.0f} hours ago ({built_raw}), more than {MAX_DB_AGE_HOURS}; a "
                         f"stale DB misses recent fixes, so the gate does not pass on it"), age_h
    return None, None, age_h


def _db_age_problem(what, built_raw):
    """None, or why a DB built at `built_raw` may not be used."""
    return _db_age(what, built_raw)[1]


def _load_json_object(path, what):
    with open(path, encoding="utf-8") as f:
        d = json.load(f)
    if not isinstance(d, dict):
        raise ValueError(f"{path} is not a JSON object ({what})")
    return d


def cmd_grype_db_listing(path):
    try:
        d = _load_json_object(path, "grype DB listing")
    except (OSError, ValueError, RecursionError) as e:
        print(f"grype DB listing {path} is missing or unreadable ({e})", file=sys.stderr)
        return 1
    problems = []
    if d.get("status") != "active":
        problems.append(f"status {d.get('status')!r} is not 'active'")
    schema = d.get("schemaVersion")
    if not isinstance(schema, str) or not GRYPE_DB_SCHEMA.match(schema):
        problems.append(f"schemaVersion {schema!r} is not v6.N.N")
    db_path = d.get("path")
    if not isinstance(db_path, str) or not GRYPE_DB_PATH.match(db_path):
        problems.append(f"path {db_path!r} is not a bare vulnerability-db_v6 archive name")
    checksum = d.get("checksum")
    if not isinstance(checksum, str) or not DIGEST.match(checksum):
        problems.append(f"checksum {checksum!r} is not sha256:<64 hex>")
    built = d.get("built")
    why = _db_age_problem("the listed grype DB", built if isinstance(built, str) else repr(built))
    if why:
        problems.append(why)
    if problems:
        for m in problems:
            print(f"grype DB listing {path}: {m}", file=sys.stderr)
        return 1
    print(f"path={db_path}")
    print(f"checksum={checksum}")
    print(f"built={built}")
    print(f"schema={schema}")
    return 0


def cmd_grype_db_status(path, built, schema):
    try:
        d = _load_json_object(path, "grype db status")
    except (OSError, ValueError, RecursionError) as e:
        print(f"grype db status {path} is missing or unreadable ({e}); refusing to scan with a DB of unknown "
              f"state", file=sys.stderr)
        return 1
    problems = []
    if d.get("valid") is not True:
        problems.append(f"grype reports the DB as not valid ({d.get('error')!r})")
    if d.get("built") != built:
        problems.append(f"built {d.get('built')!r} is not the listing's {built!r}: not the DB this run verified")
    if d.get("schemaVersion") != schema:
        problems.append(f"schemaVersion {d.get('schemaVersion')!r} is not the listing's {schema!r}")
    why = _db_age_problem("the imported grype DB", d.get("built") if isinstance(d.get("built"), str)
                          else repr(d.get("built")))
    if why:
        problems.append(why)
    if problems:
        for m in problems:
            print(f"grype db status: {m}", file=sys.stderr)
        return 1
    print(f"grype_db_built={built}")
    print(f"grype_db_schema={schema}")
    return 0


def read_waivers_json(path):
    """{provider: waiver} from the file grype-ignore-file --emit-waivers wrote.
    Raises ValueError on anything else. A waiver whose date has passed since
    that file was written (a run crossing midnight) is left out."""
    with open(path, encoding="utf-8") as f:
        rows = json.load(f)
    if not isinstance(rows, list):
        raise ValueError("not a JSON list of provider waivers")
    out = {}
    for w in rows:
        if not isinstance(w, dict) or w.get("provider") not in WAIVABLE_PROVIDERS or w["provider"] in out:
            raise ValueError(f"not a provider waiver of a waivable provider: {w!r}")
        for k in ("expired_at", "approved_by", "approval_ref", "approved_on", "where"):
            if not isinstance(w.get(k), str):
                raise ValueError(f"provider waiver {w['provider']}: no {k}")
        exp = parse_date(w["expired_at"])
        if exp is None:
            raise ValueError(f"provider waiver {w['provider']}: expired_at is not a date")
        if exp >= today():
            out[w["provider"]] = w
    return out


def _hours(age_h):
    return "an unknown number of hours" if age_h is None else f"{age_h:.0f} hours"


def cmd_grype_db_providers(path, required, waivers_path=None):
    try:
        waivers = read_waivers_json(waivers_path) if waivers_path is not None else {}
    except (OSError, ValueError, RecursionError) as e:
        print(f"provider waivers {waivers_path} are missing or unreadable ({e})", file=sys.stderr)
        return 1
    try:
        with open(path, encoding="utf-8") as f:
            rows = json.load(f)
        if not isinstance(rows, list) or not all(isinstance(r, dict) for r in rows):
            raise ValueError("not a JSON list of provider objects")
    except (OSError, ValueError, RecursionError) as e:
        print(f"grype db providers {path} is missing or unreadable ({e})", file=sys.stderr)
        return 1
    by_name = {r.get("name"): r for r in rows if isinstance(r.get("name"), str)}
    problems = []
    for name in required:
        r = by_name.get(name)
        if r is None:
            # A waiver never admits a missing provider: there is nothing to be stale.
            problems.append(f"provider {name!r} is not in the DB")
            continue
        captured = r.get("dateCaptured")
        kind, why, age_h = _db_age(f"provider {name}", captured if isinstance(captured, str) else repr(captured))
        if kind is None:
            print(f"provider_{name}={captured}")
        elif kind == "stale" and name in waivers:
            # The ONE thing a provider waiver admits: a capture time that reads
            # fine and is merely older than MAX_DB_AGE_HOURS.
            w = waivers[name]
            print(f"provider_{name}={captured}")
            print(f"waiver: provider {name} captured {captured}, {_hours(age_h)} old (over the "
                  f"{MAX_DB_AGE_HOURS}-hour limit), admitted by the provider waiver at {w['where']}: expires "
                  f"{w['expired_at']}, approved_by {w['approved_by']}, approval_ref {w['approval_ref']}, "
                  f"approved_on {w['approved_on']}")
        else:
            if kind == "stale":
                why += (f" (only a reviewed provider waiver for {name} in .grypeignore.yaml admits a stale "
                        f"provider: docs/ci-architecture.md \"A grype DB provider is stale\")")
            problems.append(why)
    if problems:
        for m in problems:
            print(f"grype db providers: {m}", file=sys.stderr)
        return 1
    return 0


def cmd_grype_components(path, names):
    try:
        d = _load_json_object(path, "grype CycloneDX output")
        comps = d.get("components")
        if not isinstance(comps, list):
            raise ValueError(f"{path} has no components list")
    except (OSError, ValueError, RecursionError) as e:
        print(f"grype components: cannot read {e}", file=sys.stderr)
        return 1
    # A component counts only as grype's own binary identification of it
    # (purl pkg:generic/<name>@<version>, as grype 0.121.3 reports the
    # gateway's beam.smp), so an OS package of the same name cannot stand in.
    found = {}
    for comp in comps:
        if not isinstance(comp, dict):
            continue
        name, ver, purl = comp.get("name"), comp.get("version"), comp.get("purl")
        if isinstance(name, str) and isinstance(ver, str) and ver and isinstance(purl, str) \
                and purl == f"pkg:generic/{name}@{ver}":
            found.setdefault(name, ver)
    missing, wrong = [], []
    for spec in names:
        n, _, want = spec.partition("=")
        if n not in found:
            missing.append(n)
        elif want and found[n] != want:
            wrong.append(f"{n} {found[n]} (expected {want})")
        else:
            print(f"component_{n}={found[n]}")
    if wrong:
        print(f"grype catalogued {', '.join(wrong)}: a version grype misread, or an image whose runtime is not "
              f"the one the gate's table pins", file=sys.stderr)
    if missing:
        print(f"grype did not catalogue {', '.join(missing)} (as pkg:generic, with a version) in the image, so it "
              f"could not "
              f"match its vulnerabilities", file=sys.stderr)
    return 1 if missing or wrong else 0


def cmd_grype_report(path):
    try:
        d = _load_json_object(path, "grype report")
        desc = d.get("descriptor")
        if not isinstance(desc, dict) or desc.get("name") != "grype" or not isinstance(d.get("matches"), list):
            raise ValueError(f"{path} is not a grype JSON report (descriptor.name grype, a matches list)")
        ignored = d.get("ignoredMatches") or []
        if not isinstance(ignored, list):
            raise ValueError(f"{path}: ignoredMatches is not a list")
        distro = d.get("distro") or {}
        source = d.get("source") or {}
        target = source.get("target") if isinstance(source, dict) else None
        if not isinstance(distro, dict) or (target is not None and not isinstance(target, dict)):
            raise ValueError(f"{path}: distro or source.target is not an object")
        def fixable_critical(rows):
            n = 0
            for m in rows:
                v = m.get("vulnerability") if isinstance(m, dict) else None
                if not isinstance(v, dict):
                    raise ValueError(f"{path}: a match has no vulnerability object")
                fix = v.get("fix") if isinstance(v.get("fix"), dict) else {}
                if v.get("severity") == "Critical" and fix.get("state") == "fixed":
                    n += 1
            return n

        # The record scan already applies the acceptances: an accepted finding
        # is in ignoredMatches, not matches. Count both, never one as the other.
        crit = fixable_critical(d["matches"])
        crit_accepted = fixable_critical(ignored)
    except (OSError, ValueError, RecursionError, AttributeError) as e:
        print(f"grype report: cannot read {e}", file=sys.stderr)
        return 1
    print(f"grype_version={desc.get('version', '?')}")
    print(f"image_id={(target or {}).get('imageID') or '?'}")
    print(f"distro_family={distro.get('name') or ''}")
    print(f"distro_version={distro.get('version') or ''}")
    print(f"matches={len(d['matches'])}")
    print(f"ignored={len(ignored)}")
    print(f"fixable_critical={crit}")
    print(f"fixable_critical_accepted={crit_accepted}")
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
        elif argv and argv[0] == "grype-ignore-file":
            pos, f = flags(argv[1:], {"--emit": True, "--emit-waivers": True, "--require-approved": False})
            if len(pos) == 1:
                return cmd_ignore_file(pos[0], f.get("--emit"), bool(f.get("--require-approved")),
                                       schema=GRYPE_SCHEMA, emit_waivers=f.get("--emit-waivers"))
        elif len(argv) == 4 and argv[0] == "pending":
            return cmd_pending(argv[1], argv[2], argv[3])
        elif len(argv) == 2 and argv[0] == "grype-db-listing":
            return cmd_grype_db_listing(argv[1])
        elif argv and argv[0] == "grype-db-status":
            pos, f = flags(argv[1:], {"--built": True, "--schema": True})
            if len(pos) == 1 and f.get("--built") and f.get("--schema"):
                return cmd_grype_db_status(pos[0], f["--built"], f["--schema"])
        elif argv and argv[0] == "grype-db-providers":
            pos, f = flags(argv[1:], {"--waivers": True})
            if len(pos) >= 2:
                return cmd_grype_db_providers(pos[0], pos[1:], f.get("--waivers"))
        elif len(argv) >= 3 and argv[0] == "grype-components":
            return cmd_grype_components(argv[1], argv[2:])
        elif len(argv) == 2 and argv[0] == "grype-report":
            return cmd_grype_report(argv[1])
        elif argv and argv[0] == "db-age":
            pos, f = flags(argv[1:], {"--downloaded-after": True})
            if len(pos) == 1:
                after = f.get("--downloaded-after")
                return cmd_db_age(pos[0], int(after) if after is not None else None)
        elif argv and argv[0] == "resolve-digest":
            pos, f = flags(argv[1:], {"--deadline": True})
            if len(pos) == 1:
                d = f.get("--deadline")
                return cmd_resolve_digest(pos[0], deadline=int(d) if d is not None else RESOLVE_DEADLINE)
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
