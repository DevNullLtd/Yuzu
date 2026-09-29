#!/usr/bin/env python3
"""plugin_doc_gen.py — per-plugin README generator (docs/plugin-readme-standard.md).

Rewrites the generated fences in every ``agents/plugins/<name>/README.md``, the
generated index block in ``docs/user-manual/agent-plugins.md``, the site
navigation fragment ``site/src/nav.plugins.mjs`` and the machine manifests
``content/plugin-docs/<name>.json`` from four code-adjacent sources:

* the CI-verified capability-matrix block in ``docs/os-capability-matrix.md``
  (per action, per OS: support, rung, mechanism, fallback) — this is the
  descriptor truth without a build, because ``scripts/ci/check-capability-matrix.sh``
  byte-diffs it against the compiled plugins;
* ``content/definitions/*.yaml`` (definition ids, parameters, result columns,
  roles, approval mode, gather);
* ``server/core/src/capability_decls/*.hpp`` (securable, operation, risk,
  dispatch class, mutability, execute gate);
* the plugin directory itself (identity regex over the plugin TU, samples,
  source listing) plus ``tests/`` and ``changelog.d/`` by name.

Everything is read from the checked-out tree — never from git history or a
running process — so the byte-gate produces the same bytes on every host
and on a shallow clone.

No build is required. Only captures (``tools/plugin-capture``) need a built
plugin, and only on that leg's OS.

Every parser and renderer is a module-level pure function so
``tests/test_plugin_doc_gen.py`` can exercise it on inline fixtures;
``tests/test_plugin_readmes.py`` imports ``check_repo`` to gate the tree.
"""
from __future__ import annotations

import argparse
import difflib
import hashlib
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

try:
    import yaml  # PyYAML — a CI dependency already (requirements-ci.in)
except ImportError:  # pragma: no cover - surfaced as a clear error at runtime
    yaml = None

MANIFEST_VERSION = 1
END_MARK = "<!-- END GENERATED -->"
README_BLOCKS = ("header", "capability", "inputs", "outputs", "samples", "source")
OS_ORDER = ("windows", "macos", "linux")
OS_LABEL = {"windows": "Windows", "macos": "macOS", "linux": "Linux"}
HOST_CLASSES = ("bare-metal", "vm", "container")
YAML_PLATFORM = {"windows": "windows", "linux": "linux", "darwin": "macos"}
SUPPORT_ICON = {"supported": "✅", "constrained": "🟡", "planned": "🟡", "unsupported": "⛔",
                "undeclared": "⛔"}
SAMPLE_ROW_LIMIT = 12
MANIFEST_SAMPLE_ROWS = 5
HEADINGS = (
    "## How it works",
    "## OS capability",
    "## Privileges and prerequisites",
    "## Data contract",
    "## Sample output",
    "## Caveats and known gaps",
    "## Source and tests",
)
HAND_SECTIONS = (
    "## How it works",
    "## Privileges and prerequisites",
    "### Outputs",
    "### Result status",
    "### Where the data goes",
    "## Caveats and known gaps",
)
CAPDECL_GLOB = "server/core/src/capability_decls/*.hpp"


# ── data model ────────────────────────────────────────────────────────────────

@dataclass
class Leg:
    support: str
    rung: str
    mechanism: str
    fallback: str


@dataclass
class CapRow:
    plugin: str
    action: str
    dispatch_class: str
    mutability: str
    securable: str
    operation: str
    risk_tier: str
    execute_gate: str
    fragment: str


@dataclass
class Definition:
    id: str
    display_name: str
    description: str
    plugin: str
    action: str
    platforms: list[str]
    approval_mode: str
    execute_roles: list[str]
    author_roles: list[str]
    gather: dict
    parameters: dict
    columns: list[dict]
    path: str


@dataclass
class Sample:
    os: str
    stamp: dict
    actions: list[dict]


@dataclass
class PluginDoc:
    name: str
    version: str
    description: str
    legs: dict[str, dict[str, Leg]]           # action -> os -> Leg
    cap_rows: list[CapRow]
    definitions: list[Definition]
    samples: dict[str, Sample]
    source: dict
    readme_path: str
    warnings: list[str] = field(default_factory=list)


# ── source parsers (pure) ─────────────────────────────────────────────────────

_UNESCAPED_PIPE_RE = re.compile(r"(?<!\\)\|")


def split_md_row(line: str) -> list[str]:
    r"""Split one Markdown table row on UNESCAPED pipes only; `\|` inside a
    cell is a literal pipe (GFM's own escape), unescaped in the returned cell.
    Shared by the hand-table parser and the capability-matrix parser — both
    feed byte-gated artefacts, so both must agree with the renderer."""
    body = line.strip()
    if body.startswith("|"):
        body = body[1:]
    if body.endswith("|") and not body.endswith("\\|"):
        body = body[:-1]
    return [c.strip().replace("\\|", "|") for c in _UNESCAPED_PIPE_RE.split(body)]


def parse_matrix_block(text: str) -> dict[str, dict[str, dict[str, Leg]]]:
    """Parse the capmatrix-gen block of docs/os-capability-matrix.md.

    Returns plugin -> action -> os -> Leg. Only the first generated block (the
    7-column ``| Plugin | Action | OS | Support | Rung | Mechanism | Fallback |``
    table) is read; the optional registries block that follows is ignored.
    """
    start = text.find("<!-- BEGIN GENERATED: capmatrix-gen")
    if start < 0:
        raise ValueError("capmatrix-gen block not found in os-capability-matrix.md")
    end = text.find(END_MARK, start)
    block = text[start:end if end > 0 else len(text)]
    out: dict[str, dict[str, dict[str, Leg]]] = {}
    for line in block.splitlines():
        if not line.startswith("| ") or line.startswith("| Plugin ") or line.startswith("|---"):
            continue
        cells = split_md_row(line)  # capmatrix-gen escapes a literal pipe as \| (GFM)
        if len(cells) < 7:
            continue
        plugin, action, os_name, support, rung, mechanism, fallback = cells[:7]
        if os_name not in OS_ORDER:
            continue
        out.setdefault(plugin, {}).setdefault(action, {})[os_name] = Leg(
            support=support,
            rung="" if rung == "-" else rung,
            mechanism="" if mechanism == "-" else mechanism,
            fallback="" if fallback == "-" else fallback,
        )
    return out


_CAP_FIELD_RE = re.compile(r"\.(\w+)\s*=\s*([^,]+?)\s*(?:,|$)", re.DOTALL)


def _find_capability_row_bodies(text: str) -> list[str]:
    """Every ``{...}`` designated-initialiser row body, honoring string
    literals and nested braces -- PR #4112 review, minor: the regex this
    replaces (``\\{\\s*(\\.plugin\\s*=.*?)\\}``) matches up to the FIRST
    literal ``}``, with no brace-depth or string-literal awareness. A ``}``
    inside a quoted field value (a rationale/description string) silently
    truncated the row there, defaulting every field after the truncation
    point to ``-`` with no warning of any kind -- worse than a warning, a
    silently wrong security-relevant row (securable/risk_tier/execute_gate
    all default that way). Depth-tracking also protects any future
    aggregate-typed field the same way.
    """
    rows: list[str] = []
    i, n = 0, len(text)
    while i < n:
        if text[i] == "{":
            j = i + 1
            while j < n and text[j].isspace():
                j += 1
            if text[j:j + 7] == ".plugin":
                depth, k, in_str = 1, i + 1, False
                while k < n and depth > 0:
                    c = text[k]
                    if in_str:
                        if c == "\\":
                            k += 1  # skip the escaped character, incl. \"
                        elif c == '"':
                            in_str = False
                    elif c == '"':
                        in_str = True
                    elif c == "{":
                        depth += 1
                    elif c == "}":
                        depth -= 1
                    k += 1
                if depth == 0:
                    rows.append(text[i + 1:k - 1])
                    i = k
                    continue
        i += 1
    return rows


def parse_capability_fragment(text: str, fragment: str) -> list[CapRow]:
    """Every ``CommandCapability`` designated-initialiser row in one fragment."""
    rows: list[CapRow] = []
    # Line comments are stripped from the whole fragment first: a comment
    # between `{` and `.plugin` (the rationale line many rows open with) or
    # after a field's value is never part of a value, and a comment-led row
    # left unmatched would silently drop the plugin's security row.
    stripped = re.sub(r"//[^\n]*", "", text)
    for body in _find_capability_row_bodies(stripped):
        fields: dict[str, str] = {}
        for fm in _CAP_FIELD_RE.finditer(body):
            key, raw = fm.group(1), fm.group(2).strip()
            raw = raw.strip('"')
            if "::" in raw:
                raw = raw.rsplit("::", 1)[1]
            fields[key] = raw
        if "plugin" not in fields or "action" not in fields:
            continue
        rows.append(CapRow(
            plugin=fields.get("plugin", ""), action=fields.get("action", ""),
            dispatch_class=fields.get("dispatch_class", "-"),
            mutability=fields.get("mutability", "-"),
            securable=fields.get("securable", "-"),
            operation=fields.get("operation", "-"),
            risk_tier=fields.get("risk_tier", "-"),
            execute_gate=fields.get("execute_gate", "-"),
            fragment=fragment,
        ))
    return rows


_NAME_RE = re.compile(
    r'std::string_view\s+name\(\)\s*const\s*noexcept\s*override\s*\{\s*return\s+(?:"([^"]+)"|(\w+))\s*;')
_VERSION_RE = re.compile(
    r'std::string_view\s+version\(\)\s*const\s*noexcept\s*override\s*\{\s*return\s+(?:"([^"]+)"|([\w:]+))\s*;')
_DESC_RE = re.compile(
    r'std::string_view\s+description\(\)\s*const\s*noexcept\s*override\s*\{\s*return\s+((?:"(?:[^"\\]|\\.)*"\s*)+);',
    re.DOTALL)
_LITERAL_RE = re.compile(r'"((?:[^"\\]|\\.)*)"')


_CPP_ESCAPES = {"\\\\": "\\", '\\"': '"', "\\n": " ", "\\t": " "}


def _unescape_cpp(literal: str) -> str:
    """Undo the four escapes a description literal realistically carries,
    without touching the (already UTF-8) bytes around them — `unicode_escape`
    would re-decode them as Latin-1."""
    return re.sub(r'\\\\|\\"|\\n|\\t', lambda m: _CPP_ESCAPES[m.group(0)], literal)


def _resolve_constant(text: str, ident: str) -> str | None:
    ident = ident.rsplit("::", 1)[-1]
    m = re.search(r'\b' + re.escape(ident) + r'\b[^=;]*=\s*"([^"]+)"', text)
    return m.group(1) if m else None


def parse_plugin_identity(text: str) -> dict[str, str | None]:
    """name/version/description from a plugin TU (the ``*_plugin.cpp`` with the
    ``name()`` override). Unresolvable values are ``None``."""
    name = version = description = None
    if m := _NAME_RE.search(text):
        name = m.group(1) or _resolve_constant(text, m.group(2))
    if m := _VERSION_RE.search(text):
        version = m.group(1) or _resolve_constant(text, m.group(2))
    if m := _DESC_RE.search(text):
        description = _unescape_cpp("".join(_LITERAL_RE.findall(m.group(1))))
    return {"name": name, "version": version, "description": description}

_SCALAR = (str, int, float, bool)


def _check_definition_shapes(spec: dict, perms: dict, result: dict, definition_id: str, path: str) -> None:
    """A scalar where the DSL wants a list renders letter-by-letter and ships a
    garbage manifest with a green gate; refuse it at the source, by file."""
    where = f"{path}: {definition_id}"
    for label, value in (("spec.platforms", spec.get("platforms")),
                         ("spec.permissions.executeRoles", perms.get("executeRoles")),
                         ("spec.permissions.authorRoles", perms.get("authorRoles")),
                         ("spec.result.columns", result.get("columns"))):
        if value is not None and not isinstance(value, list):
            raise ValueError(f"{where}: {label} must be a list, not {type(value).__name__}")
    if spec.get("parameters") is not None and not isinstance(spec.get("parameters"), dict):
        raise ValueError(f"{where}: spec.parameters must be an object")
    props = (spec.get("parameters") or {}).get("properties")
    if props is not None and not isinstance(props, dict):
        raise ValueError(f"{where}: spec.parameters.properties must be an object")
    for pname, pspec in (props or {}).items():
        if not isinstance(pspec, dict):
            raise ValueError(f"{where}: parameter {pname!r} must be an object")
        v = pspec.get("validation")
        if v is not None:
            if not isinstance(v, dict):
                raise ValueError(f"{where}: parameter {pname!r}: validation must be an object")
            if "enum" in v and not isinstance(v["enum"], list):
                raise ValueError(f"{where}: parameter {pname!r}: validation.enum must be a list")
            for key in ("pattern", "minLength", "maxLength", "minimum", "maximum"):
                if key in v and not isinstance(v[key], _SCALAR):
                    raise ValueError(f"{where}: parameter {pname!r}: validation.{key} must be a scalar")
    for col in result.get("columns") or []:
        if not isinstance(col, dict):
            raise ValueError(f"{where}: every spec.result.columns entry must be an object")


def _check_column_docs(c: dict, definition_id: str, path: str) -> None:
    """The four optional documentation keys of ``spec.result.columns[]``
    (docs/yaml-dsl-spec.md): the server ignores them, so nothing else would
    ever notice a scalar where a list was meant — and the manifest would then
    carry the wrong shape into ``yuzu://plugin-docs``."""
    where = f"{path}: {definition_id}.{c.get('name', '?')}"
    if c.get("description") is not None and not isinstance(c["description"], str):
        raise ValueError(f"{where}: `description` must be a string")
    values = c.get("values")
    if values is not None:
        if not isinstance(values, list) or not all(isinstance(v, _SCALAR) for v in values):
            raise ValueError(f"{where}: `values` must be a list of scalars")
        if str(c.get("type", "")) != "string":
            raise ValueError(f"{where}: `values` (a closed vocabulary) is only meaningful on a string column")
    if c.get("example") is not None and not isinstance(c["example"], _SCALAR):
        raise ValueError(f"{where}: `example` must be a scalar")
    platforms = c.get("platforms")
    if platforms is not None:
        if not isinstance(platforms, list) or not all(isinstance(pl, str) for pl in platforms):
            raise ValueError(f"{where}: `platforms` must be a list")
        bad = [pl for pl in platforms if pl not in YAML_PLATFORM]
        if bad:
            raise ValueError(f"{where}: `platforms` accepts {sorted(YAML_PLATFORM)}, not {bad}")


def parse_definition_docs(docs: Iterable[dict], path: str) -> list[Definition]:
    """InstructionDefinition documents (already YAML-loaded) -> Definition rows."""
    out: list[Definition] = []
    for doc in docs:
        if not isinstance(doc, dict) or doc.get("kind") != "InstructionDefinition":
            continue
        meta = doc.get("metadata") or {}
        spec = doc.get("spec") or {}
        execution = spec.get("execution") or {}
        plugin = execution.get("plugin") or spec.get("plugin")
        action = execution.get("action") or spec.get("action")
        if not plugin or not action:
            continue
        defn_id = str(meta.get("id", ""))
        perms = spec.get("permissions") or {}
        result = spec.get("result") or {}
        _check_definition_shapes(spec, perms, result, defn_id, path)
        columns = []
        for c in result.get("columns") or []:
            if isinstance(c, dict):
                _check_column_docs(c, defn_id, path)
                columns.append({
                    "name": str(c.get("name", "")),
                    "type": str(c.get("type", "")),
                    "description": c.get("description"),
                    "values": c.get("values"),
                    "example": c.get("example"),
                    "platforms": c.get("platforms"),
                })
        out.append(Definition(
            id=str(meta.get("id", "")),
            display_name=str(meta.get("displayName", "")),
            description=" ".join(str(meta.get("description", "")).split()),
            plugin=str(plugin), action=str(action),
            platforms=[str(p) for p in (spec.get("platforms") or [])],
            approval_mode=str((spec.get("approval") or {}).get("mode", "")),
            execute_roles=[str(r) for r in (perms.get("executeRoles") or [])],
            author_roles=[str(r) for r in (perms.get("authorRoles") or [])],
            gather=dict(spec.get("gather") or {}),
            parameters=dict(spec.get("parameters") or {}),
            columns=columns,
            path=path,
        ))
    return out


_STAMP_RE = re.compile(
    r"^captured:\s*(?P<os>\w+)\s+(?P<osver>.*?)\s+·\s+(?P<host>[\w-]+)\s+·\s+(?P<date>\d{4}-\d{2}-\d{2})"
    r"\s+·\s+(?P<priv>.*?)\s+·\s+leg-hash\s+(?P<hash>\w+)\s*$")
_ACTION_LINE_RE = re.compile(r"^== action=(?P<name>\S+)(?P<params>.*)$")
_STATUS_LINE_RE = re.compile(r"^\[result_status\]\s*(?P<status>\w+)\s*/\s*(?P<comp>\w+)\s*/\s*(?P<prov>.*)$")
_NOT_CAPTURED_RE = re.compile(r"^\[not captured\]\s*(?P<why>.*)$")
# The marker's class is a closed set (docs/plugin-readme-standard.md rule 5):
# `<DispatchClass>/<Mutability>` for a mutator never run live, `agent-context`
# when init needs services plugin-capture has no way to provide, or
# `hardware-absent`. Anything else is a typo the sweep would multiply.
_NOT_CAPTURED_CLASS_RE = re.compile(
    r"^(?P<cls>[A-Z][A-Za-z]+/[A-Z][A-Za-z]+|agent-context|hardware-absent):\s*(?P<reason>\S.*)$")
_TRUNCATED_RE = re.compile(r"^\[truncated\]\s*(?P<why>.*)$")
_RC_RE = re.compile(r"^\[rc\]\s*(?P<rc>-?\d+)\s*$")


def parse_sample(text: str, os_name: str) -> Sample:
    """Parse one ``docs/samples/<os>.txt`` file (plugin-capture output)."""
    lines = text.splitlines()
    if not lines:
        raise ValueError(f"{os_name}: empty sample file")
    m = _STAMP_RE.match(lines[0].strip())
    if not m:
        raise ValueError(f"{os_name}: first line is not a capture stamp: {lines[0]!r}")
    stamp = {"os": m.group("os"), "os_version": m.group("osver"), "host_class": m.group("host"),
             "date": m.group("date"), "privilege": m.group("priv"), "leg_hash": m.group("hash")}
    if stamp["os"] != os_name:
        raise ValueError(f"{os_name}: the stamp says os {stamp['os']!r} but the file is {os_name}.txt")
    if stamp["host_class"] not in HOST_CLASSES:
        raise ValueError(f"{os_name}: host class {stamp['host_class']!r} is not one of {', '.join(HOST_CLASSES)}")
    actions: list[dict] = []
    current: dict | None = None
    for line in lines[1:]:
        if am := _ACTION_LINE_RE.match(line):
            if any(a["action"] == am.group("name") for a in actions):
                raise ValueError(f"{os_name}: action {am.group('name')!r} appears twice")
            current = {"action": am.group("name"), "params": am.group("params").strip(),
                       "rows": [], "result_status": None, "not_captured": None,
                       "truncated": False, "rc": 0}
            actions.append(current)
        elif nm := _NOT_CAPTURED_RE.match(line):
            # A leg deliberately not executed (docs/plugin-readme-standard.md
            # rule 5): the marker is the sample, and its class is a closed set.
            if current is None:
                raise ValueError(f"{os_name}: `[not captured]` before any `== action=` line")
            cm = _NOT_CAPTURED_CLASS_RE.match(nm.group("why").strip())
            if not cm:
                raise ValueError(f"{os_name}: action {current['action']!r}: `[not captured]` must read "
                                 "`[not captured] <DispatchClass>/<Mutability>|agent-context|hardware-absent: <reason>`")
            current["not_captured"] = nm.group("why").strip()
        elif tm := _TRUNCATED_RE.match(line):
            if current is not None:
                current["truncated"] = True
        elif rm := _RC_RE.match(line):
            if current is not None:
                current["rc"] = int(rm.group("rc"))
        elif sm := _STATUS_LINE_RE.match(line):
            if current is not None:
                current["result_status"] = {"status": sm.group("status"),
                                            "completeness": sm.group("comp"),
                                            "provenance": sm.group("prov").strip()}
        elif current is not None and line.strip():
            current["rows"].append(line)
    if not actions:
        raise ValueError(f"{os_name}: no `== action=` block in the sample")
    for a in actions:
        # plugin-capture always closes an executed action with its status
        # line; a block without one is a short write (disk full, killed
        # process) or a hand-typed sample, and either must not pass as a
        # whole capture (rule 5).
        if a["not_captured"] is None and a["result_status"] is None:
            raise ValueError(f"{os_name}: action '{a['action']}' has no [result_status] line — "
                             "the capture is incomplete; recapture with plugin-capture")
        # PR #4112 review, minor: the inverse contradiction -- a leg marked
        # [not captured] (never executed) that ALSO carries row/status/rc
        # data (only producible by an executed run) is self-contradictory,
        # and was previously accepted silently.
        if a["not_captured"] is not None and (a["rows"] or a["result_status"] is not None or a["rc"]):
            raise ValueError(f"{os_name}: action '{a['action']}' has `[not captured]` but also "
                             "carries row/status/rc data — a leg is either not captured or "
                             "captured, never both")
    return Sample(os=os_name, stamp=stamp, actions=actions)


def leg_hash(legs: dict[str, dict[str, Leg]], definitions: list[Definition]) -> str:
    """Stable 12-hex digest of the declared legs and result columns.

    Fallback prose and every column key beyond name/type are excluded so a
    wording edit never forces a recapture; a mechanism, support, rung or
    column-shape change does."""
    payload = {
        "actions": {a: {o: {"support": l.support, "rung": l.rung, "mechanism": l.mechanism}
                        for o, l in sorted(os_legs.items())}
                    for a, os_legs in sorted(legs.items())},
        "columns": {d.id: [[c["name"], c["type"]] for c in d.columns]
                    for d in sorted(definitions, key=lambda d: d.id)},
    }
    digest = hashlib.sha256(json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
    return digest[:12]


# ── README hand-section parsing (manifest source) ─────────────────────────────

def split_sections(readme: str) -> dict[str, str]:
    """Map every ``##``/``###`` heading line to the text beneath it (up to the
    next heading of any level). Fenced code blocks are opaque to the split."""
    out: dict[str, str] = {}
    current = None
    buf: list[str] = []
    in_fence = False
    for line in readme.splitlines():
        if line.startswith("```"):
            in_fence = not in_fence
        if not in_fence and (line.startswith("## ") or line.startswith("### ")):
            if current is not None:
                out[current] = "\n".join(buf).strip()
            current, buf = line.strip(), []
            continue
        buf.append(line)
    if current is not None:
        out[current] = "\n".join(buf).strip()
    return out


def strip_generated(text: str) -> str:
    return re.sub(r"<!-- BEGIN GENERATED: plugin-doc-gen \w+ -->.*?<!-- END GENERATED -->", "",
                  text, flags=re.DOTALL).strip()


def strip_fences(text: str) -> str:
    return re.sub(r"```.*?```", "", text, flags=re.DOTALL).strip()


def parse_md_table(text: str) -> list[list[str]]:
    rows: list[list[str]] = []
    for line in text.splitlines():
        s = line.strip()
        if not s.startswith("|"):
            continue
        cells = split_md_row(s)
        if all(re.fullmatch(r":?-+:?", c or "-") for c in cells):
            continue
        rows.append(cells)
    return rows[1:] if rows else []


def parse_bullets(text: str) -> list[str]:
    items: list[str] = []
    for line in text.splitlines():
        s = line.strip()
        if re.match(r"^(?:[-*]|\d+\.)\s+", s):
            items.append(re.sub(r"^(?:[-*]|\d+\.)\s+", "", s))
        elif items and s:
            items[-1] += " " + s
    return items


def hand_sections_to_manifest(readme: str) -> dict:
    sec = split_sections(readme)
    priv_rows = parse_md_table(sec.get("## Privileges and prerequisites", ""))
    status_rows = parse_md_table(sec.get("### Result status", ""))
    return {
        "how_it_works": strip_fences(strip_generated(sec.get("## How it works", ""))),
        "outputs_note": strip_fences(strip_generated(sec.get("### Outputs", ""))),
        "privileges": [dict(zip(("os", "runs_as", "grant", "measured", "if_refused"), r + [""] * 5))
                       for r in priv_rows],
        "result_status": [dict(zip(("status", "completeness", "provenance", "when"), r + [""] * 4))
                          for r in status_rows],
        "where_the_data_goes": parse_bullets(sec.get("### Where the data goes", "")),
        "caveats": parse_bullets(sec.get("## Caveats and known gaps", "")),
    }


# ── README shape and sample coverage (the gate's checks, importable) ──────────

DATA_CONTRACT_ORDER = ("### Inputs", "### Outputs", "### Result status", "### Where the data goes")
HAND_TABLE_WIDTHS = (("## Privileges and prerequisites", 5), ("### Result status", 4))
# Provenance tokens reach the host through the CC-07 status seam. The gate
# takes them from (a) every literal passed to a status call in the plugin's own
# sources — `"<os>:<token>"`, `"<plugin>:<token>"`, or the literal prefix of a
# formatted token — and (b) the tokens a shared status-emitting header defines
# (runner_status.hpp's `subprocess_runner:*`) when the plugin includes it.
_STATUS_CALL_RE = re.compile(
    r"\b(?:set_result_status|mark_result_[a-z_]+|emit_unsupported|forward_runner_failure)\s*\(([^;]*?)\)\s*;",
    re.DOTALL)
_PROVENANCE_TOKEN_RE = re.compile(r'"([a-z][a-z0-9_]*:[a-z0-9_]+(?::[a-z0-9_]+)*)')
_OS_LITERAL_RE = re.compile(r'"((?:windows|macos|linux):[a-z0-9_:]+)"')
_INCLUDE_RE = re.compile(r'^\s*#include\s*[<"]([^>"]+)[>"]', re.MULTILINE)
_SHARED_HEADER_ROOTS = ("agents/core/include/yuzu/agent", "agents/shared", "agents/core/include")
_COMMENT_RE = re.compile(r"//[^\n]*|/\*.*?\*/", re.DOTALL)
_CAVEAT_ITEM_RE = re.compile(r"^\*\*[^*]+\*\*")  # parse_bullets has stripped the `1. `


def _heading_lines(text: str) -> list[str]:
    out, in_fence = [], False
    for line in text.splitlines():
        if line.startswith("```"):
            in_fence = not in_fence
        elif not in_fence and (line.startswith("## ") or line.startswith("### ")):
            out.append(line.strip())
    return out


def _ordered_subsequence(haystack: list[str], needles: Iterable[str]) -> bool:
    it = iter(haystack)
    return all(any(h == n for h in it) for n in needles)


def readme_shape_problems(text: str, name: str, rel: str, provenance_literals: Iterable[str] = ()) -> list[str]:
    """Rule 2 / rule 10 shape checks for one README; empty when it conforms.
    ``provenance_literals`` are the `<os>:<token>` strings the plugin source
    emits through set_result_status — each must be named in `### Result status`."""
    problems = []
    first = next((l for l in text.splitlines() if l.strip()), "")
    if first.strip() != f"# {name}":
        problems.append(f"{rel}: first line must be '# {name}', got {first!r}")
    heads = _heading_lines(text)
    if not _ordered_subsequence(heads, HEADINGS):
        problems.append(f"{rel}: the seven `##` section headings must appear in order {list(HEADINGS)}; found {heads}")
    if not _ordered_subsequence(heads, DATA_CONTRACT_ORDER):
        problems.append(f"{rel}: Data contract subsections must appear in order {list(DATA_CONTRACT_ORDER)}")
    sections = split_sections(text)
    for hand in HAND_SECTIONS:
        if not strip_generated(sections.get(hand, "")).strip():
            problems.append(f"{rel}: hand-written section '{hand}' is empty")
    for block in README_BLOCKS:
        if f"<!-- BEGIN GENERATED: plugin-doc-gen {block} -->" not in text:
            problems.append(f"{rel}: missing fence 'plugin-doc-gen {block}'")
    # Hand tables feed the manifest positionally: an unescaped `|` in a cell
    # shifts every field after it, deterministically, so the byte gate cannot
    # see it — the contracted column count can.
    for heading, width in HAND_TABLE_WIDTHS:
        for row in parse_md_table(sections.get(heading, "")):
            if len(row) != width:
                problems.append(f"{rel}: '{heading}' row has {len(row)} cells, contract is {width} "
                                f"(escape a literal pipe as \\|): {row[0][:40]!r}")
    priv_os = {row[0].strip() for row in parse_md_table(sections.get("## Privileges and prerequisites", ""))}
    for os_label in OS_LABEL.values():
        if os_label not in priv_os:
            problems.append(f"{rel}: '## Privileges and prerequisites' has no {os_label} row (one row per OS, "
                            "'n/a' where the leg does not exist)")
    caveats = parse_bullets(sections.get("## Caveats and known gaps", ""))
    if not 1 <= len(caveats) <= 5:
        problems.append(f"{rel}: '## Caveats and known gaps' has {len(caveats)} items; the contract is 1–5")
    for item in caveats:
        if not _CAVEAT_ITEM_RE.match(item):
            problems.append(f"{rel}: caveat does not open with a bold lead ('1. **Lead.** …'): {item[:50]!r}")
    if len(parse_bullets(sections.get("### Where the data goes", ""))) < 2:
        problems.append(f"{rel}: '### Where the data goes' needs at least the instruction-result bullet and the "
                        "'Not consumed by' bullet")
    where_bullets = parse_bullets(sections.get("### Where the data goes", ""))
    if not any(b.startswith("**Sensitivity") for b in where_bullets):
        problems.append(f"{rel}: '### Where the data goes' has no '**Sensitivity.**' bullet (what in the rows could "
                        "identify a device, a person or installed software)")
    status_text = sections.get("### Result status", "")
    for lit in sorted(set(provenance_literals)):
        if lit not in status_text:
            problems.append(f"{rel}: the source emits result provenance `{lit}` but '### Result status' does not "
                            "name it (every provenance token is listed, grouped by status)")
    return problems


def _strip_comments(text: str) -> str:
    return _COMMENT_RE.sub("", text)


_ADJACENT_LITERALS_RE = re.compile(r'"((?:[^"\\]|\\.)*)"(\s*"(?:[^"\\]|\\.)*")+')


def _join_adjacent_literals(text: str) -> str:
    """C++ concatenates adjacent string literals at compile time
    (`"macos" ":" "not_root"` is one string); a provenance token built that
    way is invisible to a scanner that only looks inside a single pair of
    quotes. Collapse every such run into one literal before matching."""
    def repl(m: re.Match) -> str:
        return '"' + "".join(_LITERAL_RE.findall(m.group(0))) + '"'
    return _ADJACENT_LITERALS_RE.sub(repl, text)


def provenance_literals(repo: Path, name: str) -> set[str]:
    out: set[str] = set()
    includes: set[str] = set()
    for src in sorted((repo / "agents" / "plugins" / name / "src").glob("*"), key=lambda q: q.as_posix()):
        if not (src.is_file() and src.suffix in (".cpp", ".hpp", ".h", ".mm")):
            continue
        text = _join_adjacent_literals(_strip_comments(_read(src)))
        for call in _STATUS_CALL_RE.findall(text):
            out.update(_PROVENANCE_TOKEN_RE.findall(call))
        out.update(_OS_LITERAL_RE.findall(text))
        includes.update(_INCLUDE_RE.findall(text))
    for inc in sorted(includes):
        for root in _SHARED_HEADER_ROOTS:
            header = repo / root / inc
            if header.is_file():
                text = _strip_comments(_read(header))
                if "set_result_status" in text:
                    out.update(m.group(1) for m in _PROVENANCE_TOKEN_RE.finditer(text) if m.group(1).count(":") >= 1)
                break
    return out


def sample_coverage_problems(doc: "PluginDoc") -> list[str]:
    """Rule 5, per leg: every (action, OS) declared supported or constrained is
    captured, or carries a `[not captured]` marker, and a sample names no
    action the descriptor does not declare."""
    problems = []
    for os_name in OS_ORDER:
        wanted = sorted(a for a, per_os in doc.legs.items()
                        if per_os.get(os_name) and per_os[os_name].support in ("supported", "constrained"))
        sample = doc.samples.get(os_name)
        if sample is None:
            if wanted:
                problems.append(f"{doc.name}: {os_name} declares {wanted} supported/constrained but "
                                f"docs/samples/{os_name}.txt is missing or unparseable (rule 5)")
            continue
        present = {a["action"] for a in sample.actions}
        cap_by_action = {r.action: r for r in doc.cap_rows}
        for a in sample.actions:
            marker = a.get("not_captured")
            if marker and "/" in marker.split(":", 1)[0]:
                cls = marker.split(":", 1)[0]
                row = cap_by_action.get(a["action"])
                expected = f"{row.dispatch_class}/{row.mutability}" if row else None
                if row is None or row.dispatch_class not in ("Mutating", "Destructive") or cls != expected:
                    problems.append(f"{doc.name}/{os_name}: `[not captured] {cls}:` on action '{a['action']}' — the "
                                    f"capability row says {expected or 'no row'}; only a Mutating or Destructive "
                                    "action may skip a live run under that class (rule 5)")
        for action in wanted:
            if action not in present:
                problems.append(f"{doc.name}/{os_name}: action '{action}' is {doc.legs[action][os_name].support} "
                                f"on {os_name} but docs/samples/{os_name}.txt has no `== action={action}` "
                                "block (capture it, or record `[not captured] <class>: <reason>`)")
        for action in sorted(present - set(doc.legs)):
            problems.append(f"{doc.name}/{os_name}: docs/samples/{os_name}.txt captures action '{action}', "
                            "which the descriptor does not declare")
    return problems


# ── repository loading ────────────────────────────────────────────────────────

def _read(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except UnicodeDecodeError as e:
        raise ValueError(f"{path.as_posix()}: not UTF-8 ({e.reason} at byte {e.start})") from None
    except OSError as e:
        raise ValueError(f"{path.as_posix()}: {e.strerror}") from None


def load_definitions(repo: Path) -> dict[str, list[Definition]]:
    if yaml is None:
        raise RuntimeError("PyYAML is required: pip install pyyaml")
    by_plugin: dict[str, list[Definition]] = {}
    seen_ids: dict[str, str] = {}
    for path in sorted((repo / "content" / "definitions").glob("*.yaml"), key=lambda q: q.as_posix()):
        rel = path.relative_to(repo).as_posix()
        try:
            docs = list(yaml.safe_load_all(_read(path)))
        except yaml.YAMLError as e:
            raise ValueError(f"{rel}: not valid YAML: {str(e).splitlines()[0]}") from None
        for d in parse_definition_docs(docs, rel):
            if d.id in seen_ids:
                raise ValueError(f"{rel}: definition id {d.id!r} is already defined in {seen_ids[d.id]}")
            seen_ids[d.id] = rel
            by_plugin.setdefault(d.plugin, []).append(d)
    return by_plugin


def load_capability_rows(repo: Path) -> dict[str, list[CapRow]]:
    by_plugin: dict[str, list[CapRow]] = {}
    for path in sorted(repo.glob(CAPDECL_GLOB), key=lambda q: q.as_posix()):
        rel = path.relative_to(repo).as_posix()
        for row in parse_capability_fragment(_read(path), rel):
            by_plugin.setdefault(row.plugin, []).append(row)
    return by_plugin


def collect_source(repo: Path, name: str, definitions: list[Definition],
                   cap_rows: list[CapRow]) -> dict:
    pdir = repo / "agents" / "plugins" / name
    srcs = sorted(p.relative_to(repo).as_posix() for p in (pdir / "src").glob("*") if p.is_file())
    # Explicit, case-sensitive name matching — pathlib globbing is case-insensitive
    # on Windows only, and this list is byte-gated on every host.
    tests = sorted(p.relative_to(repo).as_posix() for p in (repo / "tests").rglob("*")
                   if p.is_file() and p.suffix in (".cpp", ".py") and p.name.startswith(f"test_{name}"))
    changelog = sorted(p.relative_to(repo).as_posix() for p in (repo / "changelog.d").iterdir()
                       if p.is_file() and p.suffix == ".md" and name in p.name)
    priv = repo / "docs" / "agent-privilege-model.md"
    priv_row = priv.exists() and (f"`{name}." in _read(priv))
    return {
        "plugin": srcs,
        "definitions": sorted({d.path for d in definitions}),
        "capability_rows": sorted({r.fragment for r in cap_rows}),
        "tests": tests,
        "privilege_row": bool(priv_row),
        "changelog": changelog,
    }


def load_plugin(repo: Path, name: str, matrix: dict, defs: dict, caps: dict) -> PluginDoc:
    pdir = repo / "agents" / "plugins" / name
    identity = {"name": None, "version": None, "description": None}
    warnings: list[str] = []
    for tu in sorted((pdir / "src").glob("*.cpp"), key=lambda q: q.as_posix()):
        ident = parse_plugin_identity(_read(tu))
        if ident["name"]:
            identity = ident
            break
    if not identity["name"]:
        # PR #4112 review, minor: "error:"-prefixed, matching the two
        # adjacent conditions in this same function (lines below) -- a
        # missing identity silently rendering as "-" is not a lesser defect
        # than the ones that already fail the gate.
        warnings.append(f"error: {name}: no name() override found under src/ — identity rendered as '-'")
    declared = identity["name"] or name
    if declared != name:
        warnings.append(f"error: {name}: plugin declares name() '{declared}' but lives in agents/plugins/{name}/ — "
                        "the gate keys legs, definitions and samples by directory; rename one of them")
    legs = matrix.get(declared, {})
    if not legs:
        # PR #4112 review, minor: "error:"-prefixed, same rationale as above.
        warnings.append(f"error: {name}: no rows in the capability-matrix block (regenerate it?)")
    definitions = defs.get(declared, [])
    cap_rows = caps.get(declared, [])
    cap_actions = {r.action for r in cap_rows}
    for action in sorted(legs):
        if action not in cap_actions:
            warnings.append(f"error: {name}: action '{action}' is in the capability-matrix block but no "
                            f"CommandCapability row was parsed for it from {CAPDECL_GLOB} — every "
                            "dispatchable action has one (tests/test_capability_catalogue_complete.py), so "
                            "the fragment parser missed the row; check the initialiser's layout")
    samples: dict[str, Sample] = {}
    for os_name in OS_ORDER:
        sp = pdir / "docs" / "samples" / f"{os_name}.txt"
        if sp.exists():
            try:
                samples[os_name] = parse_sample(_read(sp), os_name)
            except ValueError as e:
                # An unparseable capture is an error, not a note: the coverage
                # check would otherwise report the leg as merely missing.
                warnings.append(f"error: {name}: docs/samples/{os_name}.txt: {e}")
    return PluginDoc(
        name=declared, version=identity["version"] or "-",
        description=identity["description"] or "-",
        legs=legs, cap_rows=cap_rows, definitions=definitions, samples=samples,
        source=collect_source(repo, name, definitions, cap_rows),
        readme_path=f"agents/plugins/{name}/README.md", warnings=warnings,
    )


# ── renderers (pure) ──────────────────────────────────────────────────────────

def _esc(cell: str) -> str:
    return str(cell).replace("|", "\\|").replace("\n", " ")


def best_support(legs: dict[str, dict[str, Leg]], os_name: str) -> str:
    levels = [l.support for a in legs.values() for o, l in a.items() if o == os_name]
    for level in ("supported", "constrained", "planned"):
        if level in levels:
            return level
    return "unsupported" if levels else "undeclared"


def platforms_line(legs: dict[str, dict[str, Leg]]) -> str:
    parts = []
    for os_name in OS_ORDER:
        s = best_support(legs, os_name)
        label = "" if s == "supported" else f" {s}"
        parts.append(f"{OS_LABEL[os_name]} {SUPPORT_ICON[s]}{label}")
    return " · ".join(parts)


def kind_line(cap_rows: list[CapRow], definitions: list[Definition]) -> str:
    mutating = any(r.dispatch_class in ("Mutating", "Destructive") for r in cap_rows)
    gathered = [d.id for d in definitions if d.gather]
    kind = "Action · mutating" if mutating else "Collector · read-only"
    kind += f" · gathered ({', '.join(gathered)})" if gathered else " · on-demand"
    return kind


def render_header(doc: PluginDoc) -> str:
    actions = []
    for action in sorted(doc.legs):
        ids = sorted(d.id for d in doc.definitions if d.action == action)
        actions.append(f"`{action}`" + (f" (definition {', '.join(f'`{i}`' for i in ids)})" if ids else ""))
    sec_cells = []
    for r in doc.cap_rows:
        sec_cells.append(f"`{r.action}`: securable `{r.securable}` · operation {r.operation} · risk {r.risk_tier}"
                         f" · dispatch {r.dispatch_class} · approval gate {r.execute_gate}")
    if len({(r.securable, r.operation, r.risk_tier, r.dispatch_class, r.execute_gate) for r in doc.cap_rows}) == 1:
        r = doc.cap_rows[0]
        sec_cells = [f"securable `{r.securable}` · operation {r.operation} · risk {r.risk_tier}"
                     f" · dispatch {r.dispatch_class} · approval gate {r.execute_gate}"]
    auth_roles = sorted({x for d in doc.definitions for x in d.author_roles})
    if len({tuple(sorted(d.execute_roles)) for d in doc.definitions}) == 1:
        exec_roles_cell = ", ".join(sorted({x for d in doc.definitions for x in d.execute_roles})) or "-"
    else:
        exec_roles_cell = "; ".join(
            f"`{d.action}`: {', '.join(sorted(d.execute_roles)) or '-'}" for d in doc.definitions
        )
    rows = [
        ("**What it does**", doc.description),
        ("**Version**", doc.version),
        ("**Kind**", kind_line(doc.cap_rows, doc.definitions)),
        ("**Platforms**", platforms_line(doc.legs)),
        ("**Actions**", " · ".join(actions) or "-"),
        ("**Security**", "; ".join(sec_cells) or "no capability row (not dispatchable)"),
        ("**Roles**", f"execute: {exec_roles_cell} · author: {', '.join(auth_roles) or '-'}"),
    ]
    lines = ["| | |", "|---|---|"] + [f"| {k} | {_esc(v)} |" for k, v in rows]
    return "\n".join(lines)


def render_capability(doc: PluginDoc) -> str:
    lines = ["| Action | Windows | macOS | Linux |", "|---|---|---|---|"]
    for action in sorted(doc.legs):
        cells = []
        for os_name in OS_ORDER:
            leg = doc.legs[action].get(os_name)
            if not leg:
                cells.append("⛔ undeclared")
                continue
            cell = f"{SUPPORT_ICON.get(leg.support, '⛔')} {leg.support}"
            if leg.rung:
                cell += f" · rung {leg.rung}"
            if leg.mechanism:
                cell += f" · {leg.mechanism}"
            cells.append(_esc(cell))
        lines.append(f"| `{action}` | " + " | ".join(cells) + " |")
    limits = []
    for action in sorted(doc.legs):
        for os_name in OS_ORDER:
            leg = doc.legs[action].get(os_name)
            if leg and leg.fallback:
                limits.append(f"- **`{action}` / {OS_LABEL[os_name]}** — {leg.fallback}")
    if limits:
        lines += ["", "**Declared limits per leg** (descriptor fallback text, verbatim):", ""] + limits
    return "\n".join(lines)


def _scalar_cell(v) -> str:
    """A YAML scalar as a reader expects it: `true`, not Python's `True`."""
    if v is None:
        return "-"
    if isinstance(v, bool):
        return "true" if v else "false"
    return str(v)


_CONSTRAINT_ORDER = ("enum", "pattern", "minLength", "maxLength", "minimum", "maximum")  # docs/yaml-dsl-spec.md §3.1


def constraints_text(spec: dict) -> str:
    """The parameter's ``validation`` block (docs/yaml-dsl-spec.md §3.1) as one
    cell: `enum: a, b · pattern: ^x$ · minLength 1`. Unknown keys are kept."""
    v = spec.get("validation")
    if not isinstance(v, dict) or not v:
        return "-"
    parts = []
    for key in list(_CONSTRAINT_ORDER) + sorted(k for k in v if k not in _CONSTRAINT_ORDER):
        if key not in v:
            continue
        val = v[key]
        if isinstance(val, list):
            parts.append(f"{key}: " + ", ".join(_scalar_cell(x) for x in val))
        elif key in ("pattern", "format"):
            parts.append(f"{key}: {val}")
        else:
            parts.append(f"{key} {_scalar_cell(val)}")
    return " · ".join(parts)


def render_inputs(doc: PluginDoc) -> str:
    rows = []
    for d in sorted(doc.definitions, key=lambda d: d.id):
        props = (d.parameters or {}).get("properties") or {}
        required = set((d.parameters or {}).get("required") or [])
        for pname, spec in props.items():
            spec = spec if isinstance(spec, dict) else {}
            rows.append((d.id, pname, str(spec.get("type", "-")), "yes" if pname in required else "no",
                         _scalar_cell(spec.get("default")), constraints_text(spec),
                         " ".join(str(spec.get("description", "-")).split())))
    if not rows:
        n = len(doc.legs)
        if n == 1:
            return "The action takes no parameters."
        return ("Neither action takes" if n == 2 else "No action takes") + " parameters."
    lines = ["| Definition | Parameter | Type | Required | Default | Constraints | Description |",
             "|---|---|---|---|---|---|---|"]
    lines += ["| " + " | ".join(_esc(c) for c in (f"`{r[0]}`", f"`{r[1]}`", *r[2:])) + " |" for r in rows]
    return "\n".join(lines)


def _plat(platforms) -> str:
    if not platforms:
        return "all"
    return ", ".join(OS_LABEL.get(YAML_PLATFORM.get(str(p), str(p)), str(p)) for p in platforms)


def render_outputs(doc: PluginDoc) -> str:
    blocks = []
    for d in sorted(doc.definitions, key=lambda d: d.id):
        if not d.columns:
            continue
        fmt = "|".join(c["name"] for c in d.columns)
        lines = [f"**`{d.id}` — `{fmt}`**", "",
                 "| Field | Type | Values | Available | Example | Description |", "|---|---|---|---|---|---|"]
        for c in d.columns:
            values = c.get("values")
            values_cell = " ".join(f"`{v}`" for v in values) if isinstance(values, list) else "-"
            example = c.get("example")
            example_cell = f"`{example}`" if example not in (None, "") else "-"
            desc = c.get("description") or "-"
            lines.append("| " + " | ".join(_esc(x) for x in (
                f"`{c['name']}`", c["type"], values_cell, _plat(c.get("platforms")), example_cell,
                " ".join(str(desc).split()))) + " |")
        blocks.append("\n".join(lines))
    return "\n\n".join(blocks) if blocks else "No definition declares result columns."


def trim_rows(rows: list[str], limit: int = SAMPLE_ROW_LIMIT) -> list[str]:
    if len(rows) <= limit:
        return rows
    return rows[:limit] + [f"… {limit} of {len(rows)} rows shown"]


def render_samples(doc: PluginDoc) -> str:
    blocks = []
    for os_name in OS_ORDER:
        s = doc.samples.get(os_name)
        if not s:
            continue
        st = s.stamp
        head = (f"**{OS_LABEL[os_name]}** — captured: {st['os']} {st['os_version']} · {st['host_class']}"
                f" · {st['date']} · {st['privilege']} · leg-hash {st['leg_hash']}")
        body = []
        for a in s.actions:
            body.append(f"== action={a['action']}" + (f" {a['params']}" if a["params"] else ""))
            if a.get("not_captured"):
                body.append(f"[not captured] {a['not_captured']}")
            body += trim_rows(a["rows"])
            if a.get("truncated"):
                body.append("[truncated] capture hit the LocalDispatcher byte cap")
            rs = a["result_status"]
            if rs:
                body.append(f"[result_status] {rs['status']} / {rs['completeness']} / {rs['provenance']}".rstrip(" /"))
            if a.get("rc"):
                body.append(f"[rc] {a['rc']}")
            body.append("")
        while body and body[-1] == "":
            body.pop()
        blocks.append(head + "\n\n```\n" + "\n".join(body) + "\n```")
    if not blocks:
        return "No captures yet — run `plugin-capture` on each supported OS (docs/plugin-readme-standard.md rule 5)."
    return "\n\n".join(blocks)


def render_source(doc: PluginDoc) -> str:
    s = doc.source
    lines = ["- Plugin: " + " · ".join(f"`{p}`" for p in s["plugin"])]
    if s["definitions"]:
        lines.append("- Definitions: " + " · ".join(f"`{p}`" for p in s["definitions"]))
    if s["capability_rows"]:
        lines.append("- Capability rows: " + " · ".join(f"`{p}`" for p in s["capability_rows"]))
    lines.append("- Tests: " + (" · ".join(f"`{p}`" for p in s["tests"]) if s["tests"] else "none found by name"))
    lines.append("- Privilege row: `docs/agent-privilege-model.md`" + ("" if s["privilege_row"] else " (no row yet)"))
    if s["changelog"]:
        lines.append("- Changelog: " + " · ".join(f"`{p}`" for p in s["changelog"]))
    return "\n".join(lines)


RENDERERS = {
    "header": render_header, "capability": render_capability, "inputs": render_inputs,
    "outputs": render_outputs, "samples": render_samples, "source": render_source,
}


def render_index(docs: list[PluginDoc], total: int | None = None) -> str:
    lines = []
    if total is not None:
        lines += [f"{len(docs)} of {total} plugins document themselves this way; the rest are described in the "
                  "prose below until their README lands.", ""]
    lines += ["| Plugin | Platforms | What it does | Docs |", "|---|---|---|---|"]
    for d in sorted(docs, key=lambda d: d.name):
        plats = " ".join(SUPPORT_ICON[best_support(d.legs, o)] for o in OS_ORDER)
        lines.append(f"| `{d.name}` | {plats} | {_esc(d.description)} | [README](../../{d.readme_path}) |")
    lines.append("")
    lines.append("Platform cells are Windows · macOS · Linux (✅ supported · 🟡 constrained or planned · ⛔ unsupported).")
    return "\n".join(lines)


def render_nav(docs: list[PluginDoc]) -> str:
    entries = ",\n".join(
        f"  {{ file: 'agents/plugins/{d.name}/README', slug: 'plugins/{d.name}', title: '{d.name}' }}"
        for d in sorted(docs, key=lambda d: d.name))
    return ("// AUTO-GENERATED by tools/plugin-doc-gen/plugin_doc_gen.py — do not hand-edit.\n"
            "// <!-- BEGIN GENERATED: plugin-doc-gen nav -->\n"
            "export const PLUGIN_ENTRIES = [\n" + entries + ("\n" if entries else "") + "];\n"
            "// <!-- END GENERATED -->\n")


# Every top-level key build_manifest emits — tests/test_plugin_readmes.py binds
# this to the "Manifest schema" table in docs/plugin-readme-standard.md, so a
# key added to one without the other fails the docs suite.
MANIFEST_KEYS = frozenset({
    "manifest_version", "name", "version", "description", "kind", "platforms", "security",
    "actions", "definitions", "inputs", "outputs", "leg_hash", "how_it_works", "outputs_note",
    "privileges", "result_status", "where_the_data_goes", "caveats", "samples", "source", "readme",
})


def build_manifest(doc: PluginDoc, readme: str) -> dict:
    hand = hand_sections_to_manifest(readme)
    by_action_defs: dict[str, list[str]] = {}
    for d in doc.definitions:
        by_action_defs.setdefault(d.action, []).append(d.id)
    samples = {}
    for os_name, s in doc.samples.items():
        samples[os_name] = {
            "stamp": s.stamp,
            "actions": [{"action": a["action"], "params": a["params"], "rows": a["rows"][:MANIFEST_SAMPLE_ROWS],
                         "row_count": len(a["rows"]), "result_status": a["result_status"],
                         "not_captured": a.get("not_captured"), "truncated": a.get("truncated", False),
                         "rc": a.get("rc", 0)} for a in s.actions],
        }
    return {
        "manifest_version": MANIFEST_VERSION,
        "name": doc.name, "version": doc.version, "description": doc.description,
        "kind": {"collector": not any(r.dispatch_class in ("Mutating", "Destructive") for r in doc.cap_rows),
                 "mutating": any(r.dispatch_class in ("Mutating", "Destructive") for r in doc.cap_rows),
                 "gathered": any(d.gather for d in doc.definitions)},
        "platforms": {o: best_support(doc.legs, o) for o in OS_ORDER},
        "security": [{"action": r.action, "securable": r.securable, "operation": r.operation,
                      "risk_tier": r.risk_tier, "dispatch_class": r.dispatch_class,
                      "mutability": r.mutability, "execute_gate": r.execute_gate} for r in doc.cap_rows],
        "actions": [{"action": a, "definition_ids": sorted(by_action_defs.get(a, [])),
                     "legs": {o: {"support": l.support, "rung": l.rung, "mechanism": l.mechanism,
                                  "fallback": l.fallback} for o, l in sorted(legs.items())}}
                    for a, legs in sorted(doc.legs.items())],
        "definitions": [{"id": d.id, "display_name": d.display_name, "description": d.description,
                         "platforms": d.platforms, "approval_mode": d.approval_mode,
                         "execute_roles": d.execute_roles, "author_roles": d.author_roles,
                         "gather": d.gather} for d in sorted(doc.definitions, key=lambda d: d.id)],
        "inputs": [{"definition_id": d.id, "name": n, "type": str(s.get("type", "")),
                    "required": n in set((d.parameters or {}).get("required") or []),
                    "default": s.get("default"),
                    "constraints": s.get("validation") if isinstance(s.get("validation"), dict) else None,
                    "description": s.get("description")}
                   for d in sorted(doc.definitions, key=lambda d: d.id)
                   for n, s in ((d.parameters or {}).get("properties") or {}).items()
                   if isinstance(s, dict)],
        "outputs": [{"definition_id": d.id, "columns": d.columns}
                    for d in sorted(doc.definitions, key=lambda d: d.id) if d.columns],
        "leg_hash": leg_hash(doc.legs, doc.definitions),
        **hand,
        "samples": samples,
        "source": doc.source,
        "readme": doc.readme_path,
    }


# ── fence splicing ────────────────────────────────────────────────────────────

def splice(text: str, blocks: dict[str, str], required: Iterable[str] = ()) -> tuple[str, list[str]]:
    """Replace the body of every ``plugin-doc-gen <block>`` fence in ``text``.
    Returns the new text and the list of required blocks that were missing."""
    seen: set[str] = set()

    def repl(m: re.Match) -> str:
        name = m.group(1)
        seen.add(name)
        body = blocks.get(name)
        if body is None:
            return m.group(0)
        return f"{m.group(0).splitlines()[0]}\n{body}\n{END_MARK}"

    pattern = re.compile(r"<!-- BEGIN GENERATED: plugin-doc-gen (\w+) -->.*?<!-- END GENERATED -->", re.DOTALL)
    out = pattern.sub(repl, text)
    missing = [b for b in required if b not in seen]
    return out, missing


# ── repository-level driver ───────────────────────────────────────────────────

@dataclass
class Outcome:
    changed: dict[str, tuple[str, str]] = field(default_factory=dict)   # path -> (old, new)
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


def plugin_dirs(repo: Path) -> list[str]:
    return sorted(p.name for p in (repo / "agents" / "plugins").iterdir() if (p / "src").is_dir())


def documented_plugins(repo: Path) -> list[str]:
    return [n for n in plugin_dirs(repo) if (repo / "agents" / "plugins" / n / "README.md").exists()]


def generate(repo: Path, only: str | None = None) -> Outcome:
    """Compute every generated artefact. Nothing is written; ``apply`` does that."""
    out = Outcome()
    if not (repo / "agents" / "plugins").is_dir() or not (repo / "docs" / "os-capability-matrix.md").is_file():
        raise ValueError(f"{repo.as_posix()}: not a Yuzu repository root (no agents/plugins/ or docs/os-capability-matrix.md)")
    matrix = parse_matrix_block(_read(repo / "docs" / "os-capability-matrix.md"))
    defs = load_definitions(repo)
    caps = load_capability_rows(repo)
    names = documented_plugins(repo)
    if only:
        if only not in names:
            out.errors.append(f"{only}: no agents/plugins/{only}/README.md — the generator never creates one")
            return out
        names = [only]
    docs: list[PluginDoc] = []
    for name in names:
        doc = load_plugin(repo, name, matrix, defs, caps)
        out.errors += [w for w in doc.warnings if w.startswith("error:")]
        out.warnings += [w for w in doc.warnings if not w.startswith("error:")]
        readme_path = repo / doc.readme_path
        readme = _read(readme_path)
        out.errors += readme_shape_problems(readme, name, doc.readme_path, provenance_literals(repo, name))
        out.errors += sample_coverage_problems(doc)
        blocks = {b: RENDERERS[b](doc) for b in README_BLOCKS}
        new, missing = splice(readme, blocks, README_BLOCKS)
        for b in missing:
            out.errors.append(f"{doc.readme_path}: missing fence `plugin-doc-gen {b}`")
        if new != readme:
            out.changed[doc.readme_path] = (readme, new)
        current_hash = leg_hash(doc.legs, doc.definitions)
        for os_name, s in doc.samples.items():
            h = s.stamp["leg_hash"]
            if h == "pending":
                out.warnings.append(f"{doc.name}/{os_name}: capture stamp leg-hash pending (run --stamp after capture)")
            elif h != current_hash:
                out.errors.append(f"{doc.name}/{os_name}: capture leg-hash {h} is stale (legs/columns now {current_hash}) — "
                                  f"recapture: plugin-capture … --out agents/plugins/{doc.name}/docs/samples/{os_name}.txt, "
                                  f"then plugin_doc_gen.py --stamp {doc.name} {os_name}, then --all")
        manifest_path = f"content/plugin-docs/{doc.name}.json"
        try:
            manifest = json.dumps(build_manifest(doc, new), indent=2, sort_keys=True, ensure_ascii=False,
                                  allow_nan=False) + "\n"
        except ValueError as e:  # NaN/Infinity in a column example, a default, or similar
            raise ValueError(f"{doc.name}: manifest is not valid JSON: {e}") from None
        old_manifest = _read(repo / manifest_path) if (repo / manifest_path).exists() else ""
        if manifest != old_manifest:
            out.changed[manifest_path] = (old_manifest, manifest)
        docs.append(doc)
    if only:
        return out
    # Whole-tree artefacts: the catalog index, the site nav fragment.
    catalog_path = "docs/user-manual/agent-plugins.md"
    catalog = _read(repo / catalog_path)
    new_catalog, missing = splice(catalog, {"index": render_index(docs, len(plugin_dirs(repo)))}, ["index"])
    for b in missing:
        out.errors.append(f"{catalog_path}: missing fence `plugin-doc-gen {b}`")
    if new_catalog != catalog:
        out.changed[catalog_path] = (catalog, new_catalog)
    nav_path = "site/src/nav.plugins.mjs"
    nav = render_nav(docs)
    old_nav = _read(repo / nav_path) if (repo / nav_path).exists() else ""
    if nav != old_nav:
        out.changed[nav_path] = (old_nav, nav)
    # A manifest whose README vanished is stale.
    for stale in sorted((repo / "content" / "plugin-docs").glob("*.json")) if (repo / "content" / "plugin-docs").exists() else []:
        if stale.stem not in names:
            out.errors.append(f"{stale.relative_to(repo).as_posix()}: no README for this plugin — delete the manifest")
    return out


def apply(repo: Path, outcome: Outcome) -> None:
    for rel, (_, new) in outcome.changed.items():
        path = repo / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(new, encoding="utf-8", newline="\n")


def stamp(repo: Path, name: str, os_name: str) -> str:
    """Replace ``leg-hash pending`` (or a stale hash) in a sample stamp with the
    current hash. Returns the hash written."""
    if name not in plugin_dirs(repo):
        raise ValueError(f"{name}: no such plugin directory under agents/plugins/")
    if os_name not in OS_ORDER:
        raise ValueError(f"{os_name}: OS must be one of {', '.join(OS_ORDER)}")
    matrix = parse_matrix_block(_read(repo / "docs" / "os-capability-matrix.md"))
    doc = load_plugin(repo, name, matrix, load_definitions(repo), load_capability_rows(repo))
    path = repo / "agents" / "plugins" / name / "docs" / "samples" / f"{os_name}.txt"
    if not path.exists():
        raise ValueError(f"{path.relative_to(repo).as_posix()}: no capture to stamp — run plugin-capture first")
    text = _read(path)
    h = leg_hash(doc.legs, doc.definitions)
    first, _, rest = text.partition("\n")
    if not _STAMP_RE.match(first.strip()):
        raise ValueError(f"{path}: first line is not a capture stamp")
    first = re.sub(r"leg-hash\s+\w+\s*$", f"leg-hash {h}", first)
    path.write_text(first + "\n" + rest, encoding="utf-8", newline="\n")
    return h


def check_repo(repo: Path) -> tuple[list[str], list[str]]:
    """Gate entry point: (errors, warnings). Errors = any generated artefact
    differs from what the sources produce, a missing fence, or a stale hash."""
    outcome = generate(repo)
    errors = list(outcome.errors)
    for rel, (old, new) in outcome.changed.items():
        diff = "".join(difflib.unified_diff(old.splitlines(True), new.splitlines(True),
                                            fromfile=f"{rel} (committed)", tofile=f"{rel} (generated)", n=1))
        errors.append(f"{rel}: generated content differs — run plugin_doc_gen.py --all\n{diff}")
    return errors, outcome.warnings


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--repo-root", default=None, help="repository root (default: auto from this file)")
    mode = ap.add_mutually_exclusive_group(required=True)
    mode.add_argument("--all", action="store_true", help="regenerate every README fence, the index, nav and manifests")
    mode.add_argument("--plugin", metavar="NAME", help="regenerate one plugin's fences and manifest")
    mode.add_argument("--check", action="store_true", help="exit 1 if anything would change (CI gate)")
    mode.add_argument("--stamp", nargs=2, metavar=("NAME", "OS"), help="write the current leg-hash into a capture stamp")
    args = ap.parse_args(argv)
    repo = Path(args.repo_root).resolve() if args.repo_root else Path(__file__).resolve().parents[2]
    try:
        if args.stamp:
            print(f"leg-hash {stamp(repo, *args.stamp)}")
            return 0
        if args.check:
            errors, warnings = check_repo(repo)
        else:
            outcome = generate(repo, only=args.plugin)
    except ValueError as e:  # a malformed source file, named
        print(f"error: {e}", file=sys.stderr)
        return 1
    if args.check:
        for w in warnings:
            print(f"warning: {w}", file=sys.stderr)
        for e in errors:
            print(f"error: {e}", file=sys.stderr)
        print(f"plugin-doc-gen --check: {len(errors)} error(s), {len(warnings)} warning(s)")
        return 1 if errors else 0
    for w in outcome.warnings:
        print(f"warning: {w}", file=sys.stderr)
    for e in outcome.errors:
        print(f"error: {e}", file=sys.stderr)
    if outcome.errors:
        return 1
    apply(repo, outcome)
    for rel in outcome.changed:
        print(f"wrote {rel}")
    if not outcome.changed:
        print("nothing to do — every generated artefact is current")
    return 0


if __name__ == "__main__":
    sys.exit(main())
