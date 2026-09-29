#!/usr/bin/env python3
"""Build-time YAML→JSON converter for shipped Yuzu content.

Walks a content tree of .yaml files (InstructionDefinition,
InstructionSet, ProductPack), normalises each doc into the JSON envelope
shape that ``InstructionStore::import_definition_json`` and
``InstructionStore::create_set`` expect, and emits a .cpp file with two
``std::vector<std::string>`` constants the server iterates on startup.

Why build-time conversion: YAML parsing in C++ requires yaml-cpp, which
has known Windows MSVC build risk (#625) and would add a vcpkg
dependency. PyYAML is already present in every supported build env
(Linux/macOS/Windows MSYS2), and the conversion result is content-
addressable from the input tree, so embedding the JSON in the binary
keeps the air-gapped install story whole.

Usage:
    embed_content.py <content_root> <output.cpp>

Where <content_root> contains subdirectories ``definitions/`` and
``packs/`` of .yaml files. Multi-document YAML (``---`` separators)
is handled.
"""

from __future__ import annotations  # 'dict | None' type hints under py 3.9

import json
import re
import sys
from pathlib import Path

# Raw-string delimiter for every embedded literal: R"BCT(...)BCT".
DELIM = "BCT"

# PyYAML is a hard build dependency. Bundled content is the *only* path
# by which shipped InstructionDefinitions reach the server's runtime
# (no filesystem fallback — see CLAUDE.md "Instruction Engine"), so a
# build host without PyYAML must fail loudly rather than silently
# producing a binary with zero embedded definitions and an empty
# Instructions tab. Provisioning: `pip install pyyaml` (Linux/macOS),
# `pacman -S python-yaml` (MSYS2). The `meson setup` step also probes
# this so the failure surfaces at configure rather than mid-compile.
try:
    import yaml  # type: ignore[import-not-found]
except ImportError:
    print(
        "ERROR: embed_content.py: PyYAML is required to embed shipped "
        "InstructionDefinitions. Install it with `pip install pyyaml` "
        "(Linux/macOS) or `pacman -S python-yaml` (MSYS2).",
        file=sys.stderr,
    )
    sys.exit(1)


# The three modes InstructionStore::import_definition_json_impl and the
# governed-execute path (workflow_routes.cpp) actually understand. Any other
# value falls through the governed path's fail-closed "unknown mode" arm —
# approval-required for every caller including admins — which is safe but
# means the definition is effectively unexecutable via the governed REST
# path. Rejecting it here at build time (#1398) surfaces that as a build
# failure instead of a silent, permanently-pending definition discovered
# only at runtime.
VALID_APPROVAL_MODES = {"auto", "role-gated", "always"}


def to_string_list(v):
    if v is None:
        return ""
    if isinstance(v, list):
        return ",".join(str(x) for x in v)
    return str(v)


def def_envelope(doc: dict, yaml_source: str) -> dict | None:
    """Convert an InstructionDefinition YAML doc to the JSON envelope
    accepted by InstructionStore::import_definition_json.

    Returns None if the doc is missing required fields (id, plugin, action)
    so the caller can skip silently rather than crash startup."""
    meta = doc.get("metadata") or {}
    spec = doc.get("spec") or {}
    exec_ = spec.get("execution") or {}
    approval = spec.get("approval") or {}
    gather = spec.get("gather") or {}

    # action may be on `spec.execution.action` or fall back to spec.action.
    action = exec_.get("action") or spec.get("action") or ""
    plugin = exec_.get("plugin") or spec.get("plugin") or ""
    id_ = meta.get("id") or ""
    if not (id_ and plugin and action):
        return None

    env = {
        "id": id_,
        "name": meta.get("displayName") or meta.get("name") or id_,
        "version": str(meta.get("version") or "1.0.0"),
        "type": spec.get("type") or "question",
        "plugin": plugin,
        "action": str(action).lower(),
        "description": meta.get("description") or "",
        "enabled": True,
        "platforms": to_string_list(spec.get("platforms")),
        "approval_mode": approval.get("mode") or "auto",
        "concurrency_mode": exec_.get("concurrency") or "per-device",
        "gather_ttl_seconds": int(gather.get("ttlSeconds") or 300),
        "yaml_source": yaml_source,
        "created_by": "system",
    }

    # Schemas: stringify nested objects so the store can persist them
    # verbatim and the engine parses them at query time.
    if spec.get("parameters") is not None:
        env["parameter_schema"] = json.dumps(spec["parameters"])
    if spec.get("result") is not None:
        env["result_schema"] = json.dumps(spec["result"])

    # Visualization — passed as a structured object; the store's normalise
    # step in import_definition_json wraps singular into a 1-element array.
    viz = spec.get("visualization") or spec.get("visualizations")
    if viz is not None:
        env["visualization"] = viz

    if spec.get("readablePayload"):
        env["readable_payload"] = spec["readablePayload"]

    return env


def set_envelope(doc: dict) -> dict | None:
    meta = doc.get("metadata") or {}
    id_ = meta.get("id") or ""
    if not id_:
        return None
    return {
        "id": id_,
        "name": meta.get("displayName") or meta.get("name") or id_,
        "description": meta.get("description") or "",
        "created_by": "system",
    }


def split_docs(text: str) -> list[str]:
    """Split a YAML file on ``---`` separators, mirroring the C++
    side's split_yaml_documents — preserves the original byte ranges
    so we can use them as the verbatim ``yaml_source`` for each doc."""
    parts = re.split(r"(?m)^---\s*$", text)
    # Drop empty lead-in (file starting with ---)
    return [p for p in parts if p.strip()]


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: embed_content.py <content_root> <output.cpp>",
              file=sys.stderr)
        return 1
    root = Path(sys.argv[1])
    out_path = Path(sys.argv[2])

    defs_json: list[str] = []
    sets_json: list[str] = []

    # Plugin documentation manifests — see the kBundledPluginDocs emit below.
    # Re-serialised compactly (sorted keys) so the embedded bytes are stable
    # regardless of how the generator pretty-printed the file.
    plugin_docs_json: list[str] = []
    bad_manifests: list[tuple[str, str]] = []
    for mf in sorted((root / "plugin-docs").glob("*.json")):
        try:
            manifest = json.loads(mf.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as e:
            bad_manifests.append((str(mf), str(e)))
            continue
        if not isinstance(manifest, dict) or manifest.get("name") != mf.stem:
            bad_manifests.append((str(mf), "top-level object with name == file stem required"))
            continue
        # The keys the server's index reads (discover_routes.cpp) must have the
        # shape it expects; a wrong-typed key must fail HERE, at build time.
        shape_errors = [
            f"{key} must be a string" for key in ("description", "readme")
            if not isinstance(manifest.get(key), str)
        ]
        for key in ("platforms", "kind"):
            if not isinstance(manifest.get(key), dict):
                shape_errors.append(f"{key} must be an object")
        if shape_errors:
            bad_manifests.append((str(mf), "; ".join(shape_errors)))
            continue
        try:
            compact = json.dumps(manifest, sort_keys=True, separators=(",", ":"), allow_nan=False)
        except ValueError as e:  # NaN/Infinity: not JSON, and the server's parser would drop the manifest
            bad_manifests.append((str(mf), str(e)))
            continue
        if f"){DELIM}\"" in compact:
            bad_manifests.append((str(mf), "contains the raw-string delimiter sequence"))
            continue
        plugin_docs_json.append(compact)
    if bad_manifests:
        print(
            f"ERROR: embed_content.py: {len(bad_manifests)} plugin-docs manifest(s) "
            "failed validation (content/plugin-docs/<name>.json must be a JSON object "
            "whose name matches the file stem, with string description/readme and object "
            "platforms/kind — regenerate with tools/plugin-doc-gen):",
            file=sys.stderr,
        )
        for path, reason in bad_manifests:
            print(f"  {path}: {reason}", file=sys.stderr)
        return 1
    bad_defs: list[tuple[str, str]] = []  # (path, reason) — fail loudly at build

    if not root.is_dir():
        print(
            f"ERROR: embed_content.py: content root {root} does not exist. "
            f"The build-time embed is the only source of shipped "
            f"InstructionDefinitions; an empty bundle would silently ship a "
            f"binary with no instructions. Did the source tree get cleaned?",
            file=sys.stderr,
        )
        return 1

    yaml_files = sorted(
        list((root / "definitions").rglob("*.yaml")) +
        list((root / "packs").rglob("*.yaml"))
    )

    if not yaml_files:
        print(
            f"ERROR: embed_content.py: no .yaml files found under "
            f"{root}/definitions or {root}/packs. Refusing to emit an "
            f"empty bundle. Restore content/ from git and rebuild.",
            file=sys.stderr,
        )
        return 1

    seen_def_ids: set[str] = set()
    seen_set_ids: set[str] = set()

    for yf in yaml_files:
        text = yf.read_text(encoding="utf-8")
        for doc_text in split_docs(text):
            try:
                doc = yaml.safe_load(doc_text)
            except yaml.YAMLError as e:
                print(f"WARN {yf}: YAML parse error: {e}", file=sys.stderr)
                continue
            if not isinstance(doc, dict):
                continue
            kind = doc.get("kind")
            if kind == "InstructionDefinition":
                env = def_envelope(doc, doc_text)
                if env is None:
                    # Required field missing — capture for fail-loud
                    # exit at end of pass. Silently skipping at build
                    # time becomes an unexplained "errored" line at
                    # operator startup. (Gate 3 QE-S3.)
                    meta = (doc.get("metadata") or {})
                    spec = (doc.get("spec") or {})
                    exec_ = (spec.get("execution") or {})
                    bad_defs.append((
                        str(yf),
                        f"missing required field(s): "
                        f"id={meta.get('id')!r} "
                        f"plugin={(exec_.get('plugin') or spec.get('plugin'))!r} "
                        f"action={(exec_.get('action') or spec.get('action'))!r}",
                    ))
                    continue
                if env["approval_mode"] not in VALID_APPROVAL_MODES:
                    bad_defs.append((
                        str(yf),
                        f"invalid approval.mode {env['approval_mode']!r} for "
                        f"id={env['id']!r} plugin={env['plugin']!r} "
                        f"action={env['action']!r} — must be one of "
                        f"{sorted(VALID_APPROVAL_MODES)}",
                    ))
                    continue
                if env["id"] not in seen_def_ids:
                    seen_def_ids.add(env["id"])
                    defs_json.append(json.dumps(env))
            elif kind == "InstructionSet":
                env = set_envelope(doc)
                if env and env["id"] not in seen_set_ids:
                    seen_set_ids.add(env["id"])
                    sets_json.append(json.dumps(env))
            # ProductPack and other kinds: skipped here. The pack's
            # member docs are imported via their own kind dispatch.

    if bad_defs:
        print(
            f"ERROR: embed_content.py: {len(bad_defs)} "
            f"InstructionDefinition doc(s) failed validation "
            f"(missing required fields or invalid approval.mode):",
            file=sys.stderr,
        )
        for path, reason in bad_defs:
            print(f"  {path}: {reason}", file=sys.stderr)
        return 1

    if not defs_json:
        print(
            "ERROR: embed_content.py: walked content/ but extracted zero "
            "InstructionDefinitions. Refusing to emit an empty bundle.",
            file=sys.stderr,
        )
        return 1

    # Emit C++. Each JSON string becomes a raw string literal in a
    # std::vector<std::string> (DELIM, module scope, is the raw-string
    # delimiter — chosen for impossibility in any sane content YAML).

    # MSVC has TWO string-literal limits. A single literal token is capped at
    # 16380 bytes (error C2026), so a large envelope (a verbose definition's
    # yaml_source + parameter_schema, a plugin-docs manifest) is split into
    # several ADJACENT raw-string literals the compiler concatenates. The
    # CONCATENATED literal is then capped at 65535 bytes (error C1091), so
    # adjacent chunks are grouped well under that and, when an element needs
    # more than one group, the groups are joined with std::string's operator+
    # instead — a std::string expression is a valid vector<std::string>
    # initialiser element and carries no literal-length limit. Both limits are
    # enforced by construction here, on every host, so an oversize element can
    # never surface only on the Windows CI leg. Safe because the whole
    # envelope is verified free of the `)BCT"` delimiter below, so no chunk
    # can contain it and no chunk boundary can synthesise it (chunks are
    # separate literals; only their VALUES are concatenated).
    CHUNK = 12000           # bytes per literal token, well under 16380
    CHUNKS_PER_GROUP = 4    # 48000 bytes per concatenated literal, well under 65535

    def emit_literal(j: str) -> bytes:
        # Sanity check: rule out delimiter collision in the JSON envelope.
        if f"){DELIM}\"" in j:
            raise ValueError("JSON envelope contains raw-string delimiter")
        raw = j.encode("utf-8")
        parts = [raw[i:i + CHUNK] for i in range(0, len(raw), CHUNK)] or [b""]
        groups = [parts[i:i + CHUNKS_PER_GROUP] for i in range(0, len(parts), CHUNKS_PER_GROUP)]
        rendered = [
            b" ".join(b'R"' + DELIM.encode() + b"(" + part + b")" + DELIM.encode() + b'"' for part in group)
            for group in groups
        ]
        if len(rendered) == 1:
            return b"    " + rendered[0] + b",\n"
        return b"    std::string(" + rendered[0] + b")\n      + " + b"\n      + ".join(rendered[1:]) + b",\n"

    out = bytearray()
    out += f"// AUTO-GENERATED from {root.name}/ by embed_content.py — do not edit.\n".encode("utf-8")
    out += f"// Definitions: {len(defs_json)}, Sets: {len(sets_json)}.\n\n".encode("ascii")
    out += b"#include <string>\n#include <vector>\n\n"
    out += b"namespace yuzu::server {\n\n"

    try:
        out += b"extern const std::vector<std::string> kBundledDefinitions = {\n"
        for j in defs_json:
            out += emit_literal(j)
        out += b"};\n\n"

        out += b"extern const std::vector<std::string> kBundledSets = {\n"
        for j in sets_json:
            out += emit_literal(j)
        out += b"};\n\n"

        # Plugin documentation manifests (docs/plugin-readme-standard.md rule
        # 10): content/plugin-docs/<name>.json, generated by tools/plugin-doc-gen
        # from each plugin's README. Served as GET /api/v1/discover/plugin-docs
        # and the MCP resource yuzu://plugin-docs. Zero files is legitimate —
        # the retrospective sweep lands them plugin by plugin — so, unlike
        # definitions, an empty table is emitted rather than refused. Each
        # file is validated as JSON here so a malformed manifest fails the
        # build, never the server's boot or a discovery request.
        out += b"extern const std::vector<std::string> kBundledPluginDocs = {\n"
        for j in plugin_docs_json:
            out += emit_literal(j)
        out += b"};\n\n"
    except ValueError as e:
        print(f"ERROR: {e} {DELIM}", file=sys.stderr)
        return 1

    out += b"}  // namespace yuzu::server\n"

    out_path.write_bytes(bytes(out))
    print(f"embed_content.py: wrote {out_path} "
          f"({len(defs_json)} definitions, {len(sets_json)} sets, "
          f"{len(plugin_docs_json)} plugin-docs manifests)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
