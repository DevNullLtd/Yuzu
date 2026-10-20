#!/usr/bin/env python3
"""test_software_vocabulary_consistency.py — #5328's installed-software vocabulary drift gate.

The typed installed-software store carries a `kind` and an `ecosystem` per row. The
agents emit the values; MCP `query_installed_software`, the OpenAPI description of
`GET /api/v1/inventory/software` and the inventory manual publish them; and the CPE
Lane-3 predicate (`is_os_native`, cpe_normalize.hpp) routes them. This script checks,
against the real tree, that:

  1. every published surface equals the agreed vocabulary (EXPECTED_*) — the one prose
     `kind (a|b)` enumeration per source file AND every JSON `enum` array the catalogue
     twins publish for `kind`/`ecosystem` (MCP input schemas, OpenAPI parameters); the
     OpenAPI ecosystem arrays are generated from kEcosystemFamilies and pinned in C++, and
     their provenance is read from the document check-api-parity.py decodes, not from bytes;
  2. the values the agents emit are exactly that vocabulary (emitted == published);
  3. every non-Lane-1 ecosystem and Lane-3 kind is named in `is_os_native`, and `pkg`
     is NOT a kind-level trigger (it is routed by its ecosystem).

Discovery is anti-vacuous: each emitter pattern must match a file and the emitted sets
must be non-empty, otherwise the test fails rather than passing on nothing.
Hermetic: parses sources only.
"""

import importlib.util
import json
import re
import unittest
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent

EXPECTED_KINDS = {"package", "app", "pkg", "feat"}
CATALOG_RULES = "server/core/src/software_catalog_rules.hpp"
LANE1 = {"rpm", "deb", "apk", "pacman"}
LANE3_KINDS = {"app", "feat"}

# Plain patterns only: Path.glob has no brace expansion.
EMITTER_GLOBS = [
    "agents/plugins/installed_apps/src/*.cpp",
    "agents/plugins/installed_apps/src/*.hpp",
    "agents/core/src/sync_source_installed_software.*",
]
MCP_SRC = "server/core/src/mcp_server.cpp"
OPENAPI_SRC = "server/core/src/rest_api_v1.cpp"
MANUAL = "docs/user-manual/inventory.md"
CPE_HDR = "server/core/src/cpe_normalize.hpp"

LITERAL_RE = re.compile(r'\b(kind|ecosystem)\s*=\s*"([a-z_]+)"')
# The two generator tokens (rest_api_v1.cpp expand_ecosystem_tokens): the only enum an OpenAPI
# `ecosystem` parameter may carry in the source literal.
ECOSYSTEM_TOKENS = (["@@ECOSYSTEM_ENUM@@"], ["@@ECOSYSTEM_ENUM_OR_EMPTY@@"])


def load_parity():
    """check-api-parity.py as a module (same load as check-docs-drift.py): its lexer decodes
    the unexpanded openapi_spec() literal, so spelling, key order and JSON escapes cannot matter."""
    spec = importlib.util.spec_from_file_location(
        "check_api_parity", REPO_ROOT / "scripts" / "ci" / "check-api-parity.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


PARITY = load_parity()


def discover_sources(root, patterns):
    files = []
    for pat in patterns:
        found = sorted(root.glob(pat))
        if not found:
            raise AssertionError(f"emitter pattern matches no file: {pat}")
        files.extend(found)
    return files


def extract_literals(text):
    """Return ({kinds}, {ecosystems}) assigned from string literals."""
    kinds, ecos = set(), set()
    for field, value in LITERAL_RE.findall(text):
        (kinds if field == "kind" else ecos).add(value)
    return kinds, ecos


def extract_enumeration(text, field):
    """The `<field> (a|b|c)` enumeration; exactly one match or a hard failure."""
    found = re.findall(rf"\b{field} \(([a-z_|]+)\)", text)
    if len(found) != 1:
        raise AssertionError(f"expected exactly one `{field} (...)` enumeration, found {len(found)}")
    return set(found[0].split("|"))


def extract_json_enums(text, field):
    """Every JSON-schema `enum` array an MCP tool schema publishes for `<field>`, as a list of
    sets: the `"<field>": {... "enum": [...]}` property. The span between the key and its `enum`
    never crosses a closing brace, so a later field's enum is never attributed to this one. The
    OpenAPI document is read decoded instead (openapi_field_enums)."""
    pat = rf'"{field}":\s*\{{[^{{}}]*?"enum":\s*\[([^\]]*)\]'
    return [set(re.findall(r'"([a-z_]+)"', m.group(1))) for m in re.finditer(pat, text)]


def extract_table_row(text, field):
    """Backticked cell values of the manual's `| `<field>` |` row."""
    rows = [l for l in text.splitlines() if re.match(rf"\s*\| `{field}` \|", l)]
    if len(rows) != 1:
        raise AssertionError(f"expected exactly one `{field}` table row, found {len(rows)}")
    return set(re.findall(r"`([a-z_]+)`", rows[0].split("|", 2)[2]))


def read(rel):
    return (REPO_ROOT / rel).read_text(encoding="utf-8")


def parse_ecosystem_table(text):
    """The ecosystem vocabulary in `text`'s kEcosystemFamilies, the catalogue's single source of
    truth. Anti-vacuous: the parsed entry count must equal the declared std::array size."""
    m = re.search(r"std::array<EcosystemFamily, (\d+)> kEcosystemFamilies\{\{(.*?)\}\};", text, re.S)
    if not m:
        raise AssertionError("kEcosystemFamilies not found in " + CATALOG_RULES)
    # A commented-out row is not a table row, in either comment form (one alternation, so the
    # leftmost comment wins: a `/*` inside a `//` comment opens nothing). The header's
    # static_assert is the compile-time side of the same guard.
    body = re.sub(r"/\*.*?\*/|//[^\n]*", "", m.group(2), flags=re.S)
    entries = re.findall(r'\{"([a-z_]+)", "[a-z]+"\}', body)
    if not entries or len(entries) != int(m.group(1)):
        raise AssertionError(f"parsed {len(entries)} ecosystems, declared {m.group(1)}")
    if len(set(entries)) != len(entries):
        raise AssertionError(f"duplicate ecosystem rows in {CATALOG_RULES}: {entries}")
    return set(entries)


def table_ecosystems():
    return parse_ecosystem_table(read(CATALOG_RULES))


def resolve_ref(spec, ref):
    """The node a "#/a/b/c" ref points at in the decoded document, or None."""
    node = spec
    for part in ref.lstrip("#").split("/"):
        if part == "":
            continue
        if not isinstance(node, dict) or part not in node:
            return None
        node = node[part]
    return node


def openapi_field_enums(spec, field):
    """[(where, enum or None)] for every site in the decoded document `spec` that publishes
    `field`: a Parameter Object named `field` (its schema's `enum`, a `$ref` schema resolved) and a
    dict keyed `field` that carries an `enum` (a schema property; one without an `enum` is not a
    provenance site). The whole document is walked, so path-level and operation-level parameters
    and components/parameters/* are each visited once, whatever the source spelling or key order."""
    found = []

    def enum_of(schema):
        if isinstance(schema, dict) and "$ref" in schema:
            schema = resolve_ref(spec, schema["$ref"])
        return schema.get("enum") if isinstance(schema, dict) else None

    def walk(node, where):
        if isinstance(node, dict):
            if node.get("name") == field and ("schema" in node or "in" in node):
                found.append((where, enum_of(node.get("schema"))))
            for key, val in node.items():
                if key == field and isinstance(val, dict):
                    enum = enum_of(val)
                    if enum is not None:
                        found.append((f"{where}/{key}", enum))
                walk(val, f"{where}/{key}")
        elif isinstance(node, list):
            for i, val in enumerate(node):
                walk(val, f"{where}/{i}")

    walk(spec, "")
    return found


EXPECTED_ECOSYSTEMS = table_ecosystems()


class VocabularyConsistency(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        files = discover_sources(REPO_ROOT, EMITTER_GLOBS)
        cls.emitted_kinds, cls.emitted_ecos = set(), set()
        for f in files:
            k, e = extract_literals(f.read_text(encoding="utf-8"))
            cls.emitted_kinds |= k
            cls.emitted_ecos |= e

    def test_discovery_is_not_vacuous(self):
        self.assertTrue(self.emitted_kinds)
        self.assertTrue(self.emitted_ecos)
        self.assertIn("macos_pkgutil", self.emitted_ecos)
        self.assertIn("app", self.emitted_kinds)

    def test_mcp_enumeration(self):
        text = read(MCP_SRC)
        self.assertEqual(extract_enumeration(text, "kind"), EXPECTED_KINDS)
        self.assertEqual(extract_enumeration(text, "ecosystem"), EXPECTED_ECOSYSTEMS)

    def test_openapi_enumeration(self):
        text = read(OPENAPI_SRC)
        self.assertEqual(extract_enumeration(text, "kind"), EXPECTED_KINDS)

    def test_json_enum_arrays_equal_vocabulary(self):
        # Anti-vacuous: each source must publish at least one `kind` enum array, and the MCP source
        # also an `ecosystem` one; every one must equal the vocabulary. OpenAPI's `ecosystem`
        # enums are the two generator tokens (checked below, as provenance: a hand-typed array
        # equal to the table is value-identical once served, so only the unexpanded literal can
        # tell); the served values are pinned by test_openapi_spec_completeness.cpp. The OpenAPI
        # side is read from the document check-api-parity.py decodes, so how the source spells
        # or orders a parameter's keys cannot hide it, and a parameter with no enum fails too.
        # Other tools reuse the field name `kind` for unrelated enums (e.g. the orientation
        # tool's fleet|agent|...): an array is a software-vocabulary array iff it shares a
        # value with the vocabulary, so a drifted copy (a dropped value) is still caught.
        def software(arrays, vocabulary):
            return [a for a in arrays if a & vocabulary]

        mcp = read(MCP_SRC)
        kinds = software(extract_json_enums(mcp, "kind"), EXPECTED_KINDS)
        ecos = software(extract_json_enums(mcp, "ecosystem"), EXPECTED_ECOSYSTEMS)
        self.assertGreaterEqual(len(kinds), 1, f"{MCP_SRC}: no JSON `kind` enum found")
        self.assertGreaterEqual(len(ecos), 1, f"{MCP_SRC}: no JSON `ecosystem` enum found")
        for k in kinds:
            self.assertEqual(k, EXPECTED_KINDS, MCP_SRC)
        for e in ecos:
            self.assertEqual(e, EXPECTED_ECOSYSTEMS, MCP_SRC)

        _, spec = PARITY.extract_openapi_paths()
        kinds = software([set(e) for _, e in openapi_field_enums(spec, "kind") if e],
                         EXPECTED_KINDS)
        self.assertGreaterEqual(len(kinds), 1, f"{OPENAPI_SRC}: no JSON `kind` enum found")
        for k in kinds:
            self.assertEqual(k, EXPECTED_KINDS, OPENAPI_SRC)
        sites = openapi_field_enums(spec, "ecosystem")
        self.assertGreaterEqual(len(sites), 6, f"{OPENAPI_SRC}: ecosystem parameters not found")
        for where, enum in sites:
            self.assertIn(enum, ECOSYSTEM_TOKENS,
                          f"{OPENAPI_SRC}: {where}: an OpenAPI ecosystem enum must be one of the "
                          f"generator tokens, never a hand-typed array or no enum")

    def test_manual_table(self):
        text = read(MANUAL)
        self.assertEqual(extract_table_row(text, "kind"), EXPECTED_KINDS)
        self.assertEqual(extract_table_row(text, "ecosystem"), EXPECTED_ECOSYSTEMS)

    def test_emitted_equals_published(self):
        self.assertEqual(self.emitted_kinds, EXPECTED_KINDS)
        self.assertEqual(self.emitted_ecos, EXPECTED_ECOSYSTEMS)

    def test_lane3_predicate_covers_vocabulary(self):
        hdr = read(CPE_HDR)
        for eco in EXPECTED_ECOSYSTEMS - LANE1:
            self.assertIn(f'eco == "{eco}"', hdr)
        for kind in LANE3_KINDS:
            self.assertIn(f'kind == "{kind}"', hdr)
        self.assertNotIn('kind == "pkg"', hdr)


def _table(declared, *rows):
    return "std::array<EcosystemFamily, %d> kEcosystemFamilies{{\n%s\n}};" % (declared, "\n".join(rows))


def _doc(params=(), **components):
    """A minimal decoded document: one operation carrying `params`, plus `components`."""
    return {"paths": {"/x": {"get": {"parameters": list(params)}}}, "components": components}


class GateParsers(unittest.TestCase):
    """The gate's own parsers on synthetic input: the real tree cannot hold a negative."""

    TOKEN_PARAM = json.loads(
        '{"name": "ecosystem", "in": "query", "schema": {"enum": ["@@ECOSYSTEM_ENUM@@"]}}')

    def enums(self, spec, field="ecosystem"):
        return [e for _, e in openapi_field_enums(spec, field)]

    def test_token_parameter_is_a_token(self):
        (enum,) = self.enums(_doc([self.TOKEN_PARAM]))
        self.assertIn(enum, ECOSYSTEM_TOKENS)

    def test_hand_typed_table_equal_array_is_found_and_is_not_a_token(self):
        param = {"name": "ecosystem", "in": "query",
                 "schema": {"type": "string", "enum": sorted(EXPECTED_ECOSYSTEMS)}}
        (enum,) = self.enums(_doc([param]))
        self.assertEqual(set(enum), EXPECTED_ECOSYSTEMS)
        self.assertNotIn(enum, ECOSYSTEM_TOKENS)

    def test_spelling_key_order_escape_and_prose_do_not_hide_or_inflate(self):
        # The source bytes of these parameters defeat any `"name":` text scan: a space before the
        # colon, schema before name, a `}` and a verbatim `"name": "ecosystem"` inside a
        # description, and a JSON-escaped key. Decoded, they are two parameters and nothing else.
        params = json.loads(r"""[
          {"name" : "ecosystem", "description": "a } b and \"name\": \"ecosystem\"",
           "schema": {"enum": ["a"]}},
          {"schema": {"enum": ["a"]}, "\u006eame": "ecosystem", "in": "query"}
        ]""")
        self.assertEqual(self.enums(_doc(params)), [["a"], ["a"]])

    def test_enum_bearing_property_keyed_ecosystem_is_found_a_plain_one_is_not(self):
        spec = _doc(schemas={
            "Row": {"properties": {"ecosystem": {"type": "string", "enum": ["a"]}}},
            "Plain": {"properties": {"ecosystem": {"type": "string"}}}})
        self.assertEqual(openapi_field_enums(spec, "ecosystem"),
                         [("/components/schemas/Row/properties/ecosystem", ["a"])])

    def test_ref_schema_is_resolved_to_its_array(self):
        param = {"name": "ecosystem", "in": "query", "schema": {"$ref": "#/components/schemas/E"}}
        spec = _doc([param], schemas={"E": {"type": "string", "enum": ["a", "b"]}})
        self.assertEqual(self.enums(spec), [["a", "b"]])

    def test_ref_parameter_is_counted_once_through_components(self):
        spec = _doc([{"$ref": "#/components/parameters/ecosystem"}],
                    parameters={"ecosystem": self.TOKEN_PARAM})
        (enum,) = self.enums(spec)
        self.assertIn(enum, ECOSYSTEM_TOKENS)

    def test_parameter_without_a_resolvable_enum_is_found_as_none(self):
        spec = _doc([{"name": "ecosystem", "in": "query", "schema": {"type": "string"}},
                     {"name": "ecosystem", "in": "query", "schema": {"$ref": "#/nowhere"}},
                     {"name": "ecosystem", "in": "query"}])
        self.assertEqual(self.enums(spec), [None, None, None])

    def test_commented_row_is_not_a_row_in_either_comment_form(self):
        live = '{"a", "linux"},'
        for off in ('// {"b", "linux"},', '/* {"b", "linux"}, */', '/*\n{"b", "linux"},\n*/'):
            self.assertEqual(parse_ecosystem_table(_table(1, live, off)), {"a"}, off)

    def test_block_commented_row_with_the_size_kept_is_a_mismatch(self):
        with self.assertRaisesRegex(AssertionError, "parsed 1 ecosystems, declared 2"):
            parse_ecosystem_table(_table(2, '{"a", "linux"},', '/* {"b", "linux"}, */'))

    def test_block_opener_inside_a_line_comment_opens_nothing(self):
        rows = ('{"a", "linux"}, // note /*', '{"b", "linux"},')
        self.assertEqual(parse_ecosystem_table(_table(2, *rows)), {"a", "b"})


if __name__ == "__main__":
    unittest.main()
