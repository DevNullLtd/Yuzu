#!/usr/bin/env python3
"""Static gate: the OpenAPI authoring mistakes a dev-side author otherwise meets one CI round at
a time, reported together and before any build.

An operation added to the OpenAPI literal in server/core/src/rest_api_v1.cpp is checked, after a
full Linux build, by two test cases in tests/unit/server/test_openapi_spec_completeness.cpp, and
each stops at its first kind of failure:

  1. "every operation has a unique, well-formed and pinned operationId in both forms":
     REQUIRE(op has a string operationId), CHECK(id matches kShape), CHECK(id is unused so far),
     then CHECK(content_etag(sorted "id method path" lines) == kOperationIdChecksum).
  2. "all but two operations declare a typed success response": the set of operations with no
     typed 2xx response must equal kUntyped.

An author who has never seen the document meets them in that order: no operationId, then the
checksum, then an untyped response, three build-and-wait rounds. This gate reads the same
literal text (the R"json(...)json" chain that tests/test_openapi_literal_segments.py lexes) and
the same constants out of the C++ test, applies the same rules, and prints every violation in one
run, with the checksum the pin must be changed to. It does not build anything.

Rules, each mirroring tests/unit/server/test_openapi_spec_completeness.cpp (named, not
line-numbered, because the lines move):
  A. every operation (a path item member named get/put/post/delete/options/head/patch/trace,
     as all_operations() lists them) has a string operationId;
  B. operationIds match kShape (^[a-z][A-Za-z0-9]*$ today, read from the C++ test) and are
     unique across the document;
  C. an operation with no 2xx response carrying content.<media>.schema (has_typed_success() in
     the C++ test) is listed in kUntyped (read from the C++ test), and a kUntyped entry names an
     operation that exists and is untyped (the C++ test compares the two sets for equality);
  D. kOperationIdChecksum (read from the C++ test) equals content_etag() of the sorted
     "<id> <method> <path>\\n" lines, content_etag() being FNV-1a 64 with the offset constant in
     server/core/src/content_etag.hpp. Skipped, and said so, while A or B fail, because the C++
     test REQUIREs those first;
  E. every raw-string segment stays under the 15,000-byte ceiling, by calling
     test_openapi_literal_segments.py's own function (one lexer, one ceiling).

Both forms of the document (default and ?guides=true) differ only in the tags' x-yuzu-guide
members, so they hold the same operations and one pass covers both.

Not checked here, still covered by the C++ tests after the build: the wording rules (no issue or
ADR citations), response schemas against real handler output (ResponsePin), security and
x-yuzu-unavailable markers (the wiring gate beside this one covers the markers), $ref targets,
and any error response being typed (the C++ test requires a typed SUCCESS only).

Run: python3 -I tests/test_openapi_operation_authoring.py [rest_api_v1.cpp] [test_openapi_spec_completeness.cpp]
"""

import json
import pathlib
import re
import sys

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))
import test_openapi_literal_segments as literal  # noqa: E402  (the one lexer of the literal chain)

SOURCE = ROOT / "server" / "core" / "src" / "rest_api_v1.cpp"
CPP_TEST = ROOT / "tests" / "unit" / "server" / "test_openapi_spec_completeness.cpp"

# all_operations() in the C++ test: these path item members are operations, others are not.
VERBS = ("get", "put", "post", "delete", "options", "head", "patch", "trace")
# The shape the C++ test requires today; the gate refuses to run if the test's kShape changes.
SHAPE_PATTERN = "^[a-z][A-Za-z0-9]*$"
SHAPE = re.compile(r"[a-z][A-Za-z0-9]*")
MIN_OPERATIONS = 100  # REQUIRE(ops.size() > 100) in the C++ test

ID_PROCEDURE = (
    "To update the pin: copy the new value into kOperationIdChecksum in "
    "tests/unit/server/test_openapi_spec_completeness.cpp, and state any rename or removal in "
    "the operationId note of docs/user-manual/upgrading.md and in the change's changelog "
    "fragment (the comment above kOperationIdChecksum)"
)


class SetupError(Exception):
    pass


def content_etag(body: bytes) -> str:
    """content_etag() in server/core/src/content_etag.hpp: FNV-1a 64 with the offset constant
    1469598103934665603 (the standard basis with its last digit dropped, kept on purpose),
    rendered as a quoted sixteen-digit lowercase hex string."""
    h = 1469598103934665603
    for c in body:
        h ^= c
        h = (h * 1099511628211) & 0xFFFFFFFFFFFFFFFF
    return f'"{h:016x}"'


def spec_from_chain(chain: bytes):
    """Parses the joined literal chain. The three @@ECOSYSTEM_*@@ tokens are replaced with
    placeholders of the same JSON shape (expand_ecosystem_tokens() in software_catalog_rules.hpp
    substitutes the real vocabulary); no operation, operationId or response depends on them."""
    text = chain.decode("utf-8")
    text = text.replace('"@@ECOSYSTEM_ENUM@@"', '"x"')
    text = text.replace('"@@ECOSYSTEM_ENUM_OR_EMPTY@@"', '"", "x"')
    text = text.replace("@@ECOSYSTEM_LIST@@", "x")
    try:
        spec = json.loads(text)
    except ValueError as e:
        raise SetupError(
            f"the OpenAPI literal chain is not valid JSON ({e}); fix the JSON first, nothing "
            "else can be checked until it parses"
        )
    if not isinstance(spec.get("paths"), dict):
        raise SetupError('the OpenAPI literal has no "paths" object')
    return spec


def operations(spec):
    """[(method, path, op)] in the C++ test's iteration order: nlohmann::json objects are
    std::map, so paths and then members iterate in sorted key order."""
    out = []
    for path in sorted(spec["paths"]):
        item = spec["paths"][path]
        if not isinstance(item, dict):
            continue
        for key in sorted(item):
            if key in VERBS:
                out.append((key, path, item[key]))
    return out


def has_typed_success(op) -> bool:
    """has_typed_success() in the C++ test: a response whose code starts with '2' and whose
    content has any media type declaring a schema."""
    responses = op.get("responses") if isinstance(op, dict) else None
    if not isinstance(responses, dict):
        return False
    for code, resp in responses.items():
        if not code.startswith("2") or not isinstance(resp, dict):
            continue
        content = resp.get("content")
        if not isinstance(content, dict):
            continue
        for body in content.values():
            if isinstance(body, dict) and "schema" in body:
                return True
    return False


def read_cpp_constants(cpp: str):
    """(kShape pattern, kUntyped set, kOperationIdChecksum) lexed from the C++ test source."""
    m = re.search(r'std::regex\s+kShape\(\s*"((?:[^"\\]|\\.)*)"\s*\)', cpp)
    if not m:
        raise SetupError("cannot find `std::regex kShape(\"...\")` in the C++ test")
    shape = m.group(1)
    m = re.search(r'const\s+std::set<std::string>\s+kUntyped\s*=\s*\{(.*?)\}\s*;', cpp, re.S)
    if not m:
        raise SetupError("cannot find `const std::set<std::string> kUntyped = {...};` in the C++ test")
    untyped = set(re.findall(r'"((?:[^"\\]|\\.)*)"', m.group(1)))
    m = re.search(r'kOperationIdChecksum\s*=\s*"\\"([0-9a-f]{16})\\""\s*;', cpp)
    if not m:
        raise SetupError('cannot find `kOperationIdChecksum = "\\"<16 hex>\\"";` in the C++ test')
    return shape, untyped, f'"{m.group(1)}"'


def line_finder(src: bytes):
    """where(path) -> 'rest_api_v1.cpp:<line>' of the first appearance of the quoted path key
    in the literal chain, best effort (an empty string when it cannot be placed)."""
    spans = literal.spans(src)

    def where(path: str) -> str:
        needle = b'"' + path.encode("utf-8") + b'"'
        for line0, start, end in spans:
            at = src.find(needle, start, end)
            if at >= 0:
                line = src.count(b"\n", 0, at) + 1
                return f"rest_api_v1.cpp:{line}: "
        return ""

    return where


def problems(spec, shape_pattern, kuntyped, pin, where=lambda _p: ""):
    found = []
    if shape_pattern != SHAPE_PATTERN:
        raise SetupError(
            f"the C++ test's kShape is now {shape_pattern!r}, not {SHAPE_PATTERN!r}: update "
            "SHAPE in this gate to match before trusting its verdict"
        )
    ops = operations(spec)
    if len(ops) <= MIN_OPERATIONS:
        found.append(
            f"only {len(ops)} operations found (the C++ test requires more than {MIN_OPERATIONS}); "
            "the paths object was probably restructured, update this gate"
        )

    # A and B: operationId present, well formed, unique.
    seen = {}
    ids_ok = True
    for method, path, op in ops:
        label = f"{method} {path}"
        oid = op.get("operationId") if isinstance(op, dict) else None
        if oid is None:
            found.append(f"{where(path)}{label}: no operationId (every operation needs one; it is "
                         "the method name an OpenAPI client generator derives, so pick it once and "
                         "never rename it, e.g. getFoo for GET /foo)")
            ids_ok = False
            continue
        if not isinstance(oid, str):
            found.append(f"{where(path)}{label}: operationId is not a string")
            ids_ok = False
            continue
        if not SHAPE.fullmatch(oid):
            found.append(f"{where(path)}{label}: operationId {oid!r} is ill-formed (it must match "
                         f"{SHAPE_PATTERN}: lower-case first letter, then letters and digits only)")
            ids_ok = False
        if oid in seen:
            found.append(f"{where(path)}{label}: operationId {oid!r} is also used by {seen[oid]}")
            ids_ok = False
        else:
            seen[oid] = label

    # C: typed success, against the exclusion list.
    untyped = {f"{m} {p}" for m, p, op in ops if not has_typed_success(op)}
    exists = {f"{m} {p}" for m, p, _op in ops}
    path_of = {f"{m} {p}": p for m, p, _op in ops}
    for label in sorted(untyped - kuntyped):
        found.append(f"{where(path_of[label])}{label}: no 2xx response declares a schema "
                     "(responses.<2xx>.content.<media>.schema). Type the success response with a "
                     "$ref or inline schema; kUntyped in the C++ test is only for a body-less "
                     "answer such as a 204 and a new name there is a regression, not an addition")
    for label in sorted(kuntyped - untyped):
        why = "is typed now" if label in exists else "names no operation in the document"
        found.append(f"kUntyped in the C++ test lists {label!r}, which {why}: remove the entry "
                     "(the C++ test compares the two sets for equality)")

    # D: the pin, over the sorted "id method path" lines.
    if not ids_ok:
        found.append("operationId pin not checked: fix the operationId problems above first (the "
                     "C++ test REQUIREs them before it hashes)")
    else:
        # std::map<std::string, ...> orders by byte value, so sort on the UTF-8 bytes.
        lines = "".join(f"{oid} {label}\n" for oid, label in sorted(seen.items(),
                                                                    key=lambda kv: kv[0].encode()))
        digest = content_etag(lines.encode("utf-8"))
        if digest != pin:
            found.append(f"kOperationIdChecksum is {pin} but the document's operationIds hash to "
                         f"{digest}. {ID_PROCEDURE}")
    return found


def check(src: bytes, cpp: str):
    shape, kuntyped, pin = read_cpp_constants(cpp)
    spec = spec_from_chain(literal.chain_text(src))
    found = problems(spec, shape, kuntyped, pin, line_finder(src))
    # E: the segment ceiling, from the one existing gate.
    found += literal.problems(src)
    return found


# ── self-test ────────────────────────────────────────────────────────────────────────────────────


def _fixture():
    def op(oid=None, typed=True):
        d = {"summary": "s"}
        if oid is not None:
            d["operationId"] = oid
        if typed:
            d["responses"] = {"200": {"content": {"application/json": {"schema": {"type": "object"}}}}}
        else:
            d["responses"] = {"204": {"description": "gone"}}
        return d

    paths = {}
    for i in range(MIN_OPERATIONS + 5):
        paths[f"/r{i}"] = {"get": op(f"getR{i}")}
    paths["/r0"]["delete"] = op("deleteR0", typed=False)
    paths["/r0"]["parameters"] = [{"name": "ignored"}]  # not a verb: never an operation
    return {"openapi": "3.0.3", "paths": paths}, {"delete /r0"}


def _pin(spec):
    rows = sorted(
        ((op["operationId"], f"{m} {p}") for m, p, op in operations(spec)), key=lambda r: r[0].encode()
    )
    return content_etag("".join(f"{i} {w}\n" for i, w in rows).encode())


def selftest():
    # content_etag known vectors, from the C++ test "content_etag(): known vectors".
    assert content_etag(b"") == '"14650fb0739d0383"'
    assert content_etag(b"a") == '"44bd8ad473cd9906"'
    assert content_etag(b"yuzu") == '"ea31ac803c5388dc"'
    assert content_etag(bytes(range(256))) == '"16d173bdfcdae583"'

    spec, kuntyped = _fixture()
    pin = _pin(spec)
    run = lambda s, k=kuntyped, p=pin: problems(s, SHAPE_PATTERN, k, p)  # noqa: E731
    assert run(spec) == [], "the clean fixture must pass"

    def mutated(fn):
        s = json.loads(json.dumps(spec))
        fn(s["paths"])
        return s

    # A: missing operationId; the pin is skipped, not mis-reported.
    out = run(mutated(lambda p: p["/r1"]["get"].pop("operationId")))
    assert len(out) == 2 and "no operationId" in out[0] and "pin not checked" in out[1], out
    # B: ill-formed (upper-case start, underscore, empty) and duplicate.
    for bad in ("GetR1", "get_r1", "1get", ""):
        out = run(mutated(lambda p, b=bad: p["/r1"]["get"].update(operationId=b)))
        assert any("ill-formed" in o for o in out), (bad, out)
    out = run(mutated(lambda p: p["/r2"]["get"].update(operationId="getR1")))
    assert any("also used by" in o for o in out), out
    # C: an untyped success not in kUntyped; a stale kUntyped entry; an error-only schema.
    out = run(mutated(lambda p: p["/r3"]["get"].update(responses={"200": {"description": "x"}})))
    assert any("no 2xx response declares a schema" in o and "get /r3" in o for o in out), out
    out = run(mutated(lambda p: p["/r4"]["get"].update(
        responses={"400": {"content": {"application/json": {"schema": {}}}}})))
    assert any("get /r4" in o for o in out), "a schema on an error response does not type the success"
    out = run(spec, k=kuntyped | {"get /r5"})
    assert any("get /r5" in o and "is typed now" in o for o in out), out
    out = run(spec, k=kuntyped | {"get /nope"})
    assert any("names no operation" in o for o in out), out
    # D: a stale pin, and the swap of two ids (the pin carries the method and path).
    out = run(mutated(lambda p: p["/r6"]["get"].update(operationId="getRenamed")))
    assert len(out) == 1 and "kOperationIdChecksum" in out[0], out
    def swap(p):
        p["/r6"]["get"]["operationId"], p["/r7"]["get"]["operationId"] = "getR7", "getR6"
    out = run(mutated(swap))
    assert len(out) == 1 and "kOperationIdChecksum" in out[0], out
    # All three first-round mistakes at once, in one run.
    def three(p):
        p["/r1"]["get"].pop("operationId")
        p["/r2"]["get"]["operationId"] = "getR3"
        p["/r4"]["get"]["responses"] = {"200": {"description": "x"}}
    assert len(run(mutated(three))) == 4  # missing id, duplicate id, untyped success, pin skipped
    # A short document is reported, not trusted.
    assert any("only 1 operations" in o for o in
               problems({"paths": {"/a": {"get": {"operationId": "getA"}}}}, SHAPE_PATTERN, set(), pin))
    # A changed C++ kShape stops the gate instead of letting it diverge silently.
    try:
        problems(spec, "^[A-Za-z]+$", kuntyped, pin)
    except SetupError:
        pass
    else:
        raise AssertionError("a changed kShape must stop the gate")

    # The constants lexer, on a miniature of the C++ test text.
    cpp = (
        'static const std::string kOperationIdChecksum = "\\"70d0ae0ed158e548\\"";\n'
        'static const std::regex kShape("^[a-z][A-Za-z0-9]*$");\n'
        'const std::set<std::string> kUntyped = {"delete /a/{id}",\n  "delete /b"};\n'
    )
    assert read_cpp_constants(cpp) == (
        SHAPE_PATTERN, {"delete /a/{id}", "delete /b"}, '"70d0ae0ed158e548"')
    for broken in (cpp.replace("kShape", "kForm"), cpp.replace("kUntyped", "kOther"),
                   cpp.replace("70d0ae0ed158e548", "xyz")):
        try:
            read_cpp_constants(broken)
        except SetupError:
            continue
        raise AssertionError("an unreadable C++ constant must stop the gate, never pass it")

    # End to end on a miniature chain: the lexer, the token placeholders, the line finder.
    doc = json.dumps(spec, indent=1)
    chain = ('static const std::string spec = expand_ecosystem_tokens(\n    R"json(' + doc[:200] +
             ')json"\n    R"json(' + doc[200:] + ')json");\n').encode()
    assert json.loads(literal.chain_text(chain)) == spec
    tokens = literal.chain_text(
        b'static const std::string spec = expand_ecosystem_tokens(R"json({"paths": {}, "e": '
        b'["@@ECOSYSTEM_ENUM_OR_EMPTY@@"], "n": "a @@ECOSYSTEM_LIST@@"})json");')
    assert spec_from_chain(tokens) == {"paths": {}, "e": ["", "x"], "n": "a x"}
    assert line_finder(chain)("/r1").startswith("rest_api_v1.cpp:")


def main():
    selftest()
    literal.selftest()  # the docs-lint job runs only this script, so it carries the detector's own self-test
    args = [pathlib.Path(a) for a in sys.argv[1:]]
    source = args[0] if args else SOURCE
    cpp_test = args[1] if len(args) > 1 else CPP_TEST
    try:
        found = check(source.read_bytes(), cpp_test.read_text(encoding="utf-8"))
    except (SetupError, literal.ChainError) as e:
        print(f"FAIL: {e}")
        return 1
    for f in found:
        print(f"FAIL: {f}")
    if found:
        print(f"{len(found)} OpenAPI authoring problem(s); the C++ tests in "
              "tests/unit/server/test_openapi_spec_completeness.cpp would report them one kind "
              "at a time after a full build")
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main())
