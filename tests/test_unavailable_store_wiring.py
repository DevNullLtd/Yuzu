#!/usr/bin/env python3
"""Static gate: the OpenAPI x-yuzu-unavailable markers agree with the stores server.cpp wires.

Three route groups exist only when their store is passed to RestApiV1::register_routes():
Software Deployment, Device Tokens and License Management. The OpenAPI document marks each of
their operations x-yuzu-unavailable, which tells a reader the running server does not serve
them. The unit test test_openapi_spec_completeness.cpp checks the markers against a registration
made with null and fake stores, so it cannot see what server.cpp actually passes. This gate
reads that call and ties the two together:

  * a store passed as the literal nullptr  <=>  its group is marked unavailable in the document.

Wiring a store without removing its markers, or removing the markers while the store is still
null, fails here. A marked group that has no entry in GROUPS fails too, so a new unavailable
group has to be added to the table on purpose.

Lexical, like scripts/ci/check-api-parity.py: it reads source text and does not build anything.
Carries an in-memory self-test that mutates the text and expects each change to be caught.
Run: python3 tests/test_unavailable_store_wiring.py
"""

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
SERVER = ROOT / "server" / "core" / "src" / "server.cpp"
SPEC = ROOT / "server" / "core" / "src" / "rest_api_v1.cpp"

# OpenAPI tag of the group -> the register_routes parameter that gates its routes.
GROUPS = {
    "Software Deployment": "sw_deploy_store",
    "Device Tokens": "device_token_store",
    "License Management": "license_store",
}

CALL = re.compile(r"rest_api_v1_\s*->\s*register_routes\s*\(")
# `/*name=*/ expression,` : the argument comment server.cpp uses for these three.
ARG = re.compile(r"/\*\s*(%s)\s*=\s*\*/\s*([^,)]+?)\s*[,)]" % "|".join(GROUPS.values()))
MARKER_LINE = re.compile(r'"x-yuzu-unavailable"')
TAGS = re.compile(r'"tags"\s*:\s*\[\s*"([^"]+)"')


class GateError(Exception):
    pass


def wired_stores(server_src: str):
    """Returns {parameter: True when server.cpp passes something other than nullptr}."""
    calls = list(CALL.finditer(server_src))
    if len(calls) != 1:
        raise GateError(
            "expected exactly one rest_api_v1_->register_routes( call in server.cpp, found %d: "
            "if it moved or a second call was added, update this gate" % len(calls)
        )
    # The three arguments sit within the call's argument list; the list is long, so bound the
    # search by the next 6,000 characters rather than parsing parentheses.
    window = server_src[calls[0].end() : calls[0].end() + 6000]
    found = {m.group(1): m.group(2) != "nullptr" for m in ARG.finditer(window)}
    missing = set(GROUPS.values()) - set(found)
    if missing:
        raise GateError(
            "cannot find the /*%s=*/ argument comment(s) in the register_routes call in "
            "server.cpp: %s" % ("*/ and /*".join(sorted(missing)), ", ".join(sorted(missing)))
        )
    return found


def marked_groups(spec_src: str):
    """Returns the set of OpenAPI tags that have an operation marked x-yuzu-unavailable."""
    tags = set()
    marker_lines = 0
    for line in spec_src.splitlines():
        if not MARKER_LINE.search(line):
            continue
        marker_lines += 1
        m = TAGS.search(line)
        if not m:
            raise GateError("a line with x-yuzu-unavailable has no tags array: %r" % line[:120])
        tags.add(m.group(1))
    if marker_lines == 0:
        raise GateError(
            "no x-yuzu-unavailable marker found in rest_api_v1.cpp: if the marker was renamed, "
            "update this gate"
        )
    return tags


def check(server_src: str, spec_src: str):
    """Returns a list of problems; empty when the markers and the wiring agree."""
    wired = wired_stores(server_src)
    marked = marked_groups(spec_src)
    problems = []
    for tag in sorted(marked - set(GROUPS)):
        problems.append(
            "group %r is marked x-yuzu-unavailable but has no entry in GROUPS: add the "
            "register_routes parameter that gates it" % tag
        )
    for tag, param in GROUPS.items():
        is_wired = wired[param]
        is_marked = tag in marked
        if is_wired and is_marked:
            problems.append(
                "%s is wired in server.cpp but its operations are still marked "
                "x-yuzu-unavailable" % param
            )
        if not is_wired and not is_marked:
            problems.append(
                "%s is passed as nullptr in server.cpp but %r has no x-yuzu-unavailable "
                "marker, so the document presents unserved routes as callable" % (param, tag)
            )
    return problems


def self_test(server_src: str, spec_src: str):
    """Each mutation must be reported; the unmutated text must be clean."""
    assert check(server_src, spec_src) == [], "the unmutated sources are not clean"
    # Wire the license store: the License Management markers are now wrong.
    wired = server_src.replace("/*license_store=*/nullptr", "/*license_store=*/license_store_.get()", 1)
    assert wired != server_src, "self-test: license_store argument not found to mutate"
    assert check(wired, spec_src), "wiring a store while it is marked was not caught"
    # Strip every Device Tokens marker: the group is unmarked while its store is still null.
    stripped = "\n".join(
        line.replace('"x-yuzu-unavailable"', '"x-removed"')
        if '"tags": ["Device Tokens"]' in line
        else line
        for line in spec_src.splitlines()
    )
    assert stripped != spec_src, "self-test: no Device Tokens marker found to mutate"
    assert check(server_src, stripped), "removing markers while the store is null was not caught"
    # A new marked group nobody mapped.
    extra = spec_src + '\n"x-yuzu-unavailable": "x", "tags": ["Brand New Group"]\n'
    assert check(server_src, extra), "an unmapped marked group was not caught"


def main():
    server_src = SERVER.read_text(encoding="utf-8")
    spec_src = SPEC.read_text(encoding="utf-8")
    try:
        self_test(server_src, spec_src)
        problems = check(server_src, spec_src)
    except GateError as e:
        print("FAIL: %s" % e)
        return 1
    except AssertionError as e:
        print("FAIL (self-test): %s" % e)
        return 1
    if problems:
        for p in problems:
            print("FAIL: %s" % p)
        return 1
    print("OK: %d unavailable groups agree with the register_routes wiring" % len(GROUPS))
    return 0


if __name__ == "__main__":
    sys.exit(main())
