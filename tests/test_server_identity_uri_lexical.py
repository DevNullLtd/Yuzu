#!/usr/bin/env python3
"""Static LEXICAL gate (#6016): only default_certs mints the server identity URI.

The gateway management plane will admit a peer by the exact URI SAN
`yuzu://<install>/server`. The guarantee that no agent or gateway can obtain it is
STRUCTURAL: `sign_agent_csr` ignores the CSR's SAN and only ever emits `/agent/<id>`, and
the only code that builds the `/server` URI is `default_certs.cpp`. A unit test over the
signing primitive cannot see a future edit that adds a new signer or a new `/server` literal
elsewhere, so this gate pins the call-site shape. Over every C/C++ file under server/, with
comments removed (string and character literals kept intact, so the `//` in "yuzu://" is not
mistaken for a comment):

  1. `server_identity_uri(` is mentioned only in default_certs.hpp / default_certs.cpp.
  2. The exact string literal "/server" (the URI suffix) appears only in default_certs.cpp.
  3. `issue_leaf(` is called only from x509_ca.* and default_certs.cpp.
  4. `revoke_system` (the system-reserved revocation reasons) is mentioned only in
     default_certs.cpp and ca_store.{hpp,cpp}: an operator surface must go through
     `CaStore::revoke`, which qualifies a reason that collides with a system marker.
  5. `sign_csr(` is called from exactly: x509_ca.* (the primitive), default_certs.cpp (1: the
     server-leaf upgrade) and server.cpp (2: sign_agent_csr and the code-signing issuer).
     A new signer is a new reviewed decision, not a drive-by.

LEXICAL ONLY: not data-flow. It cannot see a signer reached through a macro or generated code.
The behavioural guarantee is tests/unit/server/test_x509_ca.cpp (a CSR requesting the server
URI is issued without it) and test_default_certs.cpp (only the server leaf carries it).

Usage: python3 tests/test_server_identity_uri_lexical.py [SERVER_DIR]
Carries its own negative-control self-test (in-memory mutated sources); exits non-zero on
either a violation in the tree or a self-test that failed to catch its mutation.
"""
from __future__ import annotations

import pathlib
import re
import sys

EXTS = {".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx", ".inc", ".ipp", ".mm"}
URI_FILES = {"default_certs.hpp", "default_certs.cpp"}
SIGN_CSR_EXPECTED = {"default_certs.cpp": 1, "server.cpp": 2}


def strip_comments(src: str) -> str:
    """Remove // and /* */ comments; leave string/char literals untouched."""
    out, i, n = [], 0, len(src)
    while i < n:
        c = src[i]
        two = src[i : i + 2]
        if two == "//":
            while i < n and src[i] != "\n":
                i += 1
        elif two == "/*":
            j = src.find("*/", i + 2)
            i = n if j < 0 else j + 2
            out.append(" ")
        elif c == "'" and i > 0 and src[i - 1].isalnum() and i + 1 < n and src[i + 1].isalnum():
            # C++14 digit separator (86'400, 0xFF'FF): not a character literal.
            out.append(c)
            i += 1
        elif c == '"' and i > 0 and src[i - 1] == "R" and (i < 2 or not (src[i - 2].isalnum() or src[i - 2] == "_") or src[i - 2:i] in ("8R",) or src[i - 2] in "uUL"):
            # Raw string literal R"delim( ... )delim": comment markers inside are data.
            m = re.match(r'"([^()\\ \t\n]{0,16})\(', src[i:])
            if m:
                end = src.find(")" + m.group(1) + '"', i + m.end())
                j = n if end < 0 else end + len(m.group(1)) + 2
                out.append(src[i:j])
                i = j
            else:
                out.append(c)
                i += 1
        elif c in "\"'":
            q, j = c, i + 1
            while j < n and src[j] != q:
                j += 2 if src[j] == "\\" else 1
            out.append(src[i : j + 1])
            i = j + 1
        else:
            out.append(c)
            i += 1
    return "".join(out)


def problems(files: dict[str, str]) -> list[str]:
    """`files` maps a basename-or-relative path to its source text."""
    found: list[str] = []
    sign_counts: dict[str, int] = {}
    for path, raw in files.items():
        base = pathlib.PureWindowsPath(path).name  # handles both "/" and "\\" separators
        text = strip_comments(raw)
        if base not in URI_FILES and re.search(r"\bserver_identity_uri\s*\(", text):
            found.append(f"{path}: mentions server_identity_uri( outside default_certs")
        if base != "default_certs.cpp" and re.search(r'"/server"', text):
            found.append(f'{path}: builds the "/server" URI suffix outside default_certs.cpp')
        if base not in {"default_certs.cpp", "ca_store.hpp", "ca_store.cpp"} and re.search(
                r"\brevoke_system\b", text):
            found.append(f"{path}: mentions revoke_system outside default_certs/ca_store")
        is_x509 = base.startswith("x509_ca.")
        if not is_x509 and base != "default_certs.cpp" and re.search(r"\bissue_leaf\s*\(", text):
            found.append(f"{path}: calls issue_leaf( outside default_certs.cpp")
        if not is_x509:
            # `sign_csr(` only as a call/definition-shaped token (not issue_code_signing_leaf etc.).
            # Accumulate per basename: a same-named file in another directory must ADD to the
            # count, not be masked by (or mask) the real one.
            sign_counts[base] = sign_counts.get(base, 0) + len(
                re.findall(r"(?<![\w])(?:pki::)?sign_csr\s*\(", text))
    for base, count in sign_counts.items():
        want = SIGN_CSR_EXPECTED.get(base, 0)
        if count != want:
            found.append(f"{base}: {count} sign_csr( call site(s), reviewed set allows {want}")
    for base, want in SIGN_CSR_EXPECTED.items():
        if base not in sign_counts:
            found.append(f"{base}: not scanned (expected {want} sign_csr( call site(s)); "
                         "was it renamed or moved?")
    return found


def load_tree(root: pathlib.Path) -> dict[str, str]:
    files = {}
    for p in sorted(root.rglob("*")):
        if p.is_file() and p.suffix.lower() in EXTS:
            files[p.relative_to(root).as_posix()] = p.read_text(encoding="utf-8", errors="replace")
    return files


def self_test() -> int:
    good = {
        "core/src/default_certs.hpp": "std::string server_identity_uri(std::string_view);",
        "core/src/default_certs.cpp": 'auto u = "yuzu://" + id + "/server"; pki::issue_leaf(a); '
        "pki::sign_csr(c);",
        "core/src/server.cpp": "pki::sign_csr(a); pki::sign_csr(b); // \"/server\" in a comment",
        "core/src/x509_ca.cpp": "sign_csr(x); issue_leaf(y);",
    }
    failures = 0

    def expect(name: str, files: dict[str, str], want_clean: bool) -> None:
        nonlocal failures
        got = problems(files)
        if bool(got) == want_clean:
            failures += 1
            print(f"SELF-TEST FAIL: {name}: expected {'clean' if want_clean else 'violation'}, "
                  f"got {got}")

    expect("baseline is clean", good, True)
    expect("URI helper used in server.cpp", {**good, "core/src/server.cpp":
           good["core/src/server.cpp"] + "\nserver_identity_uri(fp);"}, False)
    expect('"/server" literal in server.cpp', {**good, "core/src/server.cpp":
           good["core/src/server.cpp"] + '\nauto s = "yuzu://" + i + "/server";'}, False)
    expect("revoke_system in a route", {**good, "core/src/ca_routes.cpp":
           "store->revoke_system(s, kRevokeReasonSuperseded);"}, False)
    expect("revoke_system as a pointer-to-member", {**good, "core/src/ca_routes.cpp":
           "auto f = &CaStore::revoke_system;"}, False)
    expect("new issue_leaf caller", {**good, "core/src/ca_routes.cpp": "pki::issue_leaf(a);"}, False)
    expect("third sign_csr in server.cpp", {**good, "core/src/server.cpp":
           good["core/src/server.cpp"] + "\npki::sign_csr(z);"}, False)
    expect("new sign_csr file", {**good, "core/src/other.cpp": "pki::sign_csr(z);"}, False)
    expect("scanned set lost default_certs.cpp",
           {k: v for k, v in good.items() if k != "core/src/default_certs.cpp"}, False)
    expect("a // inside a string is not a comment", {**good, "core/src/server.cpp":
           good["core/src/server.cpp"] + '\nauto s = "x//y"; pki::sign_csr(z);'}, False)
    expect("digit separator does not eat a comment", {**good, "core/src/ca_routes.cpp":
           "int d = 86'400; // pki::sign_csr( here is a comment\nint e = 1'000;"}, True)
    expect("raw string with // inside is data", {**good, "core/src/server.cpp":
           good["core/src/server.cpp"] + '\nauto r = R"(a // b)"; pki::sign_csr(z);'}, False)
    # Windows-style separators must not defeat the basename match (the Windows CI leg
    # runs this gate; load_tree emits posix paths, but problems() is defensive).
    expect("same-named file in another directory is counted too", {**good,
           "core/src/a/server.cpp": "pki::sign_csr(a); pki::sign_csr(b); pki::sign_csr(c);"}, False)
    expect("backslash paths are normalised",
           {k.replace("/", "\\"): v for k, v in good.items()}, True)
    expect("comment mention is ignored", {**good, "core/src/ca_routes.cpp":
           "// pki::issue_leaf(a); server_identity_uri(x) \"/server\"\n/* sign_csr( */"}, True)
    return failures


def main(argv: list[str]) -> int:
    failures = self_test()
    here = pathlib.Path(__file__).resolve().parent
    root = pathlib.Path(argv[1]) if len(argv) > 1 else here.parent / "server"
    tree = load_tree(root)
    if not tree:
        print(f"no C/C++ sources found under {root}")
        return 1
    for line in problems(tree):
        failures += 1
        print(f"VIOLATION: {line}")
    if failures:
        print(f"test_server_identity_uri_lexical: FAILED ({failures})")
        return 1
    print(f"test_server_identity_uri_lexical: OK ({len(tree)} files scanned)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
