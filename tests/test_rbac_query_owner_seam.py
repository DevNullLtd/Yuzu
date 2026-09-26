#!/usr/bin/env python3
"""ADR-0012 s3 tripwire for the RBAC cross-schema query owner (PR #4985).

ADR-0012 s3: per-store classes stay single-schema owners; cross-schema work is written by a
dedicated query owner that takes one lease. The last-Administrator guard needs grants
(`rbac_store`) and account state (`auth`) in one transaction, so its SQL lives ONLY in
`RbacAdminAuthorityOwner` (server/core/src/rbac_admin_authority_owner.cpp). This test fails
if either half of that seam regresses:

  1. `server/core/src/rbac_store.cpp` contains an `auth.`-schema reference inside a string
     literal (SQL). Comments are ignored, so prose that names `auth.users` is fine.
  2. `kAuthenticatableAdminGrantsFrom`, the one SQL fragment that defines "an authenticatable
     Administrator grant", is not defined exactly once under server/core/src, in the owner's
     translation unit. A second copy is the drift the fragment exists to remove.

It scans string literals only (a small tokenizer skips `//` and `/* */` comments), so a doc
comment cannot trip it. Wired into tests/meson.build (suite 'docs') and docs-lint.yml.
"""
import re
import subprocess
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
STORE = "server/core/src/rbac_store.cpp"
OWNER = "server/core/src/rbac_admin_authority_owner.cpp"
FRAGMENT = "kAuthenticatableAdminGrantsFrom"
FOREIGN = re.compile(r"\bauth\.[A-Za-z_]+", re.IGNORECASE)
DEFINITION = re.compile(r"\bconstexpr\b[^;=]*\b" + FRAGMENT + r"\s*=")


def tokenize(src: str):
    """Yield ("code" | "string", text) chunks; comments are dropped, char literals kept as code."""
    i, n = 0, len(src)
    code_start = 0
    out = []

    def flush(end):
        if end > code_start:
            out.append(("code", src[code_start:end]))

    while i < n:
        c = src[i]
        nxt = src[i + 1] if i + 1 < n else ""
        if c == "/" and nxt == "/":
            flush(i)
            j = src.find("\n", i)
            i = n if j == -1 else j
            code_start = i
        elif c == "/" and nxt == "*":
            flush(i)
            j = src.find("*/", i + 2)
            i = n if j == -1 else j + 2
            code_start = i
        elif c == "R" and nxt == '"':
            k = src.find("(", i + 2)
            delim = src[i + 2:k]
            end = src.find(")" + delim + '"', k + 1)
            if k == -1 or end == -1:
                i += 1
                continue
            flush(i)
            out.append(("string", src[k + 1:end]))
            i = end + len(delim) + 2
            code_start = i
        elif c == '"':
            flush(i)
            j = i + 1
            while j < n and src[j] != '"':
                j += 2 if src[j] == "\\" else 1
            out.append(("string", src[i + 1:j]))
            i = j + 1
            code_start = i
        elif c == "'":
            j = i + 1
            while j < n and src[j] != "'":
                j += 2 if src[j] == "\\" else 1
            i = j + 1
        else:
            i += 1
    flush(n)
    return out


def literals(src: str):
    return [t for kind, t in tokenize(src) if kind == "string"]


def code(src: str) -> str:
    return "".join(t for kind, t in tokenize(src) if kind == "code")


def _selfcheck() -> None:
    # Explicit raises, not `assert`: python3 -O strips asserts.
    sample = (
        '// auth.users in a line comment\n'
        '/* auth.users in a block comment */\n'
        'const char* a = "SELECT 1 FROM auth.users";\n'
        'const char* b = R"sql(SELECT * FROM auth.users u)sql";\n'
        'const char* c = "https://example.test/x"; // auth.users trailing\n'
        'int rbac = 1; // rbac_store.principal_roles is fine\n'
    )
    lits = literals(sample)
    hits = [s for s in lits if FOREIGN.search(s)]
    if len(hits) != 2:
        raise SystemExit(f"selfcheck: expected 2 auth. literals, got {hits!r}")
    if any("comment" in s for s in lits):
        raise SystemExit("selfcheck: a comment leaked into the literal set")
    if FOREIGN.search(code(sample)):
        raise SystemExit("selfcheck: auth. leaked into the code (non-literal) stream")
    d = 'constexpr std::string_view ' + FRAGMENT + ' =\n    "FROM x";\n'
    if len(DEFINITION.findall(code(d))) != 1:
        raise SystemExit("selfcheck: definition pattern failed to match a definition")
    use = "auto s = std::string(" + FRAGMENT + ");\n"
    if DEFINITION.search(code(use)):
        raise SystemExit("selfcheck: definition pattern wrongly matched a use")
    if DEFINITION.search(code("// constexpr " + FRAGMENT + " = 1;\n")):
        raise SystemExit("selfcheck: definition pattern wrongly matched a comment")


def main() -> int:
    _selfcheck()
    failures = []

    store = (REPO_ROOT / STORE).read_text(encoding="utf-8", errors="replace")
    for lit in literals(store):
        m = FOREIGN.search(lit)
        if m:
            failures.append(
                f"{STORE}: string literal references the auth schema ({m.group(0)!r}); "
                f"cross-schema SQL belongs in {OWNER} (ADR-0012 s3)"
            )

    files = subprocess.run(
        ["git", "ls-files", "--", "server/core/src"],
        cwd=REPO_ROOT, capture_output=True, text=True, check=True,
    ).stdout.splitlines()
    defs = []
    for rel in files:
        if not rel.endswith((".cpp", ".hpp", ".h", ".cc")):
            continue
        text = (REPO_ROOT / rel).read_text(encoding="utf-8", errors="replace")
        for _ in DEFINITION.findall(code(text)):
            defs.append(rel)
    if defs != [OWNER]:
        failures.append(
            f"{FRAGMENT} must be defined exactly once, in {OWNER}; found {defs!r}"
        )

    if failures:
        print("FAIL: the RBAC cross-schema query-owner seam regressed (ADR-0012 s3):")
        print("\n".join("  " + f for f in failures))
        return 1
    print(f"OK: no auth. SQL in {STORE}; {FRAGMENT} defined once, in {OWNER}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
