#!/usr/bin/env python3
"""check-docs-drift.py - code-to-documentation drift gate (docs/docs-drift-gate.md).

Two layers, one script:

1. FACT PARITY (hermetic, default mode). Extracts facts an operator or an
   agentic worker relies on from the code and asserts the owning user-manual
   doc names each one:

     rest_undocumented  every /api/vN/ route registration has a heading
                        `#### \\`METHOD /api/vN/...\\`` in docs/user-manual/rest-api.md
     rest_stale         every such heading names a route that still exists
     mcp_undocumented   every kTools[] entry is named (backticked) in
                        docs/user-manual/mcp.md
     flag_undocumented  every server/agent CLI flag appears somewhere under
                        docs/user-manual/

   Route and tool extraction is NOT re-implemented here: it reuses
   scripts/ci/check-api-parity.py's extractors (extract_all_routes,
   extract_mcp_tools, canonicalize), so the two gates can never disagree about
   what the route table or tool table contains. Like that script this is a
   LEXICAL TRIPWIRE, not a proof - it sees what the regexes see.

   RATCHET: known gaps are listed BY NAME in scripts/ci/docs-drift-baseline.json.
   A gap not in the baseline fails (new drift). A baseline entry that is no
   longer a gap also fails, so the baseline can only shrink as docs are fixed:
   delete the entry in the same change. A named set rather than a count means
   fixing one old gap can never hide a new one. `--write-baseline` rewrites the
   file from the current tree but refuses to ADD entries without
   `--allow-growth`, so growing the baseline is always a visible, deliberate
   diff to that file.

   The same mode also self-checks the touch manifest (below): every rule id is
   unique, every code glob matches at least one file, every named doc exists,
   and no glob reaches agents/plugins/*/src/** (the plugin README touch rule,
   scripts/ci/check-plugin-readme-touch.sh, owns those paths).

2. TOUCH RULE (`--touch BASE HEAD [PR_BODY_FILE]`). scripts/ci/doc-coupling.json maps
   code globs to the docs that describe them. If a PR changes a file matching a
   rule's `code` globs and none of that rule's `docs`, it fails unless the PR
   body carries, per unmet rule, a line

       doc-coupling-exempt: <rule-id> — <reason>

   so the reviewer sees the claim rather than a silent omission. The keyword is
   deliberately NOT the plugin rule's `docs-unchanged:` - that script accepts
   any such line as a global override, so sharing the keyword would let one
   exemption silently satisfy both gates. Lines inside fenced code blocks or
   HTML comments do not count (they do not render), matching the plugin rule's
   parser. Co-change is what this layer measures, not correctness; the fact
   layer and the docs-writer governance agent cover the rest.

Usage (every form also accepts a leading `--root DIR`: check that tree, read
as data only; the extractor code always comes from this script's own tree):
  check-docs-drift.py                           fact parity + manifest self-check
  check-docs-drift.py --list                    print every current gap (worklist), exit 0
  check-docs-drift.py --write-baseline [--allow-growth]
  check-docs-drift.py --touch BASE HEAD [PR_BODY_FILE]

Exit: 0 ok, 1 drift / rule violated / cannot evaluate (fail closed), 2 usage.
Stdlib only. Self-test: tests/test_docs_drift_selftest.py.
"""
from __future__ import annotations

import importlib.util
import json
import re
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
# The extractor is ALWAYS the copy beside this file, never the --root tree's:
# --root names a tree to read as DATA, and the PR hook relies on that to check
# a worktree without executing any code from it.
PARITY_SCRIPT = HERE / "check-api-parity.py"
USER_MANUAL = "docs/user-manual"
REST_DOC = "docs/user-manual/rest-api.md"
MCP_DOC = "docs/user-manual/mcp.md"
BASELINE_REL = "scripts/ci/docs-drift-baseline.json"
MANIFEST_REL = "scripts/ci/doc-coupling.json"
BASELINE = ROOT / BASELINE_REL
MANIFEST = ROOT / MANIFEST_REL

# Files whose CLI11 add_option/add_flag calls define a binary's flags. A new
# options header must be added here or its flags go unchecked.
FLAG_SOURCES = (
    "server/core/src/main.cpp",
    "server/core/src/server_ota_options.hpp",
    "server/core/src/server_gateway_peer_options.hpp",
    "agents/core/src/main.cpp",
)

# Every file read from a tree is a regular file inside it, at most this big:
# under --root the tree is untrusted, and a symlink to /dev/zero or a FIFO
# must fail the run, not exhaust memory or hang it.
MAX_READ_BYTES = 16 * 1024 * 1024
# Applied to every git call: a tree's own .git/config must not run anything.
GIT_SAFE = ("-c", "core.fsmonitor=false", "-c", "core.hooksPath=/dev/null")

# Fail closed below these extraction counts (about half of the October 2026
# tree). A broken extractor otherwise reads as "nothing undocumented", which
# the ratchet cannot see once a category's baseline has reached zero.
MIN_EXTRACTED = {"routes": 120, "tools": 90, "flags": 60}

CATEGORIES = ("rest_undocumented", "rest_stale", "mcp_undocumented", "flag_undocumented")

FIX_HINT = {
    "rest_undocumented": "add a heading of the form #### `METHOD /api/vN/path` to docs/user-manual/rest-api.md",
    "rest_stale": "the route no longer exists - remove or correct its heading in docs/user-manual/rest-api.md",
    "mcp_undocumented": "describe the tool (backticked name) in docs/user-manual/mcp.md",
    "flag_undocumented": "document the flag in the owning docs/user-manual/ page (server-admin.md for server flags)",
}

PLUGIN_SRC = re.compile(r"^agents/plugins/[^/]+/src/")
EXEMPT_KEYWORD = "doc-coupling-exempt"


# ── Extraction ────────────────────────────────────────────────────────────

def read_tree_file(root, path):
    """Text of `path`, which must be a regular file resolving inside `root`
    and no bigger than MAX_READ_BYTES. Raises otherwise: fail closed."""
    root, path = Path(root).resolve(), Path(path)
    real = path.resolve()
    if real != root and root not in real.parents:
        raise ValueError(f"{path} resolves outside the tree")
    if not real.is_file():
        raise ValueError(f"{path} is not a regular file")
    if real.stat().st_size > MAX_READ_BYTES:
        raise ValueError(f"{path} is larger than {MAX_READ_BYTES} bytes")
    return real.read_text(encoding="utf-8")


def load_parity(root=ROOT):
    """check-api-parity.py's extractors, pointed at `root`'s sources. Its
    extract_all_routes / extract_mcp_tools read only these two globals."""
    spec = importlib.util.spec_from_file_location("check_api_parity", PARITY_SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    mod.SERVER_SRC = Path(root) / "server" / "core" / "src"
    mod.MCP_SERVER_CPP = mod.SERVER_SRC / "mcp_server.cpp"
    return mod


_DOC_PARAM = re.compile(r"<[^>/]+>|(?<=/):[A-Za-z_]\w*")


def normalize_doc_path(path, canonicalize):
    """A doc path in the `{id}` / `<id>` / `:id` styles, keyed the way
    check-api-parity keys a registered route. Trailing punctuation and a query
    string are prose, not path."""
    path = path.split("?", 1)[0].rstrip(".,;:)")
    return canonicalize(_DOC_PARAM.sub("{p}", path))


_METHOD = r"(?:GET|POST|PUT|DELETE|PATCH)"
_HEADING_ROUTE = re.compile(
    r"\b(" + _METHOD + r"(?:`?\s*[/,|]\s*`?\s*" + _METHOD + r")*)`?\s+`?(/api/v\d+/[^\s`]*)")


def doc_heading_routes(text, canonicalize):
    """{(METHOD, canonical path): line_no} for every route named in a heading.
    `GET`/`DELETE /api/v1/x` in one heading yields both methods."""
    out = {}
    in_fence = False
    for no, line in enumerate(text.splitlines(), 1):
        if line.lstrip().startswith(("```", "~~~")):
            in_fence = not in_fence
            continue
        if in_fence or not re.match(r"#{2,6} ", line):
            continue
        for m in _HEADING_ROUTE.finditer(line):
            path = normalize_doc_path(m.group(2), canonicalize)
            for method in re.findall(_METHOD, m.group(1)):
                out.setdefault((method, path), no)
    return out


_ADD_OPT = re.compile(r'add_(?:option|flag)\(\s*"([^"]+)"')


def extract_flags(sources):
    """{flag: source} for every `--long` name in a literal CLI11 name string,
    including the `!--no-x` negated form."""
    out = {}
    for rel, text in sources.items():
        for m in _ADD_OPT.finditer(text):
            for tok in m.group(1).split(","):
                tok = tok.strip().lstrip("!").split("{", 1)[0]
                if tok.startswith("--"):
                    out.setdefault(tok, rel)
    return out


def documented(token, text):
    return re.search(re.escape(token) + r"(?![\w-])", text) is not None


def compute_drift(code_routes, doc_routes, tools, mcp_text, flags, manual_text):
    """Pure: the current gap set per category, as sorted string lists."""
    return {
        "rest_undocumented": sorted(f"{m} {p}" for m, p in set(code_routes) - set(doc_routes)),
        "rest_stale": sorted(f"{m} {p}" for m, p in set(doc_routes) - set(code_routes)),
        "mcp_undocumented": sorted(t for t in tools if not documented(f"`{t}`", mcp_text)),
        "flag_undocumented": sorted(f for f in flags if not documented(f, manual_text)),
    }


def extraction_floor_errors(counts):
    return [f"only {counts[k]} {k} extracted (floor {MIN_EXTRACTED[k]}) - an extractor anchor "
            f"probably changed; fix the extractor, never lower the floor to pass"
            for k in MIN_EXTRACTED if counts[k] < MIN_EXTRACTED[k]]


def current_drift(root=ROOT):
    root = Path(root)
    parity = load_parity(root)
    # The extractors read these themselves, unbounded: vet them first.
    for f in [*sorted(parity.SERVER_SRC.glob("*.cpp")), parity.MCP_SERVER_CPP]:
        read_tree_file(root, f)
    _legacy, versioned = parity.extract_all_routes()
    # OPTIONS registrations are CORS preflight catch-alls, not endpoints.
    versioned = {k: v for k, v in versioned.items() if re.fullmatch(_METHOD, k[0])}
    doc_routes = doc_heading_routes(read_tree_file(root, root / REST_DOC), parity.canonicalize)
    tools = parity.extract_mcp_tools()
    manual = "\n".join(read_tree_file(root, p) for p in sorted((root / USER_MANUAL).glob("*.md")))
    flags = extract_flags({rel: read_tree_file(root, root / rel) for rel in FLAG_SOURCES})
    floors = extraction_floor_errors({"routes": len(versioned), "tools": len(tools), "flags": len(flags)})
    if floors:
        raise RuntimeError("; ".join(floors))
    return compute_drift(versioned, doc_routes, tools, read_tree_file(root, root / MCP_DOC),
                         flags, manual)


# ── Ratchet ───────────────────────────────────────────────────────────────

def load_baseline(path):
    data = json.loads(read_tree_file(Path(path).parents[2], path))
    return {c: set(data.get(c, [])) for c in CATEGORIES}


def ratchet_errors(drift, baseline):
    errors = []
    for cat in CATEGORIES:
        now, known = set(drift[cat]), baseline[cat]
        for item in sorted(now - known):
            errors.append(f"new {cat}: {item} - {FIX_HINT[cat]}")
        for item in sorted(known - now):
            errors.append(f"fixed {cat}: {item} - delete it from "
                          f"scripts/ci/docs-drift-baseline.json (the baseline only shrinks)")
    return errors


def write_baseline(path, drift, allow_growth):
    old = load_baseline(path) if path.exists() else {c: set() for c in CATEGORIES}
    grown = {c: sorted(set(drift[c]) - old[c]) for c in CATEGORIES}
    if not allow_growth and any(grown.values()):
        for c, items in grown.items():
            for i in items:
                print(f"check-docs-drift: would ADD {c}: {i}", file=sys.stderr)
        print("check-docs-drift: refusing to grow the baseline - document the gap instead, "
              "or pass --allow-growth and justify it in the PR", file=sys.stderr)
        return 1
    body = {"_comment": ("Known code-to-docs gaps, by name. Only ever SHRINKS: fix a gap, delete "
                         "its line. See docs/docs-drift-gate.md.")}
    body.update({c: sorted(drift[c]) for c in CATEGORIES})
    path.write_text(json.dumps(body, indent=2) + "\n", encoding="utf-8")
    print(f"check-docs-drift: wrote {path}")
    return 0


# ── Touch manifest ────────────────────────────────────────────────────────

def glob_to_regex(glob):
    """`**` any run including '/', `*` and `?` stay within a segment,
    `{a,b}` alternates. Anchored at both ends."""
    out, i = [], 0
    while i < len(glob):
        c = glob[i]
        if glob.startswith("**/", i):
            out.append("(?:.*/)?")
            i += 3
            continue
        if glob.startswith("**", i):
            out.append(".*")
            i += 2
            continue
        if c == "*":
            out.append("[^/]*")
        elif c == "?":
            out.append("[^/]")
        elif c == "{":
            j = glob.index("}", i)
            out.append("(?:" + "|".join(re.escape(a) for a in glob[i + 1:j].split(",")) + ")")
            i = j
        else:
            out.append(re.escape(c))
        i += 1
    return re.compile("^" + "".join(out) + "$")


def load_manifest(path):
    data = json.loads(read_tree_file(Path(path).parents[2], path))
    rules = []
    for r in data["rules"]:
        rules.append({"id": r["id"], "code": list(r["code"]), "docs": list(r["docs"]),
                      "_rx": [glob_to_regex(g) for g in r["code"]]})
    return rules


def manifest_errors(rules, files, exists):
    """files: every repo-relative path a glob may match. exists(rel) -> bool."""
    errors, seen = [], set()
    for r in rules:
        if r["id"] in seen:
            errors.append(f"doc-coupling: duplicate rule id {r['id']!r}")
        seen.add(r["id"])
        if not re.fullmatch(r"[a-z0-9][a-z0-9-]*", r["id"]):
            errors.append(f"doc-coupling: rule id {r['id']!r} must be kebab-case")
        if not r["docs"]:
            errors.append(f"doc-coupling: rule {r['id']!r} names no docs")
        for d in r["docs"]:
            if not exists(d):
                errors.append(f"doc-coupling: rule {r['id']!r} names missing doc {d}")
        for g, rx in zip(r["code"], r["_rx"]):
            hits = [f for f in files if rx.match(f)]
            if not hits:
                errors.append(f"doc-coupling: rule {r['id']!r} glob {g!r} matches no file (dead rule)")
            if any(PLUGIN_SRC.match(f) for f in hits):
                errors.append(f"doc-coupling: rule {r['id']!r} glob {g!r} reaches agents/plugins/*/src/ "
                              f"- the plugin README touch rule owns those paths")
    return errors


def repo_files(root=ROOT):
    out = subprocess.run(["git", *GIT_SAFE, "-C", str(root), "ls-files"], capture_output=True, text=True,
                         check=True).stdout
    return out.splitlines()


# ── Touch rule ────────────────────────────────────────────────────────────

def visible_lines(body):
    """Lines of a markdown body that render as plain text: fenced code blocks,
    HTML comments and anything inside raw HTML removed. A fence closes only on
    a run of the SAME character at least as long as its opener; a backtick
    opener's info string may not contain a backtick (CommonMark) - ported from
    check-plugin-readme-touch.sh. Raw HTML is dropped conservatively: a line
    opening an HTML block hides everything to the next blank line (to the
    closing tag for script/pre/style/textarea), and a tag left open at the end
    of a line hides following lines until one closes it - so an exemption in a
    multi-line attribute, which GitHub does not render, never counts."""
    out, fence, comment = [], None, False
    raw_end, html_block, open_tag = None, False, False
    for raw in body.replace("\r", "").split("\n"):
        t = re.sub(r"^[ \t]{0,3}", "", raw)
        m = re.match(r"(`{3,}|~{3,})(.*)$", t)
        is_fence = bool(m) and (m.group(1)[0] == "~" or "`" not in m.group(2))
        if fence:
            if is_fence and m.group(1)[0] == fence[0] and len(m.group(1)) >= len(fence) \
                    and not m.group(2).strip():
                fence = None
            continue
        if is_fence:
            fence = m.group(1)
            continue
        if raw_end:
            if raw_end.search(raw):
                raw_end = None
            continue
        if open_tag:
            open_tag = ">" not in raw
            continue
        if html_block:
            html_block = bool(raw.strip())
            continue
        if not comment:
            rb = re.match(r"<(script|pre|style|textarea)\b", t, re.I)
            if rb:
                end = re.compile(r"</" + rb.group(1) + r"\s*>", re.I)
                raw_end = None if end.search(t) else end
                continue
            if re.match(r"</?[A-Za-z]|<\?|<!(?!--)", t):
                html_block = True
                open_tag = re.search(r"<[A-Za-z][^>]*$", raw) is not None
                continue
        line = raw
        while True:
            if comment:
                i = line.find("-->")
                if i < 0:
                    line = None
                    break
                line, comment = line[i + 3:], False
            i = line.find("<!--")
            if i < 0:
                break
            j = line.find("-->", i + 4)
            if j < 0:
                line, comment = line[:i], True
                break
            line = line[:i] + line[j + 3:]
        if line is not None:
            if re.search(r"<[A-Za-z][^>]*$", line):
                open_tag = True
                line = line[:re.search(r"<[A-Za-z][^>]*$", line).start()]
            out.append(line)
    return out


_EXEMPT = re.compile(r"^\s*(?:[-*]\s+)?" + EXEMPT_KEYWORD +
                     r":\s*([a-z0-9][a-z0-9-]*)\s+(?:—|-)\s+(\S.*)$")


def exemptions(body):
    """{rule_id: reason} from visible `doc-coupling-exempt: <id> — <reason>` lines."""
    out = {}
    for line in visible_lines(body or ""):
        m = _EXEMPT.match(line)
        if m and len(m.group(2).strip()) >= 3:
            out.setdefault(m.group(1), m.group(2).strip())
    return out


def touch_check(changed, rules, body):
    """Pure. Returns (errors, notes)."""
    changed = set(changed)
    exempt = exemptions(body)
    errors, notes = [], []
    known = {r["id"] for r in rules}
    for rid in sorted(set(exempt) - known):
        notes.append(f"exemption names unknown rule {rid!r} - ignored")
    for r in rules:
        hits = sorted(f for f in changed if any(rx.match(f) for rx in r["_rx"]))
        if not hits:
            continue
        touched = sorted(d for d in r["docs"] if d in changed)
        if touched:
            notes.append(f"{r['id']}: code and docs both changed ({', '.join(touched)}) - ok")
        elif r["id"] in exempt:
            notes.append(f"{r['id']}: docs unchanged, exemption stated: {exempt[r['id']]}")
        else:
            shown = ", ".join(hits[:5]) + (f" (+{len(hits) - 5} more)" if len(hits) > 5 else "")
            errors.append(
                f"{r['id']}: {shown} changed but none of {', '.join(r['docs'])} did.\n"
                f"    Update the doc, or add to the PR body a line:\n"
                f"      {EXEMPT_KEYWORD}: {r['id']} — <why the docs are still accurate>")
    return errors, notes


def changed_files(base, head, root=ROOT):
    for ref in (base, head):
        if subprocess.run(["git", *GIT_SAFE, "-C", str(root), "cat-file", "-e", f"{ref}^{{commit}}"],
                          capture_output=True).returncode:
            raise RuntimeError(f"commit {ref} unavailable - cannot evaluate, failing closed")
    out = subprocess.run(["git", *GIT_SAFE, "-C", str(root), "diff", "--name-only", "--no-renames", base, head, "--"],
                         capture_output=True, text=True, check=True).stdout
    return [l for l in out.splitlines() if l]


# ── CLI ───────────────────────────────────────────────────────────────────

def run_facts(root=ROOT):
    root = Path(root)
    errors = []
    try:
        drift = current_drift(root)
        baseline = load_baseline(root / BASELINE_REL)
        errors += ratchet_errors(drift, baseline)
        rules = load_manifest(root / MANIFEST_REL)
        errors += manifest_errors(rules, repo_files(root), lambda rel: (root / rel).is_file())
    except Exception as e:  # an unreadable anchor is a red gate, never a silent pass
        print(f"check-docs-drift: cannot evaluate ({type(e).__name__}: {e}) - failing closed",
              file=sys.stderr)
        return 1
    for e in errors:
        print(f"check-docs-drift: {e}", file=sys.stderr)
    if errors:
        print(f"check-docs-drift: FAIL ({len(errors)} problem(s)) - see docs/docs-drift-gate.md",
              file=sys.stderr)
        return 1
    print("check-docs-drift: OK (" + ", ".join(f"{c} {len(drift[c])} == baseline"
                                              for c in CATEGORIES) + f"; {len(rules)} coupling rules)")
    return 0


def run_touch(base, head, body_file, root=ROOT):
    root = Path(root)
    try:
        rules = load_manifest(root / MANIFEST_REL)
        changed = changed_files(base, head, root)
        body = Path(body_file).read_text(encoding="utf-8", errors="replace") if body_file else ""
    except Exception as e:
        print(f"check-docs-drift --touch: {e}", file=sys.stderr)
        return 1
    errors, notes = touch_check(changed, rules, body)
    for n in notes:
        print(f"check-docs-drift --touch: {n}")
    for e in errors:
        print(f"check-docs-drift --touch: {e}", file=sys.stderr)
    if not errors and not notes:
        print("check-docs-drift --touch: no coupled code changed - nothing to enforce")
    return 1 if errors else 0


def main(argv):
    root = ROOT
    if len(argv) >= 2 and argv[0] == "--root":
        root, argv = Path(argv[1]).resolve(), argv[2:]
    if not argv:
        return run_facts(root)
    if argv[0] == "--list":
        for cat, items in current_drift(root).items():
            for i in items:
                print(f"{cat}\t{i}")
        return 0
    if argv[0] == "--write-baseline":
        return write_baseline(root / BASELINE_REL, current_drift(root), "--allow-growth" in argv[1:])
    if argv[0] == "--touch" and len(argv) in (3, 4):
        return run_touch(argv[1], argv[2], argv[3] if len(argv) == 4 else None, root)
    print(__doc__.split("Usage:", 1)[1].split("Exit:", 1)[0], file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
