#!/usr/bin/env python3
"""check-api-parity.py - F1 ledger conformance gate for the ADR-0031/#2146
REST/MCP/dashboard parity programme (issue #3991).

ADR-0031 INV-31-4 requires that every capability the dashboard exposes is
also reachable through the versioned REST API (and, per ADR-1005, through
MCP). Nobody has ever verified this mechanically: `openapi_spec()`
(server/core/src/rest_api_v1.cpp) is a hand-typed literal that the file's
own comment admits can under-report the live route table. This script is
the machine-checked backstop `docs/adr/0031-presentation-core-engine-
decomposition.md` calls "a deliverable of migration step 3" (INV-31-4) and
the unit-test half's sibling - `tests/unit/server/
test_openapi_spec_completeness.cpp` covers the in-process half for
`rest_api_v1.cpp` alone; this script is the exhaustive, whole-tree half.

WHAT THIS IS: a LEXICAL TRIPWIRE, NOT A PROOF. It regex-extracts route
registrations, the OpenAPI literal, and the MCP tool table as plain text -
it does not parse C++ and cannot see through indirection (a route
registered via a helper function that itself calls `sink.Get(...)`, a path
built from a runtime variable, a tool added through anything other than a
`kTools[]` array literal). A fully general version needs a type-aware /
clang-based approach - see #2572, which is the type-aware successor to the
sibling `scripts/ci/check-inline-route-registrations.py` lexical gate this
script's technique is modeled on (same general approach - regex extraction
+ a monotonic ratchet baseline - applied to a different question: REST/MCP/
OpenAPI/fragment parity, not inline-vs-sink route registration style).

FUTURE HOME: this ledger + gate is a deliberate STOPGAP. ADR-0032 interlock
(j) / issue #2678 will eventually generate the capability projection this
script hand-extracts; when that lands, this script becomes (or is replaced
by) the diff harness that compares the generated projection against the
served surface, rather than parsing source text by hand. Nothing here
competes with that work - see docs/api-parity-ledger.md's prose header.

WHAT IT CHECKS
  1. Every `/fragments/*` or unversioned `/api/*` route registered anywhere
     under server/core/src/*.cpp has a corresponding row in exactly one
     scripts/ci/api-parity/<domain>.json ledger file, keyed by (method,
     canonical path - see `canonicalize()`).
  2. Every ledger row whose status is "twinned" names a `rest_v1_twin`
     and/or `mcp_twin` that actually exists in the CURRENT extraction (a
     twin claim referencing a renamed/removed route or tool is a lie, and
     this catches it going stale).
  3. Every registered `/api/v1/*` route either appears in the OpenAPI
     `paths` table (openapi_spec() in rest_api_v1.cpp) or is named in this
     script's ALLOWLIST_OPENAPI_MISSING with a reason. F2's job is to
     shrink that allowlist to zero, not to add to it.
  4. The RATCHET: the total count of ledger rows whose status is not
     "twinned" ("untwinned") must not exceed BASELINE_UNTWINNED below. Like
     check-capability-matrix.sh's ratchet, this is BIDIRECTIONAL - an
     improvement (count decreases) must lower the constant in the same
     change, or a later regression back up to the old baseline would pass
     silently.

USAGE
  check-api-parity.py                    # run the full gate (CI mode)
  check-api-parity.py --dump-json        # dump raw extraction as JSON (debug)
  check-api-parity.py --bootstrap        # add default rows for any
                                          # unledgered fragment/legacy route
                                          # (planned:#2146, both twins null)
                                          # to the right domain file
  check-api-parity.py --baseline-inventory
                                          # print current vs baseline counts
                                          # without failing - use when
                                          # preparing to lower a baseline
"""
import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SERVER_SRC = ROOT / "server" / "core" / "src"
LEDGER_DIR = ROOT / "scripts" / "ci" / "api-parity"
REST_API_V1_CPP = SERVER_SRC / "rest_api_v1.cpp"
MCP_SERVER_CPP = SERVER_SRC / "mcp_server.cpp"
LEDGER_DOC = ROOT / "docs" / "api-parity-ledger.md"

DOC_BEGIN = ("<!-- BEGIN GENERATED: check-api-parity.py - do not hand-edit; "
             "regenerate with `python3 scripts/ci/check-api-parity.py "
             "--render-doc` and splice between these markers -->")
DOC_END = "<!-- END GENERATED -->"

VERBS = ("Get", "Post", "Put", "Delete", "Patch", "Options")

# ── RATCHET BASELINE ─────────────────────────────────────────────────────
# Total ledger rows (across every scripts/ci/api-parity/*.json file) whose
# status is NOT EXACTLY "twinned" - i.e. every "planned:#N", "exception:...",
# "composed-of:...", and "retire" row counts as untwinned. This baseline
# therefore has a floor above zero for as long as any row legitimately
# carries one of those non-"twinned" statuses (a `composed-of` or
# `exception` row is never expected to flip to "twinned" - it is a
# deliberate, reviewed classification, not a backlog item) - "0 untwinned"
# is not this gate's success criterion, "no regression from the reviewed
# baseline" is. May SHRINK as F2+ wires real REST/MCP twins and flips
# `planned` rows to "twinned". May also GROW, but ONLY for a reviewed reason
# stated in the same change that raises it - either a genuinely new route
# just registered, or (as in the #3991 fix that took this from 189 to 265)
# extraction-completeness catching up to a route that already existed but
# was previously invisible to the lexical scan; growth from a silent
# regression in the check itself is never legitimate. Lower (or, with a
# stated reason, raise) this in the SAME change that changes the real count -
# see check-capability-matrix.sh's CDX-P2-006 comment for why an un-adjusted
# baseline is not a real ratchet.
#
# #4035 (DEX read-twin batch, #2146 API-parity Batch A) flips most of the
# dex domain's rows from "planned:#2146" to "twinned" (2 device-status
# tools plus 8 genuinely-new REST+MCP twins), on top of origin/dev's own
# already-merged #4027/#4028/#4029/#4030/#4031/#4033/#4034 twins (237) --
# reconciled post-merge against the actual measured count below, not
# hand-added from either side's stale pre-merge value.
#
# #4036 (preflight/deploy read-twin batch) flips 2 more rows to "twinned"
# on top of origin/dev's 221 -- reconciled post-merge against the actual
# measured count, not hand-added.
#
# #4037 (api-parity #2146 Batch A): six guardian.json rows flip to "twinned"
# (get.fragments-device-guardian, get.fragments-guardian-events, get.fragments-
# guardian-guard-form, get.fragments-guardian-guard-param-page, get.fragments-
# guardian-guards, get.fragments-guardian-status) on top of origin/dev's 219 --
# reconciled post-merge against the actual measured count, not hand-added.
#
# #2146 Batch B2: seven rows flip to "twinned" -- post.api-scope-validate
# (mcp_twin: validate_scope) and six result-set fragment rows (mcp_twin:
# list_result_sets/create_result_set/get_result_set/delete_result_set/
# pin_result_set/unpin_result_set) -- on top of the prior 213, measured after
# the flip, not hand-added.
#
# feat/hardware-ci-view (governance Gate 3): +5 unledgered fragment routes
# bootstrapped (get.fragments-hardware-{list,ci,ci/actions,ci/result},
# get.fragments-inventory-software-devices); 2 immediately wired to their real
# REST v1 twins and flipped to "twinned" (hardware-list -> GET /api/v1/hardware,
# hardware-ci -> GET /api/v1/hardware/{id}); the remaining 3 have no REST/MCP
# twin yet (hardware-ci/actions, hardware-ci/result -- same "planned:#2146"
# class as the pre-existing device-live/run and device-live/result rows they
# sit alongside; inventory-software-devices -- a fleet-wide software search
# fragment with no REST twin proposed yet) -- net +3 untwinned, 206 -> 209.
#
# #2146 A2-R1 (merged into dev's 209 by the #4581-region dev-catch-up merge):
# get.api-executions-param-children flipped planned:#2146 -> twinned (GET
# /api/v1/executions/{id}/children + MCP get_execution_children) -- value
# below reconciled post-merge against the actual measured count (208), not
# hand-picked from either side's stale pre-merge number (212 vs 209).
#
# #2146 A2-R2 (merged into dev's 208 as #4652): response-query REST v1 + MCP
# twins land, flipping three legacy rows in scripts/ci/api-parity/other.json
# (GET /api/responses/{param}, .../aggregate, .../export) to "twinned"
# against the new /api/v1/responses/{id}, .../aggregate, .../export routes
# + their MCP twins (query_responses, aggregate_responses; export has no
# MCP twin) -- measured post-build at 205 (208 - 3), not hand-picked.
#
# #2146 A2-R4 (this dev-catch-up merge, on top of dev's 205): approval-review
# REST v1/MCP parity flips 2 other.json rows to "twinned" (GET /api/approvals
# -> GET /api/v1/approvals + list_pending_approvals; GET
# /api/approvals/pending/count -> GET /api/v1/approvals/pending/count +
# get_pending_approval_count) -- measured post-build at 203 (205 - 2), not
# hand-picked.
BASELINE_UNTWINNED = 203

# ── OpenAPI-missing allowlist (seed for F2) ──────────────────────────────
# Every /api/v1/* route registered today that has no OpenAPI `paths` entry.
# F2's job is to backfill openapi_spec() until this list is empty - it must
# only ever SHRINK. Each entry is [METHOD, canonical_path, reason].
ALLOWLIST_OPENAPI_MISSING = [
    # The 39-entry "F2 backlog" this list originally carried (device tokens,
    # license, sessions, agent plugin-policy, execution-statistics, the
    # result-sets/scope-walking cluster, software deployments/packages,
    # statistics/topology, and three misc singletons) was backfilled into
    # openapi_spec() by #3992 (merged to dev 2026-09-06) - see
    # changelog.d/3992-openapi-backfill.added.md. Removed here rather than
    # left stale, per this script's own "no stale allowlist entry" check.
    #
    # Blanket CORS preflight, not a discrete documentable capability - every
    # /api/v1/* path answers OPTIONS the same way (204, no body). Structural
    # exception, never an F2-style backlog item.
    ("OPTIONS", "/api/v1/{param}", "blanket CORS preflight handler (sink.Options(R\"(/api/v1/.*)\", ...)) - not a discrete capability, exempt from OpenAPI documentation"),
]

# ── Domain classification ────────────────────────────────────────────────
# Order matters - first match wins. Path-prefix rules are checked before
# the owner-file fallback, since several owner files (rest_api_v1.cpp,
# dashboard_routes.cpp) register routes across multiple domains.
DOMAINS = [
    "devices", "inventory", "dex", "guardian", "tar", "auto-preflight",
    "auto-deploy", "auto-verify", "network", "viz", "executions",
    "scope-result-sets", "instructions", "compliance-policy", "settings",
    "rbac", "auth-mfa", "engine-principals", "access-reviews", "ca-pki",
    "ota", "enrollment", "other",
]

PATH_DOMAIN_RULES = [
    (re.compile(r"^/(fragments/)?device/dex"), "dex"),
    (re.compile(r"^/(fragments/)?dex/"), "dex"),
    (re.compile(r"^/fragments/network/"), "network"),
    (re.compile(r"^/(fragments/)?device/guardian"), "guardian"),
    (re.compile(r"^/(fragments/)?guardian/"), "guardian"),
    (re.compile(r"^/(fragments/)?tar/"), "tar"),
    (re.compile(r"^/fragments/auto/preflight"), "auto-preflight"),
    (re.compile(r"^/fragments/auto/deploy"), "auto-deploy"),
    (re.compile(r"^/fragments/auto/verify"), "auto-verify"),
    (re.compile(r"^/(fragments/)?viz/"), "viz"),
    (re.compile(r"^/fragments/scope-list"), "scope-result-sets"),
    (re.compile(r"^/fragments/create-group-form"), "devices"),
    (re.compile(r"^/fragments/device"), "devices"),
    (re.compile(r"^/fragments/devices"), "devices"),
    (re.compile(r"^/fragments/results"), "executions"),
    (re.compile(r"^/api/dashboard/(execute|group-from-results|tar-execute)"), "executions"),
    (re.compile(r"^/fragments/compliance"), "compliance-policy"),
    (re.compile(r"^/api/(compliance|polic(y|ies))"), "compliance-policy"),
    # Settings sub-panels: several are administrative UI over a capability
    # that has its OWN domain elsewhere in this list. Route those to the
    # capability's domain, not to the generic "settings" catch-all, so the
    # ledger groups by what the row is FOR rather than which .cpp happens to
    # register it. Order matters - specific sub-panel rules before the
    # generic /api/settings|/fragments/settings fallback below.
    (re.compile(r"^/(api|fragments)/settings/ca\b"), "ca-pki"),
    (re.compile(r"^/(api|fragments)/settings/(mfa|oidc)\b"), "auth-mfa"),
    (re.compile(r"^/fragments/settings/access-reviews"), "access-reviews"),
    (re.compile(r"^/fragments/settings/engine-principals"), "engine-principals"),
    (re.compile(r"^/(api|fragments)/settings/(users|api-tokens|tokens)\b"), "rbac"),
    (re.compile(r"^/(api|fragments)/settings/(pending-agents|pending|enrollment-tokens|auto-approve|directory)\b"), "enrollment"),
    (re.compile(r"^/(api|fragments)/settings/updates"), "ota"),
    (re.compile(r"^/(api|fragments)/settings/dex-alerts"), "dex"),
    (re.compile(r"^/fragments/settings/(nvd|tag-compliance)"), "compliance-policy"),
    (re.compile(r"^/(api|fragments)/settings/management-groups"), "devices"),
    (re.compile(r"^/(api|fragments)/settings"), "settings"),
    (re.compile(r"^/api/notifications"), "other"),
    (re.compile(r"^/api/webhooks"), "other"),
    (re.compile(r"^/api/workflow"), "instructions"),
    (re.compile(r"^/api/instructions"), "instructions"),
    (re.compile(r"^/api/product-packs"), "instructions"),
    (re.compile(r"^/api/patches/deployments"), "ota"),
    (re.compile(r"^/api/deployment-jobs"), "ota"),
    (re.compile(r"^/api/directory"), "enrollment"),
    (re.compile(r"^/api/help"), "other"),
]

OWNER_FILE_DOMAIN_FALLBACK = {
    "device_routes.cpp": "devices",
    "hardware_routes.cpp": "devices", # Hardware is THE device surface (round-3 plan) — /devices and
                                       # /device?id= 302-redirect here; same domain as device_routes.cpp.
    "device_ui.cpp": "devices",
    "inventory_routes.cpp": "inventory",
    "dex_routes.cpp": "dex",
    "dex_perf_ui.cpp": "dex",
    "dex_app_perf_ui.cpp": "dex",
    "guardian_routes.cpp": "guardian",
    "tar_tree_routes.cpp": "tar",
    "preflight_routes.cpp": "auto-preflight",
    "deployment_routes.cpp": "auto-deploy",
    "deployment_ui.cpp": "auto-deploy",
    "verify_routes.cpp": "auto-verify",
    "network_routes.cpp": "network",
    "viz_routes.cpp": "viz",
    "workflow_routes.cpp": "instructions",
    "compliance_routes.cpp": "compliance-policy",
    "compliance_ui.cpp": "compliance-policy",
    "settings_routes.cpp": "settings",
    "auth_routes.cpp": "auth-mfa",
    "ca_routes.cpp": "ca-pki",
    "kek_routes.cpp": "ca-pki",
    "discovery_routes.cpp": "ota",
    "offload_routes.cpp": "ota",
    "file_retrieval_routes.cpp": "other",
    "plugin_config_routes.cpp": "settings",
    "webhook_routes.cpp": "other",
    "notification_routes.cpp": "other",
    "dashboard_routes.cpp": "executions",
    "dashboard_ui.cpp": "other",
    "rest_api_v1.cpp": "other",
}


def gh(kind, msg):
    # stderr, not stdout - --dump-json/--baseline-inventory print machine-
    # readable output to stdout and must stay uncontaminated by warnings.
    print(f"::{kind}::{msg}", file=sys.stderr, flush=True)


# ── Lexical helpers ──────────────────────────────────────────────────────

_FULL_LINE_COMMENT = re.compile(r"^[ \t]*//.*$", re.MULTILINE)


def strip_full_line_comments(text):
    """Blank out lines whose first non-whitespace token is `//`. Does NOT
    touch inline trailing comments (raw strings embed `https://` mid-line,
    which a naive inline-comment stripper would corrupt) - see module
    docstring / #3991 design notes."""
    return _FULL_LINE_COMMENT.sub("", text)


def parse_literal_at(text, pos):
    """If a C++ string or raw-string literal starts at/after `pos` (skipping
    only whitespace), return (content, end_pos). Otherwise return (None,
    pos) unchanged - caller decides what "not a literal" means."""
    i = pos
    n = len(text)
    while i < n and text[i] in " \t\r\n":
        i += 1
    if i >= n:
        return None, pos
    if text[i] == '"':
        j = i + 1
        buf = []
        while j < n and text[j] != '"':
            if text[j] == "\\" and j + 1 < n:
                buf.append(text[j + 1])
                j += 2
            else:
                buf.append(text[j])
                j += 1
        return "".join(buf), j + 1
    if text[i] == "R" and i + 1 < n and text[i + 1] == '"':
        j = i + 2
        delim_end = text.index("(", j)
        delim = text[j:delim_end]
        terminator = ")" + delim + '"'
        end = text.index(terminator, delim_end + 1)
        return text[delim_end + 1:end], end + len(terminator)
    return None, pos


def parse_adjacent_literals(text, pos):
    """Like `parse_literal_at`, but concatenates every C++ string/raw-string
    literal that is ADJACENT to the first - i.e. separated only by
    whitespace and/or full-line `//` comments - per ordinary C++ adjacent-
    string-literal concatenation (`"/api/v1" "/route"` is one string,
    `/api/v1/route`, at compile time). Mirrors the chunk-concatenation loop
    `extract_openapi_paths()` already needs for the MSVC-16KB-split case;
    without this, a route registration split across two adjacent literals
    (the natural place a human wraps a long path - at a version-prefix
    boundary, exactly like the existing split convention this script's own
    module docstring documents for the OpenAPI literal) silently truncates
    to the first chunk instead of erroring or warning, and a truncated path
    like "/api/v1" satisfies neither ledger bucket in `extract_all_routes`
    and is dropped with no requirement and no `::warning::` at all."""
    literal, end = parse_literal_at(text, pos)
    if literal is None:
        return None, pos
    parts = [literal]
    n = len(text)
    while True:
        i = end
        while i < n and text[i] in " \t\r\n":
            i += 1
        if text[i:i + 2] == "//":
            eol = text.index("\n", i)
            i = eol + 1
            while i < n and text[i] in " \t\r\n":
                i += 1
        nxt, nxt_end = parse_literal_at(text, i)
        if nxt is None:
            break
        parts.append(nxt)
        end = nxt_end
    return "".join(parts), end


_VERB_CALL = re.compile(r"\b(\w+)(?:\.|->)(" + "|".join(VERBS) + r")\s*\(")

# httplib::Client call sites (directory_sync.cpp, analytics_sinks.cpp,
# nvd_client.cpp, offload_target_store.cpp, webhook_store.cpp, oidc_provider.cpp,
# settings_routes.cpp - all outbound HTTP clients, never route registrations)
# always pass a runtime variable as their first argument, by construction -
# fetching a caller-supplied URL is the entire point of an httplib::Client.
# These receiver names are the verified, complete false-positive set (grepped
# across the whole tree at #3991-time, both `.` and `->` forms - see
# docs/architecture.md "Route Registration" for why the receiver-agnostic
# `(\.|->)` pattern is required at all: a dot-only grep silently missed
# server.cpp's ~107 `web_server_->{Get,Post,...}(` inline registrations, the
# exact false negative #2542 already documented once); a verb call through
# any OTHER receiver with no literal first argument is unexpected and still
# warns loudly below rather than being silently dropped.
_KNOWN_CLIENT_RECEIVERS = {"cli", "client"}


def extract_verb_calls(text, path):
    """Yields (method, raw_path_literal) for every `<receiver>.<Verb>(` call
    whose first argument is a string/raw-string literal starting with '/'.
    A call whose first argument is not a literal is reported via stderr WARN
    (never silently dropped) UNLESS the receiver is a known httplib::Client
    variable name (see `_KNOWN_CLIENT_RECEIVERS`) - route-registration sinks
    (`sink`, `svr`, and any future receiver name) always warn loudly on a
    non-literal first argument, since that would be a real extraction gap."""
    for m in _VERB_CALL.finditer(text):
        receiver = m.group(1)
        method = m.group(2).upper()
        literal, _end = parse_adjacent_literals(text, m.end())
        if literal is None:
            if receiver in _KNOWN_CLIENT_RECEIVERS:
                continue
            line = text.count("\n", 0, m.start()) + 1
            gh("warning",
               f"check-api-parity: {path}:{line}: verb call with no literal "
               f"first argument (skipped) - {text[m.start():m.start()+60]!r}")
            continue
        if not literal.startswith("/"):
            continue
        yield method, literal


def _mask_paren_groups(path):
    """Replace every balanced (...) run with a single NUL marker byte, so a
    capture group's own internal '/' (extremely common here - '([^/]+)' is
    the majority pattern) never causes a wrong path-segment split below.
    Handles nesting (depth-tracked) even though none of today's patterns
    nest; nothing in the char class or literal text outside parens is
    touched."""
    out = []
    depth = 0
    for ch in path:
        if ch == "(":
            if depth == 0:
                out.append("\x00")
            depth += 1
        elif ch == ")":
            depth = max(0, depth - 1)
        elif depth == 0:
            out.append(ch)
    return "".join(out)


def canonicalize(path):
    """Collapse a regex-capture-group segment (registered routes) or a
    '{param}'-style segment (OpenAPI) into a single '{param}' token, so the
    two sides - and a route whose capture charset changes over time - key
    identically. See module docstring point 1. Splits on the PAREN-MASKED
    text (see `_mask_paren_groups`) so a capture group like '([^/]+)' - the
    majority pattern in this codebase - doesn't get sliced by its own
    internal '/'."""
    segs = _mask_paren_groups(path).split("/")
    out = []
    for seg in segs:
        if seg == "":
            out.append(seg)
            continue
        if re.fullmatch(r"\{[^{}]*\}", seg):
            out.append("{param}")
        elif "\x00" in seg or re.search(r"[\[\]*+?|\\]", seg):
            out.append("{param}")
        else:
            out.append(seg)
    return "/".join(out)


def classify_domain(canonical_path, owner_file):
    for rx, domain in PATH_DOMAIN_RULES:
        if rx.match(canonical_path):
            return domain
    return OWNER_FILE_DOMAIN_FALLBACK.get(owner_file, "other")


# ── Extraction ────────────────────────────────────────────────────────────

def extract_all_routes():
    """Returns (bucket_a, bucket_b): each a dict {(method, canonical_path):
    [(owner_file, raw_path), ...]} - fragments/legacy-api and versioned
    /api/vN/* registrations respectively, across every server/core/src/*.cpp
    file. bucket_b covers every /api/vN/ generation (v1, and #4144's v2 -
    the repo's first breaking-change route, docs/api-versioning-policy.md) -
    each is OpenAPI-completeness-checked the same way; a version bump is not
    a new tracking mechanism, it is the SAME mechanism at a new prefix."""
    bucket_a = {}
    bucket_b = {}
    versioned_api_re = re.compile(r"^/api/v\d+/")
    for f in sorted(SERVER_SRC.glob("*.cpp")):
        text = strip_full_line_comments(f.read_text(encoding="utf-8"))
        for method, raw in extract_verb_calls(text, f.name):
            if versioned_api_re.match(raw):
                bucket = bucket_b
            elif raw.startswith("/fragments/") or (
                raw.startswith("/api/") and not versioned_api_re.match(raw)
            ):
                bucket = bucket_a
            else:
                continue
            canon = canonicalize(raw)
            bucket.setdefault((method, canon), []).append((f.name, raw))
    return bucket_a, bucket_b


def extract_openapi_paths():
    """Parses the openapi_spec() literal out of rest_api_v1.cpp (concatenated
    raw-string chunks, MSVC C2026 16KB-cap split - see the source comment
    at rest_api_v1.cpp:664) and returns the set of (METHOD, canonical "/api/
    v1"+path, or "/api/v2"+path for a path-item carrying a "/v2" server
    override - #4144, the repo's first breaking-change route) tuples in its
    `paths` table, plus the parsed spec dict."""
    text = REST_API_V1_CPP.read_text(encoding="utf-8")
    anchor = text.index("static const std::string spec =")
    pos = anchor + len("static const std::string spec =")
    chunks = []
    n = len(text)
    while True:
        i = pos
        while i < n and text[i] in " \t\r\n":
            i += 1
        # Skip a full C++ line comment between literal chunks.
        if text[i:i + 2] == "//":
            eol = text.index("\n", i)
            pos = eol + 1
            continue
        if text[i] == ";":
            pos = i + 1
            break
        literal, end = parse_literal_at(text, i)
        if literal is None:
            raise RuntimeError(
                f"check-api-parity: could not parse openapi_spec() literal "
                f"chunk at offset {i} (expected a string/raw-string literal "
                f"or ';')")
        chunks.append(literal)
        pos = end
    spec_json = "".join(chunks)
    spec = json.loads(spec_json)

    paths = set()
    methods = {"get": "GET", "post": "POST", "put": "PUT", "delete": "DELETE",
               "patch": "PATCH", "options": "OPTIONS"}
    for path, ops in spec.get("paths", {}).items():
        if not isinstance(ops, dict):
            continue
        # A path-item's own "servers" override (OpenAPI 3.0.3 SS4.7.9.2) means
        # it resolves against a DIFFERENT base than the top-level "/api/v1"
        # servers[] entry - #4144's v2 route is the only one today, keyed
        # "/v2/..." precisely so this is a literal-prefix strip, not a guess.
        base = "/api/v1"
        servers = ops.get("servers")
        if isinstance(servers, list) and servers and path.startswith("/v2/"):
            base = "/api/v2"
            path = path[len("/v2"):]
        for m_lower, m_upper in methods.items():
            if m_lower in ops:
                paths.add((m_upper, canonicalize(base + path)))
    return paths, spec


_TOOLDEF_ENTRY = re.compile(r'^\s{4}\{"([A-Za-z0-9_]+)"', re.MULTILINE)


def extract_mcp_tools():
    text = MCP_SERVER_CPP.read_text(encoding="utf-8")
    start = text.index("static const ToolDef kTools[] = {")
    # Matching closing "};" at column 0, mirroring the array's own style.
    end = text.index("\n};", start)
    body = text[start:end]
    return set(_TOOLDEF_ENTRY.findall(body))


def all_ref_targets(node, out):
    """Walk the ENTIRE OpenAPI doc (not just literal `$ref` keys) collecting
    every string value that starts with '#/' - `discriminator.mapping`
    values are refs too (see rest_api_v1.cpp:713-717) and a naive
    '$ref'-key-only walk misses them."""
    if isinstance(node, dict):
        for k, v in node.items():
            if isinstance(v, str) and v.startswith("#/"):
                out.add(v)
            else:
                all_ref_targets(v, out)
    elif isinstance(node, list):
        for v in node:
            all_ref_targets(v, out)


def resolve_ref(spec, ref):
    parts = ref.lstrip("#/").split("/")
    node = spec
    for p in parts:
        if not isinstance(node, dict) or p not in node:
            return False
        node = node[p]
    return True


# ── Ledger I/O ────────────────────────────────────────────────────────────

STATUS_RE = re.compile(
    r"^(twinned|retire|planned:#\d+|composed-of:[A-Za-z0-9_.:,\-]+|exception:.+)$"
)


def ledger_files():
    return sorted(LEDGER_DIR.glob("*.json"))


def load_ledger():
    """Returns (rows, errors): rows is {(method, canonical_path): row_dict
    with '_domain' and '_file' added}; errors is a list of strings for
    malformed ledger content (duplicate key, bad status, etc.)."""
    rows = {}
    errors = []
    for f in ledger_files():
        domain = f.stem
        if domain not in DOMAINS:
            errors.append(f"{f}: filename '{domain}.json' is not one of the "
                           f"declared domains {DOMAINS}")
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
        except json.JSONDecodeError as e:
            errors.append(f"{f}: invalid JSON ({e})")
            continue
        if not isinstance(data, list):
            errors.append(f"{f}: top level must be a JSON array of rows")
            continue
        for idx, row in enumerate(data):
            missing = {"method", "path", "capability_id", "rest_v1_twin",
                       "mcp_twin", "status"} - row.keys()
            if missing:
                errors.append(f"{f}[{idx}]: missing field(s) {sorted(missing)}")
                continue
            if not STATUS_RE.match(row["status"]):
                errors.append(f"{f}[{idx}] ({row['method']} {row['path']}): "
                               f"invalid status {row['status']!r}")
            key = (row["method"], row["path"])
            if key in rows:
                errors.append(f"{f}[{idx}]: duplicate ledger key {key} "
                               f"(already defined in {rows[key]['_file']})")
                continue
            row = dict(row)
            row["_domain"] = domain
            row["_file"] = str(f)
            rows[key] = row
    return rows, errors


def capability_id_for(method, canonical_path):
    slug = re.sub(r"[^a-z0-9]+", "-", canonical_path.lower()).strip("-")
    return f"{method.lower()}.{slug}"


def bootstrap(bucket_a):
    rows, errors = load_ledger()
    if errors:
        for e in errors:
            gh("error", f"check-api-parity --bootstrap: refusing to write - "
                        f"existing ledger is malformed: {e}")
        return 1
    by_domain = {}
    added = 0
    for (method, canon), sources in bucket_a.items():
        if (method, canon) in rows:
            continue
        owner_file = sources[0][0]
        domain = classify_domain(canon, owner_file)
        by_domain.setdefault(domain, []).append({
            "method": method,
            "path": canon,
            "capability_id": capability_id_for(method, canon),
            "rest_v1_twin": None,
            "mcp_twin": None,
            "status": "planned:#2146",
        })
        added += 1
    for domain, new_rows in by_domain.items():
        f = LEDGER_DIR / f"{domain}.json"
        existing = json.loads(f.read_text(encoding="utf-8")) if f.exists() else []
        existing.extend(new_rows)
        existing.sort(key=lambda r: (r["path"], r["method"]))
        f.write_text(json.dumps(existing, indent=2, sort_keys=False) + "\n",
                     encoding="utf-8")
        print(f"check-api-parity --bootstrap: {f}: +{len(new_rows)} row(s)")
    print(f"check-api-parity --bootstrap: {added} row(s) added total")
    return 0


# ── Checks ────────────────────────────────────────────────────────────────

def render_doc_block(ledger_rows, bucket_b, openapi_paths, allowlist_set, mcp_tools):
    """Renders the docs/api-parity-ledger.md generated block: per-domain row/
    twinned/untwinned counts plus the overall totals this gate enforces.
    Deterministic (domains sorted) so a re-render of unchanged data
    byte-matches - required for the freshness check in run_check()."""
    by_domain = {}
    for row in ledger_rows.values():
        d = by_domain.setdefault(row["_domain"], {"total": 0, "twinned": 0})
        d["total"] += 1
        if row["status"] == "twinned":
            d["twinned"] += 1

    lines = [DOC_BEGIN, ""]
    lines.append("| Domain | Rows | Twinned | Untwinned |")
    lines.append("|---|---:|---:|---:|")
    total_rows = 0
    total_twinned = 0
    for domain in DOMAINS:
        d = by_domain.get(domain, {"total": 0, "twinned": 0})
        untwinned = d["total"] - d["twinned"]
        total_rows += d["total"]
        total_twinned += d["twinned"]
        lines.append(f"| {domain} | {d['total']} | {d['twinned']} | {untwinned} |")
    total_untwinned = total_rows - total_twinned
    lines.append(f"| **Total** | **{total_rows}** | **{total_twinned}** | "
                 f"**{total_untwinned}** |")
    lines.append("")
    missing_openapi = len(set(bucket_b) - openapi_paths)
    lines.append(f"Registered `/api/vN/*` routes: {len(bucket_b)}. OpenAPI "
                 f"`paths` entries: {len(openapi_paths)}. Missing from "
                 f"OpenAPI: {missing_openapi} ({len(allowlist_set)} carried "
                 f"in `check-api-parity.py`'s `ALLOWLIST_OPENAPI_MISSING` "
                 f"pending F2, {missing_openapi - len(allowlist_set)} "
                 f"unallowlisted). MCP tools: {len(mcp_tools)}.")
    lines.append("")
    lines.append(f"Ratchet baseline (untwinned rows; shrinks as routes are "
                 f"twinned, or rises only with a reviewed reason stated in "
                 f"the change that raises it): {BASELINE_UNTWINNED}.")
    lines.append("")
    lines.append(DOC_END)
    return "\n".join(lines) + "\n"


def extract_doc_block(text):
    try:
        start = text.index(DOC_BEGIN)
        end = text.index(DOC_END, start) + len(DOC_END)
    except ValueError:
        return None
    return text[start:end] + "\n"


def render_doc():
    bucket_a, bucket_b = extract_all_routes()
    openapi_paths, _spec = extract_openapi_paths()
    mcp_tools = extract_mcp_tools()
    ledger_rows, errors = load_ledger()
    for e in errors:
        gh("warning", f"check-api-parity --render-doc: {e}")
    allowlist_set = {(m, canonicalize(p)) for m, p, _r in ALLOWLIST_OPENAPI_MISSING}
    print(render_doc_block(ledger_rows, bucket_b, openapi_paths, allowlist_set, mcp_tools))
    return 0


def run_check():
    bucket_a, bucket_b = extract_all_routes()
    openapi_paths, _spec = extract_openapi_paths()
    mcp_tools = extract_mcp_tools()
    ledger_rows, ledger_errors = load_ledger()

    ok = True
    for e in ledger_errors:
        gh("error", f"check-api-parity: {e}")
        ok = False

    # 1. every extracted fragment/legacy route must be ledgered.
    unledgered = sorted(set(bucket_a) - set(ledger_rows))
    for method, canon in unledgered:
        sources = bucket_a[(method, canon)]
        gh("error", f"check-api-parity: unledgered route {method} {canon} "
                    f"(registered in {sources[0][0]}) - add a row to "
                    f"scripts/ci/api-parity/<domain>.json")
        ok = False

    # 1b. stale ledger rows (route no longer registered) must be marked
    #     retire, not silently left twinned/planned against nothing.
    for key, row in ledger_rows.items():
        if key in bucket_a:
            continue
        if row["status"] != "retire":
            gh("error", f"check-api-parity: {row['_file']}: ledger row "
                        f"{key[0]} {key[1]} no longer matches any "
                        f"registered route - mark status \"retire\" or "
                        f"remove the row")
            ok = False

    # 2. twinned rows must reference twins that actually exist.
    all_extracted = set(bucket_a) | set(bucket_b)
    for key, row in ledger_rows.items():
        if row["status"] != "twinned":
            continue
        rest_twin = row.get("rest_v1_twin")
        mcp_twin = row.get("mcp_twin")
        if not rest_twin and not mcp_twin:
            gh("error", f"check-api-parity: {row['_file']}: {key[0]} {key[1]} "
                        f"is status=twinned but names neither rest_v1_twin "
                        f"nor mcp_twin")
            ok = False
            continue
        if rest_twin:
            twin_key = (rest_twin.get("method"), canonicalize(rest_twin.get("path", "")))
            if twin_key not in all_extracted:
                gh("error", f"check-api-parity: {row['_file']}: {key[0]} {key[1]} "
                            f"claims rest_v1_twin {twin_key} which is not "
                            f"currently registered")
                ok = False
        if mcp_twin and mcp_twin not in mcp_tools:
            gh("error", f"check-api-parity: {row['_file']}: {key[0]} {key[1]} "
                        f"claims mcp_twin {mcp_twin!r} which is not in "
                        f"mcp_server.cpp's kTools[]")
            ok = False

    # 2b. composed-of rows must reference real capability ids in the ledger.
    all_capability_ids = {r["capability_id"] for r in ledger_rows.values()}
    for key, row in ledger_rows.items():
        if not row["status"].startswith("composed-of:"):
            continue
        ids = row["status"][len("composed-of:"):].split(",")
        for cid in ids:
            if cid not in all_capability_ids:
                gh("error", f"check-api-parity: {row['_file']}: {key[0]} {key[1]} "
                            f"composed-of references unknown capability id "
                            f"{cid!r}")
                ok = False

    # 3. every registered v1 route is in OpenAPI or the allowlist.
    allowlist_set = {(m, canonicalize(p)) for m, p, _reason in ALLOWLIST_OPENAPI_MISSING}
    for key in sorted(set(bucket_b) - openapi_paths):
        if key in allowlist_set:
            continue
        gh("error", f"check-api-parity: {key[0]} {key[1]} is registered but "
                    f"missing from openapi_spec()'s paths table, and is not "
                    f"in ALLOWLIST_OPENAPI_MISSING - either document it in "
                    f"the OpenAPI spec (preferred, closes part of F2) or add "
                    f"it to the allowlist with a reason")
        ok = False
    stale_allowlist = sorted(allowlist_set - (set(bucket_b) - openapi_paths))
    for key in stale_allowlist:
        gh("error", f"check-api-parity: ALLOWLIST_OPENAPI_MISSING entry "
                    f"{key[0]} {key[1]} is stale - it is now either "
                    f"documented in OpenAPI or no longer registered; remove "
                    f"it from the allowlist")
        ok = False

    # 4. ratchet on the untwinned-row count (bidirectional).
    untwinned = sum(1 for r in ledger_rows.values() if r["status"] != "twinned")
    if untwinned > BASELINE_UNTWINNED:
        gh("error", f"check-api-parity: untwinned-row count grew "
                    f"({BASELINE_UNTWINNED} -> {untwinned}) - RATCHET mode "
                    f"forbids this. Wire a real REST/MCP twin, or if this "
                    f"growth is a deliberate reviewed decision (a newly-"
                    f"discovered fragment route with no twin yet), raise "
                    f"BASELINE_UNTWINNED in THIS change.")
        ok = False
    elif untwinned < BASELINE_UNTWINNED:
        gh("error", f"check-api-parity: untwinned-row count improved "
                    f"({BASELINE_UNTWINNED} -> {untwinned}) but "
                    f"BASELINE_UNTWINNED was not lowered to match - the "
                    f"ratchet would not be sticky (a later regression back "
                    f"to {BASELINE_UNTWINNED} would pass). Lower "
                    f"BASELINE_UNTWINNED to {untwinned} in THIS change.")
        ok = False

    # 5. docs/api-parity-ledger.md's generated block must match a fresh
    #    render (same drift class check-capability-matrix.sh runs for
    #    docs/os-capability-matrix.md). Reuses `allowlist_set` from check 3.
    expected_block = render_doc_block(ledger_rows, bucket_b, openapi_paths,
                                       allowlist_set, mcp_tools)
    doc_text = LEDGER_DOC.read_text(encoding="utf-8") if LEDGER_DOC.exists() else ""
    actual_block = extract_doc_block(doc_text)
    if actual_block is None:
        gh("error", f"check-api-parity: {LEDGER_DOC} has no "
                    f"'{DOC_BEGIN[:40]}...' / '{DOC_END}' generated block")
        ok = False
    elif actual_block != expected_block:
        gh("error", f"check-api-parity: {LEDGER_DOC}'s generated block is "
                    f"stale - regenerate with `python3 scripts/ci/"
                    f"check-api-parity.py --render-doc` and splice it "
                    f"between the BEGIN/END GENERATED markers")
        ok = False

    if ok:
        print(f"check-api-parity: OK ({len(ledger_rows)} ledger rows, "
              f"{untwinned} untwinned == baseline {BASELINE_UNTWINNED}; "
              f"{len(bucket_b)} v1 routes, {len(openapi_paths)} OpenAPI "
              f"entries, {len(allowlist_set)} allowlisted; {len(mcp_tools)} "
              f"MCP tools)")
    return 0 if ok else 1


def dump_json():
    bucket_a, bucket_b = extract_all_routes()
    openapi_paths, _spec = extract_openapi_paths()
    mcp_tools = extract_mcp_tools()
    out = {
        "fragments_and_legacy_api": sorted(f"{m} {p}" for m, p in bucket_a),
        "api_v1": sorted(f"{m} {p}" for m, p in bucket_b),
        "openapi_paths": sorted(f"{m} {p}" for m, p in openapi_paths),
        "mcp_tools": sorted(mcp_tools),
        "counts": {
            "fragments_and_legacy_api": len(bucket_a),
            "api_v1": len(bucket_b),
            "openapi_paths": len(openapi_paths),
            "mcp_tools": len(mcp_tools),
            "api_v1_missing_from_openapi": len(set(bucket_b) - openapi_paths),
        },
    }
    print(json.dumps(out, indent=2))
    return 0


def baseline_inventory():
    bucket_a, bucket_b = extract_all_routes()
    openapi_paths, _spec = extract_openapi_paths()
    ledger_rows, ledger_errors = load_ledger()
    for e in ledger_errors:
        gh("warning", f"check-api-parity --baseline-inventory: {e}")
    untwinned = sum(1 for r in ledger_rows.values() if r["status"] != "twinned")
    missing = sorted(set(bucket_b) - openapi_paths)
    allowlist_set = {(m, canonicalize(p)) for m, p, _r in ALLOWLIST_OPENAPI_MISSING}
    print(f"fragments/legacy routes extracted : {len(bucket_a)}")
    print(f"ledger rows                       : {len(ledger_rows)}")
    print(f"untwinned rows                     : {untwinned} "
          f"(baseline {BASELINE_UNTWINNED})")
    print(f"api/v1 routes extracted            : {len(bucket_b)}")
    print(f"openapi paths                      : {len(openapi_paths)}")
    print(f"api/v1 missing from openapi        : {len(missing)} "
          f"({len(allowlist_set)} allowlisted, "
          f"{len(set(missing) - allowlist_set)} unallowlisted)")
    return 0


def _selftest():
    """Unit-tests the extraction/parsing/canonicalization logic itself against
    synthetic fixtures, per this repo's established precedent for CI tooling
    scripts of this shape (flake-retry.py, check-plugin-spawn-lexical.sh,
    tsan-gdb-capture.py all carry --selftest; #3443 is the governance finding
    that made it a standing expectation). Targets, in particular, the two
    concrete false-negative shapes this script has already shipped once each:
    a receiver-notation blind spot (dot-only vs `->`, the #3991 BLOCKING-1
    fix) and an adjacent-string-literal blind spot (the Doomgoose #4003
    review finding) - both are exactly the "route registration silently
    produces no requirement and no warning" failure class this script exists
    to prevent in the PRODUCT, and neither would be caught by running the
    script against the real tree, since the real tree doesn't (yet) contain
    either shape. Runs no filesystem I/O against the real source tree."""
    failures = []

    def check(cond, label):
        if not cond:
            failures.append(label)

    # -- parse_literal_at: the two literal forms it must recognise --------
    lit, end = parse_literal_at('"/api/v1/foo"', 0)
    check(lit == "/api/v1/foo", f"parse_literal_at: plain string, got {lit!r}")
    lit, end = parse_literal_at('R"(/api/v1/(bar)/baz)"', 0)
    check(lit == "/api/v1/(bar)/baz", f"parse_literal_at: raw string, got {lit!r}")
    lit, end = parse_literal_at('R"json({"a":1})json"', 0)
    check(lit == '{"a":1}', f"parse_literal_at: custom raw-string delimiter, got {lit!r}")
    lit, end = parse_literal_at("not_a_literal", 0)
    check(lit is None, "parse_literal_at: non-literal input must return None")
    lit, end = parse_literal_at(r'"esc\"aped"', 0)
    check(lit == 'esc"aped', f"parse_literal_at: escaped quote, got {lit!r}")

    # -- parse_adjacent_literals: the Doomgoose #4003 finding --------------
    # Two plain literals split at the natural version-prefix boundary - the
    # exact reported bypass (previously silently truncated to "/api/v1").
    lit, _end = parse_adjacent_literals('"/api/v1" "/route", h)', 0)
    check(lit == "/api/v1/route",
          f"parse_adjacent_literals: two plain literals must concatenate, got {lit!r}")
    # Raw string followed by a plain literal (mixed forms).
    lit, _end = parse_adjacent_literals('R"(/api/v1/foo)" "/bar", h)', 0)
    check(lit == "/api/v1/foo/bar",
          f"parse_adjacent_literals: raw+plain must concatenate, got {lit!r}")
    # Three-way split.
    lit, _end = parse_adjacent_literals('"/api" "/v1" "/three", h)', 0)
    check(lit == "/api/v1/three",
          f"parse_adjacent_literals: three-way split must concatenate, got {lit!r}")
    # A single literal (the common case) must still work unchanged.
    lit, _end = parse_adjacent_literals('"/api/v1/simple", h)', 0)
    check(lit == "/api/v1/simple",
          f"parse_adjacent_literals: single literal regressed, got {lit!r}")
    # A comment between two adjacent literals (legal C++) must not break it.
    lit, _end = parse_adjacent_literals('"/api/v1" // note\n"/commented", h)', 0)
    check(lit == "/api/v1/commented",
          f"parse_adjacent_literals: comment-separated literals, got {lit!r}")

    # -- extract_verb_calls: both known false-negative shapes, end-to-end -
    # Shape 1 (#3991 BLOCKING-1): arrow-notation receiver, not just dot.
    calls = list(extract_verb_calls('web_server_->Get("/api/legacy", h);', "s.cpp"))
    check(calls == [("GET", "/api/legacy")],
          f"extract_verb_calls: arrow-notation receiver, got {calls}")
    # Shape 2 (#4003 review): adjacent-literal split must not silently vanish.
    calls = list(extract_verb_calls('sink.Post("/api/v1" "/split", h);', "s.cpp"))
    check(calls == [("POST", "/api/v1/split")],
          f"extract_verb_calls: adjacent-literal call site, got {calls}")
    # A genuinely non-literal first argument on a route-sink receiver must
    # still be reported (never silently dropped) - this is `gh("warning",
    # ...)`, which prints rather than raising, so we only check it doesn't
    # crash and doesn't yield a route.
    calls = list(extract_verb_calls('sink.Get(kSomeConstant, h);', "s.cpp"))
    check(calls == [], "extract_verb_calls: non-literal first arg must yield nothing")
    # The known httplib::Client false-positive exemption must still apply.
    calls = list(extract_verb_calls('client.Get(url_var, h);', "s.cpp"))
    check(calls == [], "extract_verb_calls: known client receiver must be silently skipped")

    # -- canonicalize: paren-masking must not let a capture group's own '/'
    #    cause a wrong split, and must collapse both capture groups and
    #    {param}-style OpenAPI segments to the same token. -----------------
    check(canonicalize("/api/v1/tags/([^/]+)/([^/]+)") == "/api/v1/tags/{param}/{param}",
          "canonicalize: two capture groups")
    check(canonicalize("/api/v1/result-sets/{id}") == "/api/v1/result-sets/{param}",
          "canonicalize: OpenAPI {id}-style segment")
    check(canonicalize("/api/v1/plain") == "/api/v1/plain",
          "canonicalize: no-capture-group path is unchanged")

    if failures:
        print("SELFTEST FAILURES:", *failures, sep="\n  ")
        return 1
    print("check-api-parity selftest: OK")
    return 0


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                  formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--dump-json", action="store_true",
                     help="dump raw extraction as JSON and exit")
    ap.add_argument("--bootstrap", action="store_true",
                     help="add default (planned:#2146) rows for any "
                          "currently-unledgered fragment/legacy route")
    ap.add_argument("--baseline-inventory", action="store_true",
                     help="print current vs baseline counts without failing")
    ap.add_argument("--render-doc", action="store_true",
                     help="print docs/api-parity-ledger.md's generated block "
                          "(splice between the BEGIN/END GENERATED markers)")
    ap.add_argument("--selftest", action="store_true",
                     help="run internal extraction/parsing logic checks "
                          "against synthetic fixtures and exit (no real-tree "
                          "I/O)")
    args = ap.parse_args()

    if args.selftest:
        return _selftest()
    if args.dump_json:
        return dump_json()
    if args.baseline_inventory:
        return baseline_inventory()
    if args.render_doc:
        return render_doc()
    if args.bootstrap:
        bucket_a, _bucket_b = extract_all_routes()
        return bootstrap(bucket_a)
    return run_check()


if __name__ == "__main__":
    sys.exit(main())
