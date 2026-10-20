#!/usr/bin/env python3
"""Static lexical gate over server/core/src/server.cpp's production wiring of the pre-routing
same-site write gate (cookie-session writes require a same-site Origin or Referer).

The gate's unit and integration tests drive `apply_same_site_write_gate` directly, so a deleted
call, a call placed before authentication, or an extra early return ahead of it would leave every
one of them green. This gate pins the one production call site. It reads the balanced body of the
`set_pre_routing_handler(` lambda (comments stripped, whitespace collapsed) and checks:

  1. exactly one `apply_same_site_write_gate(` in the file, inside that lambda, after the single
     `auth_routes_->resolve_session(req)` and before the lambda's last `Unhandled` return;
  2. exactly FOUR `Unhandled` returns before `resolve_session(req)`, in this order, each inside
     an `if` chain whose condition text is exactly one of the pinned strings (a widened
     condition or a different predicate fails). These four are the PATH-ONLY bypasses that
     tests/unit/server/test_same_site_exempt_inventory.cpp inventories;
  3. the metrics branch condition is exactly the pinned path comparison (ties the inventory's one
     literal to production; enforced as part of 2);
  4. between `resolve_session(req)` and the gate call: no `Unhandled`, exactly one `Handled`
     return (the 401 block), and the `if (!session) {` block closes before the gate call;
  5. the gate call precedes the engine-principal stash;
  6. the call spelling is the pinned one (six arguments, `*session`, `cfg_.csrf_trusted_origins`,
     `metrics_`, `same_site_audit_fn_`) and a refusal returns `Handled` inside its `if`;
  7. `same_site_audit_fn_` is declared with an initialiser that calls
     `auth_routes_->audit_log_for_principal(`, and `#include "same_site_write_gate.hpp"` is
     present;
  8. none of the step-up entry points (`run_pre_request_stage(`, `apply_step_up_chokepoint(`,
     `run_in_handler_step_up(`, `require_mfa_step_up(`) occurs in the pre-routing lambda, and
     `run_pre_request_stage(`, once it exists in the file, occurs exactly once, inside the
     `set_pre_request_handler(` lambda;
  9. the only step-up token inside the pre-routing lambda is the single, OPTIONAL
     `clear_step_up_pass();` (spelled `detail::clear_step_up_pass();` once the step-up branch
     merges, placed beside the quota-slot reset at the top), and it sits before the first early
     `Unhandled` return. String literals are excluded from this scan: a token inside a path
     literal is not a call;
 10. the gate is LIVE, not merely present. Every token count and position is taken on
     literal-blanked text (a call inside a string or raw-string literal is not a call); the lambda
     carries no `#` preprocessor directive, and the registration is not inside a conditional
     directive; the lambda head and `auto session = ...resolve_session(req);` are pinned
     verbatim; the gate's `if (` is a top-level statement of the lambda (no enclosing block, and
     the text before it ends in `;` or `}`, so it is not the body of an unbraced `if`, an `else`,
     a loop or a `try`); after `resolve_session` and before the gate there is exactly one
     `return` token (the 401 block) and no loop, `switch`, `try`, `throw`, `goto` or process-exit
     token, and no assignment to `session` or `req`; every `return` after `resolve_session` is
     one of the two pinned spellings; the lambda declares no local named `cfg_`, `metrics_`,
     `same_site_audit_fn_`, `req`, `res` or `session` other than the pinned one.

Limits (stated, not hidden): lexical only. It cannot see a relocation that keeps every token in
its pinned order, a semantically different but textually identical condition, or a gate call
whose callee was changed elsewhere (a different overload, a changed `apply_same_site_write_gate`
body). Semantic mutations that keep every pinned token and position also pass: mutating the
request or the session through an alias or a helper call between `resolve_session` and the gate,
a macro or `using` that redefines a pinned name, shadowing `cfg_` or `metrics_` through a path the
declaration scan does not see (a captured init, a structured binding), and any change to the
gate's own decision logic. Those stay review-enforced, with the behavioural tests, like the
sibling wiring gates. tests/test_same_site_wiring_lexical_selftest.py applies in-memory mutations
to prove each check can fail.

Changing a pin here is a review event: land a pin change in a SEPARATE commit from any server.cpp
wiring move, so a restructure cannot be made to pass by editing the pins in the same diff.

Usage:
  python3 -I tests/test_same_site_wiring_lexical.py
  python3 -I tests/test_same_site_wiring_lexical.py --server-cpp PATH    # check another copy
  python3 -I tests/test_same_site_wiring_lexical.py --repo-root DIR
"""
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SERVER_CPP = ROOT / "server" / "core" / "src" / "server.cpp"
TAG = "test_same_site_wiring_lexical"
HINT = (" (this gate pins the pre-routing same-site gate wiring; if server.cpp was legitimately"
        " restructured, update tests/test_same_site_wiring_lexical.py and its selftest in a"
        " SEPARATE commit from the wiring move, never in the same diff)")

UNHANDLED_RET = "return httplib::Server::HandlerResponse::Unhandled;"
HANDLED_RET = "return httplib::Server::HandlerResponse::Handled;"
GATE_NAME = "apply_same_site_write_gate("
GATE_ARGS = "req, res, *session, cfg_.csrf_trusted_origins, metrics_, same_site_audit_fn_"
INCLUDE = '#include "same_site_write_gate.hpp"'
ENGINE_STASH = "detail::tls_engine_principal() = session->is_engine();"
RESOLVE = "auth_routes_->resolve_session(req)"

# The four early returns, in source order: the chain of `if` conditions enclosing each.
EARLY_UNHANDLED_CHAINS = [
    ['if (yuzu::server::health::is_probe_path(req.path))'],
    ['if (is_login_exempt_path(req.path))'],
    ['if (req.path == "/metrics")',
     'if (req.remote_addr == "127.0.0.1" || req.remote_addr == "::1")'],
    ['if (req.path == "/metrics")', 'if (!cfg_.metrics_require_auth)'],
]

STEP_UP_ENTRY_POINTS = ("run_pre_request_stage(", "apply_step_up_chokepoint(",
                        "run_in_handler_step_up(", "require_mfa_step_up(")
# The single step-up token the pre-routing lambda may carry. It appears only after the step-up
# branch merges, so it is optional; if present it must sit before the first early Unhandled.
STEP_UP_ALLOWED_TOKEN = "clear_step_up_pass();"


# ---------------------------------------------------------------------------------------------
# Lexing helpers


def skip_literal(t, i):
    """If t[i] opens a string / char / raw-string literal, return the index just past it."""
    c = t[i]
    if c == '"':
        if i > 0 and t[i - 1] == "R":
            open_paren = t.find("(", i)
            if open_paren < 0:
                return len(t)
            delim = t[i + 1:open_paren]
            end = t.find(")" + delim + '"', open_paren)
            return len(t) if end < 0 else end + len(delim) + 2
        j = i + 1
        while j < len(t) and t[j] != '"':
            j += 2 if t[j] == "\\" else 1
        return min(j + 1, len(t))
    if c == "'" and not (i > 0 and t[i - 1].isalnum()):  # not a digit separator
        j = i + 1
        while j < len(t) and t[j] != "'":
            j += 2 if t[j] == "\\" else 1
        return min(j + 1, len(t))
    return None


def strip_comments(src):
    """Remove // and /* */ comments, leaving string / char / raw-string literals intact."""
    out = []
    i, n = 0, len(src)
    while i < n:
        c = src[i]
        end = skip_literal(src, i) if c in "\"'" else None
        if end is not None:
            out.append(src[i:end])
            i = end
        elif src.startswith("//", i):
            nl = src.find("\n", i)
            i = n if nl < 0 else nl
        elif src.startswith("/*", i):
            end = src.find("*/", i + 2)
            out.append(" ")
            i = n if end < 0 else end + 2
        else:
            out.append(c)
            i += 1
    return "".join(out)


def blank_literals(t):
    """Same-length copy of `t` with the contents of string / char literals replaced by spaces
    (so a path literal that merely contains a token is not mistaken for code)."""
    out = list(t)
    i = 0
    while i < len(t):
        end = skip_literal(t, i) if t[i] in "\"'" else None
        if end is not None:
            lo, hi = i + 1, end - 1
            if t[i] == '"' and i > 0 and t[i - 1] == "R":
                # Raw string: keep `delim(` and `)delim"` so the blanked copy still lexes as one.
                open_paren = t.find("(", i)
                delim = t[i + 1:open_paren] if open_paren >= 0 else ""
                if open_paren >= 0 and end - len(delim) - 2 >= open_paren + 1:
                    lo, hi = open_paren + 1, end - len(delim) - 2
            for k in range(lo, hi):
                out[k] = " "
            i = end
        else:
            i += 1
    return "".join(out)


def normalise(src):
    t = re.sub(r"[ \t\n\r\f\v]+", " ", strip_comments(src))
    t = re.sub(r"\( ", "(", t)
    return re.sub(r" \)", ")", t)


def find_close(t, open_idx):
    """Index of the bracket closing t[open_idx] (one of ( { [), literal-aware, or -1."""
    depth = 0
    i = open_idx
    while i < len(t):
        c = t[i]
        end = skip_literal(t, i) if c in "\"'" else None
        if end is not None:
            i = end
            continue
        if c in "({[":
            depth += 1
        elif c in ")}]":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return -1


def lambda_body(t, opener):
    """The text between the braces of the lambda passed to `opener` (e.g. `x->set_foo(`), or
    None. The call's balanced parens are walked first, so a second registration after it is
    never mistaken for part of this one."""
    at = t.find(opener)
    if at < 0:
        return None
    paren = t.index("(", at)
    close = find_close(t, paren)
    if close < 0:
        return None
    depth = 0
    i = paren
    while i < close:
        c = t[i]
        end = skip_literal(t, i) if c in "\"'" else None
        if end is not None:
            i = end
            continue
        if c == "{" and depth == 1:
            body_close = find_close(t, i)
            return t[i + 1:body_close] if 0 < body_close <= close else None
        if c in "([":
            depth += 1
        elif c in ")]":
            depth -= 1
        i += 1
    return None


def if_chain_at(body, idx):
    """Heads of the blocks enclosing body[idx], outermost first, whitespace-normalised."""
    stack = []
    boundary = 0
    i = 0
    while i < idx:
        c = body[i]
        end = skip_literal(body, i) if c in "\"'" else None
        if end is not None:
            i = end
            continue
        if c == "{":
            stack.append(body[boundary:i].strip())
            boundary = i + 1
        elif c == "}":
            if stack:
                stack.pop()
            boundary = i + 1
        elif c == ";":
            boundary = i + 1
        i += 1
    return stack


def occurrences(text, needle):
    out, at = [], text.find(needle)
    while at >= 0:
        out.append(at)
        at = text.find(needle, at + 1)
    return out


# ---------------------------------------------------------------------------------------------
# The gate


LAMBDA_HEAD = ("set_pre_routing_handler([this](const httplib::Request& req, httplib::Response& res)"
               " -> httplib::Server::HandlerResponse {")
RESOLVE_STMT = "auto session = " + RESOLVE + ";"
# Tokens that make the stretch between resolve_session and the gate non-straight-line.
FLOW_TOKENS = re.compile(r"\b(?:for|while|do|switch|try|catch|throw|goto|co_return|co_await|"
                         r"co_yield|abort|exit|quick_exit|_Exit|terminate)\b")
RETURN_TOKEN = re.compile(r"\breturn\b")
SPELLED_RETURN = re.compile(r"\breturn httplib::Server::HandlerResponse::(?:Handled|Unhandled);")
# Before resolve_session the lambda legitimately holds a nested lambda returning bool.
EARLY_RETURN_OK = re.compile(r"\breturn (?:httplib::Server::HandlerResponse::(?:Handled|Unhandled)"
                             r"|false|true)\b")
SESSION_OR_REQ_ASSIGN = re.compile(
    r"(?<![\w.>])(?:session|req)\b(?:\s*(?:\.|->)\s*\w+|\s*\[[^\]]*\])*\s*"
    r"(?:<<|>>|[-+*/%&|^])?=(?!=)")
SESSION_MUTATORS = re.compile(r"\bsession\s*(?:\.|->)\s*reset\b|\bstd::(?:move|swap)\(")
PINNED_LOCALS = ("cfg_", "metrics_", "same_site_audit_fn_", "req", "res")
CONDITIONAL_DIRECTIVE = re.compile(r"^\s*#\s*(if|ifdef|ifndef)\b")
ENDIF_DIRECTIVE = re.compile(r"^\s*#\s*endif\b")


def registration_in_conditional(src):
    """True if set_pre_routing_handler( sits inside a preprocessor conditional (#if 0, #ifdef...)
    in the comment-stripped, NOT whitespace-collapsed source."""
    s = strip_comments(src)
    at = s.find("set_pre_routing_handler(")
    if at < 0:
        return False
    depth = 0
    for line in s[:at].split("\n"):
        if CONDITIONAL_DIRECTIVE.match(line):
            depth += 1
        elif ENDIF_DIRECTIVE.match(line):
            depth = max(0, depth - 1)
    return depth > 0


def local_declarations(blank, names):
    """Names from `names` declared as locals in `blank` (a `<type> name =|{|(|;` shape that is not
    a member access)."""
    found = []
    for n in names:
        pat = r"(?<![\w.>:])[\w:<>,]+[&*]*\s+[&*]?\s*" + re.escape(n) + r"\s*(?:=(?!=)|\{|;|\()"
        for m in re.finditer(pat, blank):
            if m.group(0).split()[0] in ("return", "else", "throw", "co_return"):
                continue
            found.append(n)
            break
    return found


def problems(src):
    out = []
    t = normalise(src)
    tb = blank_literals(t)  # same length as t; literal contents are spaces

    if INCLUDE not in t:
        out.append(f"server.cpp no longer has {INCLUDE}")

    if len(occurrences(tb, "set_pre_routing_handler(")) != 1:
        out.append("server.cpp must register exactly one set_pre_routing_handler( lambda")
    if registration_in_conditional(src):
        out.append("the set_pre_routing_handler( registration is inside a preprocessor "
                   "conditional (#if / #ifdef / #ifndef)")
    body = lambda_body(t, "set_pre_routing_handler(")
    if body is None:
        out.append("could not extract the set_pre_routing_handler( lambda body")
        return out
    # Every position-based check below runs on `bb`, the literal-blanked twin of `body` (same
    # indices); `body` itself is only read where a literal's text matters (conditions, args).
    bb = blank_literals(body)
    at = t.find("set_pre_routing_handler(")
    if not t[at:].startswith(LAMBDA_HEAD):
        out.append("the pre-routing lambda head is not exactly `" + LAMBDA_HEAD + "`")
    if "#" in bb:
        out.append("a `#` preprocessor directive appears inside the pre-routing lambda")

    # 1: the gate call
    file_calls = occurrences(tb, GATE_NAME)
    calls = occurrences(bb, GATE_NAME)
    if len(file_calls) != 1 or len(calls) != 1:
        out.append(f"expected exactly one {GATE_NAME} in server.cpp, inside the pre-routing "
                   f"lambda (file: {len(file_calls)}, lambda: {len(calls)})")
        gate = None
    else:
        gate = calls[0]

    resolves = occurrences(bb, RESOLVE)
    if len(resolves) != 1:
        out.append(f"the pre-routing lambda must call {RESOLVE} exactly once "
                   f"(found {len(resolves)})")
        return out
    resolve = resolves[0]
    if not body[:resolve + len(RESOLVE) + 1].endswith(RESOLVE_STMT) or \
            bb.count(RESOLVE_STMT) != 1:
        out.append(f"the session must be taken by exactly `{RESOLVE_STMT}`")

    unhandled = occurrences(bb, UNHANDLED_RET)
    if not unhandled:
        out.append("the pre-routing lambda has no Unhandled return")
        return out
    last_unhandled = unhandled[-1]
    if bb.count("HandlerResponse::Unhandled") != len(unhandled):
        out.append("an Unhandled spelling other than the pinned `" + UNHANDLED_RET +
                   "` appears in the pre-routing lambda")

    # every return keeps a pinned spelling (a `return static_cast<...>(1);` is not one)
    for m in RETURN_TOKEN.finditer(bb):
        ok = EARLY_RETURN_OK if m.start() < resolve else SPELLED_RETURN
        if not ok.match(bb, m.start()):
            out.append("a return other than the pinned HandlerResponse spellings appears in the "
                       f"pre-routing lambda: `{body[m.start():m.start() + 60]}`")
            break

    # 2 and 3: exactly four early Unhandled returns with pinned condition chains
    early = [u for u in unhandled if u < resolve]
    if len(early) != len(EARLY_UNHANDLED_CHAINS):
        out.append(f"expected exactly {len(EARLY_UNHANDLED_CHAINS)} Unhandled returns before "
                   f"{RESOLVE}, found {len(early)}")
    else:
        for k, (u, want) in enumerate(zip(early, EARLY_UNHANDLED_CHAINS), 1):
            chain = if_chain_at(body, u)
            if chain != want:
                out.append(f"early Unhandled return #{k} is not under exactly {want} "
                           f"(found {chain})")

    # 9 (position half): the optional step-up allowance sits before the first early Unhandled
    first_early = early[0] if early else None
    step_hits = [m for m in re.finditer(r"step_?up", bb, re.IGNORECASE)]
    allowed_spans = [(a, a + len(STEP_UP_ALLOWED_TOKEN))
                     for a in occurrences(bb, STEP_UP_ALLOWED_TOKEN)]
    if len(allowed_spans) > 1:
        out.append(f"{STEP_UP_ALLOWED_TOKEN} appears more than once in the pre-routing lambda")
    for m in step_hits:
        if not any(a <= m.start() < b for a, b in allowed_spans):
            out.append("a step-up token other than the single optional "
                       f"{STEP_UP_ALLOWED_TOKEN} appears in the pre-routing lambda: "
                       f"`{body[max(0, m.start() - 20):m.end() + 20]}`")
            break
    for a, _ in allowed_spans:
        if first_early is not None and a > first_early:
            out.append(f"{STEP_UP_ALLOWED_TOKEN} must sit before the first early Unhandled return")

    # 8: the step-up entry points are not in the pre-routing lambda
    for name in STEP_UP_ENTRY_POINTS:
        if name in bb:
            out.append(f"{name} must not be called from the pre-routing lambda")
    pre_request_calls = occurrences(tb, "set_pre_request_handler(")
    stage_calls = occurrences(tb, "run_pre_request_stage(")
    if stage_calls:
        pr_body = lambda_body(t, "set_pre_request_handler(")
        pr_blank = blank_literals(pr_body) if pr_body is not None else None
        if len(pre_request_calls) != 1 or pr_body is None:
            out.append("run_pre_request_stage( exists but set_pre_request_handler( is not "
                       "registered exactly once")
        elif len(stage_calls) != 1 or pr_blank.count("run_pre_request_stage(") != 1:
            out.append("run_pre_request_stage( must occur exactly once in server.cpp, inside "
                       "the set_pre_request_handler( lambda")

    # locals that could shadow what the gate call reads
    shadowed = local_declarations(bb, PINNED_LOCALS)
    if shadowed:
        out.append(f"the pre-routing lambda declares a local named {shadowed}; the gate call's "
                   "arguments must be the members / parameters")

    if gate is None:
        return out

    # 1 (order half)
    if not resolve < gate < last_unhandled:
        out.append(f"{GATE_NAME} must come after {RESOLVE} and before the lambda's last "
                   "Unhandled return")
        return out

    # 6: pinned spelling and the Handled return inside its `if`
    paren = gate + len(GATE_NAME) - 1
    close = find_close(body, paren)
    args = body[paren + 1:close] if close > 0 else ""
    if args != GATE_ARGS:
        out.append(f"the gate call's arguments are not exactly `{GATE_ARGS}` (found `{args}`)")
    head = body[:gate]
    if head.endswith("if (detail::"):
        if_start = gate - len("if (detail::")
    elif head.endswith("if ("):
        if_start = gate - len("if (")
    else:
        if_start = None
        out.append("the gate call is not the bare condition of an `if`")
    if not body[close + 1:].startswith(") { " + HANDLED_RET + " }"):
        out.append("a refused gate call must `" + HANDLED_RET + "` inside its `if`")

    # 10: the gate is live. A top-level statement of the lambda: no enclosing block, and the
    # preceding text ends a statement (so it is not an unbraced `if` / `else` / loop body).
    chain = if_chain_at(body, gate)
    if chain != []:
        out.append(f"the gate call is nested inside {chain}; it must be a top-level statement of "
                   "the pre-routing lambda")
    if if_start is not None:
        pre = body[:if_start].rstrip()
        if not pre or pre[-1] not in ";}":
            out.append("the gate's `if (` does not start a new statement (it follows "
                       f"`{pre[-30:]}`): an unbraced `if`, `else` or loop body would make it "
                       "conditional")

    # 4: the stretch between resolve_session and the gate
    between = bb[resolve:gate]
    if "Unhandled" in between:
        out.append("an Unhandled appears between resolve_session and the gate call")
    if between.count("HandlerResponse::Handled") != 1 or between.count(HANDLED_RET) != 1:
        out.append("expected exactly one Handled return (the 401 block) between "
                   "resolve_session and the gate call")
    if len(RETURN_TOKEN.findall(between)) != 1:
        out.append("expected exactly one `return` token (the 401 block) between "
                   f"resolve_session and the gate call (found {len(RETURN_TOKEN.findall(between))})")
    flow = FLOW_TOKENS.search(between)
    if flow:
        out.append(f"`{flow.group(0)}` appears between resolve_session and the gate call")
    if SESSION_OR_REQ_ASSIGN.search(between[len(RESOLVE_STMT):]) or SESSION_MUTATORS.search(between):
        out.append("session or req is assigned / moved from between resolve_session and the "
                   "gate call")
    sess = bb.find("if (!session) {", resolve)
    if sess < 0 or sess > gate:
        out.append("the `if (!session) {` block is not between resolve_session and the gate call")
    else:
        sess_close = find_close(bb, bb.index("{", sess))
        if sess_close < 0 or sess_close > gate:
            out.append("the `if (!session)` block does not close before the gate call")

    # 5: the gate precedes the engine stash
    stash = occurrences(bb, ENGINE_STASH)
    if len(stash) != 1:
        out.append(f"expected exactly one `{ENGINE_STASH}` in the pre-routing lambda")
    elif not gate < stash[0]:
        out.append("the gate call must come before the engine-principal stash")

    # 7: the audit sink cannot be empty
    decls = [m.start() for m in re.finditer(r"\bSameSitePrincipalAuditFn same_site_audit_fn_ =", tb)]
    if len(decls) != 1:
        out.append("same_site_audit_fn_ must be declared exactly once with an initialiser")
    else:
        semi = tb.find(";", decls[0])
        # the initialiser is a lambda: walk to the first `{`, then its close, then the `;`
        brace = tb.find("{", decls[0])
        end = find_close(tb, brace) if brace >= 0 else -1
        stmt = tb[decls[0]:(tb.find(";", end) if end >= 0 else semi)]
        if "auth_routes_->audit_log_for_principal(" not in stmt:
            out.append("same_site_audit_fn_ is not initialised from "
                       "auth_routes_->audit_log_for_principal(")
    return out


# ---------------------------------------------------------------------------------------------


class SameSiteWiring(unittest.TestCase):
    server_cpp = SERVER_CPP

    @classmethod
    def setUpClass(cls):
        cls.raw = cls.server_cpp.read_text(encoding="utf-8")

    def test_source_is_clean(self):
        p = problems(self.raw)
        for m in p:
            print(f"\n::error::{TAG}: {m}{HINT}", file=sys.stderr)
        self.assertEqual(p, [])


def main(argv):
    args = list(argv[1:])
    rest = []
    while args:
        a = args.pop(0)
        if a == "--server-cpp" and args:
            SameSiteWiring.server_cpp = Path(args.pop(0))
        elif a == "--repo-root" and args:
            SameSiteWiring.server_cpp = Path(args.pop(0)) / "server" / "core" / "src" / "server.cpp"
        else:
            rest.append(a)
    result = unittest.main(argv=[argv[0]] + rest, exit=False).result
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
