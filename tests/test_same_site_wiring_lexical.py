#!/usr/bin/env python3
"""Static lexical gate over server/core/src/server.cpp's production wiring of the pre-routing
same-site write gate (cookie-session writes require a same-site Origin or Referer).

This is a BEST-EFFORT TRIPWIRE, not proof. The gate's unit and integration tests drive
`apply_same_site_write_gate` directly, so a deleted call, a call placed before authentication, or
an extra early return ahead of it would leave every one of them green. This gate pins the one
production call site. It reads the balanced body of the `set_pre_routing_handler` lambda (comments
stripped, whitespace collapsed) and checks:

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
  6. the call spelling is the pinned one (seven arguments, `*session`, `cfg_.csrf_trusted_origins`,
     `cfg_.https_enabled` (the web listener's TLS state, never a literal `true` / `false`),
     `metrics_`, `same_site_audit_fn_`) and a refusal returns `Handled` inside its `if`;
  7. `same_site_audit_fn_` is declared with an initialiser whose body is exactly the pinned
     `return auth_routes_->audit_log_for_principal(...)` (none of `sizeof`, `decltype`,
     `noexcept`, `typeid`, `alignof` appears in it), and `#include "same_site_write_gate.hpp"` is
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
     `same_site_audit_fn_`, `req`, `res`, `is_login_exempt_path`, `auth_routes_`, `detail` or
     `home_ui`, and contains none of the tokens `using`, `namespace`, `typedef`;
 10b. the registration itself is pinned: the receiver is exactly `web_server_->` (a swap to another
     server object leaves the real one ungated) and it is an unconditional statement: no
     enclosing `if` / `else` / loop / `switch` / `try` / lambda block head, and not the body of
     an unbraced `if`, `else`, loop or label;
 11. the text between `resolve_session` and the gate's `if (` is EXACTLY the pinned session
     lookup and 401 / redirect block (an ALLOWLIST, whitespace-collapsed: any added statement,
     including a call that never returns, breaks the equality);
 12. the lexing refuses what it cannot model instead of modelling it. ANY backslash followed by
     blanks (space, tab, FF, VT, NUL, CR) and the end of a line, or the end of the file,
     anywhere in server.cpp is rejected: compilers splice such lines (inside comments, string and
     raw-string literals, identifiers) in ways a lexical pass cannot reproduce faithfully, and
     the file has none today. None of the digraphs `<%` `%>` `<:` `:>` `%:` appears in the
     lambda, and a `%:` directive counts as `#`; a `??/` trigraph is rejected; no noreturn call
     (`abort`, `exit`, `_Exit`, `quick_exit`, `terminate`, `longjmp`, `unreachable`, `throw`,
     `ExitThread` and kin) appears anywhere in the lambda; char literals carry their encoding
     prefix (`u8'"'`, `u'"'`, `U'"'`, `L'"'`) while a digit separator (`1'000`) does not open
     one; no file-scope `#define` / `#undef` names a C++ keyword, a pinned identifier or any
     identifier the lambda uses; and EVERY use of the name `set_pre_routing_handler`, however
     spelled (a space or newline before the paren, a comment between, a bare mention), counts as
     a registration;
 13. a registration inventory (`inventory_problems`) reads every C / C++ / Objective-C(++) source
     (`SOURCE_SUFFIXES`: `.cpp .hpp .h .inc .inl .cc .cxx .hh .hxx .ipp .mm .m`) under
     server/core/src (comments stripped, literals blanked, line splices applied) and requires
     that no file other than server.cpp mentions `set_pre_routing_handler` except
     health_routes.cpp, which holds exactly one call (the plaintext redirect install on its own
     server object): a second registrar replaces the whole handler.

Limits (stated, not hidden). This is a lexical tripwire over one file, not proof the gate runs.
The closure evidence for production wiring is the live-stack assertion in
scripts/e2e-security-test.sh, which sends real refused and admitted requests at a running server.
What the lexical gate cannot see:
  - a noreturn call hidden behind a macro, an alias or another function name;
  - a helper, alias or `const_cast` mutation of the request, the session or a pinned name BEFORE
    `resolve_session` (statements before it are unconstrained beyond the four pinned early
    returns, the lambda head and the forbidden-token lists; the stretch after it is pinned
    exactly);
  - a macro defined in a header that server.cpp includes (only server.cpp's own `#define` lines
    are read), or a rebinding of a pinned name that the declaration scan does not recognise
    (a captured init, a structured binding);
  - a registrar outside server/core/src, or in a file whose own lexing the scan does not model
    (the inventory applies line splices but does not reject them);
  - a relocation that keeps every token in its pinned order, a semantically different but
    textually identical condition, or a gate call whose callee was changed elsewhere (a
    different overload, a changed `apply_same_site_write_gate` body, any change to the gate's own
    decision logic);
  - a later assignment or nulling of the audit-sink member after its initialiser (only the
    initialiser's body is pinned);
  - the `csrf.denied` audit row and its principal: they are asserted only by the unit tests, not
    by the live category;
  - a new `httplib::Server` object that serves routes without the handler (only the registration
    on `web_server_` and the inventory of other registrars are pinned);
  - an unlisted pre-resolve block that returns before authentication: it is unconstrained apart
    from the four pinned returns and the forbidden-token lists;
  - compiler-specific preprocessing and extension behaviour beyond what is listed above.
Those stay review-enforced, with the behavioural tests, like the sibling wiring gates.
tests/test_same_site_wiring_lexical_selftest.py applies in-memory mutations to prove each check
can fail.

Changing a pin here is a review event: land a pin change in a SEPARATE commit from any server.cpp
wiring move, so a restructure cannot be made to pass by editing the pins in the same diff.

Usage:
  python3 -I tests/test_same_site_wiring_lexical.py
  python3 -I tests/test_same_site_wiring_lexical.py --server-cpp PATH    # check another copy
  python3 -I tests/test_same_site_wiring_lexical.py --src-dir DIR        # inventory tree
  python3 -I tests/test_same_site_wiring_lexical.py --repo-root DIR
--server-cpp does not move the inventory: the other files are always read from the repo's
server/core/src (or --src-dir), so a scratch copy of server.cpp is checked in context.
"""
import re
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = ROOT / "server" / "core" / "src"
SERVER_CPP = SRC_DIR / "server.cpp"
TAG = "test_same_site_wiring_lexical"
HINT = (" (this gate pins the pre-routing same-site gate wiring; if server.cpp was legitimately"
        " restructured, update tests/test_same_site_wiring_lexical.py and its selftest in a"
        " SEPARATE commit from the wiring move, never in the same diff)")

UNHANDLED_RET = "return httplib::Server::HandlerResponse::Unhandled;"
HANDLED_RET = "return httplib::Server::HandlerResponse::Handled;"
GATE_NAME = "apply_same_site_write_gate("
GATE_ARGS = ("req, res, *session, cfg_.csrf_trusted_origins, cfg_.https_enabled, metrics_, "
             "same_site_audit_fn_")
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


_PP_CHARS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.'")
_WORD = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_")


def _raw_open(t, i):
    """True if the `"` at t[i] opens a raw string: an `R` (optionally behind a `u8` / `u` / `U` /
    `L` encoding prefix) that is itself not the tail of a longer identifier."""
    if i < 1 or t[i - 1] != "R":
        return False
    s = i - 1
    if t[max(0, s - 2):s] == "u8":
        s -= 2
    elif s > 0 and t[s - 1] in "uUL":
        s -= 1
    return s == 0 or t[s - 1] not in _WORD


def _digit_separator(t, i):
    """True if the `'` at t[i] sits inside a preprocessing number (`1'000`, `0x1'F`): the run of
    number characters behind it starts with a digit. An encoding prefix (`u8'"'`, `L'"'`) or an
    identifier tail (`return'"'`) starts with a letter, so the quote there opens a char literal."""
    j = i
    while j > 0 and t[j - 1] in _PP_CHARS:
        j -= 1
    tok = t[j:i]
    # a separator continues the number only before a digit / nondigit (the regex's `'\w`)
    nxt = t[i + 1:i + 2]
    return (bool(tok) and bool(nxt) and nxt in _WORD and
            (tok[0].isdigit() or (tok[0] == "." and tok[1:2].isdigit())))


def skip_literal(t, i):
    """If t[i] opens a string / char / raw-string literal, return the index just past it."""
    c = t[i]
    if c == '"':
        if _raw_open(t, i):
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
    if c == "'" and not _digit_separator(t, i):
        j = i + 1
        while j < len(t) and t[j] != "'":
            j += 2 if t[j] == "\\" else 1
        return min(j + 1, len(t))
    return None


# One scanner for every pass. A literal (raw string, string, char) is matched whole so a comment
# marker inside it is never a comment. A preprocessing number is matched whole too, so a digit
# separator (`1'000`) is consumed with its number and never opens a char literal, while an
# encoding-prefixed (`u8'"'`) or identifier-adjacent (`return'"'`) char literal still does.
_LITERAL = (r'(?<![\w])(?:u8|[uUL])?R"(?P<d>[^()\\\s"]{0,16})\(.*?\)(?P=d)"'
            r"|\d(?<![\w']\d)(?:[eEpP][+-]|[\w.]|'\w)*"
            r'|"(?:\\.|[^"\\])*(?:"|\Z)'
            r"|'(?:\\.|[^'\\])*(?:'|\Z)")
_LITERAL_RE = re.compile(_LITERAL, re.DOTALL)
_TOKEN_RE = re.compile(_LITERAL + r"|//[^\n]*|/\*.*?(?:\*/|\Z)", re.DOTALL)
# Translation phase 2: a backslash followed by blanks and the end of a line (or of the file). The
# blanks are every character gcc splices through: space, tab, FF, VT, NUL, and the CR of a CRLF.
# The gate does NOT model splices: any occurrence in the checked source is a problem (see
# `problems`); `splice_lines` only lets the later passes keep reporting on the joined text.
_SPLICE_RE = re.compile(r"\\[ \t\f\v\x00\r]*(?:\n|\Z)")
_WS_RE = re.compile(r"[ \t\n\r\f\v]+")


def splice_lines(src):
    """Delete every backslash-end-of-line (diagnostic use only; see `_SPLICE_RE`)."""
    return _SPLICE_RE.sub("", src)


def strip_comments(src):
    """Remove // and /* */ comments, leaving string / char / raw-string literals intact. The
    caller applies `splice_lines` first (normalise() and problems() do)."""
    def rep(m):
        s = m.group(0)
        if s[0] != "/":
            return s
        return "" if s[1] == "/" else " "
    return _TOKEN_RE.sub(rep, src)


def blank_literals(t):
    """Same-length copy of `t` with the contents of string / char literals replaced by spaces
    (so a path literal that merely contains a token is not mistaken for code)."""
    def rep(m):
        s = m.group(0)
        if s[0].isdigit():  # a preprocessing number, kept as is
            return s
        if m.group("d") is not None:
            # Raw string: keep `R"delim(` and `)delim"` so the blanked copy still lexes as one.
            lo, hi = s.index("(") + 1, len(s) - len(m.group("d")) - 2
            return s[:lo] + " " * (hi - lo) + s[hi:]
        hi = len(s) - 1 if len(s) >= 2 and s[-1] == s[0] else len(s)
        return s[0] + " " * (hi - 1) + s[hi:]
    return _LITERAL_RE.sub(rep, t)


def collapse(stripped):
    t = _WS_RE.sub(" ", stripped)
    return t.replace("( ", "(").replace(" )", ")")


def normalise(src):
    return collapse(strip_comments(splice_lines(src)))


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


def _name_uses(tb, name):
    """(start, end) of every standalone use of the identifier `name` in `tb`."""
    out, at = [], tb.find(name)
    while at >= 0:
        end = at + len(name)
        if (at == 0 or not (tb[at - 1].isalnum() or tb[at - 1] == "_")) and \
                (end >= len(tb) or not (tb[end].isalnum() or tb[end] == "_")):
            out.append((at, end))
        at = tb.find(name, at + 1)
    return out


def registrations(tb, name):
    """Start indices of every `name (` call-shaped use in `tb` (comment-stripped, literal-blanked):
    whitespace, including a newline, may sit between the name and the paren."""
    return [a for a, e in _name_uses(tb, name) if tb[e:].lstrip().startswith("(")]


def mentions(tb, name):
    """Count of every use of the identifier `name` in `tb`, call-shaped or not."""
    return len(_name_uses(tb, name))


def lambda_body(t, name, tb=None):
    """The text between the braces of the lambda passed to the first `name (` call in `t`, or
    None. `tb` is the literal-blanked twin of `t` (same length) used to find the call. The call's
    balanced parens are walked first, so a second registration after it is never mistaken for
    part of this one."""
    tb = blank_literals(t) if tb is None else tb
    regs = registrations(tb, name)
    if not regs:
        return None
    paren = t.index("(", regs[0])
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
# Names the gate call and the pinned stretch read, plus the names the early path-only returns
# call; a local of the same name would rebind them. Each is a name the lambda really uses.
PINNED_LOCALS = ("cfg_", "metrics_", "same_site_audit_fn_", "req", "res", "is_login_exempt_path",
                 "auth_routes_", "detail", "home_ui")
# Constructs that rebind or alias a name without declaring a local the scan above would see.
REBINDING_TOKENS = re.compile(r"\b(?:using|namespace|typedef)\b")
# C++23 keywords and alternative tokens: a file-scope `#define` / `#undef` of one reshapes the
# lambda's control flow (`#define if(x) ...`, `#define return`).
CXX_KEYWORDS = frozenset("""
alignas alignof and and_eq asm auto bitand bitor bool break case catch char char8_t char16_t
char32_t class compl concept const consteval constexpr constinit const_cast continue co_await
co_return co_yield decltype default delete do double dynamic_cast else enum explicit export
extern false float for friend goto if inline int long mutable namespace new noexcept not not_eq
nullptr operator or or_eq private protected public register reinterpret_cast requires return
short signed sizeof static static_assert static_cast struct switch template this thread_local
throw true try typedef typeid typename union unsigned using virtual void volatile wchar_t while
xor xor_eq""".split())
DEFINE_DIRECTIVE = re.compile(r"^[ \t\f\v]*(?:#|%:)[ \t]*(?:define|undef)[ \t]+([A-Za-z_]\w*)",
                              re.MULTILINE)
UNEVALUATED_OPERATOR = re.compile(r"\b(?:sizeof|decltype|noexcept|typeid|alignof)\b")
# The ONLY body the audit-sink lambda may have: it returns the audit call, nothing else.
PINNED_AUDIT_BODY = ("{ return auth_routes_->audit_log_for_principal(r, action, result, p.id, "
                     "p.role, tt, tid, d, p.cls); }")
# `%:` is the digraph for `#`; a directive can be spelled with either.
CONDITIONAL_DIRECTIVE = re.compile(r"^\s*(?:#|%:)\s*(if|ifdef|ifndef)\b")
ENDIF_DIRECTIVE = re.compile(r"^\s*(?:#|%:)\s*endif\b")
REGISTRATION = "set_pre_routing_handler"
RECEIVER = "web_server_->"
# Block heads that make a registration conditional at runtime, and the tail of a statement that
# leaves the registration as the body of an unbraced `if` / `else` / loop / label.
CONTROL_HEAD = re.compile(r"(?<![\w:.>])(?:if|else|for|while|do|switch|try|catch)\b")
LAMBDA_IN_HEAD = re.compile(r"\[[^\]]*\]\s*(?:\(|\{|->)")
UNBRACED_BEFORE = re.compile(r"(?:\)|:|\b(?:else|do))\Z")
# Alternative-token spellings of braces / brackets / hash. A digraph block wraps the gate call in
# a scope the brace-based nesting scan cannot see, so none may appear in the lambda.
DIGRAPH = re.compile(r"<%|%>|<:|:>|%:")
# A noreturn call anywhere in the lambda would make everything after it unreachable; the
# stretch before the gate is pinned exactly (below), this covers the rest of the lambda.
NORETURN_CALL = re.compile(r"(?<![\w])(?:__builtin_unreachable|__builtin_trap|__builtin_abort|"
                           r"unreachable|longjmp|siglongjmp|_longjmp|abort|exit|_exit|_Exit|"
                           r"quick_exit|terminate|pthread_exit|thrd_exit|__fastfail|throw|"
                           r"rethrow_exception|rethrow_nested|throw_with_nested|ExitThread|"
                           r"ExitProcess|FatalExit|FatalAppExit|TerminateProcess|_endthread|"
                           r"_endthreadex)\b")
# The ONLY text allowed between `resolve_session` and the gate's `if (`: the session lookup and
# the 401 / redirect block, whitespace-collapsed exactly as normalise() renders it. Any added,
# removed or reworded statement (a noreturn call, an assignment, an early return, a changed
# condition or status) breaks the equality. Changing it is a review event (see HINT).
PINNED_RESOLVE_TO_GATE = (
    "auth_routes_->resolve_session(req); if (!session) { "
    'if (req.path.starts_with("/api/") || req.path == "/events" || '
    'req.path.starts_with("/mcp/")) { res.status = 401; '
    'res.set_content(R"({"error":{"code":401,"message":"unauthorized"},'
    '"meta":{"api_version":"v1"}})", "application/json"); } '
    'else if (!req.get_header_value("HX-Request").empty()) { res.status = 401; '
    'res.set_header("HX-Redirect", "/home"); res.set_content("", "text/plain"); } '
    "else { res.set_redirect(home_ui::sign_in_location(req.path)); } "
    "return httplib::Server::HandlerResponse::Handled; } ")


def registration_in_conditional(sb):
    """True if the set_pre_routing_handler registration sits inside a preprocessor conditional
    (#if 0, #ifdef...). `sb` is the line-spliced, comment-stripped, literal-blanked source, NOT
    whitespace-collapsed (the directives are line based)."""
    regs = registrations(sb, REGISTRATION)
    if not regs:
        return False
    depth = 0
    for line in sb[:regs[0]].split("\n"):
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
    splice = _SPLICE_RE.search(src)
    if splice:
        out.append("a line splice (a backslash, optional blanks, then the end of a line) appears "
                   f"at line {src.count(chr(10), 0, splice.start()) + 1} of server.cpp: the gate "
                   "cannot model splices (compilers revert them inside raw strings and splice "
                   "through FF / VT / NUL), so none is accepted anywhere in the file")
    # The later passes still run on the joined text so their findings are reported too.
    spliced = splice_lines(src)
    stripped = strip_comments(spliced)
    t = collapse(stripped)
    tb = blank_literals(t)  # same length as t; literal contents are spaces

    if INCLUDE not in t:
        out.append(f"server.cpp no longer has {INCLUDE}")
    if "??/" in spliced:
        out.append("a `??/` trigraph (a backslash spelling) appears in server.cpp")

    # Any use of the identifier counts, however spelled: `set_pre_routing_handler (nullptr)`,
    # a newline before the paren, or a bare mention are all a second registration.
    regs = registrations(tb, REGISTRATION)
    if len(regs) != 1 or mentions(tb, REGISTRATION) != len(regs):
        out.append("server.cpp must register exactly one set_pre_routing_handler( lambda "
                   f"(found {len(regs)} call(s), {mentions(tb, REGISTRATION)} use(s) of the name)")
    sb = blank_literals(stripped)  # line-based twin for the directive scans
    if registration_in_conditional(sb):
        out.append("the set_pre_routing_handler( registration is inside a preprocessor "
                   "conditional (#if / #ifdef / #ifndef)")
    body = lambda_body(t, REGISTRATION, tb)
    if body is None:
        out.append("could not extract the set_pre_routing_handler( lambda body")
        return out
    # Every position-based check below runs on `bb`, the literal-blanked twin of `body` (same
    # indices); `body` itself is only read where a literal's text matters (conditions, args).
    bb = blank_literals(body)
    at = regs[0] if regs else tb.find(REGISTRATION)
    if not t[at:].startswith(LAMBDA_HEAD):
        out.append("the pre-routing lambda head is not exactly `" + LAMBDA_HEAD + "`")
    # The receiver is part of the pin: the handler must be installed on `web_server_`, the server
    # that serves the routes (a swapped receiver would leave the real server ungated), and the
    # registration must be an unconditional statement (no enclosing runtime `if` / loop / lambda,
    # not the body of an unbraced `if`, `else` or loop).
    if t[max(0, at - len(RECEIVER)):at] != RECEIVER or \
            (at > len(RECEIVER) and (t[at - len(RECEIVER) - 1] in _WORD or
                                     t[at - len(RECEIVER) - 1] in ".>")):
        out.append("the set_pre_routing_handler( registration is not exactly `" + RECEIVER +
                   "set_pre_routing_handler(`: the receiver is pinned")
    for enclosing in if_chain_at(t, at):
        if CONTROL_HEAD.search(enclosing) or LAMBDA_IN_HEAD.search(enclosing):
            out.append("the set_pre_routing_handler( registration is inside a runtime "
                       f"conditional, loop or lambda (`{enclosing[:60]}`)")
            break
    if UNBRACED_BEFORE.search(t[:max(0, at - len(RECEIVER))].rstrip()):
        out.append("the set_pre_routing_handler( registration is the body of an unbraced "
                   "`if`, `else`, loop or label")
    if "#" in bb:
        out.append("a `#` preprocessor directive appears inside the pre-routing lambda")
    digraph = DIGRAPH.search(bb)
    if digraph:
        out.append(f"a digraph `{digraph.group(0)}` appears inside the pre-routing lambda")
    noreturn = NORETURN_CALL.search(bb)
    if noreturn:
        out.append(f"a noreturn call `{noreturn.group(0)}` appears inside the pre-routing lambda")
    rebinding = REBINDING_TOKENS.search(bb)
    if rebinding:
        out.append(f"`{rebinding.group(0)}` appears inside the pre-routing lambda: a using / "
                   "namespace / typedef declaration can rebind a pinned name")
    # A file-scope macro named like a keyword or like any identifier the lambda uses rewrites it.
    lambda_names = set(re.findall(r"[A-Za-z_]\w*", bb)) | set(PINNED_LOCALS) | CXX_KEYWORDS
    for dm in DEFINE_DIRECTIVE.finditer(sb):
        if dm.group(1) in lambda_names:
            out.append(f"a preprocessor `#define` / `#undef` of `{dm.group(1)}` appears in "
                       "server.cpp: it is a C++ keyword or a name the pre-routing lambda uses")

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
    pre_request_calls = registrations(tb, "set_pre_request_handler")
    stage_calls = occurrences(tb, "run_pre_request_stage(")
    if stage_calls:
        pr_body = lambda_body(t, "set_pre_request_handler", tb)
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
    # The allowlist: the stretch is EXACTLY the pinned lookup + 401 block. The checks above give
    # the specific diagnoses; this one is what makes an unlisted construct (a noreturn call, a
    # helper that never returns, any added statement) fail.
    stretch = body[resolve:gate]
    if stretch not in (PINNED_RESOLVE_TO_GATE + "if (detail::", PINNED_RESOLVE_TO_GATE + "if ("):
        pinned = PINNED_RESOLVE_TO_GATE + "if ("
        k = 0
        while k < min(len(stretch), len(pinned)) and stretch[k] == pinned[k]:
            k += 1
        out.append("the text between resolve_session and the gate call is not exactly the pinned "
                   f"session lookup + 401 block (first difference at offset {k}: "
                   f"`{stretch[max(0, k - 20):k + 40]}`)")
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
        audit_body = tb[brace:end + 1] if brace >= 0 and end >= 0 else ""
        unevaluated = UNEVALUATED_OPERATOR.search(stmt)
        if unevaluated:
            out.append(f"`{unevaluated.group(0)}` appears in the same_site_audit_fn_ initialiser: "
                       "an unevaluated operand never calls auth_routes_->audit_log_for_principal(")
        if "auth_routes_->audit_log_for_principal(" not in stmt or audit_body != PINNED_AUDIT_BODY:
            out.append("same_site_audit_fn_ is not initialised from "
                       "auth_routes_->audit_log_for_principal( (the lambda body must be exactly "
                       f"`{PINNED_AUDIT_BODY}`)")
    return out


# ---------------------------------------------------------------------------------------------
# Registration inventory: a second registrar anywhere else replaces the whole handler.

SOURCE_SUFFIXES = frozenset({".cpp", ".hpp", ".h", ".inc", ".inl", ".cc", ".cxx", ".hh", ".hxx",
                             ".ipp", ".mm", ".m"})
# Files other than server.cpp that may call `set_pre_routing_handler`, with the exact number of
# calls each must hold. health_routes.cpp installs the plaintext-to-TLS redirect on its own
# `httplib::Server` object, never on the main web server.
EXPECTED_REGISTRARS = {"health_routes.cpp": 1}


def inventory_problems(src_dir):
    """Problems with the `set_pre_routing_handler` registrations in every source file under
    `src_dir` other than `server.cpp` (which `problems` covers)."""
    src_dir = Path(src_dir)
    if not src_dir.is_dir():
        return [f"the source directory {src_dir} does not exist (registration inventory)"]
    out, seen = [], {}
    for path in sorted(src_dir.rglob("*")):
        rel = path.relative_to(src_dir).as_posix()
        if path.suffix not in SOURCE_SUFFIXES or rel == "server.cpp" or not path.is_file():
            continue
        text = splice_lines(path.read_text(encoding="utf-8", errors="replace"))
        if REGISTRATION not in text:  # cheap pre-filter; the exact scan follows
            continue
        tb = blank_literals(strip_comments(text))
        calls, uses = len(registrations(tb, REGISTRATION)), mentions(tb, REGISTRATION)
        if uses:
            seen[rel] = (calls, uses)
    for rel, want in EXPECTED_REGISTRARS.items():
        calls, uses = seen.pop(rel, (0, 0))
        if calls != want or uses != want:
            out.append(f"{rel} must hold exactly {want} {REGISTRATION}( call and no other use of "
                       f"the name (found {calls} call(s), {uses} use(s))")
    for rel, (calls, uses) in sorted(seen.items()):
        out.append(f"{rel} uses {REGISTRATION} ({calls} call(s), {uses} use(s)): a second "
                   "registrar replaces the pre-routing handler that carries the same-site gate")
    return out


# ---------------------------------------------------------------------------------------------


class SameSiteWiring(unittest.TestCase):
    server_cpp = SERVER_CPP
    src_dir = SRC_DIR

    @classmethod
    def setUpClass(cls):
        cls.raw = cls.server_cpp.read_text(encoding="utf-8")

    def test_source_is_clean(self):
        p = problems(self.raw)
        for m in p:
            print(f"\n::error::{TAG}: {m}{HINT}", file=sys.stderr)
        self.assertEqual(p, [])

    def test_no_other_registrar(self):
        p = inventory_problems(self.src_dir)
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
        elif a == "--src-dir" and args:
            SameSiteWiring.src_dir = Path(args.pop(0))
        elif a == "--repo-root" and args:
            root = Path(args.pop(0))
            SameSiteWiring.src_dir = root / "server" / "core" / "src"
            SameSiteWiring.server_cpp = SameSiteWiring.src_dir / "server.cpp"
        else:
            rest.append(a)
    result = unittest.main(argv=[argv[0]] + rest, exit=False).result
    return 0 if result.wasSuccessful() else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv))
