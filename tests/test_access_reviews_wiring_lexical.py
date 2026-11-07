#!/usr/bin/env python3
"""Static lexical gate over server/core/src/server.cpp's Access reviews registration block.

The route tests stub every dependency, so a permissive gate or a swapped data source in
server.cpp would leave them all green. This gate pins the production wiring of
access_reviews::register_access_reviews_routes( ... ):

  1. `.perm_fn`/`.audit_fn` are the server's; `.quiet_perm_fn` is `draw_perm_fn`; `.probe_perm_fn`
     runs `draw_perm_fn` on a scratch Response (never a constant, never a gate that writes the
     real response).
  2. The campaign reads fail closed on a missing or closed store.
  3. `.grants_fn` reads the grant TABLE through build_access_review (not a roster walk, so orphan
     grants are kept) and stamps access_review_rbac_enforcement.

It also pins two properties of the attestation write path that no route test can see:

  4. Every `record_attestation(` caller outside the store runs `evaluate_attestation_sod(` first, in
     its own handler (today: the REST route and the MCP tool). A third caller without the gate would
     let a reviewer decide a grant they own or belong to. This is a source-text check: a helper
     lambda placed after a gated handler, or `std::bind` / member-pointer use of the call, can
     evade it. The exactly-two-callers assertion is the backstop for that.
  5. Every error string `AccessReviewStore` returns as a DIRECT string literal after `unexpected(`
     is either one of the three machine-checkable prefixes the two classifiers key on, or a string
     recorded here as a genuine fault (503 / internal-error). A new unprefixed client-validation
     string would otherwise be answered as a retryable store failure. A message built in a variable
     (the decision-cap refusal) is outside this check; the classifier test covers it. The REST and
     MCP classifiers must both delegate to the one shared `classify_store_error` (a local copy is
     how they drift apart).

Same method as test_access_audit_wiring_lexical.py (line comments stripped, whitespace
collapsed, in-memory mutations prove each pattern is live; the attest-gate check also strips
block comments). Lexical only.

Usage: python3 tests/test_access_reviews_wiring_lexical.py
"""
import re
import sys
import unittest

from test_access_audit_wiring_lexical import SERVER_CPP, block, normalise

SRC_DIR = SERVER_CPP.parent
STORE_CPP = SRC_DIR / "access_review_store.cpp"

TAG = "test_access_reviews_wiring_lexical"
HINT = (" (this gate pins the Access reviews production wiring; if server.cpp was legitimately"
        " restructured, update tests/test_access_reviews_wiring_lexical.py)")


def problems(src):
    b = block(src, "access_reviews::register_access_reviews_routes(")
    if b is None:
        return ["server.cpp no longer calls access_reviews::register_access_reviews_routes( (or its parens are unbalanced)"]
    out = []
    if ".perm_fn = perm_fn," not in b:
        out.append("reviews .perm_fn is no longer the server's loud perm_fn")
    if ".audit_fn = audit_fn," not in b:
        out.append("reviews .audit_fn is no longer the server's audit_fn")
    if ".quiet_perm_fn = draw_perm_fn," not in b:
        out.append("reviews .quiet_perm_fn is no longer the server's quiet probe (draw_perm_fn)")
    pf = re.search(r"\.probe_perm_fn = (.*?), \.audit_fn", b)
    if not pf or "httplib::Response scratch; return draw_perm_fn(req, scratch, type, op);" not in pf.group(1):
        out.append("reviews .probe_perm_fn is no longer the quiet draw_perm_fn on a scratch Response")
    for name, call in ((".list_campaigns_fn", "access_review_store_->list_campaigns()"),
                       (".get_campaign_fn", "access_review_store_->get_campaign(id, /*include_history=*/true)")):
        m = re.search(re.escape(name) + r" = (.*?)(?=, \.(?:get_campaign_fn|grants_fn)|$)", b)
        body = m.group(1) if m else ""
        if not m:
            out.append(f"reviews {name} is no longer bound")
        else:
            if not re.search(r"if \(!access_review_store_ \|\| !access_review_store_->is_open\(\)\) return std::unexpected\(", body):
                out.append(f"reviews {name} no longer fails closed for a missing or closed store")
            if call not in body:
                out.append(f"reviews {name} no longer reads {call}")
    g = re.search(r"\.grants_fn = (.*)$", b)
    gbody = g.group(1) if g else ""
    if not g:
        out.append("reviews .grants_fn is no longer bound")
    else:
        if "build_access_review(" not in gbody:
            out.append("reviews .grants_fn no longer reads build_access_review")
        if "access_review_rbac_enforcement(rbac_store_.get())" not in gbody:
            out.append("reviews .grants_fn no longer stamps access_review_rbac_enforcement")
        if "if (!rows) return std::unexpected(rows.error());" not in gbody:
            out.append("reviews .grants_fn no longer maps a read failure to std::unexpected")
    if re.search(r"\.probe_perm_fn = \[[^\]]*\]\([^)]*\) -> bool \{ return (true|false)", b):
        out.append("reviews .probe_perm_fn returns a constant")
    return out


# A handler boundary: the nearest one before a record_attestation( call opens its own region.
HANDLER_START = re.compile(r"sink\.(?:Get|Post|Put|Delete)\(|if \(tool_name == ")
CALL = re.compile(r"(?:->|\.)\s*record_attestation\s*\(")


def strip_block_comments(src):
    """A gate named only inside a /* */ comment must not satisfy the check. Local to the gate
    check: the shared `normalise` keeps block comments because other pins match text such as
    `/*include_history=*/true`. A small lexer, not a regex: `/*` appears inside string literals
    and `//` comments in the big route files (a path such as "/api/v1/dex/*"), and a regex would
    swallow hundreds of KB from there to the next `*/`. Dead code (an `if (false)` branch) stays
    out of a lexical gate's reach, so the behavioural SoD tests are the real evidence."""
    out = []
    i, n = 0, len(src)
    while i < n:
        c = src[i]
        two = src[i:i + 2]
        if two == "//":  # line comment: kept verbatim, `normalise` strips it
            j = src.find("\n", i)
            j = n if j < 0 else j
            out.append(src[i:j])
            i = j
        elif two == "/*":
            j = src.find("*/", i + 2)
            i = n if j < 0 else j + 2
            out.append(" ")
        elif c == "R" and src[i + 1:i + 2] == '"' and re.match(r'R"([^()\\ \t\n]{0,16})\(', src[i:i + 24]):
            delim = re.match(r'R"([^()\\ \t\n]{0,16})\(', src[i:i + 24]).group(1)
            end = src.find(")" + delim + '"', i)
            j = n if end < 0 else end + len(delim) + 2
            out.append(src[i:j])
            i = j
        elif c in "\"'":
            j = i + 1
            while j < n and src[j] != c:
                j += 2 if src[j] == "\\" else 1
            out.append(src[i:j + 1])
            i = j + 1
        else:
            out.append(c)
            i += 1
    return "".join(out)


def gate_problems(name, src):
    """Every record_attestation( call in `src` has evaluate_attestation_sod( earlier in its handler."""
    t = normalise(strip_block_comments(src))
    out = []
    for call in CALL.finditer(t):
        starts = [m.start() for m in HANDLER_START.finditer(t, 0, call.start())]
        region = t[(starts[-1] if starts else 0):call.start()]
        if "evaluate_attestation_sod(" not in region:
            out.append(f"{name}: a record_attestation( call is not preceded by evaluate_attestation_sod( in its handler")
    return out


def attesting_sources():
    for path in sorted(SRC_DIR.glob("*.[ch]pp")):
        if path.name.startswith("access_review_store."):
            continue
        yield path


# Unprefixed store errors, all answered 503 / internal-error. Entries are matched as prefixes. The
# first six are validation strings the handlers pre-empt (never reachable through them today).
KNOWN_UNPREFIXED = (
    "database not open", "title cannot be empty", "created_by cannot be empty",
    "rbac_enforcement must be", "decision must be", "campaign_id/principal_type",
    "closed_by cannot be empty", "open_campaign failed", "record_attestation failed",
    "get_campaign failed", "database unavailable", "close_campaign write failed",
    "list_campaigns read failed",
)
PREFIXES = ("not_found:", "bad_request:", "forbidden:")
UNEXPECTED = re.compile(r'unexpected\(\s*(?:error_msg\.empty\(\)\s*\?\s*|std::string\()?"((?:[^"\\]|\\.)*)"')


def store_error_problems(src):
    out = []
    for m in UNEXPECTED.finditer(src):
        lit = m.group(1)
        if lit.startswith(PREFIXES) or lit.startswith(KNOWN_UNPREFIXED):
            continue
        out.append(f"access_review_store.cpp returns an unclassified error string: {lit!r}")
    return out


# (pattern, replacement, expected substring of a problem)
MUTATIONS = [
    (r"httplib::Response scratch;\s*return draw_perm_fn\(req, scratch, type, op\);", "return true;",
     "probe_perm_fn"),
    (r"\.quiet_perm_fn = draw_perm_fn,(\s*\.probe_perm_fn)", r".quiet_perm_fn = perm_fn,\1", "quiet_perm_fn"),
    (r"if \(!access_review_store_ \|\| !access_review_store_->is_open\(\)\)\s*return std::unexpected\(std::string\(\"access review store not open\"\)\);\s*return access_review_store_->list_campaigns\(\);",
     "return access_review_store_->list_campaigns();", "list_campaigns_fn"),
    (r"build_access_review\(auth_mgr_", "build_roster(auth_mgr_", "build_access_review"),
    (r"access_reviews::register_access_reviews_routes\(", "access_reviews::register_access_reviews_route(",
     "register_access_reviews_routes"),
]


class ReviewsWiring(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.raw = SERVER_CPP.read_text(encoding="utf-8")

    def test_source_is_clean(self):
        p = problems(self.raw)
        for m in p:
            print(f"\n::error::{TAG}: {m}{HINT}", file=sys.stderr)
        self.assertEqual(p, [])

    def test_mutations_are_caught(self):
        for i, (pat, repl, expected) in enumerate(MUTATIONS, 1):
            with self.subTest(mutation=i, pattern=pat):
                mutated, n = re.subn(pat, repl, self.raw, count=1)
                self.assertGreaterEqual(n, 1, "mutation changed nothing (stale pattern)")
                p = problems(mutated)
                self.assertTrue(p, "mutation was NOT detected by the gate")
                self.assertIn(expected, p[0])

GATED = 'sink.Post(R"(/x)", [](auto&) { auto v = access_review_sod::evaluate_attestation_sod(a); s->record_attestation(b); });'
UNGATED = 'sink.Post(R"(/x)", [](auto&) { s->record_attestation(b); });'
BLOCK_COMMENT_GATE = ('sink.Post(R"(/x)", [](auto&) { /* evaluate_attestation_sod(a); */'
                      ' s->record_attestation(b); });')
LINE_COMMENT_GATE = ('sink.Post(R"(/x)", [](auto&) {\n // evaluate_attestation_sod(a);\n'
                     ' s->record_attestation(b); });')
STRING_WITH_COMMENT_OPENER = ('sink.Get(R"(/api/v1/dex/*)", [](auto&) { return 1; });'
                              ' sink.Post(R"(/x)", [](auto&) { s->record_attestation(b); }); /* x */')
STALE_GATE = ('sink.Post(R"(/a)", [](auto&) { evaluate_attestation_sod(a); });'
              ' sink.Post(R"(/b)", [](auto&) { s->record_attestation(b); });')


class AttestGate(unittest.TestCase):
    def test_real_callers_are_gated(self):
        callers = 0
        for path in attesting_sources():
            text = path.read_text(encoding="utf-8")
            callers += len(CALL.findall(normalise(strip_block_comments(text))))
            p = gate_problems(path.name, text)
            for m in p:
                print(f"\n::error::{TAG}: {m}{HINT}", file=sys.stderr)
            self.assertEqual(p, [])
        # rest_api_v1.cpp and mcp_server.cpp: a lexer that lost the calls must not pass silently.
        self.assertEqual(callers, 2)

    def test_pattern_is_live(self):
        self.assertEqual(gate_problems("f", GATED), [])
        self.assertEqual(len(gate_problems("f", UNGATED)), 1)
        # A gate in another handler earlier in the file does not cover a later ungated one.
        self.assertEqual(len(gate_problems("f", STALE_GATE)), 1)
        self.assertEqual(len(gate_problems("f", GATED + " " + UNGATED)), 1)

    def test_a_gate_named_only_in_a_comment_does_not_count(self):
        # Block and line comments are stripped before the check, so neither satisfies it.
        self.assertEqual(len(gate_problems("f", BLOCK_COMMENT_GATE)), 1)
        self.assertEqual(len(gate_problems("f", LINE_COMMENT_GATE)), 1)

    def test_a_comment_opener_inside_a_string_does_not_hide_a_later_call(self):
        # A regex stripper would swallow from the "/*" in the path string to the final "*/" and
        # miss the ungated call; the lexer must keep it.
        self.assertEqual(len(gate_problems("f", STRING_WITH_COMMENT_OPENER)), 1)


class StoreAuthorship(unittest.TestCase):
    """The store authors every time column from the database clock and reads the frozen owner under
    the shared snapshot key: pin both so a revert or a rename cannot pass silently."""

    def setUp(self):
        self.store = normalise((SRC_DIR / "access_review_store.cpp").read_text(encoding="utf-8"))

    def test_no_replica_clock_in_the_store(self):
        self.assertNotIn("system_clock", self.store)
        self.assertNotIn("now_ms(", self.store)

    def test_each_time_statement_uses_the_database_clock(self):
        # definition + open (created_at_ms) + attest history and state (decided_at_ms) + close
        self.assertGreaterEqual(self.store.count("kDbNowMsSql"), 5)
        for col in ("created_at_ms", "decided_at_ms", "closed_at_ms"):
            self.assertIn(col, self.store)

    def test_snapshot_owner_key_is_shared(self):
        self.assertIn("kSnapshotOwnerKey", self.store)
        for name in ("rest_api_v1.cpp", "mcp_server.cpp"):
            text = normalise((SRC_DIR / name).read_text(encoding="utf-8"))
            self.assertIn(".add(kSnapshotOwnerKey, r.owner_or_email)", text,
                          f"{name}: the open-campaign snapshot no longer uses the shared owner key")


class DashboardDecisionFeedback(unittest.TestCase):
    """Both dashboard surfaces must say when a decision replaced another one, and the Settings
    buttons must stay disabled while a request is in flight (each extra click appends a decision)."""

    def test_settings_script_guards_and_reports(self):
        t = normalise((SRC_DIR / "settings_routes.cpp").read_text(encoding="utf-8"))
        at = t.find("function arAttest(")
        self.assertGreaterEqual(at, 0, "arAttest no longer defined")
        body = t[at:at + 2600]
        self.assertIn("arSetBusy(true)", body, "Settings Attest/Flag buttons are not disabled in flight")
        self.assertIn("arSetBusy(false)", body, "Settings buttons are never re-enabled after a failure")
        self.assertIn("previous_decision", body, "Settings does not report a replaced decision")

    def test_access_page_script_reports_a_replaced_decision(self):
        raw = (SRC_DIR.parent / "static" / "yuzu-audit.js").read_text(encoding="utf-8")
        # Comments are not code: a comment naming previous_decision must not satisfy the pin.
        js = re.sub(r"/\*.*?\*/", " ", re.sub(r"(?m)^\s*//.*$", "", raw), flags=re.S)
        at = js.find("function decide(")
        self.assertGreaterEqual(at, 0, "decide() no longer defined")
        body = js[at:at + 1800]
        self.assertIn("previous_decision", body, "Access page ignores previous_decision")
        self.assertRegex(body, r"prev\s*!==\s*'pending'[^;]*\n?[^;]*banner\(",
                         "Access page does not show a notice for a replaced decision")


CLASSIFIERS = (
    ("rest_api_v1.cpp", "static int access_review_error_status(const std::string& err) {",
     "store_error_http_status(access_review_sod::classify_store_error(err))"),
    ("mcp_server.cpp", "int mcp_error_for_access_review_msg(const std::string& msg) {",
     "store_error_jsonrpc_code(access_review_sod::classify_store_error(msg))"),
)


def classifier_problems(name, src, head, call):
    t = normalise(src)
    at = t.find(head)
    if at < 0:
        return [f"{name}: the access review store-error classifier is no longer defined as `{head}`"]
    body = t[at + len(head):t.find("}", at)]
    if call not in body:
        return [f"{name}: the access review store-error classifier no longer delegates to the shared classify_store_error"]
    return []


class StoreErrorStrings(unittest.TestCase):
    def test_both_classifiers_delegate(self):
        for name, head, call in CLASSIFIERS:
            text = (SRC_DIR / name).read_text(encoding="utf-8")
            p = classifier_problems(name, text, head, call)
            for m in p:
                print(f"\n::error::{TAG}: {m}{HINT}", file=sys.stderr)
            self.assertEqual(p, [])
            # Pattern is live: a local prefix test in the same body is caught.
            local = text.replace(call, 'err.starts_with("not_found:") ? 404 : 503', 1)
            self.assertTrue(classifier_problems(name, local, head, call))

    def test_every_error_string_is_classified(self):
        src = STORE_CPP.read_text(encoding="utf-8")
        self.assertGreaterEqual(len(UNEXPECTED.findall(src)), 25, "lexer lost the error strings")
        p = store_error_problems(src)
        for m in p:
            print(f"\n::error::{TAG}: {m}{HINT}", file=sys.stderr)
        self.assertEqual(p, [])

    def test_pattern_is_live(self):
        self.assertEqual(store_error_problems('return std::unexpected("bad_request: x");'), [])
        self.assertEqual(store_error_problems('return std::unexpected("database not open");'), [])
        self.assertEqual(len(store_error_problems('return std::unexpected("title is too long");')), 1)


SETTINGS_CPP = SRC_DIR / "settings_routes.cpp"


def settings_error_problems(src):
    """The Settings panel's arPost must show the error MESSAGE: the A4 envelope is
    {error: {message, ...}}, so reading `data.error` alone shows "[object Object]" for every refusal."""
    t = normalise(src)
    at = t.find("function arPost(")
    if at < 0:
        return ["settings_routes.cpp: the Settings access review script no longer defines arPost"]
    body = t[at:t.find("function arLoadCampaign(", at)]
    if "e.message" not in body or "data.error ||" in body:
        return ["settings_routes.cpp: arPost does not read error.message (a refusal would show [object Object])"]
    at = t.find("function arOpenCampaign(")
    open_body = t[at:t.find("function arAttest(", at)] if at >= 0 else ""
    if "data.data" not in open_body:
        return ["settings_routes.cpp: arOpenCampaign does not read the campaign id from the A4 envelope (data.data.campaign_id)"]
    return []


class SettingsErrorMessage(unittest.TestCase):
    def test_arpost_reads_the_message(self):
        p = settings_error_problems(SETTINGS_CPP.read_text(encoding="utf-8"))
        for m in p:
            print(f"\n::error::{TAG}: {m}{HINT}", file=sys.stderr)
        self.assertEqual(p, [])

    def test_pattern_is_live(self):
        text = SETTINGS_CPP.read_text(encoding="utf-8")
        self.assertTrue(settings_error_problems(text.replace("e.message", "e.msg")))
        # Restoring `data.error ||` while keeping e.message is caught on its own.
        self.assertTrue(settings_error_problems(
            text.replace("var e = data && data.error;", "var e = data && data.error; var m = data.error || 1;")))
        # Reading the campaign id from the unwrapped body is caught.
        self.assertTrue(settings_error_problems(text.replace("data && data.data", "data")))
        self.assertTrue(settings_error_problems(text.replace("var e = data && data.error;",
                                                             "var e = data.error || data.message;")
                                                .replace("e.message", "x")))


UPGRADING_MD = SRC_DIR.parent.parent.parent / "docs" / "user-manual" / "upgrading.md"
BOOT_REFUSAL = "[PG] Refusing to start: access-review store migration/open failed"
MIGRATION_REFUSAL = "decision row(s) were recorded by the subject of the grant under an earlier build"


def boot_refusal_problems(server_src, store_src, doc):
    """The operator's way to find the schema v3 refusal is the log text the upgrade note quotes."""
    out = []
    # server.cpp splits the literal over two lines; compare the first fragment and the flag.
    at = server_src.find("Refusing to start: access-review store migration/open failed")
    if at < 0 or "[PG] " not in server_src[max(0, at - 12):at + 1]:
        out.append("server.cpp no longer logs the access-review store boot refusal text")
    elif "startup_failed_ = true" not in server_src[at:at + 900]:
        out.append("the access-review store boot refusal no longer sets startup_failed_")
    if MIGRATION_REFUSAL not in store_src:
        out.append("access_review_store.cpp no longer carries the schema v3 migration refusal text")
    if BOOT_REFUSAL not in doc or MIGRATION_REFUSAL not in doc:
        out.append("docs/user-manual/upgrading.md no longer quotes the access-review boot and migration refusal text")
    if "**Fresh database only.**" not in doc:
        out.append("docs/user-manual/upgrading.md lost the 'Fresh database only' paragraph of the #4752 section")
    return out


class BootRefusalDocs(unittest.TestCase):
    def sources(self):
        return (SERVER_CPP.read_text(encoding="utf-8"), STORE_CPP.read_text(encoding="utf-8"),
                UPGRADING_MD.read_text(encoding="utf-8"))

    def test_refusal_text_and_doc_agree(self):
        p = boot_refusal_problems(*self.sources())
        for m in p:
            print(f"\n::error::{TAG}: {m}{HINT}", file=sys.stderr)
        self.assertEqual(p, [])

    def test_pattern_is_live(self):
        server, store, doc = self.sources()
        self.assertTrue(boot_refusal_problems(server.replace("Refusing to start: access-review store", "Refusing: access-review store"), store, doc))
        self.assertTrue(boot_refusal_problems(server, store.replace(MIGRATION_REFUSAL, "x"), doc))
        self.assertTrue(boot_refusal_problems(server, store, doc.replace("**Fresh database only.**", "**Fresh.**")))
        self.assertTrue(boot_refusal_problems(server, store, doc.replace(BOOT_REFUSAL, "x")))


if __name__ == "__main__":
    sys.exit(0 if unittest.main(exit=False).result.wasSuccessful() else 1)
