#!/usr/bin/env python3
"""BEST-EFFORT lexical tripwire (WP03): every production verifier of a second-factor code is
budgeted, per handler.

`AuthDB::mfa_verify_login_code` / `mfa_consume_recovery_code` are the two guessable checks. Outside
auth_db.* they may be called ONLY from server/core/src/auth_routes.cpp. Inside it, each of the two
budgeted handlers (`/login/mfa`, `/login/mfa/stepup`; the enroll handler between them is
deliberately not budgeted and must call neither) must, in this order and inside its own body:
  1. take the PBKDF2 slot (`acquire_pbkdf2(`) for recovery-shaped codes,
  2. `mfa_budget_reserve(`,
  3. only then call a verifier (exactly two verifier calls per handler),
  4. settle the reservation (`mfa_budget_note_failure(` and `mfa_budget_refund(`).
It also pins the break-glass arm state at `/login/mfa` and the tri-state gate (WP03):
  a. the pending token records `break_glass`; exactly two gate calls, each first in its own
     `if (entry.break_glass) {`;
  b. re-check #1 precedes the reservation and every verifier, records `arm1` from an armed
     answer, and both of its refusals return;
  c. re-check #2 samples ONE clock value on the statement after its gate call, admits only with
     `arm1` set and (armed, or the bounded transient rule with all four clauses), returns on a
     refusal, and nothing but the MintDenial declaration sits between it and the mint;
  d. the gate result has no comparison operator and no conversion, nothing spells
     `!= SsoOnlyLocalGate::kRefused`, and the password-change gate uses the one admit set;
  e. the gate applies the 4.5 s cap on both of its armed return paths and writes the
     last-not-armed time in one place only.
The script also runs a SELFTEST that deletes each of those anchors from an in-memory copy and
requires the check to fail, so a tripwire that stops tripping is itself a failure. Not proof: the
unit tests drive the behaviour.
"""
import pathlib
import re
import sys

SRC = pathlib.Path(__file__).resolve().parent.parent / "server" / "core" / "src"
CALL = re.compile(r"(?:->|\.)\s*(mfa_verify_login_code|mfa_consume_recovery_code)\s*\(")


def strip_comments(t):
    t = re.sub(r"/\*.*?\*/", "", t, flags=re.S)
    return re.sub(r"//[^\n]*", "", t)


def handler(t, start_pat, end_pat):
    a = t.find(start_pat)
    b = t.find(end_pat, a + 1) if a >= 0 else -1
    return (a, b) if a >= 0 and b > a else None


def check_routes(t):
    """t = comment-stripped auth_routes.cpp. Returns a list of problems."""
    bad = []
    spans = {
        "/login/mfa": handler(t, 'sink.Post("/login/mfa",', 'sink.Post("/login/mfa/enroll"'),
        "/login/mfa/enroll": handler(t, 'sink.Post("/login/mfa/enroll"', 'sink.Post("/login/mfa/stepup"'),
        "/login/mfa/stepup": handler(t, 'sink.Post("/login/mfa/stepup"', 'sink.Post("/logout"'),
    }
    for name, sp in spans.items():
        if sp is None:
            bad.append(f"handler {name} not found")
    if bad:
        return bad
    a, b = spans["/login/mfa/enroll"]
    if CALL.search(t[a:b]):
        bad.append("the unbudgeted enroll handler calls a code verifier")
    for name in ("/login/mfa", "/login/mfa/stepup"):
        a, b = spans[name]
        body = t[a:b]
        calls = [m.start() for m in CALL.finditer(body)]
        if len(calls) != 2:
            bad.append(f"{name}: expected 2 verifier calls, found {len(calls)}")
            continue
        acq = body.find("acquire_pbkdf2(")
        res = body.find("mfa_budget_reserve(")
        if res < 0:
            bad.append(f"{name}: no mfa_budget_reserve(")
        elif res > calls[0]:
            bad.append(f"{name}: mfa_budget_reserve( is after the first verifier call")
        if acq < 0:
            bad.append(f"{name}: no acquire_pbkdf2(")
        elif res >= 0 and acq > res:
            bad.append(f"{name}: acquire_pbkdf2( must precede mfa_budget_reserve(")
        for tok in ("mfa_budget_note_failure(", "mfa_budget_refund("):
            if tok not in body:
                bad.append(f"{name}: {tok} missing")
    return bad


def check_gate_order(t, hpp="", server=""):
    """verify_password_with_lockout shape (token/regex level, see LIMITS): the sso-only gate FIRST;
    the break-glass slot (every attempt, no over-length shortcut) before the stripe; the ordinary
    slot likewise; the stripe only for lockout_active, with defer_lock, try_lock first and the
    bounded kLoginStripeWait; the per-stripe and global waiter comparisons present as written."""
    a = t.find("AuthRoutes::verify_password_with_lockout(")
    if a < 0:
        return ["verify_password_with_lockout not found"]
    body = t[a:]
    fn_end = body.find("PasswordVerifyFn AuthRoutes::password_change_verify_fn")
    fn = body if fn_end < 0 else body[:fn_end]
    gate = fn.find("opts.pre_verify_gate()")
    bg_slot = fn.find("acquire_pbkdf2(Pbkdf2Class::kBreakGlass")
    stripe = fn.find("try_lock_for(kLoginStripeWait)")
    slot = fn.find("acquire_pbkdf2(!login_route")
    anchors = {"pre_verify_gate": gate, "break-glass slot": bg_slot,
               "stripe try_lock_for": stripe, "ordinary slot": slot}
    missing = [k for k, v in anchors.items() if v < 0]
    if missing:
        return [f"anchors missing: {missing}"]
    bad = []
    if not gate < bg_slot:
        bad.append("the sso-only pre_verify_gate must run BEFORE the break-glass slot (its arm-state "
                   "read is cached and single-flight, so this position cannot park workers)")
    if not gate < stripe or not gate < slot:
        bad.append("the sso-only pre_verify_gate must run before the stripe and the ordinary slot")
    if not re.search(r"if \(break_glass_attempt\) \{\s*pbkdf2_slot\.emplace\(acquire_pbkdf2\(Pbkdf2Class::kBreakGlass", fn):
        bad.append("the break-glass slot must be taken for EVERY break-glass attempt "
                   "(`if (break_glass_attempt) {`, no over-length shortcut)")
    if not re.search(r"if \(!break_glass_attempt\) \{\s*const bool login_route", fn):
        bad.append("the ordinary slot must be taken for EVERY attempt "
                   "(`if (!break_glass_attempt) {`, no over-length shortcut)")
    if re.search(r"password_exceeds_max\(password\)\)?\s*\{\s*(?:const bool login_route|pbkdf2_slot)", fn):
        bad.append("a slot must not be skipped for an over-length password")
    if "if (lockout_active)" not in fn[:stripe][-1500:]:
        bad.append("the login stripe must be taken only when lockout_active")
    if not re.search(r"login_lk\s*=\s*std::unique_lock<std::timed_mutex>\(login_lock_for\(username\),\s*std::defer_lock\)", fn):
        bad.append("the login stripe unique_lock must be constructed with std::defer_lock")
    if re.search(r"login_lock_for\([^)]*\)\s*\.\s*lock\(\)|login_lk\.lock\(\)", fn):
        bad.append("the login stripe must never be locked unboundedly")
    if re.search(r"(?:lock_guard|scoped_lock)<std::timed_mutex>", fn):
        bad.append("no lock_guard/scoped_lock on a login stripe (unbounded wait)")
    if "try_lock_for(std::chrono" in fn:
        bad.append("the stripe wait must be kLoginStripeWait, not an ad-hoc duration")
    if not re.search(r"if \(!login_lk\.try_lock\(\)\) \{", fn):
        bad.append("the stripe lock must be TRIED first (only a would-be waiter counts)")
    if not re.search(r"if \(stripe_waiter\.prior\(\) >= kStripeWaitersPerStripe\) \{[^}]*return \{PasswordCheckOutcome::kBusy", fn):
        bad.append("the per-stripe waiter comparison must be present and return kBusy")
    if not re.search(r"BoundedWaiterGuard waiter\(stripe_waiters_,\s*stripe_waiter_cap_\.load\(std::memory_order_relaxed\)\);\s*if \(!waiter\.admitted\(\)\) \{[^}]*return \{PasswordCheckOutcome::kBusy", fn):
        bad.append("the global waiter ceiling comparison must be present and return kBusy")
    if hpp:
        if not re.search(r"kLoginStripeWait\{150\}", hpp):
            bad.append("kLoginStripeWait must be 150 ms (auth_routes.hpp)")
        if not re.search(r"kStripeWaitersPerStripe\s*=\s*2\b", hpp):
            bad.append("kStripeWaitersPerStripe must be 2 (auth_routes.hpp)")
    if server:
        # Line-anchored statements: a commented-out call, a token inside a string literal and an
        # altered argument all fail these (the sizing helper is the single source, unit-tested).
        for pat, what in (
            (r"(?m)^\s*const auto sz = yuzu::server::login_sizing\(pool_max, cfg_\.auth_pbkdf2_per_source_cap\);",
             "const auto sz = login_sizing(pool_max, cfg_.auth_pbkdf2_per_source_cap)"),
            (r"(?m)^\s*auth_routes_->set_pbkdf2_cap\(sz\.cap\);", "auth_routes_->set_pbkdf2_cap(sz.cap)"),
            (r"(?m)^\s*auth_routes_->set_stripe_waiter_cap\(sz\.stripe_waiters\);",
             "auth_routes_->set_stripe_waiter_cap(sz.stripe_waiters)"),
            (r"(?m)^\s*auth_routes_->pbkdf2_budget\(\)\.set_per_source_cap\(cfg_\.auth_pbkdf2_per_source_cap\);",
             "set_per_source_cap(cfg_.auth_pbkdf2_per_source_cap)"),
        ):
            if not re.search(pat, server):
                bad.append(f"server.cpp must contain the statement {what} (production sizing)")
    return bad


GATE1 = "const SsoOnlyGateResult gate1 = sso_only_local_password_gate(entry.username);"
GATE2 = ("const SsoOnlyGateResult gate2 =\n                "
         "sso_only_local_password_gate(entry.username, SsoOnlyArmRead::kOwnFreshRead);")
ADMIT_SET = "return state == SsoOnlyLocalGate::kOpen || state == SsoOnlyLocalGate::kBreakGlassArmed;"


def _ws(t):
    return re.sub(r"\s+", " ", t).strip()


def _block_end(t, open_idx):
    """Index just past the brace block that opens at t[open_idx] == '{' (no string awareness;
    the pinned blocks hold no brace inside a literal)."""
    depth = 0
    for i in range(open_idx, len(t)):
        if t[i] == "{":
            depth += 1
        elif t[i] == "}":
            depth -= 1
            if depth == 0:
                return i + 1
    return -1


FOR_TEST_DECL = re.compile(r"\b(\w+_for_test)\s*\(")
PRODUCTION_TREES = ("server", "agents", "common", "sdk", "enterprise")


_PROD_CACHE = {}
_SEAM_SCAN_CACHE = {}


def load_production_sources():
    """Every C++ source and header outside tests/ that mentions `_for_test` (comment-stripped),
    keyed by repo-relative path. Read once per run."""
    if "files" in _PROD_CACHE:
        return _PROD_CACHE["files"]
    root = SRC.parent.parent.parent
    out = {}
    for tree in PRODUCTION_TREES:
        base = root / tree
        if not base.is_dir():
            continue
        for p in sorted(base.rglob("*")):
            if p.suffix not in (".cpp", ".hpp", ".h", ".cc", ".mm") or not p.is_file():
                continue
            rel = p.relative_to(root).as_posix()
            if "/tests/" in "/" + rel or "vcpkg_installed" in rel or p.name == "server.cpp":
                continue
            raw = p.read_text(encoding="utf-8", errors="replace")
            if "_for_test" in raw:
                out[rel] = strip_comments(raw)
    # server.cpp is read raw (see load()); a *_for_test( call in it is a call either way.
    sp = root / "server" / "core" / "src" / "server.cpp"
    if sp.is_file():
        out["server/core/src/server.cpp"] = sp.read_text(encoding="utf-8", errors="replace")
    _PROD_CACHE["files"] = out
    return out


def check_for_test_callers(files):
    """No file outside tests/ calls a *_for_test member of AuthRoutes. The names are read from
    auth_routes.hpp; auth_routes.hpp declares them and auth_routes.cpp may DEFINE them
    (`AuthRoutes::name(`), nothing else may spell `name(`."""
    hpp = files.get("auth_routes.hpp", "")
    names = sorted(set(FOR_TEST_DECL.findall(hpp)))
    if not names:
        return ["no *_for_test member found in auth_routes.hpp (the pin has nothing to check)"]
    prod = files.get("__production__")
    key = None
    if prod is None:
        key = tuple(names)
        if key in _SEAM_SCAN_CACHE:  # the real tree does not change between selftest mutants
            return list(_SEAM_SCAN_CACHE[key])
        prod = load_production_sources()
    bad = []
    for rel, text in prod.items():
        if rel.endswith("server/core/src/auth_routes.hpp"):
            continue
        for n in names:
            for m in re.finditer(r"\b" + re.escape(n) + r"\s*\(", text):
                if rel.endswith("server/core/src/auth_routes.cpp") and \
                        text[max(0, m.start() - 12):m.start()].endswith("AuthRoutes::"):
                    continue  # the out-of-line definition
                bad.append(f"{rel}: calls AuthRoutes test seam {n}( outside tests/")
    if key is not None:
        _SEAM_SCAN_CACHE[key] = list(bad)
    return bad


def check_arm_recheck(files):
    """WP03: the break-glass arm state at the MFA step and the tri-state gate (see the module
    docstring's second list). Token level, like the rest of this file."""
    bad = []
    t = files.get("auth_routes.cpp", "")
    hpp = files.get("auth_routes.hpp", "")
    sp = handler(t, 'sink.Post("/login/mfa",', 'sink.Post("/login/mfa/enroll"')
    if sp is None:
        return ["handler /login/mfa not found (arm re-check)"]
    body = t[sp[0]:sp[1]]
    # The pending token records that the password step was the armed break-glass account's.
    if not re.search(r"entry\.break_glass = break_glass_login;", t):
        bad.append("the pending token must record break_glass (entry.break_glass = break_glass_login;)")
    # Exactly two gate calls, each inside `if (entry.break_glass) {`.
    if body.count("sso_only_local_password_gate(") != 2:
        bad.append(f"/login/mfa: expected 2 arm-gate calls, found {body.count('sso_only_local_password_gate(')}")
    for g in (GATE1, GATE2):
        if not re.search(r"if \(entry\.break_glass\) \{\s*" + re.escape(g), body):
            bad.append(f"/login/mfa: `{g}` must be the first statement of `if (entry.break_glass) {{`")
    g1, g2 = body.find(GATE1), body.find(GATE2)
    res = body.find("mfa_budget_reserve(")
    calls = [m.start() for m in CALL.finditer(body)]
    mint = body.find("create_local_session(")
    if min(g1, g2, res, mint) < 0 or not calls:
        return bad + ["/login/mfa: arm re-check anchors missing"]
    # Re-check #1 is before the reservation and before any verifier, and both of its refusals return.
    if not g1 < res or not g1 < calls[0]:
        bad.append("/login/mfa: the first arm re-check must precede mfa_budget_reserve( and the first verifier")
    if g1 < res and body[g1:res].count("return;") != 2:
        bad.append("/login/mfa: the first arm re-check must have exactly two refusals, each ending in return;")
    if "arm1 = ArmSnapshot{gate1.arm_id, gate1.deadline, gate1.read_at, gate1.read_wall_at};" not in body[g1:res]:
        bad.append("/login/mfa: the first arm re-check must record arm1 from the armed answer, with the wall "
                   "time at which THAT read started (gate1.read_wall_at), not a sample taken after the gate returned")
    for stmt in ("const bool superseded1 = gate1.state == SsoOnlyLocalGate::kBreakGlassArmed && "
                 "gate1.last_not_armed_at && *gate1.last_not_armed_at >= gate1.read_at;",
                 "if (gate1.state == SsoOnlyLocalGate::kBreakGlassArmed && !superseded1) {"):
        if stmt not in _ws(body[g1:res]):
            bad.append(f"/login/mfa: the first arm re-check must contain `{stmt}` (an armed answer older "
                       "than a not-armed read this server holds is refused before anything is spent)")
    if "arm_wall_clock_now()" in body[g1:res]:
        bad.append("/login/mfa: no wall-clock sample between the first gate call and the reservation "
                   "(the anchor is the read's start, carried by the gate)")
    # Re-check #2: the gate, then ONE clock sample, then the decision, then the mint.
    if not calls[-1] < g2 < mint:
        bad.append("/login/mfa: the second arm re-check must be after the verifiers and before the mint")
    seg = body[g2:mint] if g2 < mint else ""
    if not re.search(re.escape(GATE2) + r"\s*const auto now2 = arm_clock_now\(\);", body):
        bad.append("/login/mfa: now2 must be sampled on the statement after the second gate call")
    if seg.count("arm_clock_now()") != 1:
        bad.append("/login/mfa: exactly one clock sample between the second gate call and the mint")
    # The wall clock (suspend detection) is sampled once, right after now2, and appears only in the
    # refusing clause: wall time is never evidence for admitting.
    if not re.search(r"const auto now2 = arm_clock_now\(\);\s*const auto wall2 = arm_wall_clock_now\(\);", seg):
        bad.append("/login/mfa: wall2 must be sampled on the statement after now2")
    if seg.count("arm_wall_clock_now()") != 1 or seg.count("wall2") != 2:
        bad.append("/login/mfa: exactly one wall-clock sample, used only in the transient admit rule")
    for clause in ("gate2.state == SsoOnlyLocalGate::kTransient",
                   "!arm1->arm_id.empty()",
                   "now2 < arm1->deadline",
                   "arm_observation_fresh(arm1->read_at, now2)",
                   "wall2 - arm1->wall_at <= kArmSnapshotMaxAge",
                   "gate2.arm_id == arm1->arm_id",
                   "!(gate2.last_not_armed_at && *gate2.last_not_armed_at >= arm1->read_at)"):
        if clause not in seg:
            bad.append(f"/login/mfa: the transient admit rule must contain `{clause}`")
    # C-01 (PR #8626 review): an ARMED own read is also tested for supersession, against the own
    # read's own start: a not-armed read recorded at or after it started refuses.
    if not re.search(r"const bool armed_ok =\s*gate2\.state == SsoOnlyLocalGate::kBreakGlassArmed &&\s*"
                     r"!\(gate2\.last_not_armed_at && \*gate2\.last_not_armed_at >= gate2\.read_at\);", seg):
        bad.append("/login/mfa: armed_ok must be `armed && !(gate2.last_not_armed_at && "
                   "*gate2.last_not_armed_at >= gate2.read_at)` (an armed own read is superseded "
                   "by a not-armed read that ended at or after it started)")
    if not re.search(r"const bool admit =\s*arm1\.has_value\(\) &&\s*"
                     r"\(armed_ok \|\| transient_ok\);", seg):
        bad.append("/login/mfa: admit must be `arm1.has_value() && (armed_ok || transient_ok)` "
                   "(a login with no first-re-check snapshot never mints)")
    refuse = seg.find("if (!admit) {")
    if refuse < 0:
        bad.append("/login/mfa: `if (!admit) {` missing")
    else:
        end = _block_end(seg, refuse + len("if (!admit) "))
        blk = seg[refuse:end] if end > 0 else ""
        if "return;" not in blk:
            bad.append("/login/mfa: the second arm re-check's refusal must return")
        tail = _ws(seg[end:]) if end > 0 else ""
        want = ("admitted_under_transient = gate2.state == SsoOnlyLocalGate::kTransient; } "
                "auth::AuthManager::MintDenial denial = auth::AuthManager::MintDenial::kNone; "
                "auto token = auth_mgr_.")
        if tail != want:
            bad.append("/login/mfa: nothing but the transient marker and the MintDenial declaration "
                       "may sit between the second arm re-check and the mint")
    if 'counter("yuzu_auth_break_glass_pending_refused_total")' in t:
        bad.append("yuzu_auth_break_glass_pending_refused_total must carry reason and stage labels")
    # The gate result cannot be compared with, or converted to, the bare state.
    for name, text in files.items():
        if name.startswith("__"):
            continue
        if "!= SsoOnlyLocalGate::kRefused" in text:
            bad.append(f"{name}: `!= SsoOnlyLocalGate::kRefused` admits kTransient; name the admitted states")
    if re.search(r"operator\s*[!=]=\s*\([^)]*SsoOnlyGateResult", hpp) or \
            re.search(r"operator\s+SsoOnlyLocalGate\b", hpp):
        bad.append("SsoOnlyGateResult must have no comparison operator and no conversion")
    for term in ("!SsoGateEqComparable<SsoOnlyGateResult, SsoOnlyLocalGate>",
                 "!SsoGateNeComparable<SsoOnlyGateResult, SsoOnlyLocalGate>",
                 "!std::is_convertible_v<SsoOnlyGateResult, SsoOnlyLocalGate>"):
        if term not in hpp:
            bad.append(f"auth_routes.hpp: the static_assert term `{term}` is missing")
    if ADMIT_SET not in hpp:
        bad.append("admits_password_evaluation() must admit exactly kOpen and kBreakGlassArmed")
    a = t.find("PasswordVerifyFn AuthRoutes::password_change_verify_fn()")
    b = t.find("SsoOnlyGateResult AuthRoutes::sso_only_local_password_gate(")
    if a < 0 or b < a:
        bad.append("password_change_verify_fn / the gate definition not found")
    else:
        if "return sso_only_local_password_gate(username).admits_password_evaluation();" not in t[a:b]:
            bad.append("the password-change gate must be `...admits_password_evaluation()`")
        gate_end = t.find("void AuthRoutes::register_routes(", b)
        gate = t[b:gate_end]
        for stmt in ("if (!arm_observation_fresh(bg_arm_started_, now)) {",
                     "if (armed_now && !arm_observation_fresh(started, finished)) {"):
            if stmt not in gate:
                bad.append(f"the gate must apply the cap as `{stmt}`")
        # The wall anchor of a cached snapshot is the wall time when its read STARTED (UP-1b).
        if "const auto started_wall = arm_wall_clock_now();" not in gate or \
                gate.find("const auto started_wall = arm_wall_clock_now();") > gate.find("read = hook();"):
            bad.append("the gate must sample `started_wall` before the read")
        for stmt in ("bg_arm_started_wall_ = started_wall;", "out.read_wall_at = bg_arm_started_wall_;",
                     "out.read_wall_at = started_wall;"):
            if stmt not in gate:
                bad.append(f"the gate must contain `{stmt}`")
        # An armed snapshot older than a not-armed read this server holds is never served (UP-2).
        for stmt in ("const bool superseded = bg_arm_armed_ && bg_last_not_armed_at_ && "
                     "*bg_last_not_armed_at_ >= bg_arm_started_;",
                     "if (bg_arm_valid_ && now - bg_arm_at_ < kBreakGlassArmCacheTtl && !superseded) {"):
            if stmt not in _ws(gate):
                bad.append(f"the gate must contain `{stmt}`")
        if "const auto started = arm_clock_now();" not in gate or \
                gate.find("const auto started = arm_clock_now();") > gate.find("read = hook();"):
            bad.append("the gate must sample `started` before the read")
        busy = re.search(r"compare_exchange_strong\(expected, true\)\) \{(.*?)count\(\"refresh_busy\"\);", gate, re.S)
        if not busy or "out.arm_id = bg_last_armed_id_;" not in busy.group(1) or \
                "out.last_not_armed_at = bg_last_not_armed_at_;" not in busy.group(1) or \
                "std::lock_guard lk(bg_arm_mu_);" not in busy.group(1):
            bad.append("a refresh_busy answer must re-read the last armed id and the last-not-armed "
                       "time under the mutex after the failed CAS")
        if gate.count("bg_last_not_armed_at_ =") != 1:
            bad.append("the gate must write bg_last_not_armed_at_ in exactly one place (a not-armed read)")
        own_a = t.find("SsoOnlyGateResult AuthRoutes::break_glass_arm_own_read(")
        own = t[own_a:b] if 0 <= own_a < b else ""
        if not own:
            bad.append("break_glass_arm_own_read must be defined before the gate")
        else:
            if own.count("bg_last_not_armed_at_ =") != 1:
                bad.append("the own read must write bg_last_not_armed_at_ in exactly one place "
                           "(a successful not-armed read)")
            for forbidden in ("bg_arm_armed_ =", "bg_arm_at_ =", "bg_arm_deadline_ =", "bg_arm_started_ =",
                              "bg_arm_id_ =", "bg_arm_started_wall_ =", "bg_arm_valid_ = true",
                              "compare_exchange_strong"):
                if forbidden in own:
                    bad.append(f"the second re-check's own read must not write the armed cache or "
                               f"take the single flight (`{forbidden}`)")
            for needed in ("const bool too_old = armed_now && !arm_observation_fresh(started, finished);",
                           "if (read.ok && !armed_now) {",
                           "if (!bg_last_not_armed_at_ || *bg_last_not_armed_at_ < finished)"):
                if needed not in own:
                    bad.append(f"the second re-check's own read must contain `{needed}`")
            if not (0 <= own.find("const auto started = arm_clock_now();") < own.find("read = hook();")):
                bad.append("the own read must sample `started` before the read")
            # The two "last" facts are copied into the answer AFTER the read.
            if not (0 <= own.find("const auto finished = arm_clock_now();")
                    < own.find("out.last_not_armed_at = bg_last_not_armed_at_;")):
                bad.append("the own read must copy the last facts into its answer after the read")
        if t.count("SsoOnlyArmRead::kOwnFreshRead") != 2:
            bad.append("SsoOnlyArmRead::kOwnFreshRead must appear exactly twice in auth_routes.cpp "
                       "(the gate's dispatch and the second re-check)")
    if "break_glass_login = gate.admits_password_evaluation();" not in t:
        bad.append("POST /login must decide the break-glass admit with admits_password_evaluation()")
    bad += check_for_test_callers(files)
    if "kArmSnapshotMaxAge{4500}" not in hpp or "return now - read_at <= kArmSnapshotMaxAge;" not in hpp:
        bad.append("kArmSnapshotMaxAge must be 4500 ms and arm_observation_fresh must compare against it")
    return bad


def check(files):
    bad = []
    sites = {}
    for name, t in files.items():
        if name.startswith("auth_db.") or name.startswith("__"):
            continue
        for m in CALL.finditer(t):
            sites.setdefault(name, []).append(m.start())
    if set(sites) != {"auth_routes.cpp"}:
        bad.append(f"verifier callers outside auth_routes.cpp: {sorted(sites)}")
    if "auth_routes.cpp" in files:
        bad += check_routes(files["auth_routes.cpp"])
        bad += check_gate_order(files["auth_routes.cpp"], files.get("auth_routes.hpp", ""),
                                files.get("server.cpp", ""))
        bad += check_arm_recheck(files)
    else:
        bad.append("auth_routes.cpp missing")
    return bad


def load():
    out = {}
    for p in sorted(SRC.glob("*.[ch]pp")):
        t = p.read_text(encoding="utf-8", errors="replace")
        # server.cpp holds string literals containing "/*" that make comment stripping eat code,
        # so it is read raw (its pins are call tokens spelled `auth_routes_->set_...(`).
        out[p.name] = t if p.name == "server.cpp" else strip_comments(t)
    return out


def selftest(files):
    base = files["auth_routes.cpp"]
    failures = []
    for name in ("/login/mfa", "/login/mfa/stepup"):
        for tok in ("mfa_budget_reserve(", "acquire_pbkdf2(", "mfa_budget_refund(",
                    "mfa_budget_note_failure("):
            sp = handler(
                base,
                {"/login/mfa": 'sink.Post("/login/mfa",', "/login/mfa/stepup": 'sink.Post("/login/mfa/stepup"'}[name],
                {"/login/mfa": 'sink.Post("/login/mfa/enroll"', "/login/mfa/stepup": 'sink.Post("/logout"'}[name],
            )
            a, b = sp
            body = base[a:b]
            if tok not in body:
                failures.append(f"selftest cannot find {tok} in {name}")
                continue
            mutated = base[:a] + body.replace(tok, "removed_by_selftest(") + base[b:]
            m = dict(files)
            m["auth_routes.cpp"] = mutated
            if not check(m):
                failures.append(f"MUTATION NOT DETECTED: {tok} removed from {name}")
    # Moving the gate after the slot, or an unbounded stripe lock, must be caught.
    gate_stmt = re.search(
        r"if \(opts\.pre_verify_gate && !opts\.pre_verify_gate\(\)\)\s*return \{[^;]*\};", base)
    if gate_stmt and "int prior_failed_count = 0;" in base:
        mutated = base.replace(gate_stmt.group(0), "", 1).replace(
            "int prior_failed_count = 0;", gate_stmt.group(0) + " int prior_failed_count = 0;", 1)
        m = dict(files)
        m["auth_routes.cpp"] = mutated
        if not check(m):
            failures.append("MUTATION NOT DETECTED: gate moved after the slot")
    else:
        failures.append("selftest cannot find the gate statement")
    if "try_lock_for(kLoginStripeWait)" in base:
        m = dict(files)
        m["auth_routes.cpp"] = base.replace("try_lock_for(kLoginStripeWait)", "lock()", 1)
        if not check(m):
            failures.append("MUTATION NOT DETECTED: unbounded stripe lock")
    else:
        failures.append("selftest cannot find the bounded stripe wait")
    if "if (lockout_active) {\n        login_lk" in base or "if (lockout_active) { login_lk" in base:
        pass
    m = dict(files)
    mutated = re.sub(r"if \(lockout_active\)\s*\{(\s*login_lk)", r"if (true) {\1", base, count=1)
    if mutated != base:
        m["auth_routes.cpp"] = mutated
        if not check(m):
            failures.append("MUTATION NOT DETECTED: stripe taken for lockout-exempt names")
    else:
        failures.append("selftest cannot find the lockout_active stripe condition")
    def mut(label, fn_):
        m = dict(files)
        try:
            changed = fn_(m)
        except Exception as e:  # noqa
            failures.append(f"selftest cannot build mutation {label}: {e}")
            return
        if not changed:
            failures.append(f"selftest cannot find the text for: {label}")
        elif not check(m):
            failures.append(f"MUTATION NOT DETECTED: {label}")

    def sub_cpp(old, new, key="auth_routes.cpp", count=1):
        def f(m):
            if old not in m[key]:
                return False
            m[key] = m[key].replace(old, new, count)
            return True
        return f

    mut("stripe without defer_lock", sub_cpp("login_lock_for(username), std::defer_lock)", "login_lock_for(username))"))
    mut("ad-hoc stripe wait", sub_cpp("try_lock_for(kLoginStripeWait)", "try_lock_for(std::chrono::hours(1))"))
    mut("extra lock_guard", sub_cpp("std::unique_lock<std::timed_mutex> login_lk;", "std::lock_guard<std::timed_mutex> extra(login_lock_for(username)); std::unique_lock<std::timed_mutex> login_lk;"))
    mut("blocking login_lock_for(...).lock()", sub_cpp("std::unique_lock<std::timed_mutex> login_lk;", "login_lock_for(username).lock(); std::unique_lock<std::timed_mutex> login_lk;"))
    mut("per-stripe comparison neutralised", sub_cpp("if (stripe_waiter.prior() >= kStripeWaitersPerStripe) {", "if (false && stripe_waiter.prior() >= kStripeWaitersPerStripe) {"))
    mut("global comparison neutralised", sub_cpp("if (!waiter.admitted()) {", "if (false && !waiter.admitted()) {"))
    mut("both caps deleted, tokens kept in a string", lambda m: m.__setitem__("auth_routes.cpp", re.sub(r"if \((?:false && )?(?:stripe_waiter|waiter)\.prior\(\)[^{]*\{", 'const char* x = "kStripeWaitersPerStripe stripe_waiter_cap_"; if (false) {', m["auth_routes.cpp"])) or True)
    mut("kLoginStripeWait 150 -> 3600000", sub_cpp("kLoginStripeWait{150}", "kLoginStripeWait{3600000}", key="auth_routes.hpp"))
    mut("kStripeWaitersPerStripe 2 -> 1000", sub_cpp("kStripeWaitersPerStripe = 2", "kStripeWaitersPerStripe = 1000", key="auth_routes.hpp"))
    mut("try_lock() first dropped", sub_cpp("if (!login_lk.try_lock()) {", "if (true) {"))
    mut("over-length shortcut back on the ordinary slot", sub_cpp("if (!break_glass_attempt) {\n        const bool login_route", "if (!break_glass_attempt && !auth::password_exceeds_max(password)) {\n        const bool login_route"))
    mut("over-length shortcut back on the break-glass slot", sub_cpp("if (break_glass_attempt) {\n        pbkdf2_slot.emplace", "if (break_glass_attempt && !auth::password_exceeds_max(password)) {\n        pbkdf2_slot.emplace"))
    # WP03 arm re-check and tri-state gate: each pin has a mutant.
    def move_text(m, text, before, key="auth_routes.cpp"):
        """Cut the first occurrence of `text` and paste it just before `before`."""
        src = m[key]
        if text not in src or before not in src.replace(text, "", 1):
            return False
        src = src.replace(text, "", 1)
        m[key] = src.replace(before, text + " " + before, 1)
        return True

    hsp = handler(base, 'sink.Post("/login/mfa",', 'sink.Post("/login/mfa/enroll"')
    hbody = base[hsp[0]:hsp[1]] if hsp else ""
    g1 = hbody.find(GATE1)
    r1 = hbody.find("mfa_budget_reserve(")
    blk1 = ""
    if g1 >= 0 and r1 > g1:
        o = hbody.rfind("if (entry.break_glass) {", 0, g1)
        e = _block_end(hbody, o + len("if (entry.break_glass) "))
        blk1 = hbody[o:e] if o >= 0 and e > 0 else ""
    g2 = hbody.find(GATE2)
    blk2 = ""
    if g2 >= 0:
        o = hbody.rfind("if (entry.break_glass) {", 0, g2)
        e = _block_end(hbody, o + len("if (entry.break_glass) "))
        blk2 = hbody[o:e] if o >= 0 and e > 0 else ""
    if not blk1 or not blk2:
        failures.append("selftest cannot find the two arm re-check blocks")
    else:
        mut("pending token never records break_glass", sub_cpp("entry.break_glass = break_glass_login;", ""))
        mut("pending token records break_glass = false", sub_cpp("entry.break_glass = break_glass_login;", "entry.break_glass = false;"))
        mut("both arm re-checks disabled", sub_cpp("if (entry.break_glass) {", "if (false && entry.break_glass) {", count=2))
        mut("first arm re-check removed", sub_cpp(blk1, ""))
        mut("second arm re-check removed", sub_cpp(blk2, ""))
        mut("a third arm re-check", sub_cpp(blk2, blk2 + " if (entry.break_glass) { (void)sso_only_local_password_gate(entry.username); }"))
        for i, pos in enumerate([m_.start() for m_ in re.finditer(r"return;", blk1)]):
            mut(f"first re-check refusal {i} without return",
                sub_cpp(blk1, blk1[:pos] + blk1[pos + len("return;"):]))
        mut("first re-check moved after the reserve",
            lambda m: move_text(m, blk1, "bool matched = false;"))
        mut("first re-check moved after the first verifier",
            lambda m: move_text(m, blk1, "if (store_unavailable) {"))
        mut("first re-check accepts an armed answer older than a not-armed read",
            sub_cpp("kBreakGlassArmed && !superseded1) {", "kBreakGlassArmed) {"))
        mut("first re-check never sees a superseded answer",
            sub_cpp("gate1.last_not_armed_at && *gate1.last_not_armed_at >= gate1.read_at;", "false;"))
        mut("first re-check does not record arm1",
            sub_cpp("arm1 = ArmSnapshot{gate1.arm_id, gate1.deadline, gate1.read_at, gate1.read_wall_at};", ""))
        mut("first re-check anchors the wall time after the gate returned",
            sub_cpp("gate1.read_at, gate1.read_wall_at};", "gate1.read_at, arm_wall_clock_now()};"))
        mut("second re-check moved after the mint",
            lambda m: move_text(m, blk2, "if (token.empty()) {"))
        mut("now2 sampled before the second gate call",
            sub_cpp(GATE2 + "\n            const auto now2 = arm_clock_now();",
                    "const auto now2 = arm_clock_now();\n            " + GATE2))
        mut("a second clock sample in the second re-check",
            sub_cpp("now2 < arm1->deadline", "arm_clock_now() < arm1->deadline"))
        for clause in ("now2 < arm1->deadline &&", "arm_observation_fresh(arm1->read_at, now2) &&",
                       "wall2 - arm1->wall_at <= kArmSnapshotMaxAge &&",
                       "gate2.arm_id == arm1->arm_id &&",
                       "!(gate2.last_not_armed_at && *gate2.last_not_armed_at >= arm1->read_at)"):
            mut(f"transient admit clause removed: {clause}",
                sub_cpp(clause, "true &&" if clause.endswith("&&") else "true"))
        mut("the cache hit does not carry the wall time of the read",
            sub_cpp("out.read_wall_at = bg_arm_started_wall_;", ""))
        mut("the cached snapshot's wall time is not recorded",
            sub_cpp("bg_arm_started_wall_ = started_wall;", ""))
        def _late_wall(m):
            k, stmt = "auth_routes.cpp", "const auto started_wall = arm_wall_clock_now();"
            anchor = "bg_arm_started_wall_ = started_wall;"
            if stmt not in m[k] or anchor not in m[k]:
                return False
            m[k] = m[k].replace(stmt, "", 1).replace(anchor, stmt + " " + anchor, 1)
            return True
        mut("the gate samples the wall time after its read, at the cache write", _late_wall)
        mut("the cache serves an armed snapshot older than a not-armed read this server holds",
            sub_cpp("kBreakGlassArmCacheTtl && !superseded) {", "kBreakGlassArmCacheTtl) {"))
        mut("the superseded test never fires",
            sub_cpp("bg_arm_armed_ && bg_last_not_armed_at_ && *bg_last_not_armed_at_ >= bg_arm_started_;", "false;"))
        mut("a second wall sample in the second re-check",
            sub_cpp("wall2 - arm1->wall_at", "arm_wall_clock_now() - arm1->wall_at"))
        mut("wall2 sampled before now2",
            sub_cpp("const auto now2 = arm_clock_now();\n            const auto wall2 = arm_wall_clock_now();",
                    "const auto wall2 = arm_wall_clock_now();\n            const auto now2 = arm_clock_now();"))
        mut("wall time used to admit",
            sub_cpp("(armed_ok || transient_ok);",
                    "(armed_ok || transient_ok || wall2 < arm1->wall_at);"))
        mut("arm1.has_value() dropped from admit",
            sub_cpp("const bool admit = arm1.has_value() &&", "const bool admit ="))
        mut("arm1.has_value() only inside the transient rule",
            sub_cpp("arm1.has_value() && (armed_ok || transient_ok);",
                    "(armed_ok || (arm1.has_value() && transient_ok));"))
        # C-01: the armed branch's supersession test.
        mut("the armed own read skips the supersession test (C-01)",
            sub_cpp("gate2.state == SsoOnlyLocalGate::kBreakGlassArmed &&\n"
                    "                !(gate2.last_not_armed_at && *gate2.last_not_armed_at >= gate2.read_at);",
                    "gate2.state == SsoOnlyLocalGate::kBreakGlassArmed;"))
        mut("the armed own read is superseded against the first check's start, not its own",
            sub_cpp("*gate2.last_not_armed_at >= gate2.read_at);", "*gate2.last_not_armed_at >= arm1->read_at);"))
        mut("admit takes the raw armed state instead of armed_ok",
            sub_cpp("(armed_ok || transient_ok);",
                    "(gate2.state == SsoOnlyLocalGate::kBreakGlassArmed || transient_ok);"))
        r2 = blk2.find("if (!admit) {")
        ret2 = blk2.find("return;", r2)
        if r2 < 0 or ret2 < 0:
            failures.append("selftest cannot find the second re-check's refusal")
        else:
            mut("second re-check refusal without return",
                sub_cpp(blk2, blk2[:ret2] + blk2[ret2 + len("return;"):]))
        mut("a call between the second re-check and the mint",
            sub_cpp("admitted_under_transient = gate2.state == SsoOnlyLocalGate::kTransient;",
                    "admitted_under_transient = gate2.state == SsoOnlyLocalGate::kTransient; (void)db->mfa_status(entry.username);"))
        mut("pending_refused counter without labels",
            sub_cpp('"yuzu_auth_break_glass_pending_refused_total",', '"yuzu_auth_break_glass_pending_refused_total").increment(); (void)(0,'))
    mut("/login decides the break-glass admit without the one admit set",
        sub_cpp("break_glass_login = gate.admits_password_evaluation();",
                "break_glass_login = gate.state == SsoOnlyLocalGate::kBreakGlassArmed || gate.state == SsoOnlyLocalGate::kTransient;"))
    mut("the non-empty arm id requirement dropped", sub_cpp("!arm1->arm_id.empty() && ", ""))
    # A production file calling a test seam must be caught (the real tree is scanned once; the
    # mutant adds one rogue production file to that scan).
    prod = load_production_sources()
    m = dict(files)
    m["__production__"] = dict(prod)
    m["__production__"]["server/core/src/rogue_seam_caller.cpp"] = \
        "void f(yuzu::server::AuthRoutes& r) { r.set_arm_clock_for_test(0); }"
    if not check(m):
        failures.append("MUTATION NOT DETECTED: a production file calls an AuthRoutes test seam")
    m = dict(files)
    m["__production__"] = dict(prod)
    m["__production__"]["server/core/src/auth_routes.cpp"] = \
        prod.get("server/core/src/auth_routes.cpp", "") + "\nvoid g(AuthRoutes& r) { r.reset_break_glass_arm_cache_for_test(); }"
    if not check(m):
        failures.append("MUTATION NOT DETECTED: auth_routes.cpp itself calls a test seam")
    mut("password-change gate back to != kRefused",
        sub_cpp("return sso_only_local_password_gate(username).admits_password_evaluation();",
                "return sso_only_local_password_gate(username).state != SsoOnlyLocalGate::kRefused;"))
    mut("kTransient added to the admit set",
        sub_cpp(ADMIT_SET, ADMIT_SET[:-1] + " || state == SsoOnlyLocalGate::kTransient;", key="auth_routes.hpp"))
    mut("an operator!= on the gate result",
        sub_cpp("    [[nodiscard]] bool admits_password_evaluation() const noexcept {",
                "    friend bool operator!=(const SsoOnlyGateResult& r, SsoOnlyLocalGate s) { return r.state != s; }\n"
                "    [[nodiscard]] bool admits_password_evaluation() const noexcept {", key="auth_routes.hpp"))
    mut("a conversion operator on the gate result",
        sub_cpp("    [[nodiscard]] bool admits_password_evaluation() const noexcept {",
                "    operator SsoOnlyLocalGate() const { return state; }\n"
                "    [[nodiscard]] bool admits_password_evaluation() const noexcept {", key="auth_routes.hpp"))
    mut("the comparison static_assert term removed",
        sub_cpp("!SsoGateNeComparable<SsoOnlyGateResult, SsoOnlyLocalGate> &&", "", key="auth_routes.hpp"))
    mut("the second re-check back on the shared cache and single flight",
        sub_cpp("sso_only_local_password_gate(entry.username, SsoOnlyArmRead::kOwnFreshRead);",
                "sso_only_local_password_gate(entry.username, SsoOnlyArmRead::kCachedSingleFlight);"))
    mut("the own read without the cap",
        sub_cpp("const bool too_old = armed_now && !arm_observation_fresh(started, finished);",
                "const bool too_old = false;"))
    mut("the own read writes the armed cache",
        sub_cpp("            bg_last_armed_id_ = read.armed_until;\n        }\n        out.arm_id = bg_last_armed_id_;",
                "            bg_last_armed_id_ = read.armed_until;\n            bg_arm_valid_ = true;\n            bg_arm_armed_ = true;\n        }\n        out.arm_id = bg_last_armed_id_;"))
    mut("a failed own read records not armed",
        sub_cpp("if (read.ok && !armed_now) {", "if (!armed_now) {"))
    mut("refresh_busy answers with the facts from before the failed CAS",
        sub_cpp("        {\n            std::lock_guard lk(bg_arm_mu_);\n            out.arm_id = bg_last_armed_id_;\n            out.last_not_armed_at = bg_last_not_armed_at_;\n        }\n        out.state = SsoOnlyLocalGate::kTransient;",
                "        out.state = SsoOnlyLocalGate::kTransient;"))
    mut("the gate cap dropped from the cache hit",
        sub_cpp("if (!arm_observation_fresh(bg_arm_started_, now)) {", "if (false) {"))
    mut("the gate cap dropped from its own read",
        sub_cpp("if (armed_now && !arm_observation_fresh(started, finished)) {", "if (false) {"))
    mut("started sampled after the read",
        sub_cpp("    const auto started = arm_clock_now();", "").__call__ and (lambda m: (
            m.__setitem__("auth_routes.cpp", m["auth_routes.cpp"].replace("    const auto started = arm_clock_now();", "", 1).replace(
                "    const auto finished = arm_clock_now();", "    const auto started = arm_clock_now();\n    const auto finished = arm_clock_now();", 1)) or True)
        if "    const auto started = arm_clock_now();" in m["auth_routes.cpp"] else False))
    mut("kArmSnapshotMaxAge raised", sub_cpp("kArmSnapshotMaxAge{4500}", "kArmSnapshotMaxAge{450000}", key="auth_routes.hpp"))
    mut("the cap records a not-armed observation",
        sub_cpp("out.cause = SsoOnlyTransientCause::kStaleRead;",
                "out.cause = SsoOnlyTransientCause::kStaleRead; bg_last_not_armed_at_ = started;"))
    mut("server.cpp: set_stripe_waiter_cap commented out", sub_cpp("    auth_routes_->set_stripe_waiter_cap(sz.stripe_waiters);", "    // auth_routes_->set_stripe_waiter_cap(sz.stripe_waiters);", key="server.cpp"))
    mut("server.cpp: set_pbkdf2_cap only inside a string literal", sub_cpp("    auth_routes_->set_pbkdf2_cap(sz.cap);", '    const char* x = "auth_routes_->set_pbkdf2_cap(sz.cap);";', key="server.cpp"))
    mut("server.cpp: set_pbkdf2_cap altered argument", sub_cpp("auth_routes_->set_pbkdf2_cap(sz.cap);", "auth_routes_->set_pbkdf2_cap(4);", key="server.cpp"))
    mut("server.cpp: sizing computed with a constant per-source cap", sub_cpp("login_sizing(pool_max, cfg_.auth_pbkdf2_per_source_cap)", "login_sizing(pool_max, 1)", key="server.cpp"))
    mut("break-glass slot moved before the sso-only gate", lambda m: m.__setitem__("auth_routes.cpp", m["auth_routes.cpp"].replace("if (break_glass_attempt) {\n        pbkdf2_slot.emplace(acquire_pbkdf2(Pbkdf2Class::kBreakGlass", "if (false) {\n        pbkdf2_slot.emplace(acquire_pbkdf2(Pbkdf2Class::kBreakGlass", 1).replace("    // Serialize concurrent attempts for THIS username across the whole", "    if (break_glass_attempt) { pbkdf2_slot.emplace(acquire_pbkdf2(Pbkdf2Class::kBreakGlass, req, opts.metric_route)); }\n    // Serialize concurrent attempts for THIS username across the whole", 1)) or True)
    # A new caller elsewhere must be caught too.
    m = dict(files)
    m["rogue.cpp"] = "void f(){ db->mfa_verify_login_code(u, c); }"
    if not check(m):
        failures.append("MUTATION NOT DETECTED: rogue verifier caller")
    return failures


def main():
    files = load()
    bad = check(files) + selftest(files)
    if bad:
        print("\n".join(bad))
        return 1
    print("ok")
    return 0


if __name__ == "__main__":
    sys.exit(main())
