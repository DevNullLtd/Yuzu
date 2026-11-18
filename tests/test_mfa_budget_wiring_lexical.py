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


def check_gate_order(t):
    """verify_password_with_lockout: the sso-only gate runs BEFORE the PBKDF2 slot, and the
    stripe acquire (try_lock_for) comes before the slot; both are bounded-wait."""
    bad = []
    a = t.find("AuthRoutes::verify_password_with_lockout(")
    b = t.find("Account-lockout pre-check", a) if a >= 0 else -1
    if a < 0:
        return ["verify_password_with_lockout not found"]
    body = t[a:] if b < 0 else t[a:]
    gate = body.find("opts.pre_verify_gate()")
    slot = body.find("acquire_pbkdf2(")
    stripe = body.find("try_lock_for(")
    if gate < 0 or slot < 0 or stripe < 0:
        return [f"gate/slot/stripe anchors missing ({gate},{slot},{stripe})"]
    if not gate < slot:
        bad.append("the sso-only pre_verify_gate must run BEFORE the PBKDF2 slot is taken")
    if not stripe < gate:
        bad.append("the bounded stripe wait (try_lock_for) must come before the gate/slot")
    if "break_glass_gate_.try_acquire_for(" not in body[:slot]:
        bad.append("the lockout-exempt break-glass guess gate must be taken before the slot")
    pre = body[:stripe]
    if "if (lockout_active)" not in pre[-400:]:
        bad.append("the login stripe must be taken only when lockout_active (a lockout-exempt "
                   "name such as break-glass must never take it)")
    if "login_lk.lock()" in body[:slot]:
        bad.append("the login stripe must use try_lock_for, never an unbounded lock()")
    return bad


def check(files):
    bad = []
    sites = {}
    for name, t in files.items():
        if name.startswith("auth_db."):
            continue
        for m in CALL.finditer(t):
            sites.setdefault(name, []).append(m.start())
    if set(sites) != {"auth_routes.cpp"}:
        bad.append(f"verifier callers outside auth_routes.cpp: {sorted(sites)}")
    if "auth_routes.cpp" in files:
        bad += check_routes(files["auth_routes.cpp"])
        bad += check_gate_order(files["auth_routes.cpp"])
    else:
        bad.append("auth_routes.cpp missing")
    return bad


def load():
    return {
        p.name: strip_comments(p.read_text(encoding="utf-8", errors="replace"))
        for p in sorted(SRC.glob("*.[ch]pp"))
    }


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
