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
    if not re.search(r"if \(waiter\.prior\(\) >= stripe_waiter_cap_\.load\(std::memory_order_relaxed\)\) \{[^}]*return \{PasswordCheckOutcome::kBusy", fn):
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
        bad += check_gate_order(files["auth_routes.cpp"], files.get("auth_routes.hpp", ""),
                                files.get("server.cpp", ""))
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
    mut("global comparison neutralised", sub_cpp("if (waiter.prior() >= stripe_waiter_cap_.load(std::memory_order_relaxed)) {", "if (false && waiter.prior() >= stripe_waiter_cap_.load(std::memory_order_relaxed)) {"))
    mut("both caps deleted, tokens kept in a string", lambda m: m.__setitem__("auth_routes.cpp", re.sub(r"if \((?:false && )?(?:stripe_waiter|waiter)\.prior\(\)[^{]*\{", 'const char* x = "kStripeWaitersPerStripe stripe_waiter_cap_"; if (false) {', m["auth_routes.cpp"])) or True)
    mut("kLoginStripeWait 150 -> 3600000", sub_cpp("kLoginStripeWait{150}", "kLoginStripeWait{3600000}", key="auth_routes.hpp"))
    mut("kStripeWaitersPerStripe 2 -> 1000", sub_cpp("kStripeWaitersPerStripe = 2", "kStripeWaitersPerStripe = 1000", key="auth_routes.hpp"))
    mut("try_lock() first dropped", sub_cpp("if (!login_lk.try_lock()) {", "if (true) {"))
    mut("over-length shortcut back on the ordinary slot", sub_cpp("if (!break_glass_attempt) {\n        const bool login_route", "if (!break_glass_attempt && !auth::password_exceeds_max(password)) {\n        const bool login_route"))
    mut("over-length shortcut back on the break-glass slot", sub_cpp("if (break_glass_attempt) {\n        pbkdf2_slot.emplace", "if (break_glass_attempt && !auth::password_exceeds_max(password)) {\n        pbkdf2_slot.emplace"))
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
