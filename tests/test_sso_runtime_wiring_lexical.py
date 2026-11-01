#!/usr/bin/env python3
"""#4160 best-effort lexical tripwire over server/core/src/server.cpp (and settings_routes.cpp):
the `--auth-mode=sso-only` runtime-wiring check and the provider gauges stay wired.

WHY THIS EXISTS. `sso_only_runtime_providers_ok`, the gauge publishers and the IdP-certificate probe
are each unit-tested, but the statements that CALL them live in the ServerImpl constructor, which is
not unit-constructible (it needs Postgres). A refactor could drop the call, feed it the wrong flag,
or move it before the providers are built, and every unit test would stay green while sso-only
quietly went back to booting into a fleet-wide lockout. This gate pins the statements lexically.

Required statements (each is one requirement id below):
  1. the SAML IdP-certificate probe result is consulted (`idp_cert_configured_but_broken()`), BEFORE
     the `is_enabled()` success branch, and disables SAML (`saml_provider_.reset()`);
  2. `oidc_up` / `saml_up` are derived from the provider POINTERS and `is_enabled()`, never from
     config (config presence is the earlier main.cpp guard's job);
  3. both gauge publishers are called with `configured` from the config predicate and `enabled`
     from `oidc_up` / `saml_up`;
  4. `sso_only_runtime_providers_ok(cfg_, oidc_up, saml_up)` is called exactly once, its failure
     sets `startup_failed_ = true`, and it sits AFTER the last provider construction/reset;
  5. the Settings OIDC save republishes the OIDC gauges (so a runtime reconfigure cannot leave them
     stale);
  6. the old divergent probe (`pki::parse_certificate` on the IdP cert) is not reintroduced in the
     SAML wiring block (it false-rejected TRUSTED CERTIFICATE and false-accepted Ed25519).

LEXICAL ONLY: it pins the refusal condition and body verbatim (so an inverted or short-circuited
condition is caught), but it cannot see a relocation that keeps the tokens, such as wrapping the
block in `#if 0`, moving it into the `#ifndef _WIN32` region, an early `return` before it, a later
`startup_failed_ = false`, or putting it in a never-called lambda (review-enforced; the live boot
is the real check). The in-file selftest
deletes each required statement in memory and requires the gate to name it, so a stale pattern
fails loudly instead of passing vacuously.
"""
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
# The literal-aware comment stripper + whitespace normaliser the sibling wiring gates share.
from test_same_site_wiring_lexical import normalise  # noqa: E402

SERVER = os.path.join(ROOT, "server", "core", "src", "server.cpp")
SETTINGS = os.path.join(ROOT, "server", "core", "src", "settings_routes.cpp")


def squash(path_or_text, is_text=False):
    src = path_or_text if is_text else open(path_or_text, encoding="utf-8").read()
    return re.sub(r"\s+", "", normalise(src))


# (id, file-key, pattern). Patterns are whitespace-free; matched against whitespace-free text.
REQUIRED = [
    ("R1a-cert-probe-consulted", "server",
     r"elseif(saml_provider_&&saml_provider_->idp_cert_configured_but_broken()){"),
    ("R2a-oidc-up-from-pointer", "server",
     r"constbooloidc_up=oidc_provider_&&oidc_provider_->is_enabled();"),
    ("R2b-saml-up-from-pointer", "server",
     r"constboolsaml_up=saml_provider_&&saml_provider_->is_enabled();"),
    ("R3a-oidc-gauges", "server",
     r"publish_oidc_provider_gauges(metrics_,oidc_config_complete(cfg_),oidc_up);"),
    ("R3b-saml-gauges", "server",
     r"publish_saml_provider_gauges(metrics_,saml_config_complete(cfg_),saml_up);"),
    ("R4a-runtime-check-call", "server",
     r"sso_only_runtime_providers_ok(cfg_,oidc_up,saml_up)"),
    # Pins the WHOLE condition and body, so an inverted `!runtime`, a `false&&`, or a
    # missing `startup_failed_ = true` is detected (not just the tokens being present).
    ("R4b-failure-sets-startup-failed", "server",
     'if(autoruntime=sso_only_runtime_providers_ok(cfg_,oidc_up,saml_up);!runtime){'
     'spdlog::error("[SSO]Refusingtostart:{}",runtime.error());startup_failed_=true;}'),
    ("R5-settings-republish", "settings",
     r"if(metrics_registry_){publish_oidc_provider_gauges(*metrics_registry_,"
     r"oidc_config_complete(*cfg_),*oidc_provider_&&(*oidc_provider_)->is_enabled());}"),
]


def problems(server_text, settings_text):
    texts = {"server": server_text, "settings": settings_text}
    out = []
    for rid, key, pat in REQUIRED:
        n = texts[key].count(pat)
        if n != 1:
            out.append(f"{rid}: expected exactly 1 occurrence of {pat!r} in {key}, found {n}")

    s = server_text
    # R1b: the probe branch precedes the is_enabled() success branch and disables SAML.
    i_probe = s.find("saml_provider_->idp_cert_configured_but_broken()")
    i_ok = s.find("saml_provider_->is_enabled())", i_probe if i_probe >= 0 else 0)
    if i_probe < 0 or i_ok < 0 or i_probe > i_ok:
        out.append("R1b-probe-before-success-branch: the cert-probe branch must precede the "
                   "is_enabled() success branch in the SAML wiring")
    else:
        seg = s[i_probe:i_ok]
        if "saml_provider_.reset();" not in seg:
            out.append("R1c-probe-disables-saml: the cert-probe branch must saml_provider_.reset()")

    # R4c: the runtime check comes after the last provider construction / reset.
    i_check = s.find("sso_only_runtime_providers_ok(cfg_,oidc_up,saml_up)")
    last_build = max(s.rfind("saml_provider_=std::make_unique<saml::SamlProvider>"),
                     s.rfind("saml_provider_.reset();"),
                     s.rfind("oidc_provider_=std::make_unique<oidc::OidcProvider>"))
    if i_check >= 0 and last_build > i_check:
        out.append("R4c-check-after-wiring: sso_only_runtime_providers_ok must come AFTER the "
                   "last oidc_provider_/saml_provider_ construction or reset in the constructor")

    # R5b: the Settings republish reads the NEW provider, so it must come after the swap.
    sw = settings_text.find("*oidc_provider_=std::move(new_provider);")
    pub = settings_text.find("publish_oidc_provider_gauges(*metrics_registry_")
    if sw < 0 or pub < 0 or pub < sw:
        out.append("R5b-republish-after-swap: the gauge republish must follow "
                   "`*oidc_provider_ = std::move(new_provider);` in settings_routes.cpp")

    # R6: the divergent probe must not come back inside the SAML wiring block.
    i_wire = s.find("saml_provider_=std::make_unique<saml::SamlProvider>")
    i_gauge = s.find("publish_oidc_provider_gauges(metrics_")
    if i_wire < 0 or i_gauge < 0 or i_gauge < i_wire:
        # The anchors themselves are required: a refactor that renames the construction
        # site must not turn the checks that hang off it into silent no-ops.
        out.append("R6a-anchors-present: the SamlProvider construction site and the gauge "
                   "publish must both be present, construction first")
    else:
        block = s[max(0, s.rfind("saml_config_complete(cfg_)", 0, i_wire)):i_gauge]
        if "pki::parse_certificate" in block:
            out.append("R6-no-divergent-cert-probe: pki::parse_certificate must not gate the SAML "
                       "IdP cert (use SamlProvider::idp_cert_configured_but_broken)")
    return out


def selftest(server_text, settings_text):
    """Every required statement, deleted in memory, must make the gate fail naming it."""
    failures = []
    for rid, key, pat in REQUIRED:
        st = server_text.replace(pat, "", 1) if key == "server" else server_text
        se = settings_text.replace(pat, "", 1) if key == "settings" else settings_text
        found = problems(st, se)
        if not any(p.startswith(rid) for p in found):
            failures.append(f"selftest: deleting {rid} was NOT detected (stale pattern?)")
    # Ordering mutation: move the runtime check before the SAML construction.
    check = "sso_only_runtime_providers_ok(cfg_,oidc_up,saml_up)"
    if check in server_text:
        moved = check + server_text.replace(check, "", 1)
        if not any(p.startswith("R4c") for p in problems(moved, settings_text)):
            failures.append("selftest: moving the check before provider wiring was NOT detected")
    # Divergent-probe mutation.
    mark = "saml_provider_=std::make_unique<saml::SamlProvider>"
    if mark in server_text:
        bad = server_text.replace(mark, "pki::parse_certificate(cert_pem);" + mark, 1)
        if not any(p.startswith("R6") for p in problems(bad, settings_text)):
            failures.append("selftest: reintroducing pki::parse_certificate was NOT detected")
    return failures


def main():
    server_text = squash(SERVER)
    settings_text = squash(SETTINGS)
    found = problems(server_text, settings_text) + selftest(server_text, settings_text)
    if found:
        print("FAIL: #4160 sso-only runtime wiring tripwire:")
        for p in found:
            print("  -", p)
        return 1
    print("OK: #4160 sso-only runtime wiring tripwire (%d statements pinned)" % len(REQUIRED))
    return 0


if __name__ == "__main__":
    sys.exit(main())
