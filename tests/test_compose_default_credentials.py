#!/usr/bin/env python3
"""No tracked compose may start Grafana with a known admin password (#4817).

Every shipped compose that ran Grafana used to set
`GF_SECURITY_ADMIN_PASSWORD=admin` and publish port 3000 on every interface,
so anyone who could reach the host had full Grafana admin, including adding
data sources that make Grafana's server-side client fetch arbitrary internal
URLs. Deleting the line would not help: Grafana's own built-in default is
admin/admin.

Rules checked here, for every tracked *compose*.yml and for every service
whose image is grafana/grafana:

  * the environment sets GF_SECURITY_ADMIN_PASSWORD (or the __FILE form, a
    path to a secret). A missing key falls back to admin/admin, so absence
    fails exactly like a literal;
  * GF_SECURITY_ADMIN_PASSWORD is exactly `${YUZU_GRAFANA_ADMIN_PASSWORD:?<message>}`.
    `:?` makes Compose refuse to run when the variable is unset OR empty; a
    literal, a `:-`/`-` default, a bare `${VAR}` (empty when unset) or `?`
    without the colon (accepts empty) all fail. One variable name everywhere,
    so the docs, the launcher scripts and the Compose Wizard's .env agree;
  * anonymous access is not switched on (GF_AUTH_ANONYMOUS_ENABLED), which
    would make the password irrelevant.

It also checks the UAT launchers (scripts/docker-start-UAT.sh and
scripts/win-start-UAT.sh), which run the UAT composes for the operator:

  * the shared helper scripts/lib/uat-grafana-password.sh generates a random
    password, keeps it in a 0600 state file, reuses it on the next call,
    honours (and persists) an exported value, and refuses an empty value, the
    literal `admin` and a symlinked state file;
  * every launcher function that runs `docker compose` calls the helper first.
    Compose substitutes variables for EVERY subcommand, `down` and `ps`
    included, so a stop path that forgot it would fail - and both launchers
    discard that error (`down -v 2>/dev/null && ok ... || ok "No containers
    running"`), leaving the stack running while reporting it stopped;
  * neither launcher prints admin/admin any more.

Stdlib only; no Docker. Mutation self-tests prove each rule fails when broken.
"""

import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_compose_certs_volume import _strip_comment, _unquote, tracked_composes  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
VAR = "YUZU_GRAFANA_ADMIN_PASSWORD"
PASSWORD_KEY = "GF_SECURITY_ADMIN_PASSWORD"
PASSWORD_FILE_KEY = PASSWORD_KEY + "__FILE"
REQUIRED_RE = re.compile(r"^\$\{" + VAR + r":\?(?P<msg>[^}]*\S[^}]*)\}$")
GRAFANA_IMAGE_RE = re.compile(r"^(?:docker\.io/)?grafana/grafana(?:-oss|-enterprise)?(?:[:@]|$)")

# Composes known to run Grafana. A file dropping out of this set (renamed, or
# the reader stops seeing its Grafana service) must fail loudly instead of
# silently shrinking coverage.
EXPECTED_IN_SCOPE = {
    "deploy/docker/docker-compose.yml",
    "deploy/docker/docker-compose.uat.yml",
    "deploy/docker/docker-compose.full-uat.yml",
    "docker-compose.uat.yml",
}

HELPER = ROOT / "scripts" / "lib" / "uat-grafana-password.sh"
LAUNCHERS = ("scripts/docker-start-UAT.sh", "scripts/win-start-UAT.sh")
BASH = shutil.which("bash")


def parse_services(text):
    """Return {service: {"image": str, "env": {key: value}}}.

    Understands the subset the tracked composes use: block mappings, the list
    form (`- KEY=VALUE`, optionally quoted) and the map form (`KEY: VALUE`) of
    `environment:`."""
    services = {}
    section = child = svc = prop = env_indent = None
    in_env = False
    for raw in text.splitlines():
        line = _strip_comment(raw)
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip(" "))
        s = line.strip()
        if indent == 0:
            section = s.split(":", 1)[0]
            child = svc = prop = env_indent = None
            in_env = False
            continue
        if section != "services":
            continue
        if child is None:
            child = indent
        if indent == child:
            m = re.match(r"^([A-Za-z0-9_.-]+):\s*$", s)
            svc = m.group(1) if m else None
            if svc:
                services.setdefault(svc, {"image": "", "env": {}})
            prop, in_env, env_indent = None, False, None
            continue
        if svc is None:
            continue
        if prop is None:
            prop = indent
        if indent == prop:
            in_env, env_indent = s == "environment:", None
            m = re.match(r"^image:\s*(.*)$", s)
            if m:
                services[svc]["image"] = _unquote(m.group(1))
            continue
        if not in_env or indent < prop:
            continue
        if env_indent is None:
            env_indent = indent
        if indent != env_indent:
            continue
        if s.startswith("- "):
            item = _unquote(s[2:])
            key, _, value = item.partition("=")
        else:
            key, _, value = s.partition(":")
            value = _unquote(value)
        services[svc]["env"][key.strip()] = value.strip()
    return services


def grafana_services(text):
    return {name: svc for name, svc in parse_services(text).items()
            if GRAFANA_IMAGE_RE.match(svc["image"])}


def check(text):
    """Return a list of rule violations (empty when every Grafana is safe)."""
    errs = []
    for name, svc in grafana_services(text).items():
        env = svc["env"]
        if env.get("GF_AUTH_ANONYMOUS_ENABLED", "").lower() in ("true", "1", "yes"):
            errs.append(f"{name}: GF_AUTH_ANONYMOUS_ENABLED is on, so no password is needed")
        if PASSWORD_FILE_KEY in env and PASSWORD_KEY not in env:
            if not env[PASSWORD_FILE_KEY]:
                errs.append(f"{name}: {PASSWORD_FILE_KEY} is empty")
            continue
        if PASSWORD_KEY not in env:
            errs.append(f"{name}: {PASSWORD_KEY} is not set, so Grafana falls back to "
                        f"its built-in admin/admin")
            continue
        value = env[PASSWORD_KEY]
        if not REQUIRED_RE.match(value):
            errs.append(f"{name}: {PASSWORD_KEY}={value!r} must be exactly "
                        f"${{{VAR}:?<message>}} (required, refused when unset or empty)")
    return errs


class ComposeGrafanaPassword(unittest.TestCase):
    def test_every_tracked_compose(self):
        composes = tracked_composes()
        self.assertTrue(composes, "found no tracked compose files")
        in_scope, failures = set(), []
        for rel in composes:
            text = (ROOT / rel).read_text(encoding="utf-8")
            if grafana_services(text):
                in_scope.add(rel)
            failures += [f"{rel}: {e}" for e in check(text)]
        self.assertEqual(failures, [], "\n".join(
            failures + ["(#4817: see docs/user-manual/server-admin.md "
                        "'Grafana admin password')"]))
        missing = EXPECTED_IN_SCOPE - in_scope
        self.assertEqual(missing, set(),
                         f"expected these composes to run Grafana but the reader "
                         f"found none in them: {sorted(missing)}")

    def test_mutation_tracked_files(self):
        # Each in-scope file must FAIL when its password line is reverted to the
        # #4817 literal, or removed: proves the reader sees the real line.
        line_re = re.compile(r"^(\s*-\s*)" + PASSWORD_KEY + r"=.*$", re.M)
        for rel in sorted(EXPECTED_IN_SCOPE):
            text = (ROOT / rel).read_text(encoding="utf-8")
            with self.subTest(rel=rel, mutation="literal admin"):
                mutated = line_re.sub(r"\g<1>" + PASSWORD_KEY + "=admin", text)
                self.assertNotEqual(mutated, text, f"{rel}: no password line found")
                self.assertTrue(check(mutated))
            with self.subTest(rel=rel, mutation="line removed"):
                mutated = line_re.sub("", text)
                self.assertTrue(check(mutated))

    def test_mutation_variants(self):
        base = """services:
  grafana:
    image: grafana/grafana:11.5.2@sha256:abc
    ports:
      - "3000:3000"
    environment:
{env}
    volumes:
      - grafana-data:/var/lib/grafana
volumes:
  grafana-data:
"""
        good = [
            f"      - {PASSWORD_KEY}=${{{VAR}:?set {VAR}, e.g. openssl rand -hex 16}}",
            f"      {PASSWORD_KEY}: \"${{{VAR}:?set it}}\"",
            f"      - {PASSWORD_FILE_KEY}=/run/secrets/grafana_admin_password",
        ]
        for env in good:
            with self.subTest(good=env):
                self.assertEqual(check(base.format(env=env)), [])
        bad = [
            f"      - {PASSWORD_KEY}=admin",
            f"      {PASSWORD_KEY}: admin",
            f"      - {PASSWORD_KEY}=${{{VAR}:-admin}}",
            f"      - {PASSWORD_KEY}=${{{VAR}-admin}}",
            f"      - {PASSWORD_KEY}=${{{VAR}}}",
            f"      - {PASSWORD_KEY}=${VAR}",
            f"      - {PASSWORD_KEY}=${{{VAR}?set it}}",
            f"      - {PASSWORD_KEY}=${{{VAR}:?}}",
            f"      - {PASSWORD_KEY}=${{{VAR}:? }}",
            f"      - {PASSWORD_KEY}=${{OTHER_VAR:?set it}}",
            f"      - {PASSWORD_KEY}=x${{{VAR}:?set it}}",
            f"      - {PASSWORD_KEY}=",
            "      - GF_DASHBOARDS_DEFAULT_HOME_DASHBOARD_PATH=/x.json",
            f"      - {PASSWORD_FILE_KEY}=",
            f"      - {PASSWORD_KEY}=${{{VAR}:?set it}}\n      - GF_AUTH_ANONYMOUS_ENABLED=true",
        ]
        for env in bad:
            with self.subTest(bad=env):
                self.assertTrue(check(base.format(env=env)), env)
        # No environment block at all is the same as no password.
        self.assertTrue(check(base.replace("    environment:\n{env}\n", "")))
        # A non-Grafana image is not in scope.
        self.assertEqual(check(base.replace("grafana/grafana", "prom/prometheus")
                               .format(env=f"      - {PASSWORD_KEY}=admin")), [])


def run_helper(state_file, env_value=None, extra=""):
    """Source the helper, call it, and print the exported value."""
    env = {k: v for k, v in os.environ.items() if k != VAR}
    if env_value is not None:
        env[VAR] = env_value
    script = (f'set -euo pipefail\n. "{HELPER}"\n{extra}'
              f'uat_grafana_password "$1"\nprintf "%s" "${VAR}"\n')
    return subprocess.run([BASH, "-c", script, "helper", str(state_file)],
                          capture_output=True, text=True, env=env, timeout=60)


@unittest.skipIf(BASH is None, "bash is not installed")
class UatGrafanaPasswordHelper(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="yuzu_test_grafana_pw_")
        self.state = Path(self.tmp.name) / "grafana-admin-password"

    def tearDown(self):
        self.tmp.cleanup()

    def test_helper_exists(self):
        self.assertTrue(HELPER.is_file(), f"missing {HELPER.relative_to(ROOT)}")

    def test_generates_persists_and_reuses(self):
        first = run_helper(self.state)
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertRegex(first.stdout, r"^[0-9a-f]{32}$")
        self.assertEqual(self.state.read_text().strip(), first.stdout)
        if os.name == "posix":
            self.assertEqual(stat.S_IMODE(self.state.stat().st_mode), 0o600)
        again = run_helper(self.state)
        self.assertEqual(again.returncode, 0, again.stderr)
        self.assertEqual(again.stdout, first.stdout, "stored value was not reused")

    def test_two_fresh_state_files_differ(self):
        other = Path(self.tmp.name) / "other"
        a, b = run_helper(self.state), run_helper(other)
        self.assertEqual((a.returncode, b.returncode), (0, 0), a.stderr + b.stderr)
        self.assertNotEqual(a.stdout, b.stdout)

    def test_exported_value_wins_and_is_persisted(self):
        run_helper(self.state)
        out = run_helper(self.state, env_value="operator-chosen-value-123")
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(out.stdout, "operator-chosen-value-123")
        self.assertEqual(self.state.read_text().strip(), "operator-chosen-value-123")

    def test_refuses_weak_or_empty(self):
        for value in ("admin", "Admin", ""):
            with self.subTest(value=value):
                out = run_helper(self.state, env_value=value)
                if value == "":
                    # Empty means "not set": a fresh value is generated.
                    self.assertEqual(out.returncode, 0, out.stderr)
                    self.assertRegex(out.stdout, r"^[0-9a-f]{32}$")
                else:
                    self.assertNotEqual(out.returncode, 0, out.stdout)
                    self.assertIn(VAR, out.stderr)

    def test_refuses_stored_admin_or_empty_file(self):
        for content in ("admin\n", "\n", ""):
            with self.subTest(content=content):
                self.state.write_text(content)
                out = run_helper(self.state)
                self.assertNotEqual(out.returncode, 0, out.stdout)

    def test_refuses_symlinked_state_file(self):
        target = Path(self.tmp.name) / "elsewhere"
        target.write_text("0123456789abcdef0123456789abcdef\n")
        try:
            self.state.symlink_to(target)
        except OSError:
            self.skipTest("cannot create a symlink here")
        out = run_helper(self.state)
        self.assertNotEqual(out.returncode, 0, out.stdout)
        self.assertEqual(target.read_text(), "0123456789abcdef0123456789abcdef\n")

    def test_generator_failure_fails_closed(self):
        # Neither openssl nor python3 usable: the helper must fail, never
        # export an empty or predictable value.
        out = run_helper(self.state, extra=(
            'openssl() { return 1; }\npython3() { return 1; }\n'
            'od() { return 1; }\n'))
        self.assertNotEqual(out.returncode, 0, out.stdout)
        self.assertFalse(self.state.exists())


def shell_functions(text):
    """Return {name: body} for top-level `name() {` ... `}` functions."""
    funcs, name, body = {}, None, []
    for line in text.splitlines():
        m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)\(\)\s*\{\s*$", line)
        if m and name is None:
            name, body = m.group(1), []
            continue
        if name is not None:
            if line == "}":
                funcs[name] = "\n".join(body)
                name = None
            else:
                body.append(line)
    return funcs


def launcher_errors(text):
    errs = []
    if not re.search(r'^\s*\.\s+"\$YUZU_ROOT/scripts/lib/uat-grafana-password\.sh"\s*$',
                     text, re.M):
        errs.append("does not source scripts/lib/uat-grafana-password.sh")
    for name, body in shell_functions(text).items():
        lines = [_strip_comment(l) for l in body.splitlines()]
        compose = [i for i, l in enumerate(lines) if re.search(r"\bdocker compose\b", l)]
        if not compose:
            continue
        helper = [i for i, l in enumerate(lines) if re.search(r"\buat_grafana_password\b", l)]
        if not helper or helper[0] > compose[0]:
            errs.append(f"{name}() runs docker compose without calling "
                        f"uat_grafana_password first")
    for i, l in enumerate(text.splitlines(), 1):
        if "Grafana" in l and "admin/admin" in l:
            errs.append(f"line {i} still prints admin/admin for Grafana")
    return errs


class UatLaunchers(unittest.TestCase):
    def test_launchers(self):
        for rel in LAUNCHERS:
            with self.subTest(rel=rel):
                text = (ROOT / rel).read_text(encoding="utf-8")
                self.assertTrue(re.search(r"\bdocker compose\b", text),
                                f"{rel}: no docker compose call found; the check proves nothing")
                errs = launcher_errors(text)
                self.assertEqual(errs, [], f"{rel}:\n" + "\n".join(errs))

    def test_launcher_mutation(self):
        for rel in LAUNCHERS:
            text = (ROOT / rel).read_text(encoding="utf-8")
            with self.subTest(rel=rel, mutation="helper call removed"):
                mutated = re.sub(r"^\s*uat_grafana_password\b.*$", "", text, flags=re.M)
                self.assertNotEqual(mutated, text, f"{rel}: no helper call to remove")
                self.assertTrue(any("without calling" in e for e in launcher_errors(mutated)))
            with self.subTest(rel=rel, mutation="banner reverted"):
                mutated = text + '\necho "  Grafana:     http://localhost:3000 (admin/admin)"\n'
                self.assertTrue(any("admin/admin" in e for e in launcher_errors(mutated)))


if __name__ == "__main__":
    unittest.main(verbosity=2)
