#!/usr/bin/env python3
"""No tracked compose may start Grafana with a known admin password (#4817).

Every shipped compose that ran Grafana used to set
`GF_SECURITY_ADMIN_PASSWORD=admin` and publish port 3000 on every interface,
so anyone who could reach the host had full Grafana admin, including adding
data sources that make Grafana's server-side client fetch arbitrary internal
URLs. Deleting the line would not help: Grafana's own built-in default is
admin/admin.

Rules checked here, for every tracked *compose*.yml and every service that
runs Grafana (a grafana/grafana image, any image or service name containing
"grafana"):

  * the environment sets GF_SECURITY_ADMIN_PASSWORD (or the __FILE form, a
    path to a secret). A missing key falls back to admin/admin, so absence
    fails exactly like a literal;
  * GF_SECURITY_ADMIN_PASSWORD is exactly `${YUZU_GRAFANA_ADMIN_PASSWORD:?<message>}`.
    `:?` makes Compose refuse to run when the variable is unset OR empty; a
    literal, a `:-`/`-` default, a bare `${VAR}` (empty when unset) or `?`
    without the colon (accepts empty) all fail. One variable name everywhere,
    so the docs, the launcher scripts and the Compose Wizard's .env agree;
  * nothing the reader cannot see decides the login: anonymous access
    (GF_AUTH_ANONYMOUS_ENABLED) and auth proxy (GF_AUTH_PROXY_ENABLED) are off,
    and the service has no `env_file:`, no `<<:` merge key and no mounted
    grafana.ini (each could set or override the password out of sight).

It also checks the UAT launchers (scripts/docker-start-UAT.sh and
scripts/win-start-UAT.sh) and the helper they share,
scripts/lib/uat-grafana-password.sh:

  * `start` (uat_grafana_password) generates a random password, keeps it in a
    0600 state file (where the filesystem honours it) and reuses it across
    restarts; an exported value wins and is saved; empty, padded, multi-line
    and `admin` values are refused with the reason; a symlink or directory
    state file is refused; each random source is a working fallback, and with
    none it fails closed;
  * `stop` and `status` (uat_grafana_password_for_compose) NEVER write, and an
    unreadable, unwritable or missing state file never stops them: the stack
    can always be stopped, and `status` says "unknown" rather than inventing a
    login;
  * the password is never exported to the processes the launchers start: every
    `docker compose` call passes it explicitly, and only after the helper ran;
    `up` only after the saving helper. Compose substitutes variables for every
    subcommand, so a stop path that forgot it would fail - and both launchers
    discard that error (`down -v 2>/dev/null && ok ... || ok "No containers
    running"`), reporting a running stack as stopped;
  * the launchers' `stop` and `status` are run for real against a fake
    `docker` (and fake process tools) in a temporary copy of the scripts;
  * neither launcher prints admin/admin any more.

Stdlib + bash; no Docker daemon. Mutation self-tests prove the rules fail when
broken.
"""

import hashlib
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
SHELL_VAR = "UAT_GRAFANA_ADMIN_PASSWORD"
PASSWORD_KEY = "GF_SECURITY_ADMIN_PASSWORD"
PASSWORD_FILE_KEY = PASSWORD_KEY + "__FILE"
REQUIRED_RE = re.compile(r"^\$\{" + VAR + r":\?(?P<msg>[^}]*\S[^}]*)\}$")
GRAFANA_IMAGE_RE = re.compile(r"^(?:docker\.io/)?grafana/grafana(?:-oss|-enterprise)?(?:[:@]|$)")
BYPASS_KEYS = ("GF_AUTH_ANONYMOUS_ENABLED", "GF_AUTH_PROXY_ENABLED")

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


def _find_bash():
    bash = shutil.which("bash")
    # On native Windows, System32\bash.exe is WSL's, which cannot open the
    # Windows temp paths these tests pass it.
    if bash and os.name == "nt" and "system32" in bash.lower():
        return None
    return bash


BASH = _find_bash()


# ── Compose reader ────────────────────────────────────────────────────────

def parse_services(text):
    """Return {service: {"image", "env", "env_file", "merge", "mounts"}}.

    Understands the subset the tracked composes use: block mappings, the list
    form (`- KEY=VALUE`, optionally quoted) and the map form (`KEY: VALUE`) of
    `environment:`, and the targets of `volumes:`/`configs:` entries (short
    `src:target[:ro]` and long `target:` forms)."""
    services = {}
    section = child = svc = prop = sub_indent = None
    current = None  # the service property whose children are being read
    for raw in text.splitlines():
        line = _strip_comment(raw)
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip(" "))
        s = line.strip()
        if indent == 0:
            section = s.split(":", 1)[0]
            child = svc = prop = sub_indent = current = None
            continue
        if section != "services":
            continue
        if child is None:
            child = indent
        if indent == child:
            m = re.match(r"^([A-Za-z0-9_.-]+):\s*$", s)
            svc = m.group(1) if m else None
            if svc:
                services.setdefault(svc, {"image": "", "env": {}, "env_file": False,
                                          "merge": False, "mounts": []})
            prop = sub_indent = current = None
            continue
        if svc is None:
            continue
        if prop is None:
            prop = indent
        entry = services[svc]
        if indent == prop:
            key, _, value = s.partition(":")
            current, sub_indent = key.strip(), None
            if current == "image":
                entry["image"] = _unquote(value)
            elif current == "env_file":
                entry["env_file"] = True
            elif current == "<<":
                entry["merge"] = True
            continue
        if indent < prop or current is None:
            continue
        if sub_indent is None:
            sub_indent = indent
        if current == "environment" and indent == sub_indent:
            if s.startswith("- "):
                key, _, value = _unquote(s[2:]).partition("=")
            else:
                key, _, value = s.partition(":")
                value = _unquote(value)
            entry["env"][key.strip()] = value.strip()
        elif current in ("volumes", "configs"):
            if s.startswith("- "):
                item = _unquote(s[2:].strip())
                kv = re.match(r"^(target|source|type|read_only):\s*(.*)$", item)
                if kv:
                    if kv.group(1) == "target":
                        entry["mounts"].append(_unquote(kv.group(2)))
                    continue
                parts = item.split(":")
                entry["mounts"].append(parts[1] if len(parts) > 1 else parts[0])
            else:
                kv = re.match(r"^target:\s*(.*)$", s)
                if kv:
                    entry["mounts"].append(_unquote(kv.group(1)))
    return services


def grafana_services(text):
    return {name: svc for name, svc in parse_services(text).items()
            if GRAFANA_IMAGE_RE.match(svc["image"]) or "grafana" in svc["image"].lower()
            or "grafana" in name.lower()}


def check(text):
    """Return a list of rule violations (empty when every Grafana is safe)."""
    errs = []
    for name, svc in grafana_services(text).items():
        env = svc["env"]
        for key in BYPASS_KEYS:
            if env.get(key, "").lower() in ("true", "1", "yes"):
                errs.append(f"{name}: {key} is on, so no password is needed")
        if svc["merge"]:
            errs.append(f"{name}: a `<<:` merge key can set the password out of this check's sight")
        if any(m.rstrip("/").endswith("grafana.ini") for m in svc["mounts"]):
            errs.append(f"{name}: a mounted grafana.ini can set the admin password or "
                        f"anonymous access out of this check's sight")
        if PASSWORD_FILE_KEY in env and PASSWORD_KEY not in env:
            if not env[PASSWORD_FILE_KEY]:
                errs.append(f"{name}: {PASSWORD_FILE_KEY} is empty")
            continue
        if PASSWORD_KEY not in env:
            why = ("it may come from env_file:, which this check cannot see; set it "
                   "in environment:" if svc["env_file"] else
                   "so Grafana falls back to its built-in admin/admin")
            errs.append(f"{name}: {PASSWORD_KEY} is not set, {why}")
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
        # #4817 literal, given a default, or removed: proves the reader sees the
        # real line.
        line_re = re.compile(r"^(\s*-\s*)" + PASSWORD_KEY + r"=.*$", re.M)
        for rel in sorted(EXPECTED_IN_SCOPE):
            text = (ROOT / rel).read_text(encoding="utf-8")
            for label, repl in (("literal admin", PASSWORD_KEY + "=admin"),
                                ("default", PASSWORD_KEY + "=${" + VAR + ":-admin}"),
                                ("bare", PASSWORD_KEY + "=${" + VAR + "}")):
                with self.subTest(rel=rel, mutation=label):
                    mutated = line_re.sub(lambda m: m.group(1) + repl, text)
                    self.assertNotEqual(mutated, text, f"{rel}: no password line found")
                    self.assertTrue(check(mutated))
            with self.subTest(rel=rel, mutation="line removed"):
                self.assertTrue(check(line_re.sub("", text)))

    BASE = """services:
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
    GOOD_ENV = f"      - {PASSWORD_KEY}=${{{VAR}:?set {VAR}, e.g. openssl rand -hex 16}}"

    def test_mutation_variants(self):
        base = self.BASE
        good = [
            self.GOOD_ENV,
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
            self.GOOD_ENV + "\n      - GF_AUTH_ANONYMOUS_ENABLED=true",
            self.GOOD_ENV + "\n      - GF_AUTH_PROXY_ENABLED=true",
        ]
        for env in bad:
            with self.subTest(bad=env):
                self.assertTrue(check(base.format(env=env)), env)
        # No environment block at all is the same as no password.
        self.assertTrue(check(base.replace("    environment:\n{env}\n", "")))
        # A non-Grafana image under a non-Grafana name is not in scope.
        other = base.replace("grafana/grafana", "prom/prometheus").replace(
            "  grafana:", "  prometheus:")
        self.assertEqual(check(other.format(env=f"      - {PASSWORD_KEY}=admin")), [])

    def test_out_of_sight_sources_fail(self):
        good = self.BASE.format(env=self.GOOD_ENV)
        cases = {
            "env_file": good.replace("    environment:\n" + self.GOOD_ENV + "\n",
                                     "    env_file: grafana.env\n"),
            "merge key": good.replace("    ports:", "    <<: *grafana-defaults\n    ports:"),
            "grafana.ini": good.replace("      - grafana-data:/var/lib/grafana",
                                        "      - grafana-data:/var/lib/grafana\n"
                                        "      - ./grafana.ini:/etc/grafana/grafana.ini:ro"),
            "image via variable": good.replace(
                "grafana/grafana:11.5.2@sha256:abc", "${GRAFANA_IMAGE}").replace(
                "    environment:\n" + self.GOOD_ENV + "\n", ""),
            "renamed service": good.replace("  grafana:", "  dashboards:").replace(
                "    environment:\n" + self.GOOD_ENV + "\n", ""),
        }
        for label, text in cases.items():
            with self.subTest(case=label):
                self.assertNotEqual(text, good, label)
                self.assertTrue(check(text), label)
        # env_file is fine when the password is still set explicitly.
        both = good.replace("    environment:", "    env_file: grafana.env\n    environment:")
        self.assertEqual(check(both), [])


# ── Helper (scripts/lib/uat-grafana-password.sh) ──────────────────────────

def run_helper(state_file, *, func="uat_grafana_password", args=(), env_value=None,
               extra="", path=None):
    """Source the helper, call FUNC, and print the shell variable it set, then
    whether that variable (and YUZU_GRAFANA_ADMIN_PASSWORD) reached a child's
    environment."""
    env = {k: v for k, v in os.environ.items() if k not in (VAR, SHELL_VAR)}
    if env_value is not None:
        env[VAR] = env_value
    if path is not None:
        env["PATH"] = path
    argv = " ".join(f'"${i + 2}"' for i in range(len(args)))
    script = (f'set -euo pipefail\n. "{HELPER.as_posix()}"\n{extra}'
              f'{func} "$1" {argv}\n'
              f'printf "%s\\n" "${{{SHELL_VAR}:-}}"\n'
              f'printf "%s\\n" "${{{SHELL_VAR}_SOURCE:-}}"\n'
              f'if env | grep -q "^{SHELL_VAR}="; then echo exported; else echo private; fi\n')
    proc = subprocess.run([BASH, "-c", script, "helper", str(state_file), *args],
                          capture_output=True, text=True, env=env, timeout=60)
    lines = proc.stdout.split("\n")
    proc.value = lines[0] if lines else ""
    proc.source = lines[1] if len(lines) > 1 else ""
    proc.exported = len(lines) > 2 and lines[2] == "exported"
    return proc


def digest(path):
    st = path.stat()
    return hashlib.sha256(path.read_bytes()).hexdigest(), st.st_mtime_ns


@unittest.skipIf(BASH is None, "bash is not installed")
class UatGrafanaPasswordHelper(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="yuzu_test_grafana_pw_")
        self.dir = Path(self.tmp.name)
        self.state = self.dir / "grafana-admin-password"

    def tearDown(self):
        self.tmp.cleanup()

    def no_tmp_left(self):
        self.assertEqual(sorted(p.name for p in self.dir.glob("*.tmp.*")), [])

    def test_helper_exists(self):
        self.assertTrue(HELPER.is_file(), f"missing {HELPER}")

    # start (persist mode)

    def test_generates_persists_and_reuses(self):
        first = run_helper(self.state)
        self.assertEqual(first.returncode, 0, first.stderr)
        self.assertRegex(first.value, r"^[0-9a-f]{32}$")
        self.assertEqual(self.state.read_text(), first.value + "\n")
        if os.name == "posix":
            self.assertEqual(stat.S_IMODE(self.state.stat().st_mode), 0o600)
        again = run_helper(self.state)
        self.assertEqual(again.returncode, 0, again.stderr)
        self.assertEqual(again.value, first.value, "stored value was not reused")
        self.no_tmp_left()

    def test_never_exported(self):
        out = run_helper(self.state)
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertFalse(out.exported, f"{SHELL_VAR} reached a child process")
        out = run_helper(self.state, func="uat_grafana_password_for_compose")
        self.assertFalse(out.exported, f"{SHELL_VAR} reached a child process")

    def test_two_fresh_state_files_differ(self):
        a = run_helper(self.state)
        b = run_helper(self.dir / "other")
        self.assertEqual((a.returncode, b.returncode), (0, 0), a.stderr + b.stderr)
        self.assertNotEqual(a.value, b.value)

    def test_exported_value_wins_and_is_persisted(self):
        run_helper(self.state)
        out = run_helper(self.state, env_value="operator-chosen-value-123")
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(out.value, "operator-chosen-value-123")
        self.assertEqual(self.state.read_text(), "operator-chosen-value-123\n")

    def test_previous_value_survives_the_wipe(self):
        # start_all reads the stored value, wipes .uat, then passes it back.
        out = run_helper(self.state, args=("value-read-before-the-wipe",))
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(out.value, "value-read-before-the-wipe")
        self.assertEqual(self.state.read_text(), "value-read-before-the-wipe\n")
        # An exported value still wins over it.
        out = run_helper(self.state, args=("previous",), env_value="exported-wins")
        self.assertEqual(out.value, "exported-wins")

    def test_refuses_weak_or_malformed_exports(self):
        for value, reason in (("admin", "admin"), ("Admin", "admin"),
                              (" admin", "whitespace"), ("admin ", "whitespace"),
                              ("\tadmin", "whitespace"), (" ", "whitespace"),
                              ("a\nb", "line break"), ("ab\r", "line break")):
            with self.subTest(value=value):
                out = run_helper(self.state, env_value=value)
                self.assertNotEqual(out.returncode, 0, out.stdout)
                self.assertIn(VAR, out.stderr)
                self.assertIn("exported", out.stderr)
                self.assertIn(reason, out.stderr)
                self.assertFalse(self.state.exists())

    def test_preflight(self):
        for value, ok in (("good-value-1234", True), ("", True), ("admin", False),
                          (" x", False), ("a\nb", False)):
            with self.subTest(value=value):
                out = run_helper(self.state, func="uat_grafana_password_preflight",
                                 env_value=value)
                self.assertEqual(out.returncode == 0, ok, out.stderr)
                if not ok:
                    self.assertIn("nothing was stopped", out.stderr)
                self.assertFalse(self.state.exists(), "preflight wrote a file")
        out = run_helper(self.state, func="uat_grafana_password_preflight")
        self.assertEqual(out.returncode, 0, out.stderr)

    def test_refusal_clears_the_shell_variable(self):
        # A caller that ignored the failure must not reach `up` with a value:
        # the read-only mode's public placeholder in particular.
        out = run_helper(self.state, env_value="admin", extra=(
            'uat_grafana_password_for_compose "$1"\n'
            'uat_grafana_password "$1" || true\n'
            'printf "%s\\n" "${UAT_GRAFANA_ADMIN_PASSWORD:-}"; exit 0\n'))
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(out.value, "")

    def test_sourcing_unexports_both_names(self):
        env = {k: v for k, v in os.environ.items() if k not in (VAR, SHELL_VAR)}
        env.update({VAR: "operator-export-1", SHELL_VAR: "inherited-2"})
        proc = subprocess.run(
            [BASH, "-c", f'. "{HELPER.as_posix()}"; env | grep -c -e "^{VAR}=" -e "^{SHELL_VAR}=" || true; '
                         f'printf "%s\\n" "${VAR}"'],
            capture_output=True, text=True, env=env, timeout=60)
        lines = proc.stdout.split("\n")
        self.assertEqual(lines[0], "0", "a child process still sees the password")
        self.assertEqual(lines[1], "operator-export-1", "the shell itself lost the value")

    def test_same_value_is_not_rewritten(self):
        self.state.write_text("stored-value-eeee\n")
        before = digest(self.state)
        out = run_helper(self.state)
        self.assertEqual((out.returncode, out.value), (0, "stored-value-eeee"), out.stderr)
        self.assertEqual(digest(self.state), before)

    def test_planted_temp_symlink_is_not_followed(self):
        target = self.dir / "target"
        target.write_text("untouched\n")
        out = run_helper(self.state, extra=f'ln -s "{target.as_posix()}" "$1.tmp.$$" || exit 3\n')
        if out.returncode == 3:
            self.skipTest("cannot create a symlink here")
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertEqual(target.read_text(), "untouched\n")
        self.assertRegex(self.state.read_text(), r"^[0-9a-f]{32}\n$")
        self.no_tmp_left()

    def test_failed_rename_leaves_no_temp_file(self):
        out = run_helper(self.state, extra="mv() { return 1; }\n")
        self.assertNotEqual(out.returncode, 0, out.stdout)
        self.assertIn("could not write", out.stderr)
        self.assertFalse(self.state.exists())
        self.no_tmp_left()

    def test_crlf_stored_value_on_read_paths(self):
        self.state.write_bytes(b"crlf-value-ffff\r\n")
        out = run_helper(self.state, func="uat_grafana_password_for_compose")
        self.assertEqual((out.value, out.source), ("crlf-value-ffff", "stored"), out.stderr)
        proc = subprocess.run([BASH, "-c", f'. "{HELPER.as_posix()}"; uat_grafana_password_stored "$1"',
                               "s", str(self.state)], capture_output=True, text=True, timeout=60)
        self.assertEqual(proc.stdout, "crlf-value-ffff")

    def test_empty_export_means_unset(self):
        out = run_helper(self.state, env_value="")
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertRegex(out.value, r"^[0-9a-f]{32}$")

    def test_stored_file_table(self):
        good = "0123456789abcdef0123456789abcdef"
        cases = [
            (good + "\n", good), (good, good), (good + "\r\n", good),
            (good + "\r\r\n", None), (" " + good + "\n", None), (good + "\t\n", None),
            ("admin\n", None), ("ADMIN\r\n", None), ("", None), ("\n", None),
            (good + "\nsecond\n", None),
        ]
        for content, expect in cases:
            with self.subTest(content=content):
                self.state.write_bytes(content.encode())
                out = run_helper(self.state)
                if expect is None:
                    self.assertNotEqual(out.returncode, 0, out.stdout)
                    self.assertIn(str(self.state), out.stderr)
                    self.assertIn("delete it", out.stderr)
                else:
                    self.assertEqual(out.returncode, 0, out.stderr)
                    self.assertEqual(out.value, expect)

    def test_refuses_symlink_or_directory_state(self):
        target = self.dir / "elsewhere"
        target.write_text("0123456789abcdef0123456789abcdef\n")
        try:
            self.state.symlink_to(target)
        except OSError:
            self.skipTest("cannot create a symlink here")
        out = run_helper(self.state)
        self.assertNotEqual(out.returncode, 0, out.stdout)
        self.assertIn("not a regular file", out.stderr)
        self.assertIn("delete it", out.stderr)
        self.assertEqual(target.read_text(), "0123456789abcdef0123456789abcdef\n")
        self.state.unlink()
        self.state.mkdir()
        out = run_helper(self.state)
        self.assertNotEqual(out.returncode, 0, out.stdout)
        self.assertIn("not a regular file", out.stderr)

    def test_each_random_source_works(self):
        # Each fake records that it ran, so a broken fallback that happens to be
        # rescued by the next one is still caught.
        mark = 'echo {name} >> "$SRC_LOG"'
        wrap = {n: f'{n}() {{ {mark.format(name=n)}; command {n} "$@"; }}\n'
                for n in ("openssl", "python3", "od")}
        fail = {n: f'{n}() {{ {mark.format(name=n)}; return 1; }}\n' for n in ("openssl", "python3")}
        crlf = ('openssl() { ' + mark.format(name="openssl") +
                "; printf '%s\\r\\n' 0123456789abcdef0123456789abcdef; }\n")
        for label, extra, expect in (
                ("openssl", wrap["openssl"] + wrap["python3"] + wrap["od"], ["openssl"]),
                ("python3", fail["openssl"] + wrap["python3"] + wrap["od"], ["openssl", "python3"]),
                ("od", fail["openssl"] + fail["python3"] + wrap["od"], ["openssl", "python3", "od"]),
                ("openssl CRLF", crlf + fail["python3"] + wrap["od"], ["openssl", "python3", "od"])):
            with self.subTest(source=label):
                state = self.dir / f"state-{label.replace(' ', '-')}"
                out = run_helper(state, extra='SRC_LOG="$1.src"\n' + extra)
                self.assertEqual(out.returncode, 0, out.stderr)
                self.assertRegex(out.value, r"^[0-9a-f]{32}$")
                self.assertNotEqual(out.value, "0123456789abcdef0123456789abcdef")
                ran = Path(str(state) + ".src").read_text().split()
                self.assertEqual(ran, expect)

    def test_generator_failure_fails_closed(self):
        out = run_helper(self.state, extra=(
            'openssl() { return 1; }\npython3() { return 1; }\nod() { return 1; }\n'))
        self.assertNotEqual(out.returncode, 0, out.stdout)
        self.assertIn("could not generate", out.stderr)
        self.assertFalse(self.state.exists())
        self.assertEqual(out.value, "")

    def test_unwritable_directory_fails_closed(self):
        if os.name != "posix" or os.geteuid() == 0:
            self.skipTest("needs a non-root POSIX user")
        self.dir.chmod(0o500)
        try:
            out = run_helper(self.state)
        finally:
            self.dir.chmod(0o700)
        self.assertNotEqual(out.returncode, 0, out.stdout)
        self.assertIn("could not write", out.stderr)
        self.no_tmp_left()

    # stop / status (read-only mode)

    def test_for_compose_never_writes(self):
        cases = {
            "absent": None,
            "valid": "stored-value-aaaa\n",
            "admin": "admin\n",
            "empty": "",
        }
        for label, content in cases.items():
            for env_value in (None, "exported-value-bbbb"):
                with self.subTest(state=label, env=env_value):
                    if self.state.exists():
                        self.state.unlink()
                    if content is not None:
                        self.state.write_text(content)
                        before = digest(self.state)
                    out = run_helper(self.state, func="uat_grafana_password_for_compose",
                                     env_value=env_value)
                    self.assertEqual(out.returncode, 0, out.stderr)
                    self.assertNotEqual(out.value, "")
                    if content is None:
                        self.assertFalse(self.state.exists(), "read-only mode wrote a file")
                    else:
                        self.assertEqual(digest(self.state), before, "read-only mode rewrote the file")
                    if env_value:
                        self.assertEqual((out.value, out.source), (env_value, "env"))
                    elif label == "valid":
                        self.assertEqual((out.value, out.source), ("stored-value-aaaa", "stored"))
                    else:
                        self.assertEqual(out.source, "none")
                    self.no_tmp_left()

    def test_for_compose_survives_hostile_state(self):
        target = self.dir / "elsewhere"
        target.write_text("target-content\n")
        self.state.mkdir()
        out = run_helper(self.state, func="uat_grafana_password_for_compose")
        self.assertEqual((out.returncode, out.source), (0, "none"), out.stderr)
        self.state.rmdir()
        try:
            self.state.symlink_to(target)
        except OSError:
            self.skipTest("cannot create a symlink here")
        out = run_helper(self.state, func="uat_grafana_password_for_compose")
        self.assertEqual((out.returncode, out.source), (0, "none"), out.stderr)
        self.assertEqual(target.read_text(), "target-content\n")

    def test_for_compose_needs_no_random_source(self):
        out = run_helper(self.state, func="uat_grafana_password_for_compose", extra=(
            'openssl() { return 1; }\npython3() { return 1; }\nod() { return 1; }\n'))
        self.assertEqual(out.returncode, 0, out.stderr)
        self.assertNotEqual(out.value, "")

    def test_for_compose_ignores_unwritable_directory(self):
        if os.name != "posix" or os.geteuid() == 0:
            self.skipTest("needs a non-root POSIX user")
        self.dir.chmod(0o500)
        try:
            out = run_helper(self.state, func="uat_grafana_password_for_compose")
        finally:
            self.dir.chmod(0o700)
        self.assertEqual(out.returncode, 0, out.stderr)

    def test_describe(self):
        def describe(env_value=None):
            env = {k: v for k, v in os.environ.items() if k != VAR}
            if env_value is not None:
                env[VAR] = env_value
            return subprocess.run(
                [BASH, "-c", f'. "{HELPER.as_posix()}"; uat_grafana_password_describe "$1"',
                 "d", str(self.state)], capture_output=True, text=True, env=env,
                timeout=60).stdout
        self.assertIn("unknown", describe())
        self.assertNotRegex(describe(), r"[0-9a-f]{32}")
        self.assertIn("exported", describe("exported-cccc"))
        self.assertIn("would be refused", describe("admin"))
        self.assertNotIn("admin / admin", describe("admin"))
        self.state.write_text("stored-dddd\n")
        self.assertEqual(describe("exported-cccc"), "admin / stored-dddd")
        self.assertFalse(any(self.dir.glob("*.tmp.*")))


# ── Launchers: lexical rules ──────────────────────────────────────────────
#
# These are BEST-EFFORT guards over the shapes the launchers use; bash has more
# spellings than any regex covers (an indirect `export "$v"`, `builtin export`).
# The behavioural UatLauncherRuns / helper tests below are the backstop: they
# run the real launchers and helper and observe what child processes see.

ASSIGN_RE = r"(?:[A-Za-z_][A-Za-z0-9_]*=(?:\"[^\"]*\"|'[^']*'|\S*)\s+)*"
COMPOSE_CMD_RE = re.compile(r"^" + ASSIGN_RE + r"docker\s+compose\b")
COMPOSE_ANY_RE = re.compile(r"\bdocker\s+compose\b|\bdocker-compose(?![\w.-])")
PASS_PREFIX = f'{VAR}="${SHELL_VAR}"'
PRINT_RE = re.compile(r"^(echo|printf|ok|fail|warn|info)\b")
# Definitions this check cannot read: the `function` keyword, or `name()` with
# its `{` on the next line. One-line `name() { ...; }` helpers are fine: a
# compose call inside one is reported as outside a function.
BAD_FUNC_DEF_RE = re.compile(r"^\s*(function\s+[A-Za-z_]\w*|[A-Za-z_]\w*\s*\(\)\s*)$")
VAR_COMPOSE_RE = re.compile(r"^" + ASSIGN_RE + r"\"?\$\{?(\w*(compose|COMPOSE)\w*|DC)\}?\"?(\s|$)"
                            r"|^" + ASSIGN_RE + r"\"?\$\{?\w+\}?\"?\s+compose\b")
WIPE_RE = re.compile(r'(rm\s+-rf\s+"\$UAT_DIR"|find\s+"\$UAT_DIR")')
# A helper call counts only as a plain statement of its own: not under `if`,
# in a subshell, after `||`/`&&`, or inside a string.
PERSIST_CALL_RE = re.compile(r'^uat_grafana_password\s+"\$GRAFANA_PASSWORD_FILE"(\s+"\$grafana_prev")?$')
ANY_HELPER_RE = re.compile(r'^uat_grafana_password(_for_compose)?\s+"\$GRAFANA_PASSWORD_FILE"(\s+"\$grafana_prev")?$')
PREFLIGHT_RE = re.compile(r"^uat_grafana_password_preflight$")
EXPORT_FORMS_RE = re.compile(r"\b(declare|typeset|local)\s+-\w*x|\bset\s+-[A-Za-z]*a|\bset\s+-o\s+allexport\b")
UNEXPORT_RE = re.compile(r'^\.\s+"\$YUZU_ROOT/scripts/lib/uat-grafana-password\.sh"\s*$')


def split_commands(logical):
    """Split a logical line on ; && || | outside quotes."""
    parts, buf, quote, i = [], [], None, 0
    while i < len(logical):
        ch = logical[i]
        if quote:
            if ch == quote:
                quote = None
            buf.append(ch)
        elif ch in "'\"":
            quote = ch
            buf.append(ch)
        elif ch == ";" or logical.startswith("&&", i) or logical.startswith("||", i) or ch == "|":
            parts.append("".join(buf).strip())
            buf = []
            if logical.startswith(("&&", "||"), i):
                i += 1
        else:
            buf.append(ch)
        i += 1
    parts.append("".join(buf).strip())
    return [p for p in parts if p]


def logical_lines(text):
    """Yield (first_line_number, logical_line) with comments stripped and
    backslash continuations joined."""
    buf, start = [], None
    for n, raw in enumerate(text.splitlines(), 1):
        line = _strip_comment(raw)
        if start is None:
            start = n
        if line.endswith("\\"):
            buf.append(line[:-1].strip())
            continue
        buf.append(line.strip())
        joined = " ".join(p for p in buf if p)
        if joined:
            yield start, joined
        buf, start = [], None


def shell_functions(text):
    """Return ({name: [(line_no, logical_line)]}, {line_no of every top-level line})."""
    funcs, name, body, top = {}, None, [], set()
    lines = text.splitlines()
    func_ranges = []
    for n, line in enumerate(lines, 1):
        m = re.match(r"^([A-Za-z_][A-Za-z0-9_]*)\(\)\s*\{\s*$", line)
        if m and name is None:
            name, begin = m.group(1), n
            continue
        if name is not None and line == "}":
            func_ranges.append((name, begin, n))
            name = None
    for fname, begin, end in func_ranges:
        funcs[fname] = []
    for n, logical in logical_lines(text):
        owner = next((f for f, b, e in func_ranges if b < n < e), None)
        if owner is None:
            top.add((n, logical))
        else:
            funcs[owner].append((n, logical))
    return funcs, top, func_ranges


def launcher_errors(text):
    errs = []
    lines = text.splitlines()
    src = [i for i, l in enumerate(lines) if UNEXPORT_RE.match(l)]
    first_func = next((i for i, l in enumerate(lines)
                       if re.match(r"^[A-Za-z_]\w*\(\)\s*\{", l)), len(lines))
    if not src:
        errs.append("does not source scripts/lib/uat-grafana-password.sh")
    elif src[0] > first_func:
        errs.append("sources the helper after its first function definition: its "
                    "un-export must run before anything else")
    if not any(re.match(r"^set -euo pipefail\s*$", l) for l in lines[:first_func]):
        errs.append("no top-level `set -euo pipefail` before the functions: the "
                    "helper's refusals rely on errexit")
    for n, logical in logical_lines(text):
        for cmd in split_commands(logical):
            args = cmd.split()
            # Look past compound-command openers: `then set +e`, `{ set +e`, `(set +e`.
            while args and args[0] in ("then", "do", "else", "{", "(", "!"):
                args = args[1:]
            if args and args[0].startswith("(") and args[0] != "(":
                args[0] = args[0][1:]
            if not args or args[0] != "set":
                continue
            args = [a.rstrip(");}") for a in args]
            for a, nxt in zip(args[1:], args[2:] + [""]):
                if re.fullmatch(r"\+[A-Za-z]*e[A-Za-z]*", a) or (a == "+o" and nxt == "errexit"):
                    errs.append(f"line {n}: turns errexit off; the helper's refusals rely on it")
    funcs, top, ranges = shell_functions(text)
    for i, l in enumerate(text.splitlines(), 1):
        if BAD_FUNC_DEF_RE.match(_strip_comment(l)) or re.match(r"^\s*function\s", l):
            errs.append(f"line {i}: function definition not in the `name() {{` form "
                        f"this check reads")
    for n, logical in top:
        if COMPOSE_ANY_RE.search(logical) and not PRINT_RE.match(logical):
            errs.append(f"line {n}: docker compose call outside a function")
    for n, logical in [(n, l) for f in funcs.values() for n, l in f] + sorted(top):
        for cmd in split_commands(logical):
            if VAR_COMPOSE_RE.match(cmd):
                errs.append(f"line {n}: command run through a variable: {cmd[:60]}")
        for cmd in split_commands(logical):
            if re.match(r"^export\b", cmd) and not re.match(r"^export\s+-n\b", cmd) \
                    and re.search(r"\b(" + VAR + "|" + SHELL_VAR + r")\b", cmd):
                errs.append(f"line {n}: exports the Grafana password to child processes")
        if EXPORT_FORMS_RE.search(logical):
            errs.append(f"line {n}: exports variables wholesale or by declare/typeset -x")
    for name, body in funcs.items():
        helpers = [(n, bool(PERSIST_CALL_RE.match(l))) for n, l in body if ANY_HELPER_RE.match(l)]
        for n, logical in body:
            cmds = [c for c in split_commands(logical)
                    if COMPOSE_ANY_RE.search(c) and not PRINT_RE.match(c)]
            if not cmds:
                continue
            if len(cmds) > 1 or not COMPOSE_CMD_RE.match(cmds[0]) or not logical.startswith(cmds[0]):
                errs.append(f"{name}() line {n}: unrecognised compose invocation: {logical[:60]}")
                continue
            logical = cmds[0]
            if PASS_PREFIX not in logical.split("docker", 1)[0]:
                errs.append(f"{name}() line {n}: docker compose without {PASS_PREFIX}")
            earlier = [persist for h, persist in helpers if h < n]
            if not earlier:
                errs.append(f"{name}() runs docker compose without calling the "
                            f"uat_grafana_password helper first")
            elif re.search(r"\bup\b", logical.split("compose", 1)[1]) and not any(earlier):
                errs.append(f"{name}() runs docker compose up without the saving "
                            f"helper uat_grafana_password")
    for n, logical in sorted(top):
        cmds = split_commands(logical.split(")", 1)[-1]) if re.match(r"^\w+\)", logical) else []
        if any(c.startswith("rebuild_images") for c in cmds):
            first = next(i for i, c in enumerate(cmds) if c.startswith("rebuild_images"))
            arm = logical.split(")", 1)[1]
            # The preflight must be a plain `;`-terminated statement (errexit
            # applies), never part of an `||`/`&&` list that would swallow it.
            if not re.match(r"^\s*uat_grafana_password_preflight\s*;", arm):
                errs.append(f"line {n}: rebuild builds images before "
                            f"uat_grafana_password_preflight")
    start = funcs.get("start_all", [])
    preflight = [n for n, l in start if PREFLIGHT_RE.match(l)]
    kills = [n for n, l in start if re.match(r"^kill_\w+$", l)]
    if not (preflight and kills and preflight[0] < kills[0]):
        errs.append("start_all() must call uat_grafana_password_preflight before it "
                    "stops anything (kill_*)")
    wipe = [n for n, l in start if WIPE_RE.search(l)]
    stored = [n for n, l in start if "uat_grafana_password_stored" in l]
    persist = [n for n, l in start if PERSIST_CALL_RE.match(l)]
    if not (wipe and stored and persist and stored[0] < wipe[0] < persist[0]):
        errs.append("start_all() must read uat_grafana_password_stored before the "
                    ".uat wipe and call uat_grafana_password after it")
    for i, l in enumerate(text.splitlines(), 1):
        if "Grafana" in l and "admin/admin" in l:
            errs.append(f"line {i} still prints admin/admin for Grafana")
    return errs


class UatLaunchers(unittest.TestCase):
    def test_launchers(self):
        for rel in LAUNCHERS:
            with self.subTest(rel=rel):
                text = (ROOT / rel).read_text(encoding="utf-8")
                self.assertGreaterEqual(len(COMPOSE_ANY_RE.findall(text)), 3,
                                        f"{rel}: expected its 3 docker compose calls")
                errs = launcher_errors(text)
                self.assertEqual(errs, [], f"{rel}:\n" + "\n".join(errs))

    def test_launcher_mutation(self):
        def lines_matching(text, pattern):
            return [i for i, l in enumerate(text.splitlines()) if re.search(pattern, l)]

        def drop(text, idx):
            ls = text.splitlines()
            del ls[idx]
            return "\n".join(ls) + "\n"

        for rel in LAUNCHERS:
            text = (ROOT / rel).read_text(encoding="utf-8")
            calls = lines_matching(text, r"^\s*uat_grafana_password(_for_compose)?\s")
            self.assertGreaterEqual(len(calls), 3, rel)
            for idx in calls:
                with self.subTest(rel=rel, mutation=f"helper call on line {idx + 1} removed"):
                    self.assertTrue(launcher_errors(drop(text, idx)))
            prefixes = lines_matching(text, re.escape(PASS_PREFIX) + r" \\$")
            self.assertGreaterEqual(len(prefixes), 3, rel)
            for idx in prefixes:
                with self.subTest(rel=rel, mutation=f"password prefix on line {idx + 1} removed"):
                    self.assertTrue(any("without " + PASS_PREFIX in e
                                        for e in launcher_errors(drop(text, idx))))
            mutations = {
                "banner reverted": text + '\necho "  Grafana:     http://localhost:3000 (admin/admin)"\n',
                "export": text.replace("GRAFANA_PASSWORD_FILE=", f"export {VAR}=x\nGRAFANA_PASSWORD_FILE=", 1),
                "top-level compose": text + "\ndocker compose -f x.yml down\n",
                "compose via variable": text.replace("kill_docker() {", 'kill_docker() {\n    "$DC" -f x down', 1),
                "function keyword": text + "\nfunction extra {\n    docker compose -f x.yml ps\n}\n",
                "persist swapped for read-only before up": re.sub(
                    r'uat_grafana_password "\$GRAFANA_PASSWORD_FILE" "\$grafana_prev"',
                    'uat_grafana_password_for_compose "$GRAFANA_PASSWORD_FILE"', text),
                "helper under if false": text.replace(
                    '    uat_grafana_password_for_compose "$GRAFANA_PASSWORD_FILE"',
                    '    if false; then uat_grafana_password_for_compose "$GRAFANA_PASSWORD_FILE"; fi'),
                "helper with || true": text.replace(
                    '    uat_grafana_password_for_compose "$GRAFANA_PASSWORD_FILE"',
                    '    uat_grafana_password_for_compose "$GRAFANA_PASSWORD_FILE" || true'),
                "compose after an echo on one line": text.replace(
                    "kill_docker() {", 'kill_docker() {\n    echo hi; docker compose -f x.yml up -d', 1),
                "set -a": text + "\nset -a\n",
                "set -ae": text + "\nset -ae\n",
                "export as second word": text + f"\nexport FOO {SHELL_VAR}\n",
                "export after export -n": text + f"\nexport -n FOO; export {VAR}\n",
                "errexit dropped": text.replace("set -euo pipefail", "set -uo pipefail", 1),
                "helper sourced late": text.replace(
                    '. "$YUZU_ROOT/scripts/lib/uat-grafana-password.sh"\n', "", 1)
                    + '\n. "$YUZU_ROOT/scripts/lib/uat-grafana-password.sh"\n',
                "declare -x": text.replace("GRAFANA_PASSWORD_FILE=", "declare -x GRAFANA_PASSWORD_FILE=", 1),
                "preflight removed": text.replace("    uat_grafana_password_preflight\n", ""),
                **({"rebuild before preflight": text.replace(
                    "rebuild) uat_grafana_password_preflight; ", "rebuild) "),
                    "rebuild preflight || true": text.replace(
                    "rebuild) uat_grafana_password_preflight; ",
                    "rebuild) uat_grafana_password_preflight || true; ")}
                   if "rebuild)" in text else {}),
                "set +e": text + "\nset +e\n",
                "set +euo pipefail": text + "\nset +euo pipefail\n",
                "set -u +e": text + "\nset -u +e\n",
                "set +e under if": text + "\nif true; then set +e; fi\n",
                "set +e in braces": text + "\n{ set +e; }\n",
                "set +e in a subshell": text + "\n(set +e)\n",
                "set +o errexit": text + "\nset +o errexit\n",
                "preflight after the kills": re.sub(
                    r"    uat_grafana_password_preflight\n(    kill_\w+\n    kill_docker\n)",
                    r"\1    uat_grafana_password_preflight\n", text),
                "stored read moved after the wipe": text.replace(
                    'grafana_prev="$(uat_grafana_password_stored "$GRAFANA_PASSWORD_FILE")" || grafana_prev=""',
                    "true"),
            }
            for label, mutated in mutations.items():
                with self.subTest(rel=rel, mutation=label):
                    self.assertNotEqual(mutated, text, label)
                    self.assertTrue(launcher_errors(mutated), label)


# ── Launchers: stop and status run for real against fakes ─────────────────

FAKE_DOCKER = """#!/bin/bash
{{
  printf 'argv=%s\\n' "$*"
  printf 'pw=%s\\n' "${{YUZU_GRAFANA_ADMIN_PASSWORD:-}}"
  if env | grep -q '^UAT_GRAFANA_ADMIN_PASSWORD='; then echo leaked=1; else echo leaked=0; fi
}} >> "{log}"
exit 0
"""


@unittest.skipIf(BASH is None or os.name != "posix", "needs bash on a POSIX host")
class UatLauncherRuns(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="yuzu_test_grafana_launch_")
        self.root = Path(self.tmp.name) / "root"
        (self.root / "scripts" / "lib").mkdir(parents=True)
        (self.root / "deploy" / "docker").mkdir(parents=True)
        for rel in LAUNCHERS + ("scripts/lib/uat-grafana-password.sh",):
            shutil.copy(ROOT / rel, self.root / rel)
        self.bin = Path(self.tmp.name) / "bin"
        self.bin.mkdir()
        self.log = Path(self.tmp.name) / "docker.log"
        fakes = {
            "docker": FAKE_DOCKER.format(log=self.log),
            # Never touch real processes on this host. pgrep also records whether
            # a non-docker child process can see the password.
            "pgrep": ("#!/bin/sh\nenv | grep -c -e '^YUZU_GRAFANA_ADMIN_PASSWORD=' "
                      f"-e '^UAT_GRAFANA_ADMIN_PASSWORD=' >> \"{Path(self.tmp.name) / 'child.log'}\"\n"
                      "exit 1\n"),
            "pkill": "#!/bin/sh\nexit 1\n",
            "tasklist": ("#!/bin/sh\nenv | grep -c -e '^YUZU_GRAFANA_ADMIN_PASSWORD=' "
                         f"-e '^UAT_GRAFANA_ADMIN_PASSWORD=' >> \"{Path(self.tmp.name) / 'child.log'}\"\n"
                         "exit 0\n"),
            "taskkill": "#!/bin/sh\nexit 1\n",
            "netstat": "#!/bin/sh\nexit 0\n", "sleep": "#!/bin/sh\nexit 0\n",
        }
        for name, body in fakes.items():
            p = self.bin / name
            p.write_text(body)
            p.chmod(0o755)
        self.state = self.root / ".uat" / "grafana-admin-password"

    def tearDown(self):
        (self.root / ".uat").chmod(0o700) if (self.root / ".uat").exists() else None
        self.tmp.cleanup()

    def run_launcher(self, rel, command, env_value=None, extra_env=None):
        env = {k: v for k, v in os.environ.items() if k not in (VAR, SHELL_VAR)}
        env["PATH"] = f"{self.bin}{os.pathsep}{env['PATH']}"
        if env_value is not None:
            env[VAR] = env_value
        env.update(extra_env or {})
        if self.log.exists():
            self.log.unlink()
        proc = subprocess.run([BASH, str(self.root / rel), command], capture_output=True,
                              text=True, env=env, timeout=60, cwd=str(self.root))
        proc.calls = self.log.read_text().split("argv=")[1:] if self.log.exists() else []
        return proc

    def test_refused_export_stops_nothing(self):
        # start must refuse a bad exported value BEFORE kill_* / down -v, or a
        # typo tears down a running stack (and its saved password) first.
        # Preflight checks (images, agents) fail first in this sandbox, so drive
        # the start_all prefix directly: everything up to the first kill.
        for rel in LAUNCHERS:
            with self.subTest(rel=rel):
                text = (self.root / rel).read_text()
                body = re.search(r"^start_all\(\) \{\n(.*?)^\}", text, re.M | re.S).group(1)
                script = (f'set -euo pipefail\nYUZU_ROOT="{self.root}"\n'
                          f'. "{self.root}/scripts/lib/uat-grafana-password.sh"\n'
                          'kill_agent() { echo KILLED; }\nkill_native() { echo KILLED; }\n'
                          'kill_docker() { echo KILLED; }\n'
                          + body[body.index("uat_grafana_password_preflight"):
                                 body.index("kill_docker") + len("kill_docker")] + "\n")
                env = {k: v for k, v in os.environ.items() if k not in (VAR, SHELL_VAR)}
                env[VAR] = "admin"
                proc = subprocess.run([BASH, "-c", script], capture_output=True, text=True,
                                      env=env, timeout=60)
                self.assertNotEqual(proc.returncode, 0, proc.stdout)
                self.assertNotIn("KILLED", proc.stdout)
                self.assertIn("nothing was stopped", proc.stderr)

    def assert_calls(self, proc, verb, pw=None):
        self.assertTrue(proc.calls, f"docker was never called\n{proc.stdout}\n{proc.stderr}")
        for call in proc.calls:
            self.assertIn(f" {verb}", call.split("\n")[0])
            got = re.search(r"^pw=(.*)$", call, re.M).group(1)
            self.assertNotEqual(got, "", "docker compose got an empty password")
            if pw is not None:
                self.assertEqual(got, pw)
            self.assertIn("leaked=0", call)

    def test_no_state_file(self):
        # No state file: a stack started before #4817, or after .uat was removed.
        for rel in LAUNCHERS:
            with self.subTest(rel=rel):
                status = self.run_launcher(rel, "status")
                self.assertEqual(status.returncode, 0, status.stderr)
                self.assert_calls(status, "ps")
                grafana = [l for l in status.stdout.splitlines() if "Grafana:" in l]
                self.assertTrue(grafana and "unknown" in grafana[0], status.stdout)
                self.assertNotRegex(grafana[0], r"[0-9a-f]{32}")
                stop = self.run_launcher(rel, "stop")
                self.assertEqual(stop.returncode, 0, stop.stderr)
                self.assert_calls(stop, "down")
                self.assertFalse(self.state.exists(), "stop/status wrote a state file")

    def test_export_differs_from_stored(self):
        # A stray export: stop/status never rewrite the record of the effective password.
        self.state.parent.mkdir()
        self.state.write_text("effective-password-1\n")
        before = digest(self.state)
        for rel in LAUNCHERS:
            for command, verb in (("status", "ps"), ("stop", "down")):
                with self.subTest(rel=rel, command=command):
                    out = self.run_launcher(rel, command, env_value="stray-export-2")
                    self.assertEqual(out.returncode, 0, out.stderr)
                    self.assert_calls(out, verb, pw="stray-export-2")
                    self.assertEqual(digest(self.state), before)
                    if command == "status":
                        self.assertIn("admin / effective-password-1", out.stdout)

    def test_unwritable_state_directory(self):
        # An unwritable .uat: stop must still reach `down`.
        if os.geteuid() == 0:
            self.skipTest("root ignores directory permissions")
        self.state.parent.mkdir()
        self.state.parent.chmod(0o500)
        for rel in LAUNCHERS:
            with self.subTest(rel=rel):
                out = self.run_launcher(rel, "stop")
                self.assertEqual(out.returncode, 0, out.stderr)
                self.assert_calls(out, "down")

    def test_hostile_state_file(self):
        # A directory where the state file should be.
        self.state.mkdir(parents=True)
        for rel in LAUNCHERS:
            with self.subTest(rel=rel):
                for command, verb in (("status", "ps"), ("stop", "down")):
                    out = self.run_launcher(rel, command)
                    self.assertEqual(out.returncode, 0, out.stderr)
                    self.assert_calls(out, verb)
                self.assertTrue(self.state.is_dir())

    def test_exported_password_does_not_reach_other_children(self):
        # tasklist (both launchers) and pgrep (docker-start-UAT.sh) record whether
        # they can see either name in their environment.
        child_log = Path(self.tmp.name) / "child.log"
        for rel in LAUNCHERS:
            with self.subTest(rel=rel):
                if child_log.exists():
                    child_log.unlink()
                out = self.run_launcher(rel, "stop", env_value="operator-export-1",
                                        extra_env={SHELL_VAR: "inherited-export-2"})
                self.assertEqual(out.returncode, 0, out.stderr)
                self.assert_calls(out, "down", pw="operator-export-1")
                counts = child_log.read_text().split() if child_log.exists() else []
                self.assertTrue(counts, "no non-docker child process ran")
                self.assertEqual(set(counts), {"0"}, "a non-docker child saw the Grafana password")

    def test_weak_export_still_stops(self):
        # stop does not judge the value: `down` must work whatever is exported.
        for rel in LAUNCHERS:
            with self.subTest(rel=rel):
                out = self.run_launcher(rel, "stop", env_value="admin")
                self.assertEqual(out.returncode, 0, out.stderr)
                self.assert_calls(out, "down")


if __name__ == "__main__":
    unittest.main(verbosity=2)
