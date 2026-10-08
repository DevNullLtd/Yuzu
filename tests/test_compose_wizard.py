#!/usr/bin/env python3
"""Every Compose Wizard mode must give the server a WRITABLE /etc/yuzu/certs (#5420).

The server writes its secrets KEK (FileKeyProvider) and its internal CA into
/etc/yuzu/certs (auth::default_cert_dir(); the wizard passes no --ca-dir). The
KEK is registered in Postgres, so the directory must be writable and live
exactly as long as the database (#5370). Operator mode used to bind-mount the
operator's PEM files READ-ONLY over that directory (`./certs:/etc/yuzu/certs:ro`),
so the server could not write its KEK and stopped at first boot.

This test runs the wizard's real generator, tools/compose-wizard/js/generate.js,
under node (the `vm` module, with only the DOM/alert shims generate() touches)
and checks the generated compose for the matrix

    tlsMode in {plaintext, default, operator}
  x persistentVolumes in {true, false}
  x pgBundled in {true, false}

with the gateway off (gateway + TLS is refused by design). For every compose:

  * the `server` service mounts /etc/yuzu/certs exactly once, writable (no
    :ro) and never from a host bind mount;
  * it is a NAMED volume declared under top-level `volumes:` whenever named
    volumes are on or Postgres is external (anonymous is allowed only with
    named volumes off + bundled Postgres, where the database volume is
    anonymous too and both are discarded together);
  * no service mounts anything read-only over /etc/yuzu/certs, and every named
    volume a service mounts is declared;
  * Operator mode mounts the PEMs as `./certs:/etc/yuzu/tls:ro` and every
    --cert/--key/--ca-cert path is under /etc/yuzu/tls/; the other modes pass
    none of those flags.

It also drives the browser entry point generate() with stubbed form fields to
prove the wizard refuses an operator cert/key/CA path outside /etc/yuzu/tls/.

Skips cleanly when `node` is not on PATH. Set YUZU_WIZARD_GENERATE_JS to point
the test at another copy of generate.js (used to show the pre-fix generator
fails the operator cases). Stdlib only; the volume reader is shared with
test_compose_certs_volume.py.
"""

import itertools
import json
import os
import posixpath
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_compose_certs_volume import _strip_comment, _unquote, parse_compose  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
GENERATE_JS = Path(os.environ.get("YUZU_WIZARD_GENERATE_JS")
                   or ROOT / "tools" / "compose-wizard" / "js" / "generate.js")
CERTS = "/etc/yuzu/certs"
TLS_DIR = "/etc/yuzu/tls"
NODE = shutil.which("node")

# Node driver: loads generate.js into a fresh vm context (classic-script
# semantics, like the browser's <script> tag) and either calls the pure
# generateCompose(config) for each config, or runs the async generate() entry
# point against stubbed form fields.
DRIVER = r"""
'use strict';
const fs = require('fs');
const vm = require('vm');
const [, , srcPath, mode] = process.argv;
const input = JSON.parse(fs.readFileSync(0, 'utf8'));
const alerts = [];
const fields = Object.assign({}, input.fields || {});
const elements = {};
function el(id) {
  if (!elements[id]) {
    const f = fields[id];
    elements[id] = {
      value: f === undefined ? '' : (typeof f === 'boolean' ? '' : String(f)),
      checked: f === true,
      textContent: '',
      innerHTML: '',
      style: {},
      scrollIntoView() {},
    };
  }
  return elements[id];
}
const sandbox = {
  console,
  TextEncoder,
  Uint8Array,
  crypto: globalThis.crypto,
  window: { crypto: globalThis.crypto },
  alert: m => alerts.push(String(m)),
  document: { getElementById: el },
  // wizard.js helpers generate() calls (same bodies as wizard.js).
  val: id => el(id).value.trim(),
  num: id => parseInt(el(id).value) || 0,
  chk: id => el(id).checked,
};
vm.createContext(sandbox);
vm.runInContext(fs.readFileSync(srcPath, 'utf8'), sandbox, { filename: srcPath });
(async () => {
  if (mode === 'compose') {
    sandbox.__configs = input.configs;
    const out = vm.runInContext('__configs.map(c => generateCompose(c))', sandbox);
    process.stdout.write(JSON.stringify({ composes: out }));
  } else {
    await vm.runInContext('generate()', sandbox);
    process.stdout.write(JSON.stringify({
      alerts,
      compose: el('compose-output').textContent,
    }));
  }
})().catch(e => { console.error(e && e.stack || e); process.exit(2); });
"""

BASE_CONFIG = {
    "authLine": "admin:admin:00112233445566778899aabbccddeeff:"
                + "ab" * 32,
    "gwCookie": "cd" * 32,
    "version": "0.14.1",
    "adminUser": "admin",
    "adminPass": "correct-horse-battery",
    "dashboardPort": 8080,
    "grpcPort": 50051,
    "mgmtPort": 50052,
    "gwUpstreamPort": 50055,
    "tlsCert": "",
    "tlsKey": "",
    "tlsCaCert": "",
    "certSans": "",
    "persistCerts": True,
    "dataDir": "/var/lib/yuzu",
    "pgSuperPass": "s" * 24,
    "pgAppPass": "a" * 24,
    "pgDsn": "",
    "clickhouse": False,
    "chHttpPort": 8123,
    "chNativePort": 9000,
    "chUser": "yuzu",
    "chPass": "chpass",
    "chDb": "yuzu",
    "prometheus": True,
    "promPort": 9090,
    "grafana": True,
    "grafanaPort": 3000,
    "grafanaPass": "grafana",
    "gateway": False,
    "gwAgentPort": 50061,
    "gwHealthPort": 8081,
    "gwMetricsPort": 9568,
    "gwPoolSize": 4,
    "gwTls": False,
}

OPERATOR_PATHS = {
    "tlsCert": f"{TLS_DIR}/server.pem",
    "tlsKey": f"{TLS_DIR}/server.key",
    "tlsCaCert": f"{TLS_DIR}/ca.pem",
}

MATRIX = list(itertools.product(("plaintext", "default", "operator"),
                                (True, False), (True, False)))


def make_config(tls_mode, persistent, pg_bundled):
    c = dict(BASE_CONFIG)
    c.update(tlsMode=tls_mode, persistentVolumes=persistent,
             pgBundled=pg_bundled, pgMode="bundled" if pg_bundled else "external")
    if not pg_bundled:
        c["pgDsn"] = "postgresql://yuzu:pw@db.example:5432/yuzu"
    if tls_mode == "operator":
        c.update(OPERATOR_PATHS)
    return c


def run_node(mode, payload):
    with tempfile.TemporaryDirectory(prefix="yuzu_test_wizard_") as d:
        driver = Path(d) / "driver.js"
        driver.write_text(DRIVER, encoding="utf-8")
        proc = subprocess.run([NODE, str(driver), str(GENERATE_JS), mode],
                              input=json.dumps(payload), capture_output=True,
                              text=True, timeout=60)
    if proc.returncode != 0:
        raise AssertionError(f"node driver failed ({proc.returncode}):\n{proc.stderr}")
    return json.loads(proc.stdout)


def server_command(text):
    """Return the server service's `command:` list (short-syntax items only)."""
    args, section, svc, in_cmd, cmd_indent = [], None, None, False, None
    for raw in text.splitlines():
        line = _strip_comment(raw)
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip(" "))
        s = line.strip()
        if indent == 0:
            section, svc, in_cmd = s.split(":", 1)[0], None, False
            continue
        if section != "services":
            continue
        if indent == 2:
            svc, in_cmd = s.rstrip(":"), False
            continue
        if svc != "server":
            continue
        if indent == 4:
            in_cmd, cmd_indent = s == "command:", None
            continue
        if in_cmd and s.startswith("- "):
            if cmd_indent is None:
                cmd_indent = indent
            if indent == cmd_indent:
                args.append(_unquote(s[2:]))
    return args


def flag_values(args, flag):
    return [args[i + 1] for i, a in enumerate(args[:-1]) if a == flag]


def is_bind(src):
    return src.startswith((".", "/", "~", "$"))


def under_tls_dir(path):
    return (path.startswith(TLS_DIR + "/")
            and posixpath.normpath(path) == path)


def check_compose(text, tls_mode, persistent, pg_bundled):
    """Return a list of rule violations for one generated compose."""
    errs = []
    services, top_volumes = parse_compose(text)
    if "server" not in services:
        return ["no server service"]
    server = services["server"]

    certs = [(src, ro) for src, t, ro in server if t.rstrip("/") == CERTS]
    if len(certs) != 1:
        errs.append(f"server mounts {CERTS} {len(certs)} times, want exactly 1")
    for src, ro in certs:
        if ro:
            errs.append(f"server mounts {CERTS} read-only ('{src}'); the server "
                        f"writes its KEK and CA there")
        if src and is_bind(src):
            errs.append(f"server mounts {CERTS} from host path '{src}', not a volume")
        if (persistent or not pg_bundled) and (not src or is_bind(src)):
            errs.append(f"{CERTS} must be a NAMED volume (named volumes on or "
                        f"external Postgres), got '{src or '(anonymous)'}'")
        if src and not is_bind(src) and src not in top_volumes:
            errs.append(f"volume '{src}' on {CERTS} is not declared under top-level volumes:")

    for name, mounts in services.items():
        for src, t, ro in mounts:
            if t.rstrip("/") == CERTS and ro:
                errs.append(f"service {name} mounts '{src}' read-only over {CERTS}")
            if src and not is_bind(src) and src not in top_volumes:
                errs.append(f"service {name} mounts undeclared named volume '{src}'")

    args = server_command(text)
    tls_flags = {f: flag_values(args, f) for f in ("--cert", "--key", "--ca-cert")}
    if tls_mode == "operator":
        if ("./certs", TLS_DIR, True) not in [(s, t.rstrip("/"), ro) for s, t, ro in server]:
            errs.append(f"operator PEMs are not mounted as ./certs:{TLS_DIR}:ro "
                        f"(server mounts: {server})")
        for flag, vals in tls_flags.items():
            if len(vals) != 1:
                errs.append(f"server passes {flag} {len(vals)} times, want exactly 1")
            for v in vals:
                if not under_tls_dir(v):
                    errs.append(f"{flag} {v} is not under {TLS_DIR}/")
    else:
        for flag, vals in tls_flags.items():
            if vals:
                errs.append(f"{tls_mode} mode passes {flag} {vals}")
    return errs


# Form-field values for the browser entry point generate(), mirroring
# index.html's defaults for a server-only bundled-Postgres operator stack.
FORM_FIELDS = {
    "pg-mode": "bundled", "pg-superuser-pass": "s" * 24, "pg-app-pass": "a" * 24,
    "pg-dsn": "", "tls-mode": "operator", "include-gateway": False,
    "cert-san": "", "admin-user": "admin", "admin-pass": "correct-horse-battery",
    "yuzu-version": "0.14.1", "dashboard-port": "8080", "grpc-port": "50051",
    "mgmt-port": "50052", "gateway-upstream-port": "50055",
    "tls-cert": f"{TLS_DIR}/server.pem", "tls-key": f"{TLS_DIR}/server.key",
    "tls-ca-cert": f"{TLS_DIR}/ca.pem", "persist-certs": True,
    "data-dir": "/var/lib/yuzu", "include-clickhouse": False,
    "persistent-volumes": True, "include-prometheus": False,
    "include-grafana": False, "gw-pool-size": "4",
}


@unittest.skipIf(NODE is None, "node is not installed; the Compose Wizard "
                 "generator is JavaScript and needs node to run")
class ComposeWizardCerts(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        configs = [make_config(*m) for m in MATRIX]
        cls.composes = run_node("compose", {"configs": configs})["composes"]

    def test_matrix(self):
        self.assertEqual(len(self.composes), len(MATRIX))
        for (tls_mode, persistent, pg_bundled), text in zip(MATRIX, self.composes):
            label = (f"tlsMode={tls_mode} persistentVolumes={persistent} "
                     f"pgBundled={pg_bundled}")
            with self.subTest(label):
                errs = check_compose(text, tls_mode, persistent, pg_bundled)
                self.assertEqual(errs, [], "\n".join(errs))
        # The checker must see the server in every compose, or it proves nothing.
        for text in self.composes:
            self.assertIn("server", parse_compose(text)[0])

    def test_checker_rejects_the_pre_5420_operator_mount(self):
        # Self-test: swapping the fixed operator mounts back to the #5420 shape
        # must trip the checker.
        idx = MATRIX.index(("operator", True, True))
        text = self.composes[idx]
        broken = text.replace("      - server-certs:/etc/yuzu/certs\n",
                              "      - ./certs:/etc/yuzu/certs:ro\n")
        broken = broken.replace(f"      - ./certs:{TLS_DIR}:ro\n", "")
        broken = broken.replace(f"{TLS_DIR}/", f"{CERTS}/")
        self.assertNotEqual(broken, text)
        errs = check_compose(broken, "operator", True, True)
        for needle in ("read-only", "host path", f"./certs:{TLS_DIR}:ro", "--cert "):
            self.assertTrue(any(needle in e for e in errs), (needle, errs))

    def _generate(self, **overrides):
        fields = dict(FORM_FIELDS)
        fields.update(overrides)
        return run_node("generate", {"fields": fields})

    def test_generate_accepts_paths_under_tls_dir(self):
        out = self._generate()
        self.assertEqual(out["alerts"], [])
        self.assertIn(f"./certs:{TLS_DIR}:ro", out["compose"])
        self.assertEqual(check_compose(out["compose"], "operator", True, True), [])

    def test_generate_refuses_paths_outside_tls_dir(self):
        for field, path in [
            ("tls-cert", f"{CERTS}/server.pem"),
            ("tls-key", f"{CERTS}/server.key"),
            ("tls-ca-cert", f"{CERTS}/ca.pem"),
            ("tls-cert", f"{TLS_DIR}/../certs/server.pem"),
            ("tls-key", "/srv/server.key"),
            ("tls-ca-cert", "ca.pem"),
            ("tls-cert", f"{TLS_DIR}"),
        ]:
            with self.subTest(field=field, path=path):
                out = self._generate(**{field: path})
                self.assertEqual(out["compose"], "",
                                 f"generate() emitted a compose for {field}={path}")
                self.assertEqual(len(out["alerts"]), 1, out["alerts"])
                self.assertIn(TLS_DIR, out["alerts"][0])


if __name__ == "__main__":
    unittest.main(verbosity=2)
