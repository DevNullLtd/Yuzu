#!/usr/bin/env python3
"""Every tracked compose that persists Postgres must persist /etc/yuzu/certs (#5370).

The server keeps its internal CA, default certs and the secrets KEK in
/etc/yuzu/certs (auth::default_cert_dir(); the images pass no --ca-dir). Since
0.14.0 the KEK is registered in Postgres, so a compose that keeps Postgres on a
volume but leaves /etc/yuzu/certs in the container layer loses the key file on
the next container recreate, and the server then refuses to boot with
kek_unresolvable. 0.14.0 shipped exactly that in the README quickstart.

Rule checked here, for every tracked *compose*.yml: if the `server` service
exists AND some service mounts a volume on /var/lib/postgresql, the `server`
service must mount a NAMED volume, declared under the top-level `volumes:`, on
/etc/yuzu/certs, and not read-only (the server writes the KEK there on first
boot). The sanitizer rig keeps Postgres in its container layer, so the rule
does not apply to it.

Stdlib only: the compose files are read with a small indentation-based
reader that understands the subset they use (block mappings, block sequences,
short- and long-syntax volume entries). A mutation self-test proves the check
fails when the line is removed.
"""

import re
import subprocess
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CERTS = "/etc/yuzu/certs"
PG_TARGET = "/var/lib/postgresql"

# Composes known to carry both a server and a Postgres volume. A file dropping
# out of this set (renamed, or the reader stops seeing its server) must fail
# loudly instead of silently shrinking coverage.
EXPECTED_IN_SCOPE = {
    "deploy/docker/docker-compose.yml",
    "deploy/docker/docker-compose.demo.yml",
    "deploy/docker/docker-compose.full-uat.yml",
    "deploy/docker/docker-compose.viz-uat.yml",
    "deploy/docker/docker-compose.reference.yml",
    "deploy/docker/docker-compose.reference-gateway.yml",
    "docker-compose.uat.yml",
    "scripts/test/docker-compose.upgrade-test.yml",
}


def tracked_composes():
    try:
        out = subprocess.run(
            ["git", "-C", str(ROOT), "ls-files"],
            check=True, capture_output=True, text=True,
        ).stdout.splitlines()
    except (OSError, subprocess.CalledProcessError):
        out = [str(p.relative_to(ROOT)).replace("\\", "/")
               for p in ROOT.rglob("*compose*.y*ml")
               if ".git" not in p.parts and "worktrees" not in p.parts]
    return sorted(p for p in out
                  if re.search(r"(^|/)[^/]*compose[^/]*\.ya?ml$", p))


def _strip_comment(line):
    # Compose files here never put '#' inside a quoted volume spec.
    out, quote = [], None
    for ch in line:
        if quote:
            if ch == quote:
                quote = None
        elif ch in "'\"":
            quote = ch
        elif ch == "#":
            break
        out.append(ch)
    return "".join(out).rstrip()


def _unquote(s):
    s = s.strip()
    if len(s) >= 2 and s[0] == s[-1] and s[0] in "'\"":
        return s[1:-1]
    return s


def parse_compose(text):
    """Return ({service: [(source, target, read_only)]}, {top-level volume names})."""
    lines = []
    for raw in text.splitlines():
        line = _strip_comment(raw)
        if line.strip():
            lines.append((len(line) - len(line.lstrip(" ")), line.strip()))

    services, top_volumes = {}, set()
    section = None       # current top-level key
    child = None         # indent of that section's direct children
    svc = None           # current service name
    prop = None          # indent of the current service's properties
    in_vols = False      # inside the current service's `volumes:` list
    entry = None         # long-syntax volume entry being collected

    def flush():
        nonlocal entry
        if entry is not None and svc is not None:
            services[svc].append((entry.get("source", ""), entry.get("target", ""),
                                  entry.get("read_only", "false") == "true"))
        entry = None

    for indent, s in lines:
        if indent == 0:
            flush()
            section = s.split(":", 1)[0]
            child, svc, prop, in_vols = None, None, None, False
            continue
        if child is None:
            child = indent
        if section == "volumes":
            m = re.match(r"^([A-Za-z0-9_.-]+):", s)
            if m and indent == child:
                top_volumes.add(m.group(1))
            continue
        if section != "services":
            continue
        if indent == child:                      # a service name
            flush()
            m = re.match(r"^([A-Za-z0-9_.-]+):\s*$", s)
            svc = m.group(1) if m else None
            if svc:
                services.setdefault(svc, [])
            prop, in_vols = None, False
            continue
        if svc is None:
            continue
        if prop is None:
            prop = indent
        if indent == prop:                       # a service property
            flush()
            in_vols = s == "volumes:"
            continue
        if not in_vols:
            continue
        if s.startswith("- "):                   # a volume entry
            flush()
            item = s[2:].strip()
            kv = re.match(r"^([a-z_]+):\s*(.*)$", item)
            if kv and kv.group(1) in ("type", "source", "target", "read_only"):
                entry = {kv.group(1): _unquote(kv.group(2))}
                continue
            parts = _unquote(item).split(":")
            if len(parts) == 1:
                services[svc].append(("", parts[0], False))
            else:
                ro = len(parts) >= 3 and "ro" in parts[2].split(",")
                services[svc].append((parts[0], parts[1], ro))
        elif entry is not None:                  # long-syntax continuation
            kv = re.match(r"^([a-z_]+):\s*(.*)$", s)
            if kv:
                entry[kv.group(1)] = _unquote(kv.group(2))
    flush()
    return services, top_volumes


def check(text):
    """Return None if the rule holds or does not apply, else a reason string."""
    services, top_volumes = parse_compose(text)
    if "server" not in services:
        return None
    if not any(t.rstrip("/") == PG_TARGET
               for mounts in services.values() for _, t, _ in mounts):
        return None
    hits = [(src, ro) for src, t, ro in services["server"]
            if t.rstrip("/") == CERTS]
    if not hits:
        return f"server mounts nothing on {CERTS}"
    src, ro = hits[0]
    if ro:
        return f"server mounts {CERTS} read-only; the server writes the KEK there"
    if not src or src.startswith((".", "/", "$", "~")):
        return (f"server mounts {CERTS} from '{src or '(anonymous)'}', not a named "
                f"volume; it must outlive the container exactly as Postgres does")
    if src not in top_volumes:
        return f"volume '{src}' mounted on {CERTS} is not declared under top-level volumes:"
    return None


class ComposeCertsVolume(unittest.TestCase):
    def test_every_tracked_compose(self):
        composes = tracked_composes()
        self.assertTrue(composes, "found no tracked compose files")
        in_scope, failures = set(), []
        for rel in composes:
            text = (ROOT / rel).read_text(encoding="utf-8")
            services, _ = parse_compose(text)
            if "server" in services and any(
                    t.rstrip("/") == PG_TARGET
                    for m in services.values() for _, t, _ in m):
                in_scope.add(rel)
            reason = check(text)
            if reason:
                failures.append(f"{rel}: {reason}")
        self.assertEqual(failures, [], "\n".join(
            failures + ["(#5370: the KEK in /etc/yuzu/certs is registered in "
                        "Postgres; see docs/user-manual/server-admin.md "
                        "'What must persist')"]))
        missing = EXPECTED_IN_SCOPE - in_scope
        self.assertEqual(missing, set(),
                         f"expected these composes to be checked but they were "
                         f"not found in scope: {sorted(missing)}")

    def test_mutation_line_removed_fails(self):
        for rel in sorted(EXPECTED_IN_SCOPE):
            text = (ROOT / rel).read_text(encoding="utf-8")
            mutated = "\n".join(l for l in text.splitlines()
                                if not re.match(r"^\s*-\s*[\"']?[A-Za-z0-9_.-]+:/etc/yuzu/certs[\"']?\s*$", l))
            self.assertNotEqual(mutated, text, f"{rel}: no certs line to remove")
            self.assertIsNotNone(check(mutated),
                                 f"{rel}: check still passes with the certs line removed")

    def test_mutation_variants(self):
        base = """services:
  server:
    image: x
    volumes:
      - server-data:/var/lib/yuzu
{certs}
  postgres:
    image: y
    volumes:
      - postgres-data:/var/lib/postgresql
volumes:
  server-data:
{decl}
  postgres-data:
"""
        good = base.format(certs="      - server-certs:/etc/yuzu/certs",
                           decl="  server-certs:")
        self.assertIsNone(check(good))
        long_form = base.format(
            certs="      - type: volume\n        source: server-certs\n        target: /etc/yuzu/certs",
            decl="  server-certs:")
        self.assertIsNone(check(long_form))
        for certs, decl, why in [
            ("", "", "missing"),
            ("      - /etc/yuzu/certs", "", "anonymous"),
            ("      - ./certs:/etc/yuzu/certs", "", "bind mount"),
            ("      - server-certs:/etc/yuzu/certs:ro", "  server-certs:", "read-only"),
            ("      - server-certs:/etc/yuzu/certs", "", "undeclared"),
        ]:
            with self.subTest(why=why):
                self.assertIsNotNone(check(base.format(certs=certs, decl=decl)))
        no_pg = good.replace("/var/lib/postgresql", "/srv/elsewhere").replace(
            "      - server-certs:/etc/yuzu/certs\n", "")
        self.assertIsNone(check(no_pg), "rule must not apply without a Postgres volume")


if __name__ == "__main__":
    unittest.main(verbosity=2)
