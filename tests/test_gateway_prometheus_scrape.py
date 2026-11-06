#!/usr/bin/env python3
"""Every shipped Prometheus config scrapes the gateway (#5695, METRICS).

The gateway exports its metrics on `prometheus_port` (9568 in every shipped
sys.config); the gateway's capacity alerts and dashboards are only as good as
the scrape. Two rules:

1. Every Prometheus config under deploy/prometheus/ has a scrape target on the
   gateway's default metrics port (read from gateway/config/sys.config).
2. Every tracked compose file that runs BOTH a Prometheus service and a gateway
   service gives that Prometheus a config (a bind-mounted file, or a top-level
   `configs:` entry with inline `content:` or a `file:`) that scrapes each
   gateway service at the port that gateway actually listens on: the service's
   name, container_name or hostname, and the port from its
   YUZU_GW_PROMETHEUS_PORT, else from the sys.config it mounts, else 9568. A
   gateway the compose runs more than once (deploy.replicas other than 1) needs
   a dns_sd_configs entry naming it, because a static target resolves to one
   replica at a time.

So a new compose stack that adds a gateway next to a Prometheus without a
scrape target, or moves its metrics port, fails here.

Stdlib only (the docs-lint job has no PyYAML): the compose files and the
Prometheus configs are read with small indentation-based readers for the
subset they use. Mutation self-tests prove each rule fails when its line goes.
"""

import re
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_compose_certs_volume import (  # noqa: E402
    ROOT, _strip_comment, _unquote, parse_compose, tracked_composes)

PROM_TARGET = "/etc/prometheus/prometheus.yml"

# Stacks known to run a Prometheus next to a gateway. A file dropping out of
# this set (renamed, or the reader stops seeing one of the two services) must
# fail loudly instead of silently shrinking coverage.
EXPECTED_IN_SCOPE = {
    "deploy/docker/docker-compose.full-uat.yml",
    "docker-compose.uat.yml",
}


def default_port():
    text = (ROOT / "gateway/config/sys.config").read_text(encoding="utf-8")
    m = re.search(r"\{prometheus_port,\s*(\d+)\}", text)
    assert m, "gateway/config/sys.config sets no prometheus_port"
    return int(m.group(1))


# ── compose reading ─────────────────────────────────────────────────────────

def _lines(text):
    out = []
    for raw in text.splitlines():
        line = _strip_comment(raw)
        if line.strip():
            out.append((len(line) - len(line.lstrip(" ")), line.strip(), raw))
    return out


def service_blocks(text):
    """{service: [(indent, stripped line)]} of each service's own lines."""
    blocks, section, child, svc = {}, None, None, None
    for indent, s, _raw in _lines(text):
        if indent == 0:
            section, child, svc = s.split(":", 1)[0], None, None
            continue
        if section != "services":
            continue
        if child is None:
            child = indent
        if indent == child:
            m = re.match(r"^([A-Za-z0-9_.-]+):\s*$", s)
            svc = m.group(1) if m else None
            if svc:
                blocks[svc] = []
            continue
        if svc:
            blocks[svc].append((indent, s))
    return blocks


def top_configs(text):
    """{name: {"content": str} | {"file": str}} from the top-level `configs:`."""
    raw_lines = text.splitlines()
    configs, i, in_cfg, child = {}, 0, False, None
    while i < len(raw_lines):
        raw = raw_lines[i]
        line = _strip_comment(raw)
        if not line.strip():
            i += 1
            continue
        indent = len(line) - len(line.lstrip(" "))
        s = line.strip()
        if indent == 0:
            in_cfg, child = s == "configs:", None
            i += 1
            continue
        if not in_cfg:
            i += 1
            continue
        if child is None:
            child = indent
        if indent == child:
            name = s.rstrip(":")
            configs[name] = {}
            i += 1
            continue
        m = re.match(r"^(content|file):\s*(.*)$", s)
        if m and name in configs:
            if m.group(1) == "file":
                configs[name]["file"] = _unquote(m.group(2))
                i += 1
                continue
            # a block scalar: every following line indented deeper than the key
            body, j = [], i + 1
            while j < len(raw_lines):
                nxt = raw_lines[j]
                if nxt.strip() and len(nxt) - len(nxt.lstrip(" ")) <= indent:
                    break
                body.append(nxt)
                j += 1
            configs[name]["content"] = "\n".join(body)
            i = j
            continue
        i += 1
    return configs


def service_value(block, key):
    for _indent, s in block:
        m = re.match(rf"^{key}:\s*(.+)$", s)
        if m:
            return _unquote(m.group(1))
    return None


def service_configs(block):
    """[(source, target)] of a service's long-syntax `configs:` entries."""
    out, cur, in_cfg, prop = [], None, False, None
    for indent, s in block:
        if prop is None:
            prop = indent
        if indent == prop:
            in_cfg = s == "configs:"
            continue
        if not in_cfg:
            continue
        if s.startswith("- "):
            if cur:
                out.append((cur.get("source"), cur.get("target")))
            cur = {}
            s = s[2:].strip()
        kv = re.match(r"^(source|target):\s*(.*)$", s)
        if kv and cur is not None:
            cur[kv.group(1)] = _unquote(kv.group(2))
    if cur:
        out.append((cur.get("source"), cur.get("target")))
    return out


def env_value(block, name):
    for _indent, s in block:
        m = re.match(rf"^-?\s*['\"]?{name}\s*[=:]\s*['\"]?([^'\"\s]+)", s)
        if m:
            return m.group(1)
    return None


def replicas(block):
    v = service_value(block, "replicas")
    return v if v is not None else "1"


def is_gateway(block):
    image = service_value(block, "image") or ""
    dockerfile = service_value(block, "dockerfile") or ""
    return "yuzu-gateway" in image or "Dockerfile.gateway" in dockerfile


def is_prometheus(block):
    return "prom/prometheus" in (service_value(block, "image") or "")


def file_text(compose_dir, src):
    """The text of a file a mount or a config names (relative to the compose
    file), or None."""
    if src is None:
        return None
    path = (compose_dir / src).resolve()
    return path.read_text(encoding="utf-8") if path.is_file() else None


def mounted(compose_dir, mounts, configs, svc_configs, target_suffix):
    """Text of what the service sees at a path ending target_suffix."""
    for src, tgt, _ro in mounts:
        if tgt.endswith(target_suffix) and src:
            return file_text(compose_dir, src)
    for source, tgt in svc_configs:
        if tgt and tgt.endswith(target_suffix) and source in configs:
            c = configs[source]
            if "content" in c:
                return c["content"]
            if "file" in c:
                return file_text(compose_dir, c["file"])
    return None


def gateway_port(compose_dir, block, mounts, configs):
    env = env_value(block, "YUZU_GW_PROMETHEUS_PORT")
    if env and env.isdigit():
        return int(env)
    sys_config = mounted(compose_dir, mounts, configs, service_configs(block), "sys.config")
    if sys_config:
        m = re.search(r"\{prometheus_port,\s*(\d+)\}", sys_config)
        if m:
            return int(m.group(1))
    return default_port()


# ── Prometheus config reading ───────────────────────────────────────────────

def static_targets(prom_text):
    """Every host:port in a static_configs `targets:` list (flow or block)."""
    found, lines = [], prom_text.splitlines()
    for i, raw in enumerate(lines):
        line = _strip_comment(raw)
        m = re.search(r"targets:\s*\[(.*)\]", line)
        if m:
            found += [_unquote(t) for t in m.group(1).split(",") if t.strip()]
            continue
        if re.search(r"targets:\s*$", line):
            indent = len(line) - len(line.lstrip(" "))
            for nxt in lines[i + 1:]:
                n = _strip_comment(nxt)
                if not n.strip():
                    continue
                if len(n) - len(n.lstrip(" ")) <= indent and not n.strip().startswith("- "):
                    break
                if not n.strip().startswith("- "):
                    break
                found.append(_unquote(n.strip()[2:]))
    return found


def dns_sd_names(prom_text):
    """[(name, port)] of dns_sd_configs entries (type A with a port)."""
    out = []
    for m in re.finditer(r"dns_sd_configs:(.*?)(?=\n\s*-?\s*[a-z_]+_configs:|\n\s*- job_name:|\Z)",
                         prom_text, re.S):
        body = m.group(1)
        port = re.search(r"port:\s*(\d+)", body)
        for nm in re.findall(r"names:\s*\[(.*?)\]", body):
            for n in nm.split(","):
                if n.strip():
                    out.append((_unquote(n), int(port.group(1)) if port else None))
    return out


# ── the rules ───────────────────────────────────────────────────────────────

def check_compose(rel, text):
    """(in_scope, reasons): in scope when the compose runs a Prometheus and a
    gateway; reasons is empty when every gateway is scraped."""
    compose_dir = (ROOT / rel).parent
    blocks = service_blocks(text)
    mounts, _ = parse_compose(text)
    configs = top_configs(text)
    proms = [n for n, b in blocks.items() if is_prometheus(b)]
    gateways = [n for n, b in blocks.items() if is_gateway(b)]
    if not proms or not gateways:
        return False, []
    reasons = []
    for p in proms:
        prom_text = mounted(compose_dir, mounts.get(p, []), configs,
                            service_configs(blocks[p]), PROM_TARGET)
        if prom_text is None:
            reasons.append(f"{p}: no Prometheus config found at {PROM_TARGET}")
            continue
        targets = static_targets(prom_text)
        dns = dns_sd_names(prom_text)
        for g in gateways:
            b = blocks[g]
            port = gateway_port(compose_dir, b, mounts.get(g, []), configs)
            names = {g} | {v for v in (service_value(b, "container_name"),
                                       service_value(b, "hostname")) if v}
            if replicas(b) != "1":
                if not any(n in names and pt in (port, None) for n, pt in dns):
                    reasons.append(f"{p}: gateway '{g}' runs replicas={replicas(b)} "
                                   f"but no dns_sd_configs names it (a static target "
                                   f"scrapes one replica at a time)")
                continue
            if not any(t in {f"{n}:{port}" for n in names} for t in targets):
                reasons.append(f"{p}: no scrape target for gateway '{g}' on port {port} "
                               f"(expected one of {sorted(f'{n}:{port}' for n in names)}, "
                               f"found {targets})")
    return True, reasons


class GatewayPrometheusScrape(unittest.TestCase):
    def test_every_deploy_prometheus_config_scrapes_the_gateway_port(self):
        files = sorted((ROOT / "deploy/prometheus").glob("*.yml"))
        self.assertTrue(files, "no Prometheus configs under deploy/prometheus")
        port = default_port()
        missing = [str(f.relative_to(ROOT)) for f in files
                   if not any(t.endswith(f":{port}")
                              for t in static_targets(f.read_text(encoding="utf-8")))]
        self.assertEqual(missing, [], f"these configs scrape nothing on the gateway's "
                                      f"metrics port {port}")

    def test_every_compose_stack_scrapes_its_gateways(self):
        in_scope, failures = set(), []
        for rel in tracked_composes():
            scoped, reasons = check_compose(rel, (ROOT / rel).read_text(encoding="utf-8"))
            if scoped:
                in_scope.add(rel)
            failures += [f"{rel}: {r}" for r in reasons]
        self.assertEqual(failures, [], "\n".join(failures))
        self.assertEqual(EXPECTED_IN_SCOPE - in_scope, set(),
                         "expected these stacks to be checked but they were not in scope")

    # ── mutation self-tests ────────────────────────────────────────────────

    def test_mutation_inline_config_without_gateway_job_fails(self):
        rel = "docker-compose.uat.yml"
        text = (ROOT / rel).read_text(encoding="utf-8")
        mutated = text.replace("'gateway:9568'", "'nothing:9568'")
        self.assertNotEqual(mutated, text)
        self.assertTrue(check_compose(rel, mutated)[1])

    def test_mutation_moved_metrics_port_fails(self):
        rel = "docker-compose.uat.yml"
        text = (ROOT / rel).read_text(encoding="utf-8")
        mutated = text.replace("{prometheus_port, 9568}", "{prometheus_port, 9999}")
        self.assertNotEqual(mutated, text)
        self.assertTrue(check_compose(rel, mutated)[1])

    def test_mutation_mounted_config_without_target_fails(self):
        base = """services:
  gateway:
    image: ghcr.io/devnullltd/yuzu-gateway:1
    container_name: gw
{env}
  prometheus:
    image: prom/prometheus:v3
    configs:
      - source: prom
        target: /etc/prometheus/prometheus.yml
{deploy}
configs:
  prom:
    content: |
      scrape_configs:
        - job_name: 'yuzu-gateway'
          static_configs:
            - targets: [{targets}]
"""
        ok = base.format(env="", deploy="", targets="'gateway:9568'")
        self.assertEqual(check_compose("x/compose.yml", ok), (True, []))
        self.assertEqual(check_compose("x/compose.yml",
                                       base.format(env="", deploy="", targets="'gw:9568'")),
                         (True, []))
        for env, targets, why in [
            ("", "'server:8080'", "no gateway target"),
            ("", "'gateway:9569'", "wrong port"),
            ("    environment:\n      - YUZU_GW_PROMETHEUS_PORT=9600", "'gateway:9568'",
             "env moved the port"),
        ]:
            with self.subTest(why=why):
                self.assertTrue(check_compose("x/compose.yml",
                                              base.format(env=env, deploy="",
                                                          targets=targets))[1])
        # a scaled gateway needs dns_sd_configs, a static target is not enough
        scaled = ok.replace("    container_name: gw\n",
                            "    deploy:\n      replicas: 3\n")
        self.assertTrue(check_compose("x/compose.yml", scaled)[1])
        dns = scaled.replace(
            "          static_configs:\n            - targets: ['gateway:9568']\n",
            "          dns_sd_configs:\n            - names: ['gateway']\n"
            "              type: A\n              port: 9568\n")
        self.assertEqual(check_compose("x/compose.yml", dns), (True, []))

    def test_mutation_deploy_config_without_gateway_job_fails(self):
        text = (ROOT / "deploy/prometheus/prometheus-docker.yml").read_text(encoding="utf-8")
        mutated = text.replace("gateway:9568", "gateway:9999")
        self.assertNotEqual(mutated, text)
        self.assertFalse(any(t.endswith(f":{default_port()}") for t in static_targets(mutated)))


if __name__ == "__main__":
    unittest.main(verbosity=2)
