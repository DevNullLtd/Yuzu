#!/usr/bin/env python3
"""The README's Docker Compose quickstart must point at a compose that runs released images (#5419).

0.14.0's README told users to download deploy/docker/docker-compose.yml and run
`YUZU_VERSION=0.14.0 docker compose up -d`. That compose builds from a checkout
(`build: context: ../..`), so a downloaded copy has no build context, the
variable is ignored, and the stack never starts.

This test reads the first ```bash block after the README's "Docker Compose
quickstart" bullet and checks that:

  * it downloads exactly one tracked compose from this repository's main branch;
  * no service in that compose has a `build:` key, and every Yuzu image is a
    ghcr.io/devnullltd image tagged `${YUZU_VERSION:-...}`;
  * the `server` service runs the released yuzu-server image with no
    `command:` override, publishes 8443, and mounts a named, declared,
    writable volume on /etc/yuzu/certs (the CA and the secrets KEK, #5370);
  * the README pins YUZU_VERSION to a release number in `.env`;
  * the admin seed the README writes lands at the image's `--config` path,
    on the compose's `/var/lib/yuzu` volume, with the server's PBKDF2
    iteration count;
  * the block brings the stack up and checks /readyz.

It does not run Docker. The quickstart was run verbatim against the released
0.14.0 images when this test was added; see the #5419 PR.

Stdlib only. The volume reader is shared with test_compose_certs_volume.py.
"""

import re
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_compose_certs_volume import _strip_comment, parse_compose  # noqa: E402

CERTS = "/etc/yuzu/certs"
RAW_PREFIX = "https://raw.githubusercontent.com/DevNullLtd/Yuzu/main/"
DEV_STACK = "deploy/docker/docker-compose.yml"
IMAGE_RE = re.compile(r"ghcr\.io/devnullltd/yuzu-[a-z-]+:\$\{YUZU_VERSION(:-[^}]+)?\}$")


def quickstart_block(readme):
    """Return the text of the first ```bash block after the quickstart bullet."""
    i = readme.find("**Docker Compose** quickstart")
    if i < 0:
        raise AssertionError("README has no '**Docker Compose** quickstart' bullet")
    j = readme.find("```bash\n", i)
    if j < 0:
        raise AssertionError("no ```bash block after the quickstart bullet")
    j += len("```bash\n")
    k = readme.find("```", j)
    return readme[j:k]


def service_props(text):
    """Return {service: {property: value_text}} for the top-level services: map."""
    out, section, child, svc, prop_indent, prop = {}, None, None, None, None, None
    for raw in text.splitlines():
        line = _strip_comment(raw)
        if not line.strip():
            continue
        indent, s = len(line) - len(line.lstrip(" ")), line.strip()
        if indent == 0:
            section, child, svc, prop_indent, prop = s.split(":", 1)[0], None, None, None, None
            continue
        if section != "services":
            continue
        if child is None:
            child = indent
        if indent == child:
            m = re.match(r"^([A-Za-z0-9_.-]+):\s*$", s)
            svc = m.group(1) if m else None
            if svc:
                out[svc] = {}
            prop_indent, prop = None, None
            continue
        if svc is None:
            continue
        if prop_indent is None:
            prop_indent = indent
        if indent == prop_indent:
            m = re.match(r"^([A-Za-z0-9_.-]+):\s*(.*)$", s)
            prop = m.group(1) if m else None
            if prop:
                out[svc][prop] = m.group(2)
        elif prop:
            out[svc][prop] += "\n" + s
    return out


def image_cmd_config(dockerfile_text):
    """Return the --config value of the Dockerfile's final CMD."""
    cmds = re.findall(r"^CMD\s+(\[.*\])\s*$", dockerfile_text, re.M)
    if not cmds:
        return None
    args = re.findall(r'"([^"]*)"', cmds[-1])
    return args[args.index("--config") + 1] if "--config" in args else None


def check(block, compose_text, compose_rel, image_config, iterations):
    """Return a list of reasons the quickstart is broken (empty when it holds)."""
    bad = []
    urls = re.findall(r"https://raw\.githubusercontent\.com/\S+", block)
    if len(urls) != 1 or not urls[0].startswith(RAW_PREFIX):
        bad.append(f"expected one download from {RAW_PREFIX}, found {urls}")
    elif urls[0][len(RAW_PREFIX):] != compose_rel:
        bad.append(f"downloads {urls[0]}, expected {compose_rel}")
    if compose_rel == DEV_STACK:
        bad.append(f"{DEV_STACK} builds from a checkout; it cannot be a download-only quickstart")

    props = service_props(compose_text)
    for svc, p in props.items():
        if "build" in p:
            bad.append(f"service '{svc}' has build:, which a downloaded copy cannot run")
        img = p.get("image", "").strip().strip("\"'")
        if "devnullltd/yuzu-" in img and not IMAGE_RE.match(img):
            bad.append(f"service '{svc}' image '{img}' is not tagged ${{YUZU_VERSION:-...}}")

    server = props.get("server")
    if server is None:
        bad.append("compose has no 'server' service")
        return bad
    img = server.get("image", "").strip().strip("\"'")
    if not img.startswith("ghcr.io/devnullltd/yuzu-server:${YUZU_VERSION"):
        bad.append(f"server image '{img}' is not the released yuzu-server at ${{YUZU_VERSION}}")
    if "command" in server or "entrypoint" in server:
        bad.append("server overrides command:/entrypoint:, so the image's --config path may not apply")
    if not re.search(r"""^-\s*["']?8443:8443["']?$""", server.get("ports", ""), re.M):
        bad.append("server does not publish 8443 (the HTTPS dashboard)")

    mounts, top_volumes = parse_compose(compose_text)
    certs = [(src, ro) for src, t, ro in mounts.get("server", []) if t.rstrip("/") == CERTS]
    if not certs:
        bad.append(f"server mounts nothing on {CERTS} (#5370)")
    else:
        src, ro = certs[0]
        if ro or not src or src.startswith((".", "/", "$", "~")) or src not in top_volumes:
            bad.append(f"server's {CERTS} mount '{src}' is not a named, declared, writable volume")

    m = re.search(r"^YUZU_VERSION=(\S+)$", block, re.M)
    if not m or not re.fullmatch(r"\d+\.\d+\.\d+", m.group(1)):
        bad.append("README does not pin YUZU_VERSION=X.Y.Z in .env")

    seed = re.search(r"cat > (/\S+yuzu-server\.cfg)", block)
    if not seed:
        bad.append("README does not seed yuzu-server.cfg for a headless first boot")
    else:
        if image_config is None or seed.group(1) != image_config:
            bad.append(f"README seeds {seed.group(1)}, image CMD reads --config {image_config}")
        data_dir = str(Path(seed.group(1)).parent)
        if not any(t.rstrip("/") == data_dir and src and src in top_volumes
                   for src, t, _ in mounts.get("server", [])):
            bad.append(f"compose keeps {data_dir} (where the seed goes) on no named volume")
    pbkdf2 = re.search(r'pbkdf2_hmac\("sha256",.*?,\s*(\d+)\)', block)
    if not pbkdf2 or int(pbkdf2.group(1)) != iterations:
        bad.append(f"README's PBKDF2 iteration count does not match the server's {iterations}")

    if "docker compose up -d" not in block:
        bad.append("README block never runs docker compose up -d")
    if "/readyz" not in block:
        bad.append("README block never checks /readyz")
    return bad


def tracked(rel):
    try:
        out = subprocess.run(["git", "-C", str(ROOT), "ls-files", "--error-unmatch", rel],
                             capture_output=True, text=True)
        return out.returncode == 0
    except OSError:
        return (ROOT / rel).is_file()


def live_inputs():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    block = quickstart_block(readme)
    urls = re.findall(re.escape(RAW_PREFIX) + r"(\S+)", block)
    rel = urls[0] if urls else ""
    compose = (ROOT / rel).read_text(encoding="utf-8") if rel and (ROOT / rel).is_file() else ""
    image_config = image_cmd_config(
        (ROOT / "deploy/docker/Dockerfile.server").read_text(encoding="utf-8"))
    auth_hpp = (ROOT / "server/core/include/yuzu/server/auth.hpp").read_text(encoding="utf-8")
    m = re.search(r"kPbkdf2Iterations\s*=\s*([\d']+)", auth_hpp)
    iterations = int(m.group(1).replace("'", "")) if m else -1
    return block, compose, rel, image_config, iterations


class ReadmeQuickstart(unittest.TestCase):
    def test_readme_quickstart_runs_released_images(self):
        block, compose, rel, image_config, iterations = live_inputs()
        self.assertTrue(rel and tracked(rel), f"quickstart compose '{rel}' is not a tracked file")
        self.assertNotEqual(iterations, -1, "kPbkdf2Iterations not found in auth.hpp")
        bad = check(block, compose, rel, image_config, iterations)
        self.assertEqual(bad, [], "\n".join(bad + ["(#5419: README quickstart)"]))

    def test_both_images_read_the_same_config_path(self):
        a = image_cmd_config((ROOT / "deploy/docker/Dockerfile.server").read_text(encoding="utf-8"))
        b = image_cmd_config(
            (ROOT / "deploy/docker/Dockerfile.server.chisel").read_text(encoding="utf-8"))
        self.assertIsNotNone(a)
        self.assertEqual(a, b, "yuzu-server and yuzu-server-chisel read different --config paths")

    def test_mutations_fail(self):
        block, compose, rel, image_config, iterations = live_inputs()
        self.assertEqual(check(block, compose, rel, image_config, iterations), [])
        dev = (ROOT / DEV_STACK).read_text(encoding="utf-8")
        cases = {
            "dev stack": (block.replace(rel, DEV_STACK), dev, DEV_STACK),
            "build key": (block, compose.replace(
                "  server:\n", "  server:\n    build:\n      context: ../..\n", 1), rel),
            "fixed tag": (block, re.sub(r"yuzu-server:\$\{YUZU_VERSION:-[^}]+\}",
                                        "yuzu-server:0.14.0", compose), rel),
            "no certs": (block, "\n".join(
                l for l in compose.splitlines()
                if not re.match(r"^\s*-\s*\S+:/etc/yuzu/certs\s*$", l)), rel),
            "certs ro": (block, re.sub(r"(-\s*\S+:/etc/yuzu/certs)\s*$", r"\1:ro",
                                       compose, flags=re.M), rel),
            "no 8443": (block, re.sub(r'^\s*-\s*"8443:8443".*\n', "", compose, flags=re.M), rel),
            "command": (block, compose.replace(
                "  server:\n", "  server:\n    command: [\"--no-tls\"]\n", 1), rel),
            "no seed": (re.sub(r"cat > /\S+yuzu-server\.cfg", "true", block), compose, rel),
            "seed path": (block.replace("/var/lib/yuzu/yuzu-server.cfg",
                                        "/etc/yuzu/yuzu-server.cfg"), compose, rel),
            "iterations": (block.replace("s, 100000)", "s, 1000)"), compose, rel),
            "no version": (re.sub(r"^YUZU_VERSION=.*\n", "", block, flags=re.M), compose, rel),
            "no readyz": (block.replace("/readyz", "/"), compose, rel),
        }
        for name, (b, c, r) in cases.items():
            with self.subTest(mutation=name):
                self.assertNotEqual((b, c), (block, compose), f"{name}: mutation changed nothing")
                self.assertNotEqual(check(b, c, r, image_config, iterations), [],
                                    f"{name}: check still passes")


if __name__ == "__main__":
    unittest.main(verbosity=2)
