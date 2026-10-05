#!/usr/bin/env python3
"""The README's Docker Compose quickstart must point at a compose that runs released images (#5419).

0.14.0's README told users to download deploy/docker/docker-compose.yml and run
`YUZU_VERSION=0.14.0 docker compose up -d`. That compose builds from a checkout
(`build: context: ../..`), so a downloaded copy has no build context, the
variable is ignored, and the stack never starts.

This test reads every ```bash block between the README's "Docker Compose
quickstart" bullet and the next `## ` heading, and checks that:

  * they download exactly one tracked compose from this repository at a
    release tag (vX.Y.Z), and the tag, the `.env` YUZU_VERSION and the
    compose's `${YUZU_VERSION:-X.Y.Z}` defaults all agree;
  * no service in that compose has a `build:` key, and every Yuzu image is a
    ghcr.io/devnullltd image tagged `${YUZU_VERSION:-...}`;
  * the `server` service runs the released yuzu-server image with no
    `command:` override, publishes container port 8443, and mounts a named,
    declared, writable volume on /etc/yuzu/certs (the CA and the secrets KEK,
    #5370);
  * the blocks are paste-safe: the first one is a single `mkdir yuzu && cd
    yuzu && ...` chain, so a re-paste from the parent directory runs nothing
    in the wrong place; no block holds a comment line (macOS zsh has
    interactive comments off); every `docker compose` call passes
    `-f docker-compose.yml`, so Compose cannot walk up to another project;
  * nothing is clobbered: `.env` is written under `umask 077; set -C`, the
    host `yuzu-server.cfg` with O_EXCL, and the in-container seed under
    `umask 077 && set -C`;
  * the admin seed is a well-formed `admin:admin:<salt>:<hash>` line, written
    to the image's `--config` path on the compose's `/var/lib/yuzu` volume,
    with the server's PBKDF2 iteration count and a 12-character minimum;
  * the README says to set YUZU_CERT_SAN before the first start;
  * the stack is brought up with `--wait` and checked with
    `curl -f --cacert ... https://localhost:8443/readyz`.

It does not run Docker. The quickstart was run verbatim against the released
0.14.0 images when this test was added; see issue #5419.

Stdlib only. The volume reader is shared with test_compose_certs_volume.py.
Container paths are handled with posixpath: on the Windows docs leg
pathlib.Path would turn /var/lib/yuzu into \\var\\lib\\yuzu.
"""

import posixpath
import re
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(Path(__file__).resolve().parent))
from test_compose_certs_volume import _strip_comment, parse_compose  # noqa: E402

CERTS = "/etc/yuzu/certs"
RAW_RE = re.compile(r"https://raw\.githubusercontent\.com/DevNullLtd/Yuzu/v(\d+\.\d+\.\d+)/(\S+)")
DEV_STACK = "deploy/docker/docker-compose.yml"
IMAGE_RE = re.compile(r"ghcr\.io/devnullltd/yuzu-[a-z-]+:\$\{YUZU_VERSION(:-[^}]+)?\}$")
COMPOSE_F = "docker compose -f docker-compose.yml "


def quickstart_region(readme):
    """Return the README text from the quickstart bullet to the next `## ` heading."""
    i = readme.find("**Docker Compose** quickstart")
    if i < 0:
        raise AssertionError("README has no '**Docker Compose** quickstart' bullet")
    k = readme.find("\n## ", i)
    return readme[i:] if k < 0 else readme[i:k]


def bash_blocks(region):
    """Return the ```bash blocks of the quickstart region, in order."""
    blocks = re.findall(r"^```bash\n(.*?)^```", region, re.M | re.S)
    if not blocks:
        raise AssertionError("no ```bash block after the quickstart bullet")
    return blocks


def unquote_keys(text):
    """Turn `"server":` / `'8443'` style quoted mapping keys into bare keys."""
    return re.sub(r"""^(\s*)(["'])([A-Za-z0-9_.-]+)\2:""", r"\1\3:", text, flags=re.M)


def service_props(text):
    """Return {service: {property: value_text}} for the top-level services: map."""
    out, section, child, svc, prop_indent, prop = {}, None, None, None, None, None
    for raw in unquote_keys(text).splitlines():
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


def publishes_8443(ports_text):
    """True if a `ports:` value publishes container port 8443 (short or long syntax)."""
    for item in re.split(r"^-\s*", ports_text, flags=re.M):
        item = item.strip().strip("\"'")
        if re.fullmatch(r"(?:[\d.]+:|\[[0-9a-fA-F:]+\]:)?(?:\d+:)?8443(?:/tcp)?", item):
            return True
        if re.search(r"^target:\s*[\"']?8443[\"']?\s*$", item, re.M):
            return True
    return False


def image_cmd_config(dockerfile_text):
    """Return the --config value of the Dockerfile's final CMD."""
    cmds = re.findall(r"^CMD\s+(\[.*\])\s*$", dockerfile_text, re.M)
    if not cmds:
        return None
    args = re.findall(r'"([^"]*)"', cmds[-1])
    return args[args.index("--config") + 1] if "--config" in args else None


def check(region, compose_text, compose_rel, image_config, iterations):
    """Return a list of reasons the quickstart is broken (empty when it holds)."""
    bad = []
    blocks = bash_blocks(region)
    code = "\n".join(blocks)

    # ── Download: one tracked compose, at a release tag that matches everything else.
    urls = RAW_RE.findall(code)
    all_raw = re.findall(r"https://raw\.githubusercontent\.com/\S+", code)
    if len(urls) != 1 or len(all_raw) != 1:
        bad.append(f"expected one download from DevNullLtd/Yuzu/vX.Y.Z/, found {all_raw}")
        tag = None
    else:
        tag, rel = urls[0]
        if rel != compose_rel:
            bad.append(f"downloads {rel}, expected {compose_rel}")
    if compose_rel == DEV_STACK:
        bad.append(f"{DEV_STACK} builds from a checkout; it cannot be a download-only quickstart")
    m = re.search(r"YUZU_VERSION=(\d+\.\d+\.\d+)\\n", code) or \
        re.search(r"^YUZU_VERSION=(\d+\.\d+\.\d+)$", code, re.M)
    env_version = m.group(1) if m else None
    if env_version is None:
        bad.append("README does not pin YUZU_VERSION=X.Y.Z in .env")
    elif tag is not None and tag != env_version:
        bad.append(f"compose URL tag v{tag} differs from .env YUZU_VERSION={env_version}")
    defaults = set(re.findall(r"yuzu-[a-z-]+:\$\{YUZU_VERSION:-([^}]+)\}", compose_text))
    if env_version and defaults != {env_version}:
        bad.append(f"compose ${{YUZU_VERSION:-...}} defaults {sorted(defaults)} differ from "
                   f".env YUZU_VERSION={env_version}")

    # ── The compose itself.
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
    if not publishes_8443(server.get("ports", "")):
        bad.append("server does not publish 8443 (the HTTPS dashboard)")
    if "environment" not in server:
        bad.append("server has no environment: map for the README's YUZU_CERT_SAN line")

    mounts, top_volumes = parse_compose(unquote_keys(compose_text))
    certs = [(src, ro) for src, t, ro in mounts.get("server", []) if t.rstrip("/") == CERTS]
    if not certs:
        bad.append(f"server mounts nothing on {CERTS} (#5370)")
    else:
        src, ro = certs[0]
        if ro or not src or src.startswith((".", "/", "$", "~")) or src not in top_volumes:
            bad.append(f"server's {CERTS} mount '{src}' is not a named, declared, writable volume")

    # ── Operator guidance that must not regress (RD-N1, qe-N1).
    if "Never clear `/etc/yuzu/certs`" not in region:
        bad.append("the README no longer says never to clear /etc/yuzu/certs (#5370)")
    if "upgrading.md#docker" not in region or "P=yuzu" not in region:
        bad.append("backup does not point at the prefixed recipe in upgrading.md with P=yuzu "
                   "(the 0.14.0 compose header recipe backs up nothing)")

    # ── Paste safety.
    first = [l for l in blocks[0].splitlines() if l.strip()]
    # UP-N2: step 1 first refuses when a `yuzu` project's volumes already exist,
    # so a second same-named install never attaches to (or `down -v`s) the first.
    if not first or first[0] != "! docker volume inspect yuzu_server-data >/dev/null 2>&1 &&":
        bad.append("step 1 does not first refuse an existing yuzu_server-data volume")
    if len(first) < 2 or not first[1].startswith("mkdir yuzu && cd yuzu &&"):
        bad.append("step 1 does not open with one `mkdir yuzu && cd yuzu && ...` chain")
    elif any(not l.rstrip().endswith("&&") for l in first[:-1]):
        bad.append("step 1 is not one && chain, so a failed mkdir/cd would not stop later lines")
    if re.search(r"(^|[;&|]\s*)cd\s", "\n".join(blocks[1:]), re.M):
        bad.append("a later block changes directory")
    for n, b in enumerate(blocks, 1):
        if re.search(r"^\s*#", b, re.M):
            bad.append(f"block {n} has a comment line (a parse error in macOS zsh)")
    calls = re.findall(r"docker compose\b[^\n]*", code)
    for c in calls:
        if not c.startswith(COMPOSE_F):
            bad.append(f"'{c[:60]}' does not pass -f docker-compose.yml")
    if not re.search(r"-o docker-compose\.yml(\s|$)", code):
        bad.append("the compose is not saved as docker-compose.yml")

    # ── No clobbering, private modes.
    if not re.search(r"\(umask 077; set -C; [^\n]*> \.env\)", code):
        bad.append(".env is not written under (umask 077; set -C; ... > .env)")
    if not re.search(r'os\.open\("yuzu-server\.cfg",[^)]*O_EXCL[^)]*0o600\)', code):
        bad.append("the host yuzu-server.cfg is not created with O_EXCL and mode 0o600")
    if len(re.findall(r"\$\(openssl rand -hex \d+\)", code)) < 2 or \
            "YUZU_POSTGRES_PASSWORD=" not in code or "YUZU_DB_PASSWORD=" not in code:
        bad.append("README does not generate two separate Postgres passwords")

    # ── The admin seed.
    seed = re.search(r"run --rm --no-deps -T --entrypoint sh server -c "
                     r"'umask 077 && set -C && cat > (/\S+yuzu-server\.cfg)' < yuzu-server\.cfg",
                     code)
    if not seed:
        bad.append("README does not seed yuzu-server.cfg with `umask 077 && set -C && cat >`")
    else:
        if image_config is None or seed.group(1) != image_config:
            bad.append(f"README seeds {seed.group(1)}, image CMD reads --config {image_config}")
        data_dir = posixpath.dirname(seed.group(1))
        if not any(t.rstrip("/") == data_dir and src and src in top_volumes
                   for src, t, _ in mounts.get("server", [])):
            bad.append(f"compose keeps {data_dir} (where the seed goes) on no named volume")
    if '"admin:admin:%s:%s\\n" % (s.hex(), hashlib.pbkdf2_hmac(' not in code or \
            "s = os.urandom(16)" not in code:
        bad.append("the seed is not an admin:admin:<salt hex>:<hash hex> line with a 16-byte salt")
    pbkdf2 = re.search(r'pbkdf2_hmac\("sha256", p\.encode\(\), s, (\d+)\)\.hex\(\)', code)
    if not pbkdf2 or int(pbkdf2.group(1)) != iterations:
        bad.append(f"README's PBKDF2-SHA256 call does not use the server's {iterations} iterations")
    if not re.search(r"len\(p\) < 12\b", code):
        bad.append("README does not refuse admin passwords under 12 characters")

    # ── Certificates are issued once, on the first start.
    up = region.find(COMPOSE_F + "up")
    san = region.find("YUZU_CERT_SAN")
    if san < 0 or up < 0 or san > up:
        bad.append("README does not say to set YUZU_CERT_SAN before the first `up`")

    # ── Bring-up and health check.
    if not re.search(r"^" + re.escape(COMPOSE_F) + r"up -d --wait\b", code, re.M):
        bad.append("README block never runs docker compose -f docker-compose.yml up -d --wait")
    if not re.search(r"^curl -f\S* [^\n]*--cacert \S+ https://localhost:8443/readyz\s*$", code, re.M):
        bad.append("README block never checks https://localhost:8443/readyz with curl -f --cacert")
    return bad


def tracked(rel):
    """True if rel is a tracked file; outside a git work tree, true if it exists."""
    try:
        inside = subprocess.run(["git", "-C", str(ROOT), "rev-parse", "--is-inside-work-tree"],
                                capture_output=True, text=True)
        if inside.returncode != 0 or inside.stdout.strip() != "true":
            return (ROOT / rel).is_file()
        out = subprocess.run(["git", "-C", str(ROOT), "ls-files", "--error-unmatch", rel],
                             capture_output=True, text=True)
        return out.returncode == 0
    except OSError:
        return (ROOT / rel).is_file()


def at_tag(tag, rel):
    """Return rel's text at tag vTAG, or None when the tag is not in this clone."""
    try:
        out = subprocess.run(["git", "-C", str(ROOT), "show", f"v{tag}:{rel}"],
                             capture_output=True, text=True, encoding="utf-8")
    except OSError:
        return None
    return out.stdout if out.returncode == 0 else None


def live_inputs():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    region = quickstart_region(readme)
    urls = RAW_RE.findall("\n".join(bash_blocks(region)))
    tag, rel = urls[0] if urls else ("", "")
    compose = (ROOT / rel).read_text(encoding="utf-8") if rel and (ROOT / rel).is_file() else ""
    image_config = image_cmd_config(
        (ROOT / "deploy/docker/Dockerfile.server").read_text(encoding="utf-8"))
    auth_hpp = (ROOT / "server/core/include/yuzu/server/auth.hpp").read_text(encoding="utf-8")
    m = re.search(r"kPbkdf2Iterations\s*=\s*([\d']+)", auth_hpp)
    iterations = int(m.group(1).replace("'", "")) if m else -1
    return region, compose, rel, tag, image_config, iterations


class ReadmeQuickstart(unittest.TestCase):
    def test_readme_quickstart_runs_released_images(self):
        region, compose, rel, _, image_config, iterations = live_inputs()
        self.assertTrue(rel and tracked(rel), f"quickstart compose '{rel}' is not a tracked file")
        self.assertNotEqual(iterations, -1, "kPbkdf2Iterations not found in auth.hpp")
        bad = check(region, compose, rel, image_config, iterations)
        self.assertEqual(bad, [], "\n".join(bad + ["(#5419: README quickstart)"]))

    def test_compose_at_the_release_tag(self):
        # Users download the compose at the tag, not the working-tree copy. Shallow
        # CI clones carry no tags, so this check only runs where the tag exists.
        region, _, rel, tag, image_config, iterations = live_inputs()
        tagged = at_tag(tag, rel) if tag else None
        if tagged is None:
            self.skipTest(f"tag v{tag} is not in this clone")
        bad = check(region, tagged, rel, image_config, iterations)
        self.assertEqual(bad, [], "\n".join(bad + [f"(#5419: compose at v{tag})"]))

    def test_both_images_read_the_same_config_path(self):
        a = image_cmd_config((ROOT / "deploy/docker/Dockerfile.server").read_text(encoding="utf-8"))
        b = image_cmd_config(
            (ROOT / "deploy/docker/Dockerfile.server.chisel").read_text(encoding="utf-8"))
        self.assertIsNotNone(a)
        self.assertEqual(a, b, "yuzu-server and yuzu-server-chisel read different --config paths")

    def test_legitimate_hardening_still_passes(self):
        region, compose, rel, _, image_config, iterations = live_inputs()
        variants = {
            "loopback port": re.sub(r'"8443:8443"', '"127.0.0.1:8443:8443"', compose),
            "long-syntax port": re.sub(
                r'^(\s*)-\s*"8443:8443".*$', r"\1- target: 8443\n\1  published: 8443",
                compose, flags=re.M),
            "quoted keys": compose.replace("  server:\n", '  "server":\n', 1),
        }
        for name, c in variants.items():
            with self.subTest(variant=name):
                self.assertNotEqual(c, compose, f"{name}: variant changed nothing")
                self.assertEqual(check(region, c, rel, image_config, iterations), [])

    def test_mutations_fail(self):
        region, compose, rel, tag, image_config, iterations = live_inputs()
        self.assertEqual(check(region, compose, rel, image_config, iterations), [])
        dev = (ROOT / DEV_STACK).read_text(encoding="utf-8")
        r = region
        cases = {
            "dev stack": (r.replace(rel, DEV_STACK), dev, DEV_STACK),
            "main branch": (r.replace(f"/Yuzu/v{tag}/", "/Yuzu/main/"), compose, rel),
            "tag mismatch": (r.replace(f"/Yuzu/v{tag}/", "/Yuzu/v0.0.1/"), compose, rel),
            "default mismatch": (r, compose.replace(f":-{tag}}}", ":-0.0.1}"), rel),
            "build key": (r, compose.replace(
                "  server:\n", "  server:\n    build:\n      context: ../..\n", 1), rel),
            "fixed tag": (r, re.sub(r"yuzu-server:\$\{YUZU_VERSION:-[^}]+\}",
                                    "yuzu-server:0.14.0", compose), rel),
            "no certs": (r, "\n".join(
                l for l in compose.splitlines()
                if not re.match(r"^\s*-\s*\S+:/etc/yuzu/certs\s*$", l)), rel),
            "certs ro": (r, re.sub(r"(-\s*\S+:/etc/yuzu/certs)\s*$", r"\1:ro",
                                   compose, flags=re.M), rel),
            "no 8443": (r, re.sub(r'^\s*-\s*"8443:8443".*\n', "", compose, flags=re.M), rel),
            "command": (r, compose.replace(
                "  server:\n", "  server:\n    command: [\"--no-tls\"]\n", 1), rel),
            "no volume guard": (r.replace("! docker volume inspect yuzu_server-data >/dev/null 2>&1 &&\n", ""),
                                compose, rel),
            "header backup recipe": (r.replace("upgrading.md#docker", "upgrading.md"), compose, rel),
            "cert dir clearable": (r.replace("Never clear `/etc/yuzu/certs`", "You may clear `/etc/yuzu/certs`"),
                                   compose, rel),
            "unchained step 1": (r.replace("mkdir yuzu && cd yuzu &&", "mkdir yuzu && cd yuzu"),
                                 compose, rel),
            "cd later": (r.replace(COMPOSE_F + "up -d --wait &&",
                                   "cd yuzu && " + COMPOSE_F + "up -d --wait &&"), compose, rel),
            "comment line": (r.replace("```bash\n! docker", "```bash\n# 1. Set up\n! docker"),
                             compose, rel),
            "no -f": (r.replace(COMPOSE_F + "up -d --wait", "docker compose up -d --wait"),
                      compose, rel),
            "env clobber": (r.replace("(umask 077; set -C; ", "(umask 077; "), compose, rel),
            "cfg clobber": (r.replace("os.O_CREAT | os.O_EXCL", "os.O_CREAT | os.O_TRUNC"),
                            compose, rel),
            "seed clobber": (r.replace("'umask 077 && set -C && cat >", "'umask 077 && cat >"),
                             compose, rel),
            "seed path": (r.replace("/var/lib/yuzu/yuzu-server.cfg' <",
                                    "/etc/yuzu/yuzu-server.cfg' <"), compose, rel),
            "user role": (r.replace('"admin:admin:%s', '"admin:user:%s'), compose, rel),
            "iterations": (r.replace("s, 100000)", "s, 1000)"), compose, rel),
            "sha1": (r.replace('pbkdf2_hmac("sha256"', 'pbkdf2_hmac("sha1"'), compose, rel),
            "short pw": (r.replace("len(p) < 12", "len(p) < 8"), compose, rel),
            "one pg password": (r.replace('"$(openssl rand -hex 24)" "$(openssl rand -hex 24)"',
                                          '"$(openssl rand -hex 24)" x'), compose, rel),
            "no version": (r.replace("YUZU_VERSION=0.14.0\\n", ""), compose, rel),
            "san after up": (r.replace("YUZU_CERT_SAN", "CERT_NAMES"), compose, rel),
            "no --wait": (r.replace("up -d --wait &&", "up -d &&"), compose, rel),
            "no readyz": (r.replace("8443/readyz", "8443/"), compose, rel),
            "http readyz": (r.replace("https://localhost:8443/readyz",
                                      "http://localhost:8443/readyz"), compose, rel),
            "curl no -f": (r.replace("curl -fsS --cacert", "curl -sS --cacert"), compose, rel),
        }
        for name, (b, c, rr) in cases.items():
            with self.subTest(mutation=name):
                self.assertNotEqual((b, c), (region, compose), f"{name}: mutation changed nothing")
                self.assertNotEqual(check(b, c, rr, image_config, iterations), [],
                                    f"{name}: check still passes")


if __name__ == "__main__":
    unittest.main(verbosity=2)
