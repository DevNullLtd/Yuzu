"""WP06 F55 tripwire: every path-like `agent.*` plugin-config key agent.cpp publishes must be in
the authoritative list in agents/shared/agent_reserved_path_keys.hpp (reserved dir/file) or in its
explicit non-secret allow-list. A new credential path published to plugins without being reserved
would be readable through filesystem.read (FileRetrieval:Read)."""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PATH_LIKE = re.compile(r"(_dir|_file|_cert|_key|_bundle|_allowlist|_endpoint|_path|_store|_secret|_token|_db|_url|_socket|_pem)$")


def blank_comments(text):
    """Blank `//` and `/* */` comments, keeping string literals, in ONE left-to-right pass
    (offsets and newlines preserved). Same single-pass reasoning as the WP14-A gate's `blank`
    (a `//` inside a string is not a comment, a quote inside a comment opens no string), but
    string literals stay: the keys this gate reads ARE string literals. Character literals and
    raw strings are not handled (the header has none; a `'"'` would open a string).""" 
    out, i, n = [], 0, len(text)
    while i < n:
        if text.startswith("//", i):
            j = text.find("\n", i)
            j = n if j < 0 else j
            out.append(" " * (j - i))
            i = j
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            j = n if j < 0 else j + 2
            out.append(re.sub(r"[^\n]", " ", text[i:j]))
            i = j
        elif text[i] == '"':
            j = i + 1
            while j < n and text[j] != '"' and text[j] != "\n":
                j += 2 if text[j] == "\\" else 1
            j = min(j + 1, n)
            out.append(text[i:j])
            i = j
        else:
            out.append(text[i])
            i += 1
    return "".join(out)


HEADER = ROOT / "agents/shared/agent_reserved_path_keys.hpp"
ARRAY_NAMES = ("kReservedDirKeys", "kReservedFileKeys", "kPublishedNonSecretPathKeys")


def header_arrays(text=None):
    """{array name: [keys]} read from the header with comments blanked, so a key that only
    appears in a comment is not a member of any array."""
    code = blank_comments(HEADER.read_text() if text is None else text)
    out = {}
    for name in ARRAY_NAMES:
        m = re.search(name + r"\s*=\s*\{(.*?)\};", code, re.S)
        out[name] = re.findall(r'"(agent\.[a-z_]+)"', m.group(1)) if m else []
    return out


def keys_in_header(text=None):
    return {k for keys in header_arrays(text).values() for k in keys}


def published_path_keys():
    src = (ROOT / "agents/core/src/agent.cpp").read_text()
    keys = set(re.findall(r'plugin_ctx_\.config\["(agent\.[a-z_]+)"\]', src))
    return {k for k in keys if PATH_LIKE.search(k)}


class AgentReservedPathKeys(unittest.TestCase):
    def test_every_published_path_key_is_classified(self):
        known = keys_in_header()
        missing = sorted(k for k in published_path_keys() if k not in known)
        self.assertEqual([], missing, "published path-like agent.* keys not in "
                         "agent_reserved_path_keys.hpp (reserve them or allow-list with a reason)")

    def test_known_credential_paths_are_reserved(self):
        arrays = header_arrays()
        reserved = set(arrays["kReservedDirKeys"]) | set(arrays["kReservedFileKeys"])
        for k in ("agent.enrollment_token_file", "agent.tls_client_key", "agent.data_dir",
                  "agent.plugin_trust_bundle", "agent.update_trust_bundle", "agent.plugin_allowlist"):
            self.assertIn(k, reserved)

    def test_every_array_is_found_and_non_empty(self):
        for name, keys in header_arrays().items():
            self.assertTrue(keys, f"{name} not found or empty: the gate would pass vacuously")

    def test_non_secret_split_is_disjoint_and_pinned(self):
        # The allow-list is the way out of the reserved set, so growing it is a deliberate act:
        # the expected set is pinned here, and no key may sit in both a reserved array and it.
        arrays = header_arrays()
        reserved = set(arrays["kReservedDirKeys"]) | set(arrays["kReservedFileKeys"])
        non_secret = arrays["kPublishedNonSecretPathKeys"]
        self.assertEqual([], sorted(set(non_secret) & reserved),
                         "a key is both reserved and allow-listed as non-secret")
        self.assertEqual({"agent.plugin_dir", "agent.container_runtime_endpoint"}, set(non_secret),
                         "kPublishedNonSecretPathKeys changed: a key added to the allow-list leaves "
                         "the filesystem plugin able to read it; justify it and update this pin")

    def test_every_non_secret_key_carries_its_reason(self):
        text = HEADER.read_text()
        m = re.search(r"kPublishedNonSecretPathKeys\s*=\s*\{(.*?)\};", blank_comments(text), re.S)
        body = text[m.start(1):m.end(1)]
        for line in body.splitlines():
            if '"agent.' in line:
                self.assertRegex(line, r"//\s*\S", f"no stated reason on: {line.strip()}")

    def test_a_key_in_a_comment_is_not_a_member(self):
        # Self-test: a key that appears only in a comment is not a member of any array.
        mutated = HEADER.read_text().replace(
            "/// Files: the file", '/// "agent.only_in_a_comment" is not reserved\n/// Files: the file', 1)
        self.assertNotEqual(HEADER.read_text(), mutated)
        self.assertNotIn("agent.only_in_a_comment", keys_in_header(mutated))
        self.assertIn("agent.data_dir", keys_in_header(mutated))

    def test_slashes_inside_a_string_are_not_a_comment(self):
        self.assertEqual('x = "a//b"; ', blank_comments('x = "a//b"; // tail')[:12])

    def test_plugin_derives_from_the_list_not_a_copy(self):
        p = (ROOT / "agents/plugins/filesystem/src/filesystem_plugin.cpp").read_text()
        self.assertIn("kReservedDirKeys", p)
        self.assertIn("kReservedFileKeys", p)
        self.assertNotIn('get_config("agent.tls_client_key")', p)

    def test_credential_discovery_runs_before_plugin_config_is_published(self):
        # The filesystem plugin builds its reserved set once at init from plugin_ctx_.config, so
        # a client key / CA that auto-discovery fills in AFTER the first publish is never refused
        # (review finding H1). Best-effort lexical pin of the startup order inside run().
        src = (ROOT / "agents/core/src/agent.cpp").read_text()
        publish = src.index('plugin_ctx_.config["agent.tls_client_key"]')
        for call in ("discover_client_cert()", "discover_install_ca_path()"):
            sites = [m.start() for m in re.finditer(re.escape(call), src)
                     if not src[src.rfind("\n", 0, m.start()) + 1:m.start()].lstrip().startswith("//")]
            self.assertEqual(1, len(sites), f"{call}: expected exactly one live call in agent.cpp")
            self.assertLess(sites[0], publish, f"{call} must run before the plugin config is published")


if __name__ == "__main__":
    unittest.main()
