"""WP06 F55 tripwire: every path-like `agent.*` plugin-config key agent.cpp publishes must be in
the authoritative list in agents/shared/agent_reserved_path_keys.hpp (reserved dir/file) or in its
explicit non-secret allow-list. A new credential path published to plugins without being reserved
would be readable through filesystem.read (FileRetrieval:Read)."""
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PATH_LIKE = re.compile(r"(_dir|_file|_cert|_key|_bundle|_allowlist|_endpoint|_path|_store|_secret|_token|_db|_url|_socket|_pem)$")


def keys_in_header():
    h = (ROOT / "agents/shared/agent_reserved_path_keys.hpp").read_text()
    return set(re.findall(r'"(agent\.[a-z_]+)"', h))


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
        h = (ROOT / "agents/shared/agent_reserved_path_keys.hpp").read_text()
        reserved = h.split("kPublishedNonSecretPathKeys")[0]
        for k in ("agent.enrollment_token_file", "agent.tls_client_key", "agent.data_dir",
                  "agent.plugin_trust_bundle", "agent.update_trust_bundle", "agent.plugin_allowlist"):
            self.assertIn(k, reserved)

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
