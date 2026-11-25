#!/usr/bin/env python3
"""test_instructions_runner_params.py - the /test --instructions runner must synthesise
parameter values the server accepts.

The server rejects a string parameter that does not match its definition's
`validation.pattern` (HTTP 400; RE2 PartialMatch, i.e. an unanchored search, which is what
`re.search` does here). Before the runner honoured the pattern, the Instructions gate failed
on device.agent_actions.set_log_level, device.discovery.scan_subnet and
crossplatform.echo.configure. This sweeps EVERY pattern-constrained parameter of every
InstructionDefinition the gate dispatches, so a new pattern the runner cannot satisfy fails
here instead of in a 15-minute live-stack run, and pins the precedence rules around it.

Runnable standalone: `python3 tests/test_instructions_runner_params.py`. Hermetic: reads
content/definitions/ only (needs PyYAML, as the runner does). No subprocess, network or clock.
"""
import contextlib
import hashlib
import io
import ipaddress
import os
import re
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts" / "test"))
import instructions_runner as ir  # noqa: E402


def synth(schema):
    return ir.synthesise_params({"required": ["p"], "properties": {"p": schema}})["p"]


def string_schema(pattern, **extra):
    return {"type": "string", "validation": {"pattern": pattern}, **extra}


class PatternSynthesis(unittest.TestCase):
    def test_every_definition_pattern_is_satisfied(self):
        swept = 0
        for d in ir.load_definitions(ROOT / "content" / "definitions", {}):
            for name, schema in (d.parameters.get("properties") or {}).items():
                pattern = ((schema or {}).get("validation") or {}).get("pattern")
                if not pattern or schema.get("type", "string") != "string":
                    continue
                swept += 1
                with self.subTest(definition=d.id, parameter=name):
                    got = ir._value_for_property(name, schema)
                    self.assertIsNotNone(re.search(pattern, got), f"{got!r} does not match {pattern!r}")
        self.assertGreater(swept, 0, "no pattern-constrained parameters found: the sweep is vacuous")

    def test_scan_subnet_never_targets_a_routable_network(self):
        d = next(d for d in ir.load_definitions(ROOT / "content" / "definitions", {})
                 if d.id == "device.discovery.scan_subnet")
        got = ir._value_for_property("subnet", d.parameters["properties"]["subnet"])
        self.assertTrue(ipaddress.ip_network(got).subnet_of(ipaddress.ip_network("192.0.2.0/24")), got)

    def test_name_based_default_is_kept_when_it_matches(self):
        # "host" synthesises 127.0.0.1; the digit fallback "10" would also satisfy this pattern.
        self.assertEqual(ir._value_for_property("host", string_schema(r"^[a-zA-Z0-9.:\-]+$")), "127.0.0.1")

    def test_no_pattern_leaves_the_name_based_default(self):
        self.assertEqual(synth({"type": "string"}), ir._synth_string("p", {}))

    def test_explicit_default_and_enum_win_over_the_pattern(self):
        # "10" (a fallback) would satisfy this pattern, so fitting a default or enum would show.
        self.assertEqual(synth(string_schema("^[0-9]+$", default="keep")), "keep")
        self.assertEqual(synth(string_schema("^[0-9]+$", enum=["a", "b"])), "a")

    def test_unsatisfiable_or_invalid_pattern_leaves_the_value_for_the_server(self):
        self.assertEqual(synth(string_schema("^zzz$")), ir._synth_string("p", {}))
        self.assertEqual(synth(string_schema("[")), ir._synth_string("p", {}))


class ContractShapedParameters(unittest.TestCase):
    """Parameters whose accepted shape the plugin enforces (the 2026-11 Instructions gate failures)."""

    def real(self, def_id):
        return next(d for d in ir.load_definitions(ROOT / "content" / "definitions", {}) if d.id == def_id)

    def test_echo_query_sends_epoch_seconds_not_a_placeholder(self):
        params = ir.synthesise_params(self.real("crossplatform.echo.query").parameters,
                                      def_id="crossplatform.echo.query")
        self.assertRegex(params["from"], r"^[0-9]+$")

    def test_from_and_to_are_epoch_seconds(self):
        with mock.patch.object(ir.time, "time", return_value=1234567890.9):
            self.assertEqual(ir._synth_string("from", {}), "0")
            self.assertEqual(ir._synth_string("to", {}), "1234567890")

    def test_no_rule_synthesises_a_budget_value_for_echo_configure(self):
        # Any db_budget_bytes value is a real write of the agent's Echo budget (the documented
        # default included), so the row is skipped by name instead and no rule may invent one.
        self.assertIsNone(ir._contract_string("db_budget_bytes"))
        self.assertIn("Echo byte budget", ir.named_skip_reason("crossplatform.echo.configure", {}))

    def test_rdp_set_state_is_skipped_by_name_not_sent_enable(self):
        self.assertIn("remote desktop", ir.named_skip_reason("windows.rdp.set_state", {}))

    def test_contract_rules_match_exact_names_only(self):
        for name in ("from_date", "xfrom", "From", "to_address", "tool", "total", "since"):
            with self.subTest(name=name):
                self.assertIsNone(ir._contract_string(name))

    def test_list_dir_gets_the_seeded_directory_and_read_the_seeded_text_file(self):
        with tempfile.TemporaryDirectory(prefix="yuzu_test_seedcase_") as base, \
                ir.seeded_directory(base) as seed:
            list_dir = ir.synthesise_params(self.real("device.filesystem.list_dir").parameters,
                                            def_id="device.filesystem.list_dir")["path"]
            read = ir.synthesise_params(self.real("device.filesystem.read").parameters,
                                        def_id="device.filesystem.read")["path"]
            self.assertEqual(list_dir, seed)
            self.assertTrue(os.path.isdir(list_dir))
            self.assertEqual(read, os.path.join(seed, "a.txt"))
            self.assertTrue(os.path.isfile(read))
            self.assertNotIn(b"\0", Path(read).read_bytes())   # text, not the "binary" the plugin refuses

    def test_the_seed_rules_are_per_definition_and_fall_back_without_a_seed(self):
        # Other definitions keep the name-based path default, and with nothing seeded so do these.
        with tempfile.TemporaryDirectory(prefix="yuzu_test_seedcase_") as base, ir.seeded_directory(base):
            self.assertEqual(ir._synth_string("path", {}, "device.filesystem.exists"),
                             ir._HOST_PATHS[ir.HOST]["file"])
        self.assertEqual(ir._synth_string("path", {}, "device.filesystem.list_dir"),
                         ir._HOST_PATHS[ir.HOST]["file"])

    def test_an_override_still_wins_over_every_rule(self):
        got = ir.synthesise_params(self.real("crossplatform.echo.query").parameters,
                                   {"from": "x"}, "crossplatform.echo.query")
        self.assertEqual(got["from"], "x")


class NamedSkips(unittest.TestCase):
    def test_http_client_rows_are_always_skipped_with_the_ssrf_reason(self):
        for def_id in ("agent.http_client.get", "agent.http_client.head"):
            self.assertIn("SSRF", ir.named_skip_reason(def_id, {}))

    def test_privileged_rows_skip_only_on_the_exact_opt_in_value(self):
        for def_id in ("device.network_actions.ping", "device.network_actions.flush_dns"):
            self.assertEqual(ir.named_skip_reason(def_id, {}), "")
            self.assertEqual(ir.named_skip_reason(def_id, {ir.SKIP_PRIVILEGED_ENV: "0"}), "")
            self.assertEqual(ir.named_skip_reason(def_id, {ir.SKIP_PRIVILEGED_ENV: ""}), "")
            self.assertIn(ir.SKIP_PRIVILEGED_ENV, ir.named_skip_reason(def_id, {ir.SKIP_PRIVILEGED_ENV: "1"}))

    def test_no_other_row_is_ever_skipped_by_name(self):
        env = {ir.SKIP_PRIVILEGED_ENV: "1"}
        skipped = {d.id for d in ir.load_definitions(ROOT / "content" / "definitions", {})
                   if ir.named_skip_reason(d.id, env)}
        self.assertEqual(skipped, {"agent.http_client.get", "agent.http_client.head",
                                   "crossplatform.echo.configure", "windows.rdp.set_state",
                                   "device.network_actions.ping", "device.network_actions.flush_dns"})

    def test_an_empty_environ_argument_is_honoured_not_replaced_by_the_process_one(self):
        with mock.patch.dict(os.environ, {ir.SKIP_PRIVILEGED_ENV: "1"}):
            self.assertEqual(ir.named_skip_reason("device.network_actions.ping", {}), "")
            self.assertNotEqual(ir.named_skip_reason("device.network_actions.ping"), "")


class SeededDirectory(unittest.TestCase):
    """seeded_directory(): the per-run directory directory-shaped parameters resolve to (#5624).

    Hermetic: every provisioning happens under a TemporaryDirectory this test owns.
    """

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory(prefix="yuzu_test_seedcase_")
        self.addCleanup(self._tmp.cleanup)
        self.base = self._tmp.name
        self.assertEqual(ir._SEED, {}, "a previous test leaked the seed")

    def test_provisions_three_regular_files_under_a_yuzu_test_prefixed_directory(self):
        with ir.seeded_directory(self.base) as path:
            self.assertEqual(Path(path).parent, Path(self.base))
            self.assertTrue(Path(path).name.startswith("yuzu_test_instr_"), path)
            names = sorted(p.name for p in Path(path).iterdir())
            self.assertEqual(names, ["a.txt", "b.txt", "c.txt"])
            for p in Path(path).iterdir():
                self.assertTrue(p.is_file() and not p.is_symlink(), p)
            # three DISTINCT files, so a hash match identifies exactly one of them
            digests = {hashlib.sha256(p.read_bytes()).hexdigest() for p in Path(path).iterdir()}
            self.assertEqual(len(digests), 3)

    @unittest.skipUnless(os.name == "posix", "POSIX permission bits")
    def test_modes_are_readable_by_an_unprivileged_agent_whatever_the_umask(self):
        previous = os.umask(0o077)  # a restrictive umask must not hide the seed from the agent
        self.addCleanup(os.umask, previous)
        with ir.seeded_directory(self.base) as path:
            self.assertEqual(stat.S_IMODE(os.stat(path).st_mode), 0o755)
            for p in Path(path).iterdir():
                self.assertEqual(stat.S_IMODE(p.stat().st_mode), 0o644, p)

    def test_published_sha256_is_the_real_digest_of_a_txt(self):
        with ir.seeded_directory(self.base) as path:
            digest = ir._SEED["sha256"]
            self.assertRegex(digest, r"^[0-9a-f]{64}$")
            self.assertEqual(digest, hashlib.sha256((Path(path) / "a.txt").read_bytes()).hexdigest())
            self.assertNotEqual(digest, "0" * 64)

    def test_synthesis_uses_the_seed_inside_and_the_host_default_after(self):
        before = (ir._synth_string("directory", {}), ir._synth_string("sha256", {}))
        self.assertEqual(before[1], "0" * 64)
        with ir.seeded_directory(self.base) as path:
            self.assertEqual(ir._synth_string("directory", {}), path)
            self.assertEqual(ir._synth_string("search_dir", {}), path)
            self.assertEqual(ir._synth_string("sha256", {}), ir._SEED["sha256"])
        self.assertEqual((ir._synth_string("directory", {}), ir._synth_string("sha256", {})), before)
        self.assertEqual(ir._synth_string("directory", {}), ir._HOST_PATHS[ir.HOST]["dir"])

    def test_find_by_hash_real_schema_yields_the_seeded_directory_and_digest(self):
        d = next(d for d in ir.load_definitions(ROOT / "content" / "definitions", {})
                 if d.id == "device.filesystem.find_by_hash")
        with ir.seeded_directory(self.base) as path:
            params = ir.synthesise_params(d.parameters)
            self.assertEqual(params["directory"], path)
            self.assertEqual(params["sha256"], ir._SEED["sha256"])
            self.assertEqual(
                hashlib.sha256((Path(path) / "a.txt").read_bytes()).hexdigest(), params["sha256"])

    def test_two_provisions_never_share_a_name(self):
        with ir.seeded_directory(self.base) as first:
            with ir.seeded_directory(self.base) as second:
                self.assertNotEqual(first, second)
                # both under the SAME base: a clash would otherwise hide behind the temp fallback
                self.assertEqual(Path(first).parent, Path(second).parent)
                self.assertTrue(Path(first).is_dir() and Path(second).is_dir())

    def test_directory_is_removed_and_seed_cleared_when_the_body_raises(self):
        seen = {}
        with self.assertRaises(RuntimeError):
            with ir.seeded_directory(self.base) as path:
                seen["path"] = path
                raise RuntimeError("boom")
        self.assertFalse(Path(seen["path"]).exists())
        self.assertEqual(ir._SEED, {})
        self.assertEqual(list(Path(self.base).iterdir()), [])

    def test_unwritable_base_falls_back_to_the_user_temp_directory(self):
        bad = os.path.join(self.base, "missing", "parent")  # mkdir under a missing parent: OSError
        fallback = Path(self.base) / "fallback"
        fallback.mkdir()
        with mock.patch.object(ir.tempfile, "gettempdir", return_value=str(fallback)):
            with ir.seeded_directory(bad) as path:
                self.assertIsNotNone(path)
                self.assertEqual(Path(path).parent, fallback)
                self.assertEqual(ir._SEED["dir"], path)
        self.assertEqual(list(fallback.iterdir()), [])

    def test_both_bases_unwritable_is_non_fatal_and_leaves_the_host_default(self):
        bad = os.path.join(self.base, "missing", "parent")
        err = io.StringIO()
        with mock.patch.object(ir.tempfile, "gettempdir", return_value=bad), \
                contextlib.redirect_stderr(err):
            with ir.seeded_directory(bad) as path:
                self.assertIsNone(path)
                self.assertEqual(ir._SEED, {})
                self.assertEqual(ir._synth_string("directory", {}), ir._HOST_PATHS[ir.HOST]["dir"])
                self.assertEqual(ir._synth_string("sha256", {}), "0" * 64)
        lines = [ln for ln in err.getvalue().splitlines() if ln.strip()]
        self.assertEqual(len(lines), 1, lines)
        self.assertIn("seed directory unavailable", lines[0])
        self.assertEqual(ir._SEED, {})

    @contextlib.contextmanager
    def _patched_main(self, fake_run):
        """main() runs `fake_run` instead of the real run, with the seed rooted in self.base."""
        with mock.patch.object(ir, "parse_args", return_value=object()), \
                mock.patch.object(ir, "run", fake_run), \
                mock.patch.object(ir.tempfile, "gettempdir", return_value=self.base), \
                mock.patch.dict(ir._HOST_PATHS, {ir.HOST: {**ir._HOST_PATHS[ir.HOST], "dir": self.base}}):
            yield

    def test_main_runs_the_whole_run_inside_the_seed_and_cleans_up_after(self):
        seen = {}

        def fake_run(_args):
            seen["dir"] = ir._SEED.get("dir")
            seen["exists"] = bool(seen["dir"]) and Path(seen["dir"]).is_dir()
            return 7

        with self._patched_main(fake_run):
            self.assertEqual(ir.main([]), 7)
        self.assertTrue(seen["exists"], "run() did not execute inside the seeded directory")
        self.assertEqual(Path(seen["dir"]).parent, Path(self.base))
        self.assertFalse(Path(seen["dir"]).exists())
        self.assertEqual(ir._SEED, {})

    def test_main_interrupt_still_exits_130_and_cleans_up(self):
        seen = {}

        def fake_run(_args):
            seen["dir"] = ir._SEED["dir"]
            raise KeyboardInterrupt

        with self._patched_main(fake_run), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(ir.main([]), 130)
        self.assertFalse(Path(seen["dir"]).exists())
        self.assertEqual(ir._SEED, {})


if __name__ == "__main__":
    unittest.main()
