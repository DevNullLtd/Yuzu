#!/usr/bin/env python3
"""Exercise the workflow extractor CLI against bounded, independent step inputs."""

from pathlib import Path
import subprocess
import sys
import tempfile
import textwrap
import unittest


EXTRACTOR = Path(__file__).parent / "shell" / "extract_run_block.py"


class ExtractRunBlockTests(unittest.TestCase):
    def extract(self, workflow, *args):
        with tempfile.TemporaryDirectory(prefix="yuzu_test_extract_") as scratch:
            source = Path(scratch) / "workflow.yml"
            output = Path(scratch) / "step.sh"
            workflow = textwrap.dedent(workflow)
            if workflow.startswith("steps:"):
                workflow = "jobs:\n  test:\n" + textwrap.indent(workflow, "    ")
            source.write_text(workflow, encoding="utf-8")
            result = subprocess.run(
                [sys.executable, str(EXTRACTOR), str(source), str(output), *args],
                capture_output=True, text=True, timeout=10,
            )
            return result, output.read_text(encoding="utf-8") if output.exists() else None

    def test_extracts_only_selected_body_and_substitutes_expression(self):
        result, body = self.extract('''\
            jobs:
              test:
                steps:
                  - id: selected
                    name: Example
                    run: |
                      echo "${{ github.sha }}"
                      if true; then
                        echo selected
                      fi
                  - id: other
                    run: |
                      echo WRONG_BODY
            ''', "--id", "selected", "--subst", "github.sha=COMMIT")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(body, 'echo "$COMMIT"\nif true; then\n  echo selected\nfi\n')

    def test_uses_step_cannot_borrow_later_run(self):
        result, body = self.extract('''\
            steps:
              - id: selected
                uses: actions/checkout@v4
              - id: other
                run: |
                  echo WRONG_BODY
            ''', "--id", "selected")
        self.assertEqual(result.returncode, 2)
        self.assertIsNone(body)

    def test_nested_run_text_is_not_step_run(self):
        result, body = self.extract('''\
            steps:
              - id: selected
                uses: example/action@v1
                with:
                  script: |
                    run: |
                      echo WRONG_BODY
            ''', "--id", "selected")
        self.assertEqual(result.returncode, 2)
        self.assertIsNone(body)

    def test_duplicate_selectors_are_ambiguous(self):
        result, body = self.extract('''\
            jobs:
              first:
                steps:
                  - name: selected
                    run: |
                      echo first
              second:
                steps:
                  - name: selected
                    run: |
                      echo second
            ''', "--name", "selected")
        self.assertEqual(result.returncode, 2)
        self.assertIn("found 2", result.stderr)
        self.assertIsNone(body)

    def test_step_shaped_heredoc_is_not_a_workflow_step(self):
        result, body = self.extract("""\
            jobs:
              test:
                steps:
                  - id: outer
                    run: |
                      cat <<'DATA'
                      - id: selected
                        run: |
                          echo WRONG_BODY
                      DATA
            """, "--id", "selected")
        self.assertEqual(result.returncode, 2)
        self.assertIsNone(body)

    def test_selector_can_follow_name_and_duplicate_run_is_rejected(self):
        workflow = """\
            steps:
              - name: Example
                id: selected
                run: |
                  echo correct
            """
        result, body = self.extract(workflow, "--id", "selected")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(body, "echo correct\n")
        # Construct the duplicate at the same indentation as the original field.
        duplicate = textwrap.dedent(workflow) + "    run: |\n      echo WRONG_BODY\n"
        result, body = self.extract(duplicate, "--id", "selected")
        self.assertEqual(result.returncode, 2)
        self.assertIsNone(body)

    def test_missing_empty_and_unsubstituted_blocks_are_refused(self):
        for workflow in [
            "steps:\n  - id: other\n    run: |\n      echo other\n",
            "steps:\n  - id: selected\n    run: |\n\n",
            "steps:\n  - id: selected\n    run: |\n      echo ${{ github.sha }}\n",
        ]:
            with self.subTest(workflow=workflow):
                result, body = self.extract(workflow, "--id", "selected")
                self.assertEqual(result.returncode, 2)
                self.assertIsNone(body)


if __name__ == "__main__":
    unittest.main()
