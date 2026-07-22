from __future__ import annotations

from contextlib import redirect_stdout
import io
import json
from pathlib import Path
import tempfile
import unittest

from repo_guard.cli import main


class CliTests(unittest.TestCase):
    def test_json_output_and_failure_code(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            token = "AKIA" + ("E" * 16)
            (root / "app.py").write_text(token + "\n", encoding="utf-8")
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                exit_code = main([str(root), "--all-files", "--format", "json"])

        payload = json.loads(stdout.getvalue())
        self.assertEqual(exit_code, 1)
        self.assertEqual(payload["summary"]["secret"], 1)

    def test_secrets_only_text_report_does_not_crash(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".env").write_text("SAFE=true\n", encoding="utf-8")
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                exit_code = main([str(root), "--all-files", "--secrets-only"])

        self.assertEqual(exit_code, 0)
        self.assertIn("No findings", stdout.getvalue())

    def test_writes_sarif_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "app.py").write_text("print('ok')\n", encoding="utf-8")
            output = root / "report.sarif"
            exit_code = main(
                [
                    str(root),
                    "--all-files",
                    "--format",
                    "sarif",
                    "--output",
                    str(output),
                ]
            )
            payload = json.loads(output.read_text(encoding="utf-8"))

        self.assertEqual(exit_code, 0)
        self.assertEqual(payload["version"], "2.1.0")


if __name__ == "__main__":
    unittest.main()
