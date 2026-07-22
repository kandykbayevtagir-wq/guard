from __future__ import annotations

import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from repo_guard.config import RepoGuardConfig
from repo_guard.models import Category
from repo_guard.scanner import scan


class ScannerTests(unittest.TestCase):
    def test_detects_secret_with_location_and_masking(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            token = "AKIA" + ("A" * 16)
            (root / "settings.py").write_text(
                f'key = "{token}"\n', encoding="utf-8"
            )
            report = scan(root, RepoGuardConfig(all_files=True), version="test")

        secrets = [f for f in report.findings if f.category == Category.SECRET]
        self.assertEqual(len(secrets), 1)
        self.assertEqual(secrets[0].line, 1)
        self.assertGreater(secrets[0].column or 0, 1)
        self.assertNotEqual(secrets[0].masked_value, token)
        self.assertEqual(len(secrets[0].fingerprint or ""), 16)

    def test_inline_suppression_and_placeholder_are_ignored(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            token = "AKIA" + ("B" * 16)
            (root / "settings.py").write_text(
                f'key = "{token}"  # repo-guard: allow\n'
                'password = "replace-me"\n',
                encoding="utf-8",
            )
            report = scan(root, RepoGuardConfig(all_files=True), version="test")

        self.assertFalse(any(f.category == Category.SECRET for f in report.findings))

    def test_reports_sensitive_name_heavy_file_and_junk_directory(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".env").write_text("SAFE=true\n", encoding="utf-8")
            (root / "large.bin").write_bytes(b"a" * 2048)
            dependency = root / "node_modules" / "package"
            dependency.mkdir(parents=True)
            (dependency / "index.js").write_text("export {};\n", encoding="utf-8")
            config = RepoGuardConfig(all_files=True, max_size_mb=0.001)
            report = scan(root, config, version="test")

        categories = {finding.category for finding in report.findings}
        self.assertIn(Category.SUSPICIOUS_FILE, categories)
        self.assertIn(Category.HEAVY_FILE, categories)
        self.assertIn(Category.JUNK_DIR, categories)

    @unittest.skipUnless(shutil.which("git"), "git is required")
    def test_git_discovery_respects_gitignore(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            (root / ".gitignore").write_text("node_modules/\n.env\n", encoding="utf-8")
            (root / "main.py").write_text("print('ok')\n", encoding="utf-8")
            ignored = root / "node_modules"
            ignored.mkdir()
            (ignored / "secret.txt").write_text(
                "AKIA" + ("C" * 16), encoding="utf-8"
            )
            (root / ".env").write_text("password=" + "realistic" + "value123\n", encoding="utf-8")
            report = scan(root, RepoGuardConfig(), version="test")

        paths = {finding.path for finding in report.findings}
        self.assertNotIn(".env", paths)
        self.assertFalse(any(path.startswith("node_modules/") for path in paths))
        self.assertEqual(report.stats.discovery_source, "git")

    def test_missing_target_is_a_scan_error(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "missing"
            report = scan(target, RepoGuardConfig(all_files=True), version="test")

        self.assertTrue(any(f.category == Category.SCAN_ERROR for f in report.findings))

    @unittest.skipIf(os.name == "nt", "symlink permissions vary on Windows")
    def test_symlink_is_not_followed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            outside = root.parent / f"{root.name}-outside.txt"
            outside.write_text("AKIA" + ("D" * 16), encoding="utf-8")
            try:
                (root / "link.txt").symlink_to(outside)
                report = scan(root, RepoGuardConfig(all_files=True), version="test")
            finally:
                outside.unlink(missing_ok=True)

        self.assertTrue(any(f.category == Category.SKIPPED_FILE for f in report.findings))
        self.assertFalse(any(f.category == Category.SECRET for f in report.findings))


if __name__ == "__main__":
    unittest.main()
