from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from repo_guard.config import ConfigError, load_config


class ConfigTests(unittest.TestCase):
    def test_loads_valid_config(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / ".repoguard.toml"
            path.write_text(
                """
[scan]
max_size_mb = 4
workers = 2
exclude = ["vendor/**"]
allow = ["^example$"]
checks = ["secret"]

[policy]
fail_on = ["secret"]
""".strip(),
                encoding="utf-8",
            )
            config = load_config(path)

        self.assertEqual(config.max_size_mb, 4)
        self.assertEqual(config.workers, 2)
        self.assertIn("vendor/**", config.excludes)
        self.assertEqual(config.allow_patterns, ["^example$"])
        self.assertEqual(config.checks, {"secret"})

    def test_rejects_invalid_allow_regex(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / ".repoguard.toml"
            path.write_text('[scan]\nallow = ["["]\n', encoding="utf-8")
            with self.assertRaises(ConfigError):
                load_config(path)

    def test_rejects_non_boolean_discovery_mode(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / ".repoguard.toml"
            path.write_text('[scan]\ntracked_only = "false"\n', encoding="utf-8")
            with self.assertRaises(ConfigError):
                load_config(path)

    def test_rejects_conflicting_discovery_modes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / ".repoguard.toml"
            path.write_text(
                "[scan]\ntracked_only = true\nall_files = true\n",
                encoding="utf-8",
            )
            with self.assertRaises(ConfigError):
                load_config(path)


if __name__ == "__main__":
    unittest.main()
