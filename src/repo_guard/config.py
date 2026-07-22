from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
import re
import tomllib

from .models import Category


DEFAULT_CHECKS = {
    Category.SECRET.value,
    Category.SUSPICIOUS_FILE.value,
    Category.HEAVY_FILE.value,
    Category.JUNK_DIR.value,
}
DEFAULT_FAIL_ON = {Category.SECRET.value, Category.SCAN_ERROR.value}
DEFAULT_EXCLUDES = [".git", ".hg", ".svn"]


class ConfigError(ValueError):
    pass


@dataclass(slots=True)
class RepoGuardConfig:
    max_size_mb: float = 10.0
    workers: int = 8
    tracked_only: bool = False
    all_files: bool = False
    excludes: list[str] = field(default_factory=lambda: list(DEFAULT_EXCLUDES))
    allow_patterns: list[str] = field(default_factory=list)
    checks: set[str] = field(default_factory=lambda: set(DEFAULT_CHECKS))
    fail_on: set[str] = field(default_factory=lambda: set(DEFAULT_FAIL_ON))

    def validate(self) -> None:
        if self.max_size_mb <= 0:
            raise ConfigError("scan.max_size_mb must be greater than zero")
        if self.workers < 1 or self.workers > 64:
            raise ConfigError("scan.workers must be between 1 and 64")
        if self.tracked_only and self.all_files:
            raise ConfigError("scan.tracked_only and scan.all_files cannot both be true")

        valid_categories = {category.value for category in Category}
        unknown_checks = self.checks - valid_categories
        if unknown_checks:
            raise ConfigError(
                "unknown checks: " + ", ".join(sorted(unknown_checks))
            )
        unknown_failures = self.fail_on - valid_categories
        if unknown_failures:
            raise ConfigError(
                "unknown fail_on categories: " + ", ".join(sorted(unknown_failures))
            )
        for pattern in self.allow_patterns:
            try:
                re.compile(pattern)
            except re.error as exc:
                raise ConfigError(f"invalid allow regex {pattern!r}: {exc}") from exc


def _expect_table(data: dict, name: str) -> dict:
    value = data.get(name, {})
    if not isinstance(value, dict):
        raise ConfigError(f"[{name}] must be a TOML table")
    return value


def _string_list(value: object, key: str) -> list[str]:
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        raise ConfigError(f"{key} must be an array of strings")
    return list(value)


def _number(value: object, key: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ConfigError(f"{key} must be a number")
    return float(value)


def _integer(value: object, key: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ConfigError(f"{key} must be an integer")
    return value


def _boolean(value: object, key: str) -> bool:
    if not isinstance(value, bool):
        raise ConfigError(f"{key} must be true or false")
    return value


def load_config(path: Path) -> RepoGuardConfig:
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ConfigError(f"cannot read config {path}: {exc}") from exc
    except tomllib.TOMLDecodeError as exc:
        raise ConfigError(f"invalid TOML in {path}: {exc}") from exc

    scan = _expect_table(data, "scan")
    policy = _expect_table(data, "policy")

    config = RepoGuardConfig()
    if "max_size_mb" in scan:
        config.max_size_mb = _number(scan["max_size_mb"], "scan.max_size_mb")
    if "workers" in scan:
        config.workers = _integer(scan["workers"], "scan.workers")
    if "tracked_only" in scan:
        config.tracked_only = _boolean(scan["tracked_only"], "scan.tracked_only")
    if "all_files" in scan:
        config.all_files = _boolean(scan["all_files"], "scan.all_files")
    if "exclude" in scan:
        config.excludes.extend(_string_list(scan["exclude"], "scan.exclude"))
    if "allow" in scan:
        config.allow_patterns = _string_list(scan["allow"], "scan.allow")
    if "checks" in scan:
        config.checks = set(_string_list(scan["checks"], "scan.checks"))
    if "fail_on" in policy:
        config.fail_on = set(_string_list(policy["fail_on"], "policy.fail_on"))

    config.validate()
    return config
