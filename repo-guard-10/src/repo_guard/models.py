from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any


class Severity(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Category(str, Enum):
    SECRET = "secret"
    SUSPICIOUS_FILE = "suspicious-file"
    HEAVY_FILE = "heavy-file"
    JUNK_DIR = "junk-dir"
    SCAN_ERROR = "scan-error"
    SKIPPED_FILE = "skipped-file"


@dataclass(frozen=True, slots=True)
class Finding:
    category: Category
    rule_id: str
    message: str
    path: str
    severity: Severity
    line: int | None = None
    column: int | None = None
    masked_value: str | None = None
    fingerprint: str | None = None
    size_bytes: int | None = None

    def sort_key(self) -> tuple[Any, ...]:
        severity_order = {Severity.HIGH: 0, Severity.MEDIUM: 1, Severity.LOW: 2}
        return (
            severity_order[self.severity],
            self.category.value,
            self.path,
            self.line or 0,
            self.column or 0,
            self.rule_id,
        )

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "category": self.category.value,
            "rule_id": self.rule_id,
            "severity": self.severity.value,
            "message": self.message,
            "path": self.path,
        }
        if self.line is not None:
            result["line"] = self.line
        if self.column is not None:
            result["column"] = self.column
        if self.masked_value is not None:
            result["masked_value"] = self.masked_value
        if self.fingerprint is not None:
            result["fingerprint"] = self.fingerprint
        if self.size_bytes is not None:
            result["size_bytes"] = self.size_bytes
        return result


@dataclass(slots=True)
class ScanStats:
    discovery_source: str = "filesystem"
    files_considered: int = 0
    files_scanned: int = 0
    bytes_scanned: int = 0
    binary_files_skipped: int = 0
    symlinks_skipped: int = 0
    duration_ms: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "discovery_source": self.discovery_source,
            "files_considered": self.files_considered,
            "files_scanned": self.files_scanned,
            "bytes_scanned": self.bytes_scanned,
            "binary_files_skipped": self.binary_files_skipped,
            "symlinks_skipped": self.symlinks_skipped,
            "duration_ms": self.duration_ms,
        }


@dataclass(slots=True)
class ScanReport:
    root: Path
    findings: list[Finding] = field(default_factory=list)
    stats: ScanStats = field(default_factory=ScanStats)
    version: str = ""

    def sorted_findings(self) -> list[Finding]:
        return sorted(self.findings, key=Finding.sort_key)

    def counts(self) -> dict[str, int]:
        counts = {category.value: 0 for category in Category}
        for finding in self.findings:
            counts[finding.category.value] += 1
        return counts

    def has_categories(self, categories: set[str]) -> bool:
        return any(finding.category.value in categories for finding in self.findings)

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": {"name": "repo-guard", "version": self.version},
            "root": str(self.root),
            "summary": self.counts(),
            "findings": [finding.to_dict() for finding in self.sorted_findings()],
            "stats": self.stats.to_dict(),
        }
