from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
import hashlib
from pathlib import Path
import re
import time

from .config import RepoGuardConfig
from .discovery import discover_files
from .models import Category, Finding, ScanReport, ScanStats, Severity
from .patterns import SECRET_RULES, SUPPRESSION_PATTERN, is_placeholder


SUSPICIOUS_EXACT_NAMES = {
    "credentials.json",
    "service-account.json",
    "id_rsa",
    "id_dsa",
    "id_ecdsa",
    "id_ed25519",
    ".npmrc",
    ".pypirc",
}
SUSPICIOUS_SAFE_SUFFIXES = (".example", ".sample", ".template", ".dist")
JUNK_DIRECTORY_NAMES = {
    "node_modules",
    "venv",
    ".venv",
    "__pycache__",
    "dist",
    "build",
    ".cache",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "coverage",
}


@dataclass(slots=True)
class FileScanResult:
    findings: list[Finding] = field(default_factory=list)
    bytes_scanned: int = 0
    scanned: bool = False
    binary_skipped: bool = False
    symlink_skipped: bool = False


def _relative(path: Path, root: Path) -> str:
    try:
        return path.relative_to(root).as_posix()
    except ValueError:
        return path.name


def _mask(value: str) -> str:
    if len(value) <= 8:
        return "*" * len(value)
    visible = 4 if len(value) >= 16 else 2
    return value[:visible] + "*" * (len(value) - visible * 2) + value[-visible:]


def _fingerprint(rule_id: str, value: str) -> str:
    digest = hashlib.sha256(f"{rule_id}\0{value}".encode("utf-8")).hexdigest()
    return digest[:16]


def _is_binary(sample: bytes) -> bool:
    if not sample:
        return False
    if b"\0" in sample:
        return True
    control_bytes = sum(byte < 9 or 13 < byte < 32 for byte in sample)
    return control_bytes / len(sample) > 0.30


def _suspicious_file(path: Path) -> bool:
    name = path.name.lower()
    if name in SUSPICIOUS_EXACT_NAMES:
        return True
    if name == ".env":
        return True
    if name.startswith(".env.") and not name.endswith(SUSPICIOUS_SAFE_SUFFIXES):
        return True
    return False


def _allowed(line: str, raw_value: str, allow_patterns: tuple[re.Pattern[str], ...]) -> bool:
    if SUPPRESSION_PATTERN.search(line):
        return True
    return any(pattern.search(raw_value) or pattern.search(line) for pattern in allow_patterns)


def _scan_file_contents(
    path: Path,
    root: Path,
    allow_patterns: tuple[re.Pattern[str], ...],
) -> FileScanResult:
    relative_path = _relative(path, root)
    result = FileScanResult()

    if path.is_symlink():
        result.symlink_skipped = True
        result.findings.append(
            Finding(
                category=Category.SKIPPED_FILE,
                rule_id="symlink-skipped",
                message="Symlink was not followed",
                path=relative_path,
                severity=Severity.LOW,
            )
        )
        return result

    try:
        with path.open("rb") as binary_file:
            sample = binary_file.read(8192)
        if _is_binary(sample):
            result.binary_skipped = True
            return result

        size = path.stat().st_size
        with path.open("r", encoding="utf-8", errors="replace") as text_file:
            for line_number, line in enumerate(text_file, start=1):
                for rule in SECRET_RULES:
                    for match in rule.pattern.finditer(line):
                        raw_value = match.group(rule.secret_group)
                        if rule.rule_id == "generic-secret-assignment" and is_placeholder(raw_value):
                            continue
                        if _allowed(line, raw_value, allow_patterns):
                            continue
                        start = match.start(rule.secret_group)
                        result.findings.append(
                            Finding(
                                category=Category.SECRET,
                                rule_id=rule.rule_id,
                                message=rule.name,
                                path=relative_path,
                                severity=rule.severity,
                                line=line_number,
                                column=start + 1,
                                masked_value=_mask(raw_value),
                                fingerprint=_fingerprint(rule.rule_id, raw_value),
                            )
                        )
        result.bytes_scanned = size
        result.scanned = True
    except (OSError, UnicodeError) as exc:
        result.findings.append(
            Finding(
                category=Category.SCAN_ERROR,
                rule_id="file-read-error",
                message=f"Could not scan file: {exc}",
                path=relative_path,
                severity=Severity.HIGH,
            )
        )
    return result


def scan(target: Path, config: RepoGuardConfig, *, version: str) -> ScanReport:
    started = time.monotonic()
    root, discovery = discover_files(
        target,
        tracked_only=config.tracked_only,
        all_files=config.all_files,
        excludes=config.excludes,
    )
    stats = ScanStats(
        discovery_source=discovery.source,
        files_considered=len(discovery.files),
    )
    report = ScanReport(root=root, stats=stats, version=version)

    for message in discovery.errors:
        report.findings.append(
            Finding(
                category=Category.SCAN_ERROR,
                rule_id="file-discovery-error",
                message=message,
                path=".",
                severity=Severity.HIGH,
            )
        )

    allow_patterns = tuple(re.compile(pattern) for pattern in config.allow_patterns)
    max_size_bytes = int(config.max_size_mb * 1024 * 1024)

    junk_directories: set[str] = set()
    content_candidates: list[Path] = []

    for path in discovery.files:
        relative_path = _relative(path, root)
        relative_parts = Path(relative_path).parts

        if Category.JUNK_DIR.value in config.checks:
            for index, part in enumerate(relative_parts[:-1]):
                if part in JUNK_DIRECTORY_NAMES:
                    junk_directories.add(Path(*relative_parts[: index + 1]).as_posix())

        try:
            stat = path.lstat()
        except OSError as exc:
            report.findings.append(
                Finding(
                    category=Category.SCAN_ERROR,
                    rule_id="file-stat-error",
                    message=f"Could not inspect file: {exc}",
                    path=relative_path,
                    severity=Severity.HIGH,
                )
            )
            continue

        if Category.SUSPICIOUS_FILE.value in config.checks and _suspicious_file(path):
            report.findings.append(
                Finding(
                    category=Category.SUSPICIOUS_FILE,
                    rule_id="suspicious-filename",
                    message="Sensitive-looking file is included in this scan",
                    path=relative_path,
                    severity=Severity.MEDIUM,
                )
            )

        if Category.HEAVY_FILE.value in config.checks and stat.st_size > max_size_bytes:
            report.findings.append(
                Finding(
                    category=Category.HEAVY_FILE,
                    rule_id="heavy-file",
                    message=f"File exceeds {config.max_size_mb:g} MB",
                    path=relative_path,
                    severity=Severity.LOW,
                    size_bytes=stat.st_size,
                )
            )

        if Category.SECRET.value in config.checks:
            content_candidates.append(path)

    for directory in sorted(junk_directories):
        report.findings.append(
            Finding(
                category=Category.JUNK_DIR,
                rule_id="generated-directory",
                message="Generated or dependency directory is not ignored by Git",
                path=directory,
                severity=Severity.LOW,
            )
        )

    if content_candidates:
        with ThreadPoolExecutor(max_workers=config.workers) as executor:
            for result in executor.map(
                lambda candidate: _scan_file_contents(candidate, root, allow_patterns),
                content_candidates,
            ):
                report.findings.extend(result.findings)
                stats.bytes_scanned += result.bytes_scanned
                stats.files_scanned += int(result.scanned)
                stats.binary_files_skipped += int(result.binary_skipped)
                stats.symlinks_skipped += int(result.symlink_skipped)

    # Multiple detectors may report the same location. Keep one stable result.
    deduplicated: dict[tuple[object, ...], Finding] = {}
    for finding in report.findings:
        key = (
            finding.category,
            finding.rule_id,
            finding.path,
            finding.line,
            finding.column,
            finding.fingerprint,
        )
        deduplicated[key] = finding
    report.findings = list(deduplicated.values())
    stats.duration_ms = round((time.monotonic() - started) * 1000)
    return report
