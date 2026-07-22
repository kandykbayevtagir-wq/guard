from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any

from .models import Category, Finding, ScanReport, Severity


SEVERITY_TO_SARIF = {
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
}


def _human_size(size_bytes: int) -> str:
    size = float(size_bytes)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024 or unit == "TB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024
    return f"{size_bytes} B"


def _location(finding: Finding) -> str:
    location = finding.path
    if finding.line is not None:
        location += f":{finding.line}"
        if finding.column is not None:
            location += f":{finding.column}"
    return location


def render_text(report: ScanReport, *, color: bool = False) -> str:
    use_color = color and not os.environ.get("NO_COLOR")

    def paint(value: str, code: str) -> str:
        return f"\033[{code}m{value}\033[0m" if use_color else value

    severity_style = {
        Severity.HIGH: "31;1",
        Severity.MEDIUM: "33;1",
        Severity.LOW: "36",
    }

    lines = [
        f"repo-guard {report.version}",
        f"Root: {report.root}",
        f"Discovery: {report.stats.discovery_source}",
        "",
    ]

    findings = report.sorted_findings()
    if not findings:
        lines.append(paint("No findings.", "32;1"))
    else:
        for finding in findings:
            level = finding.severity.value.upper()
            prefix = paint(f"[{level}]", severity_style[finding.severity])
            lines.append(
                f"{prefix} {finding.category.value}/{finding.rule_id} "
                f"{_location(finding)}"
            )
            details = finding.message
            if finding.masked_value:
                details += f" ({finding.masked_value})"
            if finding.size_bytes is not None:
                details += f" ({_human_size(finding.size_bytes)})"
            lines.append(f"  {details}")

    counts = report.counts()
    nonzero_counts = [f"{name}={count}" for name, count in counts.items() if count]
    summary = ", ".join(nonzero_counts) if nonzero_counts else "clean"
    lines.extend(
        [
            "",
            f"Summary: {summary}",
            (
                "Scanned "
                f"{report.stats.files_scanned}/{report.stats.files_considered} files "
                f"({_human_size(report.stats.bytes_scanned)}) in "
                f"{report.stats.duration_ms} ms"
            ),
        ]
    )
    if report.stats.binary_files_skipped:
        lines.append(f"Binary files skipped: {report.stats.binary_files_skipped}")
    if report.stats.symlinks_skipped:
        lines.append(f"Symlinks skipped: {report.stats.symlinks_skipped}")
    return "\n".join(lines) + "\n"


def render_json(report: ScanReport) -> str:
    return json.dumps(report.to_dict(), indent=2, sort_keys=False) + "\n"


def _sarif_rule(finding: Finding) -> dict[str, Any]:
    return {
        "id": finding.rule_id,
        "name": finding.rule_id.replace("-", "_").title(),
        "shortDescription": {"text": finding.message},
        "defaultConfiguration": {"level": SEVERITY_TO_SARIF[finding.severity]},
        "properties": {
            "category": finding.category.value,
            "tags": ["security" if finding.category == Category.SECRET else "maintainability"],
        },
    }


def render_sarif(report: ScanReport) -> str:
    findings = report.sorted_findings()
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []

    for finding in findings:
        rules.setdefault(finding.rule_id, _sarif_rule(finding))
        region: dict[str, int] = {}
        if finding.line is not None:
            region["startLine"] = finding.line
        if finding.column is not None:
            region["startColumn"] = finding.column

        location: dict[str, Any] = {
            "physicalLocation": {
                "artifactLocation": {"uri": Path(finding.path).as_posix()},
            }
        }
        if region:
            location["physicalLocation"]["region"] = region

        result: dict[str, Any] = {
            "ruleId": finding.rule_id,
            "level": SEVERITY_TO_SARIF[finding.severity],
            "message": {"text": finding.message},
            "locations": [location],
            "properties": {"category": finding.category.value},
        }
        if finding.fingerprint:
            result["partialFingerprints"] = {
                "repoGuardSecretFingerprint/v1": finding.fingerprint
            }
        results.append(result)

    document = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "repo-guard",
                        "version": report.version,
                        "informationUri": "https://github.com/kandykbayevtagir-wq/repo-guard",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }
    return json.dumps(document, indent=2) + "\n"
