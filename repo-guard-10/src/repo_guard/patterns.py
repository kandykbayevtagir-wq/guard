from __future__ import annotations

from dataclasses import dataclass
import re

from .models import Severity


@dataclass(frozen=True, slots=True)
class SecretRule:
    rule_id: str
    name: str
    pattern: re.Pattern[str]
    severity: Severity = Severity.HIGH
    secret_group: str | int = 0


SECRET_RULES: tuple[SecretRule, ...] = (
    SecretRule(
        "aws-access-key",
        "AWS access key",
        re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"),
    ),
    SecretRule(
        "github-token",
        "GitHub token",
        re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{60,255})\b"),
    ),
    SecretRule(
        "slack-token",
        "Slack token",
        re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"),
    ),
    SecretRule(
        "slack-webhook",
        "Slack incoming webhook",
        re.compile(
            r"https://hooks\.slack\.com/services/"
            r"[A-Za-z0-9]+/[A-Za-z0-9]+/[A-Za-z0-9]+"
        ),
    ),
    SecretRule(
        "stripe-live-key",
        "Stripe live secret key",
        re.compile(r"\b(?:sk|rk)_live_[A-Za-z0-9]{16,}\b"),
    ),
    SecretRule(
        "google-api-key",
        "Google API key",
        re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"),
    ),
    SecretRule(
        "private-key",
        "Private key",
        re.compile(
            r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----"
        ),
    ),
    SecretRule(
        "generic-secret-assignment",
        "Hard-coded credential assignment",
        re.compile(
            r"(?ix)"
            r"\b(?:api[_-]?key|secret(?:[_-]?key)?|password|passwd|pwd|"
            r"auth[_-]?token|access[_-]?token|client[_-]?secret)\b"
            r"\s*[:=]\s*"
            r"(?P<quote>['\"]?)"
            r"(?P<secret>[A-Za-z0-9_./+=:@-]{12,})"
            r"(?P=quote)"
        ),
        severity=Severity.MEDIUM,
        secret_group="secret",
    ),
)


PLACEHOLDER_PATTERN = re.compile(
    r"(?ix)^(?:"
    r"example|sample|dummy|placeholder|changeme|change-me|replace-me|"
    r"your[_-]?(?:api[_-]?key|secret|password|token)|"
    r"not[_-]?a[_-]?real[_-]?(?:key|secret|token|password)|"
    r"test(?:ing)?[_-]?(?:key|secret|password|token)?|"
    r"x{8,}|\*{8,}"
    r")$"
)

SUPPRESSION_PATTERN = re.compile(r"repo-guard\s*:\s*allow", re.IGNORECASE)


def is_placeholder(value: str) -> bool:
    return bool(PLACEHOLDER_PATTERN.fullmatch(value.strip()))
