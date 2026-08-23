from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    message: str
    evidence: str


_RULES: tuple[tuple[str, str, str, re.Pattern[str]], ...] = (
    (
        "SHELL-001",
        "critical",
        "Pipes downloaded content directly into a shell interpreter.",
        re.compile(r"(?:curl|wget)\b[^\n|]*\|\s*(?:bash|sh|zsh|fish)\b", re.I),
    ),
    (
        "SHELL-002",
        "high",
        "Uses recursive force deletion, which can destroy files outside the intended workspace.",
        re.compile(r"\brm\s+-[A-Za-z]*r[A-Za-z]*f\b", re.I),
    ),
    (
        "SHELL-003",
        "high",
        "Requests unrestricted filesystem permissions.",
        re.compile(r"\bchmod\s+(?:-R\s+)?777\b", re.I),
    ),
    (
        "PRIV-001",
        "high",
        "Requests privileged execution through sudo or a root shell.",
        re.compile(r"\b(?:sudo|su\s+-|doas)\b", re.I),
    ),
    (
        "SECRETS-001",
        "high",
        "Reads common credential material from the environment or credential stores.",
        re.compile(r"(?:AWS_SECRET_ACCESS_KEY|AWS_ACCESS_KEY_ID|GITHUB_TOKEN|OPENAI_API_KEY|ANTHROPIC_API_KEY|\.aws/credentials|\.git-credentials)", re.I),
    ),
    (
        "EXFIL-001",
        "high",
        "Combines credential/environment access with outbound network tooling.",
        re.compile(r"(?:env|printenv|cat|grep)\b[^\n]*(?:TOKEN|KEY|SECRET|PASSWORD)[^\n]*(?:curl|wget|nc|netcat)\b", re.I),
    ),
    (
        "ENC-001",
        "medium",
        "Uses base64 decoding, which can hide executable or downloaded payloads.",
        re.compile(r"\b(?:base64\s+-d|openssl\s+enc\s+-d)\b", re.I),
    ),
    (
        "NET-001",
        "medium",
        "Uses a raw network client that deserves explicit review in an agent skill.",
        re.compile(r"\b(?:curl|wget|nc|netcat)\b", re.I),
    ),
)


def scan_skill(instructions: str) -> list[Finding]:
    """Return deterministic findings for suspicious executable instructions.

    This is a policy guard, not a malware detector. Findings should be reviewed
    by a trusted operator before a skill is granted execution capability.
    """
    findings: list[Finding] = []
    for rule_id, severity, message, pattern in _RULES:
        match = pattern.search(instructions)
        if match:
            evidence = match.group(0).strip()[:160]
            findings.append(Finding(rule_id, severity, message, evidence))
    return findings
