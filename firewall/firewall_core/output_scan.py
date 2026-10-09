"""Output firewall: scan LLM responses for secret/PII leaks and prompt
disclosure, and mask sensitive values while preserving readability.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

# (label, severity_weight, regex, mask_style)
# mask_style: "full" -> fully redact, "partial" -> keep a hint (last 4 / domain).
_SECRET_PATTERNS = [
    ("openai-key", 0.95, re.compile(r"sk-(?!proj-)[A-Za-z0-9_-]{8,}"), "full"),
    ("openai-proj-key", 0.95, re.compile(r"sk-proj-[A-Za-z0-9_-]{20,}"), "full"),
    ("aws-access-key", 0.95, re.compile(r"AKIA[0-9A-Z]{16}"), "full"),
    ("aws-secret", 0.9, re.compile(r"aws_secret_access_key\s*=\s*[A-Za-z0-9/+=]{30,}", re.I), "full"),
    ("github-token", 0.95, re.compile(r"gh[pousr]_[A-Za-z0-9]{36,}"), "full"),
    ("google-api-key", 0.9, re.compile(r"AIza[0-9A-Za-z_-]{35}"), "full"),
    ("azure-key", 0.85, re.compile(r"(?i)azure[_-]?(?:api)?[_-]?key\s*[:=]\s*[A-Za-z0-9/+=]{20,}"), "full"),
    ("slack-token", 0.9, re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}"), "full"),
    ("private-key", 0.98, re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----.*?(?:-----END (?:RSA |EC |OPENSSH |DSA |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----|\Z)", re.S), "full"),
    ("ssh-key", 0.8, re.compile(r"ssh-(?:rsa|ed25519|dss)\s+[A-Za-z0-9+/]{40,}"), "full"),
    ("jwt", 0.7, re.compile(r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"), "full"),
    ("bearer-token", 0.75, re.compile(r"(?i)bearer\s+[A-Za-z0-9._~+/=-]+"), "full"),
    ("db-conn-string", 0.85, re.compile(r"(?i)(?:postgres|postgresql|mysql|mongodb(?:\+srv)?|redis)://[^\s]+:[^\s]+@[^\s]+"), "full"),
    ("password-assignment", 0.6, re.compile(r'''(?i)["']?(?:password|passwd|pwd)["']?\s*(?:[:=]|is\b)\s*(?:"[^"\n]*"|'[^'\n]*'|[^\s,;]+)'''), "full"),
    ("credential-assignment", 0.9, re.compile(r'''(?i)["']?\b(?:[\w-]*(?:api[ _-]?key|secret|token|credential)[\w-]*|access[ _-]?token|client[ _-]?secret)["']?\s*(?:[:=]|is\b)\s*(?:"[^"\n]*"|'[^'\n]*'|[^\s,;]+)'''), "full"),
    ("credit-card", 0.7, re.compile(r"\b(?:\d[ -]?){13,16}\b"), "partial"),
    ("aadhaar", 0.7, re.compile(r"\b\d{4}\s?\d{4}\s?\d{4}\b"), "partial"),
    ("pan", 0.6, re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]\b"), "partial"),
    ("email", 0.3, re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), "partial"),
    ("phone", 0.3, re.compile(r"\b(?:\+?\d{1,3}[-.\s]?)?(?:\(?\d{3}\)?[-.\s]?)\d{3}[-.\s]?\d{4}\b"), "partial"),
    ("ipv4", 0.25, re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"), "partial"),
    ("session-cookie", 0.6, re.compile(r"(?i)(?:session|sid|csrftoken|sessionid)\s*=\s*[A-Za-z0-9%._-]{16,}"), "full"),
]

_LEAK_PATTERNS = [
    ("internal-configuration", 0.9, re.compile(r"(?i)(?:hidden\s+instructions|internal\s+(?:security\s+)?configuration)\s*(?:is|are|:)")),
    ("system-prompt-disclosure", 0.8, re.compile(r"(?i)(?:my\s+system\s+prompt\s*(?:is\b|:)|the\s+(?:hidden\s+|internal\s+)?system\s+prompt\s*:)")),
    ("instruction-disclosure", 0.7, re.compile(r"(?i)here\s+(?:are|is)\s+my\s+(?:instructions|system\s+prompt|rules)")),
    ("configured-to-disclosure", 0.45, re.compile(r"(?i)i\s+was\s+(?:instructed|told|configured|programmed)\s+to")),
    ("chain-of-thought", 0.4, re.compile(r"(?i)<thinking>|chain[-\s]of[-\s]thought|let me think step by step internally")),
]


@dataclass
class OutputFinding:
    label: str
    severity: float
    count: int


@dataclass
class OutputScanResult:
    findings: list[OutputFinding] = field(default_factory=list)
    masked_text: str = ""
    score: float = 0.0

    @property
    def has_leak(self) -> bool:
        return bool(self.findings)


def _mask(value: str, style: str) -> str:
    if style == "partial":
        if "@" in value:  # email -> keep domain
            local, _, domain = value.partition("@")
            return (local[:1] + "***@" + domain)
        digits = re.sub(r"\D", "", value)
        if len(digits) >= 4:
            return "****" + digits[-4:]
        return "****"
    return "[REDACTED]"


class OutputScanner:
    def scan(self, text: str, *, mask: bool = True) -> OutputScanResult:
        if not text:
            return OutputScanResult(masked_text=text)

        findings: list[OutputFinding] = []
        weights: list[float] = []
        out = text

        for label, sev, regex, style in _SECRET_PATTERNS:
            hits = regex.findall(out)
            if not hits:
                continue
            count = len(hits)
            findings.append(OutputFinding(label, sev, count))
            weights.append(sev)
            if mask:
                out = regex.sub(lambda m: _mask(m.group(0), style), out)

        for label, sev, regex in _LEAK_PATTERNS:
            if regex.search(out):
                findings.append(OutputFinding(label, sev, 1))
                weights.append(sev)

        product = 1.0
        for w in weights:
            product *= (1.0 - w)
        score = 1.0 - product

        return OutputScanResult(findings=findings, masked_text=out, score=score)
