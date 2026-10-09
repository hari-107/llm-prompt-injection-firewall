from __future__ import annotations

import re

from app.detectors.base import Detector, Signal

# Response-side scanning: catch leaks on the way back to the app. Two classes of
# problem — secrets/PII escaping, and signs the model obeyed a hidden injected
# instruction (e.g. it starts dumping its system prompt).
_SECRET_PATTERNS: list[tuple[str, float, str]] = [
    (r"sk-[A-Za-z0-9]{20,}", 0.9, "openai-key"),
    (r"AKIA[0-9A-Z]{16}", 0.9, "aws-access-key"),
    (r"ghp_[A-Za-z0-9]{36}", 0.9, "github-token"),
    (r"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----", 0.95, "private-key"),
    (r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", 0.6, "jwt"),
    (r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", 0.25, "email"),
    (r"\b(?:\d[ -]?){13,16}\b", 0.4, "possible-card-number"),
]
_LEAK_PATTERNS: list[tuple[str, float, str]] = [
    (r"my\s+system\s+prompt\s+(is|:)", 0.7, "system-prompt-disclosure"),
    (r"here\s+(are|is)\s+my\s+(instructions|system\s+prompt)", 0.7, "system-prompt-disclosure"),
    (r"i\s+was\s+(instructed|told|configured)\s+to", 0.4, "instruction-disclosure"),
]


class OutputScanner(Detector):
    """Scans LLM responses for secret/PII leaks and prompt disclosure."""

    name = "output_scan"

    def __init__(self) -> None:
        self._secrets = [(re.compile(p), w, l) for p, w, l in _SECRET_PATTERNS]
        self._leaks = [(re.compile(p, re.IGNORECASE), w, l) for p, w, l in _LEAK_PATTERNS]

    def inspect(self, text: str) -> Signal:
        score = 0.0
        reasons: list[str] = []
        seen: set[str] = set()
        for regex, weight, label in self._secrets + self._leaks:
            if regex.search(text) and label not in seen:
                score += weight
                reasons.append(label)
                seen.add(label)
        return Signal(detector=self.name, score=min(score, 1.0), reasons=reasons)
