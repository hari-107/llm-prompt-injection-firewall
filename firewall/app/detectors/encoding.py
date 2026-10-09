from __future__ import annotations

import base64
import re

from app.detectors.base import Detector, Signal

# Zero-width and other invisible characters used to smuggle instructions past
# human review while still being tokenized by the model.
_INVISIBLE = re.compile(r"[​‌‍⁠﻿­]")
# Long base64-looking runs that may hide an encoded instruction payload.
_B64_RUN = re.compile(r"[A-Za-z0-9+/]{24,}={0,2}")
# Excessive backslash-escaped unicode, a common obfuscation.
_UNICODE_ESCAPE = re.compile(r"(\\u[0-9a-fA-F]{4}){4,}")

_INJECTION_HINT = re.compile(
    r"ignore|system\s+prompt|instruction|bypass|reveal", re.IGNORECASE
)


class EncodingDetector(Detector):
    """Tier 0: flags obfuscation — invisible chars, base64, unicode escapes.

    Decodes base64 runs and re-checks for injection keywords, catching payloads
    that hide behind an encoding layer.
    """

    name = "encoding"

    def inspect(self, text: str) -> Signal:
        score = 0.0
        reasons: list[str] = []

        invisible = _INVISIBLE.findall(text)
        if invisible:
            score += min(0.2 + 0.05 * len(invisible), 0.5)
            reasons.append(f"invisible-chars({len(invisible)})")

        if _UNICODE_ESCAPE.search(text):
            score += 0.3
            reasons.append("unicode-escape-obfuscation")

        for run in _B64_RUN.findall(text):
            decoded = self._try_decode(run)
            if decoded and _INJECTION_HINT.search(decoded):
                score += 0.6
                reasons.append("base64-hidden-injection")
                break
            if decoded and self._printable_ratio(decoded) > 0.85:
                score += 0.2
                reasons.append("base64-hidden-text")
                break

        return Signal(detector=self.name, score=min(score, 1.0), reasons=reasons)

    @staticmethod
    def _try_decode(run: str) -> str | None:
        try:
            raw = base64.b64decode(run + "=" * (-len(run) % 4), validate=False)
            return raw.decode("utf-8", errors="replace")
        except Exception:
            return None

    @staticmethod
    def _printable_ratio(s: str) -> float:
        if not s:
            return 0.0
        printable = sum(1 for c in s if c.isprintable() or c.isspace())
        return printable / len(s)
