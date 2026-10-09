from __future__ import annotations

import re

from app.detectors.base import Detector, Signal

# Phrases that repeatedly show up in direct prompt-injection and jailbreak
# attempts. Each pattern carries a weight; weights accumulate (capped at 1.0).
# These are intentionally conservative to keep false positives low — the
# classifier tier is where fuzzier matching belongs.
_PATTERNS: list[tuple[str, float, str]] = [
    (r"ignore\s+(all\s+|any\s+)?(previous|prior|above|earlier)\s+instructions", 0.6, "override-instructions"),
    (r"disregard\s+(all\s+|the\s+)?(previous|prior|above)\s+", 0.5, "disregard-instructions"),
    (r"forget\s+(everything|all|your)\s+(you|instructions|rules)", 0.45, "forget-instructions"),
    (r"you\s+are\s+now\s+(a|an|in)\s+", 0.35, "role-reassignment"),
    (r"act\s+as\s+(if\s+you|a|an)\b", 0.3, "role-play"),
    (r"pretend\s+(to\s+be|you\s+are)", 0.3, "role-play"),
    (r"developer\s+mode", 0.4, "jailbreak-persona"),
    (r"\bDAN\b", 0.35, "jailbreak-persona"),
    (r"do\s+anything\s+now", 0.4, "jailbreak-persona"),
    (r"(reveal|show|print|repeat|output)\s+(your|the)\s+(system\s+)?prompt", 0.6, "prompt-extraction"),
    (r"(reveal|show|print|leak)\s+(your|the)\s+(instructions|rules|guidelines)", 0.55, "prompt-extraction"),
    (r"what\s+(is|are)\s+your\s+(system\s+prompt|initial\s+instructions)", 0.5, "prompt-extraction"),
    (r"without\s+(any\s+)?(restrictions|filters|rules|limitations)", 0.4, "constraint-removal"),
    (r"bypass\s+(your|the|all)\s+(safety|content|security)", 0.5, "constraint-removal"),
    (r"</?(system|assistant|user)>", 0.45, "delimiter-injection"),
    (r"\[/?INST\]", 0.45, "delimiter-injection"),
    (r"###\s*(system|instruction|new\s+instruction)", 0.35, "delimiter-injection"),
    # Indirect-injection markers commonly embedded in fetched content.
    (r"when\s+you\s+(read|see|process)\s+this[,\s].{0,40}(send|email|post|forward)", 0.55, "indirect-exfil"),
    (r"(send|email|forward|post)\s+.{0,30}(to\s+)?[\w.+-]+@[\w-]+\.\w+", 0.4, "exfil-destination"),
]


class HeuristicDetector(Detector):
    """Tier 0: fast regex/keyword matching against known attack signatures."""

    name = "heuristics"

    def __init__(self) -> None:
        self._compiled = [
            (re.compile(pat, re.IGNORECASE | re.DOTALL), weight, label)
            for pat, weight, label in _PATTERNS
        ]

    def inspect(self, text: str) -> Signal:
        score = 0.0
        reasons: list[str] = []
        seen: set[str] = set()
        for regex, weight, label in self._compiled:
            if regex.search(text):
                score += weight
                if label not in seen:
                    reasons.append(label)
                    seen.add(label)
        return Signal(detector=self.name, score=min(score, 1.0), reasons=reasons)
