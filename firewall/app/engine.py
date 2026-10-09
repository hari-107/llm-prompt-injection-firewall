from __future__ import annotations

from dataclasses import asdict, dataclass, field

from app.detectors import (
    EncodingDetector,
    HeuristicClassifier,
    HeuristicDetector,
    OutputScanner,
)
from app.detectors.base import Signal


@dataclass
class Verdict:
    score: float
    malicious: bool
    signals: list[Signal] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "score": round(self.score, 4),
            "malicious": self.malicious,
            "signals": [asdict(s) for s in self.signals],
        }


class Engine:
    """Orchestrates the tiered inspection pipeline.

    Request path: Tier 0 (heuristics + encoding) runs first; if it already
    clears the block threshold we can short-circuit. Tier 1 (classifier) always
    contributes so borderline cases get a smoother score. The combined score is
    a saturating OR — any strong detector can raise the alarm on its own.
    """

    def __init__(self, block_threshold: float = 0.7) -> None:
        self.block_threshold = block_threshold
        self._tier0 = [HeuristicDetector(), EncodingDetector()]
        self._tier1 = HeuristicClassifier()
        self._output = OutputScanner()

    @staticmethod
    def _combine(signals: list[Signal]) -> float:
        # Probabilistic OR: 1 - Π(1 - s). One confident detector suffices,
        # and multiple weak signals still accumulate.
        product = 1.0
        for s in signals:
            product *= (1.0 - s.score)
        return 1.0 - product

    def inspect_request(self, text: str) -> Verdict:
        signals = [d.inspect(text) for d in self._tier0]
        combined = self._combine(signals)
        # Escalate to Tier 1 unless Tier 0 already decided with high confidence.
        if combined < 0.95:
            signals.append(self._tier1.inspect(text))
            combined = self._combine(signals)
        active = [s for s in signals if s.score > 0]
        return Verdict(
            score=combined,
            malicious=combined >= self.block_threshold,
            signals=active,
        )

    def inspect_response(self, text: str) -> Verdict:
        signal = self._output.inspect(text)
        return Verdict(
            score=signal.score,
            malicious=signal.score >= self.block_threshold,
            signals=[signal] if signal.score > 0 else [],
        )
