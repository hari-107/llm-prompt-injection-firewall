from __future__ import annotations

import math
import re

from app.detectors.base import Detector, Signal

# Tier 1 in a production system is a small fine-tuned model (DeBERTa-class or a
# distilled LLM) trained on injection-vs-benign data. That model IS the moat.
# This MVP ships a lightweight lexical baseline with the same interface so the
# engine, proxy, and tests all work end to end — swap `HeuristicClassifier` for
# a real model-backed detector without touching anything downstream.

_ATTACK_TERMS = {
    "ignore": 1.2, "disregard": 1.1, "override": 1.0, "bypass": 1.1,
    "jailbreak": 1.6, "instructions": 0.7, "system": 0.5, "prompt": 0.6,
    "reveal": 0.9, "pretend": 0.9, "roleplay": 1.0, "unrestricted": 1.2,
    "forget": 0.9, "confidential": 0.7, "exfiltrate": 1.5, "leak": 1.0,
}
_BENIGN_TERMS = {
    "please": -0.4, "thanks": -0.4, "recipe": -0.6, "weather": -0.6,
    "translate": -0.3, "summarize": -0.3, "explain": -0.3, "help": -0.2,
}
_BIAS = -1.4  # tuned so ordinary requests land well below threshold

_TOKEN = re.compile(r"[a-z']+")


class HeuristicClassifier(Detector):
    """Tier 1 baseline: logistic score over weighted lexical features.

    Interface-compatible with a future model-backed classifier.
    """

    name = "classifier"

    def inspect(self, text: str) -> Signal:
        tokens = _TOKEN.findall(text.lower())
        if not tokens:
            return Signal(detector=self.name, score=0.0)

        logit = _BIAS
        hits: list[str] = []
        for tok in tokens:
            if tok in _ATTACK_TERMS:
                logit += _ATTACK_TERMS[tok]
                hits.append(tok)
            elif tok in _BENIGN_TERMS:
                logit += _BENIGN_TERMS[tok]

        score = 1.0 / (1.0 + math.exp(-logit))
        reasons = [f"lexical:{'+'.join(sorted(set(hits))[:5])}"] if hits else []
        return Signal(detector=self.name, score=score, reasons=reasons)
