"""Cumulative risk scoring.

Combines rule matches, AI-classifier confidence, obfuscation flags, and
conversation/behavioral context into a single score in [0,1] mapped to a
RiskLevel. Thresholds are configurable (passed in from FirewallConfig).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from firewall_core.rules import RuleMatch


class RiskLevel(str, Enum):
    safe = "safe"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


# Default thresholds: score >= value -> at least this level.
DEFAULT_THRESHOLDS: dict[RiskLevel, float] = {
    RiskLevel.low: 0.20,
    RiskLevel.medium: 0.45,
    RiskLevel.high: 0.70,
    RiskLevel.critical: 0.90,
}


@dataclass
class RiskScore:
    score: float
    level: RiskLevel
    contributors: list[str] = field(default_factory=list)

    def as_dict(self) -> dict:
        return {
            "score": round(self.score, 4),
            "level": self.level.value,
            "contributors": self.contributors,
        }


def _combine_or(weights: list[float]) -> float:
    """Probabilistic OR: 1 - Π(1 - w). Any strong signal dominates; weak
    signals still accumulate. Bounded in [0,1] by construction."""
    product = 1.0
    for w in weights:
        product *= (1.0 - max(0.0, min(1.0, w)))
    return 1.0 - product


def level_for(score: float, thresholds: dict[RiskLevel, float] | None = None) -> RiskLevel:
    t = thresholds or DEFAULT_THRESHOLDS
    if score >= t[RiskLevel.critical]:
        return RiskLevel.critical
    if score >= t[RiskLevel.high]:
        return RiskLevel.high
    if score >= t[RiskLevel.medium]:
        return RiskLevel.medium
    if score >= t[RiskLevel.low]:
        return RiskLevel.low
    return RiskLevel.safe


def score_request(
    *,
    rule_matches: list[RuleMatch],
    ai_confidence: float = 0.0,
    obfuscation_flags: list[str] | None = None,
    repeat_offense_factor: float = 0.0,
    context_factor: float = 0.0,
    thresholds: dict[RiskLevel, float] | None = None,
) -> RiskScore:
    """Compute a cumulative risk score.

    - rule_matches: weighted by severity.
    - ai_confidence: [0,1] from the secondary classifier.
    - obfuscation_flags: encoding/invisible-char signals add a modest bump.
    - repeat_offense_factor / context_factor: [0,1] behavioral escalation.
    """
    obfuscation_flags = obfuscation_flags or []
    weights: list[float] = [m.weight for m in rule_matches]
    contributors: list[str] = [f"rule:{m.rule_id}({m.severity})" for m in rule_matches]

    if ai_confidence > 0:
        weights.append(ai_confidence)
        contributors.append(f"ai-classifier:{round(ai_confidence, 3)}")

    if obfuscation_flags:
        # Obfuscation alone isn't malicious, but it's suspicious. Cap its
        # standalone contribution so encoded benign text doesn't over-score.
        obf = min(0.15 + 0.05 * len(obfuscation_flags), 0.4)
        weights.append(obf)
        contributors.append("obfuscation:" + ",".join(obfuscation_flags))

    if repeat_offense_factor > 0:
        weights.append(min(repeat_offense_factor, 0.5))
        contributors.append(f"repeat-offense:{round(repeat_offense_factor, 3)}")

    if context_factor > 0:
        weights.append(min(context_factor, 0.6))
        contributors.append(f"conversation-context:{round(context_factor, 3)}")

    score = _combine_or(weights)
    return RiskScore(score=score, level=level_for(score, thresholds), contributors=contributors)
