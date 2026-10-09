"""firewall_core — framework-independent LLM prompt-injection detection engine.

This package contains no Django imports so it can be unit-tested in isolation
and reused outside the web app. Django models/views adapt to these primitives.
"""

from firewall_core.engine import FirewallEngine, InspectionResult
from firewall_core.rules import Rule, RuleEngine, RuleMatch, default_rules
from firewall_core.scoring import RiskLevel, RiskScore, score_request

__all__ = [
    "FirewallEngine",
    "InspectionResult",
    "Rule",
    "RuleEngine",
    "RuleMatch",
    "default_rules",
    "RiskLevel",
    "RiskScore",
    "score_request",
]

__version__ = "1.0.0"
