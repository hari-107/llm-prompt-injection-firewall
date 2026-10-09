"""Centralized firewall configuration read from the environment.

Keeping policy values (thresholds, rate limits, model selection) here means an
operator can retune the firewall via .env without touching source. The Django
`FirewallConfig` DB row can further override these at runtime from the dashboard.
"""

from __future__ import annotations

import os
from dataclasses import dataclass


def _f(name: str, default: float) -> float:
    try:
        return float(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


def _i(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, default))
    except (TypeError, ValueError):
        return default


def _b(name: str, default: bool) -> bool:
    val = os.environ.get(name)
    if val is None:
        return default
    return val.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class FirewallSettings:
    use_ai: bool = _b("FIREWALL_USE_AI", True)
    output_block_threshold: float = _f("FIREWALL_OUTPUT_BLOCK_THRESHOLD", 0.7)

    risk_low: float = _f("RISK_THRESHOLD_LOW", 0.20)
    risk_medium: float = _f("RISK_THRESHOLD_MEDIUM", 0.45)
    risk_high: float = _f("RISK_THRESHOLD_HIGH", 0.70)
    risk_critical: float = _f("RISK_THRESHOLD_CRITICAL", 0.90)

    ratelimit_requests: int = _i("RATELIMIT_REQUESTS", 60)
    ratelimit_window: int = _i("RATELIMIT_WINDOW_SECONDS", 60)
    ratelimit_block_after_attacks: int = _i("RATELIMIT_BLOCK_AFTER_ATTACKS", 5)
    ratelimit_cooldown: int = _i("RATELIMIT_BLOCK_COOLDOWN_SECONDS", 900)

    classifier_provider: str = os.environ.get("CLASSIFIER_PROVIDER", "").strip()
    classifier_api_key: str = os.environ.get("CLASSIFIER_API_KEY", "").strip()
    classifier_model: str = os.environ.get("CLASSIFIER_MODEL", "gpt-4o-mini").strip()
    classifier_base_url: str = os.environ.get("CLASSIFIER_BASE_URL", "").strip()

    upstream_base_url: str = os.environ.get("UPSTREAM_BASE_URL", "https://api.openai.com/v1").strip()
    upstream_api_key: str = os.environ.get("UPSTREAM_API_KEY", "").strip()

    def thresholds(self) -> dict:
        from firewall_core.scoring import RiskLevel

        return {
            RiskLevel.low: self.risk_low,
            RiskLevel.medium: self.risk_medium,
            RiskLevel.high: self.risk_high,
            RiskLevel.critical: self.risk_critical,
        }


firewall_settings = FirewallSettings()
