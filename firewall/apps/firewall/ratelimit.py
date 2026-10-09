"""IP/user rate limiting and abuse detection backed by the cache (Redis in
prod, locmem in dev).

Two mechanisms:
- A sliding request counter per identity → 429 when over the window budget.
- An attack counter per identity → temporary block (cooldown) once an identity
  trips too many high-risk detections, deterring brute-force probing.
"""

from __future__ import annotations

from dataclasses import dataclass

from django.core.cache import cache

from config.firewall_settings import firewall_settings


@dataclass
class RateDecision:
    allowed: bool
    reason: str = ""
    retry_after: int = 0


def _rate_key(identity: str) -> str:
    return f"rl:req:{identity}"


def _attack_key(identity: str) -> str:
    return f"rl:atk:{identity}"


def _block_key(identity: str) -> str:
    return f"rl:block:{identity}"


def check_and_consume(identity: str) -> RateDecision:
    s = firewall_settings

    if cache.get(_block_key(identity)):
        return RateDecision(False, "temporarily blocked for repeated attacks", s.ratelimit_cooldown)

    key = _rate_key(identity)
    try:
        count = cache.incr(key)
    except ValueError:
        cache.set(key, 1, timeout=s.ratelimit_window)
        count = 1

    if count > s.ratelimit_requests:
        return RateDecision(False, "rate limit exceeded", s.ratelimit_window)
    return RateDecision(True)


def register_attack(identity: str) -> None:
    """Count a high-risk detection; auto-block the identity past the threshold."""
    s = firewall_settings
    key = _attack_key(identity)
    try:
        count = cache.incr(key)
    except ValueError:
        cache.set(key, 1, timeout=s.ratelimit_cooldown)
        count = 1
    if count >= s.ratelimit_block_after_attacks:
        cache.set(_block_key(identity), True, timeout=s.ratelimit_cooldown)


def is_blocked(identity: str) -> bool:
    return bool(cache.get(_block_key(identity)))


def clear(identity: str) -> None:
    cache.delete_many([_rate_key(identity), _attack_key(identity), _block_key(identity)])
