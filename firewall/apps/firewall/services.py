"""Django-side factory that assembles a FirewallEngine from DB state.

Rules and config live in the database (editable from the dashboard); this module
reads them, converts to the pure-Python core dataclasses, wires in the configured
classifier, and returns a ready engine. Results are cached briefly so a burst of
requests doesn't re-query and re-compile every rule each time.
"""

from __future__ import annotations

from django.core.cache import cache
from django.db.models import Q

from apps.detection.client import build_classifier
from apps.firewall.models import FirewallConfig, RuleAction
from firewall_core.engine import Action, DEFAULT_ACTION_POLICY, FirewallEngine
from firewall_core.scoring import RiskLevel

_ENGINE_CACHE_KEY = "firewall:engine:version"


def bump_engine_version() -> None:
    """Call after editing rules/config so the cached engine is rebuilt."""
    try:
        cache.incr(_ENGINE_CACHE_KEY)
    except ValueError:
        cache.set(_ENGINE_CACHE_KEY, 1)


def _load_rules(active_policy_id=None):
    from apps.firewall.models import Rule as RuleModel
    from firewall_core.rules import default_rules

    rows = list(RuleModel.objects.filter(
        Q(policy_profile__isnull=True) | Q(policy_profile_id=active_policy_id)
    ))
    rules = [r.to_core() for r in rows]
    existing_ids = {r.id for r in rules}
    # Built-in protections remain present even before seed_rules is run.
    rules.extend(r for r in default_rules() if r.id not in existing_ids)
    return rules


def active_rule_count() -> int:
    return sum(rule.enabled for rule in _load_rules(FirewallConfig.load().active_policy_id))


def _action_policy(config: FirewallConfig) -> dict[RiskLevel, Action]:
    policy = dict(DEFAULT_ACTION_POLICY)
    # The global default_mode caps the harshest automatic action: if an operator
    # sets the firewall to "warn" mode, high/critical warn instead of block.
    mode = config.default_mode
    if mode == RuleAction.ALLOW:
        return {lvl: Action.allow for lvl in policy}
    if mode == RuleAction.WARN:
        return {lvl: (Action.warn if a == Action.block else a) for lvl, a in policy.items()}
    if mode == RuleAction.SANITIZE:
        return {lvl: (Action.sanitize if a == Action.block else a) for lvl, a in policy.items()}
    return policy  # block mode = defaults


def build_engine(*, local_only: bool = False, enforce_security: bool = False) -> FirewallEngine:
    config = FirewallConfig.load()
    from firewall_core.classifier import HeuristicClassifier
    policy = _action_policy(config)
    if enforce_security:
        policy[RiskLevel.low] = Action.allow
    return FirewallEngine(
        rules=_load_rules(config.active_policy_id),
        classifier=HeuristicClassifier() if local_only else build_classifier(),
        thresholds=config.thresholds(),
        action_policy=policy,
        output_block_threshold=config.output_block_threshold,
        use_ai=config.use_ai,
        enforce_security=enforce_security,
    )


def get_engine() -> FirewallEngine:
    """Build fresh each call. Engines are cheap to construct and always reflect
    current DB state; the rule-compile cost is negligible for this scale."""
    return build_engine()
