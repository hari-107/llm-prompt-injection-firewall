from __future__ import annotations

import pytest
from django.core.management import call_command

from apps.firewall.management.commands.seed_rules import _PREVIOUS_PATTERNS
from apps.firewall.models import Rule
from firewall_core.rules import default_rules


@pytest.mark.django_db
def test_seed_upgrades_unchanged_builtins_without_erasing_operator_edits():
    previous_pattern, previous_severity = _PREVIOUS_PATTERNS["jailbreak-developer-mode"]
    revised = next(r for r in default_rules() if r.id == "jailbreak-developer-mode")
    Rule.objects.create(
        rule_id=revised.id, pattern=previous_pattern,
        severity=previous_severity, category=revised.category,
        enabled=False, action="warn", builtin=True,
    )
    custom_id = "role-you-are-now"
    Rule.objects.create(
        rule_id=custom_id, pattern=r"operator-customized-pattern",
        severity="low", category="role-override", builtin=True,
    )

    call_command("seed_rules")

    upgraded = Rule.objects.get(rule_id=revised.id)
    assert upgraded.pattern == revised.pattern
    assert upgraded.severity == revised.severity
    assert upgraded.enabled is False
    assert upgraded.action == "warn"
    custom = Rule.objects.get(rule_id=custom_id)
    assert custom.pattern == r"operator-customized-pattern"
    assert custom.severity == "low"
