"""Seed the Rule table from firewall_core.default_rules().

Idempotent: safely updates known older built-in patterns while preserving
operator edits. --force replaces all built-in definitions.
"""

from __future__ import annotations

from django.core.management.base import BaseCommand

from apps.firewall.models import FirewallConfig, Rule
from firewall_core.rules import default_rules


# Previous shipped patterns. A row is upgraded only when its pattern still
# equals the shipped value, so an operator's custom regex is never replaced.
_PREVIOUS_PATTERNS = {
    "jailbreak-dan": (r"\b(DAN|do\s+anything\s+now)\b", "high"),
    "jailbreak-sudo": (r"\bsudo\s+mode\b|enable\s+sudo", "high"),
    "jailbreak-developer-mode": (r"developer\s+mode|dev\s+mode\s+enabled", "high"),
    "jailbreak-no-restrictions": (r"without\s+(any\s+)?(restrictions|filters|rules|limitations|safety|guidelines)", "medium"),
    "role-you-are-now": (r"you\s+are\s+now\s+(a|an|the|in)\s+", "medium"),
    "role-act-as": (r"act\s+as\s+(if\s+you\s+(are|were)|an?\b)", "low"),
    "role-pretend": (r"pretend\s+(to\s+be|you\s+are|that\s+you)", "low"),
    "extract-system-prompt": (r"(reveal|show|print|repeat|display|output|expose|leak)\s+(me\s+)?(your|the)\s+(system\s+|hidden\s+|initial\s+)?(prompt|instructions|rules|guidelines)", "critical"),
    "extract-what-are-instructions": (r"what\s+(is|are)\s+your\s+(system\s+prompt|initial\s+instructions|hidden\s+(prompt|instructions))", "high"),
    "injection-json-role": (r"[\"']role[\"']\s*:\s*[\"']system[\"']", "medium"),
    "injection-tool-abuse": (r"(call|invoke|use|execute)\s+(the\s+)?(tool|function|api)\s+.{0,40}(delete|drop|exfiltrate|send|email|transfer)", "high"),
    "injection-sql-tool": (r"(drop\s+table|delete\s+from|union\s+select|';\s*--)", "medium"),
    "indirect-exfil-destination": (r"(send|email|forward|post|upload)\s+.{0,40}(to\s+)?[\w.+-]+@[\w-]+\.\w+", "medium"),
    "context-poison-remember": (r"(from\s+now\s+on|going\s+forward|for\s+all\s+future),?\s+(always|never|you\s+(will|must))", "low"),
}


class Command(BaseCommand):
    help = "Seed built-in firewall rules into the database."

    def add_arguments(self, parser):
        parser.add_argument("--force", action="store_true",
                            help="Overwrite existing rows' pattern/severity/etc.")

    def handle(self, *args, **opts):
        force = opts["force"]
        created = updated = 0
        for cr in default_rules():
            row, was_created = Rule.objects.get_or_create(
                rule_id=cr.id,
                defaults=dict(
                    pattern=cr.pattern, severity=cr.severity, category=cr.category,
                    description=cr.description, mitigation=cr.mitigation,
                    atlas=cr.atlas, enabled=cr.enabled, builtin=True,
                ),
            )
            if was_created:
                created += 1
            elif force:
                row.pattern = cr.pattern
                row.severity = cr.severity
                row.category = cr.category
                row.description = cr.description
                row.mitigation = cr.mitigation
                row.atlas = cr.atlas
                row.builtin = True
                row.save()
                updated += 1
            elif row.builtin and (previous := _PREVIOUS_PATTERNS.get(cr.id)) and row.pattern == previous[0]:
                row.pattern = cr.pattern
                fields = ["pattern"]
                if row.severity == previous[1]:
                    row.severity = cr.severity
                    fields.append("severity")
                row.save(update_fields=fields)
                updated += 1

        FirewallConfig.load()  # ensure the singleton config row exists
        self.stdout.write(self.style.SUCCESS(
            f"Seeded rules: {created} created, {updated} updated, "
            f"{Rule.objects.count()} total."
        ))
