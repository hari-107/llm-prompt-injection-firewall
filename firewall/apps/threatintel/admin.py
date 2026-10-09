from __future__ import annotations

from django.contrib import admin, messages

from apps.firewall.models import Rule
from apps.firewall.services import bump_engine_version
from apps.threatintel.models import JailbreakSample, ThreatSignature


@admin.register(ThreatSignature)
class ThreatSignatureAdmin(admin.ModelAdmin):
    list_display = ("signature_id", "kind", "category", "severity", "promoted", "source")
    list_filter = ("kind", "category", "severity", "promoted")
    search_fields = ("signature_id", "pattern", "description")
    actions = ["promote_to_rules"]

    @admin.action(description="Promote selected signatures into live firewall rules")
    def promote_to_rules(self, request, queryset):
        n = 0
        for sig in queryset:
            Rule.objects.update_or_create(
                rule_id=f"ti-{sig.signature_id}",
                defaults=dict(
                    pattern=sig.as_regex(), severity=sig.severity, category=sig.category,
                    description=sig.description or f"Imported from threat intel ({sig.source}).",
                    mitigation="Review and tune; imported from threat intelligence.",
                    atlas=sig.atlas, enabled=True, builtin=False,
                ),
            )
            sig.promoted = True
            sig.save(update_fields=["promoted"])
            n += 1
        bump_engine_version()
        self.message_user(request, f"Promoted {n} signature(s) to rules.", messages.SUCCESS)


@admin.register(JailbreakSample)
class JailbreakSampleAdmin(admin.ModelAdmin):
    list_display = ("__str__", "category", "is_attack", "source")
    list_filter = ("category", "is_attack")
    search_fields = ("text", "notes")
