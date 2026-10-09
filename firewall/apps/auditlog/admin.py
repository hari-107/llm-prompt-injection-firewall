from __future__ import annotations

from django.contrib import admin

from apps.auditlog.models import RequestLog


@admin.register(RequestLog)
class RequestLogAdmin(admin.ModelAdmin):
    list_display = (
        "created_at", "request_id", "direction", "risk_level",
        "action", "ai_confidence", "ip_address", "model_used",
    )
    list_filter = ("action", "risk_level", "direction", "marked_false_positive", "marked_false_negative")
    search_fields = ("request_id", "prompt_hash", "ip_address")
    readonly_fields = [f.name for f in RequestLog._meta.fields if f.name not in
                       {"marked_false_positive", "marked_false_negative"}]
    date_hierarchy = "created_at"

    def has_add_permission(self, request) -> bool:
        return False  # logs are only created by the firewall pipeline
