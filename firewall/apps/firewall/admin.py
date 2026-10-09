from __future__ import annotations

from django.contrib import admin

from apps.firewall.models import FirewallConfig, PolicyDraft, PolicyProfile, Rule
from apps.firewall.services import bump_engine_version


@admin.register(Rule)
class RuleAdmin(admin.ModelAdmin):
    list_display = ("rule_id", "policy_profile", "severity", "category", "action", "enabled", "builtin")
    list_filter = ("severity", "category", "enabled", "builtin")
    search_fields = ("rule_id", "pattern", "description")
    list_editable = ("enabled",)

    def save_model(self, request, obj, form, change):
        super().save_model(request, obj, form, change)
        bump_engine_version()


@admin.register(PolicyProfile)
class PolicyProfileAdmin(admin.ModelAdmin):
    list_display = ("name", "slug", "source_filename", "updated_at")
    search_fields = ("name", "slug")


@admin.register(PolicyDraft)
class PolicyDraftAdmin(admin.ModelAdmin):
    list_display = ("provider_name", "source_filename", "model_used", "created_by", "activated_at")
    readonly_fields = ("provider_name", "provider_slug", "source_filename", "source_sha256",
                       "model_used", "candidates", "rejected", "created_by", "activated_by",
                       "created_at", "activated_at")

    def has_add_permission(self, request):
        return False


@admin.register(FirewallConfig)
class FirewallConfigAdmin(admin.ModelAdmin):
    list_display = ("__str__", "default_mode", "use_ai", "output_block_threshold", "updated_at")

    def has_add_permission(self, request) -> bool:
        return not FirewallConfig.objects.exists()

    def has_delete_permission(self, request, obj=None) -> bool:
        return False

    def save_model(self, request, obj, form, change):
        super().save_model(request, obj, form, change)
        bump_engine_version()
