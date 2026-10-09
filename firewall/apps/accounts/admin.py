from __future__ import annotations

from django.contrib import admin

from apps.accounts.models import APIKey, Profile


@admin.register(Profile)
class ProfileAdmin(admin.ModelAdmin):
    list_display = ("user", "role")
    list_filter = ("role",)
    search_fields = ("user__username", "user__email")


@admin.register(APIKey)
class APIKeyAdmin(admin.ModelAdmin):
    list_display = ("name", "user", "prefix", "active", "created_at", "last_used_at")
    list_filter = ("active",)
    search_fields = ("name", "prefix", "user__username")
    readonly_fields = ("prefix", "key_hash", "created_at", "last_used_at")
