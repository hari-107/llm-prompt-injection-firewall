from __future__ import annotations

import hashlib
import secrets

from django.contrib.auth.models import User
from django.db import models


class Role(models.TextChoices):
    ADMIN = "admin", "Administrator"
    ANALYST = "analyst", "Analyst"
    AUDITOR = "auditor", "Auditor"
    READONLY = "readonly", "Read-only"


class Profile(models.Model):
    """Role-based access control layered on Django's User."""

    user = models.OneToOneField(User, on_delete=models.CASCADE, related_name="profile")
    role = models.CharField(max_length=16, choices=Role.choices, default=Role.READONLY)

    def __str__(self) -> str:
        return f"{self.user.username} ({self.role})"

    @property
    def can_manage_rules(self) -> bool:
        return self.role in {Role.ADMIN, Role.ANALYST}

    @property
    def can_manage_users(self) -> bool:
        return self.role == Role.ADMIN


class APIKey(models.Model):
    """Hashed API key for programmatic access. The raw key is shown once at
    creation; only its SHA-256 hash is stored."""

    name = models.CharField(max_length=120)
    user = models.ForeignKey(User, on_delete=models.CASCADE, related_name="api_keys")
    prefix = models.CharField(max_length=12, db_index=True)
    key_hash = models.CharField(max_length=64, unique=True)
    active = models.BooleanField(default=True)
    created_at = models.DateTimeField(auto_now_add=True)
    last_used_at = models.DateTimeField(null=True, blank=True)

    def __str__(self) -> str:
        return f"{self.name} ({self.prefix}…)"

    @staticmethod
    def _hash(raw: str) -> str:
        return hashlib.sha256(raw.encode()).hexdigest()

    @classmethod
    def generate(cls, *, name: str, user: User) -> tuple["APIKey", str]:
        raw = "pifw_" + secrets.token_urlsafe(32)
        obj = cls.objects.create(
            name=name,
            user=user,
            prefix=raw[:12],
            key_hash=cls._hash(raw),
        )
        return obj, raw

    @classmethod
    def resolve(cls, raw: str) -> "APIKey | None":
        try:
            return cls.objects.select_related("user").get(
                key_hash=cls._hash(raw), active=True
            )
        except cls.DoesNotExist:
            return None
