"""Audit logging with a tamper-evident hash chain.

Each RequestLog stores a `row_hash` computed over its own fields plus the
previous row's hash (`prev_hash`). Any retroactive edit or deletion breaks the
chain, which `verify_chain()` detects. This gives forensic integrity without a
separate WORM store.
"""

from __future__ import annotations

import hashlib
import json

from django.contrib.auth.models import User
from django.db import models, transaction
from django.db.models import F


class AuditAppendLock(models.Model):
    """Singleton write lock serializing hash-chain appends across workers."""
    sequence = models.BigIntegerField(default=0)


class Action(models.TextChoices):
    ALLOW = "allow", "Allow"
    WARN = "warn", "Warn"
    SANITIZE = "sanitize", "Sanitize"
    BLOCK = "block", "Block"


class Direction(models.TextChoices):
    REQUEST = "request", "Request"
    RESPONSE = "response", "Response"


class RequestLog(models.Model):
    created_at = models.DateTimeField(auto_now_add=True, db_index=True)
    request_id = models.CharField(max_length=36, db_index=True)
    direction = models.CharField(max_length=10, choices=Direction.choices, default=Direction.REQUEST)

    user = models.ForeignKey(User, null=True, blank=True, on_delete=models.SET_NULL, related_name="request_logs")
    ip_address = models.GenericIPAddressField(null=True, blank=True, db_index=True)
    user_agent = models.TextField(blank=True)
    browser = models.CharField(max_length=80, blank=True)
    os = models.CharField(max_length=80, blank=True)

    prompt_hash = models.CharField(max_length=64, db_index=True, blank=True)
    detected_attacks = models.JSONField(default=list, blank=True)
    matched_rules = models.JSONField(default=list, blank=True)
    ai_confidence = models.FloatField(default=0.0)
    risk_score = models.FloatField(default=0.0, db_index=True)
    risk_level = models.CharField(max_length=12, blank=True, db_index=True)

    action = models.CharField(max_length=12, choices=Action.choices, db_index=True)
    obfuscation_flags = models.JSONField(default=list, blank=True)
    response_status = models.IntegerField(default=200)
    response_time_ms = models.FloatField(default=0.0)

    sanitized_prompt = models.TextField(blank=True)
    sanitized_output = models.TextField(blank=True)
    model_used = models.CharField(max_length=80, blank=True)
    chat_metadata = models.JSONField(default=dict, blank=True)

    # False-positive / false-negative flags for analytics + model tuning.
    marked_false_positive = models.BooleanField(default=False)
    marked_false_negative = models.BooleanField(default=False)

    prev_hash = models.CharField(max_length=64, blank=True)
    row_hash = models.CharField(max_length=64, blank=True, db_index=True)

    class Meta:
        ordering = ["-created_at", "-id"]
        indexes = [models.Index(fields=["risk_level", "action"])]

    def __str__(self) -> str:
        return f"{self.request_id} {self.action} ({self.risk_level})"

    def _payload(self) -> str:
        payload = {
            "request_id": self.request_id,
            "direction": self.direction,
            "ip": self.ip_address,
            "prompt_hash": self.prompt_hash,
            "attacks": self.detected_attacks,
            "rules": self.matched_rules,
            "ai": round(self.ai_confidence, 6),
            "risk": round(self.risk_score, 6),
            "level": self.risk_level,
            "action": self.action,
            "status": self.response_status,
            "prev": self.prev_hash,
        }
        # Keep historical hashes valid while binding new chat telemetry to the chain.
        if self.chat_metadata:
            payload["chat"] = self.chat_metadata
        return json.dumps(
            payload,
            sort_keys=True,
            default=str,
        )

    def compute_hash(self) -> str:
        return hashlib.sha256(self._payload().encode()).hexdigest()

    def save(self, *args, **kwargs):
        if not self.row_hash:
            with transaction.atomic():
                AuditAppendLock.objects.get_or_create(pk=1)
                # UPDATE obtains a database write lock on SQLite and PostgreSQL.
                # Acquire it before reading the predecessor, including the first row.
                AuditAppendLock.objects.filter(pk=1).update(sequence=F("sequence") + 1)
                last = RequestLog.objects.order_by("-id").first()
                self.prev_hash = last.row_hash if last else ""
                self.row_hash = self.compute_hash()
                return super().save(*args, **kwargs)
        return super().save(*args, **kwargs)


def verify_chain() -> dict:
    """Walk the log in insertion order; report the first broken link, if any."""
    prev = ""
    checked = 0
    for row in RequestLog.objects.order_by("id").iterator():
        if row.prev_hash != prev or row.compute_hash() != row.row_hash:
            return {"ok": False, "broken_at_id": row.id, "checked": checked}
        prev = row.row_hash
        checked += 1
    return {"ok": True, "broken_at_id": None, "checked": checked}
