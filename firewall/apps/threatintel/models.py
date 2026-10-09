"""Threat-intelligence store.

Two record types:
- ThreatSignature: importable detection signatures (regex or literal) that can be
  promoted into live firewall Rules without editing source.
- JailbreakSample: known jailbreak/injection prompts used for regression testing
  and as a corpus the classifier can be evaluated against.

Signatures/samples are imported from JSON so the catalog updates without a
code change.
"""

from __future__ import annotations

from django.db import models


class SignatureKind(models.TextChoices):
    REGEX = "regex", "Regex"
    LITERAL = "literal", "Literal"


class ThreatSignature(models.Model):
    signature_id = models.SlugField(max_length=100, unique=True)
    kind = models.CharField(max_length=10, choices=SignatureKind.choices, default=SignatureKind.REGEX)
    pattern = models.TextField()
    category = models.CharField(max_length=60, db_index=True)
    severity = models.CharField(max_length=12, default="medium")
    description = models.TextField(blank=True)
    source = models.CharField(max_length=120, blank=True, help_text="Feed/dataset origin.")
    atlas = models.CharField(max_length=120, blank=True)
    promoted = models.BooleanField(default=False, help_text="Copied into live Rules.")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["category", "signature_id"]

    def __str__(self) -> str:
        return f"{self.signature_id} [{self.severity}]"

    def as_regex(self) -> str:
        import re
        return self.pattern if self.kind == SignatureKind.REGEX else re.escape(self.pattern)


class JailbreakSample(models.Model):
    text = models.TextField()
    category = models.CharField(max_length=60, db_index=True)
    is_attack = models.BooleanField(default=True, help_text="False for benign control samples.")
    source = models.CharField(max_length=120, blank=True)
    notes = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["category", "id"]

    def __str__(self) -> str:
        label = "attack" if self.is_attack else "benign"
        return f"[{label}/{self.category}] {self.text[:48]}"
