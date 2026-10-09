from __future__ import annotations

from django.db import models


class Severity(models.TextChoices):
    INFO = "info", "Info"
    LOW = "low", "Low"
    MEDIUM = "medium", "Medium"
    HIGH = "high", "High"
    CRITICAL = "critical", "Critical"


class RuleAction(models.TextChoices):
    ALLOW = "allow", "Allow"
    WARN = "warn", "Warn"
    SANITIZE = "sanitize", "Sanitize"
    BLOCK = "block", "Block"


class PolicyProfile(models.Model):
    """A company's reviewed terms; only the selected profile is enforced."""

    name = models.CharField(max_length=120)
    slug = models.SlugField(max_length=64, unique=True)
    source_filename = models.CharField(max_length=255)
    source_sha256 = models.CharField(max_length=64)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    def __str__(self) -> str:
        return self.name


class PolicyDraft(models.Model):
    """Validated candidate patterns awaiting a human's activation choice."""

    provider_name = models.CharField(max_length=120)
    provider_slug = models.SlugField(max_length=64)
    source_filename = models.CharField(max_length=255)
    source_sha256 = models.CharField(max_length=64)
    model_used = models.CharField(max_length=120)
    candidates = models.JSONField(default=list)
    rejected = models.JSONField(default=list)
    created_by = models.ForeignKey("auth.User", on_delete=models.SET_NULL, null=True,
                                   blank=True, related_name="policy_drafts_created")
    activated_by = models.ForeignKey("auth.User", on_delete=models.SET_NULL, null=True,
                                     blank=True, related_name="policy_drafts_activated")
    created_at = models.DateTimeField(auto_now_add=True)
    activated_at = models.DateTimeField(null=True, blank=True)

    def __str__(self) -> str:
        return f"{self.provider_name} draft {self.pk}"


class Rule(models.Model):
    """A configurable regex detection rule, editable from the dashboard.

    Mirrors firewall_core.rules.Rule; `to_core()` converts a row into the
    engine's dataclass so DB rules drive detection.
    """

    rule_id = models.SlugField(max_length=80, unique=True)
    pattern = models.TextField()
    severity = models.CharField(max_length=12, choices=Severity.choices, default=Severity.MEDIUM)
    category = models.CharField(max_length=60, db_index=True)
    description = models.TextField(blank=True)
    mitigation = models.TextField(blank=True)
    atlas = models.CharField(max_length=120, blank=True)
    action = models.CharField(max_length=12, choices=RuleAction.choices, blank=True,
                              help_text="Optional per-rule action override.")
    enabled = models.BooleanField(default=True, db_index=True)
    builtin = models.BooleanField(default=False, help_text="Seeded default rule.")
    policy_profile = models.ForeignKey(PolicyProfile, on_delete=models.CASCADE, null=True,
                                       blank=True, related_name="rules")
    source_quote = models.TextField(blank=True)
    positive_examples = models.JSONField(default=list, blank=True)
    negative_examples = models.JSONField(default=list, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["category", "rule_id"]

    def __str__(self) -> str:
        return f"{self.rule_id} [{self.severity}]"

    def to_core(self):
        from firewall_core.rules import Rule as CoreRule

        return CoreRule(
            id=self.rule_id,
            pattern=self.pattern,
            severity=self.severity,
            category=self.category,
            description=self.description,
            mitigation=self.mitigation,
            enabled=self.enabled,
            atlas=self.atlas,
            action=self.action,
        )


class FirewallConfig(models.Model):
    """Singleton runtime config overriding env defaults from the dashboard."""

    use_ai = models.BooleanField(default=True)
    output_block_threshold = models.FloatField(default=0.7)
    risk_low = models.FloatField(default=0.20)
    risk_medium = models.FloatField(default=0.45)
    risk_high = models.FloatField(default=0.70)
    risk_critical = models.FloatField(default=0.90)
    default_mode = models.CharField(max_length=12, choices=RuleAction.choices, default=RuleAction.BLOCK)
    active_policy = models.ForeignKey(PolicyProfile, on_delete=models.SET_NULL, null=True,
                                      blank=True, related_name="+")
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        verbose_name = "Firewall configuration"
        verbose_name_plural = "Firewall configuration"

    def __str__(self) -> str:
        return "Firewall configuration"

    @classmethod
    def load(cls) -> "FirewallConfig":
        obj, _ = cls.objects.get_or_create(pk=1)
        return obj

    def thresholds(self) -> dict:
        from firewall_core.scoring import RiskLevel

        return {
            RiskLevel.low: self.risk_low,
            RiskLevel.medium: self.risk_medium,
            RiskLevel.high: self.risk_high,
            RiskLevel.critical: self.risk_critical,
        }
