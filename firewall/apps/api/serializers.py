from __future__ import annotations

from rest_framework import serializers

from apps.auditlog.models import RequestLog
from apps.firewall.models import FirewallConfig, Rule


# --- scan I/O ----------------------------------------------------------------

class PromptScanSerializer(serializers.Serializer):
    prompt = serializers.CharField(allow_blank=False, trim_whitespace=False)
    conversation = serializers.ListField(
        child=serializers.CharField(allow_blank=True, trim_whitespace=False),
        required=False, default=list,
    )
    model = serializers.CharField(required=False, allow_blank=True, default="")


class ResponseScanSerializer(serializers.Serializer):
    response = serializers.CharField(allow_blank=False, trim_whitespace=False)
    mask = serializers.BooleanField(required=False, default=True)
    model = serializers.CharField(required=False, allow_blank=True, default="")


class BatchScanSerializer(serializers.Serializer):
    prompts = serializers.ListField(
        child=serializers.CharField(allow_blank=False, trim_whitespace=False),
        allow_empty=False, max_length=200,
    )


# --- resources ---------------------------------------------------------------

class RuleSerializer(serializers.ModelSerializer):
    class Meta:
        model = Rule
        fields = [
            "id", "rule_id", "pattern", "severity", "category", "description",
            "mitigation", "atlas", "action", "enabled", "builtin",
            "policy_profile", "source_quote", "positive_examples", "negative_examples",
            "created_at", "updated_at",
        ]
        read_only_fields = ["id", "builtin", "policy_profile", "source_quote",
                            "positive_examples", "negative_examples", "created_at", "updated_at"]

    def validate_pattern(self, value: str) -> str:
        import re
        try:
            re.compile(value)
        except re.error as exc:
            raise serializers.ValidationError(f"Invalid regex: {exc}")
        return value


class FirewallConfigSerializer(serializers.ModelSerializer):
    class Meta:
        model = FirewallConfig
        fields = [
            "use_ai", "output_block_threshold", "risk_low", "risk_medium",
            "risk_high", "risk_critical", "default_mode", "updated_at",
        ]
        read_only_fields = ["updated_at"]


class RequestLogSerializer(serializers.ModelSerializer):
    class Meta:
        model = RequestLog
        fields = [
            "id", "created_at", "request_id", "direction", "ip_address",
            "browser", "os", "prompt_hash", "detected_attacks", "matched_rules",
            "ai_confidence", "risk_score", "risk_level", "action",
            "obfuscation_flags", "response_status", "response_time_ms",
            "model_used", "marked_false_positive", "marked_false_negative",
            "row_hash",
            "chat_metadata",
        ]
