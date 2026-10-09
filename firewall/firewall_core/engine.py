"""FirewallEngine — orchestrates the full inspection pipeline.

Request path:  normalize/decode -> rule engine -> AI classifier -> risk score
               -> decide action (allow/warn/sanitize/block) -> optional sanitize.
Response path: output scan for secrets/PII/prompt-disclosure -> mask/block.

The engine is pure Python; the Django layer supplies rules, config, the
classifier, and persists results.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum

from firewall_core.classifier import (
    AIClassifier,
    ClassifierVerdict,
    HeuristicClassifier,
)
from firewall_core.normalize import normalize
from firewall_core.output_scan import OutputScanner, OutputScanResult, OutputFinding
from firewall_core.rules import Rule, RuleEngine, RuleMatch
from firewall_core.sanitizer import Sanitizer
from firewall_core.scoring import RiskLevel, RiskScore, score_request


class Action(str, Enum):
    allow = "allow"
    warn = "warn"
    sanitize = "sanitize"
    block = "block"


# Which risk level triggers which action by default; overridable via config.
DEFAULT_ACTION_POLICY: dict[RiskLevel, Action] = {
    RiskLevel.safe: Action.allow,
    RiskLevel.low: Action.warn,
    RiskLevel.medium: Action.sanitize,
    RiskLevel.high: Action.block,
    RiskLevel.critical: Action.block,
}


@dataclass
class InspectionResult:
    action: Action
    risk: RiskScore
    rule_matches: list[RuleMatch] = field(default_factory=list)
    ai_verdict: ClassifierVerdict | None = None
    obfuscation_flags: list[str] = field(default_factory=list)
    decoded_layers: list[str] = field(default_factory=list)
    sanitized_text: str | None = None
    normalized_text: str = ""

    @property
    def blocked(self) -> bool:
        return self.action == Action.block

    def as_dict(self) -> dict:
        return {
            "action": self.action.value,
            "risk": self.risk.as_dict(),
            "rule_matches": [
                {
                    "rule_id": m.rule_id,
                    "severity": m.severity,
                    "category": m.category,
                    "description": m.description,
                    "mitigation": m.mitigation,
                    "atlas": m.atlas,
                    "excerpt": m.excerpt,
                }
                for m in self.rule_matches
            ],
            "ai_verdict": self.ai_verdict.as_dict() if self.ai_verdict else None,
            "obfuscation_flags": self.obfuscation_flags,
            "decoded_layers": self.decoded_layers,
            "sanitized_text": self.sanitized_text,
        }


@dataclass
class OutputResult:
    action: Action
    scan: OutputScanResult

    def as_dict(self) -> dict:
        return {
            "action": self.action.value,
            "score": round(self.scan.score, 4),
            "has_leak": self.scan.has_leak,
            "findings": [
                {"label": f.label, "severity": f.severity, "count": f.count}
                for f in self.scan.findings
            ],
            "masked_text": self.scan.masked_text,
        }


class FirewallEngine:
    def __init__(
        self,
        *,
        rules: list[Rule] | None = None,
        classifier: AIClassifier | None = None,
        thresholds: dict[RiskLevel, float] | None = None,
        action_policy: dict[RiskLevel, Action] | None = None,
        output_block_threshold: float = 0.7,
        use_ai: bool = True,
        enforce_security: bool = False,
    ) -> None:
        self._rule_engine = RuleEngine(rules)
        self._sanitizer = Sanitizer(rules)
        # A disabled rule is an operator exception for the text it matches.
        # Keep scanning the original text with enabled rules, but don't let the
        # classifier score that same disabled span a second time.
        self._disabled_patterns = []
        for rule in rules or []:
            if rule.enabled:
                continue
            try:
                self._disabled_patterns.append(rule.compiled())
            except re.error:
                # An invalid disabled rule should not interrupt all scans.
                continue
        self._classifier = classifier or HeuristicClassifier()
        self._output = OutputScanner()
        self._thresholds = thresholds
        self._policy = action_policy or DEFAULT_ACTION_POLICY
        self._output_block_threshold = output_block_threshold
        self._use_ai = use_ai
        self._enforce_security = enforce_security

    def inspect_request(
        self,
        text: str,
        *,
        conversation: list[str] | None = None,
        repeat_offense_factor: float = 0.0,
    ) -> InspectionResult:
        norm = normalize(text)
        scan_text = norm.combined

        # Conversation-aware: scan the concatenation of prior turns so multi-turn
        # / gradual-manipulation attacks surface via the same rules.
        context_factor = 0.0
        if conversation:
            joined_prior = "\n".join(conversation)
            prior_norm = normalize(joined_prior)
            prior_matches = self._rule_engine.inspect(prior_norm.combined)
            scan_text = scan_text + "\n" + prior_norm.combined
            if prior_matches:
                context_factor = min(0.2 + 0.1 * len(prior_matches), 0.6)

        rule_matches = self._rule_engine.inspect(scan_text)

        ai_verdict: ClassifierVerdict | None = None
        ai_confidence = 0.0
        if self._use_ai:
            classifier_text = scan_text
            for pattern in self._disabled_patterns:
                classifier_text = pattern.sub(" ", classifier_text)
            ai_verdict = self._classifier.classify(classifier_text)
            ai_confidence = ai_verdict.confidence if ai_verdict.is_attack else 0.0

        risk = score_request(
            rule_matches=rule_matches,
            ai_confidence=ai_confidence,
            obfuscation_flags=norm.flags,
            repeat_offense_factor=repeat_offense_factor,
            context_factor=context_factor,
            thresholds=self._thresholds,
        )

        action = self._policy.get(risk.level, Action.allow)

        rank = {Action.allow: 0, Action.warn: 1, Action.sanitize: 2, Action.block: 3}
        for match in rule_matches:
            if match.action in Action._value2member_map_:
                override = Action(match.action)
                if rank[override] > rank[action]:
                    action = override
        if self._enforce_security:
            if any(m.severity == "critical" for m in rule_matches):
                risk.level = RiskLevel.critical
            if risk.level in (RiskLevel.high, RiskLevel.critical):
                action = Action.block
            elif risk.level == RiskLevel.medium and action == Action.allow:
                action = Action.warn

        # Per-rule action override: a rule mapped to a stricter action escalates.
        sanitized_text = None
        if action in (Action.sanitize, Action.warn) and rule_matches:
            result = self._sanitizer.sanitize(text)
            if result.changed:
                sanitized_text = result.sanitized

        return InspectionResult(
            action=action,
            risk=risk,
            rule_matches=rule_matches,
            ai_verdict=ai_verdict,
            obfuscation_flags=norm.flags,
            decoded_layers=norm.decoded_layers,
            sanitized_text=sanitized_text,
            normalized_text=norm.normalized,
        )

    def inspect_response(self, text: str, *, mask: bool = True,
                         protected_texts: list[str] | None = None) -> OutputResult:
        scan = self._output.scan(text, mask=mask)
        if any(value and value in text for value in protected_texts or []):
            scan.findings.append(OutputFinding("application-system-disclosure", 0.98, 1))
            scan.score = 1 - (1 - scan.score) * 0.02
            scan.masked_text = "[REDACTED]"
        action = Action.allow
        if scan.score >= self._output_block_threshold:
            action = Action.block
        elif scan.has_leak:
            action = Action.sanitize  # masked but returned
        if self._enforce_security:
            # Operator thresholds cannot permit credential or instruction leakage.
            if any(f.severity >= 0.7 and f.label not in {
                "credit-card", "aadhaar"
            } for f in scan.findings):
                action = Action.block
        return OutputResult(action=action, scan=scan)
