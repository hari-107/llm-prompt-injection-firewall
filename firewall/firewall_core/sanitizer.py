"""Prompt sanitizer.

Removes/neutralizes the malicious spans a rule matched while preserving the
surrounding legitimate request. This is best-effort: for high-severity attacks
the engine will usually Block rather than trust sanitization.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from firewall_core.rules import Rule, default_rules

# Delimiters/markup we strip outright regardless of which rule fired.
_STRIP_PATTERNS = [
    re.compile(r"<!--.*?-->", re.DOTALL),                     # HTML comments
    re.compile(r"</?(system|assistant|user|im_start|im_end)\s*\|?>", re.IGNORECASE),
    re.compile(r"\[/?INST\]|<<SYS>>|<</SYS>>", re.IGNORECASE),
    re.compile(r"</?(instruction|system|prompt|command)>", re.IGNORECASE),
]


@dataclass
class SanitizeResult:
    sanitized: str
    removed: list[str]
    changed: bool


class Sanitizer:
    def __init__(self, rules: list[Rule] | None = None) -> None:
        self._rules = rules if rules is not None else default_rules()
        # Only sanitize spans from rules whose action is safe to redact; the
        # engine decides which rules reach here.
        self._compiled = [(r, r.compiled()) for r in self._rules if r.enabled]

    def sanitize(self, text: str) -> SanitizeResult:
        removed: list[str] = []
        out = text

        for pat in _STRIP_PATTERNS:
            def _repl(m: re.Match) -> str:
                removed.append(m.group(0))
                return ""
            out = pat.sub(_repl, out)

        # Redact injected instruction clauses (replace with a neutral marker so
        # the sentence structure survives for the legitimate remainder).
        for rule, regex in self._compiled:
            if rule.category not in {
                "instruction-override", "jailbreak", "prompt-extraction",
                "secret-extraction", "delimiter-injection", "structured-injection",
            }:
                continue
            def _redact(m: re.Match) -> str:
                removed.append(m.group(0))
                return "[removed: potential injection]"
            out, n = regex.subn(_redact, out)

        out = re.sub(r"\s{3,}", "  ", out).strip()
        return SanitizeResult(sanitized=out, removed=removed, changed=bool(removed))
