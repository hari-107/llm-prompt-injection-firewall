"""Helpers to record inspections and extract request metadata."""

from __future__ import annotations

import hashlib
import re

from apps.auditlog.models import Direction, RequestLog

_BROWSERS = [
    ("Edg/", "Edge"),
    ("OPR/", "Opera"),
    ("Chrome/", "Chrome"),
    ("Firefox/", "Firefox"),
    ("Safari/", "Safari"),
    ("curl/", "curl"),
    ("python-httpx", "httpx"),
    ("PostmanRuntime", "Postman"),
]
_OSES = [
    ("Windows NT 10", "Windows 10/11"),
    ("Windows", "Windows"),
    ("Mac OS X", "macOS"),
    ("Android", "Android"),
    ("iPhone", "iOS"),
    ("Linux", "Linux"),
]


def client_ip(request) -> str | None:
    xff = request.META.get("HTTP_X_FORWARDED_FOR")
    if xff:
        return xff.split(",")[0].strip()
    return request.META.get("REMOTE_ADDR")


def parse_ua(ua: str) -> tuple[str, str]:
    browser = next((name for token, name in _BROWSERS if token in ua), "")
    os_name = next((name for token, name in _OSES if re.search(re.escape(token), ua)), "")
    return browser, os_name


def prompt_hash(text: str) -> str:
    return hashlib.sha256((text or "").encode()).hexdigest()


def record_request(
    *,
    request,
    request_id: str,
    inspection,
    response_time_ms: float,
    raw_text: str,
    model_used: str = "",
    response_status: int = 200,
) -> RequestLog:
    """Persist an InspectionResult (firewall_core.engine.InspectionResult)."""
    ua = request.META.get("HTTP_USER_AGENT", "") if request else ""
    browser, os_name = parse_ua(ua)
    user = getattr(request, "user", None) if request else None
    if user is not None and not getattr(user, "is_authenticated", False):
        user = None

    return RequestLog.objects.create(
        request_id=request_id,
        direction=Direction.REQUEST,
        user=user,
        ip_address=client_ip(request) if request else None,
        user_agent=ua,
        browser=browser,
        os=os_name,
        prompt_hash=prompt_hash(raw_text),
        detected_attacks=[
            m.category for m in inspection.rule_matches
        ] + ([inspection.ai_verdict.category] if inspection.ai_verdict and inspection.ai_verdict.is_attack else []),
        matched_rules=[m.rule_id for m in inspection.rule_matches],
        ai_confidence=inspection.ai_verdict.confidence if inspection.ai_verdict else 0.0,
        risk_score=inspection.risk.score,
        risk_level=inspection.risk.level.value,
        action=inspection.action.value,
        obfuscation_flags=inspection.obfuscation_flags,
        response_status=response_status,
        response_time_ms=round(response_time_ms, 2),
        sanitized_prompt=inspection.sanitized_text or "",
        model_used=model_used,
    )


def record_response(
    *,
    request,
    request_id: str,
    output_result,
    response_time_ms: float,
    model_used: str = "",
) -> RequestLog:
    """Persist an OutputResult (firewall_core.engine.OutputResult)."""
    ua = request.META.get("HTTP_USER_AGENT", "") if request else ""
    browser, os_name = parse_ua(ua)
    user = getattr(request, "user", None) if request else None
    if user is not None and not getattr(user, "is_authenticated", False):
        user = None

    return RequestLog.objects.create(
        request_id=request_id,
        direction=Direction.RESPONSE,
        user=user,
        ip_address=client_ip(request) if request else None,
        user_agent=ua,
        browser=browser,
        os=os_name,
        detected_attacks=[f.label for f in output_result.scan.findings],
        matched_rules=[],
        risk_score=output_result.scan.score,
        risk_level="",
        action=output_result.action.value,
        response_time_ms=round(response_time_ms, 2),
        sanitized_output=output_result.scan.masked_text,
        model_used=model_used,
    )
