"""CSV / JSON export of audit logs."""

from __future__ import annotations

import csv
import io
import json

_FIELDS = [
    "id", "created_at", "request_id", "direction", "ip_address", "browser", "os",
    "prompt_hash", "risk_score", "risk_level", "ai_confidence", "action",
    "matched_rules", "detected_attacks", "obfuscation_flags",
    "response_status", "response_time_ms", "model_used", "row_hash",
]


def _row(log) -> dict:
    return {
        "id": log.id,
        "created_at": log.created_at.isoformat(),
        "request_id": log.request_id,
        "direction": log.direction,
        "ip_address": log.ip_address or "",
        "browser": log.browser,
        "os": log.os,
        "prompt_hash": log.prompt_hash,
        "risk_score": round(log.risk_score, 4),
        "risk_level": log.risk_level,
        "ai_confidence": round(log.ai_confidence, 4),
        "action": log.action,
        "matched_rules": ";".join(log.matched_rules),
        "detected_attacks": ";".join(log.detected_attacks),
        "obfuscation_flags": ";".join(log.obfuscation_flags),
        "response_status": log.response_status,
        "response_time_ms": log.response_time_ms,
        "model_used": log.model_used,
        "row_hash": log.row_hash,
    }


def to_csv(queryset) -> str:
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=_FIELDS)
    writer.writeheader()
    for log in queryset.iterator():
        writer.writerow(_row(log))
    return buf.getvalue()


def to_json(queryset) -> str:
    return json.dumps([_row(log) for log in queryset.iterator()], indent=2)
