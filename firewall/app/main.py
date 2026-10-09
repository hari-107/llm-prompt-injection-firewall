from __future__ import annotations

import json

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from app.config import FirewallMode, settings
from app.engine import Engine
from app.logstore import DetectionLog

app = FastAPI(title="LLM Prompt Injection Firewall", version="0.1.0")
engine = Engine(block_threshold=settings.block_threshold)
log = DetectionLog(settings.detection_log)


async def _read_json(request: Request) -> dict:
    """Parse the request body as a JSON object, raising a clean error otherwise."""
    raw = await request.body()
    try:
        payload = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise _BadRequest(f"Request body is not valid JSON: {exc}") from exc
    if not isinstance(payload, dict):
        raise _BadRequest("Request body must be a JSON object.")
    return payload


class _BadRequest(Exception):
    """Malformed client input; surfaced as HTTP 400."""


def _error(status_code: int, message: str, error_type: str) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content={"error": {"message": message, "type": error_type}},
    )


def _extract_text(payload: dict) -> str:
    """Pull user-supplied text out of an OpenAI-style chat request.

    We inspect user/tool/system-appended content — i.e. everything that could
    carry an injection — and join it for scanning.
    """
    parts: list[str] = []
    for msg in payload.get("messages", []):
        if not isinstance(msg, dict):
            continue
        if msg.get("role") == "system":
            continue  # trusted app-provided instructions
        content = msg.get("content", "")
        if isinstance(content, str):
            parts.append(content)
        elif isinstance(content, list):
            for block in content:
                if isinstance(block, dict) and isinstance(block.get("text"), str):
                    parts.append(block["text"])
    if isinstance(payload.get("prompt"), str):
        parts.append(payload["prompt"])
    return "\n".join(parts)


def _response_text(data: dict) -> str:
    parts: list[str] = []
    for choice in data.get("choices", []):
        if not isinstance(choice, dict):
            continue
        msg = choice.get("message") or {}
        if isinstance(msg.get("content"), str):
            parts.append(msg["content"])
        if isinstance(choice.get("text"), str):
            parts.append(choice["text"])
    return "\n".join(parts)


@app.get("/healthz")
async def healthz() -> dict:
    return {
        "status": "ok",
        "mode": settings.firewall_mode,
        "inspect_only": settings.inspect_only,
        "block_threshold": settings.block_threshold,
    }


@app.get("/detections")
async def detections(limit: int = 100) -> dict:
    return {"detections": log.recent(limit=limit)}


@app.post("/inspect")
async def inspect(request: Request) -> JSONResponse:
    """Scan a payload and return the verdict without forwarding. Useful for
    integration as middleware and for the inspect-only deployment."""
    try:
        payload = await _read_json(request)
    except _BadRequest as exc:
        return _error(400, str(exc), "invalid_request")
    verdict = engine.inspect_request(_extract_text(payload))
    log.record({"event": "inspect", "verdict": verdict.as_dict()})
    return JSONResponse(verdict.as_dict())


@app.post("/v1/chat/completions")
async def chat_completions(request: Request) -> JSONResponse:
    try:
        payload = await _read_json(request)
    except _BadRequest as exc:
        return _error(400, str(exc), "invalid_request")
    text = _extract_text(payload)
    verdict = engine.inspect_request(text)

    log.record(
        {
            "event": "request",
            "mode": settings.firewall_mode,
            "verdict": verdict.as_dict(),
        }
    )

    if verdict.malicious and settings.firewall_mode == FirewallMode.block:
        return JSONResponse(
            status_code=403,
            content={
                "error": {
                    "message": "Request blocked by prompt injection firewall.",
                    "type": "firewall_blocked",
                    "verdict": verdict.as_dict(),
                }
            },
        )

    if settings.inspect_only:
        # No upstream configured: return the verdict so the pipeline is testable
        # without a real provider key.
        return JSONResponse(
            {
                "firewall": {
                    "inspect_only": True,
                    "verdict": verdict.as_dict(),
                    "would_block": verdict.malicious,
                }
            }
        )

    try:
        upstream = await _forward(payload)
    except httpx.HTTPStatusError as exc:
        log.record({"event": "upstream_error", "status": exc.response.status_code})
        return _error(
            502,
            f"Upstream LLM returned {exc.response.status_code}.",
            "upstream_error",
        )
    except httpx.HTTPError as exc:
        log.record({"event": "upstream_error", "detail": str(exc)})
        return _error(502, "Failed to reach upstream LLM.", "upstream_error")

    out_verdict = engine.inspect_response(_response_text(upstream))
    if out_verdict.signals:
        log.record({"event": "response", "verdict": out_verdict.as_dict()})
    if out_verdict.malicious and settings.firewall_mode == FirewallMode.block:
        return JSONResponse(
            status_code=403,
            content={
                "error": {
                    "message": "Response blocked by firewall (data leak detected).",
                    "type": "firewall_blocked_output",
                    "verdict": out_verdict.as_dict(),
                }
            },
        )

    headers = {}
    if verdict.malicious or out_verdict.malicious:
        headers["X-Firewall-Verdict"] = "flagged"
    return JSONResponse(upstream, headers=headers)


async def _forward(payload: dict) -> dict:
    url = settings.upstream_base_url.rstrip("/") + "/chat/completions"
    headers = {
        "Authorization": f"Bearer {settings.upstream_api_key}",
        "Content-Type": "application/json",
    }
    async with httpx.AsyncClient(timeout=60.0) as client:
        resp = await client.post(url, json=payload, headers=headers)
        resp.raise_for_status()
        return resp.json()
