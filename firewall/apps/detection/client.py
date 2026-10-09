"""Wires the configured secondary model into firewall_core's LLMClassifier.

Provider-agnostic: we build a `call_fn(prompt) -> str` that POSTs to an
OpenAI-compatible chat-completions endpoint (works for OpenAI, Azure OpenAI,
and most local gateways). If no classifier key is configured we return the
deterministic HeuristicClassifier so the pipeline stays fully runnable offline.
"""

from __future__ import annotations

import httpx

from config.firewall_settings import firewall_settings
from firewall_core.classifier import (
    AIClassifier,
    HeuristicClassifier,
    LLMClassifier,
)


def _openai_call_fn(base_url: str, api_key: str, model: str):
    url = base_url.rstrip("/") + "/chat/completions"

    def call(prompt: str) -> str:
        resp = httpx.post(
            url,
            headers={"Authorization": f"Bearer {api_key}"},
            json={
                "model": model,
                "temperature": 0,
                "messages": [{"role": "user", "content": prompt}],
            },
            timeout=15.0,
        )
        resp.raise_for_status()
        data = resp.json()
        return data["choices"][0]["message"]["content"]

    return call


def build_classifier() -> AIClassifier:
    s = firewall_settings
    if s.classifier_provider and s.classifier_api_key:
        base = s.classifier_base_url or s.upstream_base_url
        return LLMClassifier(_openai_call_fn(base, s.classifier_api_key, s.classifier_model))
    return HeuristicClassifier()
