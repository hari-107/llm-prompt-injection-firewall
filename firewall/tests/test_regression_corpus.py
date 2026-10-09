"""Detection-accuracy regression test.

Runs the full attack corpus (data/attack_corpus.json) through the engine and
asserts detection accuracy stays above a floor. This guards against future
changes that silently reduce recall (attacks slipping through) or precision
(benign prompts getting blocked). Pure firewall_core — no DB required.
"""

from __future__ import annotations

import json
from pathlib import Path

from firewall_core.engine import Action, FirewallEngine

_CORPUS = Path(__file__).resolve().parent.parent / "data" / "attack_corpus.json"

# These curated examples should keep their decisions as rules evolve. They are
# regression cases, not an estimate of real-world detection accuracy.


def _load_samples():
    data = json.loads(_CORPUS.read_text(encoding="utf-8"))
    return data["samples"]


def test_corpus_present():
    samples = _load_samples()
    assert len(samples) >= 30, "corpus should contain a meaningful sample set"
    assert any(s["is_attack"] for s in samples)
    assert any(not s["is_attack"] for s in samples)


def test_curated_attacks_are_blocked():
    engine = FirewallEngine(enforce_security=True)
    attacks = [s for s in _load_samples() if s["is_attack"]]
    misses = []
    for s in attacks:
        r = engine.inspect_request(s["text"])
        if r.action != Action.block:
            misses.append(s["text"][:60])
    assert not misses, f"curated attacks passed: {misses}"


def test_curated_benign_prompts_are_allowed():
    engine = FirewallEngine(enforce_security=True)
    benign = [s for s in _load_samples() if not s["is_attack"]]
    fps = []
    for s in benign:
        r = engine.inspect_request(s["text"])
        if r.action != Action.allow:
            fps.append((r.action.value, s["text"][:60]))
    assert not fps, f"curated benign prompts flagged: {fps}"
