from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class Signal:
    """A single piece of evidence from one detector.

    score is a confidence in [0,1] that the text is a prompt-injection or
    other attack. reasons explains what matched, for the audit log.
    """

    detector: str
    score: float
    reasons: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.score = max(0.0, min(1.0, self.score))


class Detector:
    """Base class. A detector inspects text and returns a Signal."""

    name: str = "detector"

    def inspect(self, text: str) -> Signal:  # pragma: no cover - interface
        raise NotImplementedError
