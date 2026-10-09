from __future__ import annotations

import json
import threading
from datetime import datetime, timezone
from pathlib import Path


class DetectionLog:
    """Append-only JSON Lines audit log of every inspection verdict.

    JSONL keeps the MVP dependency-free and trivially greppable; swap for
    Postgres in the control plane later without changing callers.
    """

    def __init__(self, path: str) -> None:
        self._path = Path(path)
        self._lock = threading.Lock()

    def record(self, event: dict) -> None:
        event = {"ts": datetime.now(timezone.utc).isoformat(), **event}
        line = json.dumps(event, ensure_ascii=False)
        with self._lock:
            with self._path.open("a", encoding="utf-8") as fh:
                fh.write(line + "\n")

    def recent(self, limit: int = 100) -> list[dict]:
        if not self._path.exists():
            return []
        with self._lock:
            lines = self._path.read_text(encoding="utf-8").splitlines()
        out = []
        for line in lines[-limit:]:
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return out
