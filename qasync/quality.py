from __future__ import annotations

import json
import threading
import time
import uuid
from pathlib import Path
from typing import Any

from .state import private_dir, private_file


class FeedbackStore:
    VERSION = 1
    MAX_EVENTS = 5000

    def __init__(self, path: Path):
        self.path = path
        self._lock = threading.Lock()

    def add(self, case_id: int, provider: str, confidence: float,
            entries: list[dict[str, Any]], prompt_version: int) -> int:
        clean = []
        for entry in entries[:200]:
            verdict = str(entry.get("verdict", "")).lower()
            index = entry.get("step_index")
            if verdict not in {"accepted", "edited", "rejected"} or not isinstance(index, int) or index < 0:
                continue
            clean.append({"step_index": index, "verdict": verdict,
                          "reason": " ".join(str(entry.get("reason", "")).split())[:500]})
        if not clean:
            return 0
        with self._lock:
            data = self._read()
            events = data.get("events", [])
            events.append({"id": uuid.uuid4().hex, "created_at": int(time.time()), "case_id": case_id,
                           "provider": provider[:40], "confidence": confidence,
                           "prompt_version": prompt_version, "steps": clean})
            self._write(events[-self.MAX_EVENTS:])
        return len(clean)

    def metrics(self) -> dict[str, Any]:
        events = self._read().get("events", [])
        counts = {"accepted": 0, "edited": 0, "rejected": 0}
        for event in events:
            for step in event.get("steps", []) if isinstance(event, dict) else []:
                verdict = step.get("verdict") if isinstance(step, dict) else None
                if verdict in counts:
                    counts[verdict] += 1
        total = sum(counts.values())
        return {"reviews": len(events), "steps": total, **counts,
                "acceptance_rate": round(counts["accepted"] / total, 4) if total else None,
                "edit_rate": round(counts["edited"] / total, 4) if total else None,
                "rejection_rate": round(counts["rejected"] / total, 4) if total else None}

    def _read(self) -> dict[str, Any]:
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) and isinstance(data.get("events"), list) else {"version": self.VERSION, "events": []}
        except (OSError, json.JSONDecodeError):
            return {"version": self.VERSION, "events": []}

    def _write(self, events: list[dict[str, Any]]) -> None:
        private_dir(self.path.parent)
        temporary = self.path.with_suffix(".tmp")
        temporary.write_text(json.dumps({"version": self.VERSION, "events": events}, ensure_ascii=False), encoding="utf-8")
        private_file(temporary)
        temporary.replace(self.path)
