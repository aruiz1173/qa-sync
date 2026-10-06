"""Persistent, explicitly started analysis queue for captured QA journeys."""

from __future__ import annotations

import copy
import json
import threading
import time
import uuid
from pathlib import Path
from typing import Any

from .errors import ValidationError
from .sensitive import redact_text
from .state import private_dir, private_file


class DeferredQueue:
    MAX_ITEMS = 200

    def __init__(self, path: Path):
        self.path = path
        self._lock = threading.RLock()
        self._items: dict[str, dict[str, Any]] = {}
        self.paused = False
        self.paused_reason = ""
        self.retry_minutes = 15
        self.max_limit_attempts = 24
        self._load()

    def _load(self) -> None:
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
            if not isinstance(raw, dict) or raw.get("version") != 1:
                raise ValueError("Unsupported queue format")
            self.paused = raw.get("paused") is True
            self.paused_reason = str(raw.get("paused_reason") or "")[:100]
            self.retry_minutes = max(5, min(120, int(raw.get("retry_minutes") or 15)))
            self.max_limit_attempts = max(1, min(40, int(raw.get("max_limit_attempts") or 24)))
            for item in raw.get("items", []):
                if not isinstance(item, dict) or not isinstance(item.get("id"), str):
                    continue
                if item.get("state") == "running":
                    # A provider request that was in flight at process death may
                    # have completed remotely without a durable response. Do not
                    # silently spend the person's allowance a second time.
                    stage = (item.get("progress") or {}).get("stage") if isinstance(item.get("progress"), dict) else ""
                    if stage in {"batch", "synthesis", "analysis", "review"}:
                        item["state"] = "failed"
                        item["error_code"] = "uncertain_provider_call"
                        item["error"] = "The server stopped during a provider call; its remote outcome is unknown."
                        item["remedy"] = "Review this TC before Retry analysis; the unfinished call may use allowance again. Saved batches will be reused."
                        self.paused = True
                        self.paused_reason = "uncertain_call"
                    else:
                        # Checkpointed stages and draft writes can resume safely.
                        item["state"] = "scheduled"
                        item["error"] = "Interrupted by a server restart; analysis will retry in queue order."
                    item["progress"] = {}
                self._items[item["id"]] = item
            self._save()
        except FileNotFoundError:
            pass
        except (OSError, TypeError, ValueError):
            # Never overwrite damaged queue metadata; its evidence may still be recoverable.
            if self.path.exists():
                self.path.replace(self.path.with_name(f"deferred.corrupt-{int(time.time())}.json"))

    def _save(self) -> None:
        private_dir(self.path.parent)
        temporary = self.path.with_suffix(".tmp")
        temporary.write_text(json.dumps({"version": 1, "items": list(self._items.values()),
                                         "paused": self.paused, "paused_reason": self.paused_reason,
                                         "retry_minutes": self.retry_minutes,
                                         "max_limit_attempts": self.max_limit_attempts}, ensure_ascii=False), encoding="utf-8")
        private_file(temporary)
        temporary.replace(self.path)

    def list(self) -> list[dict[str, Any]]:
        with self._lock:
            return copy.deepcopy(sorted(self._items.values(), key=lambda item: item["created_at"]))

    def pending(self) -> list[dict[str, Any]]:
        with self._lock:
            items = (item for item in self._items.values()
                     if item.get("state") in {"scheduled", "waiting_limit"})
            return copy.deepcopy(sorted(items, key=lambda item: (
                int(item.get("queue_order") or 0), item["created_at"])))

    def status(self) -> dict[str, Any]:
        with self._lock:
            rows = [row for row in self._items.values() if row.get("queue_order")]
            active = [row for row in rows if row.get("state") in {"scheduled", "running", "waiting_limit"}]
            current = next((row for row in rows if row.get("state") in {"running", "waiting_limit"}), None)
            return {"paused": self.paused, "paused_reason": self.paused_reason,
                    "retry_minutes": self.retry_minutes, "max_limit_attempts": self.max_limit_attempts,
                    "total": len(rows), "remaining": len(active),
                    "completed": sum(row.get("state") == "completed" for row in rows),
                    "failed": sum(row.get("state") == "failed" for row in rows),
                    "current_case_id": current.get("case_id") if current else None,
                    "next_retry_at": current.get("retry_at", 0) if current else 0}

    def configure(self, retry_minutes: int, max_limit_attempts: int) -> None:
        with self._lock:
            self.retry_minutes = retry_minutes
            self.max_limit_attempts = max_limit_attempts
            self._save()

    def pause(self, reason: str = "user") -> None:
        with self._lock:
            self.paused = True
            self.paused_reason = reason
            self._save()

    def resume(self) -> None:
        with self._lock:
            self.paused = False
            self.paused_reason = ""
            if self.pending():
                head = self.pending()[0]
                if head["state"] == "waiting_limit":
                    self._items[head["id"]]["limit_attempts"] = 0
                    self._items[head["id"]]["retry_at"] = 0
            self._save()

    def cancel_pending(self) -> int:
        with self._lock:
            count = 0
            for item in self._items.values():
                if item["state"] in {"scheduled", "waiting_limit"}:
                    item.update(state="ready", retry_at=0, queue_order=0, limit_attempts=0,
                                error="Removed from analysis schedule; captured evidence is retained.",
                                error_code="", remedy="", progress={},
                                updated_at=time.time())
                    count += 1
            self.paused = False
            self.paused_reason = ""
            self._save()
            return count

    def unschedule(self, item_id: str) -> dict[str, Any]:
        with self._lock:
            item = self.get(item_id)
            if item["state"] not in {"scheduled", "waiting_limit"}:
                raise ValidationError("Only a pending TC can be unscheduled. Refresh the queue.")
            item.update(state="ready", queue_order=0, retry_at=0, limit_attempts=0,
                        error="Removed from analysis schedule; captured evidence is retained.",
                        error_code="", remedy="", progress={}, updated_at=time.time())
            self._items[item_id] = item
            self._save()
            return copy.deepcopy(item)

    def move(self, item_id: str, direction: str) -> dict[str, Any]:
        with self._lock:
            if direction not in {"up", "down"}:
                raise ValidationError("Move direction must be up or down.")
            item = self.get(item_id)
            if item["state"] != "scheduled":
                raise ValidationError("Only a scheduled TC can be reordered. Refresh the queue.")
            pending = self.pending()
            position = next(index for index, row in enumerate(pending) if row["id"] == item_id)
            neighbor = position + (-1 if direction == "up" else 1)
            if not 0 <= neighbor < len(pending) or pending[neighbor]["state"] != "scheduled":
                raise ValidationError("This TC cannot move past the current or waiting analysis.")
            other = pending[neighbor]
            self._items[item_id]["queue_order"], self._items[other["id"]]["queue_order"] = (
                other["queue_order"], item["queue_order"])
            self._items[item_id]["updated_at"] = self._items[other["id"]]["updated_at"] = time.time()
            self._save()
            return self.get(item_id)

    def get(self, item_id: str) -> dict[str, Any]:
        with self._lock:
            if item_id not in self._items:
                raise ValidationError("That queued journey does not exist.")
            return copy.deepcopy(self._items[item_id])

    def add(self, *, session_id: str, case_id: int, platform: str, run_id: int | None = None,
            test_id: int | None = None, project_id: int | None = None,
            context: str = "", target_config: str = "") -> dict[str, Any]:
        with self._lock:
            for item in self._items.values():
                if item["session_id"] == session_id:
                    return copy.deepcopy(item)
            if len(self._items) >= self.MAX_ITEMS:
                raise ValidationError("The deferred queue is full. Remove completed items first.")
            item = {"id": uuid.uuid4().hex, "session_id": session_id, "case_id": case_id,
                    "platform": platform, "run_id": run_id, "test_id": test_id,
                    "project_id": project_id, "context": redact_text(context)[:3000],
                    "target_config": target_config[:200], "selected_frames": [],
                    "reviewed": False, "include_test_credentials": False,
                    "state": "needs_review", "error": "", "draft_id": "",
                    "created_at": time.time(), "updated_at": time.time()}
            self._items[item["id"]] = item
            self._save()
            return copy.deepcopy(item)

    def review(self, item_id: str, selected_frames: list[int], include_credentials: bool,
               context: str = "", target_config: str = "") -> dict[str, Any]:
        with self._lock:
            item = self.get(item_id)
            if item["state"] in {"running", "scheduled", "waiting_limit"}:
                raise ValidationError("Cancel this pending analysis before changing its screen selection.")
            item.update(selected_frames=selected_frames, reviewed=True,
                        include_test_credentials=include_credentials,
                        context=redact_text(context)[:3000], target_config=target_config[:200],
                        state="ready", error="", error_code="", remedy="", progress={},
                        draft_id="", updated_at=time.time())
            self._items[item_id] = item
            self._save()
            return copy.deepcopy(item)

    def set_state(self, item_id: str, state: str, **fields: Any) -> dict[str, Any]:
        with self._lock:
            item = self.get(item_id)
            item.update(state=state, updated_at=time.time(), **fields)
            self._items[item_id] = item
            self._save()
            return copy.deepcopy(item)

    def remove(self, item_id: str) -> dict[str, Any]:
        with self._lock:
            item = self.get(item_id)
            if item["state"] in {"running", "scheduled"}:
                raise ValidationError("A running analysis cannot be removed.")
            del self._items[item_id]
            self._save()
            return item
