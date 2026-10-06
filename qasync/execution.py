from __future__ import annotations

import copy
import json
import threading
import time
import uuid
from pathlib import Path
from typing import Any

from .errors import ValidationError
from .state import private_dir, private_file


FINAL_OUTCOMES = {"passed", "failed", "blocked", "skipped"}


class ExecutionStore:
    """Crash-resistant metadata for deterministic device executions.

    Screens remain in RecorderManager's encrypted evidence store. This file only
    contains bounded case identifiers, step text and verdicts so an interrupted
    local session can be inspected without retaining another image copy.
    """

    VERSION = 1
    MAX_EXECUTIONS = 500

    def __init__(self, path: Path, retention_days: int = 0):
        self.path = path
        self.retention_seconds = max(0, retention_days) * 86400
        self._items: dict[str, dict[str, Any]] = {}
        self._lock = threading.Lock()
        self._load()

    def create(self, *, recorder_session_id: str, run_id: int, test_id: int, case_id: int,
               platform: str, device_id: str, steps: list[dict[str, Any]], offline: bool = False) -> dict[str, Any]:
        clean_steps = []
        for index, step in enumerate(steps):
            if not isinstance(step, dict):
                raise ValidationError(f"Step {index + 1} is invalid.")
            content, expected = str(step.get("content", "")).strip(), str(step.get("expected", "")).strip()
            if not content or not expected or len(content) > 5000 or len(expected) > 5000:
                raise ValidationError(f"Step {index + 1} needs a bounded action and expected result.")
            optional = content.lower().startswith(("[optional]", "[opcional]"))
            clean_steps.append({"index": index, "content": content, "expected": expected, "optional": optional})
        if not clean_steps or len(clean_steps) > 100:
            raise ValidationError("Execution requires 1 to 100 separate steps.")
        item = {
            "id": uuid.uuid4().hex, "recorder_session_id": recorder_session_id,
            "run_id": run_id, "test_id": test_id, "case_id": case_id,
            "platform": platform, "device_id": device_id, "steps": clean_steps,
            "results": [], "state": "running", "offline": offline, "started_at": time.time(),
            "finished_at": None, "published": False, "testrail_result_id": None,
        }
        with self._lock:
            self._items[item["id"]] = item
            self._prune_locked()
            self._save()
        return self.public(item["id"])

    def get(self, execution_id: str) -> dict[str, Any]:
        with self._lock:
            item = self._items.get(str(execution_id))
            if not item:
                raise ValidationError("That execution does not exist or expired.")
            return copy.deepcopy(item)

    def public(self, execution_id: str) -> dict[str, Any]:
        item = self.get(execution_id)
        done = {int(result["step_index"]): result for result in item["results"]
                if result.get("outcome") in FINAL_OUTCOMES}
        current_index = next((index for index in range(len(item["steps"])) if index not in done), len(item["steps"]))
        return {
            **{key: item.get(key) for key in (
                "id", "recorder_session_id", "run_id", "test_id", "case_id", "platform",
                "device_id", "state", "offline", "started_at", "finished_at", "published", "testrail_result_id",
            )},
            "steps": copy.deepcopy(item["steps"]), "results": copy.deepcopy(item["results"]),
            "current_index": current_index, "complete": current_index >= len(item["steps"]),
        }

    def record(self, execution_id: str, step_index: int, outcome: str, reason: str,
               *, source: str, confidence: float | None = None, observed: str = "",
               provider: str = "", evidence: dict[str, Any] | None = None,
               usage: dict[str, Any] | None = None) -> dict[str, Any]:
        if outcome not in FINAL_OUTCOMES and outcome != "needs_review":
            raise ValidationError("The execution verdict is invalid.")
        if source not in {"ai", "manual"}:
            raise ValidationError("The execution verdict source is invalid.")
        with self._lock:
            item = self._items.get(str(execution_id))
            if not item or item.get("state") != "running":
                raise ValidationError("That execution is not running.")
            if isinstance(step_index, bool) or not isinstance(step_index, int) or not 0 <= step_index < len(item["steps"]):
                raise ValidationError("That execution step does not exist.")
            result = {
                "step_index": step_index, "outcome": outcome, "reason": str(reason).strip()[:1000],
                "source": source, "confidence": confidence, "observed": str(observed).strip()[:2000],
                "provider": str(provider)[:40], "recorded_at": time.time(),
                "evidence": {
                    "baseline_stable": bool((evidence or {}).get("baseline_stable")),
                    "after_stable": bool((evidence or {}).get("after_stable")),
                    "settle_seconds": max(0.0, min(60.0, float((evidence or {}).get("settle_seconds", 0) or 0))),
                },
                "usage": self._clean_usage(usage),
            }
            item["results"] = [old for old in item["results"] if old.get("step_index") != step_index]
            item["results"].append(result)
            item["results"].sort(key=lambda value: value["step_index"])
            self._save()
        return self.public(execution_id)

    def finish(self, execution_id: str, overall: str, published: bool = False,
               testrail_result_id: object = None) -> dict[str, Any]:
        with self._lock:
            item = self._items.get(str(execution_id))
            if not item or item.get("state") != "running":
                raise ValidationError("That execution is not running.")
            final = {result.get("step_index") for result in item["results"] if result.get("outcome") in FINAL_OUTCOMES}
            if len(final) != len(item["steps"]):
                raise ValidationError("Every step needs a final verdict before finishing.")
            item.update({"state": overall, "finished_at": time.time(), "published": published,
                         "testrail_result_id": testrail_result_id})
            self._save()
        return self.public(execution_id)

    def cancel(self, execution_id: str) -> dict[str, Any]:
        with self._lock:
            item = self._items.get(str(execution_id))
            if not item:
                raise ValidationError("That execution does not exist or expired.")
            if item.get("state") == "running":
                item.update({"state": "cancelled", "finished_at": time.time()})
                self._save()
        return self.public(execution_id)

    def running(self) -> list[dict[str, Any]]:
        with self._lock:
            identifiers = [item["id"] for item in self._items.values() if item.get("state") == "running"]
        return sorted((self.public(identifier) for identifier in identifiers),
                      key=lambda item: float(item.get("started_at") or 0), reverse=True)

    def mark_publish_unknown(self, execution_id: str, overall: str) -> dict[str, Any]:
        with self._lock:
            item = self._items.get(str(execution_id))
            if not item or item.get("state") != "running":
                raise ValidationError("That execution cannot be marked as an uncertain publication.")
            item.update({"state": "publish_unknown", "intended_overall": overall,
                         "finished_at": time.time(), "published": False})
            self._save()
        return self.public(execution_id)

    def reconcile_publication(self, execution_id: str, result_id: object | None) -> dict[str, Any]:
        with self._lock:
            item = self._items.get(str(execution_id))
            if not item or item.get("state") != "publish_unknown":
                raise ValidationError("That execution has no uncertain publication to reconcile.")
            if result_id is None:
                item["state"] = "publish_not_found"
            else:
                item.update({"state": str(item.get("intended_overall") or "published"), "published": True,
                             "testrail_result_id": result_id})
            self._save()
        return self.public(execution_id)

    def report(self, execution_id: str) -> dict[str, Any]:
        item = self.get(execution_id)
        return {key: item.get(key) for key in (
            "id", "run_id", "test_id", "case_id", "platform", "device_id", "state", "started_at",
            "finished_at", "published", "testrail_result_id", "intended_overall", "steps", "results",
        )}

    def metrics(self) -> dict[str, Any]:
        with self._lock:
            items = copy.deepcopy(list(self._items.values()))
        results = [result for item in items for result in item.get("results", []) if isinstance(result, dict)]
        final = [result for result in results if result.get("outcome") in FINAL_OUTCOMES]
        counts = {name: sum(1 for result in final if result.get("outcome") == name)
                  for name in sorted(FINAL_OUTCOMES)}
        ai = [result for result in results if result.get("source") == "ai"]
        manual = [result for result in results if result.get("source") == "manual"]
        settled = [float((result.get("evidence") or {}).get("settle_seconds") or 0) for result in results]
        ai_usage = [result.get("usage") or {} for result in ai]
        return {
            "executions": len(items), "completed": sum(1 for item in items if item.get("finished_at")),
            "running": sum(1 for item in items if item.get("state") == "running"),
            "steps": len(final), **counts, "ai_verdicts": len(ai), "manual_verdicts": len(manual),
            "needs_review": sum(1 for result in results if result.get("outcome") == "needs_review"),
            "ai_final_rate": round(sum(1 for result in ai if result.get("outcome") in FINAL_OUTCOMES) / len(ai), 4) if ai else None,
            "average_settle_seconds": round(sum(settled) / len(settled), 3) if settled else None,
            "ai_cost_usd": round(sum(float(usage.get("estimated_cost_usd") or 0) for usage in ai_usage), 6),
            "ai_duration_seconds": round(sum(float(usage.get("duration_seconds") or 0) for usage in ai_usage), 3),
        }

    @staticmethod
    def _clean_usage(raw: dict[str, Any] | None) -> dict[str, float]:
        if not isinstance(raw, dict):
            return {}
        clean: dict[str, float] = {}
        for key in ("estimated_cost_usd", "duration_seconds"):
            try:
                value = float(raw.get(key, 0) or 0)
            except (TypeError, ValueError):
                continue
            if 0 <= value <= 1_000_000:
                clean[key] = round(value, 6)
        return clean

    @staticmethod
    def overall(item: dict[str, Any]) -> str:
        outcomes = [result.get("outcome") for result in item.get("results", [])]
        if "failed" in outcomes:
            return "failed"
        if "blocked" in outcomes:
            return "blocked"
        return "passed"

    def _load(self) -> None:
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
            items = raw.get("executions", {}) if isinstance(raw, dict) else {}
            if isinstance(items, dict):
                self._items = {str(key): value for key, value in items.items() if isinstance(value, dict)}
        except (OSError, ValueError, TypeError):
            self._items = {}

    def _prune_locked(self) -> None:
        completed = sorted((item for item in self._items.values() if item.get("finished_at")),
                           key=lambda item: float(item.get("finished_at") or 0), reverse=True)
        remove = {item["id"] for item in completed[self.MAX_EXECUTIONS:]}
        if self.retention_seconds:
            cutoff = time.time() - self.retention_seconds
            remove.update(item["id"] for item in completed if float(item.get("finished_at") or 0) < cutoff)
        for execution_id in remove:
            self._items.pop(execution_id, None)

    def _save(self) -> None:
        private_dir(self.path.parent)
        temporary = self.path.with_suffix(".tmp")
        temporary.write_text(json.dumps({"version": self.VERSION, "executions": self._items},
                                        ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
        private_file(temporary)
        temporary.replace(self.path)
