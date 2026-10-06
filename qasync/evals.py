from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any


def _normal(value: object) -> str:
    return re.sub(r"\s+", " ", str(value or "").strip().lower())


def score_case(expected: dict[str, Any], actual: dict[str, Any]) -> dict[str, Any]:
    expected_steps = expected.get("steps") if isinstance(expected.get("steps"), list) else []
    actual_steps = actual.get("steps") if isinstance(actual.get("steps"), list) else []
    expected_pairs = {(_normal(step.get("content")), _normal(step.get("expected"))) for step in expected_steps if isinstance(step, dict)}
    actual_pairs = {(_normal(step.get("content")), _normal(step.get("expected"))) for step in actual_steps if isinstance(step, dict)}
    matched = len(expected_pairs & actual_pairs)
    precision = matched / len(actual_pairs) if actual_pairs else (1.0 if not expected_pairs else 0.0)
    recall = matched / len(expected_pairs) if expected_pairs else 1.0
    return {
        "title_match": _normal(expected.get("title")) == _normal(actual.get("title")),
        "step_precision": round(precision, 4), "step_recall": round(recall, 4),
        "unsupported_steps": max(0, len(actual_pairs) - matched),
        "missing_steps": max(0, len(expected_pairs) - matched),
    }


def run_directory(root: Path) -> dict[str, Any]:
    results = []
    for path in sorted(root.glob("*.json")):
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict) or not isinstance(data.get("expected"), dict) or not isinstance(data.get("actual"), dict):
            continue
        results.append({"fixture": path.name, **score_case(data["expected"], data["actual"])})
    count = len(results)
    return {"fixtures": count, "results": results,
            "title_accuracy": round(sum(item["title_match"] for item in results) / count, 4) if count else None,
            "step_precision": round(sum(item["step_precision"] for item in results) / count, 4) if count else None,
            "step_recall": round(sum(item["step_recall"] for item in results) / count, 4) if count else None}
