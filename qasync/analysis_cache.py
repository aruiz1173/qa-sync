from __future__ import annotations

import copy
import hashlib
import json
import time
from pathlib import Path
from typing import Any

from .evidence import EvidenceCipher
from .errors import ValidationError
from .state import private_dir, private_file


class AnalysisCache:
    """Bounded, authenticated local cache for validated vision responses."""

    VERSION = 1
    TTL_SECONDS = 24 * 60 * 60
    MAX_ENTRIES = 100

    def __init__(self, root: Path, encoded_key: str, ttl_seconds: int | None = None):
        self.root = root
        self.cipher = EvidenceCipher(encoded_key)
        self.ttl_seconds = ttl_seconds or self.TTL_SECONDS
        self.metrics_path = self.root / "metrics.json"

    @staticmethod
    def fingerprint(payload: dict[str, Any]) -> str:
        canonical = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":"), default=str)
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def get(self, key: str) -> dict[str, Any] | None:
        path = self.root / f"{key}.qacache"
        try:
            raw = self.cipher.decrypt(path.read_bytes())
            item = json.loads(raw.decode("utf-8"))
        except (OSError, UnicodeDecodeError, ValueError, ValidationError):
            try:
                path.unlink()
            except OSError:
                pass
            return None
        if not isinstance(item, dict) or item.get("version") != self.VERSION or item.get("key") != key:
            return None
        try:
            expired = time.time() - float(item.get("created_at", 0)) > self.ttl_seconds
        except (TypeError, ValueError, OverflowError):
            expired = True
        if expired:
            try:
                path.unlink()
            except OSError:
                pass
            return None
        result = item.get("result")
        if not isinstance(result, dict):
            return None
        usage = result.get("_usage") if isinstance(result.get("_usage"), dict) else {}
        self._record_hit(max(1, int(usage.get("model_calls", 1) or 1)))
        return copy.deepcopy(result)

    def put(self, key: str, result: dict[str, Any]) -> None:
        private_dir(self.root)
        item = {"version": self.VERSION, "key": key, "created_at": time.time(), "result": result}
        payload = self.cipher.encrypt(json.dumps(item, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
        path = self.root / f"{key}.qacache"
        temporary = path.with_suffix(".tmp")
        temporary.write_bytes(payload)
        private_file(temporary)
        temporary.replace(path)
        self._prune()

    def _prune(self) -> None:
        try:
            entries = sorted(self.root.glob("*.qacache"), key=lambda path: path.stat().st_mtime, reverse=True)
        except OSError:
            return
        cutoff = time.time() - self.ttl_seconds
        for index, path in enumerate(entries):
            try:
                if index >= self.MAX_ENTRIES or path.stat().st_mtime < cutoff:
                    path.unlink()
            except OSError:
                pass

    def stats(self) -> dict[str, Any]:
        now = time.time()
        entries = []
        for path in self.root.glob("*.qacache") if self.root.exists() else []:
            try:
                entries.append({"key": path.stem, "bytes": path.stat().st_size,
                                "expires_at": int(path.stat().st_mtime + self.ttl_seconds)})
            except OSError:
                continue
        metrics = self._load_metrics()
        ordered = sorted(entries, key=lambda item: item["expires_at"])
        return {"entries": len(entries), "bytes": sum(item["bytes"] for item in entries),
                "ttl_seconds": self.ttl_seconds, "cache_hits": metrics["cache_hits"],
                "model_calls_avoided": metrics["model_calls_avoided"],
                "next_expiry": ordered[0]["expires_at"] if ordered else None, "items": ordered}

    def clear(self) -> int:
        removed = 0
        for path in self.root.glob("*.qacache") if self.root.exists() else []:
            try:
                path.unlink()
                removed += 1
            except OSError:
                pass
        try:
            self.metrics_path.unlink()
        except OSError:
            pass
        return removed

    def _load_metrics(self) -> dict[str, int]:
        try:
            data = json.loads(self.metrics_path.read_text(encoding="utf-8"))
            return {"cache_hits": max(0, int(data.get("cache_hits", 0))),
                    "model_calls_avoided": max(0, int(data.get("model_calls_avoided", 0)))}
        except (OSError, ValueError, TypeError):
            return {"cache_hits": 0, "model_calls_avoided": 0}

    def _record_hit(self, model_calls: int) -> None:
        private_dir(self.root)
        metrics = self._load_metrics()
        metrics["cache_hits"] += 1
        metrics["model_calls_avoided"] += model_calls
        temporary = self.metrics_path.with_suffix(".tmp")
        try:
            temporary.write_text(json.dumps(metrics, separators=(",", ":")), encoding="utf-8")
            private_file(temporary)
            temporary.replace(self.metrics_path)
        except OSError:
            try:
                temporary.unlink()
            except OSError:
                pass
