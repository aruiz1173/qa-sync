from __future__ import annotations

import json
import os
import threading
import time
import uuid
from pathlib import Path
from typing import Any

from .errors import ValidationError
from .state import private_dir, private_file, state_root


class HistoryStore:
    """Local, atomic backups used to safely undo TestRail updates."""

    def __init__(self, root: Path | None = None):
        configured = os.getenv("QA_SYNC_HISTORY_DIR", "").strip()
        self.root = (root or (Path(configured) if configured else state_root() / "history")).resolve()
        self._lock = threading.Lock()

    def create(
        self,
        case_id: int,
        previous_fields: dict[str, Any],
        proposed_fields: dict[str, Any],
        metadata: dict[str, Any] | None = None,
    ) -> str:
        backup_id = uuid.uuid4().hex
        now = int(time.time())
        entry = {
            "version": 1,
            "id": backup_id,
            "case_id": case_id,
            "created_at": now,
            "updated_at": now,
            "state": "pending",
            "previous_fields": previous_fields,
            "proposed_fields": proposed_fields,
            "applied_fields": None,
            "metadata": metadata or {},
        }
        with self._lock:
            self._write(backup_id, entry)
        return backup_id

    def mark_applied(self, backup_id: str, applied_fields: dict[str, Any]) -> None:
        with self._lock:
            entry = self._load(backup_id)
            entry["state"] = "applied"
            entry["applied_fields"] = applied_fields
            entry["updated_at"] = int(time.time())
            self._write(backup_id, entry)

    def mark_rolled_back(self, backup_id: str) -> None:
        with self._lock:
            entry = self._load(backup_id)
            entry["state"] = "rolled_back"
            entry["updated_at"] = int(time.time())
            self._write(backup_id, entry)

    def get(self, backup_id: str) -> dict[str, Any]:
        with self._lock:
            return self._load(backup_id)

    def list(self, case_id: int, limit: int = 25) -> list[dict[str, Any]]:
        if not self.root.exists():
            return []
        items: list[dict[str, Any]] = []
        with self._lock:
            for path in self.root.glob("*.json"):
                try:
                    entry = json.loads(path.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError):
                    continue
                if entry.get("case_id") != case_id:
                    continue
                previous = entry.get("previous_fields") or {}
                proposed = entry.get("proposed_fields") or {}
                items.append({
                    "id": entry.get("id"),
                    "case_id": case_id,
                    "created_at": entry.get("created_at"),
                    "updated_at": entry.get("updated_at"),
                    "state": entry.get("state"),
                    "previous_title": previous.get("title", ""),
                    "proposed_title": proposed.get("title", ""),
                    "confirmation": f"RESTAURAR C{case_id}",
                })
        return sorted(items, key=lambda item: int(item.get("created_at") or 0), reverse=True)[:limit]

    def audit(self, limit: int = 1000) -> list[dict[str, Any]]:
        """Export-safe audit rows. Field bodies and credentials are intentionally omitted."""
        if not self.root.exists():
            return []
        rows: list[dict[str, Any]] = []
        with self._lock:
            for path in self.root.glob("*.json"):
                try:
                    entry = json.loads(path.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError):
                    continue
                if not isinstance(entry, dict):
                    continue
                previous = entry.get("previous_fields") or {}
                proposed = entry.get("applied_fields") or entry.get("proposed_fields") or {}
                metadata = entry.get("metadata") if isinstance(entry.get("metadata"), dict) else {}
                rows.append({
                    "audit_id": entry.get("id"), "case_id": entry.get("case_id"),
                    "created_at": entry.get("created_at"), "updated_at": entry.get("updated_at"),
                    "state": entry.get("state"), "previous_title": previous.get("title", ""),
                    "updated_title": proposed.get("title", ""),
                    "changed_fields": sorted(str(key) for key in proposed),
                    "platform": metadata.get("platform", ""), "device_id": metadata.get("device_id", ""),
                    "device_name": metadata.get("device_name", ""),
                    "device_version": metadata.get("device_version", ""),
                    "provider": metadata.get("provider", ""),
                    "target_config": metadata.get("target_config", ""),
                    # Lo que informó el proveedor al generar este caso, para poder
                    # sumar el consumo real en vez de estimarlo.
                    "usage": metadata.get("usage") if isinstance(metadata.get("usage"), dict) else {},
                })
        return sorted(rows, key=lambda item: int(item.get("created_at") or 0), reverse=True)[:limit]

    def _path(self, backup_id: str) -> Path:
        if len(backup_id) != 32 or any(character not in "0123456789abcdef" for character in backup_id):
            raise ValidationError("El identificador del respaldo es inválido.")
        return self.root / f"{backup_id}.json"

    def _load(self, backup_id: str) -> dict[str, Any]:
        try:
            entry = json.loads(self._path(backup_id).read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise ValidationError("El respaldo no existe o está dañado.") from exc
        if not isinstance(entry, dict) or entry.get("id") != backup_id:
            raise ValidationError("El respaldo no es válido.")
        return entry

    def _write(self, backup_id: str, entry: dict[str, Any]) -> None:
        private_dir(self.root)
        temporary = self._path(backup_id).with_suffix(".json.tmp")
        temporary.write_text(json.dumps(entry, indent=2, ensure_ascii=False), encoding="utf-8")
        private_file(temporary)
        temporary.replace(self._path(backup_id))
