"""Encrypted, per-journey checkpoints that outlive a provider-limit wait."""

from __future__ import annotations

import hashlib
import json
import re
import shutil
from pathlib import Path
from typing import Any

from .evidence import EvidenceCipher
from .errors import ValidationError
from .state import private_dir, private_file


class VisionCheckpoints:
    VERSION = 1

    def __init__(self, root: Path, encoded_key: str):
        self.root = root
        self.cipher = EvidenceCipher(encoded_key)

    def _folder(self, job_id: str) -> Path:
        if not re.fullmatch(r"[a-f0-9]{32}", job_id):
            raise ValidationError("The analysis checkpoint ID is invalid.")
        return self.root / job_id

    def _path(self, job_id: str, analysis_key: str, stage_id: str) -> Path:
        key = hashlib.sha256(f"{analysis_key}:{stage_id}".encode()).hexdigest()
        return self._folder(job_id) / f"{key}.qacp"

    def get(self, job_id: str, analysis_key: str, stage_id: str) -> dict[str, Any] | None:
        path = self._path(job_id, analysis_key, stage_id)
        try:
            data = json.loads(self.cipher.decrypt(path.read_bytes()).decode("utf-8"))
        except (OSError, UnicodeDecodeError, ValueError, ValidationError):
            return None
        if (not isinstance(data, dict) or data.get("version") != self.VERSION or
                data.get("analysis_key") != analysis_key or data.get("stage_id") != stage_id or
                not isinstance(data.get("value"), dict)):
            return None
        return data["value"]

    def put(self, job_id: str, analysis_key: str, stage_id: str, value: dict[str, Any]) -> None:
        path = self._path(job_id, analysis_key, stage_id)
        private_dir(path.parent)
        payload = {"version": self.VERSION, "analysis_key": analysis_key,
                   "stage_id": stage_id, "value": value}
        temporary = path.with_suffix(".tmp")
        temporary.write_bytes(self.cipher.encrypt(json.dumps(payload, ensure_ascii=False).encode("utf-8")))
        private_file(temporary)
        temporary.replace(path)

    def clear(self, job_id: str) -> None:
        folder = self._folder(job_id)
        if folder.is_dir():
            try:
                shutil.rmtree(folder)
            except OSError:
                # The saved draft/queue transition remains authoritative. An
                # encrypted orphan can be pruned later without replaying AI.
                pass

    def clear_all(self) -> int:
        count = 0
        if self.root.exists():
            for folder in self.root.iterdir():
                if folder.is_dir() and re.fullmatch(r"[a-f0-9]{32}", folder.name):
                    count += len(list(folder.glob("*.qacp")))
                    shutil.rmtree(folder)
        return count
