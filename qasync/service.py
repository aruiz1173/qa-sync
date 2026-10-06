from __future__ import annotations

import secrets
import copy
import json
import sys
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .config import Config
from .deferred import DeferredQueue
from .appium import AppiumClient
from .analysis_cache import AnalysisCache
from .checkpoints import VisionCheckpoints
from .errors import ConfigurationError, ConflictError, ExternalServiceError, QASyncError, UsageLimitError, ValidationError
from .executables import TRUSTABLE_TOOLS, inspect_tool, trust_current_tool
from .execution import ExecutionStore
from .history import HistoryStore
from .recorder import RecorderManager
from .quality import FeedbackStore
from .state import private_dir, private_file, state_root
from .testrail import TestRailClient, normalize_case_id, normalize_run_id
from .sensitive import redact_known_values, redact_text
from .vision import PROMPT_VERSION, VisionAnalyzer


def _quarantine_corrupt_state(path: Path) -> None:
    """Keep damaged local work recoverable instead of silently overwriting it."""
    if not path.exists():
        return
    backup = path.with_name(f"{path.stem}.corrupt-{int(time.time())}{path.suffix}")
    try:
        path.replace(backup)
        private_file(backup)
    except OSError:
        pass


@dataclass
class Proposal:
    case_id: int
    platform: str
    current: dict[str, Any]
    changes: dict[str, Any]
    created_at: float
    confidence: float = 0.0
    warnings: list[str] | None = None
    provider_used: str = ""
    device_id: str = ""
    device_name: str = ""
    device_version: str = ""
    vision_quality: str = "high"
    target_config: str = ""
    usage: dict[str, int] | None = None
    environment: dict[str, str] | None = None
    prompt_version: int = 1
    evidence_session_id: str = ""
    evidence_links: list[int | None] | None = None
    revision: int = 0


class ProposalStore:
    SCHEMA_VERSION = 1
    def __init__(self, ttl_seconds: int = 1800, path: Path | None = None):
        self.ttl_seconds = ttl_seconds
        self.path = path
        self._items: dict[str, Proposal] = {}
        self._lock = threading.Lock()
        self._load()

    def put(self, proposal: Proposal) -> str:
        token = secrets.token_urlsafe(32)
        with self._lock:
            self._purge()
            self._items[token] = proposal
            self._save()
        return token

    def get(self, token: str, expected_revision: int | None = None) -> Proposal:
        with self._lock:
            self._purge()
            proposal = self._items.get(token)
            if proposal is not None and expected_revision is not None and proposal.revision != expected_revision:
                raise ConflictError("This proposal changed in another tab. Export your local edits before loading the latest version.")
        if proposal is None:
            raise ValidationError("That proposal expired or was already used. Analyse again.")
        return copy.deepcopy(proposal)

    def update(self, token: str, changes: dict[str, Any], evidence_links: list[int | None] | None = None,
               expected_revision: int | None = None) -> Proposal:
        with self._lock:
            self._purge()
            proposal = self._items.get(token)
            if proposal is None:
                raise ValidationError("That proposal expired or was already used. Analyse again.")
            if expected_revision is not None and proposal.revision != expected_revision:
                raise ConflictError("This proposal changed in another tab. Export your local edits before loading the latest version.")
            proposal.changes = copy.deepcopy(changes)
            if evidence_links is not None:
                proposal.evidence_links = copy.deepcopy(evidence_links)
            proposal.revision += 1
            self._save()
            return copy.deepcopy(proposal)

    def pop(self, token: str, expected_revision: int | None = None) -> Proposal:
        with self._lock:
            self._purge()
            proposal = self._items.get(token)
            if proposal is not None and expected_revision is not None and proposal.revision != expected_revision:
                raise ConflictError("This proposal changed in another tab. Export your local edits before updating TestRail.")
            proposal = self._items.pop(token, None)
            self._save()
        if proposal is None:
            raise ValidationError("That proposal expired or was already used. Analyse again.")
        return proposal

    def _purge(self) -> None:
        cutoff = time.time() - self.ttl_seconds
        before = len(self._items)
        self._items = {k: v for k, v in self._items.items() if v.created_at >= cutoff}
        if len(self._items) != before:
            self._save()

    def latest(self) -> tuple[str, Proposal] | None:
        with self._lock:
            self._purge()
            return max(self._items.items(), key=lambda item: item[1].created_at, default=None)

    def _load(self) -> None:
        if not self.path:
            return
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
            wrapped = isinstance(raw, dict) and "schema_version" in raw
            items = raw.get("proposals", {}) if wrapped else raw
            if not isinstance(items, dict):
                return
            for token, item in items.items():
                if isinstance(item, dict):
                    self._items[token] = Proposal(**item)
            self._purge()
            if not wrapped:
                self._save()
        except (OSError, ValueError, TypeError):
            _quarantine_corrupt_state(self.path)
            self._items = {}

    def _save(self) -> None:
        if not self.path:
            return
        private_dir(self.path.parent)
        temporary = self.path.with_suffix(".tmp")
        proposals = {token: {
            "case_id": item.case_id, "platform": item.platform, "current": item.current,
            "changes": item.changes, "created_at": item.created_at,
            "confidence": item.confidence, "warnings": item.warnings or [],
            "provider_used": item.provider_used, "device_id": item.device_id,
            "device_name": item.device_name, "device_version": item.device_version,
            "vision_quality": item.vision_quality,
            "target_config": item.target_config,
            "usage": item.usage or {},
            "environment": item.environment or {},
            "prompt_version": item.prompt_version,
            "evidence_session_id": item.evidence_session_id,
            "evidence_links": item.evidence_links or [],
            "revision": item.revision,
        } for token, item in self._items.items()}
        payload = {"schema_version": self.SCHEMA_VERSION, "proposals": proposals}
        temporary.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
        private_file(temporary)
        temporary.replace(self.path)


def _proposal_revision(request: dict[str, Any]) -> int | None:
    value = request.get("revision")
    if value is None:
        return None
    if type(value) is not int or value < 0:
        raise ValidationError("The proposal revision is invalid.")
    return value


class DraftStore:
    """Named work in progress that outlives a proposal.

    A proposal expires in 30 minutes and is single use, which is right for something
    about to be written to TestRail but loses the work of anyone interrupted. A draft
    has no expiry, can be reopened as often as needed and never writes anywhere.
    """

    MAX_DRAFTS = 200
    SCHEMA_VERSION = 1

    def __init__(self, path: Path | None = None, retention_days: int = 0):
        self.path = path
        self.retention_seconds = retention_days * 86400
        self._items: dict[str, dict[str, Any]] = {}
        self._lock = threading.Lock()
        self._load()

    @staticmethod
    def deferred_id(item_id: str) -> str:
        return uuid.uuid5(uuid.NAMESPACE_URL, f"qa-sync-deferred:{item_id}").hex

    def save(self, name: str, proposal: Proposal, draft_id: str = "", expected_updated_at: object = None,
             idempotency_key: str = "") -> str:
        clean = " ".join(str(name or "").split())[:80]
        if not clean:
            raise ValidationError("Give the draft a name so you can find it later.")
        with self._lock:
            self._purge_locked()
            if idempotency_key:
                draft_id = self.deferred_id(idempotency_key)
                if draft_id in self._items:
                    return draft_id
            if not draft_id or draft_id not in self._items:
                if len(self._items) >= self.MAX_DRAFTS:
                    raise ValidationError(
                        f"There are already {self.MAX_DRAFTS} drafts. Delete one before saving another."
                    )
                draft_id = draft_id if idempotency_key else uuid.uuid4().hex
                created_at = time.time()
            else:
                current_updated = float(self._items[draft_id].get("updated_at", 0))
                if expected_updated_at not in (None, ""):
                    try:
                        expected = float(expected_updated_at)
                    except (TypeError, ValueError) as exc:
                        raise ValidationError("The draft revision is invalid.") from exc
                    if expected != current_updated:
                        raise ValidationError("This draft changed in another window. Reopen it before saving.")
                created_at = float(self._items[draft_id].get("created_at", time.time()))
            self._items[draft_id] = {
                "id": draft_id, "name": clean, "created_at": created_at, "updated_at": time.time(),
                "case_id": proposal.case_id, "platform": proposal.platform,
                "target_config": proposal.target_config,
                "device_name": proposal.device_name, "device_version": proposal.device_version,
                "confidence": proposal.confidence, "warnings": proposal.warnings or [],
                "provider_used": proposal.provider_used, "vision_quality": proposal.vision_quality,
                "current": proposal.current, "changes": proposal.changes,
                "usage": proposal.usage or {},
                "environment": proposal.environment or {},
                "prompt_version": proposal.prompt_version,
                "evidence_session_id": proposal.evidence_session_id,
                "evidence_links": proposal.evidence_links or [],
            }
            self._save()
        return draft_id

    def list(self) -> list[dict[str, Any]]:
        with self._lock:
            self._purge_locked()
            items = sorted(self._items.values(), key=lambda item: item.get("updated_at", 0), reverse=True)
        # El cuerpo del caso no viaja al listado: sólo lo suficiente para reconocerlo.
        return [{
            "id": item["id"], "name": item["name"], "case_id": item["case_id"],
            "platform": item["platform"], "target_config": item.get("target_config", ""),
            "device_name": item.get("device_name", ""),
            "device_version": item.get("device_version", ""),
            "updated_at": item.get("updated_at", 0),
            "usage": item.get("usage", {}),
            "steps": len(item.get("changes", {}).get(
                next((key for key in item.get("changes", {}) if key.startswith("custom_steps")), ""), []
            ) or []),
        } for item in items]

    def export(self, case_id: int | None = None) -> list[dict[str, Any]]:
        """Return complete local drafts only for an explicit file export.

        The regular list intentionally excludes bodies.  This separate path
        includes the proposed fields so a person can archive or share the
        draft file deliberately, while omitting the prior TestRail case and
        environment metadata that are not needed to continue editing.
        """
        with self._lock:
            self._purge_locked()
            items = sorted(self._items.values(), key=lambda item: item.get("updated_at", 0), reverse=True)
        exported: list[dict[str, Any]] = []
        for item in items:
            if case_id is not None and int(item.get("case_id") or 0) != case_id:
                continue
            exported.append({
                key: copy.deepcopy(item.get(key))
                for key in ("id", "name", "created_at", "updated_at", "case_id", "platform",
                            "target_config", "device_name", "device_version", "confidence", "warnings",
                            "provider_used", "vision_quality", "usage", "prompt_version", "changes")
            })
        return exported

    def get(self, draft_id: str) -> dict[str, Any]:
        with self._lock:
            self._purge_locked()
            item = self._items.get(str(draft_id))
        if item is None:
            raise ValidationError("That draft no longer exists.")
        return copy.deepcopy(item)

    def delete(self, draft_id: str, expected_updated_at: object = None) -> None:
        with self._lock:
            self._purge_locked()
            item = self._items.get(str(draft_id))
            if item is None:
                raise ValidationError("That draft no longer exists.")
            if expected_updated_at not in (None, ""):
                try:
                    expected = float(expected_updated_at)
                except (TypeError, ValueError) as exc:
                    raise ValidationError("The draft revision is invalid.") from exc
                if expected != float(item.get("updated_at", 0)):
                    raise ValidationError("This draft changed in another window. Reopen it before deleting.")
            self._items.pop(str(draft_id))
            self._save()

    def _purge_locked(self) -> None:
        if not self.retention_seconds:
            return
        cutoff = time.time() - self.retention_seconds
        kept = {key: value for key, value in self._items.items() if float(value.get("updated_at", 0)) >= cutoff}
        if len(kept) != len(self._items):
            self._items = kept
            self._save()

    def _load(self) -> None:
        if not self.path:
            return
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
            wrapped = isinstance(raw, dict) and "schema_version" in raw
            items = raw.get("drafts", {}) if wrapped else raw
            if not isinstance(items, dict):
                return
            self._items = {
                str(key): value for key, value in items.items()
                if isinstance(value, dict) and value.get("id") == key
            }
            if not wrapped:
                self._save()
        except (OSError, ValueError, AttributeError):
            _quarantine_corrupt_state(self.path)
            self._items = {}

    def _save(self) -> None:
        if not self.path:
            return
        private_dir(self.path.parent)
        temporary = self.path.with_suffix(".tmp")
        temporary.write_text(json.dumps({"schema_version": self.SCHEMA_VERSION, "drafts": self._items}, ensure_ascii=False), encoding="utf-8")
        private_file(temporary)
        temporary.replace(self.path)


class QASyncService:
    def __init__(
        self,
        config: Config,
        store: ProposalStore | None = None,
        recorder: RecorderManager | None = None,
        history: HistoryStore | None = None,
    ):
        self.config = config
        state_dir = state_root()
        self.store = store or ProposalStore(path=state_dir / "proposals.json")
        self.drafts = DraftStore(path=state_dir / "drafts.json", retention_days=config.draft_retention_days)
        self.recorder = recorder or RecorderManager(
            interval=config.capture_interval,
            max_frames=config.max_images,
            max_duration=config.max_recording_seconds,
            appium_url=config.appium_url,
            ios_bundle_id=config.ios_bundle_id,
            appium_capabilities_json=config.appium_capabilities_json,
            ios_devices_json=config.ios_devices_json,
            developer_dir=config.developer_dir,
            evidence_key=config.evidence_key,
            recovery_dir=state_dir / "recovery",
            recovery_ttl_seconds=config.capture_retention_hours * 3600,
        )
        self.history = history or HistoryStore(state_dir / "history", retention_days=config.history_retention_days)
        self.analysis_cache = AnalysisCache(
            state_dir / "analysis-cache", config.evidence_key,
            ttl_seconds=config.cache_retention_hours * 3600,
        )
        self.vision_checkpoints = VisionCheckpoints(state_dir / "vision-checkpoints", config.evidence_key)
        self.feedback = FeedbackStore(state_dir / "quality-feedback.json")
        self.executions = ExecutionStore(state_dir / "executions.json", retention_days=config.history_retention_days)
        self.deferred = DeferredQueue(state_dir / "deferred.json")
        self._deferred_start_lock = threading.Lock()
        self._deferred_wake = threading.Event()
        self._deferred_worker: threading.Thread | None = None
        with self._deferred_start_lock:
            self._ensure_deferred_worker()

    def devices(self) -> dict[str, Any]:
        return self.recorder.list_devices()

    def launch_android_emulator(self, request: dict[str, Any]) -> dict[str, str]:
        return self.recorder.launch_android_emulator(request.get("avd_name"))

    def launch_ios_simulator(self, request: dict[str, Any]) -> dict[str, str]:
        return self.recorder.launch_ios_simulator(request.get("simulator_id"))

    def providers(self) -> dict[str, Any]:
        providers = [VisionAnalyzer.provider_status(name) for name in ("codex", "claude")]
        providers.append({
            "provider": "openai_api", "installed": True,
            "authenticated": bool(self.config.openai_api_key),
            "remaining": None, "remaining_available": False,
        })
        return {
            "providers": providers,
            "usage_note": "Providers do not expose a verifiable remaining percentage here; QA Sync shows available or not and never invents a balance.",
            "fallback_authorized": self.config.allow_provider_fallback,
            "fallback_provider": self.config.fallback_provider,
        }

    def preflight(self) -> dict[str, Any]:
        """Read-only readiness check shown before someone starts a journey."""
        checks: list[dict[str, str]] = []
        if not self.config.testrail_ready:
            checks.append({"name": "TestRail", "status": "blocked", "detail": "Add the TestRail URL, email and API key in Settings."})
        else:
            try:
                count = len(TestRailClient(self.config).get_projects())
                checks.append({"name": "TestRail", "status": "ready", "detail": f"Connected; {count} active projects are visible."})
            except QASyncError as exc:
                checks.append({"name": "TestRail", "status": "blocked", "detail": self._safe_diagnostic_text(exc)[:400]})

        provider = self.config.vision_provider
        if provider not in {"codex", "claude", "openai_api"}:
            checks.append({"name": "Vision", "status": "blocked", "detail": "Choose Codex, Claude or OpenAI API in Settings."})
        elif provider == "openai_api":
            checks.append({"name": "Vision", "status": "ready" if self.config.openai_api_key else "blocked", "detail": "OpenAI API key is configured." if self.config.openai_api_key else "Add an OpenAI API key in Settings."})
        else:
            status = VisionAnalyzer.provider_status(provider)
            ready = bool(status["installed"] and status["authenticated"])
            checks.append({"name": "Vision", "status": "ready" if ready else "blocked", "detail": f"{provider.title()} is ready." if ready else f"Install or sign in to {provider.title()} CLI."})

        devices = self.recorder.list_devices(force=True)
        caps = devices.get("capabilities", {})
        android_ready = bool(caps.get("adb") and caps.get("scrcpy"))
        checks.append({"name": "Android", "status": "ready" if android_ready else "blocked", "detail": f"{len(devices.get('android', []))} connected device(s); {len(devices.get('android_avds', []))} AVD(s) available." if android_ready else self._safe_diagnostic_text(next((item for item in devices.get("errors", []) if item.startswith("Android:")), "ADB and scrcpy must be available."))})
        ios_ready = bool(caps.get("simctl") or caps.get("appium"))
        checks.append({"name": "iOS", "status": "ready" if ios_ready else "attention", "detail": f"{len(devices.get('ios', []))} booted/remote device(s); {len(devices.get('ios_simulators', []))} simulator(s) available." if ios_ready else "Install Xcode on macOS or configure remote Appium."})
        return {"ready": not any(item["status"] == "blocked" for item in checks), "checks": checks}

    def _safe_diagnostic_text(self, value: object) -> str:
        text = str(value)
        for secret in (self.config.openai_api_key, self.config.testrail_api_key, self.config.evidence_key):
            if secret and len(secret) >= 4:
                text = text.replace(secret, "[REDACTED]")
        return redact_text(text)

    def trusted_tools(self) -> dict[str, Any]:
        """Candidates are informational until the person using this machine approves one."""
        return {"tools": [inspect_tool(name) for name in sorted(TRUSTABLE_TOOLS)]}

    def trust_tool(self, request: dict[str, Any]) -> dict[str, Any]:
        try:
            tool = trust_current_tool(str(request.get("name", "")), request.get("sha256"))
        except ValueError as exc:
            raise ValidationError(str(exc)) from exc
        return {"tool": tool}

    def cache_status(self) -> dict[str, Any]:
        return self.analysis_cache.stats()

    def clear_analysis_cache(self) -> dict[str, Any]:
        return {"cleared": self.analysis_cache.clear(), **self.analysis_cache.stats()}

    def save_feedback(self, request: dict[str, Any]) -> dict[str, Any]:
        proposal = self.store.get(str(request.get("proposal_token", "")))
        entries = request.get("entries")
        if not isinstance(entries, list):
            raise ValidationError("Feedback entries must be a list.")
        saved = self.feedback.add(proposal.case_id, proposal.provider_used, proposal.confidence, entries, proposal.prompt_version)
        return {"saved": saved, "metrics": self.quality_metrics()["quality"]}

    def quality_metrics(self) -> dict[str, Any]:
        rows = self.history.audit()
        usage = self._spend_summary(rows)
        return {"quality": {**self.feedback.metrics(), "usage": usage,
                            "execution": self.executions.metrics(), "prompt_version": PROMPT_VERSION}}

    def projects(self) -> dict[str, Any]:
        projects = TestRailClient(self.config).get_projects()
        return {
            "projects": [
                {"id": item.get("id"), "name": item.get("name", f"Project {item.get('id')}")}
                for item in projects
            ],
            "preferred_project_id": self.config.testrail_project_id,
        }

    def validate_configuration(self) -> dict[str, Any]:
        if not self.config.testrail_ready:
            raise ConfigurationError("Set up TestRail before validating the fields.")
        result = TestRailClient(self.config).validate_configuration()
        provider = self.config.vision_provider
        result["vision"] = {"provider": provider, "ready": False}
        if not provider:
            result["errors"].append("Pick Codex, Claude or the OpenAI API as the vision provider.")
        elif provider == "openai_api":
            result["vision"] = {"provider": provider, "ready": bool(self.config.openai_api_key)}
            if not self.config.openai_api_key:
                result["errors"].append("The OpenAI API key is missing for the selected provider.")
        else:
            status = VisionAnalyzer.provider_status(provider)
            result["vision"] = {**status, "ready": status["installed"] and status["authenticated"]}
            if not status["installed"]:
                result["errors"].append(f"{provider.title()} CLI is not installed.")
            elif not status["authenticated"]:
                result["errors"].append(f"Sign in to {provider.title()} CLI and validate again.")
        result["appium"] = {"configured": self.config.appium_ready, "ready": False}
        if self.config.appium_ready:
            try:
                status = AppiumClient(
                    self.config.appium_url,
                    self.config.ios_bundle_id,
                    self.config.appium_capabilities_json,
                ).status()
                result["appium"] = {"configured": True, **status}
                if not status["ready"]:
                    result["warnings"].append("Appium is connected but not ready.")
            except ExternalServiceError as exc:
                result["warnings"].append(f"Appium is not available yet: {exc}")
        result["valid"] = not result["errors"]
        return result

    RUN_FIELDS = (
        "id", "name", "description", "created_on", "is_completed", "url",
        "passed_count", "blocked_count", "untested_count", "retest_count",
        "failed_count", "custom_status1_count", "custom_status2_count",
        "plan_id", "suite_id", "entry_name", "project_id", "config", "config_ids",
    )

    def _public_run(self, run: dict[str, Any]) -> dict[str, Any]:
        return {key: run.get(key) for key in self.RUN_FIELDS}

    def runs(self, request: dict[str, Any]) -> dict[str, Any]:
        project_id = normalize_case_id(request.get("project_id"))
        client = TestRailClient(self.config)
        runs = [self._public_run(item) for item in client.get_runs(project_id)]
        plans = [
            {"id": item.get("id"), "name": item.get("name"), "is_completed": item.get("is_completed"),
             "passed_count": item.get("passed_count"), "blocked_count": item.get("blocked_count"),
             "untested_count": item.get("untested_count"), "retest_count": item.get("retest_count"),
             "failed_count": item.get("failed_count")}
            for item in client.get_plans(project_id)
        ]
        return {"runs": runs, "plans": plans}

    def device_configs(self, request: dict[str, Any]) -> dict[str, Any]:
        """Configuraciones del proyecto, tal como están definidas en TestRail.

        La lista de dispositivos no se mantiene en la app a propósito: cada proyecto
        trae la suya y un dispositivo nuevo aparece sin tocar código ni ajustes.
        """
        project_id = normalize_case_id(request.get("project_id"))
        groups = TestRailClient(self.config).get_configs(project_id)
        return {"groups": [{
            "id": group.get("id"),
            "name": str(group.get("name", "")),
            "options": [
                {"id": item.get("id"), "name": str(item.get("name", ""))}
                for item in group.get("configs", []) if isinstance(item, dict)
            ],
        } for group in groups]}

    def plan_runs(self, request: dict[str, Any]) -> dict[str, Any]:
        plan_id = normalize_case_id(request.get("plan_id"))
        runs = TestRailClient(self.config).get_plan_runs(plan_id)
        return {"runs": [self._public_run(item) for item in runs]}

    def run(self, request: dict[str, Any]) -> dict[str, Any]:
        run_id = normalize_run_id(request.get("run_id"))
        return {"run": self._public_run(TestRailClient(self.config).get_run(run_id))}

    def tests(self, request: dict[str, Any]) -> dict[str, Any]:
        run_id = normalize_case_id(request.get("run_id"))
        tests = TestRailClient(self.config).get_tests(run_id)
        fields = ("id", "case_id", "title", "status_id", "priority_id", "refs", "assignedto_id")
        return {"tests": [{key: item.get(key) for key in fields} for item in tests]}

    def case(self, request: dict[str, Any]) -> dict[str, Any]:
        case_id = normalize_case_id(request.get("case_id"))
        current = TestRailClient(self.config).get_case(case_id)
        fields = ("id", "title", "refs", "priority_id", "type_id", "estimate", "updated_on")
        result = {key: current.get(key) for key in fields}
        result["preconditions"] = current.get(self.config.testrail_preconditions_field)
        result["steps"] = current.get(self.config.testrail_steps_field) or []
        return {"case": result}

    def open_device(self, request: dict[str, Any]) -> dict[str, bool]:
        self.recorder.open_device(
            str(request.get("platform", "")), str(request.get("device_id", ""))
        )
        return {"opened": True}

    def close_mirror(self, request: dict[str, Any]) -> dict[str, bool]:
        return self.recorder.close_mirror(str(request.get("device_id", "")))

    def disconnect_android_wireless(self, request: dict[str, Any]) -> dict[str, Any]:
        return self.recorder.disconnect_android_wireless(request.get("endpoint"))

    def enable_android_tcpip(self, request: dict[str, Any]) -> dict[str, Any]:
        return self.recorder.enable_android_tcpip(request.get("device_id"), request.get("port", 5555))

    def discover_android_wireless(self) -> dict[str, Any]:
        return self.recorder.discover_android_wireless()

    def connect_android_wireless(self, request: dict[str, Any]) -> dict[str, Any]:
        return self.recorder.connect_android_wireless(
            request.get("host", ""), request.get("port", ""), request.get("pairing_code", ""),
        )

    def start_recording(self, request: dict[str, Any]) -> dict[str, Any]:
        case_value = request.get("case_id")
        return self.recorder.start(
            str(request.get("platform", "")), str(request.get("device_id", "")),
            normalize_case_id(case_value) if case_value not in (None, "") else None,
            {
                "package": request.get("package", ""),
                "deep_link": request.get("deep_link", ""),
                "reset_data": request.get("reset_data") is True,
            },
        )

    def recording_status(self, request: dict[str, Any]) -> dict[str, Any]:
        return self.recorder.status(str(request.get("session_id", "")))

    def recording_screenshot(self, request: dict[str, Any]) -> dict[str, Any]:
        return self.recorder.live_screenshot(str(request.get("session_id", "")))

    def recording_evidence_preview(self, request: dict[str, Any]) -> dict[str, Any]:
        return self.recorder.evidence_preview(
            str(request.get("session_id", "")), self.config.ai_max_images
        )

    def export_recording_evidence(self, request: dict[str, Any]) -> dict[str, Any]:
        selected = request.get("selected_frames")
        return self.recorder.export_evidence(str(request.get("session_id", "")), selected)

    def import_recording_evidence(self, request: dict[str, Any]) -> dict[str, Any]:
        case_value = request.get("case_id")
        case_id = normalize_case_id(case_value) if case_value not in (None, "") else None
        return self.recorder.import_evidence(request.get("evidence"), case_id)

    def recording_locators(self, request: dict[str, Any]) -> dict[str, Any]:
        return self.recorder.ui_locators(str(request.get("session_id", "")))

    def recording_action(self, request: dict[str, Any]) -> dict[str, Any]:
        return self.recorder.perform_action(str(request.get("session_id", "")), request)

    def start_execution(self, request: dict[str, Any]) -> dict[str, Any]:
        run_id = normalize_run_id(request.get("run_id"))
        test_id = normalize_case_id(request.get("test_id"))
        case_id = normalize_case_id(request.get("case_id"))
        client = TestRailClient(self.config)
        test = next((item for item in client.get_tests(run_id) if item.get("id") == test_id), None)
        if not test or int(test.get("case_id") or 0) != case_id:
            raise ValidationError("That test does not belong to the selected run and case.")
        current = client.get_case(case_id)
        steps = current.get(self.config.testrail_steps_field) or []
        recording = self.recorder.start(
            str(request.get("platform", "")), str(request.get("device_id", "")), case_id,
            {"package": request.get("package", ""), "deep_link": request.get("deep_link", ""),
             "reset_data": request.get("reset_data") is True},
        )
        try:
            execution = self.executions.create(
                recorder_session_id=recording["session_id"], run_id=run_id, test_id=test_id,
                case_id=case_id, platform=str(request.get("platform", "")),
                device_id=str(request.get("device_id", "")), steps=steps,
                offline=request.get("offline") is True,
            )
            self.recorder.capture_checkpoint(recording["session_id"], "step-0-before", settle=True)
        except Exception:
            self.recorder.cancel(recording["session_id"])
            if "execution" in locals():
                self.executions.cancel(execution["id"])
            raise
        return {"execution": execution}

    def execution_status(self, request: dict[str, Any]) -> dict[str, Any]:
        execution = self.executions.public(str(request.get("execution_id", "")))
        try:
            recorder = self.recorder.status(str(execution["recorder_session_id"]))
        except ValidationError:
            recorder = {"stopped": True, "error": "The device recording expired."}
        return {"execution": execution, "recorder": recorder}

    def verify_execution_step(self, request: dict[str, Any]) -> dict[str, Any]:
        execution_id = str(request.get("execution_id", ""))
        execution = self.executions.get(execution_id)
        if execution.get("state") != "running":
            raise ValidationError("That execution is not running.")
        if execution.get("offline") is True:
            raise ValidationError("AI verification is disabled for this capture-only execution. Finish it manually and review the saved screens in AI queue later.")
        try:
            step_index = int(request.get("step_index"))
        except (TypeError, ValueError) as exc:
            raise ValidationError("Choose a valid execution step.") from exc
        if isinstance(request.get("step_index"), bool) or not 0 <= step_index < len(execution["steps"]):
            raise ValidationError("That execution step does not exist.")
        recorder_id = str(execution["recorder_session_id"])
        try:
            baseline = self.recorder.checkpoint(recorder_id, f"step-{step_index}-before")
        except ValidationError:
            self.recorder.capture_checkpoint(recorder_id, f"step-{step_index}-before", settle=True)
            raise ValidationError(
                "This step had no usable baseline. A new baseline was captured; repeat the action before verifying."
            )
        after = self.recorder.capture_checkpoint(recorder_id, f"step-{step_index}-after", settle=True)
        step = execution["steps"][step_index]
        result = VisionAnalyzer(self.config).verify_step(
            platform=str(execution["platform"]), image={"type": after["type"], "data": after["data"]},
            before_image={"type": baseline["type"], "data": baseline["data"]},
            action=str(step["content"]), expected=str(step["expected"]),
            before_semantic_context=str(baseline.get("semantic", "")),
            semantic_context=str(after.get("semantic", "")),
            stable=bool(baseline.get("stable") and after.get("stable")),
        )
        stable = bool(baseline.get("stable") and after.get("stable"))
        final = stable and result["verdict"] in {"passed", "failed"} and result["confidence"] >= self.config.min_verification_confidence
        outcome = result["verdict"] if final else "needs_review"
        reason = result["reason"]
        if not stable:
            reason = f"Screen did not stabilize before timeout. {reason}"[:1000]
        updated = self.executions.record(
            execution_id, step_index, outcome, reason, source="ai",
            confidence=result["confidence"], observed=result["observed"], provider=result["provider_used"],
            evidence={"baseline_stable": baseline.get("stable"), "after_stable": after.get("stable"),
                      "settle_seconds": after.get("settle_seconds", 0)},
            usage=result.get("usage"),
        )
        next_warning = ""
        if outcome in {"passed", "failed"} and not updated["complete"]:
            try:
                self.recorder.capture_checkpoint(recorder_id, f"step-{updated['current_index']}-before", settle=True)
            except (ValidationError, ExternalServiceError) as exc:
                next_warning = f"The next-step baseline could not be captured: {exc}"
        return {"verification": {**result, "outcome": outcome,
                                 "threshold": self.config.min_verification_confidence,
                                 "stable": stable, "settle_seconds": after.get("settle_seconds", 0)},
                "execution": updated, "warning": next_warning}

    def set_execution_verdict(self, request: dict[str, Any]) -> dict[str, Any]:
        raw_index = request.get("step_index")
        try:
            step_index = int(raw_index)
        except (TypeError, ValueError) as exc:
            raise ValidationError("Choose a valid execution step.") from exc
        if isinstance(raw_index, bool):
            raise ValidationError("Choose a valid execution step.")
        outcome = str(request.get("outcome", ""))
        reason = str(request.get("reason", ""))
        execution_id = str(request.get("execution_id", ""))
        execution = self.executions.get(execution_id)
        if not 0 <= step_index < len(execution.get("steps", [])):
            raise ValidationError("That execution step does not exist.")
        if outcome == "skipped" and not execution["steps"][step_index].get("optional"):
            raise ValidationError("Only a step marked Optional can be skipped.")
        if outcome in {"failed", "blocked"} and not reason.strip():
            raise ValidationError("A failed or blocked step needs a reason.")
        capture_warning = ""
        if outcome != "skipped":
            try:
                self.recorder.capture_checkpoint(str(execution["recorder_session_id"]),
                                                 f"step-{step_index}-after", settle=False)
            except (ValidationError, ExternalServiceError) as exc:
                capture_warning = f"The final screen for this step could not be captured: {exc}"
        updated = self.executions.record(
            execution_id, step_index, outcome, reason,
            source="manual", observed="Manual reviewer decision.",
        )
        next_warning = capture_warning
        if not updated["complete"]:
            try:
                self.recorder.capture_checkpoint(str(updated["recorder_session_id"]),
                                                 f"step-{updated['current_index']}-before", settle=True)
            except (ValidationError, ExternalServiceError) as exc:
                next_warning = f"{next_warning} The next-step baseline could not be captured: {exc}".strip()
        return {"execution": updated, "warning": next_warning}

    @staticmethod
    def _execution_comment(execution: dict[str, Any]) -> str:
        labels = {"passed": "PASSED", "failed": "FAILED", "blocked": "BLOCKED", "skipped": "SKIPPED"}
        lines = ["QA Sync deterministic device execution", f"Execution: {execution['id']}",
                 f"Platform: {execution['platform']}"]
        for result in execution.get("results", []):
            reason = str(result.get("reason", "")).replace("\n", " ")[:500]
            lines.append(f"Step {int(result['step_index']) + 1}: {labels.get(result.get('outcome'), 'REVIEW')}"
                         + (f" — {reason}" if reason else ""))
        return "\n".join(lines)[:8000]

    def finish_execution(self, request: dict[str, Any]) -> dict[str, Any]:
        execution_id = str(request.get("execution_id", ""))
        execution = self.executions.get(execution_id)
        final_indices = {result.get("step_index") for result in execution.get("results", [])
                         if result.get("outcome") in {"passed", "failed", "blocked", "skipped"}}
        if len(final_indices) != len(execution.get("steps", [])):
            raise ValidationError("Every step needs a final verdict before finishing.")
        overall = ExecutionStore.overall(execution)
        published, result_id, client, status_id = False, None, None, None
        if request.get("publish") is True:
            if self.config.write_mode == "review_only":
                raise ValidationError("QA Sync is in dry run mode; the result cannot be published.")
            expected = f"PUBLICAR T{execution['test_id']}"
            if request.get("confirmation") != expected:
                raise ValidationError(f"Type exactly: {expected}")
            client = TestRailClient(self.config)
            statuses = client.get_statuses()
            wanted = {"passed": "passed", "failed": "failed", "blocked": "blocked"}[overall]
            status = next((item for item in statuses if str(item.get("name", "")).strip().lower() == wanted
                           or str(item.get("system_name", "")).strip().lower() == wanted), None)
            if not status or not isinstance(status.get("id"), int):
                raise ValidationError(f"TestRail has no '{wanted}' status available for publishing.")
            status_id = int(status["id"])
        self.recorder.stop(str(execution["recorder_session_id"]))
        deferred = None
        if request.get("defer_analysis") is True:
            session_id = str(execution["recorder_session_id"])
            self.recorder.include_execution_checkpoints(session_id)
            self.recorder.protect(session_id)
            context = self._execution_comment(execution)
            deferred = self.deferred.add(session_id=session_id, case_id=int(execution["case_id"]),
                                         platform=str(execution["platform"]),
                                         run_id=int(execution["run_id"]), test_id=int(execution["test_id"]),
                                         context=context)
        if client and status_id:
            try:
                response = client.add_result_for_test(int(execution["test_id"]), status_id,
                                                      self._execution_comment(execution))
                published, result_id = True, response.get("id")
            except ExternalServiceError:
                uncertain = self.executions.mark_publish_unknown(execution_id, overall)
                if deferred is None:
                    self.recorder.discard(str(execution["recorder_session_id"]))
                return {"execution": uncertain, "overall": overall, "published": False,
                        "publish_unknown": True,
                        "warning": "TestRail did not confirm whether it saved the result. Check the test before publishing again."}
        finished = self.executions.finish(execution_id, overall, published, result_id)
        if deferred is None:
            self.recorder.discard(str(execution["recorder_session_id"]))
        return {"execution": finished, "overall": overall, "published": published,
                "deferred": deferred}

    def cancel_execution(self, request: dict[str, Any]) -> dict[str, Any]:
        execution_id = str(request.get("execution_id", ""))
        execution = self.executions.get(execution_id)
        try:
            self.recorder.cancel(str(execution["recorder_session_id"]))
        except ValidationError:
            pass
        return {"execution": self.executions.cancel(execution_id)}

    def reconcile_execution_publication(self, request: dict[str, Any]) -> dict[str, Any]:
        execution_id = str(request.get("execution_id", ""))
        execution = self.executions.get(execution_id)
        if execution.get("state") != "publish_unknown":
            raise ValidationError("That execution has no uncertain publication to reconcile.")
        results = TestRailClient(self.config).get_results_for_test(int(execution["test_id"]))
        marker = f"Execution: {execution_id}"
        match = next((result for result in results if marker in str(result.get("comment", ""))), None)
        reconciled = self.executions.reconcile_publication(execution_id, match.get("id") if match else None)
        return {"execution": reconciled, "found": bool(match), "result_id": match.get("id") if match else None}

    def execution_report(self, request: dict[str, Any]) -> dict[str, Any]:
        return {"version": 1, "generated_at": int(time.time()),
                "execution": self.executions.report(str(request.get("execution_id", "")))}

    def stop_recording(self, request: dict[str, Any]) -> dict[str, Any]:
        return self.recorder.stop(str(request.get("session_id", "")))

    def cancel_recording(self, request: dict[str, Any]) -> dict[str, Any]:
        self.recorder.cancel(str(request.get("session_id", "")))
        return {"cancelled": True}

    def analyze_recording(self, request: dict[str, Any], *, queue_job_id: str = "") -> dict[str, Any]:
        session_id = str(request.get("session_id", ""))
        session = self.recorder.status(session_id)
        inventory = self.recorder.list_devices()
        device = next((item for item in inventory.get(session.get("platform"), []) if item.get("id") == session.get("device_id")), {})
        images, observations, platform = self.recorder.evidence(session_id)
        requested = request.get("selected_frames")
        selected_indices: list[int]
        if requested is None:
            # Compatibility for local API clients predating the preview. The
            # desktop UI always sends an explicit reviewed list.
            selected_indices = list(range(len(images)))
        elif not isinstance(requested, list):
            raise ValidationError("The selected screens must be a list.")
        else:
            selected_indices = []
            for item in requested:
                if isinstance(item, bool) or not isinstance(item, int) or not 0 <= item < len(images):
                    raise ValidationError("The selected screens contain an invalid frame.")
                if item not in selected_indices:
                    selected_indices.append(item)
        if not selected_indices:
            raise ValidationError("Select at least one screen for analysis.")
        if len(selected_indices) > self.config.ai_max_images:
            raise ValidationError(f"Select at most {self.config.ai_max_images} screens for analysis.")
        images = [images[index] for index in selected_indices]
        environment = session.get("environment") if isinstance(session.get("environment"), dict) else {}
        context = str(request.get("context", ""))[:3000]
        result = self.analyze({
            "case_id": request.get("case_id"),
            "platform": platform,
            "context": f"{context}\n\nSession metadata:\n{observations}".strip()[:12000],
            "images": images,
            "device_id": session.get("device_id", ""),
            "device_name": environment.get("model") or device.get("name", ""),
            "device_version": environment.get("os_version") or device.get("kind", ""),
            "environment": environment,
            "project_id": request.get("project_id"),
            "target_config": request.get("target_config", ""),
            "force_reanalyze": request.get("force_reanalyze") is True,
            "include_test_credentials": request.get("include_test_credentials", False),
            "_progress_callback": request.get("_progress_callback"),
            "_evidence_session_id": session_id,
            "_selected_frame_indices": selected_indices,
        }, queue_job_id=queue_job_id)
        usage = result.get("usage")
        if isinstance(usage, dict):
            usage["recorded_frames"] = session.get("frames", len(selected_indices))
            usage["selected_frame_indices"] = selected_indices
            usage["selection_reviewed"] = requested is not None
        # Keep encrypted evidence for the configured local retention window so
        # the person can adjust the selected screens and reanalyse a proposal
        # without recording the journey again. It is never reused externally
        # until they explicitly confirm a new selection in the UI.
        return result

    def deferred_list(self) -> dict[str, Any]:
        return {"items": self.deferred.list(), "queue": self.deferred.status()}

    def pause_deferred(self) -> dict[str, Any]:
        with self._deferred_start_lock:
            self.deferred.pause()
            self._deferred_wake.set()
            return {"queue": self.deferred.status()}

    def resume_deferred(self) -> dict[str, Any]:
        with self._deferred_start_lock:
            self.deferred.resume()
            self._ensure_deferred_worker()
            self._deferred_wake.set()
            return {"queue": self.deferred.status()}

    def retry_deferred_now(self, request: dict[str, Any]) -> dict[str, Any]:
        with self._deferred_start_lock:
            item = self.deferred.get(str(request.get("id", "")))
            pending = self.deferred.pending()
            if self.deferred.paused or item["state"] != "waiting_limit" or not pending or pending[0]["id"] != item["id"]:
                raise ValidationError("This TC is no longer waiting for a provider-limit retry. Refresh the queue.")
            self.deferred.set_state(item["id"], "waiting_limit", retry_at=0,
                                    error="Manual retry requested; waiting for the analysis slot.")
            self._ensure_deferred_worker()
            self._deferred_wake.set()
            return {"item": self.deferred.get(item["id"])}

    def cancel_deferred(self) -> dict[str, Any]:
        with self._deferred_start_lock:
            cancelled = self.deferred.cancel_pending()
            self._deferred_wake.set()
            return {"cancelled": cancelled, "running_continues": any(
                row["state"] == "running" for row in self.deferred.list()),
                "queue": self.deferred.status()}

    def unschedule_deferred(self, request: dict[str, Any]) -> dict[str, Any]:
        with self._deferred_start_lock:
            item = self.deferred.unschedule(str(request.get("id", "")))
            self._deferred_wake.set()
            return {"item": item}

    def move_deferred(self, request: dict[str, Any]) -> dict[str, Any]:
        with self._deferred_start_lock:
            item = self.deferred.move(str(request.get("id", "")), str(request.get("direction", "")))
            self._deferred_wake.set()
            return {"item": item}

    def defer_recording(self, request: dict[str, Any]) -> dict[str, Any]:
        session_id = str(request.get("session_id", ""))
        session = self.recorder.status(session_id)
        case_id = normalize_case_id(request.get("case_id"))
        if session.get("case_id") != case_id:
            raise ValidationError("The recording belongs to a different case.")
        raw_project = request.get("project_id")
        project_id = normalize_case_id(raw_project) if raw_project not in (None, "") else None
        self.recorder.protect(session_id)
        item = self.deferred.add(session_id=session_id, case_id=case_id,
                                 platform=str(session["platform"]), project_id=project_id,
                                 context=str(request.get("context", "")),
                                 target_config=str(request.get("target_config", "")))
        return {"item": item}

    def review_deferred(self, request: dict[str, Any]) -> dict[str, Any]:
        item = self.deferred.get(str(request.get("id", "")))
        status = self.recorder.status(item["session_id"])
        selected = request.get("selected_frames")
        if not isinstance(selected, list) or not selected or len(selected) > self.config.ai_max_images:
            raise ValidationError(f"Select 1 to {self.config.ai_max_images} screens.")
        if any(isinstance(value, bool) or not isinstance(value, int) or
               value < 0 or value >= status["frames"] for value in selected) or len(set(selected)) != len(selected):
            raise ValidationError("The screen selection is invalid.")
        if request.get("sensitive_reviewed") is not True:
            raise ValidationError("Review the selected screens for sensitive data before queuing AI analysis.")
        include = request.get("include_test_credentials")
        if not isinstance(include, bool):
            raise ValidationError("Choose whether QA credentials may be included.")
        with self._deferred_start_lock:
            reviewed = self.deferred.review(item["id"], selected, include,
                    str(request.get("context", item["context"])),
                    str(request.get("target_config", item["target_config"])))
            self.vision_checkpoints.clear(item["id"])
            self._deferred_wake.set()
        return {"item": reviewed}

    def remove_deferred(self, request: dict[str, Any]) -> dict[str, Any]:
        with self._deferred_start_lock:
            item = self.deferred.remove(str(request.get("id", "")))
            self.vision_checkpoints.clear(item["id"])
            self._deferred_wake.set()
        # Removing a queue row does not delete evidence; normal capture retention resumes.
        self.recorder.unprotect(item["session_id"])
        return {"removed": True}

    def start_deferred(self, request: dict[str, Any]) -> dict[str, Any]:
        if not self.config.vision_ready or not self.config.testrail_ready:
            raise ConfigurationError("Configure the selected AI provider and TestRail before starting queued analysis.")
        mode = request.get("mode")
        ids = request.get("ids")
        if mode != "sequential" or not isinstance(ids, list) or not 1 <= len(ids) <= 50:
            raise ValidationError("Choose 1 to 50 queued cases for one-at-a-time analysis.")
        if len(ids) != len(set(str(value) for value in ids)):
            raise ValidationError("The queue selection contains duplicate jobs.")
        retry_minutes = request.get("retry_minutes", self.deferred.retry_minutes)
        max_attempts = request.get("max_limit_attempts", self.deferred.max_limit_attempts)
        if type(retry_minutes) is not int or type(max_attempts) is not int:
            raise ValidationError("Retry settings must be whole numbers.")
        if not 5 <= retry_minutes <= 120 or not 1 <= max_attempts <= 40:
            raise ValidationError("Retry interval must be 5–120 minutes and limit attempts 1–40.")
        with self._deferred_start_lock:
            items = [self.deferred.get(str(value)) for value in ids]
            if any(item["state"] not in {"ready", "failed"} or not item["reviewed"] or
                   not item.get("selected_frames") for item in items):
                raise ValidationError("Review every selected case before starting analysis.")
            for item in items:
                self.recorder.status(item["session_id"])
            self.deferred.configure(retry_minutes, max_attempts)
            next_order = max((int(row.get("queue_order") or 0) for row in self.deferred.list()), default=0) + 1
            for offset, item in enumerate(items):
                self.deferred.set_state(item["id"], "scheduled", error="", error_code="", remedy="",
                                        progress={}, retry_at=0, limit_attempts=0,
                                        queue_order=next_order + offset)
            self._ensure_deferred_worker()
            self._deferred_wake.set()
        return {"started": len(items), "mode": "sequential", "parallel_limit": 1,
                "paused": self.deferred.paused}

    def _ensure_deferred_worker(self) -> None:
        """Called with the start lock held; only one worker may consume the local queue."""
        if self.deferred.pending() and not (self._deferred_worker and self._deferred_worker.is_alive()):
            self._deferred_worker = threading.Thread(target=self._run_deferred_queue,
                                                      name="qa-deferred-sequential", daemon=True)
            self._deferred_worker.start()

    def _run_deferred_queue(self) -> None:
        while True:
            with self._deferred_start_lock:
                pending = self.deferred.pending()
                if not pending:
                    self._deferred_worker = None
                    return
                paused = self.deferred.paused
                item = pending[0]
                delay = max(0.0, float(item.get("retry_at") or 0) - time.time()) if item["state"] == "waiting_limit" else 0.0
            if paused or delay:
                self._deferred_wake.wait(timeout=min(delay, 60.0) if delay and not paused else 60.0)
                self._deferred_wake.clear()
                continue
            self._run_deferred_item(item["id"])

    def _run_deferred_item(self, item_id: str) -> None:
        with self._deferred_start_lock:
            try:
                item = self.deferred.get(item_id)
            except ValidationError:
                return  # Removed while the worker was waiting.
            if self.deferred.paused:
                return
            if item["state"] not in {"scheduled", "waiting_limit"}:
                return
            self.deferred.set_state(item_id, "running", retry_at=0, error="", error_code="", remedy="",
                                    progress={"stage": "preparing", "current": 0, "total": 0})
        try:
            def on_progress(value: dict[str, Any]) -> None:
                self.deferred.set_state(item_id, "running", progress=value)
            deterministic_id = DraftStore.deferred_id(item_id)
            try:
                self.drafts.get(deterministic_id)
            except ValidationError:
                pass
            else:
                self.vision_checkpoints.clear(item_id)
                self.deferred.set_state(item_id, "completed", draft_id=deterministic_id, error="", progress={})
                return
            result = self.analyze_recording({
                "session_id": item["session_id"], "case_id": item["case_id"],
                "selected_frames": item["selected_frames"], "context": item["context"],
                "project_id": item["project_id"], "target_config": item["target_config"],
                "include_test_credentials": item["include_test_credentials"],
                "_progress_callback": on_progress,
            }, queue_job_id=item_id)
            on_progress({"stage": "saving_draft", "current": 1, "total": 1})
            draft_id = self._save_deferred_draft(result["proposal_token"], item)
            self.vision_checkpoints.clear(item_id)
            self.deferred.set_state(item_id, "completed", draft_id=draft_id, error="", progress={})
        except UsageLimitError:
            attempts = int(item.get("limit_attempts") or 0) + 1
            minutes = self.deferred.retry_minutes
            self.deferred.set_state(item_id, "waiting_limit", limit_attempts=attempts,
                                    retry_at=time.time() + minutes * 60,
                                    error=f"Provider allowance exhausted ({attempts}/{self.deferred.max_limit_attempts}). Later TCs will wait.",
                                    error_code="provider_limit", remedy="Wait for the provider allowance, or use Try now when it returns.", progress={})
            if attempts >= self.deferred.max_limit_attempts:
                self.deferred.pause("limit_attempts")
        except QASyncError as exc:
            if isinstance(exc, ConfigurationError):
                code, remedy = "configuration", "Open Settings and check the provider, CLI login, and TestRail configuration."
            elif isinstance(exc, ValidationError):
                code, remedy = "evidence", "Review the selected screens and captured evidence, then retry."
            elif isinstance(exc, ExternalServiceError):
                code, remedy = "external_service", "Check the provider or TestRail connection, then retry."
            else:
                code, remedy = "analysis", "Check the local server log, then retry."
            self.deferred.set_state(item_id, "failed", error=self._safe_diagnostic_text(str(exc))[:400],
                                    error_code=code, remedy=remedy, progress={})
        except Exception:
            self.deferred.set_state(item_id, "failed", error="Analysis failed unexpectedly. Check the local server log.",
                                    error_code="unexpected", remedy="Check the local server log, then retry.", progress={})

    def _save_deferred_draft(self, token: str, item: dict[str, Any]) -> str:
        proposal = self.store.get(token)
        return self.drafts.save(f"C{item['case_id']} · deferred execution", proposal,
                                idempotency_key=item["id"])

    def _style_samples(
        self, client: TestRailClient, current: dict[str, Any], project_id: object
    ) -> list[dict[str, Any]]:
        """Casos ya escritos en la misma sección, como referencia de voz.

        Es opcional a propósito: si TestRail no da la sección o el proyecto, el
        análisis sigue sin referencia en vez de fallar.
        """
        raw_project = project_id if project_id not in (None, "") else self.config.testrail_project_id
        try:
            project = normalize_case_id(raw_project)
        except ValidationError:
            return []
        section_id, suite_id = current.get("section_id"), current.get("suite_id")
        if not isinstance(section_id, int):
            return []
        try:
            cases = client.get_cases(project, suite_id, section_id)
        except (ExternalServiceError, ValidationError):
            return []
        samples: list[dict[str, Any]] = []
        for case in cases:
            if case.get("id") == current.get("id") or len(samples) >= 3:
                continue
            steps = case.get(self.config.testrail_steps_field)
            if not isinstance(steps, list) or not steps:
                continue
            samples.append({
                "title": case.get("title", ""),
                "preconditions": case.get(self.config.testrail_preconditions_field, ""),
                "steps": steps,
            })
        return samples

    def analyze(self, request: dict[str, Any], *, queue_job_id: str = "") -> dict[str, Any]:
        if not self.config.testrail_ready:
            raise ConfigurationError("Set up TestRail before analysing an existing case.")
        policy = request.get("include_test_credentials", False)
        if not isinstance(policy, bool):
            raise ValidationError("The QA credential choice must be true or false.")
        include_test_credentials = policy
        case_id = normalize_case_id(request.get("case_id"))
        platform = str(request.get("platform", "")).lower()
        client = TestRailClient(self.config)
        current = client.get_case(case_id)
        style_samples = self._style_samples(client, current, request.get("project_id"))
        target_config = str(request.get("target_config", ""))[:200]
        context = str(request.get("context", ""))[:12000]
        images = request.get("images") or []
        current_case = {
            "id": current.get("id"),
            "title": current.get("title", ""),
            "preconditions": current.get(self.config.testrail_preconditions_field, ""),
            "steps": current.get(self.config.testrail_steps_field, []),
        }
        configured_secrets = [self.config.testrail_api_key, self.config.openai_api_key]
        model_case = redact_known_values(current_case, configured_secrets)
        model_style = redact_known_values(style_samples, configured_secrets)
        model_context = redact_known_values(context, configured_secrets)
        model_target = redact_known_values(target_config, configured_secrets)
        model_template = redact_known_values(self.config.case_template, configured_secrets)
        model_procedures = redact_known_values(self.config.test_procedures, configured_secrets)
        cache_key = self.analysis_cache.fingerprint({
            "cache_version": 1, "prompt_version": PROMPT_VERSION,
            "include_test_credentials": include_test_credentials,
            "case": model_case, "style_samples": model_style,
            "platform": platform, "target_config": model_target, "context": model_context, "images": images,
            "provider": self.config.vision_provider, "quality": self.config.vision_quality,
            "fallback": [self.config.allow_provider_fallback, self.config.fallback_provider],
            "model": {
                "codex": self.config.codex_model, "claude": self.config.claude_model,
                "openai": self.config.openai_model,
            },
            "case_template": model_template, "test_procedures": model_procedures,
            "fields": [self.config.testrail_steps_field, self.config.testrail_preconditions_field,
                       self.config.testrail_platform_field, self.config.testrail_android_value,
                       self.config.testrail_ios_value],
        })
        cache_hit = False
        progress = request.get("_progress_callback")
        analysis = None if request.get("force_reanalyze") is True else self.analysis_cache.get(cache_key)
        if analysis is not None:
            cache_hit = True
            analysis["_usage"] = {"cache_hit": True, "model_calls": 0}
            if callable(progress):
                progress({"stage": "cache_hit", "current": 1, "total": 1, "model_calls": 0})
        else:
            use_checkpoints = request.get("force_reanalyze") is not True
            def stage_key(stage_id: str) -> str:
                return self.analysis_cache.fingerprint({"analysis": cache_key, "stage": stage_id, "kind": "vision-checkpoint-v1"})
            if isinstance(queue_job_id, str) and queue_job_id:
                stage_get = lambda stage_id: self.vision_checkpoints.get(queue_job_id, cache_key, stage_id)
                stage_put = lambda stage_id, value: self.vision_checkpoints.put(queue_job_id, cache_key, stage_id, value)
            else:
                stage_get = lambda stage_id: self.analysis_cache.get(stage_key(stage_id))
                stage_put = lambda stage_id, value: self.analysis_cache.put(stage_key(stage_id), value)
            analysis = VisionAnalyzer(self.config).analyze(
            style_samples=model_style,
            target_config=model_target,
            case_template=model_template,
            test_procedures=model_procedures,
            platform=platform,
            images=images,
            context=model_context,
            current_case=model_case,
            include_test_credentials=include_test_credentials,
            progress=progress,
            checkpoint_get=stage_get if use_checkpoints else None,
            checkpoint_put=stage_put if use_checkpoints else None,
            )
            self.analysis_cache.put(cache_key, analysis)
        changes: dict[str, Any] = {
            "title": analysis["title"],
            self.config.testrail_preconditions_field: analysis["preconditions"],
            self.config.testrail_steps_field: analysis["steps"],
        }
        platform_value = (
            self.config.testrail_android_value
            if platform == "android"
            else self.config.testrail_ios_value
        )
        if self.config.testrail_platform_field and platform_value:
            try:
                changes[self.config.testrail_platform_field] = int(platform_value)
            except ValueError:
                changes[self.config.testrail_platform_field] = platform_value

        provider_used = str(analysis.pop("_provider_used", self.config.vision_provider))
        usage = analysis.pop("_usage", {})
        if isinstance(usage, dict) and isinstance(request.get("_selected_frame_indices"), list):
            usage["selected_frame_indices"] = request["_selected_frame_indices"]
        proposal = Proposal(
            case_id, platform, current, changes, time.time(), analysis["confidence"], analysis["warnings"],
            provider_used, str(request.get("device_id", ""))[:200],
            str(request.get("device_name", ""))[:200], str(request.get("device_version", ""))[:200],
            # El resto va por nombre: añadir un campo al dataclass corría los
            # posicionales y usage terminaba en otro campo.
            vision_quality=self.config.vision_quality,
            target_config=str(request.get("target_config", ""))[:200],
            usage=usage if isinstance(usage, dict) else {},
            environment={str(key)[:80]: str(value)[:200] for key, value in request.get("environment", {}).items()} if isinstance(request.get("environment"), dict) else {},
            prompt_version=PROMPT_VERSION,
            evidence_session_id=str(request.get("_evidence_session_id") or "")[:64],
        )
        token = self.store.put(proposal)
        response = self._proposal_response(token, proposal)
        response["cache_hit"] = cache_hit
        return response

    def _proposal_response(self, token: str, proposal: Proposal) -> dict[str, Any]:
        return {
            "proposal_token": token,
            "case_id": proposal.case_id,
            "platform": proposal.platform,
            "current": {key: proposal.current.get(key) for key in proposal.changes},
            "changes": proposal.changes,
            "confidence": proposal.confidence,
            "warnings": proposal.warnings or [],
            "steps_field": self.config.testrail_steps_field,
            "preconditions_field": self.config.testrail_preconditions_field,
            "confirmation": f"ACTUALIZAR C{proposal.case_id}",
            "write_mode": self.config.write_mode,
            "provider_used": proposal.provider_used,
            "vision_quality": proposal.vision_quality,
            "target_config": proposal.target_config,
            "usage": proposal.usage or {},
            "environment": proposal.environment or {},
            "device_id": proposal.device_id,
            "device_name": proposal.device_name,
            "device_version": proposal.device_version,
            "prompt_version": proposal.prompt_version,
            "evidence_session_id": proposal.evidence_session_id,
            "evidence_links": proposal.evidence_links or [],
            "revision": proposal.revision,
        }

    def recovered_proposal(self) -> dict[str, Any]:
        latest = self.store.latest()
        return {"proposal": self._proposal_response(*latest) if latest else None}

    def recovery(self) -> dict[str, Any]:
        running = self.executions.running()
        deferred = self.deferred.list()
        queued_ids = {item["session_id"] for item in deferred}
        recovered = self.recorder.recovered_sessions()
        recovered["sessions"] = [session for session in recovered["sessions"]
                                 if session["session_id"] not in queued_ids]
        return {**self.recovered_proposal(), **recovered,
                "deferred_count": len(deferred),
                "execution": running[0] if running else None}

    def revise_proposal(self, request: dict[str, Any]) -> dict[str, Any]:
        token = str(request.get("proposal_token", ""))
        revision = _proposal_revision(request)
        proposal = self.store.get(token, revision)
        title = request.get("title")
        preconditions = request.get("preconditions")
        steps = request.get("steps")
        if not isinstance(title, str) or not title.strip() or len(title) > 250:
            raise ValidationError("The title must be 1 to 250 characters.")
        if not isinstance(preconditions, str) or len(preconditions) > 10000:
            raise ValidationError("The preconditions are over the allowed limit.")
        if not isinstance(steps, list) or not 1 <= len(steps) <= 100:
            raise ValidationError("The proposal must have 1 to 100 steps.")
        cleaned_steps = []
        for index, step in enumerate(steps, 1):
            if not isinstance(step, dict):
                raise ValidationError(f"Step {index} must be an object.")
            content, expected = step.get("content"), step.get("expected")
            if not isinstance(content, str) or not content.strip() or len(content) > 5000:
                raise ValidationError(f"The action of step {index} must be 1 to 5000 characters.")
            # Un paso sin resultado esperado no se puede verificar. El esquema del
            # modelo ya lo exige; editar a mano tampoco debería poder saltárselo,
            # y antes sólo se comprobaba el tipo y el largo máximo.
            if not isinstance(expected, str) or not expected.strip():
                raise ValidationError(f"Step {index} needs an expected result.")
            if len(expected) > 5000:
                raise ValidationError(f"The expected result of step {index} is longer than 5000 characters.")
            cleaned_steps.append({"content": content.strip(), "expected": expected.strip()})
        changes = copy.deepcopy(proposal.changes)
        changes["title"] = title.strip()
        changes[self.config.testrail_preconditions_field] = preconditions.strip()
        changes[self.config.testrail_steps_field] = cleaned_steps
        links = request.get("evidence_links")
        if links is not None:
            allowed = proposal.usage.get("selected_frame_indices", []) if isinstance(proposal.usage, dict) else []
            if not isinstance(links, list) or len(links) != len(cleaned_steps) or any(
                value is not None and (type(value) is not int or value not in allowed) for value in links
            ):
                raise ValidationError("Choose only screens selected for this proposal, one link per step.")
        return self._proposal_response(token, self.store.update(token, changes, links, revision))

    def get_proposal(self, request: dict[str, Any]) -> dict[str, Any]:
        token = str(request.get("proposal_token", ""))
        return self._proposal_response(token, self.store.get(token))

    def save_draft(self, request: dict[str, Any]) -> dict[str, Any]:
        """Park a proposal under a name. Nothing is written to TestRail."""
        token = str(request.get("proposal_token", ""))
        proposal = self.store.get(token, _proposal_revision(request))
        draft_id = self.drafts.save(str(request.get("name") or ""), proposal, str(request.get("draft_id") or ""), request.get("draft_updated_at"))
        return {"saved": True, "draft_id": draft_id, "draft_updated_at": self.drafts.get(draft_id).get("updated_at", 0), "drafts": self.drafts.list()}

    def draft_list(self) -> dict[str, Any]:
        return {"drafts": self.drafts.list()}

    def draft_export(self, request: dict[str, Any]) -> dict[str, Any]:
        raw_case_id = request.get("case_id")
        case_id = normalize_case_id(raw_case_id) if raw_case_id not in (None, "") else None
        return {"version": 1, "exported_at": int(time.time()), "case_id": case_id,
                "drafts": self.drafts.export(case_id)}

    def draft_import(self, request: dict[str, Any]) -> dict[str, Any]:
        entries = request.get("drafts")
        if not isinstance(entries, list) or not entries or len(entries) > 200:
            raise ValidationError("Import 1 to 200 exported drafts.")
        imported = 0
        for item in entries:
            if not isinstance(item, dict) or not isinstance(item.get("changes"), dict):
                raise ValidationError("The import file has an invalid draft.")
            case_id = normalize_case_id(item.get("case_id"))
            changes = copy.deepcopy(item["changes"])
            if not isinstance(changes.get("title"), str) or not changes["title"].strip():
                raise ValidationError(f"Imported C{case_id} has no title.")
            proposal = Proposal(case_id, str(item.get("platform", "")), {}, changes, time.time(),
                                float(item.get("confidence") or 0), list(item.get("warnings") or []),
                                str(item.get("provider_used", "")), "", str(item.get("device_name", "")),
                                str(item.get("device_version", "")), str(item.get("vision_quality", "high")),
                                str(item.get("target_config", "")), item.get("usage") if isinstance(item.get("usage"), dict) else {},
                                prompt_version=int(item.get("prompt_version") or PROMPT_VERSION))
            self.drafts.save(f"Imported · {str(item.get('name') or f'C{case_id}')}", proposal)
            imported += 1
        return {"imported": imported, "drafts": self.drafts.list()}

    def open_draft(self, request: dict[str, Any]) -> dict[str, Any]:
        """Turn a draft back into a live proposal.

        The stored `current` is kept on purpose: applying re-reads the case and refuses
        if somebody changed it since, which is exactly what should happen to a draft
        that sat for days.
        """
        item = self.drafts.get(str(request.get("draft_id", "")))
        proposal = Proposal(
            int(item["case_id"]), str(item["platform"]), item.get("current") or {},
            item.get("changes") or {}, time.time(),
            float(item.get("confidence") or 0.0), list(item.get("warnings") or []),
            str(item.get("provider_used", "")), "",
            str(item.get("device_name", "")), str(item.get("device_version", "")),
            vision_quality=str(item.get("vision_quality", "high")),
            target_config=str(item.get("target_config", "")),
            usage=item.get("usage") if isinstance(item.get("usage"), dict) else {}, environment=item.get("environment") or {},
            prompt_version=int(item.get("prompt_version") or 1),
            evidence_session_id=str(item.get("evidence_session_id") or "")[:64],
            evidence_links=item.get("evidence_links") if isinstance(item.get("evidence_links"), list) else [],
        )
        token = self.store.put(proposal)
        return {**self._proposal_response(token, proposal), "draft_id": item["id"], "draft_name": item["name"], "draft_updated_at": item.get("updated_at", 0)}

    def delete_draft(self, request: dict[str, Any]) -> dict[str, Any]:
        self.drafts.delete(str(request.get("draft_id", "")), request.get("draft_updated_at"))
        return {"deleted": True, "drafts": self.drafts.list()}

    def apply(self, request: dict[str, Any]) -> dict[str, Any]:
        if self.config.write_mode == "review_only":
            raise ValidationError("QA Sync is in dry run mode; nothing was written to TestRail.")
        token = str(request.get("proposal_token", ""))
        if not token:
            raise ValidationError("The proposal token is missing.")
        revision = _proposal_revision(request)
        preview = self.store.get(token, revision)
        if preview.confidence < self.config.min_apply_confidence:
            raise ValidationError(
                f"Confidence {preview.confidence:.0%} is below the configured minimum "
                f"of {self.config.min_apply_confidence:.0%}. Review the evidence or lower the threshold in Settings."
            )
        proposal = self.store.pop(token, revision)
        expected = f"ACTUALIZAR C{proposal.case_id}"
        if request.get("confirmation") != expected:
            # El token es de un solo uso incluso al fallar: obliga a revisar de nuevo.
            raise ValidationError(f"Type exactly: {expected}")
        optional_steps = request.get("optional_steps", [])
        if not isinstance(optional_steps, list) or any(
            isinstance(index, bool) or not isinstance(index, int) for index in optional_steps
        ):
            raise ValidationError("The optional step selection is invalid.")
        changes = copy.deepcopy(proposal.changes)
        steps = changes.get(self.config.testrail_steps_field, [])
        if not isinstance(steps, list) or any(index < 0 or index >= len(steps) for index in optional_steps):
            raise ValidationError("One of the optional steps does not exist in the proposal.")
        for index in set(optional_steps):
            step = steps[index]
            content = str(step.get("content", ""))
            # Se acepta el marcador anterior en español para no dejar huérfanos los
            # casos que esta app ya actualizó antes de la traducción.
            if not content.lower().startswith(("[optional]", "[opcional]")):
                step["content"] = f"[Optional] {content}".strip()
        client = TestRailClient(self.config)
        latest = client.get_case(proposal.case_id)
        stale_fields = [key for key in changes if latest.get(key) != proposal.current.get(key)]
        if stale_fields:
            raise ValidationError(
                "The case changed in TestRail after the analysis. Reload it before updating: "
                + ", ".join(sorted(stale_fields))
            )
        previous_fields = {key: latest.get(key) for key in changes}
        backup_id = self.history.create(proposal.case_id, previous_fields, changes, {
            "platform": proposal.platform, "device_id": proposal.device_id,
            "device_name": proposal.device_name, "device_version": proposal.device_version,
            "provider": proposal.provider_used, "target_config": proposal.target_config,
            "usage": proposal.usage or {},
            "prompt_version": proposal.prompt_version,
        })
        updated = client.update_case(proposal.case_id, changes)
        applied_fields = {key: updated.get(key, changes.get(key)) for key in changes}
        self.history.mark_applied(backup_id, applied_fields)
        draft_id = str(request.get("draft_id", ""))
        draft_retained = False
        if draft_id:
            try:
                # No borres el trabajo más reciente de otra ventana después de que
                # TestRail ya aceptó la actualización de esta propuesta.
                self.drafts.delete(draft_id, request.get("draft_updated_at"))
            except ValidationError as exc:
                if "another window" not in str(exc):
                    raise
                draft_retained = True
        return {
            "updated": True,
            "case_id": proposal.case_id,
            "title": updated.get("title", proposal.changes.get("title")),
            "backup_id": backup_id,
            "draft_retained": draft_retained,
        }

    def history_entries(self, request: dict[str, Any]) -> dict[str, Any]:
        case_id = normalize_case_id(request.get("case_id"))
        return {"history": self.history.list(case_id)}

    def reconcile_pending_update(self, request: dict[str, Any]) -> dict[str, Any]:
        """Read TestRail after a transport failure; never replay an uncertain write."""
        backup_id = str(request.get("backup_id", ""))
        entry = self.history.get(backup_id)
        if entry.get("state") != "pending":
            raise ValidationError("Only a pending update can be reconciled.")
        case_id = normalize_case_id(entry.get("case_id"))
        proposed = entry.get("proposed_fields")
        previous = entry.get("previous_fields")
        if not isinstance(proposed, dict) or not isinstance(previous, dict):
            raise ValidationError("The pending backup has no valid fields.")
        current = TestRailClient(self.config).get_case(case_id)
        if all(current.get(key) == value for key, value in proposed.items()):
            self.history.mark_applied(backup_id, proposed)
            return {"case_id": case_id, "reconciled": True, "outcome": "applied"}
        if all(current.get(key) == value for key, value in previous.items()):
            return {"case_id": case_id, "reconciled": True, "outcome": "not_applied"}
        return {"case_id": case_id, "reconciled": True, "outcome": "conflict"}

    def audit_report(self) -> dict[str, Any]:
        rows = self.history.audit()
        inventory = self.recorder.list_devices(force=True)
        devices = [
            {key: item.get(key, "") for key in ("name", "kind", "version")}
            for platform in ("android", "ios")
            for item in inventory.get(platform, []) if isinstance(item, dict)
        ]
        avds = [
            {key: item.get(key, "") for key in ("name", "api_level", "abi", "image", "device")}
            for item in inventory.get("android_avds", []) if isinstance(item, dict)
        ]
        return {
            "version": 2, "generated_at": int(time.time()), "records": rows, "count": len(rows),
            "spend": self._spend_summary(rows),
            "diagnostics": {
                "runtime": {"platform": sys.platform, "python": sys.version.split()[0]},
                "configuration": {
                    "testrail_configured": self.config.testrail_ready,
                    "vision_provider": self.config.vision_provider,
                    "vision_quality": self.config.vision_quality,
                    "write_mode": self.config.write_mode,
                },
                "capabilities": inventory.get("capabilities", {}),
                "connected_devices": devices,
                "android_avds": avds,
                "errors": [self._safe_diagnostic_text(item)[:400] for item in inventory.get("errors", [])],
            },
        }

    def support_report(self) -> dict[str, Any]:
        """Return a safe, shareable local diagnosis without test content or secrets."""
        audit = self.audit_report()
        return {
            "version": 1,
            "generated_at": int(time.time()),
            "purpose": "QA Sync local support diagnosis",
            "preflight": self.preflight(),
            "diagnostics": audit["diagnostics"],
        }

    def spend(self) -> dict[str, Any]:
        """Sólo el resumen: mostrar cuatro cifras no debe descargar mil filas de auditoría."""
        return {"spend": self._spend_summary(self.history.audit())}

    def _spend_summary(self, rows: list[dict[str, Any]]) -> dict[str, Any]:
        """Lo consumido por los casos ya aplicados, más lo que espera en borradores.

        Se suma de lo que informó el proveedor en cada análisis, no de una estimación.
        """
        def total(items: list[dict[str, Any]]) -> dict[str, float]:
            summed: dict[str, float] = {}
            for item in items:
                usage = item.get("usage")
                if not isinstance(usage, dict):
                    continue
                for key, value in usage.items():
                    if isinstance(value, (int, float)) and not isinstance(value, bool):
                        summed[key] = summed.get(key, 0) + float(value)
            return {
                key: round(value, 6) if key.endswith("_usd") else int(value)
                for key, value in sorted(summed.items())
            }

        def averages(items: list[dict[str, Any]]) -> dict[str, Any]:
            """Promedios sobre los casos que sí traen dato.

            Promediar sobre todos hundiría la cifra con los análisis de Codex, que no
            informa nada: parecería barato cuando en realidad se desconoce.
            """
            costed = [
                item["usage"] for item in items
                if isinstance(item.get("usage"), dict) and float(item["usage"].get("cost_usd") or 0) > 0
            ]
            timed = [
                item["usage"] for item in items
                if isinstance(item.get("usage"), dict) and float(item["usage"].get("duration_ms") or 0) > 0
            ]
            result: dict[str, Any] = {"measured_cases": len(costed), "timed_cases": len(timed)}
            if costed:
                result["cost_usd"] = round(sum(float(u.get("cost_usd") or 0) for u in costed) / len(costed), 6)
            if timed:
                seconds = sum(float(u.get("duration_ms") or 0) for u in timed) / len(timed) / 1000
                result["seconds"] = round(seconds, 1)
            return result

        drafts = self.drafts.list()
        applied, pending = total(rows), total(drafts)
        every = rows + drafts
        mean = averages(every)
        summary: dict[str, Any] = {
            "applied": {**applied, "cases": len(rows)},
            "drafts": {**pending, "cases": len(drafts)},
            "cost_usd": round(float(applied.get("cost_usd", 0)) + float(pending.get("cost_usd", 0)), 6),
            "average": mean,
            "note": (
                "Summed from what each provider reported. Codex reports neither tokens nor cost, "
                "so analyses run through it count as zero and are left out of the averages "
                "rather than counted as free."
            ),
        }
        rate = self.config.hourly_rate_usd
        if rate > 0 and mean.get("seconds"):
            # Sólo con una tarifa configurada: convertir tiempo a dinero sin ella
            # sería inventar la cifra que más pesa en el resultado.
            summary["average"]["time_cost_usd"] = round(mean["seconds"] / 3600 * rate, 4)
            summary["hourly_rate_usd"] = rate
        return summary

    def device_matrix(self) -> dict[str, Any]:
        rows: dict[tuple[str, str], dict[str, Any]] = {}
        for record in self.history.audit():
            platform, device_id = str(record.get("platform", "")), str(record.get("device_id", ""))
            if not platform or not device_id:
                continue
            key = (platform, device_id)
            item = rows.setdefault(key, {
                "platform": platform, "device_id": device_id,
                "device_name": record.get("device_name", ""), "version": record.get("device_version", ""),
                "cases": set(), "last_tested_at": 0,
            })
            item["cases"].add(record.get("case_id"))
            item["last_tested_at"] = max(item["last_tested_at"], int(record.get("updated_at") or 0))
        return {"matrix": [{**item, "cases": sorted(case for case in item["cases"] if case)} for item in rows.values()]}

    def rollback(self, request: dict[str, Any]) -> dict[str, Any]:
        backup_id = str(request.get("backup_id", ""))
        entry = self.history.get(backup_id)
        case_id = normalize_case_id(entry.get("case_id"))
        if request.get("confirmation") != f"RESTAURAR C{case_id}":
            raise ValidationError(f"Type exactly: RESTAURAR C{case_id}")
        if entry.get("state") == "rolled_back":
            return {"restored": True, "case_id": case_id, "already_restored": True}

        previous = entry.get("previous_fields")
        proposed = entry.get("applied_fields") or entry.get("proposed_fields")
        if not isinstance(previous, dict) or not isinstance(proposed, dict):
            raise ValidationError("The backup holds no valid fields.")
        client = TestRailClient(self.config)
        current = client.get_case(case_id)
        conflicts = [key for key, value in proposed.items() if current.get(key) != value]
        if conflicts:
            already_previous = all(current.get(key) == value for key, value in previous.items())
            if already_previous:
                self.history.mark_rolled_back(backup_id)
                return {"restored": True, "case_id": case_id, "already_restored": True}
            raise ValidationError(
                "The case changed after this update; it was not restored, to avoid overwriting newer work."
            )
        restored = client.update_case(case_id, previous)
        self.history.mark_rolled_back(backup_id)
        return {"restored": True, "case_id": case_id, "title": restored.get("title", previous.get("title"))}
