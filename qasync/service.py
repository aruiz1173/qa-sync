from __future__ import annotations

import secrets
import copy
import json
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .config import Config
from .appium import AppiumClient
from .errors import ConfigurationError, ExternalServiceError, ValidationError
from .history import HistoryStore
from .recorder import RecorderManager
from .state import private_dir, private_file, state_root
from .testrail import TestRailClient, normalize_case_id, normalize_run_id
from .vision import VisionAnalyzer


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


class ProposalStore:
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

    def get(self, token: str) -> Proposal:
        with self._lock:
            self._purge()
            proposal = self._items.get(token)
        if proposal is None:
            raise ValidationError("That proposal expired or was already used. Analyse again.")
        return copy.deepcopy(proposal)

    def update(self, token: str, changes: dict[str, Any]) -> Proposal:
        with self._lock:
            self._purge()
            proposal = self._items.get(token)
            if proposal is None:
                raise ValidationError("That proposal expired or was already used. Analyse again.")
            proposal.changes = copy.deepcopy(changes)
            self._save()
            return copy.deepcopy(proposal)

    def pop(self, token: str) -> Proposal:
        with self._lock:
            self._purge()
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
            for token, item in raw.items():
                if isinstance(item, dict):
                    self._items[token] = Proposal(**item)
            self._purge()
        except (OSError, ValueError, TypeError):
            self._items = {}

    def _save(self) -> None:
        if not self.path:
            return
        private_dir(self.path.parent)
        temporary = self.path.with_suffix(".tmp")
        payload = {token: {
            "case_id": item.case_id, "platform": item.platform, "current": item.current,
            "changes": item.changes, "created_at": item.created_at,
            "confidence": item.confidence, "warnings": item.warnings or [],
            "provider_used": item.provider_used, "device_id": item.device_id,
            "device_name": item.device_name, "device_version": item.device_version,
            "vision_quality": item.vision_quality,
            "target_config": item.target_config,
            "usage": item.usage or {},
            "environment": item.environment or {},
        } for token, item in self._items.items()}
        temporary.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
        private_file(temporary)
        temporary.replace(self.path)


class DraftStore:
    """Named work in progress that outlives a proposal.

    A proposal expires in 30 minutes and is single use, which is right for something
    about to be written to TestRail but loses the work of anyone interrupted. A draft
    has no expiry, can be reopened as often as needed and never writes anywhere.
    """

    MAX_DRAFTS = 200

    def __init__(self, path: Path | None = None):
        self.path = path
        self._items: dict[str, dict[str, Any]] = {}
        self._lock = threading.Lock()
        self._load()

    def save(self, name: str, proposal: Proposal, draft_id: str = "") -> str:
        clean = " ".join(str(name or "").split())[:80]
        if not clean:
            raise ValidationError("Give the draft a name so you can find it later.")
        with self._lock:
            if not draft_id or draft_id not in self._items:
                if len(self._items) >= self.MAX_DRAFTS:
                    raise ValidationError(
                        f"There are already {self.MAX_DRAFTS} drafts. Delete one before saving another."
                    )
                draft_id = uuid.uuid4().hex
                created_at = time.time()
            else:
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
            }
            self._save()
        return draft_id

    def list(self) -> list[dict[str, Any]]:
        with self._lock:
            items = sorted(self._items.values(), key=lambda item: item.get("updated_at", 0), reverse=True)
        # El cuerpo del caso no viaja al listado: sólo lo suficiente para reconocerlo.
        return [{
            "id": item["id"], "name": item["name"], "case_id": item["case_id"],
            "platform": item["platform"], "target_config": item.get("target_config", ""),
            "device_name": item.get("device_name", ""), "updated_at": item.get("updated_at", 0),
            "usage": item.get("usage", {}),
            "steps": len(item.get("changes", {}).get(
                next((key for key in item.get("changes", {}) if key.startswith("custom_steps")), ""), []
            ) or []),
        } for item in items]

    def get(self, draft_id: str) -> dict[str, Any]:
        with self._lock:
            item = self._items.get(str(draft_id))
        if item is None:
            raise ValidationError("That draft no longer exists.")
        return copy.deepcopy(item)

    def delete(self, draft_id: str) -> None:
        with self._lock:
            if self._items.pop(str(draft_id), None) is None:
                raise ValidationError("That draft no longer exists.")
            self._save()

    def _load(self) -> None:
        if not self.path:
            return
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
            self._items = {
                str(key): value for key, value in raw.items()
                if isinstance(value, dict) and value.get("id") == key
            }
        except (OSError, ValueError, AttributeError):
            self._items = {}

    def _save(self) -> None:
        if not self.path:
            return
        private_dir(self.path.parent)
        temporary = self.path.with_suffix(".tmp")
        temporary.write_text(json.dumps(self._items, ensure_ascii=False), encoding="utf-8")
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
        self.drafts = DraftStore(path=state_dir / "drafts.json")
        self.recorder = recorder or RecorderManager(
            interval=config.capture_interval,
            max_frames=config.max_images,
            max_duration=config.max_recording_seconds,
            appium_url=config.appium_url,
            ios_bundle_id=config.ios_bundle_id,
            appium_capabilities_json=config.appium_capabilities_json,
            ios_devices_json=config.ios_devices_json,
            evidence_key=config.evidence_key,
            recovery_dir=state_dir / "recovery",
        )
        self.history = history or HistoryStore(state_dir / "history")

    def devices(self) -> dict[str, Any]:
        return self.recorder.list_devices()

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

    def recording_action(self, request: dict[str, Any]) -> dict[str, Any]:
        return self.recorder.perform_action(str(request.get("session_id", "")), request)

    def stop_recording(self, request: dict[str, Any]) -> dict[str, Any]:
        return self.recorder.stop(str(request.get("session_id", "")))

    def cancel_recording(self, request: dict[str, Any]) -> dict[str, Any]:
        self.recorder.cancel(str(request.get("session_id", "")))
        return {"cancelled": True}

    def analyze_recording(self, request: dict[str, Any]) -> dict[str, Any]:
        session_id = str(request.get("session_id", ""))
        session = self.recorder.status(session_id)
        inventory = self.recorder.list_devices()
        device = next((item for item in inventory.get(session.get("platform"), []) if item.get("id") == session.get("device_id")), {})
        images, observations, platform = self.recorder.evidence(session_id)
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
        })
        self.recorder.discard(session_id)
        return result

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

    def analyze(self, request: dict[str, Any]) -> dict[str, Any]:
        if not self.config.testrail_ready:
            raise ConfigurationError("Set up TestRail before analysing an existing case.")
        case_id = normalize_case_id(request.get("case_id"))
        platform = str(request.get("platform", "")).lower()
        client = TestRailClient(self.config)
        current = client.get_case(case_id)
        analysis = VisionAnalyzer(self.config).analyze(
            style_samples=self._style_samples(client, current, request.get("project_id")),
            target_config=str(request.get("target_config", ""))[:200],
            case_template=self.config.case_template,
            platform=platform,
            images=request.get("images") or [],
            context=str(request.get("context", ""))[:12000],
            current_case={
                "id": current.get("id"),
                "title": current.get("title", ""),
                "preconditions": current.get(self.config.testrail_preconditions_field, ""),
                "steps": current.get(self.config.testrail_steps_field, []),
            },
        )
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
        )
        token = self.store.put(proposal)
        return self._proposal_response(token, proposal)

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
        }

    def recovered_proposal(self) -> dict[str, Any]:
        latest = self.store.latest()
        return {"proposal": self._proposal_response(*latest) if latest else None}

    def recovery(self) -> dict[str, Any]:
        return {**self.recovered_proposal(), **self.recorder.recovered_sessions()}

    def revise_proposal(self, request: dict[str, Any]) -> dict[str, Any]:
        token = str(request.get("proposal_token", ""))
        proposal = self.store.get(token)
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
        return self._proposal_response(token, self.store.update(token, changes))

    def save_draft(self, request: dict[str, Any]) -> dict[str, Any]:
        """Park a proposal under a name. Nothing is written to TestRail."""
        token = str(request.get("proposal_token", ""))
        proposal = self.store.get(token)
        draft_id = self.drafts.save(str(request.get("name") or ""), proposal, str(request.get("draft_id") or ""))
        return {"saved": True, "draft_id": draft_id, "drafts": self.drafts.list()}

    def draft_list(self) -> dict[str, Any]:
        return {"drafts": self.drafts.list()}

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
            usage={}, environment=item.get("environment") or {},
        )
        token = self.store.put(proposal)
        return {**self._proposal_response(token, proposal), "draft_id": item["id"], "draft_name": item["name"]}

    def delete_draft(self, request: dict[str, Any]) -> dict[str, Any]:
        self.drafts.delete(str(request.get("draft_id", "")))
        return {"deleted": True, "drafts": self.drafts.list()}

    def apply(self, request: dict[str, Any]) -> dict[str, Any]:
        if self.config.write_mode == "review_only":
            raise ValidationError("QA Sync is in dry run mode; nothing was written to TestRail.")
        token = str(request.get("proposal_token", ""))
        if not token:
            raise ValidationError("The proposal token is missing.")
        proposal = self.store.pop(token)
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
        })
        updated = client.update_case(proposal.case_id, changes)
        applied_fields = {key: updated.get(key, changes.get(key)) for key in changes}
        self.history.mark_applied(backup_id, applied_fields)
        draft_id = str(request.get("draft_id", ""))
        if draft_id:
            try:
                self.drafts.delete(draft_id)
            except ValidationError:
                pass
        return {
            "updated": True,
            "case_id": proposal.case_id,
            "title": updated.get("title", proposal.changes.get("title")),
            "backup_id": backup_id,
        }

    def history_entries(self, request: dict[str, Any]) -> dict[str, Any]:
        case_id = normalize_case_id(request.get("case_id"))
        return {"history": self.history.list(case_id)}

    def audit_report(self) -> dict[str, Any]:
        rows = self.history.audit()
        return {
            "version": 1, "generated_at": int(time.time()), "records": rows, "count": len(rows),
            "spend": self._spend_summary(rows),
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
