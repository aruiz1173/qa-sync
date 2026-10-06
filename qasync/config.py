from __future__ import annotations

import os
from dataclasses import dataclass


def _env(name: str, default: str = "") -> str:
    return os.getenv(name, default).strip()


def _env_float(name: str, default: float) -> float:
    try:
        return float(_env(name, str(default)))
    except ValueError:
        return default


def _env_int(name: str, default: int) -> int:
    try:
        return int(_env(name, str(default)))
    except ValueError:
        return default


@dataclass(frozen=True)
class Config:
    openai_api_key: str
    openai_model: str
    testrail_url: str
    testrail_email: str
    testrail_api_key: str
    testrail_project_id: str
    testrail_steps_field: str
    testrail_preconditions_field: str
    testrail_platform_field: str
    testrail_android_value: str
    testrail_ios_value: str
    appium_url: str = ""
    ios_bundle_id: str = ""
    appium_capabilities_json: str = "{}"
    ios_devices_json: str = "[]"
    developer_dir: str = ""
    evidence_key: str = ""
    write_mode: str = "confirm"
    vision_provider: str = ""
    codex_model: str = "gpt-5.6-sol"
    claude_model: str = "sonnet"
    allow_provider_fallback: bool = False
    fallback_provider: str = ""
    vision_quality: str = "high"
    max_request_bytes: int = 45 * 1024 * 1024
    max_images: int = 16
    ai_max_images: int = 40
    max_recording_seconds: int = 900
    capture_interval: float = 1.25
    hourly_rate_usd: float = 0.0
    case_template: str = ""
    test_procedures: str = ""
    min_apply_confidence: float = 0.0
    min_verification_confidence: float = 0.8
    capture_retention_hours: int = 1
    cache_retention_hours: int = 24
    draft_retention_days: int = 0
    history_retention_days: int = 0

    @classmethod
    def from_env(cls) -> "Config":
        return cls(
            openai_api_key=_env("OPENAI_API_KEY"),
            openai_model=_env("OPENAI_MODEL", "gpt-4o"),
            testrail_url=_env("TESTRAIL_URL").rstrip("/"),
            testrail_email=_env("TESTRAIL_EMAIL"),
            testrail_api_key=_env("TESTRAIL_API_KEY"),
            testrail_project_id=_env("TESTRAIL_PROJECT_ID"),
            testrail_steps_field=_env("TESTRAIL_STEPS_FIELD", "custom_steps_separated"),
            testrail_preconditions_field=_env("TESTRAIL_PRECONDITIONS_FIELD", "custom_preconds"),
            testrail_platform_field=_env("TESTRAIL_PLATFORM_FIELD"),
            testrail_android_value=_env("TESTRAIL_ANDROID_VALUE"),
            testrail_ios_value=_env("TESTRAIL_IOS_VALUE"),
            appium_url=_env("APPIUM_URL"),
            ios_bundle_id=_env("IOS_BUNDLE_ID"),
            appium_capabilities_json=_env("APPIUM_CAPABILITIES_JSON", "{}"),
            ios_devices_json=_env("QA_SYNC_IOS_DEVICES_JSON", "[]"),
            developer_dir=_env("QA_SYNC_DEVELOPER_DIR") or _env("DEVELOPER_DIR"),
            evidence_key=_env("QA_SYNC_EVIDENCE_KEY"),
            write_mode=_env("QA_SYNC_WRITE_MODE", "confirm").lower(),
            vision_provider=_env("QA_SYNC_VISION_PROVIDER").lower(),
            codex_model=_env("QA_SYNC_CODEX_MODEL", "gpt-5.6-sol"),
            claude_model=_env("QA_SYNC_CLAUDE_MODEL", "sonnet"),
            allow_provider_fallback=_env("QA_SYNC_ALLOW_PROVIDER_FALLBACK").lower() in {"1", "true", "yes"},
            fallback_provider=_env("QA_SYNC_FALLBACK_PROVIDER").lower(),
            vision_quality=_env("QA_SYNC_VISION_QUALITY", "high").lower(),
            max_images=_env_int("QA_SYNC_MAX_IMAGES", 16),
            ai_max_images=_env_int("QA_SYNC_AI_MAX_IMAGES", 40),
            max_recording_seconds=_env_int("QA_SYNC_MAX_RECORDING_SECONDS", 900),
            capture_interval=_env_float("QA_SYNC_CAPTURE_INTERVAL", 1.25),
            hourly_rate_usd=_env_float("QA_SYNC_HOURLY_RATE_USD", 0.0),
            case_template=_env("QA_SYNC_CASE_TEMPLATE"),
            test_procedures=_env("QA_SYNC_TEST_PROCEDURES"),
            min_apply_confidence=_env_float("QA_SYNC_MIN_APPLY_CONFIDENCE", 0.0),
            min_verification_confidence=_env_float("QA_SYNC_MIN_VERIFICATION_CONFIDENCE", 0.8),
            capture_retention_hours=_env_int("QA_SYNC_CAPTURE_RETENTION_HOURS", 1),
            cache_retention_hours=_env_int("QA_SYNC_CACHE_RETENTION_HOURS", 24),
            draft_retention_days=_env_int("QA_SYNC_DRAFT_RETENTION_DAYS", 0),
            history_retention_days=_env_int("QA_SYNC_HISTORY_RETENTION_DAYS", 0),
        )

    @property
    def vision_ready(self) -> bool:
        return self.vision_provider in {"codex", "claude"} or (
            self.vision_provider == "openai_api" and bool(self.openai_api_key)
        )

    @property
    def testrail_ready(self) -> bool:
        return bool(self.testrail_url and self.testrail_email and self.testrail_api_key)

    @property
    def appium_ready(self) -> bool:
        return bool(self.appium_url and self.ios_bundle_id)

    def public_status(self) -> dict[str, object]:
        return {
            "vision_ready": self.vision_ready,
            "testrail_ready": self.testrail_ready,
            "model": self.openai_model,
            "vision_provider": self.vision_provider,
            "project_id": self.testrail_project_id,
            "steps_field": self.testrail_steps_field,
            "platform_mapping_ready": bool(
                self.testrail_platform_field
                and self.testrail_android_value
                and self.testrail_ios_value
            ),
            "appium_ready": self.appium_ready,
            "write_mode": self.write_mode,
            "evidence_encrypted": True,
            "allow_provider_fallback": self.allow_provider_fallback,
            "fallback_provider": self.fallback_provider,
            "vision_quality": self.vision_quality,
            "ai_max_images": self.ai_max_images,
            "capture_interval": self.capture_interval,
            "min_apply_confidence": self.min_apply_confidence,
            "min_verification_confidence": self.min_verification_confidence,
        }
