from __future__ import annotations

import json
import base64
import os
import re
import subprocess
import sys
import threading
import time
from dataclasses import asdict
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .config import Config
from .errors import ValidationError
from .state import private_dir, private_file, state_root

PUBLIC_FIELDS = {
    "openai_model",
    "testrail_url",
    "testrail_email",
    "testrail_project_id",
    "testrail_steps_field",
    "testrail_preconditions_field",
    "testrail_platform_field",
    "testrail_android_value",
    "testrail_ios_value",
    "max_images",
    "ai_max_images",
    "max_recording_seconds",
    "capture_interval",
    "hourly_rate_usd",
    "case_template",
    "test_procedures",
    "min_apply_confidence",
    "min_verification_confidence",
    "capture_retention_hours",
    "cache_retention_hours",
    "draft_retention_days",
    "history_retention_days",
    "appium_url",
    "ios_bundle_id",
    "appium_capabilities_json",
    "ios_devices_json",
    "developer_dir",
    "write_mode",
    "vision_provider",
    "codex_model",
    "claude_model",
    "allow_provider_fallback",
    "fallback_provider",
    "vision_quality",
}
SECRET_FIELDS = {"openai_api_key", "testrail_api_key", "evidence_key"}
LOOPBACK_HOSTNAMES = {"127.0.0.1", "localhost", "::1"}
KEYCHAIN_SERVICE = "com.qasync.local"


def _validated_service_url(raw: object, label: str, example: str) -> str:
    """Normalize a service URL and require HTTPS outside loopback."""
    url = str(raw or "").rstrip("/")
    if not url:
        return ""
    parsed = urlparse(url)
    is_local = parsed.hostname in LOOPBACK_HOSTNAMES
    if parsed.scheme != "https" and not (is_local and parsed.scheme == "http"):
        raise ValidationError(f"{label} must use HTTPS; HTTP is only allowed on localhost.")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        # Lo que se tiene a mano es la URL de un run, no la de la instancia: el mensaje
        # dice qué pegar en vez de sólo qué está mal.
        raise ValidationError(
            f"Paste only the address of {label}, sin credenciales, query ni fragmento. "
            f"Por ejemplo: {example}"
        )
    return url


class SettingsManager:
    SETTINGS_SCHEMA_VERSION = 1
    PROFILES_SCHEMA_VERSION = 1

    def __init__(self, path: Path | None = None):
        configured = os.getenv("QA_SYNC_SETTINGS_FILE", "").strip()
        self.path = (path or (Path(configured) if configured else state_root() / "settings.json")).resolve()
        self.fallback_secrets_path = self.path.with_name("secrets.json")
        self.dpapi_secrets_path = self.path.with_name("secrets.dpapi.json")
        self.profiles_path = self.path.with_name("profiles.json")
        self.workspace_path = self.path.with_name("workspace.json")
        self._workspace_lock = threading.RLock()

    def workspace(self) -> dict[str, Any]:
        """Non-secret local navigation and device preferences, shared across browsers."""
        with self._workspace_lock:
            raw = self._read(self.workspace_path)
            if not raw:
                return {"project_id": "", "runs": {}, "choices": {}}
            if raw.get("schema_version") != 1 or not isinstance(raw.get("runs"), dict) or not isinstance(raw.get("choices"), dict):
                raise ValidationError("This workspace preferences file is unsupported. It was left unchanged.")
            return {"project_id": str(raw.get("project_id", "")),
                    "runs": raw["runs"], "choices": raw["choices"]}

    def save_workspace(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Store only choices safe to reuse; never context, deep links or reset-data."""
        with self._workspace_lock:
            saved = self.workspace()
            def numeric_id(field: str) -> str:
                value = str(payload.get(field, "")).strip()
                if value and (not value.isascii() or not value.isdigit() or int(value) < 1):
                    raise ValidationError(f"{field} must be a positive TestRail ID.")
                return value
            project_id = numeric_id("project_id")
            run_id = numeric_id("run_id")
            suite_id = numeric_id("suite_id")
            if not project_id:
                raise ValidationError("Select a project before saving workspace preferences.")
            saved["project_id"] = project_id
            if run_id:
                saved["runs"][project_id] = run_id
            if payload.get("choice") is not None:
                if not run_id or not isinstance(payload["choice"], dict):
                    raise ValidationError("A device preference needs a run and a choice object.")
                choice = payload["choice"]
                platform = str(choice.get("platform", ""))
                if platform not in {"android", "ios"}:
                    raise ValidationError("Choose Android or iOS.")
                device_id = str(choice.get("device_id", ""))
                target_config = str(choice.get("target_config", ""))
                if len(device_id) > 200 or len(target_config) > 200:
                    raise ValidationError("A saved device preference is too long.")
                value = {"platform": platform, "device_id": device_id,
                         "target_config": target_config, "suite_id": suite_id}
                saved["choices"][f"run:{project_id}:{run_id}"] = value
                if suite_id:
                    saved["choices"][f"suite:{project_id}:{suite_id}"] = value
            saved["runs"] = dict(list(saved["runs"].items())[-100:])
            saved["choices"] = dict(list(saved["choices"].items())[-300:])
            self._write(self.workspace_path, {"schema_version": 1, **saved})
            return saved

    def forget_workspace_device(self, payload: dict[str, Any]) -> dict[str, Any]:
        """Forget a run/suite device without discarding platform or target configuration."""
        with self._workspace_lock:
            saved = self.workspace()
            ids = {}
            for field in ("project_id", "run_id", "suite_id"):
                value = str(payload.get(field, "")).strip()
                if value and (not value.isascii() or not value.isdigit() or int(value) < 1):
                    raise ValidationError(f"{field} must be a positive TestRail ID.")
                ids[field] = value
            if not ids["project_id"] or not ids["run_id"]:
                raise ValidationError("Select a run before forgetting its device.")
            keys = [f"run:{ids['project_id']}:{ids['run_id']}"]
            if ids["suite_id"]:
                keys.append(f"suite:{ids['project_id']}:{ids['suite_id']}")
            for key in keys:
                choice = saved["choices"].get(key)
                if isinstance(choice, dict):
                    saved["choices"][key] = {**choice, "device_id": ""}
            self._write(self.workspace_path, {"schema_version": 1, **saved})
            return saved

    @property
    def uses_keychain(self) -> bool:
        return sys.platform == "darwin" and Path("/usr/bin/security").is_file()

    @property
    def uses_dpapi(self) -> bool:
        return sys.platform == "win32" and bool(self._powershell())

    def load(self) -> Config:
        base = Config.from_env()
        values = asdict(base)
        saved = self._settings_values()
        for key in PUBLIC_FIELDS:
            if key in saved:
                values[key] = saved[key]
        fallback = self._read(self.fallback_secrets_path)
        protected = self._read(self.dpapi_secrets_path)
        for key in SECRET_FIELDS:
            if not values.get(key):
                if self.uses_keychain:
                    values[key] = self._keychain_get(key)
                elif self.uses_dpapi:
                    values[key] = self._dpapi_decrypt(str(protected.get(key, "")))
                else:
                    values[key] = str(fallback.get(key, ""))
        if not values.get("evidence_key"):
            values["evidence_key"] = base64.urlsafe_b64encode(os.urandom(32)).decode("ascii")
            if self.uses_keychain:
                self._keychain_set("evidence_key", values["evidence_key"])
            elif self.uses_dpapi:
                protected["evidence_key"] = self._dpapi_encrypt(values["evidence_key"])
                self._write(self.dpapi_secrets_path, protected)
            else:
                fallback["evidence_key"] = values["evidence_key"]
                self._write(self.fallback_secrets_path, fallback)
        values["max_images"] = self._max_images(values.get("max_images", 16))
        values["ai_max_images"] = self._ai_max_images(values.get("ai_max_images", 40))
        values["max_recording_seconds"] = self._max_recording_seconds(
            values.get("max_recording_seconds", 900)
        )
        values["capture_interval"] = self._capture_interval(values.get("capture_interval", 1.25))
        values["hourly_rate_usd"] = self._hourly_rate(values.get("hourly_rate_usd", 0))
        values["min_apply_confidence"] = self._bounded_float(values.get("min_apply_confidence", 0), 0, 1, "minimum confidence")
        values["min_verification_confidence"] = self._bounded_float(values.get("min_verification_confidence", 0.8), 0, 1, "verification confidence")
        values["capture_retention_hours"] = self._bounded_int(values.get("capture_retention_hours", 1), 1, 24 * 365, "capture_retention_hours")
        values["cache_retention_hours"] = self._bounded_int(values.get("cache_retention_hours", 24), 1, 24 * 365, "cache_retention_hours")
        values["draft_retention_days"] = self._bounded_int(values.get("draft_retention_days", 0), 0, 3650, "draft_retention_days")
        values["history_retention_days"] = self._bounded_int(values.get("history_retention_days", 0), 0, 3650, "history_retention_days")
        self._validate(values)
        return Config(**values)

    def public(self, config: Config) -> dict[str, Any]:
        values = asdict(config)
        result = {key: values[key] for key in PUBLIC_FIELDS}
        result.update({
            "openai_api_key_set": bool(config.openai_api_key),
            "testrail_api_key_set": bool(config.testrail_api_key),
            "secret_storage": "macOS Keychain" if self.uses_keychain else "Windows DPAPI (current user)" if self.uses_dpapi else "local file with 0600 permissions",
            "settings_file": str(self.path),
        })
        return result

    def save(self, payload: dict[str, Any], current: Config) -> Config:
        values = asdict(current)
        saved: dict[str, Any] = {}
        for key in PUBLIC_FIELDS:
            if key not in payload:
                saved[key] = values[key]
                continue
            value: Any = payload[key]
            if key == "max_images":
                value = self._max_images(value)
            elif key == "ai_max_images":
                value = self._ai_max_images(value)
            elif key == "max_recording_seconds":
                value = self._max_recording_seconds(value)
            elif key == "capture_interval":
                value = self._capture_interval(value)
            elif key == "hourly_rate_usd":
                value = self._hourly_rate(value)
            elif key in {"min_apply_confidence", "min_verification_confidence"}:
                value = self._bounded_float(value, 0, 1, key.replace("_", " "))
            elif key in {"capture_retention_hours", "cache_retention_hours"}:
                value = self._bounded_int(value, 1, 24 * 365, key)
            elif key in {"draft_retention_days", "history_retention_days"}:
                value = self._bounded_int(value, 0, 3650, key)
            elif key == "allow_provider_fallback":
                value = value is True or str(value).strip().lower() in {"1", "true", "yes", "on"}
            else:
                value = str(value or "").strip()
            values[key] = value
            saved[key] = value
        self._validate(saved)
        values.update(saved)
        if not values.get("vision_provider"):
            raise ValidationError("Pick Codex, Claude or the OpenAI API as the vision provider.")
        self._write(self.path, {"schema_version": self.SETTINGS_SCHEMA_VERSION, "settings": saved})

        fallback = self._read(self.fallback_secrets_path)
        protected = self._read(self.dpapi_secrets_path)
        for key in SECRET_FIELDS:
            supplied = str(payload.get(key, "")).strip()
            if not supplied:
                continue
            values[key] = supplied
            if self.uses_keychain:
                self._keychain_set(key, supplied)
            elif self.uses_dpapi:
                protected[key] = self._dpapi_encrypt(supplied)
            else:
                fallback[key] = supplied
        if self.uses_dpapi and protected:
            self._write(self.dpapi_secrets_path, protected)
        if not self.uses_keychain and not self.uses_dpapi and fallback:
            self._write(self.fallback_secrets_path, fallback)
        return Config(**values)

    def profiles(self) -> dict[str, Any]:
        profiles = self._profiles_values()
        return {"profiles": [{
            "name": name,
            "project_id": str(value.get("testrail_project_id", "")),
            "provider": str(value.get("vision_provider", "")),
        } for name, value in sorted(profiles.items()) if isinstance(value, dict)]}

    def save_profile(self, name: str, current: Config) -> dict[str, Any]:
        clean_name = name.strip()
        if not 1 <= len(clean_name) <= 80 or not re.fullmatch(r"[\w .()/-]+", clean_name, re.UNICODE):
            raise ValidationError("The profile name contains characters that are not allowed.")
        profiles = self._profiles_values()
        values = asdict(current)
        profiles[clean_name] = {key: values[key] for key in PUBLIC_FIELDS}
        self._write(self.profiles_path, {"schema_version": self.PROFILES_SCHEMA_VERSION, "profiles": profiles})
        return self.profiles()

    def activate_profile(self, name: str, current: Config) -> Config:
        profiles = self._profiles_values()
        profile = profiles.get(name)
        if not isinstance(profile, dict):
            raise ValidationError("That profile does not exist.")
        return self.save(profile, current)

    def delete_profile(self, name: str) -> dict[str, Any]:
        profiles = self._profiles_values()
        if name not in profiles:
            raise ValidationError("That profile does not exist.")
        del profiles[name]
        self._write(self.profiles_path, {"schema_version": self.PROFILES_SCHEMA_VERSION, "profiles": profiles})
        return self.profiles()

    @staticmethod
    def _max_images(value: Any) -> int:
        try:
            parsed = int(value)
        except (TypeError, ValueError) as exc:
            raise ValidationError("The screen limit must be a number.") from exc
        # El techo alto es deliberado: una tablet lenta gasta unos 5 s por pantalla
        # guardada, así que 16 cortaba el recorrido cerca del minuto y medio. El
        # coste real lo sigue gobernando la calidad de visión, no este número.
        if not 2 <= parsed <= 200:
            raise ValidationError("The screen limit must be between 2 and 200.")
        return parsed

    @staticmethod
    def _hourly_rate(value: Any) -> float:
        """Tarifa para expresar el tiempo en dinero. Sin ella no se convierte nada:
        inventar la tarifa sería inventar la cifra que domina el resultado."""
        try:
            parsed = float(value or 0)
        except (TypeError, ValueError) as exc:
            raise ValidationError("The hourly rate must be a number.") from exc
        if not 0 <= parsed <= 10000:
            raise ValidationError("The hourly rate must be between 0 and 10000.")
        return round(parsed, 2)

    @staticmethod
    def _capture_interval(value: Any) -> float:
        """Cadencia de captura. Más corta reacciona mejor a pantallas rápidas; el
        suelo evita pedir capturas más seguido de lo que tarda un screencap."""
        try:
            parsed = float(value)
        except (TypeError, ValueError) as exc:
            raise ValidationError("The capture interval must be a number.") from exc
        if not 0.5 <= parsed <= 10:
            raise ValidationError("The capture interval must be between 0.5 and 10 seconds.")
        return round(parsed, 2)

    @staticmethod
    def _bounded_float(value: Any, minimum: float, maximum: float, label: str) -> float:
        try:
            parsed = float(value)
        except (TypeError, ValueError) as exc:
            raise ValidationError(f"The {label} must be a number.") from exc
        if not minimum <= parsed <= maximum:
            raise ValidationError(f"The {label} must be between {minimum} and {maximum}.")
        return round(parsed, 3)

    @staticmethod
    def _bounded_int(value: Any, minimum: int, maximum: int, label: str) -> int:
        try:
            parsed = int(value)
        except (TypeError, ValueError) as exc:
            raise ValidationError(f"{label} must be a whole number.") from exc
        if not minimum <= parsed <= maximum:
            raise ValidationError(f"{label} must be between {minimum} and {maximum}.")
        return parsed

    @staticmethod
    def _ai_max_images(value: Any) -> int:
        try:
            parsed = int(value)
        except (TypeError, ValueError) as exc:
            raise ValidationError("The AI screen budget must be a whole number.") from exc
        if not 1 <= parsed <= 200:
            raise ValidationError("The AI screen budget must be between 1 and 200.")
        return parsed

    @staticmethod
    def _max_recording_seconds(value: Any) -> int:
        try:
            parsed = int(value)
        except (TypeError, ValueError) as exc:
            raise ValidationError("The maximum duration must be a number.") from exc
        if not 60 <= parsed <= 3600:
            raise ValidationError("The maximum duration must be between 60 and 3600 seconds.")
        return parsed

    @staticmethod
    def _validate(values: dict[str, Any]) -> None:
        values["testrail_url"] = _validated_service_url(
            values.get("testrail_url"), "TestRail", "https://tuempresa.testrail.com"
        )
        appium_url = values["appium_url"] = _validated_service_url(
            values.get("appium_url"), "Appium", "http://127.0.0.1:4723"
        )
        template = str(values.get("case_template", "") or "")
        if len(template) > 4000:
            raise ValidationError("The case template must be 4000 characters or fewer.")
        values["case_template"] = template.strip()
        procedures = str(values.get("test_procedures", "") or "")
        if len(procedures) > 4000:
            raise ValidationError("The test procedures must be 4000 characters or fewer.")
        values["test_procedures"] = procedures.strip()
        bundle_id = str(values.get("ios_bundle_id", "")).strip()
        if bool(appium_url) != bool(bundle_id):
            raise ValidationError("Set the Appium URL and the iOS bundle ID together.")
        if bundle_id and not re.fullmatch(r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+", bundle_id):
            raise ValidationError("The iOS bundle ID is not valid.")
        capabilities_text = str(values.get("appium_capabilities_json", "{}") or "{}").strip()
        if len(capabilities_text) > 10000:
            raise ValidationError("The Appium capabilities are too large.")
        try:
            capabilities = json.loads(capabilities_text)
        except json.JSONDecodeError as exc:
            raise ValidationError("The Appium capabilities must be valid JSON.") from exc
        if not isinstance(capabilities, dict) or any(
            not isinstance(key, str) or not key.startswith("appium:") for key in capabilities
        ):
            raise ValidationError("Cada capability adicional debe comenzar con appium:.")
        reserved = {"appium:automationName", "appium:udid", "appium:bundleId"}
        if reserved.intersection(capabilities):
            raise ValidationError("No sobrescribas automationName, udid o bundleId en capabilities adicionales.")
        if any(fragment in key.lower() for key in capabilities for fragment in ("password", "token", "secret")):
            raise ValidationError("No guardes passwords, tokens o secretos dentro de capabilities adicionales.")
        values["appium_capabilities_json"] = json.dumps(capabilities, separators=(",", ":"), ensure_ascii=False)
        ios_devices_text = str(values.get("ios_devices_json", "[]") or "[]").strip()
        if len(ios_devices_text) > 20000:
            raise ValidationError("La lista de dispositivos iOS remotos es demasiado grande.")
        try:
            ios_devices = json.loads(ios_devices_text)
        except json.JSONDecodeError as exc:
            raise ValidationError("The remote iOS devices must be valid JSON.") from exc
        if not isinstance(ios_devices, list) or len(ios_devices) > 100 or any(
            not isinstance(item, dict)
            or not isinstance(item.get("id"), str) or not 1 <= len(item["id"]) <= 200
            or not isinstance(item.get("name"), str) or not 1 <= len(item["name"]) <= 200
            or not isinstance(item.get("version", ""), str) or len(item.get("version", "")) > 100
            for item in ios_devices
        ):
            raise ValidationError("Cada dispositivo iOS remoto necesita id, name y una version opcional.")
        if ios_devices and not appium_url:
            raise ValidationError("Configura Appium antes de agregar dispositivos iOS remotos.")
        values["ios_devices_json"] = json.dumps(ios_devices, separators=(",", ":"), ensure_ascii=False)
        developer_dir = str(values.get("developer_dir", "") or "").strip()
        if developer_dir:
            path = Path(developer_dir).expanduser()
            if not path.is_dir() or not (path / "usr" / "bin" / "xcodebuild").is_file() or not (
                path / "Platforms" / "iPhoneSimulator.platform"
            ).is_dir():
                raise ValidationError("Xcode Developer directory must contain xcodebuild and iPhoneSimulator.platform.")
            values["developer_dir"] = str(path.resolve())
        else:
            values["developer_dir"] = ""
        write_mode = str(values.get("write_mode", "confirm")).strip().lower()
        if write_mode not in {"confirm", "review_only"}:
            raise ValidationError("El modo de escritura debe ser confirm o review_only.")
        values["write_mode"] = write_mode
        provider = str(values.get("vision_provider", "")).strip().lower()
        if provider not in {"", "codex", "claude", "openai_api"}:
            raise ValidationError("That vision provider is not valid.")
        values["vision_provider"] = provider
        fallback = str(values.get("fallback_provider", "")).strip().lower()
        enabled = values.get("allow_provider_fallback") is True or str(values.get("allow_provider_fallback", "")).lower() == "true"
        if fallback not in {"", "codex", "claude"}:
            raise ValidationError("El proveedor alterno debe ser Codex o Claude.")
        if enabled and (provider not in {"codex", "claude"} or fallback not in {"codex", "claude"} or fallback == provider):
            raise ValidationError("Automatic switching needs Codex and Claude as two different providers.")
        values["allow_provider_fallback"] = enabled
        values["fallback_provider"] = fallback
        quality = str(values.get("vision_quality", "high")).strip().lower()
        if quality not in {"economical", "high", "maximum"}:
            raise ValidationError("Vision quality must be economical, high or maximum.")
        values["vision_quality"] = quality
        for field in ("testrail_steps_field", "testrail_preconditions_field"):
            if not str(values.get(field, "")).startswith("custom_"):
                raise ValidationError(f"{field} must start with custom_.")

    def _profiles_values(self) -> dict[str, Any]:
        raw = self._read(self.profiles_path)
        if not raw:
            return {}
        # `version` was used by the first profile implementation; accept and
        # atomically upgrade it before using the common schema name.
        version = raw.get("schema_version", raw.get("version"))
        profiles = raw.get("profiles")
        if not isinstance(profiles, dict):
            raise ValidationError("The Profiles file has no valid profiles object.")
        if version not in (None, self.PROFILES_SCHEMA_VERSION):
            raise ValidationError("This Profiles file was created by a newer QA Sync version. It was left unchanged.")
        if raw.get("schema_version") != self.PROFILES_SCHEMA_VERSION:
            self._write(self.profiles_path, {"schema_version": self.PROFILES_SCHEMA_VERSION, "profiles": profiles})
        return profiles

    def _settings_values(self) -> dict[str, Any]:
        """Read legacy flat settings once, then keep an explicit migration boundary."""
        raw = self._read(self.path)
        if not raw:
            return {}
        if "schema_version" not in raw:
            # All older releases stored public Settings as a flat object. Rewrite it
            # atomically in the first versioned shape without changing any value.
            self._write(self.path, {"schema_version": self.SETTINGS_SCHEMA_VERSION, "settings": raw})
            return raw
        if raw.get("schema_version") != self.SETTINGS_SCHEMA_VERSION:
            raise ValidationError("This Settings file was created by a newer QA Sync version. It was left unchanged.")
        settings = raw.get("settings")
        if not isinstance(settings, dict):
            raise ValidationError("The versioned Settings file has no valid settings object.")
        return settings

    @staticmethod
    def _read(path: Path) -> dict[str, Any]:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
        except json.JSONDecodeError:
            backup = path.with_name(f"{path.stem}.corrupt-{int(time.time())}{path.suffix}")
            try:
                path.replace(backup)
                private_file(backup)
            except OSError:
                pass
            return {}
        except OSError:
            return {}

    @staticmethod
    def _write(path: Path, data: dict[str, Any]) -> None:
        private_dir(path.parent)
        temporary = path.with_suffix(path.suffix + ".tmp")
        temporary.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
        private_file(temporary)
        temporary.replace(path)

    @staticmethod
    def _keychain_get(account: str) -> str:
        result = subprocess.run(
            ["/usr/bin/security", "find-generic-password", "-s", KEYCHAIN_SERVICE, "-a", account, "-w"],
            capture_output=True,
            text=True,
            check=False,
        )
        return result.stdout.strip() if result.returncode == 0 else ""

    @staticmethod
    def _keychain_set(account: str, value: str) -> None:
        result = subprocess.run(
            ["/usr/bin/security", "add-generic-password", "-U", "-s", KEYCHAIN_SERVICE, "-a", account, "-w", value],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode:
            raise ValidationError("A credential could not be stored in the macOS Keychain.")

    @staticmethod
    def _powershell() -> str:
        system_root = os.getenv("SystemRoot", "").strip()
        if not system_root:
            return ""
        executable = Path(system_root) / "System32" / "WindowsPowerShell" / "v1.0" / "powershell.exe"
        return str(executable) if executable.is_file() else ""

    @classmethod
    def _run_powershell(cls, script: str, secret_input: str) -> subprocess.CompletedProcess[str]:
        """Run a DPAPI script with an encoding pinned on both sides of the pipe.

        PowerShell emits its stdout in the console OEM codepage, which does not match
        the locale encoding Python would otherwise decode with: a secret holding a
        non-ASCII character came back corrupted. Both ends are forced to UTF-8 (without
        a BOM, which would end up inside the value) so the round-trip no longer depends
        on the machine's codepage nor on PYTHONUTF8.
        """
        environment = os.environ.copy()
        environment["QA_SYNC_SECRET_INPUT"] = secret_input
        return subprocess.run([
            cls._powershell(), "-NoProfile", "-NonInteractive", "-Command",
            "[Console]::OutputEncoding=New-Object Text.UTF8Encoding $false; " + script,
        ], capture_output=True, text=True, encoding="utf-8", check=False, env=environment, timeout=20)

    @classmethod
    def _dpapi_encrypt(cls, value: str) -> str:
        try:
            result = cls._run_powershell(
                "$s=ConvertTo-SecureString $env:QA_SYNC_SECRET_INPUT -AsPlainText -Force; ConvertFrom-SecureString $s",
                value,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise ValidationError("Windows could not run DPAPI through PowerShell.") from exc
        if result.returncode or not (result.stdout or "").strip():
            raise ValidationError("Windows could not protect a credential with DPAPI.")
        return result.stdout.strip()

    @classmethod
    def _dpapi_decrypt(cls, value: str) -> str:
        if not value:
            return ""
        try:
            result = cls._run_powershell(
                "$s=ConvertTo-SecureString $env:QA_SYNC_SECRET_INPUT; $p=[Runtime.InteropServices.Marshal]::SecureStringToBSTR($s); try {[Runtime.InteropServices.Marshal]::PtrToStringBSTR($p)} finally {[Runtime.InteropServices.Marshal]::ZeroFreeBSTR($p)}",
                value,
            )
        except (OSError, subprocess.TimeoutExpired):
            return ""
        return (result.stdout or "").rstrip("\r\n") if result.returncode == 0 else ""
