from __future__ import annotations

import base64
import json
from typing import Any

from .errors import ExternalServiceError
from .http_client import request_json


class AppiumClient:
    def __init__(self, url: str, bundle_id: str, capabilities_json: str = "{}"):
        self.url = url.rstrip("/")
        self.bundle_id = bundle_id
        parsed = json.loads(capabilities_json or "{}")
        self.extra_capabilities = parsed if isinstance(parsed, dict) else {}

    def status(self) -> dict[str, Any]:
        response = request_json(f"{self.url}/status", timeout=3)
        if not isinstance(response, dict):
            raise ExternalServiceError("Appium devolvió un estado inválido.")
        value = response.get("value") if isinstance(response.get("value"), dict) else response
        return {"ready": bool(value.get("ready", True)), "message": str(value.get("message", ""))[:300]}

    def create_session(self, udid: str) -> str:
        response = request_json(
            f"{self.url}/session",
            method="POST",
            body={"capabilities": {"alwaysMatch": {
                **self.extra_capabilities,
                "platformName": "iOS",
                "appium:automationName": "XCUITest",
                "appium:udid": udid,
                "appium:bundleId": self.bundle_id,
                "appium:noReset": True,
                "appium:newCommandTimeout": 1200,
            }}},
            timeout=120,
        )
        if not isinstance(response, dict):
            raise ExternalServiceError("Appium devolvió una sesión inválida.")
        value = response.get("value") if isinstance(response.get("value"), dict) else {}
        session_id = str(response.get("sessionId") or value.get("sessionId") or "")
        if not session_id:
            raise ExternalServiceError("Appium no devolvió sessionId. Revisa WebDriverAgent y el bundle ID.")
        return session_id

    def screenshot(self, session_id: str) -> bytes:
        response = request_json(f"{self.url}/session/{session_id}/screenshot", timeout=45)
        value = response.get("value") if isinstance(response, dict) else None
        try:
            return base64.b64decode(str(value), validate=True)
        except ValueError as exc:
            raise ExternalServiceError("Appium devolvió una captura inválida.") from exc

    def source(self, session_id: str) -> str:
        response = request_json(f"{self.url}/session/{session_id}/source", timeout=30)
        return str(response.get("value", "")) if isinstance(response, dict) else ""

    def window_rect(self, session_id: str) -> tuple[int, int]:
        response = request_json(f"{self.url}/session/{session_id}/window/rect", timeout=30)
        value = response.get("value") if isinstance(response, dict) else None
        if not isinstance(value, dict):
            raise ExternalServiceError("Appium no devolvió el tamaño de la pantalla.")
        width, height = value.get("width"), value.get("height")
        if not isinstance(width, int) or not isinstance(height, int) or width <= 0 or height <= 0:
            raise ExternalServiceError("Appium devolvió dimensiones inválidas.")
        return width, height

    def action(
        self,
        session_id: str,
        action_type: str,
        start: tuple[int, int],
        end: tuple[int, int],
    ) -> None:
        duration = 80 if action_type == "tap" else 450
        actions: list[dict[str, Any]] = [
            {"type": "pointerMove", "duration": 0, "x": start[0], "y": start[1], "origin": "viewport"},
            {"type": "pointerDown", "button": 0},
            {"type": "pause", "duration": duration},
        ]
        if action_type == "swipe":
            actions.append({
                "type": "pointerMove", "duration": duration,
                "x": end[0], "y": end[1], "origin": "viewport",
            })
        actions.append({"type": "pointerUp", "button": 0})
        request_json(
            f"{self.url}/session/{session_id}/actions",
            method="POST",
            body={"actions": [{"type": "pointer", "id": "qa-sync-touch", "parameters": {"pointerType": "touch"}, "actions": actions}]},
            timeout=45,
        )

    def text(self, session_id: str, value: str) -> None:
        request_json(
            f"{self.url}/session/{session_id}/keys",
            method="POST",
            body={"text": value, "value": list(value)},
            timeout=45,
        )

    def close(self, session_id: str) -> None:
        try:
            request_json(f"{self.url}/session/{session_id}", method="DELETE", body={}, timeout=30)
        except ExternalServiceError:
            pass
