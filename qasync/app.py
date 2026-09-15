from __future__ import annotations

import argparse
import json
import mimetypes
import os
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from .errors import QASyncError, ValidationError
from .service import QASyncService
from .settings import SettingsManager
from .state import private_dir, private_file, state_root

STATIC_DIR = Path(__file__).with_name("static")
LOOPBACK_HOSTS = {"127.0.0.1", "localhost", "::1"}
MAX_ACTIVE_REQUESTS = 32


def allowed_host(value: str) -> bool:
    host = value.strip().lower()
    if host.startswith("[") and "]" in host:
        hostname = host[1:host.index("]")]
    else:
        hostname = host.split(":", 1)[0]
    return hostname in LOOPBACK_HOSTS


def allowed_origin(value: str) -> bool:
    if not value:
        return True
    parsed = urlparse(value)
    return parsed.scheme == "http" and parsed.hostname in LOOPBACK_HOSTS


class AppHandler(BaseHTTPRequestHandler):
    service: QASyncService
    settings: SettingsManager

    def setup(self) -> None:
        super().setup()
        self.connection.settimeout(20)

    def _trusted_browser_context(self) -> bool:
        return (
            allowed_host(self.headers.get("Host", ""))
            and allowed_origin(self.headers.get("Origin", ""))
            and self.headers.get("Sec-Fetch-Site", "same-origin") not in {"cross-site"}
        )

    def log_message(self, format: str, *args: object) -> None:
        # Evita que cuerpos, tokens o credenciales terminen en logs.
        print(f"{self.address_string()} - {format % args}")

    def _json(self, status: int, payload: dict[str, Any]) -> None:
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        self.send_header("Referrer-Policy", "no-referrer")
        self.end_headers()
        self.wfile.write(data)

    def _read_json(self) -> dict[str, Any]:
        if self.headers.get_content_type() != "application/json":
            raise ValidationError("Content-Type debe ser application/json.")
        raw_length = self.headers.get("Content-Length", "")
        if not raw_length.isdigit():
            raise ValidationError("Content-Length inválido.")
        length = int(raw_length)
        if length <= 0 or length > self.service.config.max_request_bytes:
            raise ValidationError("La solicitud está vacía o supera 45 MB.")
        try:
            payload = json.loads(self.rfile.read(length))
        except json.JSONDecodeError as exc:
            raise ValidationError("JSON inválido.") from exc
        if not isinstance(payload, dict):
            raise ValidationError("El cuerpo debe ser un objeto JSON.")
        return payload

    def do_GET(self) -> None:
        if not self._trusted_browser_context():
            self._json(403, {"error": "Solicitud local rechazada."})
            return
        path = urlparse(self.path).path
        if path.startswith("/api/"):
            try:
                if path == "/api/status":
                    result = {
                        **self.service.config.public_status(),
                        "capture": self.service.recorder.capabilities(),
                    }
                elif path == "/api/devices":
                    result = self.service.devices()
                elif path == "/api/providers":
                    result = self.service.providers()
                elif path == "/api/audit":
                    result = self.service.audit_report()
                elif path == "/api/device-matrix":
                    result = self.service.device_matrix()
                elif path == "/api/settings":
                    result = self.settings.public(self.service.config)
                elif path == "/api/profiles":
                    result = self.settings.profiles()
                elif path == "/api/recovery":
                    result = self.service.recovery()
                else:
                    self._json(404, {"error": "Ruta no encontrada."})
                    return
                self._json(200, result)
            except QASyncError as exc:
                self._json(400, {"error": str(exc)})
            except Exception:
                self._json(500, {"error": "Error interno. Revisa la terminal para más detalles."})
            return
        relative = "index.html" if path == "/" else path.lstrip("/")
        target = (STATIC_DIR / relative).resolve()
        if STATIC_DIR.resolve() not in target.parents and target != STATIC_DIR.resolve():
            self.send_error(404)
            return
        if not target.is_file():
            self.send_error(404)
            return
        data = target.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", mimetypes.guess_type(target.name)[0] or "application/octet-stream")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'; object-src 'none'")
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self) -> None:
        if not self._trusted_browser_context():
            self._json(403, {"error": "Solicitud local rechazada."})
            return
        try:
            payload = self._read_json()
            path = urlparse(self.path).path
            if path == "/api/analyze":
                result = self.service.analyze(payload)
            elif path == "/api/settings":
                if self.service.recorder.has_active_sessions():
                    raise ValidationError("Finaliza o cancela la grabación antes de cambiar la configuración.")
                config = self.settings.save(payload, self.service.config)
                self.service.recorder.shutdown()
                type(self).service = QASyncService(config)
                result = self.settings.public(config)
            elif path == "/api/profile/save":
                result = self.settings.save_profile(str(payload.get("name", "")), self.service.config)
            elif path == "/api/profile/activate":
                if self.service.recorder.has_active_sessions():
                    raise ValidationError("Finaliza o cancela la grabación antes de cambiar de perfil.")
                config = self.settings.activate_profile(str(payload.get("name", "")), self.service.config)
                self.service.recorder.shutdown()
                type(self).service = QASyncService(config)
                result = self.settings.public(config)
            elif path == "/api/profile/delete":
                result = self.settings.delete_profile(str(payload.get("name", "")))
            elif path == "/api/projects":
                result = self.service.projects()
            elif path == "/api/config/validate":
                result = self.service.validate_configuration()
            elif path == "/api/runs":
                result = self.service.runs(payload)
            elif path == "/api/plan-runs":
                result = self.service.plan_runs(payload)
            elif path == "/api/run":
                result = self.service.run(payload)
            elif path == "/api/tests":
                result = self.service.tests(payload)
            elif path == "/api/case":
                result = self.service.case(payload)
            elif path == "/api/device/open":
                result = self.service.open_device(payload)
            elif path == "/api/device/close-mirror":
                result = self.service.close_mirror(payload)
            elif path == "/api/device/android-disconnect":
                result = self.service.disconnect_android_wireless(payload)
            elif path == "/api/device/android-tcpip":
                result = self.service.enable_android_tcpip(payload)
            elif path == "/api/device/android-discover":
                result = self.service.discover_android_wireless()
            elif path == "/api/device/android-wireless":
                result = self.service.connect_android_wireless(payload)
            elif path == "/api/record/start":
                result = self.service.start_recording(payload)
            elif path == "/api/record/status":
                result = self.service.recording_status(payload)
            elif path == "/api/record/screenshot":
                result = self.service.recording_screenshot(payload)
            elif path == "/api/record/action":
                result = self.service.recording_action(payload)
            elif path == "/api/record/stop":
                result = self.service.stop_recording(payload)
            elif path == "/api/record/cancel":
                result = self.service.cancel_recording(payload)
            elif path == "/api/record/analyze":
                result = self.service.analyze_recording(payload)
            elif path == "/api/proposal/revise":
                result = self.service.revise_proposal(payload)
            elif path == "/api/apply":
                result = self.service.apply(payload)
            elif path == "/api/history":
                result = self.service.history_entries(payload)
            elif path == "/api/rollback":
                result = self.service.rollback(payload)
            else:
                self._json(404, {"error": "Ruta no encontrada."})
                return
            self._json(200, result)
        except QASyncError as exc:
            self._json(400, {"error": str(exc)})
        except Exception:
            self._json(500, {"error": "Error interno. Revisa la terminal para más detalles."})


class BoundedThreadingHTTPServer(ThreadingHTTPServer):
    """Prevent an unbounded number of local connections from exhausting threads."""

    def __init__(self, *args: Any, **kwargs: Any):
        self._slots = threading.BoundedSemaphore(MAX_ACTIVE_REQUESTS)
        super().__init__(*args, **kwargs)

    def process_request(self, request: socket.socket, client_address: Any) -> None:
        if not self._slots.acquire(blocking=False):
            try:
                request.sendall(b"HTTP/1.1 503 Service Unavailable\r\nConnection: close\r\nContent-Length: 0\r\n\r\n")
            finally:
                self.shutdown_request(request)
            return
        super().process_request(request, client_address)

    def process_request_thread(self, request: socket.socket, client_address: Any) -> None:
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()


def run(host: str = "127.0.0.1", port: int = 8787) -> None:
    if host not in {"127.0.0.1", "localhost", "::1"}:
        raise ValidationError("Por seguridad, el servidor local sólo puede escuchar en loopback.")
    if not 1 <= port <= 65535:
        raise ValidationError("El puerto debe estar entre 1 y 65535.")
    settings = SettingsManager()
    config = settings.load()
    AppHandler.settings = settings
    AppHandler.service = QASyncService(config)
    server = BoundedThreadingHTTPServer((host, port), AppHandler)
    server.daemon_threads = True
    # El propio servidor publica su PID: en Windows PowerShell no tiene `exec`, así que el
    # lanzador sólo conocía el PID de su wrapper y detenerlo dejaba vivo al proceso que
    # realmente tiene el socket.
    # ponytail: se escribe al terminar el bind, así que dos arranques en el mismo segundo
    # no se ven entre sí; el segundo muere al no poder tomar el puerto.
    pid_file = private_dir(state_root()) / "server.pid"
    pid_file.write_text(str(os.getpid()), encoding="utf-8")
    private_file(pid_file)
    print(f"QA Sync disponible en http://{host}:{port}")
    print("Presiona Ctrl+C para detenerlo.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        pid_file.unlink(missing_ok=True)
        AppHandler.service.recorder.shutdown()
        server.server_close()


def main() -> None:
    parser = argparse.ArgumentParser(description="QA Sync para TestRail")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8787)
    args = parser.parse_args()
    try:
        run(args.host, args.port)
    except QASyncError as exc:
        # Un .env o unos ajustes inválidos merecen una línea legible, no un traceback
        # que en Windows termina enterrado en server-error.log.
        raise SystemExit(f"QA Sync no pudo iniciar: {exc}") from exc


if __name__ == "__main__":
    main()
