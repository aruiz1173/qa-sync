from __future__ import annotations

import base64
import binascii
import io
import copy
import hashlib
import ipaddress
import json
import os
import re
import shutil
import struct
import subprocess
import tempfile
import threading
import time
import uuid
import xml.etree.ElementTree as ElementTree
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from PIL import Image

from .appium import AppiumClient
from .devices import (
    adb_endpoint_result, parse_adb_devices, parse_adb_mdns_services, parse_adb_tcpip_result,
    parse_android_ip, parse_available_ios_simulators, parse_ios_devices, parse_rotation, parse_scrcpy_major,
    parse_touch_bounds, parse_xctrace_physical_devices,
)
from .errors import ExternalServiceError, ValidationError
from .evidence import EvidenceCipher, MAGIC as ENCRYPTED_MAGIC
from .executables import describe_untrusted, trusted_which
from .state import private_dir, private_file

PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"


def _run(command: list[str], timeout: float = 12, environment: dict[str, str] | None = None) -> subprocess.CompletedProcess[bytes]:
    try:
        return subprocess.run(command, capture_output=True, check=False, timeout=timeout, env=environment)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ExternalServiceError(f"Could not run {command[0]}: {exc}") from exc


@dataclass
class RecordingSession:
    id: str
    platform: str
    device_id: str
    directory: Path
    interval: float
    max_frames: int
    started_at: float = field(default_factory=time.time)
    frames: list[Path] = field(default_factory=list)
    stream_frames: int = 0
    observations: list[str] = field(default_factory=list)
    error: str = ""
    stopped: bool = False
    stop_event: threading.Event = field(default_factory=threading.Event)
    capture_event: threading.Event = field(default_factory=threading.Event)
    thread: threading.Thread | None = None
    last_digest: str = ""
    ended_at: float | None = None
    last_ui_summary: str = ""
    action_process: subprocess.Popen | None = None
    action_thread: threading.Thread | None = None
    appium_session_id: str = ""
    case_id: int | None = None
    environment: dict[str, str] = field(default_factory=dict)
    capture_lock: threading.Lock = field(default_factory=threading.Lock)
    hardware_serial: str = ""
    last_guided_action_at: float = 0.0


class RecorderManager:
    MAX_OBSERVATIONS = 500
    DEVICES_TTL = 2.0

    @classmethod
    def _append_observation(cls, session: RecordingSession, value: str) -> None:
        if len(session.observations) < cls.MAX_OBSERVATIONS:
            session.observations.append(value[:5000])

    def __init__(
        self,
        interval: float = 1.25,
        max_frames: int = 40,
        max_duration: int = 900,
        appium_url: str = "",
        ios_bundle_id: str = "",
        appium_capabilities_json: str = "{}",
        ios_devices_json: str = "[]",
        developer_dir: str = "",
        evidence_key: str = "",
        recovery_dir: Path | None = None,
        recovery_ttl_seconds: int = 3600,
    ):
        self.interval = interval
        self.max_frames = max_frames
        self.max_duration = max_duration
        self.evidence_cipher = EvidenceCipher(evidence_key)
        self.appium = (
            AppiumClient(appium_url, ios_bundle_id, appium_capabilities_json)
            if appium_url and ios_bundle_id else None
        )
        self.ios_bundle_id = ios_bundle_id
        self.developer_dir = developer_dir
        try:
            configured_devices = json.loads(ios_devices_json or "[]")
        except json.JSONDecodeError:
            configured_devices = []
        self.configured_ios_devices = [{
            "id": str(item["id"]), "name": str(item["name"]),
            "kind": f"remote · iOS {str(item.get('version', '')).strip()}".rstrip(),
        } for item in configured_devices if isinstance(item, dict) and item.get("id") and item.get("name")]
        self.recovery_dir = recovery_dir
        self.recovery_ttl_seconds = recovery_ttl_seconds
        self._sessions: dict[str, RecordingSession] = {}
        self._scrcpy_processes: dict[str, subprocess.Popen[Any]] = {}
        self._lock = threading.Lock()
        # Lock propio y no self._lock: list_devices() ya lo toma por dentro y este
        # mapa se muta desde los hilos HTTP, así que compartirlo se trabaría.
        self._mirror_lock = threading.Lock()
        self._devices_lock = threading.Lock()
        self._devices_cache: tuple[float, dict[str, Any]] | None = None
        self._scrcpy_version: int | None = None
        self._touch_state: dict[str, str] = {}
        self._restore_sessions()

    def _run_xcrun(self, executable: str, arguments: list[str], timeout: float = 12) -> subprocess.CompletedProcess[bytes]:
        environment = {**os.environ, "DEVELOPER_DIR": self.developer_dir} if self.developer_dir else None
        return _run([executable, *arguments], timeout=timeout, environment=environment)

    def capabilities(self) -> dict[str, bool]:
        return {
            "adb": bool(trusted_which("adb")),
            "scrcpy": bool(trusted_which("scrcpy")),
            "emulator": bool(trusted_which("emulator")),
            "simctl": bool(trusted_which("xcrun")),
            "appium": bool(self.appium),
            "evidence_encrypted": True,
        }

    def _reap_mirrors(self) -> None:
        """Drop scrcpy processes that already exited so the UI never shows a dead mirror."""
        with self._mirror_lock:
            for device_id, process in list(self._scrcpy_processes.items()):
                if process.poll() is not None:
                    self._scrcpy_processes.pop(device_id, None)

    def mirrors(self) -> dict[str, bool]:
        self._reap_mirrors()
        with self._mirror_lock:
            return {device_id: True for device_id in self._scrcpy_processes}

    def list_devices(self, force: bool = False) -> dict[str, Any]:
        """Device inventory, cached briefly.

        Every call shells out to adb, simctl and xctrace, and `open_device`/`start`
        each ask again to validate their argument; `xctrace list devices` alone takes
        seconds. A short TTL keeps one click from paying for three inventories.
        """
        with self._devices_lock:
            cached = self._devices_cache
            if not force and cached and time.time() - cached[0] < self.DEVICES_TTL:
                # El estado del espejo queda fuera del cache: es justo lo que cambia
                # cuando alguien cierra la ventana de scrcpy.
                return {**copy.deepcopy(cached[1]), "mirrors": self.mirrors()}
        result = self._collect_devices()
        with self._devices_lock:
            self._devices_cache = (time.time(), copy.deepcopy(result))
        return {**result, "mirrors": self.mirrors()}

    @staticmethod
    def _avd_metadata(name: str) -> dict[str, str]:
        """Read local AVD metadata without booting the emulator."""
        configured = os.getenv("ANDROID_AVD_HOME", "").strip()
        root = Path(configured) if configured else Path.home() / ".android" / "avd"
        config = root / f"{name}.avd" / "config.ini"
        try:
            raw = config.read_text(encoding="utf-8", errors="replace")[:100_000]
        except OSError:
            return {}
        values: dict[str, str] = {}
        for line in raw.splitlines():
            key, separator, value = line.partition("=")
            if separator:
                values[key.strip()] = value.strip()
        image = values.get("image.sysdir.1", "").strip("/")
        api = re.search(r"(?:^|/)android-(\d+)(?:/|$)", image)
        result = {
            "api_level": api.group(1) if api else "",
            "abi": values.get("abi.type", "")[:40],
            "image": image[:160],
            "device": values.get("hw.device.name", "")[:80],
        }
        return {key: value for key, value in result.items() if value}

    def _collect_devices(self) -> dict[str, Any]:
        self._cleanup_expired()
        adb = trusted_which("adb")
        xcrun = trusted_which("xcrun")
        emulator = trusted_which("emulator")
        caps = {
            "adb": bool(adb), "scrcpy": bool(trusted_which("scrcpy")),
            "emulator": bool(emulator), "simctl": bool(xcrun), "appium": bool(self.appium),
            "evidence_encrypted": True,
        }
        android: list[dict[str, str]] = []
        android_unavailable: list[dict[str, str]] = []
        android_avds: list[dict[str, str]] = []
        ios: list[dict[str, str]] = list(self.configured_ios_devices) if self.appium else []
        ios_simulators: list[dict[str, str]] = []
        errors: list[str] = []

        def tool_error(label: str, name: str) -> str:
            """Keep the UI diagnosis precise when a present binary is rejected."""
            detail = describe_untrusted(name)
            if detail.startswith(f"{name} "):
                detail = f"{label}{detail[len(name):]}"
            return f"Android: {detail}"

        if adb:
            result = _run([adb, "devices", "-l"])
            if result.returncode == 0:
                adb_output = result.stdout.decode(errors="replace")
                android = parse_adb_devices(adb_output)
                # La versión se muestra al elegir dispositivo, no sólo al terminar
                # una grabación. Es una consulta corta por equipo y falla de forma
                # aislada: un móvil lento no debe desaparecer de la lista.
                for device in android:
                    try:
                        version = _run([
                            adb, "-s", device["id"], "shell", "getprop",
                            "ro.build.version.release",
                        ], timeout=4)
                    except ExternalServiceError:
                        continue
                    if version.returncode == 0:
                        value = version.stdout.decode(errors="replace").strip()
                        if value:
                            device["version"] = value[:40]
                for raw in adb_output.splitlines()[1:]:
                    parts = raw.strip().split()
                    if len(parts) < 2 or parts[1] == "device":
                        continue
                    serial, state = parts[0][:200], parts[1].lower()
                    if state == "unauthorized":
                        android_unavailable.append({"id": serial, "name": serial, "kind": "unauthorised"})
                        errors.append(f"Android {serial}: authorise the USB debugging key on the device.")
                    elif state == "offline":
                        android_unavailable.append({"id": serial, "name": serial, "kind": "offline"})
                        errors.append(f"Android {serial}: it is offline; reconnect USB or Wireless Debugging.")
                    else:
                        android_unavailable.append({"id": serial, "name": serial, "kind": state[:40]})
                        errors.append(f"Android {serial}: ADB reports state {state[:40]}.")
            else:
                errors.append("Android: ADB could not list devices.")
        else:
            errors.append(tool_error("ADB", "adb"))
        if emulator:
            result = _run([emulator, "-list-avds"], timeout=15)
            if result.returncode == 0:
                for name in result.stdout.decode(errors="replace").splitlines():
                    clean = name.strip()
                    if re.fullmatch(r"[A-Za-z0-9_. -]{1,120}", clean):
                        android_avds.append({"id": clean, "name": clean, "kind": "Android virtual device", **self._avd_metadata(clean)})
            else:
                errors.append("Android: the emulator tool could not list virtual devices.")
        elif not android:
            errors.append(tool_error("Android Emulator", "emulator"))
        if android and not caps["scrcpy"]:
            # Un scrcpy presente pero rechazado no es "no instalado": el diagnóstico
            # dice el motivo y, si es la firma, el hash que hay que fijar.
            errors.append("Android: " + describe_untrusted("scrcpy"))
        if xcrun:
            result = self._run_xcrun(xcrun, ["simctl", "list", "devices", "booted", "--json"])
            if result.returncode == 0:
                local_ios = parse_ios_devices(result.stdout.decode(errors="replace"))
                known = {item["id"] for item in ios}
                ios.extend(item for item in local_ios if item["id"] not in known)
            else:
                errors.append("iOS: Xcode could not list booted simulators.")
            available = self._run_xcrun(xcrun, ["simctl", "list", "devices", "available", "--json"])
            if available.returncode == 0:
                ios_simulators = parse_available_ios_simulators(available.stdout.decode(errors="replace"))
            if self.appium:
                try:
                    physical = self._run_xcrun(xcrun, ["xctrace", "list", "devices"])
                    if physical.returncode == 0:
                        known = {item["id"] for item in ios}
                        ios.extend(item for item in parse_xctrace_physical_devices(
                            physical.stdout.decode(errors="replace")
                        ) if item["id"] not in known)
                except ExternalServiceError:
                    errors.append("iOS: Xcode could not list physical iOS devices.")
        elif not ios:
            errors.append("iOS: Xcode/simctl is unavailable and no remote Appium devices are configured.")
        return {
            "android": android, "android_unavailable": android_unavailable,
            "android_avds": android_avds, "ios": ios, "ios_simulators": ios_simulators,
            "capabilities": caps, "errors": errors,
        }

    def launch_android_emulator(self, avd_name: object) -> dict[str, str]:
        """Start one operator-selected AVD with its window visible on macOS or Windows."""
        name = str(avd_name or "").strip()
        if not re.fullmatch(r"[A-Za-z0-9_. -]{1,120}", name):
            raise ValidationError("Select a valid Android virtual device.")
        executable = trusted_which("emulator")
        if not executable:
            raise ValidationError(describe_untrusted("emulator"))
        result = _run([executable, "-list-avds"], timeout=15)
        available = {line.strip() for line in result.stdout.decode(errors="replace").splitlines()}
        if result.returncode or name not in available:
            raise ValidationError("That Android virtual device is no longer available. Refresh the list.")
        try:
            subprocess.Popen([executable, "-avd", name], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except OSError as exc:
            raise ExternalServiceError(f"The Android emulator could not start: {exc}") from exc
        self.invalidate_devices()
        return {"name": name, "status": "starting"}

    def launch_ios_simulator(self, simulator_id: object) -> dict[str, str]:
        """Boot a selected local iOS Simulator. This is intentionally macOS-only."""
        identifier = str(simulator_id or "").strip()
        if not re.fullmatch(r"[A-Za-z0-9-]{8,100}", identifier):
            raise ValidationError("Select a valid iOS Simulator.")
        xcrun = trusted_which("xcrun")
        if not xcrun:
            raise ValidationError("iOS Simulator needs macOS with Xcode installed.")
        result = self._run_xcrun(xcrun, ["simctl", "list", "devices", "available", "--json"], timeout=20)
        available = parse_available_ios_simulators(result.stdout.decode(errors="replace")) if result.returncode == 0 else []
        if identifier not in {item["id"] for item in available}:
            raise ValidationError("That iOS Simulator is unavailable. Refresh the list.")
        boot = self._run_xcrun(xcrun, ["simctl", "boot", identifier], timeout=30)
        if boot.returncode:
            detail = (boot.stdout + boot.stderr).decode(errors="replace").strip()[:300]
            raise ExternalServiceError(f"The iOS Simulator could not boot: {detail}")
        try:
            subprocess.Popen(["/usr/bin/open", "-a", "Simulator"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except OSError as exc:
            raise ExternalServiceError(f"The Simulator app could not open: {exc}") from exc
        self.invalidate_devices()
        return {"id": identifier, "status": "starting"}

    def _scrcpy_command(self, executable: str, device_id: str) -> list[str]:
        command = [executable, "--serial", device_id, "--window-title", "QA Sync · Android"]
        # Sin --stay-awake la pantalla se duerme a media grabación y los frames salen
        # en negro. --no-audio no existe antes de scrcpy 2.0 y ahí aborta el arranque,
        # así que se consulta la versión en vez de asumirla.
        if self._scrcpy_major(executable) >= 2:
            command.append("--no-audio")
        # Muestra dónde aterriza cada toque físico, así la evidencia deja ver el foco
        # de la interacción. Sólo aplica a toques reales: los taps del control guiado
        # son eventos inyectados y no dibujan indicador.
        command.extend(["--stay-awake", "--show-touches"])
        return command

    def _scrcpy_major(self, executable: str) -> int:
        if self._scrcpy_version is None:
            try:
                result = _run([executable, "--version"], timeout=8)
                self._scrcpy_version = parse_scrcpy_major(
                    (result.stdout + result.stderr).decode(errors="replace")
                )
            except ExternalServiceError:
                self._scrcpy_version = 0
        return self._scrcpy_version

    def open_device(self, platform: str, device_id: str) -> None:
        if platform == "android":
            if device_id not in {item["id"] for item in self.list_devices()["android"]}:
                raise ValidationError("That Android device is not connected or not authorised in ADB.")
            executable = trusted_which("scrcpy")
            if not executable:
                raise ValidationError(describe_untrusted("scrcpy"))
            self._reap_mirrors()
            with self._mirror_lock:
                if device_id in self._scrcpy_processes:
                    return
            command = self._scrcpy_command(executable, device_id)
        elif platform == "ios":
            if self.appium:
                match = next((item for item in self.list_devices()["ios"] if item["id"] == device_id), None)
                if match and str(match.get("kind", "")).startswith(("physical", "remote")):
                    return
            executable = trusted_which("open") or "/usr/bin/open"
            command = [executable, "-a", "Simulator"]
        else:
            raise ValidationError("Unknown platform.")
        try:
            process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except OSError as exc:
            raise ExternalServiceError(f"The device could not be opened: {exc}") from exc
        if platform == "android":
            time.sleep(0.35)
            if process.poll() is not None:
                raise ExternalServiceError("scrcpy closed while starting. Check the ADB authorisation and try again.")
            with self._mirror_lock:
                self._scrcpy_processes[device_id] = process

    def close_mirror(self, device_id: str) -> dict[str, bool]:
        self._close_scrcpy(str(device_id))
        return {"closed": True}

    def connect_android_wireless(self, host: object, port: object, pairing_code: object = "") -> dict[str, Any]:
        try:
            address = ipaddress.ip_address(str(host).strip())
            endpoint_port = int(str(port).strip())
        except ValueError as exc:
            raise ValidationError("Use a valid IP address and port for Wireless Debugging.") from exc
        if not (address.is_private or address.is_loopback) or not 1 <= endpoint_port <= 65535:
            raise ValidationError("Wireless Debugging only allows a private or local IP and a valid port.")
        executable = trusted_which("adb")
        if not executable:
            raise ValidationError("ADB is not installed, or not reachable from a trusted path.")
        endpoint = f"{address.compressed}:{endpoint_port}"
        code = str(pairing_code).strip()
        if code:
            if not re.fullmatch(r"\d{6}", code):
                raise ValidationError("The Android pairing code must be 6 digits.")
            result = _run([executable, "pair", endpoint, code], timeout=20)
            ok, detail = adb_endpoint_result((result.stdout + result.stderr).decode(errors="replace"))
            if result.returncode or not ok:
                raise ExternalServiceError(f"ADB could not pair the device: {detail[:300]}")
            # En Android 11+ el diálogo de emparejamiento publica un puerto distinto al
            # de depuración: conectarse al de emparejamiento falla siempre. Se resuelve
            # el de conexión por mDNS para el mismo host.
            endpoint = self._connect_endpoint(address.compressed) or endpoint
        result = _run([executable, "connect", endpoint], timeout=20)
        # `adb connect` sale con 0 aunque imprima "failed to connect to": el código de
        # salida por sí solo daba por conectado un dispositivo que nunca respondió.
        ok, detail = adb_endpoint_result((result.stdout + result.stderr).decode(errors="replace"))
        if result.returncode or not ok:
            raise ExternalServiceError(f"ADB could not connect to the wireless device: {detail[:300]}")
        self.invalidate_devices()
        return {"endpoint": endpoint, "paired": bool(code), "connected": True, "detail": detail[:300]}

    def enable_android_tcpip(self, device_id: object, port: object = 5555) -> dict[str, Any]:
        """Pasar un dispositivo USB a Wi-Fi sin código de emparejamiento.

        El otro camino, el diálogo de Android 11+ con código de 6 dígitos, no necesita
        cable pero sí manos en el teléfono; este necesita el cable una vez y después
        ninguno de los dos vuelve a pedir nada.
        """
        serial = str(device_id or "").strip()
        if not serial or len(serial) > 200 or any(ord(character) < 32 for character in serial):
            raise ValidationError("Select the USB device you want to switch to Wi-Fi.")
        try:
            tcp_port = int(str(port).strip() or 5555)
        except ValueError as exc:
            raise ValidationError("The port must be a number.") from exc
        if not 1024 <= tcp_port <= 65535:
            raise ValidationError("Use a port between 1024 and 65535.")
        if serial not in {item["id"] for item in self.list_devices()["android"]}:
            raise ValidationError("That device is not connected over ADB. Check the cable and the authorisation.")
        executable = trusted_which("adb")
        if not executable:
            raise ValidationError("ADB is not installed, or not reachable from a trusted path.")
        # La IP se lee antes de reiniciar adbd: después el serial USB puede tardar
        # en volver y quedaríamos sin saber a dónde conectarnos.
        address = ""
        for command in (["shell", "ip", "route"], ["shell", "ip", "-f", "inet", "addr", "show", "wlan0"]):
            result = _run([executable, "-s", serial] + command, timeout=15)
            address = parse_android_ip((result.stdout + result.stderr).decode(errors="replace"))
            if address:
                break
        if not address:
            raise ExternalServiceError(
                "The device Wi-Fi address could not be read. Put it on the same Wi-Fi network and retry."
            )
        result = _run([executable, "-s", serial, "tcpip", str(tcp_port)], timeout=20)
        output = (result.stdout + result.stderr).decode(errors="replace")
        if result.returncode or not parse_adb_tcpip_result(output):
            raise ExternalServiceError(f"ADB could not put the device in TCP mode: {' '.join(output.split())[:300]}")
        # adbd se reinicia: el puerto tarda un momento en aceptar conexiones.
        endpoint = f"{address}:{tcp_port}"
        last = ""
        for attempt in range(6):
            time.sleep(0.5 * (attempt + 1))
            connect = _run([executable, "connect", endpoint], timeout=20)
            ok, last = adb_endpoint_result((connect.stdout + connect.stderr).decode(errors="replace"))
            if ok:
                self.invalidate_devices()
                return {"endpoint": endpoint, "connected": True, "detail": last[:300]}
        raise ExternalServiceError(
            f"The device is in TCP mode at {endpoint} but did not accept the connection: {last[:300]}"
        )

    def _hardware_serial(self, device_id: str) -> str:
        """Serial físico detrás de un device_id.

        Un mismo tablet aparece dos veces cuando está por USB y por Wi-Fi a la vez
        (`R52W10CCAQB` y `192.168.10.39:5555`), y comparar cadenas dejaba arrancar dos
        grabaciones sobre el mismo aparato: dos `screencap` peleándose y, peor, el
        ajuste de "mostrar toques" quedaba encendido porque la segunda sesión guardaba
        como valor previo el que había puesto la primera.
        """
        executable = trusted_which("adb")
        if not executable:
            return device_id
        try:
            result = _run([executable, "-s", device_id, "shell", "getprop", "ro.serialno"], timeout=10)
        except ExternalServiceError:
            return device_id
        serial = result.stdout.decode(errors="replace").strip()
        return serial if serial and len(serial) <= 100 and "\n" not in serial else device_id

    def _set_show_touches(self, device_id: str, enable: bool, key: str = "") -> None:
        """Marca en pantalla dónde aterriza cada toque, para que la evidencia muestre el foco.

        No se delega en `scrcpy --show-touches`: en este Samsung la flag no aplica, y en
        Windows el cierre del espejo es una terminación dura, así que scrcpy nunca llega a
        restaurar el valor original. Se guarda el valor previo del dispositivo y se repone.
        """
        executable = trusted_which("adb")
        if not executable:
            return
        # La clave es el serial físico, no el device_id: el mismo aparato por USB y por
        # Wi-Fi son ids distintos, y el valor guardado debe seguir al hardware.
        slot = key or device_id
        try:
            if enable:
                # Si quedó una reposición pendiente de una sesión anterior, ese valor es
                # el verdadero. Releerlo ahora devolvería el 1 que dejó esa sesión y
                # cementaría la fuga como si fuera la preferencia de la persona.
                if slot not in self._touch_state:
                    current = _run([executable, "-s", device_id, "shell", "settings", "get", "system", "show_touches"], timeout=10)
                    previous = current.stdout.decode(errors="replace").strip()
                    self._touch_state[slot] = previous if previous in {"0", "1"} else "0"
                _run([executable, "-s", device_id, "shell", "settings", "put", "system", "show_touches", "1"], timeout=10)
                return
            pending = self._touch_state.get(slot)
            if pending is None:
                return
            result = _run([executable, "-s", device_id, "shell", "settings", "put", "system", "show_touches", pending], timeout=10)
            # Se olvida sólo si la reposición llegó: si el dispositivo se perdió a media
            # sesión, queda pendiente para el próximo intento en vez de dejarlo encendido.
            if result.returncode == 0:
                self._touch_state.pop(slot, None)
        except ExternalServiceError:
            # Un indicador de toques no vale abortar ni ensuciar el error de la grabación.
            pass

    def _connect_endpoint(self, host: str) -> str:
        """Debug endpoint advertised by a host, which is not its pairing endpoint."""
        try:
            services = self.discover_android_wireless()["services"]
        except (ExternalServiceError, ValidationError):
            return ""
        for service in services:
            if service["kind"] == "connect" and service["host"] == host:
                return f"{host}:{service['port']}"
        return ""

    def disconnect_android_wireless(self, endpoint: object) -> dict[str, Any]:
        text = str(endpoint or "").strip()
        if not re.fullmatch(r"[0-9A-Fa-f.:\[\]]{3,60}:\d{1,5}", text):
            raise ValidationError("Give the endpoint as IP:port to disconnect it.")
        executable = trusted_which("adb")
        if not executable:
            raise ValidationError("ADB is not installed, or not reachable from a trusted path.")
        self._close_scrcpy(text)
        result = _run([executable, "disconnect", text], timeout=20)
        detail = " ".join((result.stdout + result.stderr).decode(errors="replace").split())
        self.invalidate_devices()
        return {"endpoint": text, "disconnected": result.returncode == 0, "detail": detail[:300]}

    def discover_android_wireless(self) -> dict[str, Any]:
        """Devices advertising Wireless Debugging, so the IP and port need not be typed."""
        executable = trusted_which("adb")
        if not executable:
            raise ValidationError("ADB is not installed, or not reachable from a trusted path.")
        try:
            result = _run([executable, "mdns", "services"], timeout=15)
        except ExternalServiceError as exc:
            raise ExternalServiceError(f"ADB could not search for devices over mDNS: {exc}") from exc
        output = (result.stdout + result.stderr).decode(errors="replace")
        if result.returncode:
            raise ExternalServiceError("ADB could not search for devices over mDNS. Check that the daemon is running.")
        return {"services": parse_adb_mdns_services(output)}

    def invalidate_devices(self) -> None:
        with self._devices_lock:
            self._devices_cache = None

    def start(
        self,
        platform: str,
        device_id: str,
        case_id: int | None = None,
        preparation: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        self._cleanup_expired()
        if platform not in {"android", "ios"} or not device_id.strip():
            raise ValidationError("Select an Android or iOS device.")
        if len(device_id) > 200 or any(ord(character) < 32 for character in device_id):
            raise ValidationError("The device identifier is invalid.")
        known = {d["id"] for d in self.list_devices()[platform]}
        if device_id not in known:
            raise ValidationError("That device is no longer available. Refresh the list.")
        if platform == "android":
            self._prepare_android(device_id, preparation or {})
        # Se compara el serial físico, no el device_id: el mismo aparato por USB y por
        # Wi-Fi son dos ids distintos del mismo hardware.
        serial = self._hardware_serial(device_id) if platform == "android" else device_id
        with self._lock:
            if any(
                not item.stopped and (item.hardware_serial or item.device_id) == serial
                for item in self._sessions.values()
            ):
                raise ValidationError(
                    "That device already has a recording running, over USB or over Wi-Fi."
                )
        session_id = uuid.uuid4().hex
        if self.recovery_dir:
            private_dir(self.recovery_dir)
            directory = private_dir(self.recovery_dir / session_id)
        else:
            directory = Path(tempfile.mkdtemp(prefix="qa-sync-recording-"))
        session = RecordingSession(
            id=session_id,
            platform=platform,
            device_id=device_id,
            directory=directory,
            interval=self.interval,
            max_frames=self.max_frames,
            case_id=case_id,
            hardware_serial=serial,
        )
        if platform == "ios" and self.appium:
            try:
                session.appium_session_id = self.appium.create_session(device_id)
            except Exception:
                shutil.rmtree(directory, ignore_errors=True)
                raise
        session.environment = self._device_environment(session)
        if session.environment:
            self._append_observation(
                session,
                "Test environment: " + "; ".join(
                    f"{key}={value}" for key, value in session.environment.items() if value
                )[:1200],
            )
        session.thread = threading.Thread(target=self._record, args=(session,), daemon=True)
        with self._lock:
            self._sessions[session_id] = session
        self._persist(session)
        if platform == "android":
            self._set_show_touches(device_id, True, serial)
            # Abrir el espejo es parte de empezar a grabar, no un paso aparte. Si
            # scrcpy falla la grabación sigue por ADB: se anota y no se aborta.
            try:
                self.open_device("android", device_id)
            except (ValidationError, ExternalServiceError) as exc:
                self._append_observation(session, f"scrcpy did not open: {exc}")
            self._start_android_action_observer(session)
        session.thread.start()
        return self.status(session_id)

    @staticmethod
    def _prepare_android(device_id: str, preparation: dict[str, Any]) -> None:
        package = str(preparation.get("package", "")).strip()
        deep_link = str(preparation.get("deep_link", "")).strip()
        reset_data = preparation.get("reset_data") is True
        if package and not re.fullmatch(r"[A-Za-z][A-Za-z0-9_.]{2,180}", package):
            raise ValidationError("The Android package name is not valid.")
        if reset_data and not package:
            raise ValidationError("Clearing data needs the Android package name.")
        if deep_link and (len(deep_link) > 1000 or not re.fullmatch(r"https?://[A-Za-z0-9._~:/?#[\]@!$&'()*+,;=%-]+", deep_link)):
            raise ValidationError("The deep link must be a valid http(s) URL with no control characters.")
        executable = trusted_which("adb")
        if not executable:
            raise ExternalServiceError("ADB is no longer available.")
        if reset_data:
            result = _run([executable, "-s", device_id, "shell", "pm", "clear", package], timeout=20)
            if result.returncode or b"Success" not in result.stdout:
                raise ExternalServiceError("ADB could not clear the application data.")
        if deep_link:
            result = _run([
                executable, "-s", device_id, "shell", "am", "start", "-W",
                "-a", "android.intent.action.VIEW", "-d", deep_link,
            ], timeout=20)
            if result.returncode:
                raise ExternalServiceError("ADB could not open the configured deep link.")

    def _session_health(self, session: RecordingSession) -> dict[str, Any]:
        """Estado vivo de la sesión: sin esto, un dispositivo o un espejo que se caen
        a media grabación se veían igual que todo en orden."""
        if session.stopped:
            return {"device_present": None, "mirror_alive": None, "warnings": []}
        warnings: list[str] = []
        # list_devices está cacheado, así que sondear en cada poll de la UI no
        # dispara un adb por llamada.
        inventory = self.list_devices()
        present = any(item["id"] == session.device_id for item in inventory.get(session.platform, []))
        if not present:
            warnings.append(
                "The device is no longer listed; reconnect the cable or Wireless Debugging."
            )
        mirror_alive: bool | None = None
        if session.platform == "android" and trusted_which("scrcpy"):
            mirror_alive = session.device_id in inventory.get("mirrors", {})
            # Sólo se avisa del espejo si el dispositivo sigue ahí: con el dispositivo
            # perdido, el espejo también muere y decir "la captura sigue por ADB" sería
            # falso, justo cuando la captura es lo que está fallando.
            if not mirror_alive and present:
                warnings.append("The scrcpy window is closed; capture continues over ADB.")
        return {"device_present": present, "mirror_alive": mirror_alive, "warnings": warnings}

    def status(self, session_id: str) -> dict[str, Any]:
        with self._lock:
            session = self._sessions.get(session_id)
        if not session:
            raise ValidationError("That recording session does not exist or expired.")
        elapsed = (session.ended_at or time.time()) - session.started_at
        return {
            **self._session_health(session),
            "session_id": session.id,
            "platform": session.platform,
            "device_id": session.device_id,
            "case_id": session.case_id,
            "frames": len(session.frames),
            # Una sesión detenida dura lo que duró: medir contra el reloj actual hacía
            # que cualquier grabación vieja se reportara como si hubiera topado el
            # límite de duración, aunque se hubiera detenido a los segundos.
            "seconds": round(elapsed, 1),
            "stopped": session.stopped,
            "error": session.error,
            "limit_reached": session.stopped and (
                session.stream_frames >= session.max_frames
                or elapsed >= self.max_duration
            ),
            "remote_control": bool(
                not session.stopped
                and (session.appium_session_id or (session.platform == "android" and trusted_which("adb")))
            ),
            "control_kind": "appium" if session.appium_session_id else "adb" if session.platform == "android" else "",
            "environment": session.environment,
        }

    def stop(self, session_id: str) -> dict[str, Any]:
        with self._lock:
            session = self._sessions.get(session_id)
        if not session:
            raise ValidationError("That recording session does not exist or expired.")
        session.stop_event.set()
        if session.thread:
            session.thread.join(timeout=max(15, session.interval + 2))
            if session.thread.is_alive():
                raise ExternalServiceError("The capture could not be stopped safely. Try again.")
        self._stop_action_observer(session)
        self._close_appium(session)
        self._close_scrcpy(session.device_id)
        self._set_show_touches(session.device_id, False, session.hardware_serial)
        session.stopped = True
        session.ended_at = session.ended_at or time.time()
        self._persist(session)
        return self.status(session_id)

    def evidence(self, session_id: str) -> tuple[list[dict[str, str]], str, str]:
        self.stop(session_id)
        with self._lock:
            session = self._sessions.get(session_id)
        if not session:
            raise ValidationError("That recording session does not exist or expired.")
        if session.error and not session.frames:
            raise ExternalServiceError(session.error)
        if not session.frames:
            raise ValidationError("No screen was captured during the session.")
        images = [
            {"name": path.name, "type": "image/png", "data": base64.b64encode(self._read_frame(path)).decode()}
            for path in session.frames
        ]
        return images, "\n".join(session.observations), session.platform

    def evidence_preview(self, session_id: str, budget: int) -> dict[str, Any]:
        """Return small local-only thumbnails and the proposed AI selection.

        The encrypted originals never leave the evidence directory here.  The
        browser receives JPEG thumbnails solely through the loopback API so a
        person can remove a frame before any provider call is made.
        """
        self.stop(session_id)
        if not 1 <= budget <= 200:
            raise ValidationError("The AI screen budget must be between 1 and 200.")
        with self._lock:
            session = self._sessions.get(session_id)
        if not session or not session.frames:
            raise ValidationError("No screen was captured during the session.")
        count = len(session.frames)
        selected_count = min(count, budget)
        selected = {
            round(position * (count - 1) / (selected_count - 1)) if selected_count > 1 else 0
            for position in range(selected_count)
        }
        frames: list[dict[str, Any]] = []
        for index, path in enumerate(session.frames):
            try:
                with Image.open(io.BytesIO(self._read_frame(path))) as source:
                    source = source.convert("RGB")
                    source.thumbnail((180, 180), Image.Resampling.LANCZOS)
                    encoded = io.BytesIO()
                    source.save(encoded, format="JPEG", quality=68, optimize=True)
            except (OSError, ValueError) as exc:
                raise ValidationError("A recorded screen cannot be previewed safely.") from exc
            frames.append({
                "index": index,
                "selected": index in selected,
                "type": "image/jpeg",
                "data": base64.b64encode(encoded.getvalue()).decode(),
            })
        return {"session_id": session_id, "frames": frames, "captured_frames": count,
                "selected_frames": len(selected), "budget": budget}

    def export_evidence(self, session_id: str, selected_frames: list[Any]) -> dict[str, Any]:
        """Return explicitly selected original captures for a local-only export.

        This intentionally does not call a provider or TestRail.  The caller is
        responsible for turning the returned JSON into a user-initiated local
        download; originals remain encrypted at rest until that moment.
        """
        self.stop(session_id)
        with self._lock:
            session = self._sessions.get(session_id)
        if not session or not session.frames:
            raise ValidationError("No screen was captured during the session.")
        if not isinstance(selected_frames, list):
            raise ValidationError("Choose the screens to export.")
        indices: list[int] = []
        for value in selected_frames:
            if isinstance(value, bool):
                raise ValidationError("A selected screen index is invalid.")
            try:
                index = int(value)
            except (TypeError, ValueError) as exc:
                raise ValidationError("A selected screen index is invalid.") from exc
            if index < 0 or index >= len(session.frames):
                raise ValidationError("A selected screen is no longer available.")
            if index not in indices:
                indices.append(index)
        if not indices:
            raise ValidationError("Select at least one screen to export.")
        if len(indices) > 200:
            raise ValidationError("Export at most 200 screens at a time.")
        images = [
            {
                "index": index,
                "name": session.frames[index].name,
                "type": "image/png",
                "data": base64.b64encode(self._read_frame(session.frames[index])).decode(),
            }
            for index in indices
        ]
        return {
            "session_id": session_id,
            "case_id": session.case_id,
            "platform": session.platform,
            "captured_frames": len(session.frames),
            "selected_frames": len(images),
            "frames": images,
        }

    def import_evidence(self, payload: Any, case_id: int | None = None) -> dict[str, Any]:
        """Store a user-selected evidence package as an encrypted stopped session.

        Imported evidence is deliberately disconnected from devices.  It can be
        reviewed and analysed later, but cannot control an old device session.
        """
        if not isinstance(payload, dict) or payload.get("mode") != "evidence_only":
            raise ValidationError("Choose a QA Sync evidence-only export.")
        platform = str(payload.get("platform", "")).lower()
        frames = payload.get("frames")
        if platform not in {"android", "ios"} or not isinstance(frames, list):
            raise ValidationError("The evidence package is incomplete.")
        if not 1 <= len(frames) <= 200:
            raise ValidationError("An evidence package must contain 1 to 200 screens.")
        session_id = uuid.uuid4().hex
        if self.recovery_dir:
            private_dir(self.recovery_dir)
            directory = private_dir(self.recovery_dir / session_id)
        else:
            directory = Path(tempfile.mkdtemp(prefix="qa-sync-imported-evidence-"))
        session = RecordingSession(
            id=session_id, platform=platform, device_id="imported-evidence",
            directory=directory, interval=self.interval, max_frames=max(self.max_frames, len(frames)),
            case_id=case_id, stopped=True, ended_at=time.time(),
        )
        try:
            for position, item in enumerate(frames, start=1):
                if not isinstance(item, dict) or item.get("type") != "image/png":
                    raise ValidationError("An imported screen is not a PNG image.")
                encoded = item.get("data")
                if not isinstance(encoded, str) or len(encoded) > 16_000_000:
                    raise ValidationError("An imported screen is too large.")
                try:
                    image = base64.b64decode(encoded, validate=True)
                    with Image.open(io.BytesIO(image)) as source:
                        source.verify()
                        width, height = source.size
                except (ValueError, OSError, binascii.Error) as exc:
                    raise ValidationError("An imported screen could not be verified safely.") from exc
                if not image.startswith(PNG_SIGNATURE) or not 1 <= width <= 10_000 or not 1 <= height <= 10_000:
                    raise ValidationError("An imported screen has invalid dimensions.")
                path = directory / f"frame-{position:03d}.qasec"
                path.write_bytes(self.evidence_cipher.encrypt(image))
                private_file(path)
                session.frames.append(path)
            self._append_observation(session, "Imported local evidence package; no device was connected.")
            with self._lock:
                self._sessions[session_id] = session
            self._persist(session)
        except Exception:
            shutil.rmtree(directory, ignore_errors=True)
            raise
        return self.status(session_id)

    def discard(self, session_id: str) -> None:
        with self._lock:
            session = self._sessions.pop(session_id, None)
        if session:
            session.stop_event.set()
            self._stop_action_observer(session)
            self._close_appium(session)
            self._close_scrcpy(session.device_id)
            self._set_show_touches(session.device_id, False, session.hardware_serial)
            shutil.rmtree(session.directory, ignore_errors=True)

    def protect(self, session_id: str) -> None:
        """Pin encrypted evidence while a deferred QA job refers to it."""
        with self._lock:
            session = self._sessions.get(session_id)
        if not session or not session.stopped or not session.frames:
            raise ValidationError("Stop a recording with captured screens before queuing it.")
        marker = session.directory / ".deferred"
        marker.write_text("Queued locally; remove through QA Sync.\n", encoding="utf-8")
        private_file(marker)

    def include_execution_checkpoints(self, session_id: str) -> int:
        """Attach encrypted per-step captures to the timeline after Execute finishes."""
        with self._lock:
            session = self._sessions.get(session_id)
        if not session or not session.stopped:
            raise ValidationError("Finish the execution recording before attaching its checkpoints.")
        existing = set(session.frames)
        added = [path for path in session.directory.glob("checkpoint-step-*.qasec")
                 if path not in existing and re.fullmatch(r"checkpoint-step-[0-9]+-(before|after)\.qasec", path.name)]
        if added:
            session.frames = sorted([*session.frames, *added], key=lambda path: (path.stat().st_mtime_ns, path.name))
            self._append_observation(session, f"Attached {len(added)} deterministic step checkpoint screens.")
            self._persist(session)
        return len(added)

    def unprotect(self, session_id: str) -> None:
        with self._lock:
            session = self._sessions.get(session_id)
        if session:
            (session.directory / ".deferred").unlink(missing_ok=True)

    def cancel(self, session_id: str) -> None:
        with self._lock:
            session = self._sessions.get(session_id)
        if not session:
            raise ValidationError("That recording session does not exist or expired.")
        session.stop_event.set()
        if session.thread:
            session.thread.join(timeout=max(15, session.interval + 2))
            if session.thread.is_alive():
                raise ExternalServiceError("The capture could not be cancelled safely. Try again.")
        self._stop_action_observer(session)
        self._close_appium(session)
        self.discard(session_id)

    def shutdown(self) -> None:
        with self._lock:
            ids = list(self._sessions)
        for session_id in ids:
            try:
                self.stop(session_id)
            except ValidationError:
                pass
        with self._mirror_lock:
            mirrored = list(self._scrcpy_processes)
        for device_id in mirrored:
            self._close_scrcpy(device_id)
        for device_id in list(self._touch_state):
            self._set_show_touches(device_id, False)

    def has_active_sessions(self) -> bool:
        with self._lock:
            return any(not session.stopped for session in self._sessions.values())

    def _cleanup_expired(self) -> None:
        cutoff = time.time() - self.recovery_ttl_seconds
        with self._lock:
            expired = [
                session_id for session_id, session in self._sessions.items()
                if session.stopped and (session.ended_at or session.started_at) < cutoff
                and not (session.directory / ".deferred").exists()
            ]
        for session_id in expired:
            self.discard(session_id)

    def _record(self, session: RecordingSession) -> None:
        connection_failures = 0
        while (
            not session.stop_event.is_set()
            and len(session.frames) < session.max_frames
            and time.time() - session.started_at < self.max_duration
        ):
            cycle_start = time.time()
            try:
                image = self._capture(session)
                recovered = connection_failures > 0
                connection_failures = 0
                session.error = ""
                if recovered:
                    self._append_observation(session, f"Connection recovered at +{time.time() - session.started_at:.1f}s")
                self._store_frame(session, image)
            except ExternalServiceError as exc:
                connection_failures += 1
                if session.stop_event.is_set():
                    break
                if connection_failures <= 3 and not session.stop_event.is_set():
                    session.error = f"Connection interrupted; retrying ({connection_failures}/3)."
                    self._persist(session)
                    session.stop_event.wait(session.interval)
                    continue
                session.error = f"The connection to the device was lost after 3 retries: {exc}"
                session.stop_event.set()
                break
            except Exception as exc:
                session.error = str(exc)
                session.stop_event.set()
                break
            # Se descuenta lo que ya costó el ciclo: la captura y el volcado de
            # elementos tardan segundos en un dispositivo lento, y sumarles el
            # intervalo completo convertía una cadencia pedida de 1.25 s en una de 5 s.
            session.capture_event.wait(max(0.0, session.interval - (time.time() - cycle_start)))
            session.capture_event.clear()
        session.stop_event.set()
        self._stop_action_observer(session)
        session.stopped = True
        session.ended_at = time.time()
        self._persist(session)

    def _store_frame(self, session: RecordingSession, image: bytes) -> bool:
        digest = hashlib.sha256(image).hexdigest()
        with session.capture_lock:
            if digest == session.last_digest or len(session.frames) >= session.max_frames:
                return False
            index = len(session.frames) + 1
            path = session.directory / f"frame-{index:03d}.qasec"
            path.write_bytes(self.evidence_cipher.encrypt(image))
            private_file(path)
            session.frames.append(path)
            session.stream_frames += 1
            session.last_digest = digest
            elapsed = time.time() - session.started_at
        # Los dumps del dispositivo tardan hasta segundos; van fuera del lock para que el
        # control guiado y el hilo de grabación no se esperen entre sí.
        # ponytail: con dos hilos guardando a la vez, el orden de las observaciones y la
        # detección de cambio semántico quedan best-effort; numerar y ordenar al leer si importa.
        activity = self._android_activity(session) if session.platform == "android" else ""
        ui_summary = self._android_ui_summary(session) if session.platform == "android" else self._ios_ui_summary(session)
        with session.capture_lock:
            semantic_change = ui_summary if ui_summary and ui_summary != session.last_ui_summary else ""
            session.last_ui_summary = ui_summary or session.last_ui_summary
            self._append_observation(
                session,
                f"Frame {index} a +{elapsed:.1f}s"
                + (f", screen: {activity}" if activity else "")
                + (f"\nVisible elements: {semantic_change}" if semantic_change else ""),
            )
            self._persist(session)
        return True

    def _capture(self, session: RecordingSession) -> bytes:
        if session.platform == "android":
            executable = trusted_which("adb")
            if not executable:
                raise ExternalServiceError("ADB is not reachable from a trusted path.")
            result = _run([executable, "-s", session.device_id, "exec-out", "screencap", "-p"])
            image = result.stdout
        elif session.appium_session_id and self.appium:
            image = self.appium.screenshot(session.appium_session_id)
            result = subprocess.CompletedProcess([], 0, image, b"")
        else:
            target = session.directory / "latest.png"
            executable = trusted_which("xcrun")
            if not executable:
                raise ExternalServiceError("Xcode is not reachable from a trusted path.")
            result = self._run_xcrun(executable, [
                "simctl", "io", session.device_id, "screenshot", "--type=png", str(target)
            ])
            image = target.read_bytes() if result.returncode == 0 and target.exists() else b""
            target.unlink(missing_ok=True)
        if result.returncode != 0 or not image.startswith(PNG_SIGNATURE):
            detail = result.stderr.decode(errors="replace")[:300].strip()
            raise ExternalServiceError(f"The screen could not be captured. {detail}")
        return image

    def _read_frame(self, path: Path) -> bytes:
        payload = path.read_bytes()
        return self.evidence_cipher.decrypt(payload) if payload.startswith(ENCRYPTED_MAGIC) else payload

    def live_screenshot(self, session_id: str) -> dict[str, Any]:
        with self._lock:
            session = self._sessions.get(session_id)
        if not session or session.stopped:
            raise ValidationError("Guided control is not available for this session.")
        if session.platform == "android":
            image = self._capture(session)
            if len(image) < 24:
                raise ExternalServiceError("ADB returned an incomplete PNG capture.")
            width, height = struct.unpack(">II", image[16:24])
            if not 1 <= width <= 10000 or not 1 <= height <= 10000:
                raise ExternalServiceError("ADB returned invalid screen dimensions.")
        elif session.appium_session_id and self.appium:
            image = self.appium.screenshot(session.appium_session_id)
            width, height = self.appium.window_rect(session.appium_session_id)
        else:
            raise ValidationError("Appium control is not available for this session.")
        if not image.startswith(PNG_SIGNATURE):
            raise ExternalServiceError("The device did not return a valid PNG capture.")
        return {
            "type": "image/png", "data": base64.b64encode(image).decode(),
            "logical_width": width, "logical_height": height,
        }

    def semantic_context(self, session_id: str) -> str:
        with self._lock:
            session = self._sessions.get(session_id)
        if not session or session.stopped:
            raise ValidationError("Guided control is not available for this session.")
        summary = self._android_ui_summary(session) if session.platform == "android" else self._ios_ui_summary(session)
        return str(summary or "")[:3000]

    def ui_locators(self, session_id: str) -> dict[str, Any]:
        """Return short-lived locator suggestions from the live accessibility tree.

        These are never persisted as evidence and are deliberately suggestions:
        a human still chooses whether an app identifier is stable enough to use.
        """
        with self._lock:
            session = self._sessions.get(session_id)
        if not session or session.stopped:
            raise ValidationError("Guided control is not available for this session.")
        if session.platform == "android":
            return {"platform": "android", "locators": self._android_ui_locators(session)}
        return {"platform": "ios", "locators": self._ios_ui_locators(session)}

    def _android_ui_locators(self, session: RecordingSession) -> list[dict[str, str]]:
        executable = trusted_which("adb")
        if not executable:
            return []
        try:
            result = _run([executable, "-s", session.device_id, "exec-out", "uiautomator", "dump", "/dev/tty"], timeout=8)
        except ExternalServiceError:
            return []
        if result.returncode or len(result.stdout) > 2 * 1024 * 1024 or b"<!" in result.stdout.lower():
            return []
        start = result.stdout.find(b"<hierarchy")
        if start < 0:
            return []
        try:
            root = ElementTree.fromstring(result.stdout[start:])
        except ElementTree.ParseError:
            return []
        locators: list[dict[str, str]] = []
        seen: set[tuple[str, str]] = set()
        for node in root.iter("node"):
            raw_id = node.attrib.get("resource-id", "").strip()
            raw_label = node.attrib.get("content-desc", "").strip()
            if raw_id:
                strategy, value = "id", raw_id
            elif raw_label:
                strategy, value = "accessibility id", raw_label
            else:
                continue
            key = (strategy, value)
            if key in seen:
                continue
            seen.add(key)
            locators.append({"strategy": strategy, "value": value[:200],
                             "label": _redacted_label(raw_label or node.attrib.get("text", ""))[:100],
                             "type": node.attrib.get("class", "").rsplit(".", 1)[-1][:80]})
            if len(locators) == 25:
                break
        return locators

    def _ios_ui_locators(self, session: RecordingSession) -> list[dict[str, str]]:
        if not session.appium_session_id or not self.appium:
            return []
        try:
            source = self.appium.source(session.appium_session_id)
        except ExternalServiceError:
            return []
        if not source or len(source) > 2 * 1024 * 1024 or "<!" in source.lower():
            return []
        try:
            root = ElementTree.fromstring(source)
        except ElementTree.ParseError:
            return []
        locators: list[dict[str, str]] = []
        seen: set[str] = set()
        for node in root.iter():
            identifier = (node.attrib.get("name") or node.attrib.get("identifier") or "").strip()
            if not identifier or identifier in seen:
                continue
            seen.add(identifier)
            locators.append({"strategy": "accessibility id", "value": identifier[:200],
                             "label": _redacted_label(node.attrib.get("label") or node.attrib.get("value") or "")[:100],
                             "type": node.attrib.get("type", node.tag).replace("XCUIElementType", "")[:80]})
            if len(locators) == 25:
                break
        return locators

    def capture_checkpoint(self, session_id: str, label: str, *, settle: bool = False,
                           timeout: float = 8.0, interval: float = 0.35) -> dict[str, Any]:
        """Capture an encrypted named state, optionally waiting for two equal observations.

        Exact equality is intentionally conservative: an animation may time out and
        force manual review, but an unstable screen is never advertised as settled.
        """
        with self._lock:
            session = self._sessions.get(session_id)
        if not session or session.stopped:
            raise ValidationError("Execution evidence is not available for this session.")
        if not re.fullmatch(r"[a-z0-9-]{1,80}", str(label)):
            raise ValidationError("The execution checkpoint label is invalid.")
        started = time.time()
        previous = ""
        stable_matches = 0
        image = b""
        semantic = ""
        while True:
            image = self._capture(session)
            semantic = self._android_ui_summary(session) if session.platform == "android" else self._ios_ui_summary(session)
            signature = hashlib.sha256(image + b"\0" + str(semantic).encode("utf-8", errors="replace")).hexdigest()
            if signature == previous:
                stable_matches += 1
            else:
                stable_matches = 0
                previous = signature
            elapsed = time.time() - started
            if not settle or stable_matches >= 1 or elapsed >= timeout:
                break
            time.sleep(min(interval, max(0.0, timeout - elapsed)))
        stable = not settle or stable_matches >= 1
        image_path = session.directory / f"checkpoint-{label}.qasec"
        meta_path = session.directory / f"checkpoint-{label}.json.qasec"
        image_path.write_bytes(self.evidence_cipher.encrypt(image))
        metadata = json.dumps({"semantic": str(semantic)[:3000], "stable": stable,
                               "settle_seconds": round(time.time() - started, 3)},
                              ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        meta_path.write_bytes(self.evidence_cipher.encrypt(metadata))
        private_file(image_path)
        private_file(meta_path)
        return {"type": "image/png", "data": base64.b64encode(image).decode(),
                "semantic": str(semantic)[:3000], "stable": stable,
                "settle_seconds": round(time.time() - started, 3)}

    def checkpoint(self, session_id: str, label: str) -> dict[str, Any]:
        with self._lock:
            session = self._sessions.get(session_id)
        if not session:
            raise ValidationError("Execution evidence is not available for this session.")
        if not re.fullmatch(r"[a-z0-9-]{1,80}", str(label)):
            raise ValidationError("The execution checkpoint label is invalid.")
        image_path = session.directory / f"checkpoint-{label}.qasec"
        meta_path = session.directory / f"checkpoint-{label}.json.qasec"
        try:
            image = self.evidence_cipher.decrypt(image_path.read_bytes())
            metadata = json.loads(self.evidence_cipher.decrypt(meta_path.read_bytes()).decode("utf-8"))
        except (OSError, ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValidationError("The baseline for this step is missing or damaged; restart the step.") from exc
        if not image.startswith(PNG_SIGNATURE) or not isinstance(metadata, dict):
            raise ValidationError("The baseline for this step is invalid; restart the step.")
        return {"type": "image/png", "data": base64.b64encode(image).decode(),
                "semantic": str(metadata.get("semantic", ""))[:3000],
                "stable": metadata.get("stable") is True,
                "settle_seconds": float(metadata.get("settle_seconds", 0) or 0)}

    def perform_action(self, session_id: str, request: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            session = self._sessions.get(session_id)
        if not session or session.stopped:
            raise ValidationError("Guided control is not available for this session.")
        action_type = str(request.get("type", ""))
        if action_type == "text":
            value = request.get("text")
            if not isinstance(value, str) or not value or len(value) > 500:
                raise ValidationError("The text must be 1 to 500 characters.")
            if session.platform == "android" and not re.fullmatch(r"[A-Za-z0-9 @._%+,:-]+", value):
                raise ValidationError("On Android, guided text only accepts letters, digits and basic punctuation.")
            self._store_frame(session, self._capture(session))
            session.last_guided_action_at = time.time()
            if session.platform == "android":
                self._android_input(session, ["text", value.replace(" ", "%s")])
            elif session.appium_session_id and self.appium:
                self.appium.text(session.appium_session_id, value)
            else:
                raise ValidationError("Appium is not available for this iOS session.")
            self._append_observation(session,
                f"{session.platform.title()} action at +{time.time() - session.started_at:.1f}s: "
                f"text entry ({len(value)} characters; content omitted)"
            )
            time.sleep(0.4)
            self._store_frame(session, self._capture(session))
            self._persist(session)
            return {"performed": True}
        if action_type not in {"tap", "swipe"}:
            raise ValidationError("The action must be tap, swipe or text.")

        def point(name: str) -> tuple[int, int]:
            value = request.get(name)
            if not isinstance(value, dict):
                raise ValidationError(f"Missing point {name}.")
            coordinates = value.get("x"), value.get("y")
            if any(isinstance(item, bool) or not isinstance(item, int) or not 0 <= item <= 10000 for item in coordinates):
                raise ValidationError(f"El punto {name} is invalid.")
            return coordinates

        start, end = point("start"), point("end")
        self._store_frame(session, self._capture(session))
        session.last_guided_action_at = time.time()
        if session.platform == "android":
            arguments = [action_type, str(start[0]), str(start[1])]
            if action_type == "swipe":
                arguments.extend([str(end[0]), str(end[1]), "350"])
            self._android_input(session, arguments)
        elif session.appium_session_id and self.appium:
            self.appium.action(session.appium_session_id, action_type, start, end)
        else:
            raise ValidationError("Appium is not available for this iOS session.")
        self._append_observation(session,
            f"{session.platform.title()} action at +{time.time() - session.started_at:.1f}s: "
            f"{action_type} ({start[0]},{start[1]})→({end[0]},{end[1]})"
        )
        time.sleep(0.4)
        self._store_frame(session, self._capture(session))
        self._persist(session)
        return {"performed": True}

    @staticmethod
    def _android_input(session: RecordingSession, arguments: list[str]) -> None:
        executable = trusted_which("adb")
        if not executable:
            raise ExternalServiceError("ADB is no longer available.")
        result = _run([executable, "-s", session.device_id, "shell", "input", *arguments], timeout=8)
        if result.returncode:
            raise ExternalServiceError("ADB could not run the guided action.")

    def recovered_sessions(self) -> dict[str, Any]:
        self._cleanup_expired()
        with self._lock:
            sessions = sorted(self._sessions.values(), key=lambda item: item.started_at, reverse=True)
        return {"sessions": [self.status(item.id) for item in sessions if item.stopped and item.frames]}

    def _restore_sessions(self) -> None:
        if not self.recovery_dir:
            return
        private_dir(self.recovery_dir)
        cutoff = time.time() - self.recovery_ttl_seconds
        for manifest in self.recovery_dir.glob("*/manifest.json"):
            try:
                data = json.loads(manifest.read_text(encoding="utf-8"))
                started_at = float(data["started_at"])
                ended_at = float(data.get("ended_at") or started_at)
                if ended_at < cutoff and not (manifest.parent / ".deferred").exists():
                    shutil.rmtree(manifest.parent, ignore_errors=True)
                    continue
                session_id = str(data["id"])
                if not re.fullmatch(r"[a-f0-9]{32}", session_id) or manifest.parent.name != session_id:
                    continue
                frames = [manifest.parent / str(name) for name in data.get("frames", [])]
                frames = [path for path in frames if path.parent == manifest.parent and path.is_file()
                          and not path.is_symlink()]
                known = set(frames)
                recovered_frames = []
                # A hard stop can land after an authenticated frame was written
                # but before the manifest was atomically replaced. Salvage only
                # complete, decryptable files; never trust an incomplete write.
                for path in sorted(manifest.parent.glob("frame-*.qasec")):
                    if len(frames) + len(recovered_frames) >= min(200, max(1, int(data.get("max_frames", self.max_frames)))):
                        break
                    if path in known or path.is_symlink() or not re.fullmatch(r"frame-\d{3}\.qasec", path.name):
                        continue
                    try:
                        image = self.evidence_cipher.decrypt(path.read_bytes())
                        with Image.open(io.BytesIO(image)) as source:
                            source.verify()
                    except (OSError, ValueError, ValidationError, SyntaxError):
                        continue
                    recovered_frames.append(path)
                frames.extend(recovered_frames)
                frames.sort(key=lambda path: int(re.search(r"\d+", path.stem).group()) if re.search(r"\d+", path.stem) else 0)
                session = RecordingSession(
                    id=session_id, platform=str(data["platform"]), device_id=str(data["device_id"]),
                    directory=manifest.parent, interval=self.interval,
                    max_frames=int(data.get("max_frames", self.max_frames)), started_at=started_at,
                    frames=frames, stream_frames=int(data.get("stream_frames", len(frames))),
                    observations=[str(item)[:5000] for item in data.get("observations", [])[:500]],
                    error=str(data.get("error", ""))[:1000], stopped=True, ended_at=ended_at,
                    last_digest=str(data.get("last_digest", "")),
                    case_id=int(data["case_id"]) if data.get("case_id") else None,
                    environment={str(key)[:80]: str(value)[:200] for key, value in data.get("environment", {}).items()} if isinstance(data.get("environment"), dict) else {},
                )
                self._sessions[session_id] = session
                if recovered_frames:
                    self._append_observation(session, f"Recovered {len(recovered_frames)} complete frame(s) after a local interruption.")
                    self._persist(session)
            except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError):
                continue

    @staticmethod
    def _manifest_data(session: RecordingSession) -> dict[str, Any]:
        return {
            "id": session.id, "platform": session.platform, "device_id": session.device_id,
            "case_id": session.case_id,
            "started_at": session.started_at, "ended_at": session.ended_at,
            "max_frames": session.max_frames, "frames": [path.name for path in session.frames],
            "stream_frames": session.stream_frames,
            "observations": session.observations, "error": session.error,
            "last_digest": session.last_digest,
            "environment": session.environment,
        }

    def _persist(self, session: RecordingSession) -> None:
        if not self.recovery_dir:
            return
        manifest = session.directory / "manifest.json"
        temporary = session.directory / "manifest.tmp"
        temporary.write_text(json.dumps(self._manifest_data(session), ensure_ascii=False), encoding="utf-8")
        private_file(temporary)
        temporary.replace(manifest)

    def _close_appium(self, session: RecordingSession) -> None:
        if session.appium_session_id and self.appium:
            self.appium.close(session.appium_session_id)
            session.appium_session_id = ""

    def _close_scrcpy(self, device_id: str) -> None:
        with self._mirror_lock:
            process = self._scrcpy_processes.pop(device_id, None)
        if process and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=2)

    def _android_activity(self, session: RecordingSession) -> str:
        executable = trusted_which("adb")
        if not executable:
            return ""
        result = _run([
            executable, "-s", session.device_id, "shell", "dumpsys", "activity", "activities"
        ], timeout=5)
        if result.returncode:
            return ""
        for line in result.stdout.decode(errors="replace").splitlines():
            if "mResumedActivity" in line:
                return line.split("mResumedActivity", 1)[-1].strip(" :=")[:180]
        return ""

    def _device_environment(self, session: RecordingSession) -> dict[str, str]:
        if session.platform == "ios":
            return {"platform": "iOS", "app_id": self.ios_bundle_id}
        executable = trusted_which("adb")
        if not executable:
            return {}
        try:
            properties = _run([executable, "-s", session.device_id, "shell", "getprop"], timeout=8)
            size = _run([executable, "-s", session.device_id, "shell", "wm", "size"], timeout=6)
            activity = self._android_activity(session)
        except ExternalServiceError:
            return {}
        if properties.returncode:
            return {}
        values: dict[str, str] = {}
        for raw in properties.stdout.decode(errors="replace").splitlines():
            match = re.match(r"^\[([^]]+)\]: \[(.*)\]$", raw.strip())
            if match:
                values[match.group(1)] = match.group(2)
        package = activity.split("/", 1)[0].strip() if "/" in activity else ""
        environment = {
            "platform": "Android",
            "model": " ".join(part for part in (values.get("ro.product.manufacturer", ""), values.get("ro.product.model", "")) if part)[:160],
            "os_version": values.get("ro.build.version.release", "")[:40],
            "api_level": values.get("ro.build.version.sdk", "")[:20],
            "resolution": size.stdout.decode(errors="replace").replace("Physical size:", "").strip()[:40] if size.returncode == 0 else "",
            "app_id": package[:180],
        }
        # El digitalizador no sigue a la rotación: en una tablet en landscape los
        # toques llegan en coordenadas portrait. Sin el rango y la rotación no hay
        # forma de cruzarlos con una captura, y el análisis no puede atribuirlos.
        try:
            events = _run([executable, "-s", session.device_id, "shell", "getevent", "-pl"], timeout=10)
            window = _run([executable, "-s", session.device_id, "shell", "dumpsys", "window"], timeout=10)
        except ExternalServiceError:
            events = window = None
        if events is not None and events.returncode == 0:
            max_x, max_y = parse_touch_bounds(events.stdout.decode(errors="replace"))
            if max_x and max_y:
                environment["touch_space"] = f"{max_x + 1}x{max_y + 1} (device-native, does not follow rotation)"
        if window is not None and window.returncode == 0:
            environment["screen_rotation"] = f"{parse_rotation(window.stdout.decode(errors='replace'))} degrees"
        if package:
            try:
                package_info = _run([executable, "-s", session.device_id, "shell", "dumpsys", "package", package], timeout=8)
                if package_info.returncode == 0:
                    version = re.search(r"versionName=([^\s]+)", package_info.stdout.decode(errors="replace"))
                    if version:
                        environment["app_version"] = version.group(1)[:80]
            except ExternalServiceError:
                pass
        return {key: value for key, value in environment.items() if value}

    def _android_ui_summary(self, session: RecordingSession) -> str:
        executable = trusted_which("adb")
        if not executable:
            return ""
        try:
            result = _run([
                executable, "-s", session.device_id, "exec-out", "uiautomator", "dump", "/dev/tty"
            ], timeout=8)
        except ExternalServiceError:
            return ""
        if result.returncode or len(result.stdout) > 2 * 1024 * 1024:
            return ""
        lowered = result.stdout.lower()
        if b"<!doctype" in lowered or b"<!entity" in lowered:
            return ""
        xml_start = result.stdout.find(b"<hierarchy")
        if xml_start < 0:
            return ""
        try:
            root = ElementTree.fromstring(result.stdout[xml_start:])
        except ElementTree.ParseError:
            return ""
        labels: list[str] = []
        for node in root.iter("node"):
            attributes = node.attrib
            raw_label = attributes.get("content-desc") or attributes.get("text") or ""
            resource = attributes.get("resource-id", "").rsplit("/", 1)[-1]
            if not raw_label and not resource:
                continue
            label = _redacted_label(raw_label)
            flags = [name for name in ("clickable", "selected", "checked", "focused") if attributes.get(name) == "true"]
            summary = "/".join(part for part in (resource[:80], label[:100]) if part)
            if flags:
                summary += f" ({','.join(flags)})"
            if summary and summary not in labels:
                labels.append(summary)
            if len(labels) >= 25:
                break
        return "; ".join(labels)

    def _ios_ui_summary(self, session: RecordingSession) -> str:
        if not session.appium_session_id or not self.appium:
            return ""
        try:
            source = self.appium.source(session.appium_session_id)
        except ExternalServiceError:
            return ""
        if not source or len(source) > 2 * 1024 * 1024:
            return ""
        lowered = source.lower()
        if "<!doctype" in lowered or "<!entity" in lowered:
            return ""
        try:
            root = ElementTree.fromstring(source)
        except ElementTree.ParseError:
            return ""
        labels: list[str] = []
        for node in root.iter():
            label = _redacted_label(
                node.attrib.get("label") or node.attrib.get("name") or node.attrib.get("value") or ""
            )
            if not label:
                continue
            element_type = node.attrib.get("type", node.tag).replace("XCUIElementType", "")
            summary = f"{element_type}/{label[:100]}"
            if summary not in labels:
                labels.append(summary)
            if len(labels) >= 25:
                break
        return "; ".join(labels)

    def _start_android_action_observer(self, session: RecordingSession) -> None:
        executable = trusted_which("adb")
        if not executable:
            return
        try:
            process = subprocess.Popen(
                [executable, "-s", session.device_id, "shell", "getevent", "-lt"],
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
            )
        except OSError:
            return
        session.action_process = process
        session.action_thread = threading.Thread(
            target=self._observe_android_actions, args=(session,), daemon=True
        )
        session.action_thread.start()

    @staticmethod
    def _observe_android_actions(session: RecordingSession) -> None:
        process = session.action_process
        if not process or not process.stdout:
            return
        x = y = None
        start: tuple[int, int] | None = None
        tracking = False
        for raw in iter(process.stdout.readline, b""):
            if session.stop_event.is_set():
                break
            line = raw.decode(errors="replace")
            match = re.search(r"ABS_MT_POSITION_([XY])\s+([0-9a-fA-F]+)", line)
            if match:
                value = int(match.group(2), 16)
                if match.group(1) == "X":
                    x = value
                else:
                    y = value
                if tracking and start is None and x is not None and y is not None:
                    start = (x, y)
                continue
            tracking_match = re.search(r"ABS_MT_TRACKING_ID\s+([0-9a-fA-F]+)", line)
            if not tracking_match:
                continue
            marker = tracking_match.group(1).lower()
            if marker != "ffffffff":
                tracking = True
                # Las posiciones del toque nuevo llegan DESPUÉS de su tracking id, así
                # que aquí x/y todavía son las del gesto anterior: tomarlas como inicio
                # hacía que cada gesto se reportara saliendo de donde terminó el previo,
                # y un toque sostenido se clasificaba como swipe. Se limpian y el inicio
                # lo fija la primera posición real de este toque.
                x = y = None
                start = None
                # Capturar también al bajar el dedo: el indicador de toques sólo se
                # dibuja mientras el dedo está abajo, así que disparar sólo al soltar
                # dejaba la evidencia sin el punto de contacto. El mismo guardado que
                # abajo evita duplicar los taps del control guiado, que ya capturan
                # antes y después por su cuenta.
                if time.time() - session.last_guided_action_at > 1.5:
                    session.capture_event.set()
                continue
            if tracking and start and x is not None and y is not None:
                distance = abs(x - start[0]) + abs(y - start[1])
                action = "tap" if distance < 40 else "swipe"
                if time.time() - session.last_guided_action_at > 1.5:
                    RecorderManager._append_observation(session,
                        f"Android action at +{time.time() - session.started_at:.1f}s: "
                        f"{action} ({start[0]},{start[1]})→({x},{y})"
                    )
                session.capture_event.set()
            tracking = False
            start = None

    @staticmethod
    def _stop_action_observer(session: RecordingSession) -> None:
        process = session.action_process
        if process and process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=2)
        if session.action_thread and session.action_thread is not threading.current_thread():
            session.action_thread.join(timeout=2)
        session.action_process = None
        session.action_thread = None


def _redacted_label(value: str) -> str:
    text = " ".join(value.split())
    text = re.sub(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", "<email>", text, flags=re.I)
    text = re.sub(r"(?<!\d)\d{6,}(?!\d)", "<number>", text)
    return text
