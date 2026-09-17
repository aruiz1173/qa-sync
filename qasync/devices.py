from __future__ import annotations

import ipaddress
import json
import re

from .errors import ExternalServiceError


def parse_adb_devices(output: str) -> list[dict[str, str]]:
    devices = []
    for raw in output.splitlines()[1:]:
        parts = raw.strip().split()
        if len(parts) < 2 or parts[1] != "device":
            continue
        attributes = dict(part.split(":", 1) for part in parts[2:] if ":" in part)
        devices.append({"id": parts[0], "name": attributes.get("model", attributes.get("device", parts[0])).replace("_", " "), "kind": "emulator" if parts[0].startswith("emulator-") else "physical"})
    return devices


def adb_endpoint_result(output: str) -> tuple[bool, str]:
    """Read the outcome of `adb connect` / `adb pair` from its text, not its exit code.

    Both commands exit 0 even when they print `failed to connect to ...`, so trusting
    the return code reports a device as connected when it never was.
    """
    text = " ".join(output.split()).strip()
    lowered = text.lower()
    for marker in ("failed", "cannot connect", "unable to connect", "error:", "no devices"):
        if marker in lowered:
            return False, text
    if "connected to" in lowered or "successfully paired" in lowered:
        return True, text
    return False, text or "ADB returned no output."


def parse_adb_mdns_services(output: str) -> list[dict[str, str]]:
    """Devices advertising Wireless Debugging, so the IP and port need not be typed.

    `adb mdns services` prints `name<tab>service<tab>host:port`; the pairing port and
    the connect port are advertised as different services on the same device.
    """
    services: list[dict[str, str]] = []
    for raw in output.splitlines():
        parts = [part for part in re.split(r"\s+", raw.strip()) if part]
        if len(parts) < 3 or "_adb" not in parts[1]:
            continue
        endpoint = parts[-1]
        match = re.fullmatch(r"(.+):(\d{1,5})", endpoint)
        if not match or not 1 <= int(match.group(2)) <= 65535:
            continue
        services.append({
            "name": parts[0],
            "host": match.group(1),
            "port": match.group(2),
            "kind": "pairing" if "pairing" in parts[1] else "connect",
        })
    return services


def parse_android_ip(output: str) -> str:
    """Wi-Fi address of a device, read from `ip route` or `ip addr`.

    Both forms appear depending on the ROM: `... src 192.168.1.5` from the default
    route and `inet 192.168.1.5/24` from the interface. Only private addresses are
    returned, so a carrier-assigned public one is never dialled.
    """
    candidates = re.findall(r"\bsrc\s+(\d{1,3}(?:\.\d{1,3}){3})\b", output)
    candidates += re.findall(r"\binet\s+(\d{1,3}(?:\.\d{1,3}){3})(?:/\d{1,2})?\b", output)
    for candidate in candidates:
        try:
            address = ipaddress.ip_address(candidate)
        except ValueError:
            continue
        if address.is_private and not address.is_loopback and not address.is_link_local:
            return candidate
    return ""


def parse_adb_tcpip_result(output: str) -> bool:
    lowered = " ".join(output.split()).lower()
    if "error" in lowered or "cannot" in lowered or "failed" in lowered:
        return False
    return "restarting in tcp mode" in lowered or "already" in lowered


def parse_scrcpy_major(output: str) -> int:
    """Major version of scrcpy: `--no-audio` only exists from 2.0 and errors out on 1.x."""
    match = re.search(r"scrcpy\s+v?(\d+)\.", output)
    return int(match.group(1)) if match else 0


def parse_ios_devices(output: str) -> list[dict[str, str]]:
    try:
        runtimes = json.loads(output).get("devices", {})
    except (json.JSONDecodeError, AttributeError) as exc:
        raise ExternalServiceError("simctl returned an invalid device list.") from exc
    return [{"id": str(item["udid"]), "name": str(item.get("name", item["udid"])), "kind": runtime.rsplit(".", 1)[-1].replace("-", " ")} for runtime, entries in runtimes.items() for item in entries if item.get("state") == "Booted" and item.get("isAvailable", True)]


def parse_xctrace_physical_devices(output: str) -> list[dict[str, str]]:
    devices: list[dict[str, str]] = []
    in_simulators = False
    for raw in output.splitlines():
        line = raw.strip()
        if line == "== Simulators ==": in_simulators = True; continue
        if in_simulators or not line or line.startswith("==") or line.startswith("Mac"): continue
        match = re.match(r"(.+?)\s+\(([^()]*)\)\s+\(([0-9A-Fa-f-]{20,})\)$", line)
        if match: devices.append({"id": match.group(3), "name": match.group(1), "kind": f"physical · iOS {match.group(2)}"})
    return devices
