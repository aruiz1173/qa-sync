from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
from pathlib import Path

from .state import private_dir, private_file, state_root


TRUSTABLE_TOOLS = frozenset({"adb", "emulator", "scrcpy", "codex", "claude", "xcrun"})


def _authenticode_valid(path: Path) -> bool:
    """Validate a Windows executable with WinVerifyTrust without invoking a shell."""
    if os.name != "nt":
        return True
    try:
        import ctypes
        from ctypes import wintypes

        class GUID(ctypes.Structure):
            _fields_ = [
                ("Data1", wintypes.DWORD), ("Data2", wintypes.WORD),
                ("Data3", wintypes.WORD), ("Data4", ctypes.c_ubyte * 8),
            ]

        class WINTRUST_FILE_INFO(ctypes.Structure):
            _fields_ = [
                ("cbStruct", wintypes.DWORD), ("pcwszFilePath", wintypes.LPCWSTR),
                ("hFile", wintypes.HANDLE), ("pgKnownSubject", ctypes.c_void_p),
            ]

        class WINTRUST_DATA(ctypes.Structure):
            _fields_ = [
                ("cbStruct", wintypes.DWORD), ("pPolicyCallbackData", ctypes.c_void_p),
                ("pSIPClientData", ctypes.c_void_p), ("dwUIChoice", wintypes.DWORD),
                ("fdwRevocationChecks", wintypes.DWORD), ("dwUnionChoice", wintypes.DWORD),
                ("pFile", ctypes.POINTER(WINTRUST_FILE_INFO)),
                ("dwStateAction", wintypes.DWORD), ("hWVTStateData", wintypes.HANDLE),
                ("pwszURLReference", wintypes.LPCWSTR), ("dwProvFlags", wintypes.DWORD),
                ("dwUIContext", wintypes.DWORD),
            ]

        action = GUID(
            0x00AAC56B, 0xCD44, 0x11D0,
            (ctypes.c_ubyte * 8)(0x8C, 0xC2, 0x00, 0xC0, 0x4F, 0xC2, 0x95, 0xEE),
        )
        file_info = WINTRUST_FILE_INFO(
            ctypes.sizeof(WINTRUST_FILE_INFO), str(path), None, None
        )
        trust_data = WINTRUST_DATA(
            ctypes.sizeof(WINTRUST_DATA), None, None,
            2, 0, 1, ctypes.pointer(file_info), 0, None, None, 0, 0,
        )
        verify = ctypes.windll.wintrust.WinVerifyTrust
        verify.argtypes = [wintypes.HWND, ctypes.POINTER(GUID), ctypes.POINTER(WINTRUST_DATA)]
        verify.restype = wintypes.LONG
        return verify(None, ctypes.byref(action), ctypes.byref(trust_data)) == 0
    except (AttributeError, OSError, TypeError, ValueError):
        return False


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def pinned_hashes() -> dict[str, str]:
    """Hashes an operator accepted for tools that ship unsigned.

    The official scrcpy release for Windows carries no Authenticode signature, so
    requiring one leaves Android mirroring unusable. Pinning the SHA-256 keeps an
    integrity guarantee without a signature, and nothing is trusted implicitly:
    the hash has to be written down.
    Format: `QA_SYNC_TRUSTED_HASHES=scrcpy=<sha256>,adb=<sha256>`
    """
    pins = _stored_pins()
    # Environment pins stay supported for managed installations and override local
    # approvals, so an administrator can revoke a previously accepted build.
    pins.update(_parse_pins(os.getenv("QA_SYNC_TRUSTED_HASHES", "")))
    return pins


def _parse_pins(raw: str) -> dict[str, str]:
    pins: dict[str, str] = {}
    for item in raw.split(","):
        tool, _, digest = item.strip().partition("=")
        digest = digest.strip().lower()
        if tool.strip() and re.fullmatch(r"[0-9a-f]{64}", digest):
            pins[tool.strip().lower()] = digest
    return pins


def _pins_path() -> Path:
    configured = os.getenv("QA_SYNC_TRUSTED_HASH_FILE", "").strip()
    return Path(configured).resolve() if configured else state_root() / "trusted-tools.json"


def _stored_pins() -> dict[str, str]:
    try:
        data = json.loads(_pins_path().read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return _parse_pins(",".join(f"{tool}={digest}" for tool, digest in data.get("pins", {}).items())) if isinstance(data, dict) and isinstance(data.get("pins"), dict) else {}


def inspect_tool(name: str) -> dict[str, str | bool]:
    """Return a local candidate for an explicit, human-approved trust decision."""
    tool = str(name or "").strip().lower()
    if tool not in TRUSTABLE_TOOLS:
        raise ValueError("That tool cannot be approved by QA Sync.")
    resolved = _resolved_executable(tool)
    if not resolved:
        return {"name": tool, "installed": False, "trusted": False, "detail": f"{tool} is not installed or is not on PATH."}
    try:
        path = Path(resolved).resolve(strict=True)
        if not path.is_file():
            raise OSError("not a file")
        return {
            "name": tool, "installed": True, "trusted": bool(trusted_which(tool)),
            "path": str(path), "sha256": file_sha256(path), "detail": describe_untrusted(tool),
        }
    except OSError as exc:
        return {"name": tool, "installed": False, "trusted": False, "detail": f"{tool} could not be verified: {exc}"}


def trust_current_tool(name: str, expected_sha256: object) -> dict[str, str | bool]:
    """Persist only the exact hash the local user reviewed in Settings."""
    candidate = inspect_tool(name)
    digest = str(candidate.get("sha256", ""))
    if not candidate.get("installed") or not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise ValueError("That tool is not available to trust.")
    if str(expected_sha256 or "").strip().lower() != digest:
        raise ValueError("The tool changed before it could be approved. Refresh and review it again.")
    pins = _stored_pins()
    pins[str(candidate["name"])] = digest
    path = _pins_path()
    private_dir(path.parent)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps({"version": 1, "pins": pins}, sort_keys=True), encoding="utf-8")
    private_file(temporary)
    temporary.replace(path)
    return inspect_tool(str(candidate["name"]))


def _resolved_executable(name: str) -> str | None:
    """Find an executable without assuming a GUI launcher inherited a shell PATH.

    QA Sync commonly starts from Finder on macOS. Finder does not receive the PATH
    configured in the user's terminal, even though the official Codex executable
    bundled with ChatGPT is available system-wide.
    """
    resolved = shutil.which(name)
    if resolved:
        return resolved
    if os.name == "posix" and name == "codex":
        bundled = Path("/Applications/ChatGPT.app/Contents/Resources/codex")
        if bundled.is_file():
            return str(bundled)
    return None


def describe_untrusted(name: str) -> str:
    """Why a tool was rejected, so an unsigned binary is not reported as missing."""
    resolved = _resolved_executable(name)
    if not resolved:
        return f"{name} is not installed or is not on PATH."
    try:
        path = Path(resolved).resolve(strict=True)
        if os.name == "nt" and path.suffix.lower() in {".exe", ".com"} and not _authenticode_valid(path):
            return (
                f"{name} is installed at {path} but has no valid Authenticode signature. "
                f"If you trust that binary, pin its hash with "
                f"QA_SYNC_TRUSTED_HASHES={name}={file_sha256(path)}"
            )
        if os.name != "nt" and any(
            candidate.stat().st_mode & (stat.S_IWGRP | stat.S_IWOTH)
            for candidate in [path, *path.parents]
        ):
            return (
                f"{name} is installed at {path}, but one of its directories is writable by a group. "
                f"To trust this exact build, pin its hash with "
                f"QA_SYNC_TRUSTED_HASHES={name}={file_sha256(path)}"
            )
        return f"{name} resolved to {path} but did not pass the trust checks."
    except OSError as exc:
        return f"{name} could not be verified: {exc}"


def trusted_which(name: str) -> str | None:
    """Resolve a binary and reject POSIX files/directories writable by group or everyone."""
    resolved = _resolved_executable(name)
    if not resolved:
        return None
    try:
        path = Path(resolved).resolve(strict=True)
        if not path.is_file():
            return None
        if os.name == "nt":
            if path.suffix.lower() not in {".exe", ".com"}:
                return None
            if not _authenticode_valid(path):
                pinned = pinned_hashes().get(name.lower())
                if not pinned or file_sha256(path) != pinned:
                    return None
        else:
            candidates = [path, *path.parents]
            for candidate in candidates:
                mode = candidate.stat().st_mode
                if mode & (stat.S_IWGRP | stat.S_IWOTH):
                    # Homebrew's shared directories are commonly group-writable on macOS.
                    # Accepting that silently would let another group member replace a tool;
                    # an operator-provided SHA-256 makes this an explicit, per-build choice.
                    pinned = pinned_hashes().get(name.lower())
                    if not pinned or file_sha256(path) != pinned:
                        return None
                    break
        return str(path)
    except OSError:
        return None
