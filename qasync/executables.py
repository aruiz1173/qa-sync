from __future__ import annotations

import hashlib
import os
import re
import shutil
import stat
from pathlib import Path


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
    pins: dict[str, str] = {}
    for item in os.getenv("QA_SYNC_TRUSTED_HASHES", "").split(","):
        tool, _, digest = item.strip().partition("=")
        digest = digest.strip().lower()
        if tool.strip() and re.fullmatch(r"[0-9a-f]{64}", digest):
            pins[tool.strip().lower()] = digest
    return pins


def describe_untrusted(name: str) -> str:
    """Why a tool was rejected, so an unsigned binary is not reported as missing."""
    resolved = shutil.which(name)
    if not resolved:
        return f"{name} no está instalado o no está en PATH."
    try:
        path = Path(resolved).resolve(strict=True)
        if os.name == "nt" and path.suffix.lower() in {".exe", ".com"} and not _authenticode_valid(path):
            return (
                f"{name} está instalado en {path} pero no tiene firma Authenticode válida. "
                f"Si confías en ese binario, fija su hash con "
                f"QA_SYNC_TRUSTED_HASHES={name}={file_sha256(path)}"
            )
        return f"{name} se resolvió a {path} pero no pasó las comprobaciones de confianza."
    except OSError as exc:
        return f"{name} no se pudo verificar: {exc}"


def trusted_which(name: str) -> str | None:
    """Resolve a binary and reject POSIX files/directories writable by group or everyone."""
    resolved = shutil.which(name)
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
                    return None
        return str(path)
    except OSError:
        return None
