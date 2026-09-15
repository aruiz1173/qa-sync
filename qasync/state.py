from __future__ import annotations

import os
from pathlib import Path

LEGACY_DIR = Path(".qa-sync")


def state_root() -> Path:
    """Default directory for local state.

    On Windows `os.chmod` cannot express an ACL, so privacy comes from the location:
    `%LOCALAPPDATA%` is readable only by this user, while a project directory inherits
    whatever the disk grants. An existing `.qa-sync/` keeps winning so upgrades do not
    lose settings or history.
    """
    configured = os.getenv("QA_SYNC_STATE_DIR", "").strip()
    if configured:
        return Path(configured).resolve()
    if os.name == "nt" and not LEGACY_DIR.exists():
        base = os.getenv("LOCALAPPDATA", "").strip()
        if base:
            return Path(base, "QA Sync").resolve()
    return LEGACY_DIR.resolve()


def private_dir(path: Path) -> Path:
    """Create a directory reachable only by the current user where the OS supports it."""
    path.mkdir(parents=True, exist_ok=True)
    if os.name == "posix":
        os.chmod(path, 0o700)
    return path


def private_file(path: Path) -> Path:
    """Restrict a state file to the current user where the OS supports it."""
    if os.name == "posix":
        os.chmod(path, 0o600)
    return path
