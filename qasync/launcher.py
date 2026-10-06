"""Start and stop the local macOS server through the user's launchd session."""

from __future__ import annotations

import json
import hashlib
import os
import plistlib
import shutil
import subprocess
import sys
import time
from pathlib import Path
from urllib.error import URLError
from urllib.request import urlopen

from .state import private_dir, private_file

LABEL = "com.qasync.local"
URL = "http://127.0.0.1:8787/api/status"
LAUNCHCTL = "/bin/launchctl"


def _target() -> str:
    return f"gui/{os.getuid()}/{LABEL}"


def _run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run([LAUNCHCTL, *args], capture_output=True, text=True, check=False, timeout=15)


def _loaded() -> bool:
    return _run("print", _target()).returncode == 0


def _ready() -> bool:
    try:
        with urlopen(URL, timeout=2) as response:
            if response.status != 200:
                return False
            data = json.loads(response.read(65536))
            return isinstance(data, dict) and "vision_ready" in data and "testrail_ready" in data
    except (OSError, URLError, ValueError):
        return False


def _agent_path() -> Path:
    return private_dir(Path.home() / "Library" / "LaunchAgents") / f"{LABEL}.plist"


def _log_dir() -> Path:
    return private_dir(Path.home() / "Library" / "Logs" / "QA Sync")


def _runtime_root() -> Path:
    return private_dir(Path.home() / "Library" / "Application Support" / "QA Sync")


def _copy_private(source: Path, destination: Path) -> None:
    if source.is_symlink():
        raise RuntimeError("QA Sync will not copy a linked source file into its private runtime.")
    private_dir(destination.parent)
    shutil.copyfile(source, destination)
    private_file(destination)


def _prepare_runtime(project_dir: Path) -> Path:
    root = private_dir(_runtime_root())
    legacy = project_dir / ".qa-sync"
    migration_marker = root / ".migration-complete"
    if not migration_marker.exists():
        if legacy.is_dir():
            for source in sorted(legacy.rglob("*")):
                relative = source.relative_to(legacy)
                if relative.parts[0] in {"server.pid", "server.log", "server-error.log", f"{LABEL}.plist"}:
                    continue
                destination = root / relative
                if source.is_symlink():
                    raise RuntimeError("QA Sync state contains a linked file; review it before migration.")
                if source.is_dir():
                    private_dir(destination)
                elif source.is_file() and not destination.exists():
                    _copy_private(source, destination)
        migration_marker.write_text("1\n", encoding="ascii")
        private_file(migration_marker)

    sources = [path for path in (project_dir / "qasync").rglob("*")
               if path.is_file() and (path.suffix == ".py" or "static" in path.relative_to(project_dir / "qasync").parts)]
    if not sources:
        raise RuntimeError("QA Sync source files are missing.")
    env_file = project_dir / ".env"
    if env_file.is_file():
        sources.append(env_file)
    digest = hashlib.sha256()
    for source in sorted(sources):
        digest.update(str(source.relative_to(project_dir)).encode("utf-8"))
        digest.update(source.read_bytes())
    runtime = private_dir(root / "runtimes") / digest.hexdigest()[:20]
    marker = runtime / ".ready"
    if not marker.is_file():
        private_dir(runtime)
        for source in sources:
            _copy_private(source, runtime / source.relative_to(project_dir))
        marker.write_text("1\n", encoding="ascii")
        private_file(marker)
    return runtime


def _write_agent(runtime_dir: Path) -> Path:
    logs = _log_dir()
    environment = {"PATH": os.environ.get("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")}
    environment["QA_SYNC_STATE_DIR"] = str(_runtime_root())
    for key in ("QA_SYNC_SETTINGS_FILE",):
        if os.environ.get(key):
            environment[key] = os.environ[key]
    agent = {
        "Label": LABEL,
        "ProgramArguments": [sys.executable, "-m", "qasync"],
        "WorkingDirectory": str(runtime_dir.resolve()),
        "EnvironmentVariables": environment,
        "RunAtLoad": True,
        "KeepAlive": False,
        "StandardOutPath": str(logs / "server.log"),
        "StandardErrorPath": str(logs / "server-error.log"),
    }
    path = _agent_path()
    temporary = path.with_suffix(".plist.tmp")
    try:
        temporary.write_bytes(plistlib.dumps(agent))
        private_file(temporary)
        temporary.replace(path)
        private_file(path)
    finally:
        temporary.unlink(missing_ok=True)
    return path


def start(project_dir: Path) -> str:
    if sys.platform != "darwin":
        raise RuntimeError("The launchd launcher is available only on macOS.")
    loaded = _loaded()
    ready = _ready()
    if ready and not loaded:
        raise RuntimeError("Port 8787 is already serving QA Sync outside the launcher. Close that instance first; the launcher will not silently open or replace it.")
    runtime = _prepare_runtime(project_dir)
    agent_path = _agent_path()
    old_runtime = ""
    if loaded and agent_path.is_file():
        try:
            old_runtime = str(plistlib.loads(agent_path.read_bytes()).get("WorkingDirectory", ""))
        except (OSError, ValueError):
            pass
    if loaded and old_runtime == str(runtime.resolve()) and ready:
        return "QA Sync is ready under launchd."
    if loaded and old_runtime == str(runtime.resolve()):
        result = _run("kickstart", "-k", _target())
    else:
        if loaded:
            removed = _run("bootout", _target())
            if removed.returncode:
                raise RuntimeError("launchd could not replace the previous QA Sync job.")
            # bootout returns before launchd has fully released the label.
            for _ in range(20):
                if not _loaded():
                    break
                time.sleep(0.1)
            else:
                raise RuntimeError("The previous QA Sync job did not stop; it was not replaced.")
        agent = _write_agent(runtime)
        result = _run("bootstrap", f"gui/{os.getuid()}", str(agent))
        for _ in range(10):
            if result.returncode == 0 or _loaded():
                break
            time.sleep(0.2)
            result = _run("bootstrap", f"gui/{os.getuid()}", str(agent))
    if result.returncode:
        raise RuntimeError(f"launchd could not start QA Sync: {result.stderr.strip()[:300] or 'bootstrap failed'}. Check ~/Library/Logs/QA Sync/server-error.log.")
    for _ in range(100):
        if _ready():
            return "QA Sync is ready under launchd."
        time.sleep(0.2)
    raise RuntimeError("QA Sync did not become ready. Check ~/Library/Logs/QA Sync/server-error.log.")


def stop() -> str:
    if sys.platform != "darwin":
        raise RuntimeError("The launchd launcher is available only on macOS.")
    if not _loaded():
        return "QA Sync is not managed by launchd; nothing was stopped."
    result = _run("bootout", _target())
    if result.returncode:
        raise RuntimeError("launchd could not stop QA Sync.")
    for _ in range(50):
        if not _ready():
            return "QA Sync stopped."
        time.sleep(0.2)
    raise RuntimeError("QA Sync is still responding after launchd stopped it; another instance may be running.")


def main() -> None:
    if len(sys.argv) != 2 or sys.argv[1] not in {"start", "stop"}:
        raise SystemExit("Usage: python3 -m qasync.launcher start|stop")
    try:
        message = start(Path.cwd()) if sys.argv[1] == "start" else stop()
    except (OSError, subprocess.TimeoutExpired, RuntimeError) as exc:
        raise SystemExit(str(exc)) from exc
    print(message)


if __name__ == "__main__":
    main()
