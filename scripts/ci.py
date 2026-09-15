from __future__ import annotations

import compileall
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    if not compileall.compile_dir(ROOT / "qasync", quiet=1):
        return 1
    return subprocess.run([sys.executable, "-m", "unittest", "discover", "-s", "tests", "-v"], cwd=ROOT, check=False).returncode


if __name__ == "__main__":
    raise SystemExit(main())
