from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from qasync.evals import run_directory


parser = argparse.ArgumentParser(description="Score offline QA Sync golden fixtures without calling vision or TestRail.")
parser.add_argument("directory", type=Path, help="Directory containing JSON fixtures with expected and actual proposals")
args = parser.parse_args()
print(json.dumps(run_directory(args.directory), indent=2, ensure_ascii=False))
