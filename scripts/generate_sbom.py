from __future__ import annotations

import argparse
import importlib.metadata
import json
import uuid
from pathlib import Path


PACKAGES = ("cryptography", "cffi", "pycparser")


def document() -> dict[str, object]:
    components = []
    for name in PACKAGES:
        try:
            version = importlib.metadata.version(name)
        except importlib.metadata.PackageNotFoundError:
            continue
        components.append({
            "type": "library", "name": name, "version": version,
            "purl": f"pkg:pypi/{name}@{version}",
        })
    return {
        "bomFormat": "CycloneDX", "specVersion": "1.5", "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {"component": {"type": "application", "name": "qa-sync", "version": "1.0.0"}},
        "components": components,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate the QA Sync CycloneDX SBOM")
    parser.add_argument("--output", type=Path)
    arguments = parser.parse_args()
    payload = json.dumps(document(), indent=2, sort_keys=True) + "\n"
    if arguments.output:
        arguments.output.write_text(payload, encoding="utf-8")
    else:
        print(payload, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
