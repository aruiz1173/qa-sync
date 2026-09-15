from __future__ import annotations

import os
import re
from pathlib import Path

from .errors import ConfigurationError

NAME = re.compile(r"[A-Z_][A-Z0-9_]*")


def load_dotenv(path: Path) -> None:
    """Load literal KEY=VALUE pairs without shell expansion or command execution."""
    if not path.is_file():
        return
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError as exc:
        raise ConfigurationError("No se pudo leer el archivo .env.") from exc
    for number, raw in enumerate(lines, 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise ConfigurationError(f"Línea {number} inválida en .env.")
        name, value = line.split("=", 1)
        name, value = name.strip(), value.strip()
        if not NAME.fullmatch(name):
            raise ConfigurationError(f"Variable inválida en la línea {number} de .env.")
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        if "\x00" in value or len(value) > 20000:
            raise ConfigurationError(f"Valor inválido en la línea {number} de .env.")
        os.environ[name] = value
