from __future__ import annotations

import json
import time
import urllib.error
import urllib.request
from typing import Any

from .errors import ExternalServiceError

MAX_RESPONSE_BYTES = 50 * 1024 * 1024
RETRY_BUDGET_SECONDS = 12.0


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def request_json(
    url: str,
    *,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body: dict[str, Any] | None = None,
    timeout: int = 45,
    allow_list: bool = False,
) -> dict[str, Any] | list[Any]:
    data = json.dumps(body).encode("utf-8") if body is not None else None
    merged_headers = {"Accept": "application/json", **(headers or {})}
    if data is not None:
        merged_headers["Content-Type"] = "application/json"
    request_method = method.upper()
    attempts = 3 if request_method in {"GET", "HEAD"} else 1
    raw = b""
    # Presupuesto total de espera, no por intento: el servidor local corta la conexión
    # del navegador a los 20 s (app.py), así que obedecer literalmente un "Retry after
    # 19 seconds" dos veces mataría la petición que se intenta salvar.
    budget = RETRY_BUDGET_SECONDS
    for attempt in range(attempts):
        req = urllib.request.Request(url, data=data, headers=merged_headers, method=request_method)
        try:
            with urllib.request.build_opener(_NoRedirect).open(req, timeout=timeout) as response:
                raw = response.read(MAX_RESPONSE_BYTES + 1)
            if len(raw) > MAX_RESPONSE_BYTES:
                raise ExternalServiceError("El servicio externo devolvió una respuesta demasiado grande.")
            break
        except urllib.error.HTTPError as exc:
            detail = exc.read(4096).decode("utf-8", errors="replace")
            if attempt + 1 < attempts and (exc.code == 429 or 500 <= exc.code < 600):
                retry_after = (exc.headers.get("Retry-After", "") if exc.headers else "").strip()
                if retry_after.isdigit():
                    # Se respeta lo que pide el servidor: TestRail responde "Retry after
                    # 19 seconds" y un tope de 5 s garantizaba que los tres intentos
                    # fallaran igual.
                    delay = float(retry_after)
                elif exc.code == 429:
                    # Una cuota por minuto no se libera en 400 ms.
                    delay = 2.0 * (2 ** attempt)
                else:
                    delay = 0.4 * (2 ** attempt)
                # Si lo que pide no cabe en el presupuesto no se reintenta: esperar
                # menos de lo pedido sólo gasta el tiempo de quien espera para volver
                # a fallar. Se devuelve el mensaje del servidor, que ya dice cuánto.
                if 0 < delay <= budget:
                    budget -= delay
                    time.sleep(delay)
                    continue
            raise ExternalServiceError(
                f"El servicio externo respondió HTTP {exc.code}: {detail}"
            ) from exc
        except urllib.error.URLError as exc:
            if attempt + 1 < attempts:
                time.sleep(0.4 * (2 ** attempt))
                continue
            raise ExternalServiceError(f"No se pudo conectar al servicio externo: {exc.reason}") from exc
    try:
        parsed = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ExternalServiceError("El servicio externo devolvió una respuesta no válida.") from exc
    if isinstance(parsed, list) and allow_list:
        return parsed
    if not isinstance(parsed, dict):
        raise ExternalServiceError("El servicio externo devolvió un formato inesperado.")
    return parsed
