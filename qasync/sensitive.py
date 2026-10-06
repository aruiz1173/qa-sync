"""Best-effort redaction for text that may reach a provider, browser, or export."""

from __future__ import annotations

import re
from typing import Any

_TEST_CREDENTIAL = re.compile(
    r"(?i)(\b(?:password|passcode|pin|otp|one[- ]time code|verification code)\b"
    r"(?:\s|<[^>]+>){0,8}(?::|=|is|are|-)?(?:\s|<[^>]+>){0,8})([^\s<,;]{3,})"
)
_SECRET_VALUE = re.compile(
    r"(?i)(\b(?:api[-_ ]?key|access[-_ ]?token|client[-_ ]?secret|secret)\b"
    r"(?:\s|<[^>]+>){0,8}(?::|=|is|are|-)?(?:\s|<[^>]+>){0,8})([^\s<,;]{3,})"
)
_AUTH_TOKEN = re.compile(r"(?i)\b(bearer|basic)\s+[A-Za-z0-9._~+/\-=]{8,}")


def redact_text(value: object, *, include_test_credentials: bool = False) -> str:
    text = str(value or "")
    text = _SECRET_VALUE.sub(r"\1[REDACTED]", text)
    if not include_test_credentials:
        text = _TEST_CREDENTIAL.sub(r"\1[REDACTED]", text)
    return _AUTH_TOKEN.sub(r"\1 [REDACTED]", text)


def redact_structure(value: Any, *, include_test_credentials: bool = False) -> Any:
    if isinstance(value, str):
        return redact_text(value, include_test_credentials=include_test_credentials)
    if isinstance(value, list):
        return [redact_structure(item, include_test_credentials=include_test_credentials) for item in value]
    if isinstance(value, dict):
        return {str(key): redact_structure(item, include_test_credentials=include_test_credentials) for key, item in value.items()}
    return value


def redact_known_values(value: Any, secrets: list[str]) -> Any:
    """Remove configured service credentials even when pasted under a test-password label."""
    if isinstance(value, str):
        for secret in secrets:
            if secret and len(secret) >= 8:
                value = value.replace(secret, "[REDACTED]")
        return value
    if isinstance(value, list):
        return [redact_known_values(item, secrets) for item in value]
    if isinstance(value, dict):
        return {key: redact_known_values(item, secrets) for key, item in value.items()}
    return value
