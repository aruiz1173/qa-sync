from __future__ import annotations

import base64
import binascii
import os

from .errors import ConfigurationError, ValidationError

MAGIC = b"QAS1"


class EvidenceCipher:
    """Authenticated encryption for temporary screenshots using AES-256-GCM."""

    def __init__(self, encoded_key: str = ""):
        try:
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
        except ImportError as exc:
            raise ConfigurationError(
                "The cryptography dependency is missing; install it to store encrypted evidence."
            ) from exc
        if encoded_key:
            try:
                key = base64.urlsafe_b64decode(encoded_key.encode("ascii"))
            except (ValueError, UnicodeEncodeError, binascii.Error) as exc:
                raise ConfigurationError("The local evidence key is not valid.") from exc
        else:
            key = os.urandom(32)
        if len(key) != 32:
            raise ConfigurationError("The local evidence key must be 256 bits.")
        self._cipher = AESGCM(key)

    def encrypt(self, plaintext: bytes) -> bytes:
        nonce = os.urandom(12)
        return MAGIC + nonce + self._cipher.encrypt(nonce, plaintext, MAGIC)

    def decrypt(self, payload: bytes) -> bytes:
        if not payload.startswith(MAGIC) or len(payload) < len(MAGIC) + 12 + 16:
            raise ValidationError("An encrypted capture is damaged or invalid.")
        nonce = payload[len(MAGIC):len(MAGIC) + 12]
        try:
            return self._cipher.decrypt(nonce, payload[len(MAGIC) + 12:], MAGIC)
        except Exception as exc:
            raise ValidationError("An encrypted capture failed authentication.") from exc
