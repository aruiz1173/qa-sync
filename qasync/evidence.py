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
                "Falta la dependencia cryptography; instálala para guardar evidencia cifrada."
            ) from exc
        if encoded_key:
            try:
                key = base64.urlsafe_b64decode(encoded_key.encode("ascii"))
            except (ValueError, UnicodeEncodeError, binascii.Error) as exc:
                raise ConfigurationError("La clave local de evidencia no es válida.") from exc
        else:
            key = os.urandom(32)
        if len(key) != 32:
            raise ConfigurationError("La clave local de evidencia debe tener 256 bits.")
        self._cipher = AESGCM(key)

    def encrypt(self, plaintext: bytes) -> bytes:
        nonce = os.urandom(12)
        return MAGIC + nonce + self._cipher.encrypt(nonce, plaintext, MAGIC)

    def decrypt(self, payload: bytes) -> bytes:
        if not payload.startswith(MAGIC) or len(payload) < len(MAGIC) + 12 + 16:
            raise ValidationError("Una captura cifrada está dañada o no es válida.")
        nonce = payload[len(MAGIC):len(MAGIC) + 12]
        try:
            return self._cipher.decrypt(nonce, payload[len(MAGIC) + 12:], MAGIC)
        except Exception as exc:
            raise ValidationError("No se pudo autenticar una captura cifrada.") from exc
