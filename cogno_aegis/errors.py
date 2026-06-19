"""
cogno_aegis.errors — the exception hierarchy for the security primitives.

All errors derive from ``AegisError`` so a host can ``except AegisError`` around
the whole library. They are deliberately loud: unlike the parent's crypto helper
(which silently returned plaintext when the cipher was unavailable or a decrypt
failed), aegis **raises** — a security primitive must never fail open.
"""

from __future__ import annotations


class AegisError(RuntimeError):
    """Base class for every error raised by cogno-aegis."""


class CryptoUnavailableError(AegisError):
    """The optional ``cryptography`` backend is required but not installed.

    Install it with ``pip install "cogno-aegis[crypto]"``. We raise instead of
    degrading to plaintext so a missing dependency can never silently disable
    encryption-at-rest.
    """


class DecryptionError(AegisError):
    """Decryption failed — wrong key, corrupted envelope, or tampered ciphertext.

    AES-GCM is authenticated, so this also fires when the auth tag does not
    verify (i.e. the data was modified after encryption).
    """
