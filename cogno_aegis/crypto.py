"""
cogno_aegis.crypto — authenticated symmetric encryption for secrets at rest.

AES-256-GCM (authenticated encryption) to protect OAuth tokens, API keys and
other secrets a host stores in its DB. Ported from the parent ``cogno.core.crypto``
with three deliberate divergences toward the cogno philosophy:

1. **No environment reading.** The parent derived its key from ``COGNO_ENCRYPTION_KEY``
   / ``POSTGRES_URL`` env vars inside the module. Here the **host injects** the key:
   ``Cipher(key=...)`` (32 raw bytes) or ``Cipher.from_passphrase(passphrase, salt=...)``.
   The library reads no env and holds no global state.
2. **Fail loud, never silent-plaintext.** The parent returned the plaintext
   unchanged when ``cryptography`` was missing or encryption raised. That is a
   security footgun (you think it is encrypted; it is not). aegis raises
   ``CryptoUnavailableError`` / ``DecryptionError`` instead.
3. **``cryptography`` is an optional extra** (``pip install "cogno-aegis[crypto]"``),
   lazily imported so the hmac/input-guard half of the lib stays zero-dependency.

Envelope format (unchanged from the parent, so existing ciphertext stays readable)::

    ENC:v1:  base64url( nonce:12 || ciphertext || tag:16 )

The 96-bit nonce is freshly random per ``encrypt`` (thread-safe). Values without
the ``ENC:v1:`` prefix pass through ``decrypt`` unchanged (pre-encryption data).
"""

from __future__ import annotations

import base64
import hashlib
import os

from cogno_aegis.errors import CryptoUnavailableError, DecryptionError

# Self-describing prefix that marks an aegis-encrypted value in storage.
ENC_PREFIX = "ENC:v1:"

_NONCE_BYTES = 12  # 96-bit nonce, the GCM standard
_KEY_BYTES = 32  # AES-256
_DEFAULT_ITERATIONS = 200_000


def _load_aesgcm():
    """Import ``AESGCM`` lazily, raising a clear error if the extra is missing."""
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError as exc:  # pragma: no cover - exercised via monkeypatch
        raise CryptoUnavailableError(
            "cogno-aegis crypto requires the 'cryptography' package. "
            'Install it with: pip install "cogno-aegis[crypto]"'
        ) from exc
    return AESGCM


def derive_key(
    passphrase: str,
    *,
    salt: bytes,
    iterations: int = _DEFAULT_ITERATIONS,
) -> bytes:
    """Derive a 32-byte AES-256 key from a passphrase via PBKDF2-HMAC-SHA256.

    The ``salt`` is **required and host-supplied** — there is no built-in fixed
    salt (the parent hard-coded one; we make it explicit to avoid a silent
    cross-tenant footgun). Use a stable per-deployment salt so the same passphrase
    derives the same key across restarts.
    """
    if not passphrase:
        raise ValueError("passphrase must be a non-empty string")
    if not salt:
        raise ValueError("salt must be non-empty bytes")
    return hashlib.pbkdf2_hmac("sha256", passphrase.encode("utf-8"), salt, iterations, dklen=_KEY_BYTES)


class Cipher:
    """AES-256-GCM cipher over a host-supplied 32-byte key.

    Construct with raw key bytes, or derive from a passphrase::

        cipher = Cipher(key=os.urandom(32))
        cipher = Cipher.from_passphrase("…", salt=b"my-deployment-salt")

        token = cipher.encrypt("secret")     # "ENC:v1:…"
        cipher.decrypt(token)                 # "secret"
        cipher.decrypt("not-encrypted")      # "not-encrypted" (pass-through)
    """

    def __init__(self, key: bytes) -> None:
        if not isinstance(key, (bytes, bytearray)):
            raise TypeError("key must be bytes")
        if len(key) != _KEY_BYTES:
            raise ValueError(f"key must be exactly {_KEY_BYTES} bytes (AES-256); got {len(key)}")
        # Validate the backend is present at construction time (fail early/loud).
        self._aesgcm_cls = _load_aesgcm()
        self._key = bytes(key)

    @classmethod
    def from_passphrase(
        cls,
        passphrase: str,
        *,
        salt: bytes,
        iterations: int = _DEFAULT_ITERATIONS,
    ) -> "Cipher":
        """Build a ``Cipher`` from a passphrase + host-supplied salt (PBKDF2)."""
        return cls(derive_key(passphrase, salt=salt, iterations=iterations))

    @staticmethod
    def is_encrypted(value: str) -> bool:
        """True iff ``value`` carries the ``ENC:v1:`` envelope prefix."""
        return bool(value) and value.startswith(ENC_PREFIX)

    def encrypt(self, plaintext: str) -> str:
        """Encrypt ``plaintext`` → ``ENC:v1:…``. Empty input passes through."""
        if not plaintext:
            return plaintext
        aesgcm = self._aesgcm_cls(self._key)
        nonce = os.urandom(_NONCE_BYTES)
        ciphertext = aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
        encoded = base64.urlsafe_b64encode(nonce + ciphertext).decode("ascii")
        return f"{ENC_PREFIX}{encoded}"

    def decrypt(self, value: str) -> str:
        """Decrypt an ``ENC:v1:`` value. Non-prefixed values pass through.

        Raises ``DecryptionError`` on a wrong key, corrupt envelope, or tampered
        ciphertext (the GCM auth tag fails).
        """
        if not value or not value.startswith(ENC_PREFIX):
            return value
        aesgcm = self._aesgcm_cls(self._key)
        try:
            packed = base64.urlsafe_b64decode(value[len(ENC_PREFIX):])
            nonce, ciphertext = packed[:_NONCE_BYTES], packed[_NONCE_BYTES:]
            plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        except Exception as exc:
            raise DecryptionError(f"decryption failed (wrong key or tampered data): {exc}") from exc
        return plaintext.decode("utf-8")
