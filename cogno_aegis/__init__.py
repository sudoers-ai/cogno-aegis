"""
cogno-aegis — pure security primitives for the Cogno stack.

The infra-agnostic core of the security layer: authenticated encryption at rest,
constant-time HMAC/secret verification, and a neutral input-size + crisis screen.
Everything is host-injected (keys, secrets, limits, crisis data) — the library
reads no environment, holds no global state, and **fails loud** (a security
primitive must never fail open).

Three groups:

* **crypto** — ``Cipher`` (AES-256-GCM, ``ENC:v1:`` envelope) + ``derive_key``.
  Requires the optional ``cryptography`` backend: ``pip install "cogno-aegis[crypto]"``.
* **hmac_auth** — ``hmac_sign``/``hmac_verify``/``compare_secret``/``generate_secret``
  (stdlib only, constant-time): channel-neutral webhook & secret verification.
* **input_guard** — ``InputGuard`` returning a structured ``GuardResult`` (size +
  optional crisis screen). Opt-in defaults live in ``cogno_aegis.safety``.

Adapted from the parent cogno's ``core/{crypto,auth,input_guard}.py``. RBAC,
credential storage and budget guards (CoreDB-coupled) are intentionally out of
this slice.
"""

from cogno_aegis.crypto import ENC_PREFIX, Cipher, derive_key
from cogno_aegis.errors import AegisError, CryptoUnavailableError, DecryptionError
from cogno_aegis.hmac_auth import (
    SHA256_PREFIX,
    compare_secret,
    generate_secret,
    hmac_sign,
    hmac_verify,
)
from cogno_aegis.input_guard import (
    DEFAULT_MAX_AUDIO_SECONDS,
    DEFAULT_MAX_CHARS,
    InputGuard,
)
from cogno_aegis.types import GuardCategory, GuardResult

__all__ = [
    # crypto
    "Cipher",
    "derive_key",
    "ENC_PREFIX",
    # hmac_auth
    "hmac_sign",
    "hmac_verify",
    "compare_secret",
    "generate_secret",
    "SHA256_PREFIX",
    # input_guard
    "InputGuard",
    "GuardResult",
    "GuardCategory",
    "DEFAULT_MAX_CHARS",
    "DEFAULT_MAX_AUDIO_SECONDS",
    # errors
    "AegisError",
    "CryptoUnavailableError",
    "DecryptionError",
]
