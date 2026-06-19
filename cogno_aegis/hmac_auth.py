"""
cogno_aegis.hmac_auth — generic, constant-time HMAC & secret primitives.

Channel-neutral building blocks for verifying signed payloads (webhooks, callbacks)
and comparing shared secrets / API keys without a timing side-channel. These are
the *primitives* the parent's ``core.auth`` and the per-channel verifiers in
cogno-gateway are built from — aegis owns the cryptography, the edge libs keep
their channel-specific glue and may call these.

Everything here is stdlib only (``hmac``/``hashlib``/``secrets``) and uses
``hmac.compare_digest`` for every comparison, so a wrong guess can't be timed.
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from typing import Union

_Secret = Union[str, bytes]

# Common signature prefix (GitHub/Meta/Evolution style: ``sha256=<hexdigest>``).
SHA256_PREFIX = "sha256="


def _as_bytes(value: _Secret) -> bytes:
    return value if isinstance(value, bytes) else value.encode("utf-8")


def generate_secret(nbytes: int = 32) -> str:
    """Return a cryptographically strong URL-safe secret (CSPRNG).

    Suitable for a webhook shared secret or an API key. ``nbytes`` is the entropy
    in bytes (the string is longer after base64url encoding).
    """
    return secrets.token_urlsafe(nbytes)


def hmac_sign(secret: _Secret, body: bytes, *, prefix: str = SHA256_PREFIX) -> str:
    """Compute ``"<prefix><hex HMAC-SHA256>"`` of ``body`` under ``secret``.

    With the default ``prefix`` this matches the ``X-Hub-Signature-256`` /
    Evolution-API format. Pass ``prefix=""`` for a bare hexdigest.
    """
    digest = hmac.new(_as_bytes(secret), body, hashlib.sha256).hexdigest()
    return f"{prefix}{digest}"


def hmac_verify(secret: _Secret, body: bytes, signature: str, *, prefix: str = SHA256_PREFIX) -> bool:
    """Constant-time check that ``signature`` is a valid HMAC of ``body``.

    Returns ``False`` (never raises) on any mismatch, including a missing/empty
    signature — the caller decides what an invalid signature means.
    """
    if not signature:
        return False
    expected = hmac_sign(secret, body, prefix=prefix)
    return hmac.compare_digest(signature, expected)


def compare_secret(a: _Secret, b: _Secret) -> bool:
    """Constant-time equality of two secrets / tokens (e.g. an API-key header).

    Both sides are compared as bytes so non-ASCII secrets work (unlike a raw
    ``hmac.compare_digest`` on mixed str inputs).
    """
    return hmac.compare_digest(_as_bytes(a), _as_bytes(b))
