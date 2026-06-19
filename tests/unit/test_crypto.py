"""Unit tests for cogno_aegis.crypto — round-trip, tamper detection, fail-loud."""

import os

import pytest

from cogno_aegis import Cipher, DecryptionError, derive_key
from cogno_aegis.crypto import ENC_PREFIX


def _cipher() -> Cipher:
    return Cipher(key=os.urandom(32))


def test_round_trip():
    c = _cipher()
    token = c.encrypt("my-secret-token")
    assert token.startswith(ENC_PREFIX)
    assert token != "my-secret-token"
    assert c.decrypt(token) == "my-secret-token"


def test_nonce_is_random_per_call():
    c = _cipher()
    a = c.encrypt("same input")
    b = c.encrypt("same input")
    assert a != b  # fresh nonce → different ciphertext
    assert c.decrypt(a) == c.decrypt(b) == "same input"


def test_empty_passes_through():
    c = _cipher()
    assert c.encrypt("") == ""
    assert c.decrypt("") == ""


def test_decrypt_non_prefixed_passes_through():
    c = _cipher()
    assert c.decrypt("plain-text-value") == "plain-text-value"


def test_is_encrypted():
    c = _cipher()
    assert Cipher.is_encrypted(c.encrypt("x")) is True
    assert Cipher.is_encrypted("plain") is False
    assert Cipher.is_encrypted("") is False


def test_wrong_key_raises():
    token = _cipher().encrypt("secret")
    other = Cipher(key=os.urandom(32))
    with pytest.raises(DecryptionError):
        other.decrypt(token)


def test_tampered_ciphertext_raises():
    c = _cipher()
    token = c.encrypt("secret")
    # Flip a character in the base64 body → GCM auth tag fails.
    tampered = token[:-2] + ("A" if token[-1] != "A" else "B")
    with pytest.raises(DecryptionError):
        c.decrypt(tampered)


def test_bad_key_size_rejected():
    with pytest.raises(ValueError):
        Cipher(key=b"too-short")


def test_key_must_be_bytes():
    with pytest.raises(TypeError):
        Cipher(key="not-bytes")  # type: ignore[arg-type]


def test_from_passphrase_is_deterministic():
    salt = b"deployment-salt"
    a = Cipher.from_passphrase("hunter2", salt=salt)
    b = Cipher.from_passphrase("hunter2", salt=salt)
    token = a.encrypt("data")
    assert b.decrypt(token) == "data"  # same passphrase+salt → same key


def test_from_passphrase_different_salt_differs():
    a = Cipher.from_passphrase("hunter2", salt=b"salt-a")
    b = Cipher.from_passphrase("hunter2", salt=b"salt-b")
    with pytest.raises(DecryptionError):
        b.decrypt(a.encrypt("data"))


def test_derive_key_length_and_validation():
    assert len(derive_key("pw", salt=b"s")) == 32
    with pytest.raises(ValueError):
        derive_key("", salt=b"s")
    with pytest.raises(ValueError):
        derive_key("pw", salt=b"")


def test_crypto_unavailable_raises(monkeypatch):
    """A missing 'cryptography' backend must fail loud, never silent-plaintext."""
    import cogno_aegis.crypto as crypto_mod
    from cogno_aegis import CryptoUnavailableError

    def _boom():
        raise CryptoUnavailableError("simulated missing backend")

    monkeypatch.setattr(crypto_mod, "_load_aesgcm", _boom)
    with pytest.raises(CryptoUnavailableError):
        Cipher(key=os.urandom(32))
