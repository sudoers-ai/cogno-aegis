"""Unit tests for cogno_aegis.hmac_auth — signing, constant-time verify, secrets."""

from cogno_aegis import (
    SHA256_PREFIX,
    compare_secret,
    generate_secret,
    hmac_sign,
    hmac_verify,
)


def test_sign_verify_round_trip():
    secret = "shh"
    body = b'{"event":"ping"}'
    sig = hmac_sign(secret, body)
    assert sig.startswith(SHA256_PREFIX)
    assert hmac_verify(secret, body, sig) is True


def test_verify_rejects_wrong_secret():
    body = b"payload"
    sig = hmac_sign("right", body)
    assert hmac_verify("wrong", body, sig) is False


def test_verify_rejects_tampered_body():
    secret = "k"
    sig = hmac_sign(secret, b"original")
    assert hmac_verify(secret, b"modified", sig) is False


def test_verify_empty_signature_is_false():
    assert hmac_verify("k", b"x", "") is False


def test_bytes_and_str_secret_equivalent():
    body = b"x"
    assert hmac_sign("k", body) == hmac_sign(b"k", body)


def test_bare_prefix():
    sig = hmac_sign("k", b"x", prefix="")
    assert not sig.startswith("sha256=")
    assert hmac_verify("k", b"x", sig, prefix="") is True


def test_compare_secret():
    assert compare_secret("abc", "abc") is True
    assert compare_secret("abc", "abd") is False
    assert compare_secret(b"abc", "abc") is True   # mixed bytes/str
    assert compare_secret("açaí", "açaí") is True  # non-ascii


def test_generate_secret_is_random_and_sized():
    a = generate_secret()
    b = generate_secret()
    assert a != b
    assert len(generate_secret(8)) >= 8
