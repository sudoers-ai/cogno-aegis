"""
Property-based tests (hypothesis) for the crypto + hmac primitives.

The example-based suite pins specific cases; these assert the *invariants* across a
wide input space: encrypt/decrypt is a round-trip for any text, keys isolate,
HMAC verifies what it signs, and secret comparison matches equality.
"""

import os

from hypothesis import given
from hypothesis import strategies as st

from cogno_aegis import (
    Cipher,
    DecryptionError,
    compare_secret,
    derive_key,
    hmac_sign,
    hmac_verify,
)

# Exclude lone surrogates (category "Cs") so .encode("utf-8") never raises.
text = st.text(st.characters(blacklist_categories=("Cs",)))
nonempty_text = st.text(st.characters(blacklist_categories=("Cs",)), min_size=1)
secrets_st = st.one_of(nonempty_text, st.binary(min_size=1))


# ── crypto ───────────────────────────────────────────────────────────────
@given(s=text)
def test_encrypt_decrypt_round_trip(s):
    cipher = Cipher(key=os.urandom(32))
    assert cipher.decrypt(cipher.encrypt(s)) == s


@given(s=nonempty_text)
def test_distinct_keys_cannot_decrypt(s):
    a = Cipher(key=os.urandom(32))
    b = Cipher(key=os.urandom(32))
    token = a.encrypt(s)
    try:
        # Astronomically unlikely two random 256-bit keys collide; if the GCM tag
        # somehow verified, the plaintext must at least differ from the original.
        assert b.decrypt(token) != s
    except DecryptionError:
        pass  # the expected outcome: authentication fails


@given(s=nonempty_text, salt=st.binary(min_size=1))
def test_passphrase_derivation_is_deterministic(s, salt):
    a = Cipher.from_passphrase("master-pass", salt=salt)
    b = Cipher.from_passphrase("master-pass", salt=salt)
    assert b.decrypt(a.encrypt(s)) == s


@given(passphrase=nonempty_text, salt=st.binary(min_size=1))
def test_derive_key_is_always_32_bytes(passphrase, salt):
    assert len(derive_key(passphrase, salt=salt)) == 32


# ── hmac ─────────────────────────────────────────────────────────────────
@given(secret=secrets_st, body=st.binary())
def test_hmac_verifies_what_it_signs(secret, body):
    assert hmac_verify(secret, body, hmac_sign(secret, body)) is True


@given(secret=secrets_st, other=secrets_st, body=st.binary())
def test_hmac_rejects_wrong_secret(secret, other, body):
    sig = hmac_sign(secret, body)
    expected = (hmac_sign(other, body) == sig)  # equal only if secrets coincide
    assert hmac_verify(other, body, sig) is expected


@given(a=st.binary(), b=st.binary())
def test_compare_secret_matches_equality(a, b):
    assert compare_secret(a, b) == (a == b)
