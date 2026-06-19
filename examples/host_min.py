"""
Minimal host wiring for cogno-aegis — the three primitives end to end.

Run: python examples/host_min.py
(Encryption needs the extra: pip install "cogno-aegis[crypto]")
"""

from cogno_aegis import (
    Cipher,
    GuardCategory,
    InputGuard,
    compare_secret,
    generate_secret,
    hmac_sign,
    hmac_verify,
)
from cogno_aegis.safety import DEFAULT_CRISIS_MESSAGES, DEFAULT_CRISIS_RULES


def demo_crypto() -> None:
    cipher = Cipher.from_passphrase("high-entropy-master-key", salt=b"deployment-salt")
    token = cipher.encrypt("oauth-refresh-token")
    print("encrypted:", token[:24], "…")
    print("decrypted:", cipher.decrypt(token))
    print("pass-through:", cipher.decrypt("plain-value"))


def demo_hmac() -> None:
    secret = generate_secret()
    body = b'{"event":"payment.succeeded"}'
    sig = hmac_sign(secret, body)               # what the sender would send
    print("signature ok:", hmac_verify(secret, body, sig))
    print("tampered ok:", hmac_verify(secret, b'{"event":"hacked"}', sig))
    print("api-key match:", compare_secret("k-123", "k-123"))


def demo_guard() -> None:
    guard = InputGuard(max_chars=40, crisis_rules=DEFAULT_CRISIS_RULES)

    for text in ["how do I reset my password?",
                 "x" * 80,
                 "eu quero me matar"]:
        v = guard.check_text(text)
        if v:
            print(f"[ok]      {text[:30]!r}")
        elif v.category is GuardCategory.CRISIS:
            msg = DEFAULT_CRISIS_MESSAGES[v.meta["locale"]]
            print(f"[crisis]  -> render help ({v.meta['locale']}): {msg.splitlines()[0]}")
        else:
            print(f"[{v.category.value}] len={v.meta.get('length')} limit={v.meta.get('limit')}")


if __name__ == "__main__":
    print("── crypto ──")
    demo_crypto()
    print("\n── hmac ──")
    demo_hmac()
    print("\n── input guard ──")
    demo_guard()
