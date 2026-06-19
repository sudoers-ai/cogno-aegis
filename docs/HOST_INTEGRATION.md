# Host integration — cogno-aegis

cogno-aegis is the **pure security core**: it gives you primitives, you wire them
into your app. The library reads no environment, owns no keys, and makes no policy
decisions — all of that is the host's job. This guide shows the seams.

## 1. Encryption at rest

The host owns the key material and where it comes from (env, KMS, vault). aegis
just transforms plaintext ↔ ciphertext.

```python
import os
from cogno_aegis import Cipher

# Option A — raw 32-byte key (e.g. from a KMS data key)
cipher = Cipher(key=os.environ["APP_DATA_KEY"].encode()[:32])

# Option B — derive from a passphrase (PBKDF2-HMAC-SHA256, host supplies the salt)
cipher = Cipher.from_passphrase(
    os.environ["COGNO_ENCRYPTION_KEY"],
    salt=b"my-stable-deployment-salt",   # stable per deployment → stable key
)

# Store encrypted, decrypt on read:
row.oauth_token = cipher.encrypt(token)        # "ENC:v1:…"
token = cipher.decrypt(row.oauth_token)        # pass-through if not "ENC:v1:"
```

Notes:
- Build the `Cipher` **once** at startup and reuse it (it is stateless & thread-safe;
  each `encrypt` generates a fresh nonce).
- `decrypt` raises `DecryptionError` on a wrong key or tampered data. Decide your
  policy (fail the request, alert, re-key) — aegis will not swallow it.
- Install the extra: `pip install "cogno-aegis[crypto]"`. Constructing a `Cipher`
  without `cryptography` raises `CryptoUnavailableError` (it will not silently store
  plaintext).
- The `ENC:v1:` envelope matches the parent cogno format, so previously-encrypted
  values decrypt unchanged after migration.

## 2. Webhook / signature verification

aegis provides the constant-time primitives; the host (or an edge lib like
cogno-gateway) maps them onto its transport headers.

```python
from cogno_aegis import hmac_verify, compare_secret

def verify_webhook(headers, body, *, secret, api_key):
    # Mode 1: HMAC-SHA256 body signature (preferred)
    sig = headers.get("x-hub-signature-256", "")
    if secret and sig:
        return hmac_verify(secret, body, sig)          # "sha256=…" style
    # Mode 2: shared API key header (fallback)
    got = headers.get("apikey", "")
    if api_key and got:
        return compare_secret(got, api_key)
    # No secret configured: that is a host policy call (fail-open in dev,
    # fail-closed in prod) — aegis does not decide it for you.
    return not is_production
```

> cogno-gateway already implements this per channel; aegis is the shared
> cryptographic floor those verifiers can sit on (de-dup at your discretion).

## 3. Input guard

Inject your limits and (optionally) the crisis data; render the message yourself.

```python
from cogno_aegis import InputGuard, GuardCategory
from cogno_aegis.safety import DEFAULT_CRISIS_RULES, DEFAULT_CRISIS_MESSAGES

guard = InputGuard(
    max_chars=int(os.getenv("MAX_INPUT_CHARS", "1000")),
    max_audio_seconds=float(os.getenv("MAX_AUDIO_SECONDS", "30")),
    crisis_rules=DEFAULT_CRISIS_RULES,          # opt-in; or your own CrisisRule list
)

def screen(text: str) -> str | None:
    v = guard.check_text(text)
    if v:                                       # truthy GuardResult == passed
        return None
    if v.category is GuardCategory.CRISIS:
        return DEFAULT_CRISIS_MESSAGES.get(v.meta["locale"], DEFAULT_CRISIS_MESSAGES["en"])
    if v.category is GuardCategory.TOO_LONG:
        return f"Message is {v.meta['length']} chars; limit is {v.meta['limit']}."
    return "Input rejected."
```

Before downloading/transcribing audio, gate on duration:

```python
v = guard.check_audio_duration(reported_seconds)
if not v:
    reject(f"Audio over {v.meta['limit']}s limit.")
```

### Crisis data is heuristic, not clinical

`DEFAULT_CRISIS_RULES` only catches **unambiguous** self-harm phrasing (it ignores
subtle/indirect language by design) and `DEFAULT_CRISIS_MESSAGES` are Brazil/US
samples. **Review, localize, and pair them with a real human-escalation path**
before production. Subtle cases should be caught by a downstream NER/LLM layer.

## 4. Logging

The library emits `key=value` warnings only (input rejections / crisis matches,
locale only — never the text). It logs no keys, secrets, signatures or plaintext.
Configure level per package: `logging.getLogger("cogno_aegis").setLevel("INFO")`.
See [../LOGGING.md](../LOGGING.md).

## 5. What aegis does NOT do (host / other libs)

- **RBAC / permissions**, **credential storage**, **budget/cost guards**, **OAuth
  flows** — CoreDB-coupled; out of this pure slice.
- **Key management / rotation / KMS** — the host owns key lifecycle; aegis only
  uses the key you hand it.
- **Policy** — fail-open vs fail-closed on a missing webhook secret, what to do on
  a `DecryptionError`, the user-facing copy — all host decisions.
