# cogno-aegis

**Pure security primitives for the Cogno stack** — authenticated encryption at
rest, constant-time HMAC/secret verification, and a neutral input-size + crisis
screen. Infra-agnostic, host-injected, **fail-loud**, deps-minimal.

> _aegis_ (αἰγίς) — the shield. The pure, reusable security core extracted from the
> parent Cogno SaaS (`core/{crypto,auth,input_guard}.py`). RBAC, credential
> storage and budget guards (CoreDB-coupled) are intentionally **out of this slice**.

## Why

A security helper must never **fail open**. The parent's crypto module silently
returned *plaintext* when the cipher backend was missing or a decrypt failed, and
read its key straight from environment variables. cogno-aegis inverts both:

- **Host injects everything** — keys, secrets, limits, crisis data. The library
  reads no environment and holds no global state.
- **Fail loud** — a missing backend or a bad key/ciphertext **raises**
  (`CryptoUnavailableError` / `DecryptionError`); it never degrades to plaintext.
- **Core signals, host decides** — the input guard returns a structured
  `GuardResult`, never user-facing text. The host renders the message.

## Install

```bash
pip install cogno-aegis            # hmac + input-guard (stdlib only, zero deps)
pip install "cogno-aegis[crypto]"  # + AES-256-GCM (pulls `cryptography`)
```

## Three primitives

### 1. `crypto` — encryption at rest (AES-256-GCM)

```python
from cogno_aegis import Cipher

cipher = Cipher.from_passphrase("…high-entropy…", salt=b"my-deployment-salt")
# or: Cipher(key=os.urandom(32))

token = cipher.encrypt("oauth-refresh-token")   # "ENC:v1:…"
cipher.decrypt(token)                            # "oauth-refresh-token"
cipher.decrypt("not-encrypted")                  # pass-through (pre-encryption data)
```

Envelope: `ENC:v1: base64url(nonce:12 ‖ ciphertext ‖ tag:16)` — a fresh random
nonce per call, authenticated (tamper → `DecryptionError`). Wire-compatible with
the parent's format.

### 2. `hmac_auth` — channel-neutral signature & secret verification

```python
from cogno_aegis import hmac_sign, hmac_verify, compare_secret, generate_secret

secret = generate_secret()                       # CSPRNG, URL-safe
sig = hmac_sign(secret, request_body)            # "sha256=…" (X-Hub-Signature-256 style)
hmac_verify(secret, request_body, header_sig)    # constant-time bool
compare_secret(header_api_key, expected_key)     # constant-time, bytes-safe
```

These are the primitives the per-channel webhook verifiers (cogno-gateway) build
on — aegis owns the cryptography, the edge libs keep their channel glue.

### 3. `input_guard` — size cap + optional crisis screen

```python
from cogno_aegis import InputGuard, GuardCategory
from cogno_aegis.safety import DEFAULT_CRISIS_RULES, DEFAULT_CRISIS_MESSAGES

guard = InputGuard(max_chars=1000, crisis_rules=DEFAULT_CRISIS_RULES)

verdict = guard.check_text(user_text)
if not verdict:
    if verdict.category is GuardCategory.CRISIS:
        reply = DEFAULT_CRISIS_MESSAGES[verdict.meta["locale"]]   # host renders
    else:  # TOO_LONG
        reply = f"Limit is {verdict.meta['limit']} chars."
```

The engine is neutral — crisis patterns and messages are **opt-in data** in
`cogno_aegis.safety` (a heuristic Layer-1 screen, **not** a clinical tool; localize
before production). Bring your own `CrisisRule`s to extend or replace them.

## Design

| Principle | How |
|---|---|
| Infra-agnostic | no env reading, no globals; host injects keys/secrets/limits |
| Fail-loud | raises on missing backend / bad key / tamper — never fails open |
| Deps-minimal | stdlib-only core; `cryptography` is an optional `[crypto]` extra |
| Core signals, host decides | `GuardResult` verdict, not rendered text |
| Constant-time | every secret comparison via `hmac.compare_digest` |

See [docs/HOST_INTEGRATION.md](docs/HOST_INTEGRATION.md) and [LOGGING.md](LOGGING.md).

## The Cogno ecosystem

`cogno-aegis` is one organ of **[Cogno](https://github.com/sudoers-ai)** — a family of
small, composable, Apache-2.0 libraries that together form a complete
conversational-agent platform. Each library owns a single concern and stays
infra-agnostic; a **host** assembles them into a running agent:

![The Cogno ecosystem](docs/assets/cogno-ecosystem.svg)

The open-source libraries are the organs; the **host is the body** that joins
them. Our reference host — `cogno-host`, with its `cogno-ui` dashboard — is the
private product layer, but it holds no special powers: everything it does rides
on the public seams documented in each library's `docs/HOST_INTEGRATION.md`, so
you can assemble a body of your own.

## Development

```bash
pip install -e ".[dev]"
ruff check cogno_aegis tests examples
mypy cogno_aegis
pytest tests/unit -q --cov=cogno_aegis
```

## License

Apache-2.0
