# Changelog

## 0.1.1 — 2026-11-11

### Fixed

- `hmac_verify` no longer raises `TypeError` when the signature header carries a non-ASCII
  byte. The signature arrives from outside, so an attacker could turn a signed route into a
  500 by sending a header with a non-ASCII character (`hmac.compare_digest` rejects a `str`
  with non-ASCII code points). The comparison is now done as bytes — a non-ASCII signature
  is simply invalid and returns `False`, keeping the check constant-time and total.

## 0.1.0 — 2026-07-25

First public release on PyPI.

Pure security primitives for the Cogno stack — AES-256-GCM encryption at rest, constant-time HMAC/secret verification, and a neutral input-size + crisis screen. Host-injected, fail-loud, deps-minimal.
