# Logging in cogno-aegis

This library follows the Cogno house rule: **libraries emit, the host configures.**

- Each module does `logger = logging.getLogger(__name__)` and emits lazy
  `key=value` messages. The library installs **no** handlers/formatters and never
  calls `basicConfig`.
- The host attaches its handler (tenant/timestamp filter + formatter) to the real
  root logger and sets the level per package, e.g.
  `logging.getLogger("cogno_aegis").setLevel(logging.INFO)`.

## Level policy
- **ERROR** — never emitted by this lib. A security primitive **fails loud by
  raising** (`CryptoUnavailableError`, `DecryptionError`), not by logging an error
  and continuing.
- **WARNING** — a guard tripped: input rejected for length/audio duration, or a
  crisis pattern matched.
- **INFO / DEBUG** — none. The crypto and hmac primitives are deliberately silent:
  they never log keys, secrets, signatures, plaintext, or the user input they
  screen.

## What gets logged
- `cogno_aegis.input_guard` — WARNING `event=text_rejected` (with `length`/`limit`),
  `event=audio_rejected` (with `duration`/`limit`), `event=crisis_detected` (with
  `locale` only — **never the matched text**).
- `cogno_aegis.crypto` / `cogno_aegis.hmac_auth` — nothing.

Keys, passphrases, salts, plaintext, ciphertext, signatures and screened user
text are **never** logged at any level.
