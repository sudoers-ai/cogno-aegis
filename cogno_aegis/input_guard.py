"""
cogno_aegis.input_guard — neutral input-size + safety-screen engine.

Caps abusive input (LLM/transcription cost) and runs an optional crisis-language
screen, returning a structured ``GuardResult`` — never user-facing text. Ported
from the parent ``cogno.core.input_guard`` with two divergences:

1. **No environment reading.** Limits are constructor args (the host passes its
   config), not ``COGNO_MAX_*`` env vars read at import time.
2. **Verdict, not message.** Each check returns a ``GuardResult(ok, category, meta)``
   so the host renders the rejection text. Crisis content is injected via
   ``crisis_rules`` (use ``cogno_aegis.safety.DEFAULT_CRISIS_RULES`` for the
   opt-in defaults), keeping this engine free of hard-coded domain strings.
"""

from __future__ import annotations

import logging
import re
from typing import Iterable, List, Optional, Pattern, Sequence, Tuple

from cogno_aegis.types import GuardCategory, GuardResult

log = logging.getLogger(__name__)

DEFAULT_MAX_CHARS = 1000
DEFAULT_MAX_AUDIO_SECONDS = 30.0


class InputGuard:
    """Validate user input against size limits and an optional crisis screen.

    ``crisis_rules`` is an iterable of objects with ``locale`` (str) and
    ``pattern`` (regex source) attributes — e.g. ``CrisisRule`` from
    ``cogno_aegis.safety``. Patterns are compiled case-insensitively at init.
    """

    def __init__(
        self,
        *,
        max_chars: int = DEFAULT_MAX_CHARS,
        max_audio_seconds: float = DEFAULT_MAX_AUDIO_SECONDS,
        crisis_rules: Optional[Iterable] = None,
    ) -> None:
        self.max_chars = max_chars
        self.max_audio_seconds = max_audio_seconds
        self._crisis: List[Tuple[str, Pattern[str]]] = [
            (rule.locale, re.compile(rule.pattern, re.IGNORECASE)) for rule in (crisis_rules or [])
        ]

    # ── crisis screen ────────────────────────────────────────────────────
    def check_crisis(self, text: str) -> GuardResult:
        """Layer-1 regex screen for unambiguous self-harm/crisis language.

        Returns ``GuardResult(ok=False, category=CRISIS, meta={"locale": …})`` on
        the first matching rule, else a passing result. No-op (always passes) when
        no ``crisis_rules`` were configured.
        """
        if not text:
            return GuardResult.passed()
        for locale, pattern in self._crisis:
            if pattern.search(text):
                log.warning("event=crisis_detected locale=%s", locale)
                return GuardResult(ok=False, category=GuardCategory.CRISIS, meta={"locale": locale})
        return GuardResult.passed()

    # ── size guards ──────────────────────────────────────────────────────
    def check_length(self, text: str) -> GuardResult:
        """Reject text over ``max_chars``. ``None``/empty is treated as zero-length (the guard is
        the first thing to touch external input — a failed transcription surfacing as ``None`` must
        not crash the turn with a ``TypeError`` instead of failing cleanly)."""
        length = len(text or "")
        if length <= self.max_chars:
            return GuardResult.passed()
        log.warning("event=text_rejected length=%d limit=%d", length, self.max_chars)
        return GuardResult(
            ok=False,
            category=GuardCategory.TOO_LONG,
            meta={"length": length, "limit": self.max_chars},
        )

    def check_audio_duration(self, duration_seconds: float) -> GuardResult:
        """Reject audio longer than ``max_audio_seconds`` (check before download)."""
        if duration_seconds <= self.max_audio_seconds:
            return GuardResult.passed()
        log.warning(
            "event=audio_rejected duration=%.1f limit=%.1f", duration_seconds, self.max_audio_seconds
        )
        return GuardResult(
            ok=False,
            category=GuardCategory.AUDIO_TOO_LONG,
            meta={"duration": float(duration_seconds), "limit": self.max_audio_seconds},
        )

    # ── combined ─────────────────────────────────────────────────────────
    def check_text(self, text: str) -> GuardResult:
        """Run the crisis screen first (highest priority), then the length cap.

        Crisis takes precedence over length so a long crisis message still routes
        to help rather than being rejected as too long.
        """
        crisis = self.check_crisis(text)
        if not crisis.ok:
            return crisis
        return self.check_length(text)

    def crisis_locales(self) -> Sequence[str]:
        """The distinct locales covered by the configured crisis rules."""
        return tuple(dict.fromkeys(locale for locale, _ in self._crisis))
