"""
cogno_aegis.types — small value objects shared by the input guard.

Following the "core signals, host decides" rule, the guard returns a structured
``GuardResult`` (a verdict + machine-readable metadata) and never the user-facing
rejection text — the host renders the message for its locale/persona.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict


class GuardCategory(str, Enum):
    """Why the guard rejected an input (or ``OK`` when it passed)."""

    OK = "ok"
    TOO_LONG = "too_long"
    AUDIO_TOO_LONG = "audio_too_long"
    CRISIS = "crisis"


@dataclass(frozen=True)
class GuardResult:
    """The verdict of an input check.

    ``ok`` is the fast boolean; ``category`` says why it failed; ``meta`` carries
    the details a host needs to render a message (e.g. ``{"length": 1200,
    "limit": 1000}`` for ``TOO_LONG`` or ``{"locale": "pt"}`` for ``CRISIS``).
    """

    ok: bool
    category: GuardCategory = GuardCategory.OK
    meta: Dict[str, Any] = field(default_factory=dict)

    def __bool__(self) -> bool:  # truthy == passed
        return self.ok

    @classmethod
    def passed(cls) -> "GuardResult":
        return cls(ok=True, category=GuardCategory.OK)
