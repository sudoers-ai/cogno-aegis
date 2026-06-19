"""
cogno_aegis.safety — opt-in default crisis-detection data (heuristic, not clinical).

The parent's ``input_guard`` shipped a Portuguese/English self-harm regex screen
plus CVV-188 / 988 helpline messages. That content is **domain data**, so it lives
here as an *opt-in* default the host explicitly imports and passes to ``InputGuard``
— the engine in ``input_guard.py`` stays neutral (no hard-coded text).

⚠️ These patterns are a **fast, best-effort Layer-1 heuristic** for *unambiguous*
crisis language only (they deliberately ignore subtle/indirect phrasing, which a
host should catch downstream). They are **not** a clinical screening tool and carry
no guarantee of coverage. Hosts may extend, replace, or localize them freely, and
should pair them with a human-escalation path. ``DEFAULT_CRISIS_MESSAGES`` are
sample responses (Brazil/US channels) — review and localize before production use.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class CrisisRule:
    """A single crisis-detection rule: a locale tag + a case-insensitive regex."""

    locale: str
    pattern: str


# Unambiguous self-harm patterns. Each term has no reasonable benign reading
# (e.g. "infarto"/"risco de morte" in the third person are deliberately excluded).
DEFAULT_CRISIS_RULES: tuple[CrisisRule, ...] = (
    # ── English ───────────────────────────────────────────────────────────
    CrisisRule("en", r"\bsuicid"),
    CrisisRule("en", r"\bkill\s+myself\b"),
    CrisisRule("en", r"\bend\s+my\s+life\b"),
    CrisisRule("en", r"\bwant\s+to\s+die\b"),
    # ── Portuguese (pt-BR) ────────────────────────────────────────────────
    CrisisRule("pt", r"\bsuic[íi]d"),
    CrisisRule(
        "pt",
        r"(?:quero|vou|penso em|pensando em|preciso|decidi|decidido a|tentei|tentar)\s+me\s+matar\b",
    ),
    CrisisRule("pt", r"\btirar\s+minha\s+vida\b"),
    CrisisRule("pt", r"\bautoexterm"),
    CrisisRule("pt", r"\bquero\s+morrer\b"),
    CrisisRule("pt", r"\bdesejo\s+de\s+morrer\b"),
    CrisisRule("pt", r"(?:preciso|estou|tenho|meu|minha|me\s+ajud).*\brisco\s+de\s+(?:morte|vida)\b"),
    CrisisRule("pt", r"(?:preciso|estou|tenho|meu|minha|me\s+ajud).*\bemerg[êe]ncia\s+m[ée]dica\b"),
)


_MSG_PT = (
    "⚠️ **Aviso de Segurança / Canais de Ajuda Urgente**\n"
    "Se você ou alguém que você conhece está passando por um momento difícil, "
    "com pensamentos de autoextermínio ou em risco imediato de vida, por favor, "
    "busque ajuda especializada agora mesmo. Você não está sozinho.\n\n"
    "* 📞 **Apoio Emocional (CVV):** Ligue gratuitamente para o **188** "
    "(atendimento 24h, sigiloso e gratuito) ou acesse [cvv.org.br](https://www.cvv.org.br).\n"
    "* 🚑 **Emergência Médica (SAMU):** Se houver risco imediato de vida ou emergência médica, "
    "ligue para o **192** (SAMU) ou dirija-se ao pronto-socorro mais próximo.\n\n"
    "*Por favor, priorize sua segurança e procure profissionais de saúde ou pessoas de "
    "confiança imediatamente.*"
)

_MSG_EN = (
    "⚠️ **Safety Warning / Urgent Help Channels**\n"
    "If you or someone you know is going through a difficult time, "
    "having thoughts of suicide, or is in immediate danger of life, please "
    "seek specialized help right now. You are not alone.\n\n"
    "* 📞 **Crisis Helpline:** If you are in the US/Canada, call or text **988** "
    "(available 24/7, free and confidential) or access [988lifeline.org](https://988lifeline.org).\n"
    "* 🚑 **Medical Emergency:** If there is an immediate threat to life, call your local "
    "emergency number (such as **911** in the US, or **999** in the UK) or go to the nearest "
    "emergency room.\n\n"
    "*Please prioritize your safety and reach out to health professionals or trusted people "
    "immediately.*"
)

# Sample responses keyed by the ``CrisisRule.locale`` tag. Host renders one from
# ``GuardResult.meta["locale"]`` — or supplies its own.
DEFAULT_CRISIS_MESSAGES: dict[str, str] = {"pt": _MSG_PT, "en": _MSG_EN}
