"""Unit tests for cogno_aegis.input_guard + the opt-in safety defaults."""

from cogno_aegis import GuardCategory, InputGuard
from cogno_aegis.safety import (
    DEFAULT_CRISIS_MESSAGES,
    DEFAULT_CRISIS_RULES,
    CrisisRule,
)


def test_length_within_limit_passes():
    g = InputGuard(max_chars=10)
    res = g.check_length("short")
    assert res.ok and res.category is GuardCategory.OK
    assert bool(res) is True


def test_length_over_limit_rejected_with_meta():
    g = InputGuard(max_chars=5)
    res = g.check_length("way too long")
    assert not res.ok
    assert res.category is GuardCategory.TOO_LONG
    assert res.meta == {"length": 12, "limit": 5}
    assert bool(res) is False


def test_audio_duration_guard():
    g = InputGuard(max_audio_seconds=30)
    assert g.check_audio_duration(20).ok is True
    res = g.check_audio_duration(45)
    assert res.category is GuardCategory.AUDIO_TOO_LONG
    assert res.meta["duration"] == 45.0 and res.meta["limit"] == 30


def test_no_crisis_rules_is_noop():
    g = InputGuard()
    assert g.check_crisis("quero me matar").ok is True  # no rules configured
    assert g.crisis_locales() == ()


def test_crisis_detected_en_and_pt():
    g = InputGuard(crisis_rules=DEFAULT_CRISIS_RULES)
    en = g.check_crisis("I want to kill myself")
    assert not en.ok and en.category is GuardCategory.CRISIS and en.meta["locale"] == "en"
    pt = g.check_crisis("eu quero me matar")
    assert not pt.ok and pt.meta["locale"] == "pt"


def test_crisis_excludes_third_person_medical():
    g = InputGuard(crisis_rules=DEFAULT_CRISIS_RULES)
    # Third-person/historical medical phrasing must NOT trip the screen.
    assert g.check_crisis("O paciente teve risco de morte na cirurgia.").ok is True
    assert g.check_crisis("Tive um infarto ano passado").ok is True


def test_check_text_crisis_beats_length():
    g = InputGuard(max_chars=5, crisis_rules=DEFAULT_CRISIS_RULES)
    # A long crisis message → CRISIS, not TOO_LONG.
    res = g.check_text("I really want to die right now")
    assert res.category is GuardCategory.CRISIS


def test_check_text_falls_through_to_length():
    g = InputGuard(max_chars=5, crisis_rules=DEFAULT_CRISIS_RULES)
    res = g.check_text("hello world")
    assert res.category is GuardCategory.TOO_LONG


def test_empty_text_passes():
    g = InputGuard(crisis_rules=DEFAULT_CRISIS_RULES)
    assert g.check_crisis("").ok is True
    assert g.check_text("").ok is True


def test_custom_rule_and_locales():
    rules = [CrisisRule("xx", r"\bhelpword\b")]
    g = InputGuard(crisis_rules=rules)
    assert g.check_crisis("this has a HELPWORD here").meta["locale"] == "xx"
    assert g.crisis_locales() == ("xx",)


def test_default_messages_cover_default_locales():
    locales = {r.locale for r in DEFAULT_CRISIS_RULES}
    assert locales <= set(DEFAULT_CRISIS_MESSAGES)
    # Host renders text from the verdict's locale.
    g = InputGuard(crisis_rules=DEFAULT_CRISIS_RULES)
    res = g.check_text("suicidal thoughts")
    assert DEFAULT_CRISIS_MESSAGES[res.meta["locale"]].startswith("⚠️")
