from app.enrich import enrich
from app.generator import brute_force, encoded_powershell, malware_hash, noise
from app.rules import score
import random
from datetime import datetime, timezone

R, B = random.Random(1), datetime(2026, 1, 1, tzinfo=timezone.utc)


def s(a):
    return score(a, enrich(a))[0]


def test_office_powershell_is_high():
    assert s(encoded_powershell(R, B, True)) >= 70


def test_sccm_powershell_is_grey_zone():
    assert 40 <= s(encoded_powershell(R, B, False)) < 70


def test_ti_hash_is_high_and_internal_tool_low():
    assert s(malware_hash(R, B, True)) >= 70
    assert s(malware_hash(R, B, False)) < 40


def test_corporate_typo_still_fires_rule():
    # the false positive that motivates the lab: rules alone escalate it
    assert s(brute_force(R, B, False)) >= 50


def test_scanner_is_suppressed():
    for _ in range(10):
        a = noise(R, B)
        assert s(a) < 40
