import random
from datetime import datetime, timezone

from app.generator import INJECTION_TEXT, dns_tunnel, encoded_powershell, impossible_travel, malware_hash
from app.llm import build_messages, parse
from app.triage import triage
from tests.conftest import FakeLLM

R, B = random.Random(5), datetime(2026, 1, 1, tzinfo=timezone.utc)


def test_rule_floor_cannot_be_downgraded():
    llm = FakeLLM("close")
    d = triage(encoded_powershell(R, B, True), "hybrid", llm)
    assert d.disposition == "escalate" and d.decided_by == "rule_floor" and llm.seen == []


def test_llm_only_follows_model():
    d = triage(encoded_powershell(R, B, True), "llm", FakeLLM("close"))
    assert d.disposition == "close" and d.decided_by == "llm"


def test_grey_zone_goes_to_model_hardened_and_sanitized():
    llm = FakeLLM("close")
    d = triage(impossible_travel(R, B, False), "hybrid", llm)
    assert d.decided_by == "llm" and d.disposition == "close"
    assert llm.seen and llm.seen[0][2] is True


def test_injection_forces_escalation_without_model():
    llm = FakeLLM("close")
    a = dns_tunnel(R, B, True, injection=INJECTION_TEXT[0])
    d = triage(a, "hybrid", llm)
    assert d.disposition == "escalate" and d.decided_by == "injection_guard" and d.injection_fields == ["http.user_agent"]
    assert llm.seen == []


def test_subtle_injection_on_office_powershell_held_by_floor():
    d = triage(encoded_powershell(R, B, True, injection=INJECTION_TEXT[2]), "hybrid", FakeLLM("close"))
    assert d.disposition == "escalate" and d.decided_by == "rule_floor"


def test_invalid_json_fails_safe():
    d = triage(impossible_travel(R, B, False), "hybrid", FakeLLM(raw="not json"))
    assert d.disposition == "escalate" and d.decided_by == "fallback" and d.llm_valid_json is False


def test_low_score_closes_without_model():
    llm = FakeLLM("escalate")
    d = triage(malware_hash(R, B, False), "hybrid", llm)
    assert d.disposition == "close" and llm.seen == []


def test_truth_never_reaches_model():
    llm = FakeLLM("close")
    triage(impossible_travel(R, B, False), "llm", llm)
    assert "_truth" not in llm.seen[0][0]
    assert "_truth" not in build_messages(llm.seen[0][0], llm.seen[0][1], True)[1]["content"]


def test_parse_schema():
    assert parse('{"disposition":"close","severity":"low","confidence":0.5,"mitre_technique":"NONE","reasoning":"x"}')
    assert parse('{"disposition":"maybe","severity":"low","confidence":0.5,"mitre_technique":"NONE","reasoning":"x"}') is None
    assert parse("{oops") is None


def test_parse_repairs_descriptive_fields_only():
    v = parse('{"disposition":"close","severity":"low","confidence":2,"mitre_technique":"T1078 Valid Accounts","reasoning":"x"}')
    assert v and v.confidence == 0.02 and v.mitre_technique == "T1078"
    assert parse('{"disposition":"close","severity":"none","confidence":0.5,"mitre_technique":"x","reasoning":"x"}') is None


def test_close_veto_without_trusted_context():
    # malicious foreign login, no VPN egress: grey-zone score, model says close -> vetoed
    a = None
    for _ in range(50):
        x = impossible_travel(R, B, True)
        if x["source"]["ip"] == "192.0.2.66" and x["travel"]["mfa"] == "push_approved":
            a = x
            break
    assert a is not None
    d = triage(a, "hybrid", FakeLLM("close"))
    assert d.disposition == "escalate" and d.decided_by == "close_veto"


def test_close_allowed_with_vpn_context():
    d = triage(impossible_travel(R, B, False), "hybrid", FakeLLM("close"))
    assert d.disposition == "close" and d.decided_by == "llm"
