from app.generator import generate, strip_truth


def test_deterministic_and_labelled():
    a, b = generate(48, seed=3), generate(48, seed=3)
    assert a == b
    labels = [x["_truth"]["label"] for x in a]
    assert 0.4 < labels.count("malicious") / len(labels) < 0.7
    assert {x["_truth"]["scenario"] for x in a} >= {"brute_force", "impossible_travel", "encoded_powershell",
                                                    "dns_tunnel", "malware_hash", "noise", "injection"}


def test_strip_truth_removes_labels():
    for x in generate(24):
        assert "_truth" not in strip_truth(x)
        assert "_truth" in x
