import time

from fastapi.testclient import TestClient

from app import api
from app.generator import generate
from tests.conftest import FakeLLM


def test_ingest_cases_feedback_metrics(tmp_path, monkeypatch):
    monkeypatch.setattr(api, "DB", str(tmp_path / "c.db"))
    monkeypatch.setattr(api, "llm", FakeLLM("close"))
    alerts = generate(12, seed=9)
    with TestClient(api.app) as c:
        r = c.post("/ingest", json=alerts)
        assert r.status_code == 202 and len(r.json()["queued"]) == 12
        for _ in range(100):
            if len(c.get("/cases").json()) == 12:
                break
            time.sleep(0.05)
        cases = c.get("/cases").json()
        assert len(cases) == 12
        assert all("_truth" not in x["alert"] for x in cases)
        assert c.post(f"/cases/{cases[0]['id']}/decision", json={"verdict": "false_positive"}).status_code == 200
        assert c.post("/cases/nope/decision", json={"verdict": "false_positive"}).status_code == 404
        m = c.get("/metrics").text
        assert "soc_triage_decisions_total" in m and "soc_analyst_feedback_total" in m
        assert c.get("/").status_code == 200
        assert c.post("/ingest", json={"no": "id"}).status_code == 422
