"""SOC triage API: ingest alerts, triage them in the background, serve cases, UI and Prometheus metrics."""
from __future__ import annotations

import asyncio
import os
import time
from contextlib import asynccontextmanager
from typing import List, Literal, Optional, Union

from fastapi import FastAPI, HTTPException, Query
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import HTMLResponse, Response
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Gauge, Histogram, generate_latest
from pydantic import BaseModel

from .llm import OllamaLLM
from .store import Store
from .triage import triage

MODE = os.environ.get("SOC_MODE", "hybrid")
DB = os.environ.get("SOC_DB", "/data/cases.db")
UI = os.path.join(os.path.dirname(__file__), "ui.html")

INGESTED = Counter("soc_alerts_ingested_total", "Alerts received", ["rule"])
DECISIONS = Counter("soc_triage_decisions_total", "Triage decisions", ["mode", "disposition", "decided_by"])
VS_TRUTH = Counter("soc_triage_vs_truth_total", "Decisions scored against lab ground truth", ["mode", "outcome"])
LLM_LAT = Histogram("soc_llm_latency_seconds", "LLM call latency", ["mode"],
                    buckets=(0.5, 1, 2, 3, 5, 8, 13, 20, 30, 60, 120))
LLM_BAD = Counter("soc_llm_invalid_json_total", "LLM answers that failed schema validation", ["mode"])
INJECT = Counter("soc_injection_detected_total", "Alerts with instruction-like text")
FEEDBACK = Counter("soc_analyst_feedback_total", "Analyst feedback on cases", ["verdict", "disposition"])
TRIAGE_T = Histogram("soc_triage_time_seconds", "Time from ingest to decision",
                     buckets=(0.01, 0.1, 0.5, 1, 2, 5, 10, 20, 40, 80, 160))
QUEUE = Gauge("soc_triage_queue_depth", "Alerts waiting for triage")

llm = OllamaLLM()
store: Optional[Store] = None
queue: "asyncio.Queue[tuple[dict, str, float]]"


def record(alert: dict, mode: str, enqueued: float) -> dict:
    truth = alert.get("_truth")
    d = triage(alert, mode, llm).model_dump()
    DECISIONS.labels(mode, d["disposition"], d["decided_by"]).inc()
    if d["llm_latency_s"] is not None:
        LLM_LAT.labels(mode).observe(d["llm_latency_s"])
    if d["llm_valid_json"] is False:
        LLM_BAD.labels(mode).inc()
    if d["injection_fields"]:
        INJECT.inc()
    if truth:
        mal, esc = truth.get("label") == "malicious", d["disposition"] == "escalate"
        VS_TRUTH.labels(mode, {(True, True): "tp", (True, False): "fn", (False, True): "fp", (False, False): "tn"}[(mal, esc)]).inc()
    TRIAGE_T.observe(time.time() - enqueued)
    store.save({k: v for k, v in alert.items() if k != "_truth"}, d, truth)
    return d


async def worker():
    while True:
        alert, mode, t = await queue.get()
        try:
            await run_in_threadpool(record, alert, mode, t)
        except Exception as e:  # keep the worker alive; the alert is logged and dropped
            print(f"triage failed for {alert.get('id')}: {e!r}", flush=True)
        finally:
            queue.task_done()
            QUEUE.set(queue.qsize())


@asynccontextmanager
async def lifespan(app: FastAPI):
    global store, queue
    store = Store(DB)
    queue = asyncio.Queue(maxsize=5000)
    task = asyncio.create_task(worker())
    yield
    task.cancel()


app = FastAPI(title="Private AI-powered SOC triage lab", version="0.1.0", lifespan=lifespan)


class Feedback(BaseModel):
    verdict: Literal["true_positive", "false_positive", "benign_true_positive"]
    note: str = ""


@app.post("/ingest", status_code=202)
async def ingest(alerts: Union[dict, List[dict]], mode: str = Query(MODE, pattern="^(rules|llm|hybrid)$")):
    items = alerts if isinstance(alerts, list) else [alerts]
    for a in items:
        if "id" not in a or "rule" not in a:
            raise HTTPException(422, "each alert needs 'id' and 'rule'")
    for a in items:
        INGESTED.labels(a["rule"].get("name", "?")).inc()
        queue.put_nowait((a, mode, time.time()))
    QUEUE.set(queue.qsize())
    return {"queued": [a["id"] for a in items], "mode": mode}


@app.post("/triage")
async def triage_now(alert: dict, mode: str = Query(MODE, pattern="^(rules|llm|hybrid)$")):
    """Synchronous triage of one alert (not stored); handy for demos and curl."""
    return (await run_in_threadpool(triage, alert, mode, llm)).model_dump()


@app.get("/cases")
def cases(limit: int = Query(100, le=1000), disposition: Optional[str] = None):
    return store.list(limit, disposition)


@app.get("/cases/{case_id}")
def case(case_id: str):
    c = store.get(case_id)
    if not c:
        raise HTTPException(404)
    return c


@app.post("/cases/{case_id}/decision")
def decide(case_id: str, fb: Feedback):
    c = store.get(case_id)
    if not c or not store.feedback(case_id, fb.verdict, fb.note):
        raise HTTPException(404)
    FEEDBACK.labels(fb.verdict, c["disposition"]).inc()
    return {"ok": True}


@app.get("/stats")
def stats():
    return {"mode": MODE, "model": llm.model, "queue": queue.qsize(), "counts": store.counts()}


@app.get("/healthz")
def healthz():
    return {"ok": True}


@app.get("/readyz")
def readyz():
    if not llm.ready():
        raise HTTPException(503, f"model {llm.model} not loaded in Ollama")
    return {"ok": True, "model": llm.model}


@app.get("/metrics")
def metrics():
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)


@app.get("/", response_class=HTMLResponse)
def ui():
    with open(UI) as f:
        return f.read()
