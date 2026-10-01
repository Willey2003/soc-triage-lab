"""Live alert feed: posts synthetic alerts to the API at a steady rate (lab only)."""
from __future__ import annotations

import os
import time

import httpx

from .generator import generate

API = os.environ.get("SOC_API", "http://127.0.0.1:8090")
INTERVAL = float(os.environ.get("FEED_INTERVAL_S", "20"))
BATCH = int(os.environ.get("FEED_BATCH", "1"))


def main():
    seed = int(time.time()) % 10_000
    while True:  # do not feed until the model is loaded, or every alert would fail safe to "escalate"
        try:
            if httpx.get(f"{API}/readyz", timeout=5).status_code == 200:
                break
        except httpx.HTTPError:
            pass
        print("waiting for the API and model...", flush=True)
        time.sleep(15)
    print(f"feeding {API}/ingest: {BATCH} alert(s) every {INTERVAL}s", flush=True)
    while True:
        alerts = generate(200, seed=seed % 100)
        for i in range(0, len(alerts), BATCH):
            chunk = alerts[i:i + BATCH]
            for a in chunk:
                a["id"] = f"live-{seed}-{a['id'].rsplit('-', 1)[1]}"
            try:
                httpx.post(f"{API}/ingest", json=chunk, timeout=10).raise_for_status()
            except httpx.HTTPError as e:
                print(f"ingest failed: {e}", flush=True)
            time.sleep(INTERVAL)
        seed += 1


if __name__ == "__main__":
    main()
