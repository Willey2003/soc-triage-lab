"""Offline evaluation: the same labelled alerts through rules, llm and hybrid.

  python -m eval.run_eval --n 120 --seed 7 --out eval/results
Writes <out>/latest.json and <out>/latest.md (plus a timestamped copy of the JSON).
"""
from __future__ import annotations

import argparse
import json
import os
import statistics
import sys
import time
from collections import defaultdict

from app.generator import generate
from app.llm import MODEL, OllamaLLM
from app.triage import triage


def mitre_match(pred, truth):
    if not pred or not truth:
        return False
    return pred == truth or pred.split(".")[0] == truth.split(".")[0]


def score(rows):
    tp = sum(r["mal"] and r["esc"] for r in rows)
    fp = sum(not r["mal"] and r["esc"] for r in rows)
    fn = sum(r["mal"] and not r["esc"] for r in rows)
    tn = sum(not r["mal"] and not r["esc"] for r in rows)
    p = tp / (tp + fp) if tp + fp else 0.0
    rc = tp / (tp + fn) if tp + fn else 0.0
    inj = [r for r in rows if r["scenario"] == "injection"]
    lat = [r["lat"] for r in rows if r["lat"] is not None]
    llm_rows = [r for r in rows if r["valid"] is not None]
    mal_esc = [r for r in rows if r["mal"] and r["esc"]]
    return {
        "n": len(rows), "tp": tp, "fp": fp, "fn": fn, "tn": tn,
        "accuracy": (tp + tn) / len(rows), "precision": p, "recall": rc,
        "f1": 2 * p * rc / (p + rc) if p + rc else 0.0,
        "missed_malicious": fn, "escalated": tp + fp, "false_positives": fp,
        "injection_success_rate": (sum(not r["esc"] for r in inj) / len(inj)) if inj else None,
        "llm_calls": len(llm_rows),
        "json_valid_rate": (sum(r["valid"] for r in llm_rows) / len(llm_rows)) if llm_rows else None,
        "llm_latency_mean_s": statistics.mean(lat) if lat else None,
        "llm_latency_p95_s": sorted(lat)[max(0, int(len(lat) * 0.95) - 1)] if lat else None,
        "mitre_accuracy": (sum(mitre_match(r["mitre"], r["technique"]) for r in mal_esc) / len(mal_esc)) if mal_esc else None,
        "wall_s": sum(r["wall"] for r in rows),
    }


def run(alerts, mode, llm, log):
    rows = []
    for i, a in enumerate(alerts, 1):
        t0 = time.perf_counter()
        d = triage(a, mode, llm)
        wall = time.perf_counter() - t0
        t = a["_truth"]
        rows.append({"id": a["id"], "scenario": t["scenario"], "mal": t["label"] == "malicious", "technique": t["technique"],
                     "esc": d.disposition == "escalate", "by": d.decided_by, "score": d.risk_score,
                     "mitre": d.mitre_technique, "lat": d.llm_latency_s, "valid": d.llm_valid_json, "wall": wall,
                     "reasoning": d.reasoning[:300]})
        if log and (i % 10 == 0 or i == len(alerts)):
            print(f"  {mode}: {i}/{len(alerts)}", file=sys.stderr, flush=True)
    return rows


def by_scenario(rows):
    out = defaultdict(lambda: [0, 0])
    for r in rows:
        key = f"{r['scenario']}/{'mal' if r['mal'] else 'benign'}"
        out[key][0] += r["mal"] == r["esc"]
        out[key][1] += 1
    return {k: f"{c}/{n}" for k, (c, n) in sorted(out.items())}


def fmt(v, pct=False):
    if v is None:
        return "–"
    if pct:
        return f"{v * 100:.0f}%"
    return f"{v:.2f}" if isinstance(v, float) else str(v)


def markdown(res):
    modes = list(res["modes"])
    m = res["modes"]
    lines = [f"Model `{res['model']}` · {res['n']} alerts (seed {res['seed']}) · "
             f"{res['malicious']} malicious, {res['n'] - res['malicious']} benign · {res['finished']}", "",
             "| metric | " + " | ".join(modes) + " |", "|---|" + "---|" * len(modes)]
    rows = [("accuracy", "accuracy", True), ("precision (escalate)", "precision", True), ("recall (escalate)", "recall", True),
            ("F1", "f1", False), ("missed malicious (FN)", "missed_malicious", False),
            ("false positives", "false_positives", False), ("escalated to analyst", "escalated", False),
            ("prompt-injection success", "injection_success_rate", True), ("LLM calls", "llm_calls", False),
            ("valid JSON", "json_valid_rate", True), ("LLM latency mean (s)", "llm_latency_mean_s", False),
            ("LLM latency p95 (s)", "llm_latency_p95_s", False), ("MITRE technique correct", "mitre_accuracy", True),
            ("total triage time (s)", "wall_s", False)]
    for label, k, pct in rows:
        lines.append(f"| {label} | " + " | ".join(fmt(m[x][k], pct) for x in modes) + " |")
    lines += ["", "Correct per scenario:", "", "| scenario | " + " | ".join(modes) + " |", "|---|" + "---|" * len(modes)]
    for s in res["by_scenario"][modes[0]]:
        lines.append(f"| {s} | " + " | ".join(res["by_scenario"][x].get(s, "–") for x in modes) + " |")
    return "\n".join(lines) + "\n"


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=120)
    ap.add_argument("--seed", type=int, default=7)
    ap.add_argument("--modes", default="rules,llm,hybrid")
    ap.add_argument("--out", default="eval/results")
    ap.add_argument("--merge", action="store_true", help="keep other modes from <out>/latest.json")
    args = ap.parse_args()
    alerts = generate(args.n, args.seed)
    llm = OllamaLLM()
    modes = args.modes.split(",")
    if any(x != "rules" for x in modes) and not llm.ready():
        sys.exit(f"model {llm.model} is not loaded in Ollama at {llm.url}")
    prev = None
    if args.merge and os.path.exists(os.path.join(args.out, "latest.json")):
        with open(os.path.join(args.out, "latest.json")) as f:
            prev = json.load(f)
    res = {"model": MODEL, "n": args.n, "seed": args.seed, "malicious": sum(a["_truth"]["label"] == "malicious" for a in alerts),
           "modes": {}, "by_scenario": {}, "rows": {}}
    for mode in modes:
        print(f"mode {mode}", file=sys.stderr, flush=True)
        rows = run(alerts, mode, llm, log=True)
        res["modes"][mode], res["by_scenario"][mode], res["rows"][mode] = score(rows), by_scenario(rows), rows
    if prev and prev["n"] == args.n and prev["seed"] == args.seed:
        for k in ("modes", "by_scenario", "rows"):
            merged = {m: prev[k][m] for m in prev[k] if m not in res[k]}
            merged.update(res[k])
            res[k] = {m: merged[m] for m in ("rules", "llm", "hybrid") if m in merged}
    res["finished"] = time.strftime("%Y-%m-%d %H:%M UTC", time.gmtime())
    os.makedirs(args.out, exist_ok=True)
    blob = json.dumps(res, indent=1)
    for name in ("latest.json", time.strftime("run-%Y%m%d-%H%M%S.json", time.gmtime())):
        with open(os.path.join(args.out, name), "w") as f:
            f.write(blob)
    md = markdown(res)
    with open(os.path.join(args.out, "latest.md"), "w") as f:
        f.write(md)
    print(md)


if __name__ == "__main__":
    main()
