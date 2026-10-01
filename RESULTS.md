# Results

Model `qwen2.5:1.5b` (Ollama 0.34.4, CPU only: 8 vCPU Xeon Gold 6326, no GPU). The eval used 120 labelled alerts (seed 7): 60 malicious and 60 benign.
Reproduce it with `scripts/lab.sh eval 120`. The raw per-alert rows are in `eval/results/*.json`.

## Final run

| metric | rules | LLM only | hybrid |
|---|---|---|---|
| accuracy | 67% | 48% | **81%** |
| precision (escalate) | 60% | 49% | **72%** |
| recall (escalate) | **100%** | 88% | **100%** |
| F1 | 0.75 | 0.63 | **0.84** |
| missed attacks (FN) | **0** | 7 | **0** |
| false positives | 40 | 55 | **23** |
| escalated to an analyst | 100 | 108 | **83** |
| prompt-injection success | 0% | 10% | 0% |
| model calls | 0 | 120 | 43 |
| valid model JSON | – | 94% | 88% |
| model latency mean / p95 | – | 11.4 s / 18.9 s | 10.4 s / 18.3 s |
| ATT&CK technique correct | 100% | 87% | 100% |
| total triage time (120 alerts) | 0 s | 23 min | 7.4 min |

Correct decisions per scenario:

| scenario | rules | LLM only | hybrid |
|---|---|---|---|
| brute force · benign look-alike (corporate typos) | 0/10 | 0/10 | 6/10 |
| brute force · malicious | 10/10 | 10/10 | 10/10 |
| DNS tunnelling · benign (allowlisted telemetry) | 0/10 | 0/10 | 1/10 |
| DNS tunnelling · malicious | 10/10 | 10/10 | 10/10 |
| encoded PowerShell · benign (SCCM / build agent) | 0/10 | 0/10 | 0/10 |
| encoded PowerShell · malicious | 10/10 | 10/10 | 10/10 |
| impossible travel · benign (corporate VPN) | 0/10 | 2/10 | 10/10 |
| impossible travel · malicious | 10/10 | 4/10 | 10/10 |
| prompt injection · malicious | 10/10 | 9/10 | 10/10 |
| malware hash · benign (internally signed tool) | 10/10 | 3/10 | 10/10 |
| malware hash · malicious | 10/10 | 10/10 | 10/10 |
| noise · benign (scanner, single failed logon) | 10/10 | 0/10 | 10/10 |

## What it means

1. **The hybrid design cut the analyst queue by 17% and the false positives by 43%, and missed no attacks.**
   - The analyst queue fell from 100 to 83 alerts.
   - False positives fell from 40 to 23.
   - It needed only 43 model calls for 120 alerts. Rules took the clear cases at both ends.
2. **Letting the model decide everything was the worst design.**
   - It missed 7 of 60 attacks and escalated more benign alerts than the plain rules.
   - It closed 6 foreign logins from new devices. One reasoning text called a Russian login with no MFA "low severity".
   - One of the 10 injection alerts talked it into closing.
   - The model is also inconsistent in the other direction: it escalated the vulnerability scanner it had been told was approved.
3. **The model is useful for exactly one thing here: reading business context the rule does not have.**
   - Its wins are VPN logins (10/10 closed correctly in hybrid) and corporate-network typos (6/10).
   - It still did not trust the allowlist for telemetry DNS or the automation-host flag for SCCM PowerShell. A 1.5B model often restates the rule ("encoded PowerShell is an attacker technique") instead of weighing the context.
4. **Guardrails, in the order they mattered:**
   - **The rule floor (score ≥ 70) handled 54 of 120 alerts without the model.** Every high-confidence attack, including the injection variant written to evade the pattern list, was escalated before the model could see it.
   - **The close veto** (added after run 2): the model may close only when a trusted CMDB or allowlist fact explains the activity.
     - Without it, the hybrid closed 3 malicious foreign logins (recall 95%).
     - With it, recall was 100%, and the veto overrode only those 3 decisions.
   - **The injection guard** caught 3 alerts outright. The rest were already above the floor.
   - **Fail-safe on invalid output:** 5 of 43 model answers (12%) were still invalid and were escalated.
5. **Small models need output repair.**
   - In run 1, 86% of the answers in the model's grey zone failed validation. Ollama's JSON-schema mode enforces types and enums, but not number ranges, so the model returned `"confidence": 2` and `"mitre_technique": "T1078 Valid Accounts"`.
   - The fix repairs the descriptive fields and keeps the decision fields strict.
   - Run 1 is kept in `eval/results/run1-strict-schema.*`.
6. **Latency:** about 10 s per alert on CPU (p95 18 s). That is fine for a queue that gets one alert every 30 s. It is not fine for a burst, and that is one more reason the model handles only the grey zone.

## Runs

| run | change | hybrid recall | hybrid FP | file |
|---|---|---|---|---|
| 1 | strict schema | 100% | 34 (model output mostly invalid, escalated) | `run1-strict-schema.*` |
| 2 | repair descriptive fields | 95% (3 foreign logins closed) | 23 | `run2-hybrid-no-veto.*` |
| 3 | + close veto (evidence-gated close) | **100%** | **23** | `latest.*` |

## Limits

- Synthetic alerts with clean labels. Real alert streams are noisier, and the benign look-alikes here are the textbook ones.
- One model, one seed, temperature 0. Larger models (qwen2.5:7b, llama3.1:8b) are the obvious next run: `SOC_MODEL=... scripts/lab.sh up`.
- The injection guard is a pattern list. It is a tripwire, not a defense. The defense is that the model cannot close what rules score high, and cannot close anything without trusted evidence.
