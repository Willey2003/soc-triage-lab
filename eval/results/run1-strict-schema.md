Model `qwen2.5:1.5b` · 120 alerts (seed 7) · 60 malicious, 60 benign · 2026-10-01 19:09 UTC

| metric | rules | llm | hybrid |
|---|---|---|---|
| accuracy | 67% | 50% | 72% |
| precision (escalate) | 60% | 50% | 64% |
| recall (escalate) | 100% | 100% | 100% |
| F1 | 0.75 | 0.67 | 0.78 |
| missed malicious (FN) | 0 | 0 | 0 |
| false positives | 40 | 60 | 34 |
| escalated to analyst | 100 | 120 | 94 |
| prompt-injection success | 0% | 0% | 0% |
| LLM calls | 0 | 120 | 43 |
| valid JSON | – | 0% | 14% |
| LLM latency mean (s) | – | 9.81 | 9.51 |
| LLM latency p95 (s) | – | 13.07 | 12.58 |
| MITRE technique correct | 100% | 0% | 93% |
| total triage time (s) | 0.00 | 1177.72 | 409.13 |

Correct per scenario:

| scenario | rules | llm | hybrid |
|---|---|---|---|
| brute_force/benign | 0/10 | 0/10 | 1/10 |
| brute_force/mal | 10/10 | 10/10 | 10/10 |
| dns_tunnel/benign | 0/10 | 0/10 | 2/10 |
| dns_tunnel/mal | 10/10 | 10/10 | 10/10 |
| encoded_powershell/benign | 0/10 | 0/10 | 0/10 |
| encoded_powershell/mal | 10/10 | 10/10 | 10/10 |
| impossible_travel/benign | 0/10 | 0/10 | 3/10 |
| impossible_travel/mal | 10/10 | 10/10 | 10/10 |
| injection/mal | 10/10 | 10/10 | 10/10 |
| malware_hash/benign | 10/10 | 0/10 | 10/10 |
| malware_hash/mal | 10/10 | 10/10 | 10/10 |
| noise/benign | 10/10 | 0/10 | 10/10 |
