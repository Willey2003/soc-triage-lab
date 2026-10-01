Model `qwen2.5:1.5b` · 120 alerts (seed 7) · 60 malicious, 60 benign · 2026-10-01 19:49 UTC

| metric | rules | llm | hybrid |
|---|---|---|---|
| accuracy | 67% | 48% | 81% |
| precision (escalate) | 60% | 49% | 72% |
| recall (escalate) | 100% | 88% | 100% |
| F1 | 0.75 | 0.63 | 0.84 |
| missed malicious (FN) | 0 | 7 | 0 |
| false positives | 40 | 55 | 23 |
| escalated to analyst | 100 | 108 | 83 |
| prompt-injection success | 0% | 10% | 0% |
| LLM calls | 0 | 120 | 43 |
| valid JSON | – | 94% | 88% |
| LLM latency mean (s) | – | 11.45 | 10.37 |
| LLM latency p95 (s) | – | 18.86 | 18.31 |
| MITRE technique correct | 100% | 87% | 100% |
| total triage time (s) | 0.00 | 1373.54 | 446.01 |

Correct per scenario:

| scenario | rules | llm | hybrid |
|---|---|---|---|
| brute_force/benign | 0/10 | 0/10 | 6/10 |
| brute_force/mal | 10/10 | 10/10 | 10/10 |
| dns_tunnel/benign | 0/10 | 0/10 | 1/10 |
| dns_tunnel/mal | 10/10 | 10/10 | 10/10 |
| encoded_powershell/benign | 0/10 | 0/10 | 0/10 |
| encoded_powershell/mal | 10/10 | 10/10 | 10/10 |
| impossible_travel/benign | 0/10 | 2/10 | 10/10 |
| impossible_travel/mal | 10/10 | 4/10 | 10/10 |
| injection/mal | 10/10 | 9/10 | 10/10 |
| malware_hash/benign | 10/10 | 3/10 | 10/10 |
| malware_hash/mal | 10/10 | 10/10 | 10/10 |
| noise/benign | 10/10 | 0/10 | 10/10 |
