"""Three triage modes over the same alert.

rules   classic SIEM: escalate when the risk score >= 50.
llm     the model decides every alert (raw alert text, no rule floor, no injection guard).
hybrid  rules are the floor and the ceiling, the model handles the grey zone:
          injection text found  -> escalate (an alert that addresses the analyst is suspicious by itself)
          score >= 70           -> escalate; the model is never asked, so it cannot downgrade it
          score <  40, no TI hit -> close
          40 <= score < 70      -> model decides, on sanitized alert + full context
          model output invalid  -> escalate (fail safe)
          model says close, but no trusted context fact explains the activity -> escalate (close veto)
"""
from __future__ import annotations

from . import guard, rules
from .enrich import enrich
from .generator import strip_truth
from .models import Decision

HIGH, LOW = 70, 40


def severity_for(score: int) -> str:
    return "low" if score < LOW else "medium" if score < HIGH else "high" if score < 90 else "critical"


def _llm_decision(base: dict, res) -> Decision:
    if res.verdict is None:
        return Decision(**base, disposition="escalate", decided_by="fallback",
                        reasoning="model output was not valid JSON; escalated (fail safe)",
                        llm_latency_s=res.latency_s, llm_valid_json=False)
    v = res.verdict
    return Decision(**{**base, "severity": v.severity}, disposition=v.disposition, decided_by="llm",
                    mitre_technique=None if v.mitre_technique.upper() == "NONE" else v.mitre_technique,
                    reasoning=v.reasoning, next_steps=v.next_steps, llm_latency_s=res.latency_s,
                    llm_valid_json=True, llm_raw_disposition=v.disposition)


def benign_evidence(ctx: dict) -> list[str]:
    """Trusted (CMDB / allowlist) facts that can explain a benign look-alike. The model may close only if one exists."""
    host = ctx.get("host") or {}
    facts = {
        "source is a corporate VPN egress": ctx.get("source_vpn_egress"),
        "domain is allowlisted": ctx.get("domain_allowlisted"),
        "hash is an internally signed tool": ctx.get("hash_internal_signed"),
        "host is an automation/config-management host": host.get("automation"),
        "host is the approved scanner": ctx.get("host_is_scanner"),
        "source is on the corporate network": ctx.get("source_internal"),
    }
    return [k for k, v in facts.items() if v]


def triage(alert: dict, mode: str, llm=None) -> Decision:
    alert = strip_truth(alert)
    ctx = enrich(alert)
    score, why = rules.score(alert, ctx)
    top_mitre = (ctx["mitre_candidates"] or [""])[0].split(" ")[0] or None
    base = {"alert_id": alert.get("id", "?"), "mode": mode, "risk_score": score,
            "severity": severity_for(score), "rule_reasons": why}

    if mode == "rules":
        esc = score >= rules.RULES_ONLY_THRESHOLD
        return Decision(**base, disposition="escalate" if esc else "close", decided_by="rules",
                        mitre_technique=top_mitre if esc else None,
                        reasoning=f"risk score {score} {'>=' if esc else '<'} {rules.RULES_ONLY_THRESHOLD}")

    if mode == "llm":
        return _llm_decision(base, llm.triage(alert, ctx, hardened=False))

    if mode != "hybrid":
        raise ValueError(f"unknown mode {mode}")

    hits = guard.scan(alert)
    if hits:
        score = min(100, score + 30)
        why.append("+30 instruction-like text in alert fields")
        base.update(risk_score=score, severity=severity_for(score), injection_fields=hits)
        return Decision(**base, disposition="escalate", decided_by="injection_guard", mitre_technique=top_mitre,
                        reasoning=f"alert contains text addressed to the analyst/AI in {', '.join(hits)}; escalated without asking the model")
    if score >= HIGH:
        return Decision(**base, disposition="escalate", decided_by="rule_floor", mitre_technique=top_mitre,
                        reasoning=f"risk score {score} >= {HIGH}: escalated by rule, model not consulted")
    ti = ctx["ti_ip_hit"] or ctx["ti_hash_hit"] or ctx["ti_domain_hit"]
    if score < LOW and not ti:
        return Decision(**base, disposition="close", decided_by="rules",
                        reasoning=f"risk score {score} < {LOW} and no threat-intel hit")
    d = _llm_decision(base, llm.triage(guard.sanitize(alert), ctx, hardened=True))
    if d.disposition == "close" and not benign_evidence(ctx):
        return d.model_copy(update={
            "disposition": "escalate", "decided_by": "close_veto", "severity": severity_for(score),
            "reasoning": "model proposed close, but no trusted context fact (VPN egress, allowlist, automation host, "
                         "signed internal tool, scanner, corporate source) explains the activity. Model said: " + d.reasoning})
    return d
