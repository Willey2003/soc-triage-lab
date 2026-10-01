from __future__ import annotations

from typing import List, Literal, Optional

import re

from pydantic import BaseModel, Field, field_validator

Disposition = Literal["escalate", "close"]
Severity = Literal["low", "medium", "high", "critical"]


class LLMVerdict(BaseModel):
    """What the model must return (also sent to Ollama as the JSON schema)."""
    disposition: Disposition
    severity: Severity
    confidence: float = Field(description="0.0 to 1.0")
    mitre_technique: str = Field(description="ATT&CK technique id such as T1059.001, or NONE")
    reasoning: str
    next_steps: List[str] = Field(default_factory=list)

    # Ollama's grammar enforces types and enums but not numeric bounds or lengths, so small models
    # return confidence 2 or 85 and "T1078 Valid Accounts". Repair the descriptive fields;
    # the decision fields (disposition, severity) stay strict and anything else fails safe.
    @field_validator("confidence")
    @classmethod
    def _conf(cls, v: float) -> float:
        if v > 1:
            v = v / 100 if v <= 100 else 1.0
        return max(0.0, v)

    @field_validator("mitre_technique")
    @classmethod
    def _mitre(cls, v: str) -> str:
        m = re.search(r"T\d{4}(?:\.\d{3})?", v.upper())
        return m.group(0) if m else "NONE"

    @field_validator("reasoning")
    @classmethod
    def _reason(cls, v: str) -> str:
        return v[:600]

    @field_validator("next_steps")
    @classmethod
    def _steps(cls, v: List[str]) -> List[str]:
        return v[:5]


class Decision(BaseModel):
    """Final triage outcome stored on the case."""
    alert_id: str
    mode: Literal["rules", "llm", "hybrid"]
    disposition: Disposition
    severity: Severity
    risk_score: int
    decided_by: Literal["rules", "llm", "rule_floor", "injection_guard", "fallback", "close_veto"]
    mitre_technique: Optional[str] = None
    reasoning: str = ""
    next_steps: List[str] = Field(default_factory=list)
    rule_reasons: List[str] = Field(default_factory=list)
    injection_fields: List[str] = Field(default_factory=list)
    llm_latency_s: Optional[float] = None
    llm_valid_json: Optional[bool] = None
    llm_raw_disposition: Optional[str] = None
