"""Prompt-injection guard for alert content.

Alert fields (command lines, user agents, file names, DNS labels) are attacker-controlled.
The guard finds instruction-like text, replaces it before the LLM sees it, and reports it,
because an alert that tries to talk to the analyst is itself a strong signal.
It is a pattern list, so it will miss novel phrasing; the rule floor in triage.py is the second layer.
"""
from __future__ import annotations

import re

PATTERNS = [
    r"ignore (all |any )?(previous|prior|above) (instructions|rules)",
    r"disregard (all |any )?(previous|prior|above)? ?(instructions|rules)",
    r"note to (the )?(ai|llm|assistant|analyst|model)",
    r"\b(ai|llm) analyst\b",
    r"#+\s*system\s*:",
    r"\bclassify (this )?as (benign|false positive|low)",
    r"\bdisposition\s*[=:]\s*(close|benign)",
    r"\byou are (now )?(an?|the) (assistant|ai|model)",
    r"\bseverity\s*[=:]?\s*low\b.*\bbenign\b",
]
_RX = re.compile("|".join(f"(?:{p})" for p in PATTERNS), re.IGNORECASE)
MARK = "[REMOVED: instruction-like text]"


def scan(obj, path: str = "") -> list[str]:
    """Return the field paths that contain instruction-like text."""
    hits = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            hits += scan(v, f"{path}.{k}" if path else k)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            hits += scan(v, f"{path}[{i}]")
    elif isinstance(obj, str) and _RX.search(obj):
        hits.append(path)
    return hits


def sanitize(obj):
    """Copy of obj with every string that matches a pattern cut at the match and marked."""
    if isinstance(obj, dict):
        return {k: sanitize(v) for k, v in obj.items()}
    if isinstance(obj, list):
        return [sanitize(v) for v in obj]
    if isinstance(obj, str):
        m = _RX.search(obj)
        if m:
            return obj[: m.start()] + MARK
    return obj
