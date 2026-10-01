"""Enrichment: threat intel, CMDB (hosts, VPN egress, allowlists), users, MITRE mapping.

Everything is local JSON (data/), so the lab runs with no external lookups.
"""
from __future__ import annotations

import ipaddress
import json
import os
from functools import lru_cache

DATA_DIR = os.environ.get("SOC_DATA_DIR", os.path.join(os.path.dirname(__file__), "..", "data"))

MITRE = {
    "AUTH-001": [("T1110", "Brute Force"), ("T1110.003", "Password Spraying")],
    "AUTH-002": [("T1110", "Brute Force")],
    "IDN-004": [("T1078", "Valid Accounts")],
    "EDR-017": [("T1059.001", "Command and Scripting Interpreter: PowerShell"), ("T1027", "Obfuscated Files or Information")],
    "NET-031": [("T1071.004", "Application Layer Protocol: DNS"), ("T1048", "Exfiltration Over Alternative Protocol")],
    "EDR-002": [("T1204.002", "User Execution: Malicious File"), ("T1105", "Ingress Tool Transfer")],
    "NET-008": [("T1046", "Network Service Discovery")],
}


@lru_cache(maxsize=None)
def load(name: str) -> dict:
    with open(os.path.join(DATA_DIR, f"{name}.json")) as f:
        return json.load(f)


def _get(d: dict, path: str):
    for p in path.split("."):
        if not isinstance(d, dict) or p not in d:
            return None
        d = d[p]
    return d


def is_internal(ip: str | None) -> bool:
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in ipaddress.ip_network(c) for c in load("assets")["corporate_cidrs"])


def enrich(alert: dict) -> dict:
    """Full context. `rules` reads only the keys marked (rules) below; the LLM gets all of it."""
    intel, assets, users = load("intel"), load("assets"), load("users")
    ip = _get(alert, "source.ip")
    host = _get(alert, "host.name")
    user = _get(alert, "user.name")
    sha = _get(alert, "file.hash.sha256")
    domain = _get(alert, "dns.question.registered_domain")
    ctx = {
        # (rules) threat intel and the obvious bits every SIEM has
        "ti_ip_hit": ip in intel["bad_ips"],
        "ti_hash_hit": intel["bad_hashes"].get(sha) if sha else None,
        "ti_domain_hit": domain in intel["bad_domains"] if domain else False,
        "source_internal": is_internal(ip),
        "host_is_scanner": bool(assets["hosts"].get(host, {}).get("scanner")),
        # (LLM only) business context the detection rules do not encode
        "host": {"name": host, **assets["hosts"].get(host, {})} if host else None,
        "user": {"name": user, **users.get(user, {})} if user else None,
        "source_vpn_egress": assets["vpn_egress"].get(ip),
        "domain_allowlisted": domain in assets["dns_allowlist"] if domain else None,
        "hash_internal_signed": assets["signed_internal_hashes"].get(sha) if sha else None,
        "mitre_candidates": [f"{t} {n}" for t, n in MITRE.get(_get(alert, "rule.id") or "", [])],
    }
    return ctx
