"""Deterministic risk score, the way a typical SIEM correlation rule would compute it.

It sees threat intel, whether the source is internal, and whether the host is a known scanner.
It does NOT know about VPN egress points, automation hosts, DNS allowlists or internally signed tools;
that is exactly the context gap that produces the false positives the LLM is meant to remove.
"""
from __future__ import annotations

OFFICE_PARENTS = {"winword.exe", "excel.exe", "outlook.exe", "powerpnt.exe"}
RULES_ONLY_THRESHOLD = 50


def score(alert: dict, ctx: dict) -> tuple[int, list[str]]:
    rid = alert.get("rule", {}).get("id", "")
    s, why = 0, []

    def add(points: int, reason: str):
        nonlocal s
        s += points
        why.append(f"{points:+d} {reason}")

    if ctx.get("ti_ip_hit"):
        add(25, "source IP on threat-intel list")
    if ctx.get("ti_hash_hit"):
        add(50, f"hash on threat-intel list ({ctx['ti_hash_hit']})")
    if ctx.get("ti_domain_hit"):
        add(30, "domain on threat-intel list")

    if rid == "AUTH-001":
        a = alert.get("auth", {})
        add(45, "excessive failed logons")
        if a.get("failed_count", 0) >= 30:
            add(15, f"{a['failed_count']} failures in {a.get('window_min')} min")
        if a.get("followed_by_success"):
            add(15, "followed by a successful logon")
        if not ctx.get("source_internal"):
            add(10, "external source")
    elif rid == "AUTH-002":
        add(15, "single failed logon")
    elif rid == "IDN-004":
        t = alert.get("travel", {})
        add(55, "impossible travel")
        if t.get("new_device"):
            add(10, "new device")
        if t.get("mfa") == "none":
            add(10, "no MFA")
    elif rid == "EDR-017":
        add(50, "encoded PowerShell")
        parent = alert.get("process", {}).get("parent", {}).get("name", "").lower()
        if parent in OFFICE_PARENTS:
            add(25, f"spawned by Office ({parent})")
        if "-windowstyle hidden" in alert.get("process", {}).get("command_line", "").lower():
            add(5, "hidden window")
    elif rid == "NET-031":
        d = alert.get("dns", {})
        add(40, "DNS tunnelling heuristic")
        if d.get("query_count_1h", 0) > 1000:
            add(10, "high query volume")
        if d.get("avg_query_len", 0) > 50:
            add(10, "long queries")
        if d.get("label_entropy", 0) > 4.2:
            add(10, "high label entropy")
    elif rid == "EDR-002":
        f = alert.get("file", {})
        add(35, "unknown executable")
        if not f.get("signed"):
            add(10, "unsigned")
        if f.get("prevalence_in_org", 99) <= 2:
            add(10, "seen on <=2 hosts")
    elif rid == "NET-008":
        add(40, "horizontal port scan")
    else:
        add(40, "unknown rule (default)")

    if ctx.get("host_is_scanner"):
        add(-35, "source is the approved vulnerability scanner")
    return max(0, min(100, s)), why
