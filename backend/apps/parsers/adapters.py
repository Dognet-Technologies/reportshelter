"""
Adapter functions to convert new-style parser output (from cyberreport_pro_parsers)
to the OldNormalizedVulnerability expected by deduplicate_and_save().
"""

from __future__ import annotations

from apps.vulnerabilities.deduplication import NormalizedVulnerability as OldNormVuln


def adapt_canonical_vuln(v) -> OldNormVuln:
    """
    Convert a canonical_schema.NormalizedVulnerability (used by BurpParser, OpenVasParser)
    to the NormalizedVulnerability used by deduplicate_and_save().
    """
    # Prefer hostname over IP for affected_host; fall back to IP
    host = v.affected_host or v.affected_ip or ""

    # Severity enum → risk_level string
    sev = v.severity_tool
    risk_level = sev.value.lower() if sev else "info"

    # CVE list → list[str]
    cve_ids = list(getattr(v, "cve_ids_tool", []) or [])

    return OldNormVuln(
        title=v.title or "",
        description=v.description_tool or "",
        remediation=getattr(v, "remediation_tool", "") or "",
        affected_ip=v.affected_ip or "",
        affected_host=host,
        affected_port=v.affected_port,              # int|None
        affected_service=v.affected_service or "",
        cve_id=cve_ids,                             # list[str]
        cvss_score=getattr(v, "cvss_score_tool", None),
        cvss_vector="",
        risk_level=risk_level,
        evidence_code=v.evidence or "",
        source=v.source_tool or "",
        raw_output=v.raw_output or "",
    )


def adapt_nmap_vuln(v) -> OldNormVuln:
    """
    Convert nmap_parser.NormalizedVulnerability (self-contained dataclass)
    to the NormalizedVulnerability used by deduplicate_and_save().
    """
    # Prefer hostname over IP
    host = v.affected_host or v.affected_ip or ""

    # Severity enum → risk_level string
    severity = getattr(v, "severity", None)
    risk_level = severity.value.lower() if severity else "info"

    # CVE list → list[str]
    cve_ids = list(getattr(v, "cve_ids", []) or [])

    description = getattr(v, "description", "") or ""

    return OldNormVuln(
        title=v.title or "",
        description=description,
        remediation="",
        affected_ip=getattr(v, "affected_ip", "") or "",
        affected_host=host,
        affected_port=v.affected_port,              # int|None
        affected_service=v.affected_service or "",
        cve_id=cve_ids,                             # list[str]
        cvss_score=getattr(v, "cvss_score", None),
        cvss_vector="",
        risk_level=risk_level,
        evidence_code=getattr(v, "evidence", "") or "",
        source=getattr(v, "source_tool", "nmap") or "nmap",
        raw_output=v.raw_output or "",
    )
