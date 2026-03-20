"""
Adapter functions to convert new-style parser output (from cyberreport_pro_parsers)
to the OldNormalizedVulnerability expected by deduplicate_and_save().
"""

from __future__ import annotations

from apps.vulnerabilities.deduplication import NormalizedVulnerability as OldNormVuln


def adapt_canonical_vuln(v) -> OldNormVuln:
    """
    Convert a canonical_schema.NormalizedVulnerability (used by BurpParser, OpenVasParser)
    to the legacy NormalizedVulnerability used by deduplicate_and_save().
    """
    # Prefer hostname over IP for affected_host; fall back to IP
    host = v.affected_host or v.affected_ip or ""

    # Severity enum → risk_level string
    sev = v.severity_tool
    risk_level = sev.value.lower() if sev else "info"

    # Port: int → str
    port_str = str(v.affected_port) if v.affected_port else ""

    # CVE list → single string (comma-separated)
    cve_ids = getattr(v, "cve_ids_tool", []) or []
    cve_id = ", ".join(cve_ids) if cve_ids else ""

    return OldNormVuln(
        title=v.title or "",
        description=v.description_tool or "",
        remediation=getattr(v, "remediation_tool", "") or "",
        affected_host=host,
        affected_port=port_str,
        affected_service=v.affected_service or "",
        cve_id=cve_id,
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
    to the legacy NormalizedVulnerability used by deduplicate_and_save().
    """
    # Prefer hostname over IP
    host = v.affected_host or v.affected_ip or ""

    # Severity enum → risk_level string
    severity = getattr(v, "severity", None)
    risk_level = severity.value.lower() if severity else "info"

    # Port: int|None → str
    port_str = str(v.affected_port) if v.affected_port else ""

    # CVE list → single string
    cve_ids = getattr(v, "cve_ids", []) or []
    cve_id = ", ".join(cve_ids) if cve_ids else ""

    description = getattr(v, "description", "") or ""

    return OldNormVuln(
        title=v.title or "",
        description=description,
        remediation="",
        affected_host=host,
        affected_port=port_str,
        affected_service=v.affected_service or "",
        cve_id=cve_id,
        cvss_score=getattr(v, "cvss_score", None),
        cvss_vector="",
        risk_level=risk_level,
        evidence_code=getattr(v, "evidence", "") or "",
        source=getattr(v, "source_tool", "nmap") or "nmap",
        raw_output=v.raw_output or "",
    )
