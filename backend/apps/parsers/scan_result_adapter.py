"""
Adapter: converte ScanImportResult (cyberreport_pro_parsers) →
         list[NormalizedVulnerability] (apps.vulnerabilities.deduplication).

Questo modulo è il punto di integrazione tra il layer di parsing avanzato
(cyberreport_pro_parsers) e la pipeline Django (apps/parsers → tasks → DB).

Principio: nessuna logica di business qui — solo mappatura di campi.
Tutta la logica di parsing rimane nel Layer 2.
"""
from __future__ import annotations

from cyberreport_pro_parsers.parsers.canonical_schema import (
    ScanImportResult,
)
from apps.vulnerabilities.deduplication import NormalizedVulnerability as L1Vuln


def adapt_scan_result(result: ScanImportResult) -> list[L1Vuln]:
    """
    Converte ScanImportResult → list[NormalizedVulnerability] Layer 1.

    Mapping fields:
      L2.affected_ip         → L1.affected_ip
      L2.affected_host       → L1.affected_host
      L2.affected_port       → L1.affected_port  (Optional[int] → int|None)
      L2.affected_protocol   → L1.affected_protocol
      L2.affected_service    → L1.affected_service
      L2.title               → L1.title
      L2.description_tool    → L1.description
      L2.remediation_tool    → L1.remediation
      L2.severity_tool       → L1.risk_level  (Severity enum → str lowercase)
      L2.cvss_score_tool     → L1.cvss_score
      L2.cve_ids_tool        → L1.cve_id  (list[str])
      L2.evidence            → L1.evidence_code
      L2.source_tool         → L1.source
      L2.raw_output          → L1.raw_output
      L2.nvd_enrichment_status → L1.nvd_enrichment_status  (.value)
    """
    out: list[L1Vuln] = []

    for v in result.vulnerabilities:
        # Severity enum → str lowercase per risk_level
        risk_level = v.severity_tool.value.lower() if v.severity_tool else "medium"

        # EnrichmentStatus enum → str
        enrichment_status = (
            v.nvd_enrichment_status.value
            if v.nvd_enrichment_status else "pending"
        )

        out.append(L1Vuln(
            title=v.title,
            description=v.description_tool or "",
            remediation=v.remediation_tool or "",
            affected_ip=v.affected_ip or "",
            affected_host=v.affected_host or "",
            affected_port=v.affected_port,           # int|None
            affected_service=v.affected_service or "",
            affected_protocol=v.affected_protocol or "tcp",
            cve_id=list(v.cve_ids_tool or []),       # list[str]
            cvss_score=v.cvss_score_tool,
            cvss_vector="",                          # popolato da NVD enricher
            risk_level=risk_level,
            evidence_code=(v.evidence or "")[:4096],
            source=v.source_tool or "",
            raw_output=(v.raw_output or "")[:2048],
            nvd_enrichment_status=enrichment_status,
        ))

    return out
