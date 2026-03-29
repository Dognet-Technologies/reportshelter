"""
Nmap XML parser — wraps the advanced parser from cyberreport_pro_parsers.

Produces two types of findings:
  1. NSE script vulnerabilities (from vulners, exploit, http-vuln-*, etc.)
  2. Open Port findings — one per open service, even without NSE scripts.
     These are useful in most real-world scans that don't use --script vuln.

Returns a list of OldNormalizedVulnerability compatible with deduplicate_and_save().
"""

from __future__ import annotations

import logging
from typing import IO

from .adapters import adapt_nmap_vuln
from .base import BaseParser, ParserError
from apps.vulnerabilities.deduplication import NormalizedVulnerability

logger = logging.getLogger(__name__)


# Ports/services with elevated risk for open port findings
_HIGH_RISK_PORTS = {
    21, 23, 25, 69, 111, 135, 137, 138, 139, 445, 512, 513, 514,
    1099, 1524, 2049, 2121, 3306, 3389, 5432, 5900, 5984,
    6379, 27017, 27018, 27019,
}
_MEDIUM_RISK_PORTS = {
    22, 53, 79, 81, 82, 443, 8080, 8443, 8888, 10000,
    1433, 1521, 5000, 5601, 9200, 9300,
}


def _port_risk(port: int) -> str:
    if port in _HIGH_RISK_PORTS:
        return "high"
    if port in _MEDIUM_RISK_PORTS:
        return "medium"
    return "info"


def _open_port_findings(hosts) -> list[NormalizedVulnerability]:
    """Generate one NormalizedVulnerability per open port per host."""
    findings: list[NormalizedVulnerability] = []

    for host in hosts:
        if host.state != "up":
            continue

        ip = host.ip_address or ""
        hostname = host.hostname or ""
        display_host = hostname or ip

        for svc in host.services:
            # Only report open ports
            if svc.state.value != "open":
                continue

            port = svc.port
            protocol = svc.protocol.value if hasattr(svc.protocol, "value") else str(svc.protocol)
            service_name = svc.service_name or "unknown"

            # Build banner: product + version + extra_info
            banner_parts = [p for p in [svc.product, svc.version, svc.extra_info] if p]
            banner = " ".join(banner_parts)

            title = f"Open Port {port}/{protocol.upper()} ({service_name})"
            if banner:
                title += f" — {banner[:80]}"

            desc_parts = [
                f"Host: {display_host}",
                f"Port: {port}/{protocol}",
                f"State: {svc.state.value}",
                f"Service: {service_name}",
            ]
            if banner:
                desc_parts.append(f"Banner: {banner}")
            if svc.cpes:
                desc_parts.append(f"CPE: {', '.join(svc.cpes)}")
            if svc.state_reason:
                desc_parts.append(f"Reason: {svc.state_reason}")

            # Collect all script outputs as evidence
            script_evidence_parts = []
            for script in svc.scripts:
                if script.output:
                    script_evidence_parts.append(
                        f"[{script.script_id}]\n{script.output[:1000]}"
                    )
            evidence = "\n\n".join(desc_parts)
            if script_evidence_parts:
                evidence += "\n\n--- Script Output ---\n" + "\n\n".join(script_evidence_parts)

            findings.append(NormalizedVulnerability(
                title=title,
                description=(
                    f"Open port {port}/{protocol} detected on {display_host}. "
                    f"Service: {service_name}"
                    + (f" ({banner})" if banner else "")
                    + "."
                ),
                affected_host=display_host,
                affected_port=port,              # int
                affected_service=service_name,
                risk_level=_port_risk(port),
                evidence_code=evidence[:8192],
                source="nmap",
                raw_output=evidence[:2048],
            ))

    return findings


class NmapParser(BaseParser):
    """
    Adapter wrapping the advanced NmapParser from cyberreport_pro_parsers.

    Extracts:
    - NSE-script-based vulnerabilities (vulners, exploit, http-vuln-*, etc.)
    - Open Port findings for every open service found in the scan.
    """

    tool_name = "nmap"

    def parse(self, file_obj: IO[bytes]) -> list[NormalizedVulnerability]:
        from cyberreport_pro_parsers.parsers.nmap_parser import NmapParser as NewNmapParser
        import xml.etree.ElementTree as ET

        data = file_obj.read()

        # Validate XML and root tag before delegating to Layer 2
        try:
            root = ET.fromstring(data)
        except ET.ParseError as exc:
            raise ParserError(f"Invalid Nmap XML: {exc}") from exc
        if root.tag != "nmaprun":
            raise ParserError(f"Not a valid Nmap XML export (expected root tag 'nmaprun', got '{root.tag}').")

        try:
            parser = NewNmapParser(data)
            parser.parse()
        except ValueError as exc:
            raise ParserError(str(exc)) from exc

        if parser.errors:
            logger.warning("[nmap] Parse warnings: %s", "; ".join(parser.errors))

        # NSE script vulnerabilities
        vuln_findings = [adapt_nmap_vuln(v) for v in parser.vulnerabilities]

        # Open port findings (always generated)
        port_findings = _open_port_findings(parser.hosts)

        logger.info(
            "[nmap] Found %d NSE vulns + %d open ports across %d hosts.",
            len(vuln_findings),
            len(port_findings),
            len(parser.hosts),
        )

        return vuln_findings + port_findings
