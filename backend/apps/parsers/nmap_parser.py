"""
Nmap XML parser.
Parses output from: nmap -oX output.xml
Extracts hosts, open ports, services, and NSE script output as findings.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from typing import IO

from apps.vulnerabilities.deduplication import NormalizedVulnerability

from .base import BaseParser, ParserError


class NmapParser(BaseParser):
    """
    Parser for Nmap XML output (-oX flag).
    Each open port with a service becomes a finding.
    NSE script output (e.g. vuln scripts) becomes additional findings.
    """

    tool_name = "nmap"

    # Risk levels by port/service heuristics
    HIGH_RISK_PORTS = {21, 23, 445, 3389, 5900}
    MEDIUM_RISK_PORTS = {22, 25, 80, 110, 143, 3306, 5432, 6379, 27017}

    def parse(self, file_obj: IO[bytes]) -> list[NormalizedVulnerability]:
        try:
            tree = ET.parse(file_obj)
        except ET.ParseError as exc:
            raise ParserError(f"Invalid Nmap XML: {exc}") from exc

        root = tree.getroot()
        if root.tag != "nmaprun":
            raise ParserError("Not a valid Nmap XML file (root tag must be 'nmaprun').")

        results: list[NormalizedVulnerability] = []

        for host in root.findall("host"):
            if host.find("status") is None or host.find("status").get("state") != "up":
                continue

            host_addr = self._get_host_address(host)

            for port_elem in host.findall(".//port"):
                state = port_elem.find("state")
                if state is None or state.get("state") != "open":
                    continue

                port_id = port_elem.get("portid", "")
                protocol = port_elem.get("protocol", "tcp")
                service_elem = port_elem.find("service")
                service_name = service_elem.get("name", "unknown") if service_elem is not None else "unknown"
                product = service_elem.get("product", "") if service_elem is not None else ""
                version = service_elem.get("version", "") if service_elem is not None else ""
                service_desc = f"{service_name} {product} {version}".strip()

                risk_level = self._assess_port_risk(int(port_id) if port_id.isdigit() else 0)

                results.append(NormalizedVulnerability(
                    title=f"Open {protocol.upper()} Port {port_id} ({service_name})",
                    description=(
                        f"Host {host_addr} has port {port_id}/{protocol} open "
                        f"running {service_desc or service_name}."
                    ),
                    affected_host=host_addr,
                    affected_port=port_id,
                    affected_service=service_desc or service_name,
                    risk_level=risk_level,
                    source=self.tool_name,
                    raw_output=ET.tostring(port_elem, encoding="unicode"),
                ))

                # Parse NSE script output
                for script in port_elem.findall("script"):
                    script_vuln = self._parse_script(script, host_addr, port_id, service_name)
                    if script_vuln:
                        results.append(script_vuln)

            # Host-level scripts
            for script in host.findall(".//hostscript/script"):
                script_vuln = self._parse_script(script, host_addr, "", "")
                if script_vuln:
                    results.append(script_vuln)

        return results

    def _get_host_address(self, host: ET.Element) -> str:
        """Extract the primary address (IPv4 preferred, then IPv6, then hostname)."""
        for addr in host.findall("address"):
            if addr.get("addrtype") == "ipv4":
                return addr.get("addr", "")
        for addr in host.findall("address"):
            if addr.get("addrtype") == "ipv6":
                return addr.get("addr", "")
        hostname_el = host.find(".//hostname")
        if hostname_el is not None:
            return hostname_el.get("name", "unknown")
        return "unknown"

    def _assess_port_risk(self, port: int) -> str:
        if port in self.HIGH_RISK_PORTS:
            return "high"
        if port in self.MEDIUM_RISK_PORTS:
            return "medium"
        return "low"

    def _parse_script(
        self, script: ET.Element, host: str, port: str, service: str
    ) -> NormalizedVulnerability | None:
        """Parse an NSE script element into a vulnerability if it contains findings."""
        script_id = script.get("id", "")
        output = script.get("output", "")

        # Only include vuln-related scripts
        if not any(kw in script_id.lower() for kw in ("vuln", "exploit", "cve", "auth", "brute")):
            return None
        if not output.strip():
            return None

        # Try to extract CVE from output
        cve_id = ""
        import re
        cve_match = re.search(r"CVE-\d{4}-\d+", output)
        if cve_match:
            cve_id = cve_match.group(0)

        risk = "medium"
        if "VULNERABLE" in output.upper():
            risk = "high"
        elif "critical" in output.lower():
            risk = "critical"

        return NormalizedVulnerability(
            title=f"NSE: {script_id}",
            description=f"Nmap NSE script '{script_id}' found a potential issue on {host}:{port}.",
            affected_host=host,
            affected_port=port,
            affected_service=service,
            cve_id=cve_id,
            risk_level=risk,
            evidence_code=output[:4096],
            source=self.tool_name,
            raw_output=ET.tostring(script, encoding="unicode"),
        )
