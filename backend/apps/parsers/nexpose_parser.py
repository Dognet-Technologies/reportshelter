"""
Nexpose / InsightVM XML parser.

Nexpose XML report (version 1.0):
  <NexposeReport>
    <scans>
      <scan id="..." name="..." />
    </scans>
    <nodes>
      <node address="192.168.1.1" status="alive">
        <fingerprints>
          <os vendor="..." product="..." version="..." />
        </fingerprints>
        <tests>
          <test id="vuln-check-id" status="vulnerable-exploited|vulnerable-potential">
            <Paragraph>...</Paragraph>
          </test>
        </tests>
        <endpoints>
          <endpoint protocol="tcp" port="22" status="open">
            <services>
              <service name="SSH">
                <tests>
                  <test id="..." status="vulnerable-exploited">...</test>
                </tests>
              </service>
            </services>
          </endpoint>
        </endpoints>
      </node>
    </nodes>
    <VulnerabilityDefinitions>
      <vulnerability id="..." title="..." severity="1-10" cvssScore="..." cvssVector="...">
        <description><Paragraph>...</Paragraph></description>
        <solution><Paragraph>...</Paragraph></solution>
        <references><reference source="..." symbol="..."/></references>
      </vulnerability>
    </VulnerabilityDefinitions>
  </NexposeReport>
"""

from __future__ import annotations

import logging
import xml.etree.ElementTree as ET
from typing import IO

from apps.vulnerabilities.deduplication import NormalizedVulnerability

from .base import BaseParser, ParserError

logger = logging.getLogger(__name__)

_VULN_STATUSES = {"vulnerable-exploited", "vulnerable-potential", "vulnerable-version"}


def _severity_from_score(score: float | None) -> str:
    if score is None:
        return "medium"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


def _paragraphs_text(el: ET.Element | None) -> str:
    if el is None:
        return ""
    return " ".join(
        (p.text or "") for p in el.iter("Paragraph")
    ).strip()


class NexposeParser(BaseParser):
    """Parser for Nexpose / InsightVM XML reports."""

    tool_name = "nexpose"

    def parse(self, file_obj: IO[bytes]) -> list[NormalizedVulnerability]:
        try:
            root = ET.fromstring(file_obj.read())
        except ET.ParseError as exc:
            raise ParserError(f"Invalid Nexpose XML: {exc}") from exc

        if root.tag not in ("NexposeReport", "nexpose-report"):
            raise ParserError(f"Not a valid Nexpose XML (root tag: {root.tag}).")

        # Build vulnerability definition lookup
        vuln_defs: dict[str, dict] = {}
        for v in root.iter("vulnerability"):
            vid = v.get("id") or ""
            if not vid:
                continue
            cvss_raw = v.get("cvssScore") or v.get("cvss-score") or ""
            cvss_score: float | None = None
            try:
                cvss_score = float(cvss_raw) if cvss_raw else None
            except ValueError:
                pass
            cvss_vector = v.get("cvssVector") or v.get("cvss-vector") or ""
            severity_int = v.get("severity")
            try:
                severity_int = int(severity_int or 0)
            except ValueError:
                severity_int = 0

            desc_text = _paragraphs_text(v.find("description"))
            sol_text = _paragraphs_text(v.find("solution"))

            cve_list: list[str] = []
            for ref in v.iter("reference"):
                src = (ref.get("source") or "").upper()
                sym = ref.get("symbol") or ""
                if src == "CVE" and sym:
                    cve_list.append(sym if sym.startswith("CVE-") else f"CVE-{sym}")

            vuln_defs[vid] = {
                "title": v.get("title") or vid,
                "cvss_score": cvss_score,
                "cvss_vector": cvss_vector,
                "severity": severity_int,
                "description": desc_text,
                "solution": sol_text,
                "cve_list": cve_list,
            }

        results: list[NormalizedVulnerability] = []

        for node in root.iter("node"):
            address = node.get("address") or ""
            status = (node.get("status") or "").lower()
            if status not in ("alive", "dead", ""):
                continue

            os_vendor = ""
            for fp in node.iter("os"):
                os_vendor = fp.get("product") or fp.get("vendor") or ""
                break

            def _add_test_findings(test_el: ET.Element, port: int | None, service: str) -> None:
                tid = test_el.get("id") or ""
                tstatus = (test_el.get("status") or "").lower()
                if tstatus not in _VULN_STATUSES:
                    return

                test_text = _paragraphs_text(test_el)
                defn = vuln_defs.get(tid, {})

                cvss_score = defn.get("cvss_score")
                severity = _severity_from_score(cvss_score)

                results.append(NormalizedVulnerability(
                    title=defn.get("title") or tid,
                    description=defn.get("description") or test_text or f"Nexpose check: {tid}",
                    remediation=defn.get("solution") or "",
                    affected_host=address,
                    affected_ip=address,
                    affected_port=port,
                    affected_service=service,
                    cve_id=defn.get("cve_list") or [],
                    cvss_score=cvss_score,
                    cvss_vector=defn.get("cvss_vector") or "",
                    risk_level=severity,
                    evidence_code=f"Node: {address}\nCheck: {tid}\nStatus: {tstatus}\n{test_text[:1000]}",
                    source="nexpose",
                    raw_output=ET.tostring(test_el, encoding="unicode")[:2048],
                ))

            # Node-level tests (no port context)
            for test_el in (node.find("tests") or []):
                _add_test_findings(test_el, None, "")

            # Endpoint/service-level tests
            for endpoint in node.iter("endpoint"):
                ep_port_str = endpoint.get("port") or ""
                ep_port: int | None = None
                try:
                    ep_port = int(ep_port_str) if ep_port_str else None
                except ValueError:
                    pass
                ep_proto = endpoint.get("protocol") or "tcp"

                for service_el in endpoint.iter("service"):
                    svc_name = service_el.get("name") or ep_proto
                    for test_el in (service_el.find("tests") or []):
                        _add_test_findings(test_el, ep_port, svc_name)

        return results
