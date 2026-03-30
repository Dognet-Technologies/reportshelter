"""
Wapiti XML parser.

Wapiti -f xml -o report.xml produces:
  <report>
    <report_infos>
      <info name="target">URL</info>
    </report_infos>
    <vulnerabilities>
      <vulnerability name="Vuln Category">
        <description>...</description>
        <solution>...</solution>
        <references>
          <reference><title>..</title><url>..</url></reference>
        </references>
        <entries>
          <entry>
            <method>GET</method>
            <path>/path</path>
            <info>CSP is not set</info>
            <http_request>GET / HTTP/1.1...</http_request>
            <curl_command>curl ...</curl_command>
            <level>1</level>
            <parameter/>
          </entry>
        </entries>
      </vulnerability>
    </vulnerabilities>
    <anomalies>...</anomalies>
  </report>

Level mapping: 1=info, 2=low, 3=medium, 4=high, 5=critical.
"""

from __future__ import annotations

import logging
import xml.etree.ElementTree as ET
from typing import IO
from urllib.parse import urlparse

from apps.vulnerabilities.deduplication import NormalizedVulnerability

from .base import BaseParser, ParserError

logger = logging.getLogger(__name__)


def _level_to_risk(level: str | None) -> str:
    mapping = {"1": "info", "2": "low", "3": "medium", "4": "high", "5": "critical"}
    return mapping.get(str(level or "").strip(), "medium")


def _get_target(root: ET.Element) -> str:
    for info in root.iter("info"):
        if info.get("name") == "target":
            return (info.text or "").strip()
    return ""


class WapitiParser(BaseParser):
    """Parser for Wapiti XML reports."""

    tool_name = "wapiti"

    def parse(self, file_obj: IO[bytes]) -> list[NormalizedVulnerability]:
        try:
            root = ET.fromstring(file_obj.read())
        except ET.ParseError as exc:
            raise ParserError(f"Invalid Wapiti XML: {exc}") from exc

        target_url = _get_target(root)
        parsed = urlparse(target_url)
        host = parsed.hostname or target_url
        port: int | None = parsed.port
        if port is None and parsed.scheme:
            port = 443 if parsed.scheme == "https" else 80

        results: list[NormalizedVulnerability] = []

        for section in ("vulnerabilities", "anomalies"):
            section_el = root.find(section)
            if section_el is None:
                continue

            for vuln_el in section_el:
                vuln_name = vuln_el.get("name") or vuln_el.tag or "Wapiti Finding"
                description = (vuln_el.findtext("description") or "").strip()
                solution = (vuln_el.findtext("solution") or "").strip()

                # References
                ref_parts: list[str] = []
                for ref in vuln_el.iter("reference"):
                    ref_title = (ref.findtext("title") or "").strip()
                    ref_url = (ref.findtext("url") or "").strip()
                    if ref_url:
                        ref_parts.append(f"{ref_title}: {ref_url}" if ref_title else ref_url)

                entries = vuln_el.find("entries")
                if entries is None or len(entries) == 0:
                    # Vuln defined but no actual instances found
                    continue

                for entry in entries:
                    method = (entry.findtext("method") or "GET").strip()
                    path = (entry.findtext("path") or "/").strip()
                    info = (entry.findtext("info") or "").strip()
                    level = (entry.findtext("level") or "").strip()
                    parameter = (entry.findtext("parameter") or "").strip()
                    http_req = (entry.findtext("http_request") or "").strip()[:1000]

                    title = f"{vuln_name}: {method} {path}"
                    if info:
                        title += f" — {info[:60]}"

                    entry_desc = description
                    if info:
                        entry_desc += f"\n\nDetail: {info}"
                    if parameter:
                        entry_desc += f"\nParameter: {parameter}"

                    evidence = f"Method: {method}\nPath: {path}"
                    if info:
                        evidence += f"\nInfo: {info}"
                    if http_req:
                        evidence += f"\n\nRequest:\n{http_req}"
                    if ref_parts:
                        evidence += f"\n\nReferences:\n" + "\n".join(ref_parts[:3])

                    results.append(NormalizedVulnerability(
                        title=title,
                        description=entry_desc,
                        remediation=solution,
                        affected_host=host,
                        affected_port=port,
                        risk_level=_level_to_risk(level),
                        evidence_code=evidence[:4096],
                        source="wapiti",
                        raw_output=ET.tostring(entry, encoding="unicode")[:2048],
                    ))

        return results
