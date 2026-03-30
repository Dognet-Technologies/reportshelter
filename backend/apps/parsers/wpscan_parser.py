"""
WPScan JSON parser.

WPScan --format json produces:
  target_url              — scanned WordPress URL
  version.vulnerabilities[] — WordPress core vulnerabilities
  plugins[plugin_slug].vulnerabilities[] — plugin vulnerabilities
  themes[theme_slug].vulnerabilities[]   — theme vulnerabilities
  interesting_findings[]  — interesting headers, config exposure, etc.

Each vulnerability entry:
  title           — vuln title
  fixed_in        — fixed version (if known)
  references.cve[]  — CVE IDs
  references.url[]  — reference URLs
  cvss.score / .vector  — optional CVSS info
"""

from __future__ import annotations

import json
import logging
from typing import IO
from urllib.parse import urlparse

from apps.vulnerabilities.deduplication import NormalizedVulnerability

from .base import BaseParser, ParserError

logger = logging.getLogger(__name__)


def _extract_vulns(
    vulns: list,
    host: str,
    port: int | None,
    context: str,
    source_raw: str,
) -> list[NormalizedVulnerability]:
    """Convert a list of WPScan vulnerability dicts to NormalizedVulnerability."""
    results: list[NormalizedVulnerability] = []
    for v in vulns:
        if not isinstance(v, dict):
            continue

        title = v.get("title") or "WordPress Vulnerability"
        full_title = f"[WP/{context}] {title}"
        fixed_in = v.get("fixed_in") or ""

        refs = v.get("references") or {}
        cve_list = refs.get("cve") or refs.get("CVE") or []
        ref_urls = refs.get("url") or refs.get("URL") or []

        cvss_block = v.get("cvss") or {}
        cvss_score_raw = cvss_block.get("score")
        cvss_score: float | None = None
        try:
            cvss_score = float(cvss_score_raw) if cvss_score_raw else None
        except (TypeError, ValueError):
            pass
        cvss_vector = cvss_block.get("vector") or ""

        # Severity heuristic based on CVSS or presence of CVE
        if cvss_score is not None:
            if cvss_score >= 9.0:
                risk = "critical"
            elif cvss_score >= 7.0:
                risk = "high"
            elif cvss_score >= 4.0:
                risk = "medium"
            else:
                risk = "low"
        else:
            risk = "medium" if cve_list else "low"

        remediation = f"Update {context} to version {fixed_in} or later." if fixed_in else ""

        description = f"Component: {context}\nTitle: {title}"
        if ref_urls:
            description += f"\nReferences:\n" + "\n".join(ref_urls[:3])

        results.append(NormalizedVulnerability(
            title=full_title,
            description=description,
            remediation=remediation,
            affected_host=host,
            affected_port=port,
            cve_id=[f"CVE-{c}" if not c.startswith("CVE-") else c for c in cve_list],
            cvss_score=cvss_score,
            cvss_vector=cvss_vector,
            risk_level=risk,
            category="CWE-1035",  # Vulnerable Dependency
            evidence_code=description[:4096],
            source="wpscan",
            raw_output=json.dumps(v, default=str)[:2048],
        ))
    return results


class WPScanParser(BaseParser):
    """Parser for WPScan JSON reports."""

    tool_name = "wpscan"

    def parse(self, file_obj: IO[bytes]) -> list[NormalizedVulnerability]:
        try:
            data = json.loads(file_obj.read().decode("utf-8", errors="replace"))
        except json.JSONDecodeError as exc:
            raise ParserError(f"Invalid WPScan JSON: {exc}") from exc

        if not isinstance(data, dict):
            raise ParserError("WPScan JSON root must be an object.")

        target_url = data.get("target_url") or data.get("effective_url") or ""
        parsed = urlparse(target_url)
        host = parsed.hostname or target_url
        port: int | None = parsed.port
        if port is None and parsed.scheme:
            port = 443 if parsed.scheme == "https" else 80

        results: list[NormalizedVulnerability] = []

        # Core WordPress vulnerabilities
        version_block = data.get("version") or {}
        core_vulns = version_block.get("vulnerabilities") or []
        wp_version = version_block.get("number") or "unknown"
        results.extend(_extract_vulns(
            core_vulns, host, port, f"WordPress core {wp_version}", "core"
        ))

        # Plugin vulnerabilities
        plugins = data.get("plugins") or {}
        for slug, plugin_data in plugins.items():
            if not isinstance(plugin_data, dict):
                continue
            plugin_vulns = plugin_data.get("vulnerabilities") or []
            plugin_version = (plugin_data.get("version") or {}).get("number") or ""
            context = f"plugin/{slug} {plugin_version}".strip()
            results.extend(_extract_vulns(plugin_vulns, host, port, context, slug))

        # Theme vulnerabilities
        themes = data.get("themes") or {}
        for slug, theme_data in themes.items():
            if not isinstance(theme_data, dict):
                continue
            theme_vulns = theme_data.get("vulnerabilities") or []
            context = f"theme/{slug}"
            results.extend(_extract_vulns(theme_vulns, host, port, context, slug))

        return results
