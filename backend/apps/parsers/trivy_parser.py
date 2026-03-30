"""
Trivy JSON parser (Schema v1 and v2).

Trivy writes a JSON report with:
  ArtifactName  — image / repo name
  Results[]     — per-target results
    Target          — e.g. "ubuntu:latest (ubuntu 20.04)"
    Class           — "os-pkgs" | "lang-pkgs" | "config" | "secret"
    Vulnerabilities[] — CVE records
      VulnerabilityID  — CVE ID
      PkgName          — package name
      InstalledVersion
      FixedVersion
      Title
      Description
      Severity         — CRITICAL | HIGH | MEDIUM | LOW | UNKNOWN
      CweIDs[]
      CVSS.nvd.V3Score / V3Vector
      CVSS.nvd.V2Score / V2Vector
      PrimaryURL
    Misconfigurations[] — IaC issues
      ID / Title / Description / Severity / Resolution
    Secrets[]          — detected secrets
      RuleID / Title / Severity / Match
"""

from __future__ import annotations

import json
import logging
from typing import IO

from apps.vulnerabilities.deduplication import NormalizedVulnerability

from .base import BaseParser, ParserError

logger = logging.getLogger(__name__)

_SEV_MAP = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "unknown": "info",
    "negligible": "info",
}


def _sev(raw: str) -> str:
    return _SEV_MAP.get((raw or "").lower(), "info")


def _best_cvss(cvss_block: dict) -> tuple[float | None, str]:
    """Return (score, vector) picking the best available source."""
    for source in ("nvd", "redhat", "ghsa"):
        block = cvss_block.get(source) or {}
        score = block.get("V3Score") or block.get("V2Score")
        vector = block.get("V3Vector") or block.get("V2Vector") or ""
        if score is not None:
            return float(score), vector
    return None, ""


class TrivyParser(BaseParser):
    """Parser for Trivy JSON reports (container images, filesystem, IaC)."""

    tool_name = "trivy"

    def parse(self, file_obj: IO[bytes]) -> list[NormalizedVulnerability]:
        try:
            data = json.loads(file_obj.read().decode("utf-8", errors="replace"))
        except json.JSONDecodeError as exc:
            raise ParserError(f"Invalid Trivy JSON: {exc}") from exc

        # Empty / no-finding report may be JSON null.
        if data is None:
            return []

        # Legacy v1 schema: root is a list (Results array directly).
        # v2 schema: root is a dict with a "Results" key.
        if isinstance(data, list):
            artifact = ""
            results_list = data
        elif isinstance(data, dict):
            artifact = data.get("ArtifactName") or data.get("artifactName") or ""
            results_list = data.get("Results") or data.get("results") or []
        else:
            raise ParserError("Trivy JSON root must be an object or array.")

        findings: list[NormalizedVulnerability] = []

        for result in results_list:
            if not isinstance(result, dict):
                continue

            target = result.get("Target") or artifact
            vulns = result.get("Vulnerabilities") or []
            misconfs = result.get("Misconfigurations") or []
            secrets = result.get("Secrets") or []

            # --- CVE Vulnerabilities ---
            for v in vulns:
                cve_id = v.get("VulnerabilityID") or ""
                pkg = v.get("PkgName") or ""
                installed = v.get("InstalledVersion") or ""
                fixed = v.get("FixedVersion") or ""
                title = v.get("Title") or cve_id or f"Vulnerability in {pkg}"
                description = v.get("Description") or ""
                severity = _sev(v.get("Severity") or "")
                cwe_ids = [c for c in (v.get("CweIDs") or []) if c]
                cvss_score, cvss_vector = _best_cvss(v.get("CVSS") or {})
                primary_url = v.get("PrimaryURL") or ""

                remediation = f"Upgrade {pkg} from {installed} to {fixed}." if fixed else ""

                evidence = (
                    f"Target: {target}\n"
                    f"Package: {pkg} {installed}\n"
                    f"CVE: {cve_id}"
                )
                if primary_url:
                    evidence += f"\nRef: {primary_url}"

                findings.append(NormalizedVulnerability(
                    title=title,
                    description=description,
                    remediation=remediation,
                    affected_host=target,
                    cve_id=[cve_id] if cve_id else [],
                    cvss_score=cvss_score,
                    cvss_vector=cvss_vector,
                    risk_level=severity,
                    category=cwe_ids[0] if cwe_ids else "",
                    evidence_code=evidence[:4096],
                    source="trivy",
                    raw_output=json.dumps(v, default=str)[:2048],
                ))

            # --- IaC Misconfigurations ---
            for m in misconfs:
                mid = m.get("ID") or ""
                title = m.get("Title") or mid or "Misconfiguration"
                description = m.get("Description") or ""
                severity = _sev(m.get("Severity") or "")
                resolution = m.get("Resolution") or m.get("Message") or ""

                findings.append(NormalizedVulnerability(
                    title=title,
                    description=description,
                    remediation=resolution,
                    affected_host=target,
                    risk_level=severity,
                    category=mid,
                    evidence_code=f"Target: {target}\nCheck: {mid}",
                    source="trivy",
                    raw_output=json.dumps(m, default=str)[:2048],
                ))

            # --- Secrets ---
            for s in secrets:
                rule_id = s.get("RuleID") or ""
                title = s.get("Title") or rule_id or "Secret Detected"
                severity = _sev(s.get("Severity") or "high")
                match = (s.get("Match") or "")[:120]

                findings.append(NormalizedVulnerability(
                    title=f"Secret: {title}",
                    description=f"Trivy detected a secret in {target}.\nRule: {rule_id}",
                    affected_host=target,
                    risk_level=severity,
                    category="CWE-798",
                    evidence_code=f"Target: {target}\nMatch (truncated): {match}",
                    source="trivy",
                    raw_output=json.dumps(s, default=str)[:2048],
                ))

        return findings
