"""
SSH Audit JSON parser.

ssh-audit --json produces:
  banner.raw         — SSH banner string (server + version)
  banner.software    — e.g. "OpenSSH_7.9p1"
  cves[]             — known CVEs affecting this version
    name             — CVE ID
    cvssv2           — CVSS v2 base score
    description      — description
  kex[] / key[] / enc[] / mac[]  — algorithm audit entries
    algorithm        — algorithm name
    notes.warn[]     — warning messages
    notes.fail[]     — failure messages

Each CVE becomes a vulnerability. Weak/failed algorithms also become findings.
"""

from __future__ import annotations

import json
import logging
from typing import IO

from apps.vulnerabilities.deduplication import NormalizedVulnerability

from .base import BaseParser, ParserError

logger = logging.getLogger(__name__)


def _score_to_risk(score: float | None) -> str:
    if score is None:
        return "medium"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    return "low"


class SSHAuditParser(BaseParser):
    """Parser for ssh-audit JSON output."""

    tool_name = "ssh_audit"

    def parse(self, file_obj: IO[bytes]) -> list[NormalizedVulnerability]:
        try:
            data = json.loads(file_obj.read().decode("utf-8", errors="replace"))
        except json.JSONDecodeError as exc:
            raise ParserError(f"Invalid ssh-audit JSON: {exc}") from exc

        if not isinstance(data, dict):
            raise ParserError("ssh-audit JSON root must be an object.")

        banner = data.get("banner") or {}
        software = banner.get("software") or banner.get("raw") or "SSH Server"
        target = data.get("target") or data.get("host") or "ssh-server"

        results: list[NormalizedVulnerability] = []

        # --- CVEs ---
        for cve in (data.get("cves") or []):
            cve_id = cve.get("name") or ""
            score = cve.get("cvssv2")
            description = cve.get("description") or ""

            title = f"{cve_id}: {description[:80]}" if cve_id else description[:80] or "SSH CVE"
            results.append(NormalizedVulnerability(
                title=title,
                description=f"{software} is affected by {cve_id}.\n{description}",
                affected_host=target,
                affected_port=22,
                affected_service="ssh",
                cve_id=[cve_id] if cve_id else [],
                cvss_score=float(score) if score else None,
                risk_level=_score_to_risk(float(score) if score else None),
                evidence_code=f"Software: {software}\nCVE: {cve_id}",
                source="ssh_audit",
                raw_output=json.dumps(cve, default=str)[:2048],
            ))

        # --- Algorithm warnings/failures ---
        seen_algs: set[str] = set()
        for section_key in ("kex", "key", "enc", "mac"):
            for entry in (data.get(section_key) or []):
                if not isinstance(entry, dict):
                    continue
                notes = entry.get("notes") or {}
                fails = notes.get("fail") or []
                warns = notes.get("warn") or []
                algorithm = entry.get("algorithm") or ""

                for msg in fails:
                    dedup_key = f"fail:{algorithm}:{msg}"
                    if dedup_key in seen_algs:
                        continue
                    seen_algs.add(dedup_key)
                    results.append(NormalizedVulnerability(
                        title=f"Insecure SSH Algorithm: {algorithm}",
                        description=(
                            f"SSH server {software} supports the insecure algorithm '{algorithm}'.\n"
                            f"Reason: {msg}"
                        ),
                        remediation=f"Disable algorithm '{algorithm}' from the SSH server configuration.",
                        affected_host=target,
                        affected_port=22,
                        affected_service="ssh",
                        risk_level="high",
                        category="CWE-326",  # Inadequate Encryption Strength
                        evidence_code=f"Section: {section_key}\nAlgorithm: {algorithm}\nFail: {msg}",
                        source="ssh_audit",
                    ))

                for msg in warns:
                    dedup_key = f"warn:{algorithm}:{msg}"
                    if dedup_key in seen_algs:
                        continue
                    seen_algs.add(dedup_key)
                    results.append(NormalizedVulnerability(
                        title=f"Weak SSH Algorithm: {algorithm}",
                        description=(
                            f"SSH server {software} supports the weak algorithm '{algorithm}'.\n"
                            f"Reason: {msg}"
                        ),
                        remediation=f"Consider disabling algorithm '{algorithm}'.",
                        affected_host=target,
                        affected_port=22,
                        affected_service="ssh",
                        risk_level="medium",
                        category="CWE-326",
                        evidence_code=f"Section: {section_key}\nAlgorithm: {algorithm}\nWarn: {msg}",
                        source="ssh_audit",
                    ))

        return results
