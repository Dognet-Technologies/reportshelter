"""
Nuclei JSONL parser.

Nuclei writes one JSON object per line (JSONL). Each line represents a
template match. Fields of interest:
  templateID / template-id — template identifier
  info.name               — human-readable name
  info.severity           — critical|high|medium|low|info
  info.description        — optional description
  info.cwe                — optional CWE reference
  host                    — target host (URL)
  matched / matched-at    — specific matched URL/endpoint
  ip                      — resolved IP of the target
  timestamp               — ISO-8601 timestamp
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
    "info": "info",
    "informational": "info",
    "unknown": "info",
}


def _severity(raw: str) -> str:
    return _SEV_MAP.get((raw or "").lower().strip(), "info")


class NucleiParser(BaseParser):
    """Parser for Nuclei JSONL output (nuclei -o results.json)."""

    tool_name = "nuclei"

    def parse(self, file_obj: IO[bytes]) -> list[NormalizedVulnerability]:
        raw = file_obj.read()
        try:
            text = raw.decode("utf-8", errors="replace")
        except Exception as exc:
            raise ParserError(f"Cannot decode Nuclei output: {exc}") from exc

        text = text.strip()
        if not text:
            logger.info("[nuclei] File is empty — 0 findings.")
            return []

        # Nuclei v3 may emit a JSON array; v2 emits JSONL (one object per line).
        # Detect by checking whether the file starts with '['.
        if text.startswith("["):
            try:
                arr = json.loads(text)
            except json.JSONDecodeError as exc:
                raise ParserError(f"Invalid Nuclei JSON array: {exc}") from exc
            if not isinstance(arr, list):
                return []
            objects = [o for o in arr if isinstance(o, dict)]
        else:
            objects = []
            for i, line in enumerate(text.splitlines(), start=1):
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    if isinstance(obj, dict):
                        objects.append(obj)
                    else:
                        logger.warning("[nuclei] Skipping non-object line %d", i)
                except json.JSONDecodeError as exc:
                    logger.warning("[nuclei] Skipping malformed line %d: %s", i, exc)

        results: list[NormalizedVulnerability] = []
        for obj in objects:
            info = obj.get("info") or {}
            template_id = obj.get("templateID") or obj.get("template-id") or ""
            name = info.get("name") or template_id or "Nuclei Finding"
            severity = _severity(info.get("severity", "info"))
            description = info.get("description") or ""
            cwe_raw = info.get("cwe") or info.get("cwe-id") or ""
            cve_list: list[str] = []
            if isinstance(info.get("classification"), dict):
                cves = info["classification"].get("cve-id") or []
                if isinstance(cves, str):
                    cves = [cves]
                cve_list = [c for c in cves if c]

            host = obj.get("host") or ""
            matched = obj.get("matched") or obj.get("matched-at") or host
            ip = obj.get("ip") or ""

            # Derive host and port from URL
            affected_host = host
            affected_port: int | None = None
            try:
                from urllib.parse import urlparse
                parsed = urlparse(host)
                if parsed.hostname:
                    affected_host = parsed.hostname
                if parsed.port:
                    affected_port = parsed.port
                elif parsed.scheme == "https":
                    affected_port = 443
                elif parsed.scheme == "http":
                    affected_port = 80
            except Exception:
                pass

            refs = info.get("reference") or info.get("references") or []
            if isinstance(refs, str):
                refs = [refs]
            ref_text = "\n".join(refs) if refs else ""

            evidence = f"Template: {template_id}\nMatched: {matched}"
            if ref_text:
                evidence += f"\nReferences:\n{ref_text}"

            if not description and info.get("tags"):
                description = f"Tags: {', '.join(info['tags'])}" if isinstance(info["tags"], list) else str(info["tags"])

            results.append(NormalizedVulnerability(
                title=name,
                description=description,
                affected_host=affected_host,
                affected_ip=ip,
                affected_port=affected_port,
                cve_id=cve_list,
                risk_level=severity,
                category=str(cwe_raw) if cwe_raw else "",
                evidence_code=evidence[:4096],
                source="nuclei",
                raw_output=json.dumps(obj, default=str)[:2048],
            ))

        if not results:
            logger.info("[nuclei] No findings parsed.")

        return results
