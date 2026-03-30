"""
Hydra JSON parser.

Hydra -b jsonv1 produces:
  generator.server  — target host
  generator.service — service type (ssh, ftp, http-post-form, etc.)
  results[]         — successful credential pairs
    .host / .login / .password / .port / .service

Each successful credential is a confirmed authentication bypass —
reported as a "critical" finding.
"""

from __future__ import annotations

import json
import logging
from typing import IO

from apps.vulnerabilities.deduplication import NormalizedVulnerability

from .base import BaseParser, ParserError

logger = logging.getLogger(__name__)


class HydraParser(BaseParser):
    """Parser for Hydra jsonv1 output."""

    tool_name = "hydra"

    def parse(self, file_obj: IO[bytes]) -> list[NormalizedVulnerability]:
        try:
            data = json.loads(file_obj.read().decode("utf-8", errors="replace"))
        except json.JSONDecodeError as exc:
            raise ParserError(f"Invalid Hydra JSON: {exc}") from exc

        if not isinstance(data, dict):
            raise ParserError("Hydra JSON root must be an object.")

        generator = data.get("generator") or {}
        results_list = data.get("results") or []

        if not results_list:
            logger.info("[hydra] No successful credentials found.")
            return []

        findings: list[NormalizedVulnerability] = []
        for item in results_list:
            if not isinstance(item, dict):
                continue

            host = item.get("host") or generator.get("server") or ""
            port = item.get("port") or None
            service = item.get("service") or generator.get("service") or ""
            login = item.get("login") or ""
            # Do NOT include the actual password in title/description for security
            # Only note that credentials were found

            title = f"Weak/Default Credentials: {service} on {host}"
            if port:
                title += f":{port}"

            description = (
                f"Hydra successfully authenticated to the {service} service.\n"
                f"Host: {host}\n"
                f"Port: {port}\n"
                f"Service: {service}\n"
                f"Username: {login}\n"
                f"A valid password was found — this indicates weak or default credentials."
            )

            port_int: int | None = None
            try:
                port_int = int(port) if port else None
            except (TypeError, ValueError):
                pass

            findings.append(NormalizedVulnerability(
                title=title,
                description=description,
                remediation=(
                    f"Change the password for account '{login}' on {service}@{host}. "
                    "Enforce strong password policies and consider multi-factor authentication."
                ),
                affected_host=host,
                affected_port=port_int,
                affected_service=service,
                risk_level="critical",
                category="CWE-521",  # Weak Password Requirements
                evidence_code=description[:4096],
                source="hydra",
                raw_output=json.dumps(item, default=str)[:2048],
            ))

        return findings
