"""
OpenVAS / Greenbone / Nessus parser — wraps the advanced parsers from
cyberreport_pro_parsers.

Supports:
  - OpenVAS XML (GMP format)
  - OpenVAS CSV
  - Nessus CSV

Tool names registered in the parser registry:
  "openvas"  → OpenVasParser  (auto-detects XML or OpenVAS CSV)
  "nessus"   → NessusParser   (Nessus CSV)
"""

from __future__ import annotations

import logging
from typing import IO

from .adapters import adapt_canonical_vuln
from .base import BaseParser, ParserError
from apps.vulnerabilities.deduplication import NormalizedVulnerability

logger = logging.getLogger(__name__)


class OpenVasParser(BaseParser):
    """
    Adapter for OpenVAS / Greenbone reports (XML and CSV).
    Auto-detects format via detect_and_parse().
    """

    tool_name = "openvas"

    def parse(self, file_obj: IO[bytes]) -> list[NormalizedVulnerability]:
        from cyberreport_pro_parsers.parsers.openvas_parser import detect_and_parse

        data = file_obj.read()
        try:
            result = detect_and_parse(data)
        except ValueError as exc:
            raise ParserError(str(exc)) from exc

        if result.parse_errors:
            logger.warning("[openvas] Parse warnings: %s", "; ".join(result.parse_errors))

        return [adapt_canonical_vuln(v) for v in result.vulnerabilities]


class NessusParser(BaseParser):
    """
    Adapter for Nessus CSV export.
    """

    tool_name = "nessus"

    def parse(self, file_obj: IO[bytes]) -> list[NormalizedVulnerability]:
        from cyberreport_pro_parsers.parsers.openvas_parser import NessusCsvParser

        data = file_obj.read()
        try:
            result = NessusCsvParser().parse(data)
        except ValueError as exc:
            raise ParserError(str(exc)) from exc

        if result.parse_errors:
            logger.warning("[nessus] Parse warnings: %s", "; ".join(result.parse_errors))

        return [adapt_canonical_vuln(v) for v in result.vulnerabilities]
