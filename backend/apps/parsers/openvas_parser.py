"""
OpenVAS / Greenbone e Nessus parsers — Django layer.

Questo modulo è un thin wrapper che:
  1. Legge il file (IO[bytes])
  2. Delega il parsing al Layer 2 (cyberreport_pro_parsers)
  3. Converte il risultato via scan_result_adapter
  4. Ritorna list[NormalizedVulnerability] compatibile con la pipeline Django

NON contiene logica di parsing — tutta nel Layer 2.

Tool names registered in the parser registry:
  "openvas"  → OpenVasParser  (auto-detects XML, CSV, XLSX via detect_and_parse)
  "nessus"   → NessusParser   (Nessus .csv)
"""

from __future__ import annotations

import logging
from typing import IO

from apps.vulnerabilities.deduplication import NormalizedVulnerability

from .base import BaseParser, ParserError
from .scan_result_adapter import adapt_scan_result

logger = logging.getLogger(__name__)


class OpenVasParser(BaseParser):
    """
    Parser OpenVAS/Greenbone — supporta XML, CSV, Excel (.xlsx).
    Delega al Layer 2 (cyberreport_pro_parsers) via detect_and_parse().
    """

    tool_name = "openvas"

    def parse(self, file_obj: IO[bytes]) -> list[NormalizedVulnerability]:
        from cyberreport_pro_parsers.parsers.openvas_parser import detect_and_parse

        data = file_obj.read()
        if not data:
            raise ParserError("OpenVAS: file vuoto.")

        try:
            result = detect_and_parse(data)
        except ValueError as exc:
            raise ParserError(str(exc)) from exc

        if result.parse_errors:
            for err in result.parse_errors:
                logger.warning("[openvas] Parse warning: %s", err)

        adapted = adapt_scan_result(result)
        logger.info(
            "[openvas] Parsed %d vulnerabilities (%d errors).",
            len(adapted),
            len(result.parse_errors),
        )
        return adapted


class NessusParser(BaseParser):
    """
    Parser Nessus CSV — delega al Layer 2.
    """

    tool_name = "nessus"

    def parse(self, file_obj: IO[bytes]) -> list[NormalizedVulnerability]:
        from cyberreport_pro_parsers.parsers.openvas_parser import NessusCsvParser

        data = file_obj.read()
        if not data:
            raise ParserError("Nessus: file vuoto.")

        try:
            result = NessusCsvParser().parse(data)
        except Exception as exc:
            raise ParserError(f"Nessus parse error: {exc}") from exc

        return adapt_scan_result(result)
