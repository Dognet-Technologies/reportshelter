"""
Nmap XML parser — wraps the advanced parser from cyberreport_pro_parsers.
Returns a list of OldNormalizedVulnerability compatible with deduplicate_and_save().
"""

from __future__ import annotations

import logging
from typing import IO

from .adapters import adapt_nmap_vuln
from .base import BaseParser, ParserError
from apps.vulnerabilities.deduplication import NormalizedVulnerability

logger = logging.getLogger(__name__)


class NmapParser(BaseParser):
    """
    Adapter wrapping the advanced NmapParser from cyberreport_pro_parsers.
    Extracts NSE-script-based vulnerabilities from Nmap XML (-oX) output.
    """

    tool_name = "nmap"

    def parse(self, file_obj: IO[bytes]) -> list[NormalizedVulnerability]:
        from cyberreport_pro_parsers.parsers.nmap_parser import NmapParser as NewNmapParser

        data = file_obj.read()
        try:
            parser = NewNmapParser(data)
            parser.parse()
        except ValueError as exc:
            raise ParserError(str(exc)) from exc

        if parser.errors:
            logger.warning("[nmap] Parse warnings: %s", "; ".join(parser.errors))

        return [adapt_nmap_vuln(v) for v in parser.vulnerabilities]
