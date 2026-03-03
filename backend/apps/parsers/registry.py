"""
Parser registry: maps ScanImport.tool choices to parser classes.
"""

from __future__ import annotations

from .base import BaseParser
from .burp_parser import BurpParser
from .csv_parser import CSVParser
from .metasploit_parser import MetasploitParser
from .nikto_parser import NiktoParser
from .nmap_parser import NmapParser
from .zap_parser import ZAPParser

PARSER_REGISTRY: dict[str, type[BaseParser]] = {
    "nmap": NmapParser,
    "nikto": NiktoParser,
    "burp": BurpParser,
    "zap": ZAPParser,
    "metasploit": MetasploitParser,
    "csv": CSVParser,
}


def get_parser(tool: str) -> BaseParser:
    """
    Return an instantiated parser for the given tool name.
    Raises ValueError if the tool is not supported.
    """
    parser_cls = PARSER_REGISTRY.get(tool.lower())
    if parser_cls is None:
        raise ValueError(f"No parser registered for tool: '{tool}'. "
                         f"Supported: {list(PARSER_REGISTRY.keys())}")
    return parser_cls()
