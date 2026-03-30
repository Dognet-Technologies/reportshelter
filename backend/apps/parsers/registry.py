"""
Parser registry: maps ScanImport.tool choices to parser classes.
"""

from __future__ import annotations

from .base import BaseParser
from .acunetix_parser import AcunetixParser
from .arachni_parser import ArachniParser
from .aws_inspector2_parser import AWSInspector2Parser
from .awssecurityhub_parser import AWSSecurityHubParser
from .burp_parser import BurpParser
from .cargo_audit_parser import CargoAuditParser
from .cloudsploit_parser import CloudSploitParser
from .cobalt_parser import CobaltParser
from .codechecker_parser import CodeCheckerParser
from .csv_parser import CSVParser
from .cycognito_parser import CyCognitoParser
from .dockerbench_parser import DockerBenchParser
from .github_vulnerability_parser import GitHubVulnerabilityParser
from .gitlab_container_scan_parser import GitLabContainerScanParser
from .gitleaks_parser import GitleaksParser
from .hydra_parser import HydraParser
from .immuniweb_parser import ImmuniWebParser
from .metasploit_parser import MetasploitParser
from .netsparker_parser import NetsparkerParser
from .nexpose_parser import NexposeParser
from .nikto_parser import NiktoParser
from .nmap_parser import NmapParser
from .nuclei_parser import NucleiParser
from .openvas_parser import NessusParser, OpenVasParser
from .qualys_parser import QualysParser
from .qualys_webapp_parser import QualysWebAppParser
from .redhatsatellite_parser import RedHatSatelliteParser
from .sonarqube_parser import SonarQubeParser
from .ssh_audit_parser import SSHAuditParser
from .sslscan_parser import SSLScanParser
from .sysdig_parser import SysdigParser
from .trivy_parser import TrivyParser
from .wapiti_parser import WapitiParser
from .wfuzz_parser import WfuzzParser
from .wpscan_parser import WPScanParser
from .zap_parser import ZAPParser

PARSER_REGISTRY: dict[str, type[BaseParser]] = {
    # Original parsers
    "nmap": NmapParser,
    "nikto": NiktoParser,
    "burp": BurpParser,
    "zap": ZAPParser,
    "metasploit": MetasploitParser,
    "csv": CSVParser,
    "openvas": OpenVasParser,
    "nessus": NessusParser,
    # Extended parsers
    "acunetix": AcunetixParser,
    "arachni": ArachniParser,
    "aws_inspector2": AWSInspector2Parser,
    "awssecurityhub": AWSSecurityHubParser,
    "cargo_audit": CargoAuditParser,
    "cloudsploit": CloudSploitParser,
    "cobalt": CobaltParser,
    "codechecker": CodeCheckerParser,
    "cycognito": CyCognitoParser,
    "dockerbench": DockerBenchParser,
    "github_vulnerability": GitHubVulnerabilityParser,
    "gitlab_container_scan": GitLabContainerScanParser,
    "gitleaks": GitleaksParser,
    "hydra": HydraParser,
    "immuniweb": ImmuniWebParser,
    "netsparker": NetsparkerParser,
    "nexpose": NexposeParser,
    "nuclei": NucleiParser,
    "qualys": QualysParser,
    "qualys_webapp": QualysWebAppParser,
    "redhatsatellite": RedHatSatelliteParser,
    "sonarqube": SonarQubeParser,
    "ssh_audit": SSHAuditParser,
    "sslscan": SSLScanParser,
    "sysdig": SysdigParser,
    "trivy": TrivyParser,
    "wapiti": WapitiParser,
    "wfuzz": WfuzzParser,
    "wpscan": WPScanParser,
}


def get_parser(tool: str) -> BaseParser:
    """
    Return an instantiated parser for the given tool name.
    Raises ValueError if the tool is not supported.
    """
    parser_cls = PARSER_REGISTRY.get(tool.lower())
    if parser_cls is None:
        raise ValueError(
            f"No parser registered for tool: '{tool}'. "
            f"Supported: {sorted(PARSER_REGISTRY.keys())}"
        )
    return parser_cls()
