"""CyberReport Pro — Canonical Vulnerability Schema v2"""
from __future__ import annotations
import hashlib, re
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional

class Severity(str, Enum):
    CRITICAL = "Critical"; HIGH = "High"; MEDIUM = "Medium"
    LOW = "Low"; INFO = "Info"
    @classmethod
    def from_cvss(cls, score: float) -> "Severity":
        if score >= 9.0: return cls.CRITICAL
        if score >= 7.0: return cls.HIGH
        if score >= 4.0: return cls.MEDIUM
        if score > 0.0:  return cls.LOW
        return cls.INFO
    @classmethod
    def from_string(cls, value: str) -> "Severity":
        if not value: return cls.INFO
        v = str(value).strip().lower()
        _MAP = {
            "critical": cls.CRITICAL, "crit": cls.CRITICAL,
            "high": cls.HIGH, "h": cls.HIGH,
            "medium": cls.MEDIUM, "med": cls.MEDIUM, "m": cls.MEDIUM, "moderate": cls.MEDIUM,
            "low": cls.LOW, "l": cls.LOW,
            "info": cls.INFO, "informational": cls.INFO, "none": cls.INFO, "information": cls.INFO,
            "critico": cls.CRITICAL, "critica": cls.CRITICAL,
            "alto": cls.HIGH, "alta": cls.HIGH,
            "medio": cls.MEDIUM, "media": cls.MEDIUM,
            "basso": cls.LOW, "bassa": cls.LOW,
            "5": cls.CRITICAL, "4": cls.HIGH, "3": cls.MEDIUM, "2": cls.LOW, "1": cls.INFO,
        }
        return _MAP.get(v, cls.INFO)

class EnrichmentStatus(str, Enum):
    PENDING = "pending"; DONE = "done"; FAILED = "failed"
    SKIPPED = "skipped"; PARTIAL = "partial"

class VulnDiffStatus(str, Enum):
    NEW = "NEW"; FIXED = "FIXED"; PERSISTENT = "PERSISTENT"; CHANGED = "CHANGED"

@dataclass
class CvssV3Data:
    version: str = ""; base_score: Optional[float] = None; base_severity: str = ""
    vector_string: str = ""; attack_vector: str = ""; attack_complexity: str = ""
    privileges_required: str = ""; user_interaction: str = ""; scope: str = ""
    confidentiality_impact: str = ""; integrity_impact: str = ""; availability_impact: str = ""
    exploitability_score: Optional[float] = None; impact_score: Optional[float] = None
    source: str = ""; source_type: str = ""

@dataclass
class CvssV2Data:
    base_score: Optional[float] = None; vector_string: str = ""; base_severity: str = ""
    access_vector: str = ""; access_complexity: str = ""; authentication: str = ""
    confidentiality_impact: str = ""; integrity_impact: str = ""; availability_impact: str = ""
    exploitability_score: Optional[float] = None; impact_score: Optional[float] = None

@dataclass
class NvdReference:
    url: str = ""; source: str = ""; tags: list[str] = field(default_factory=list)

@dataclass
class NvdWeakness:
    cwe_id: str = ""; source: str = ""; weakness_type: str = ""

@dataclass
class NvdCpeMatch:
    criteria: str = ""; match_criteria_id: str = ""; vulnerable: bool = True
    version_start_including: Optional[str] = None; version_start_excluding: Optional[str] = None
    version_end_including: Optional[str] = None; version_end_excluding: Optional[str] = None

@dataclass
class CisaKevData:
    exploit_add: Optional[datetime] = None; action_due: Optional[datetime] = None
    required_action: str = ""; vulnerability_name: str = ""

@dataclass
class NvdEnrichmentData:
    cve_id: str = ""; published: Optional[datetime] = None; last_modified: Optional[datetime] = None
    vuln_status: str = ""; description_en: str = ""
    cvss_v31: Optional[CvssV3Data] = None; cvss_v30: Optional[CvssV3Data] = None
    cvss_v2: Optional[CvssV2Data] = None
    weaknesses: list[NvdWeakness] = field(default_factory=list)
    references: list[NvdReference] = field(default_factory=list)
    cpe_matches: list[NvdCpeMatch] = field(default_factory=list)
    kev: Optional[CisaKevData] = None
    @property
    def best_cvss(self) -> Optional[CvssV3Data]: return self.cvss_v31 or self.cvss_v30
    @property
    def cvss_score(self) -> Optional[float]:
        if self.best_cvss and self.best_cvss.base_score is not None: return self.best_cvss.base_score
        if self.cvss_v2 and self.cvss_v2.base_score is not None: return self.cvss_v2.base_score
        return None
    @property
    def severity(self) -> Severity:
        s = self.cvss_score; return Severity.from_cvss(s) if s is not None else Severity.INFO
    @property
    def primary_cwe(self) -> Optional[str]:
        p = next((w for w in self.weaknesses if w.weakness_type == "Primary"), None)
        t = p or (self.weaknesses[0] if self.weaknesses else None)
        return t.cwe_id if t else None
    @property
    def has_exploit_reference(self) -> bool: return any("Exploit" in r.tags for r in self.references)
    @property
    def is_kev(self) -> bool: return self.kev is not None

@dataclass
class NormalizedVulnerability:
    # SEZIONE A — Parser fields
    affected_ip: str = ""; affected_host: str = ""; affected_port: Optional[int] = None
    affected_protocol: str = "tcp"; affected_service: str = ""
    service_product: str = ""; service_version: str = ""
    title: str = ""; description_tool: str = ""; severity_tool: Optional[Severity] = None
    cvss_score_tool: Optional[float] = None; cve_ids_tool: list[str] = field(default_factory=list)
    cpe_tool: str = ""; evidence: str = ""; evidence_request: str = ""; evidence_response: str = ""
    affected_url: str = ""; http_method: str = ""; remediation_tool: str = ""
    references_tool: list[dict] = field(default_factory=list)
    is_exploit_available_tool: bool = False; source_tool: str = ""; source_script: str = ""
    raw_output: str = ""; scan_import_id: Optional[int] = None
    # SEZIONE B — NVD Enricher fields
    nvd_data: Optional[NvdEnrichmentData] = None; description_nvd: str = ""
    severity: Optional[Severity] = None; cvss_score: Optional[float] = None
    cvss_vector: str = ""; cvss_version: str = ""
    cvss_av: str = ""; cvss_ac: str = ""; cvss_pr: str = ""; cvss_ui: str = ""
    cvss_scope: str = ""; cvss_c: str = ""; cvss_i: str = ""; cvss_a: str = ""
    cvss_exploitability_score: Optional[float] = None; cvss_impact_score: Optional[float] = None
    cwe_id: str = ""; cwe_ids: list[str] = field(default_factory=list)
    cve_published: Optional[datetime] = None; cve_last_modified: Optional[datetime] = None
    cve_status: str = ""; references_nvd: list[dict] = field(default_factory=list)
    cpe_affected: list[str] = field(default_factory=list)
    is_kev: bool = False; kev_date_added: Optional[datetime] = None
    kev_action_due: Optional[datetime] = None; kev_required_action: str = ""
    is_exploit_available_nvd: bool = False
    # SEZIONE C — Stato
    nvd_enrichment_status: EnrichmentStatus = EnrichmentStatus.PENDING
    nvd_enriched_at: Optional[datetime] = None; diff_status: Optional[VulnDiffStatus] = None
    is_recurring: bool = False; user_severity_override: Optional[Severity] = None
    user_notes: str = ""; status: str = "Open"

    @property
    def effective_severity(self) -> Severity:
        return self.user_severity_override or self.severity or self.severity_tool or Severity.INFO
    @property
    def effective_cvss_score(self) -> Optional[float]: return self.cvss_score or self.cvss_score_tool
    @property
    def effective_description(self) -> str: return self.description_nvd or self.description_tool
    @property
    def is_exploit_available(self) -> bool: return self.is_exploit_available_nvd or self.is_exploit_available_tool
    @property
    def primary_cve_id(self) -> Optional[str]: return self.cve_ids_tool[0] if self.cve_ids_tool else None
    @property
    def needs_nvd_enrichment(self) -> bool:
        return bool(self.cve_ids_tool) and self.nvd_enrichment_status == EnrichmentStatus.PENDING
    @property
    def dedup_key(self) -> str:
        title_norm = re.sub(r'[\d\./\-]+', '', self.title.lower().strip())
        title_norm = re.sub(r'\s+', ' ', title_norm).strip()
        host_norm  = self.affected_host or self.affected_ip or "unknown"
        port_norm  = str(self.affected_port) if self.affected_port else "any"
        return hashlib.sha256(f"{title_norm}|{host_norm}|{port_norm}".encode()).hexdigest()[:16]

@dataclass
class NormalizedHost:
    ip_address: str = ""; ipv6_address: str = ""; mac_address: str = ""; hostname: str = ""
    os_name: str = ""; os_accuracy: int = 0; os_family: str = ""; os_vendor: str = ""
    os_cpe: list[str] = field(default_factory=list); host_state: str = "up"
    scan_start: Optional[datetime] = None; scan_end: Optional[datetime] = None
    source_tool: str = ""; open_ports: list[dict] = field(default_factory=list)

@dataclass
class ScanImportResult:
    source_tool: str = ""; scan_date: Optional[datetime] = None
    scan_args: str = ""; scanner_version: str = ""
    hosts: list[NormalizedHost] = field(default_factory=list)
    vulnerabilities: list[NormalizedVulnerability] = field(default_factory=list)
    parse_errors: list[str] = field(default_factory=list)
    @property
    def stats(self) -> dict:
        return {
            "hosts": len(self.hosts), "vulnerabilities": len(self.vulnerabilities),
            "with_cve": sum(1 for v in self.vulnerabilities if v.cve_ids_tool),
            "needs_enrichment": sum(1 for v in self.vulnerabilities if v.needs_nvd_enrichment),
            "errors": len(self.parse_errors),
        }

class BaseParser:
    SOURCE_TOOL: str = ""
    def parse(self, source) -> ScanImportResult: raise NotImplementedError
    @staticmethod
    def normalize_host(raw: str) -> tuple[str, str]:
        if not raw: return "", ""
        raw = re.sub(r'^https?://', '', raw.strip())
        raw = re.sub(r'[:/].*', '', raw)
        if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', raw): return raw, ""
        return "", raw
    @staticmethod
    def normalize_port(raw: str) -> Optional[int]:
        _MAP = {"http":80,"https":443,"ftp":21,"ssh":22,"smtp":25,"domain":53,"dns":53,
                "smb":445,"microsoft-ds":445,"rdp":3389,"mysql":3306,"postgresql":5432,
                "redis":6379,"mongodb":27017,"mssql":1433}
        if not raw: return None
        v = str(raw).strip()
        if '/' in v: v = v.split('/')[0]
        try:
            p = int(v); return p if 1 <= p <= 65535 else None
        except ValueError: return _MAP.get(v.lower())
    @staticmethod
    def normalize_cvss(raw: str) -> Optional[float]:
        try:
            f = float(str(raw).strip()); return round(f, 1) if 0.0 <= f <= 10.0 else None
        except (ValueError, AttributeError): return None
    @staticmethod
    def normalize_cve_ids(raw: str) -> list[str]:
        found = re.findall(r'\bCVE-\d{4}-\d{4,7}\b', raw, re.IGNORECASE)
        return list(dict.fromkeys(cve.upper() for cve in found))
    @staticmethod
    def normalize_severity_from_description(description: str) -> Severity:
        text = description.lower()
        patterns = [
            (r'remote\s*code\s*exec|command\s*exec|\brce\b|backdoor|arbitrary\s*code', Severity.CRITICAL),
            (r'sql\s*injection|blind\s*sql|sqli', Severity.HIGH),
            (r'path\s*traversal|directory\s*traversal|authentication\s*bypass|privilege\s*escal', Severity.HIGH),
            (r'cross.site\s*scripting|\bxss\b', Severity.MEDIUM),
            (r'csrf|cross.site\s*request\s*forgery|open\s*redirect', Severity.MEDIUM),
            (r'information\s*disclos|reveals?|leaks?|default\s*file|directory\s*(listing|indexing)', Severity.LOW),
            (r'header\s*(not\s*present|missing)|uncommon\s*header|etag|fingerprint', Severity.LOW),
        ]
        for pattern, severity in patterns:
            if re.search(pattern, text): return severity
        return Severity.INFO
