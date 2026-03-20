"""
CyberReport Pro — Nmap XML Parser
==================================
Parser completo per output Nmap XML (-oX).
Basato su analisi di file reali: discovery, full_tcp, udp, os, ssl, vuln,
smb, ssh, snmp, smtp, ftp, dns, db, web, http_vuln, services, eternal.

Produce oggetti NormalizedVulnerability e NormalizedHost per il DB.

Author: CyberReport Pro
"""

from __future__ import annotations

import hashlib
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Optional


# ---------------------------------------------------------------------------
# Enumerazioni canoniche
# ---------------------------------------------------------------------------

class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH     = "High"
    MEDIUM   = "Medium"
    LOW      = "Low"
    INFO     = "Info"


class PortState(str, Enum):
    OPEN            = "open"
    CLOSED          = "closed"
    FILTERED        = "filtered"
    OPEN_FILTERED   = "open|filtered"
    CLOSED_FILTERED = "closed|filtered"


class Protocol(str, Enum):
    TCP = "tcp"
    UDP = "udp"


# ---------------------------------------------------------------------------
# Dataclasses di output (schema canonico DB)
# ---------------------------------------------------------------------------

@dataclass
class CanonicalService:
    """
    Mappa: nmaprun/host/ports/port/service
    Rappresenta un singolo servizio su una porta.
    """
    # === CAMPO DB: affected_port ===
    port: int

    # === CAMPO DB: affected_protocol ===
    protocol: Protocol

    # === CAMPO DB: port_state ===
    state: PortState

    # === CAMPO DB: affected_service ===
    service_name: str = ""          # es. "ssh", "http", "ms-sql-s"

    # === CAMPO DB: service_product ===
    product: str = ""               # es. "OpenSSH", "Apache httpd"

    # === CAMPO DB: service_version ===
    version: str = ""               # es. "9.6p1", "2.4.58"

    # === CAMPO DB: service_extra_info ===
    extra_info: str = ""            # es. "Ubuntu Linux; protocol 2.0"

    # === CAMPO DB: service_cpe (lista) ===
    cpes: list[str] = field(default_factory=list)  # es. ["cpe:/a:openbsd:openssh:9.6p1"]

    # === CAMPO DB: service_hostname ===
    hostname: str = ""              # hostname dal banner (es. Postfix smtpd)

    # === CAMPO DB: detection_method ===
    detection_method: str = ""      # "probed" | "table"

    # === CAMPO DB: detection_confidence ===
    detection_confidence: int = 0   # 0-10

    # === CAMPO DB: port_reason ===
    state_reason: str = ""          # es. "syn-ack", "conn-refused"

    # Script output associati a questa porta
    scripts: list[CanonicalScript] = field(default_factory=list)


@dataclass
class CanonicalScript:
    """
    Mappa: nmaprun/host/ports/port/script
    Output di un singolo script NSE.
    """
    # === CAMPO DB: script_id ===
    script_id: str          # es. "ssh-hostkey", "vulners", "http-title"

    # === CAMPO DB: script_output ===
    output: str             # output testuale raw

    # === CAMPO DB: script_data (JSON) ===
    structured_data: dict = field(default_factory=dict)  # elementi strutturati <table>/<elem>


@dataclass
class CanonicalOsMatch:
    """
    Mappa: nmaprun/host/os/osmatch
    """
    # === CAMPO DB: os_name ===
    name: str               # es. "Linux 3.8 - 4.14"

    # === CAMPO DB: os_accuracy ===
    accuracy: int           # 0-100

    # === CAMPO DB: os_type ===
    os_type: str = ""       # es. "general purpose", "webcam"

    # === CAMPO DB: os_vendor ===
    vendor: str = ""        # es. "Linux", "Microsoft"

    # === CAMPO DB: os_family ===
    family: str = ""        # es. "Linux", "Windows"

    # === CAMPO DB: os_generation ===
    generation: str = ""    # es. "3.X", "4.X", "10"

    # === CAMPO DB: os_cpe (lista) ===
    cpes: list[str] = field(default_factory=list)


@dataclass
class CanonicalHost:
    """
    Mappa: nmaprun/host
    Rappresenta un host completo con tutti i dati estratti.
    Corrisponde al modello Asset nel DB.
    """
    # === CAMPO DB: ip_address ===
    ip_address: str                         # es. "10.99.201.56"

    # === CAMPO DB: mac_address ===
    mac_address: Optional[str] = None       # es. "D6:66:D7:7A:0E:58"

    # === CAMPO DB: hostname ===
    hostname: Optional[str] = None          # es. "lapdog5" (PTR record)

    # === CAMPO DB: host_state ===
    state: str = "up"                       # "up" | "down"

    # === CAMPO DB: host_reason ===
    state_reason: str = ""                  # es. "arp-response", "syn-ack"

    # === CAMPO DB: scan_start_time ===
    scan_start: Optional[datetime] = None

    # === CAMPO DB: scan_end_time ===
    scan_end: Optional[datetime] = None

    # === CAMPO DB: os_matches (JSON) ===
    os_matches: list[CanonicalOsMatch] = field(default_factory=list)

    # === CAMPO DB: os_best_match ===
    # calcolato: osmatch con accuracy più alta
    @property
    def os_best_match(self) -> Optional[CanonicalOsMatch]:
        return max(self.os_matches, key=lambda o: o.accuracy, default=None)

    # === CAMPO DB: services (relazione 1:N) ===
    services: list[CanonicalService] = field(default_factory=list)

    # === CAMPO DB: traceroute_hops (JSON) ===
    traceroute: list[dict] = field(default_factory=list)


@dataclass
class NormalizedVulnerability:
    """
    Schema canonico per una vulnerabilità.
    Ogni script NSE che indica un problema di sicurezza genera uno o più di questi.

    Campi con commento === CAMPO DB: xxx === indicano la colonna esatta nel DB.
    """
    # === CAMPO DB: affected_host ===
    affected_host: str

    # === CAMPO DB: affected_ip ===
    affected_ip: str

    # === CAMPO DB: affected_port ===
    affected_port: Optional[int]

    # === CAMPO DB: affected_protocol ===
    affected_protocol: str              # "tcp" | "udp"

    # === CAMPO DB: affected_service ===
    affected_service: str

    # === CAMPO DB: title ===
    title: str

    # === CAMPO DB: description ===
    description: str = ""

    # === CAMPO DB: severity ===
    severity: Severity = Severity.INFO

    # === CAMPO DB: cvss_score ===
    cvss_score: Optional[float] = None

    # === CAMPO DB: cve_id (lista, può averne multipli) ===
    cve_ids: list[str] = field(default_factory=list)

    # === CAMPO DB: cpe ===
    cpe: str = ""

    # === CAMPO DB: evidence ===
    evidence: str = ""

    # === CAMPO DB: references (JSON list) ===
    references: list[dict] = field(default_factory=list)
    # formato: [{"id": "CVE-...", "type": "cve", "url": "...", "cvss": 9.8, "is_exploit": False}]

    # === CAMPO DB: source_tool ===
    source_tool: str = "nmap"

    # === CAMPO DB: source_script ===
    source_script: str = ""             # es. "vulners", "http-csrf"

    # === CAMPO DB: raw_output ===
    raw_output: str = ""

    # === CAMPO DB: dedup_key ===
    @property
    def dedup_key(self) -> str:
        """Chiave SHA256 per deduplicazione cross-tool."""
        title_norm = re.sub(r'[\d\.]+', '', self.title.lower().strip())
        host_norm  = self.affected_host or self.affected_ip or "unknown"
        port_norm  = str(self.affected_port) if self.affected_port else "any"
        raw = f"{title_norm}|{host_norm}|{port_norm}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]


# ---------------------------------------------------------------------------
# Tabella di mapping: XML path → Campo DB canonico
# (documentazione e reference per il mapping cross-tool)
# ---------------------------------------------------------------------------

NMAP_FIELD_MAPPING: dict[str, dict] = {
    # HOST LEVEL
    "host.ip_address":          {"xml_path": "address[@addrtype='ipv4']/@addr",         "db_field": "ip_address",           "type": "str"},
    "host.ipv6_address":        {"xml_path": "address[@addrtype='ipv6']/@addr",         "db_field": "ipv6_address",         "type": "str"},
    "host.mac_address":         {"xml_path": "address[@addrtype='mac']/@addr",          "db_field": "mac_address",          "type": "str"},
    "host.hostname_ptr":        {"xml_path": "hostnames/hostname[@type='PTR']/@name",   "db_field": "hostname",             "type": "str"},
    "host.state":               {"xml_path": "status/@state",                           "db_field": "host_state",           "type": "str"},
    "host.state_reason":        {"xml_path": "status/@reason",                          "db_field": "host_reason",          "type": "str"},
    "host.scan_start":          {"xml_path": "host/@starttime",                         "db_field": "scan_start_time",      "type": "unix_ts"},
    "host.scan_end":            {"xml_path": "host/@endtime",                           "db_field": "scan_end_time",        "type": "unix_ts"},

    # PORT / SERVICE LEVEL
    "port.portid":              {"xml_path": "port/@portid",                            "db_field": "affected_port",        "type": "int"},
    "port.protocol":            {"xml_path": "port/@protocol",                          "db_field": "affected_protocol",    "type": "str"},
    "port.state":               {"xml_path": "port/state/@state",                       "db_field": "port_state",           "type": "str"},
    "port.state_reason":        {"xml_path": "port/state/@reason",                      "db_field": "port_reason",          "type": "str"},
    "service.name":             {"xml_path": "port/service/@name",                      "db_field": "affected_service",     "type": "str"},
    "service.product":          {"xml_path": "port/service/@product",                   "db_field": "service_product",      "type": "str"},
    "service.version":          {"xml_path": "port/service/@version",                   "db_field": "service_version",      "type": "str"},
    "service.extra_info":       {"xml_path": "port/service/@extrainfo",                 "db_field": "service_extra_info",   "type": "str"},
    "service.hostname":         {"xml_path": "port/service/@hostname",                  "db_field": "service_hostname",     "type": "str"},
    "service.cpe":              {"xml_path": "port/service/cpe/text()",                 "db_field": "service_cpe",          "type": "str_list"},
    "service.method":           {"xml_path": "port/service/@method",                    "db_field": "detection_method",     "type": "str"},
    "service.conf":             {"xml_path": "port/service/@conf",                      "db_field": "detection_confidence", "type": "int"},

    # SCRIPT LEVEL
    "script.id":                {"xml_path": "port/script/@id",                         "db_field": "script_id",            "type": "str"},
    "script.output":            {"xml_path": "port/script/@output",                     "db_field": "script_output",        "type": "str"},

    # OS DETECTION
    "os.match_name":            {"xml_path": "os/osmatch/@name",                        "db_field": "os_name",              "type": "str"},
    "os.match_accuracy":        {"xml_path": "os/osmatch/@accuracy",                    "db_field": "os_accuracy",          "type": "int"},
    "os.class_type":            {"xml_path": "os/osmatch/osclass/@type",                "db_field": "os_type",              "type": "str"},
    "os.class_vendor":          {"xml_path": "os/osmatch/osclass/@vendor",              "db_field": "os_vendor",            "type": "str"},
    "os.class_family":          {"xml_path": "os/osmatch/osclass/@osfamily",            "db_field": "os_family",            "type": "str"},
    "os.class_gen":             {"xml_path": "os/osmatch/osclass/@osgen",               "db_field": "os_generation",        "type": "str"},
    "os.cpe":                   {"xml_path": "os/osmatch/osclass/cpe/text()",           "db_field": "os_cpe",               "type": "str_list"},

    # SCAN METADATA
    "scan.scanner":             {"xml_path": "nmaprun/@scanner",                        "db_field": "scanner_name",         "type": "str"},
    "scan.version":             {"xml_path": "nmaprun/@version",                        "db_field": "scanner_version",      "type": "str"},
    "scan.args":                {"xml_path": "nmaprun/@args",                           "db_field": "scan_args",            "type": "str"},
    "scan.start":               {"xml_path": "nmaprun/@start",                          "db_field": "scan_date",            "type": "unix_ts"},
    "scan.type":                {"xml_path": "nmaprun/scaninfo/@type",                  "db_field": "scan_type",            "type": "str"},
    "scan.protocol":            {"xml_path": "nmaprun/scaninfo/@protocol",              "db_field": "scan_protocol",        "type": "str"},
    "scan.hosts_up":            {"xml_path": "nmaprun/runstats/hosts/@up",              "db_field": "hosts_up",             "type": "int"},
    "scan.hosts_down":          {"xml_path": "nmaprun/runstats/hosts/@down",            "db_field": "hosts_down",           "type": "int"},
    "scan.elapsed":             {"xml_path": "nmaprun/runstats/finished/@elapsed",      "db_field": "scan_duration_sec",    "type": "float"},
}

# ---------------------------------------------------------------------------
# Severità CVSS → Severity enum
# ---------------------------------------------------------------------------

def cvss_to_severity(score: float) -> Severity:
    """Converti CVSS score numerico in Severity enum (CVSS v3 thresholds)."""
    if score >= 9.0:
        return Severity.CRITICAL
    elif score >= 7.0:
        return Severity.HIGH
    elif score >= 4.0:
        return Severity.MEDIUM
    elif score > 0.0:
        return Severity.LOW
    return Severity.INFO


# ---------------------------------------------------------------------------
# Normalizzatori
# ---------------------------------------------------------------------------

_CVE_RE   = re.compile(r'\bCVE-\d{4}-\d{4,7}\b', re.IGNORECASE)
_CVSS_RE  = re.compile(r'\b(\d+\.\d)\b')

def normalize_cve_list(text: str) -> list[str]:
    """Estrai tutti i CVE ID da una stringa di testo."""
    return [m.upper() for m in _CVE_RE.findall(text)]

def normalize_cvss(value: str) -> Optional[float]:
    """Converti stringa CVSS in float. Ritorna None se non parsabile."""
    try:
        f = float(value.strip())
        return round(f, 1) if 0.0 <= f <= 10.0 else None
    except (ValueError, AttributeError):
        return None

def normalize_port(value: str) -> Optional[int]:
    """Gestisce '443/tcp', '443', 'https' → int."""
    SERVICE_PORT_MAP = {
        "http": 80, "https": 443, "ftp": 21, "ssh": 22, "smtp": 25,
        "dns": 53, "domain": 53, "smb": 445, "rdp": 3389, "mysql": 3306,
        "postgresql": 5432, "redis": 6379, "mongodb": 27017,
    }
    if not value:
        return None
    v = str(value).strip()
    if '/' in v:
        v = v.split('/')[0]
    try:
        return int(v)
    except ValueError:
        return SERVICE_PORT_MAP.get(v.lower())

def parse_unix_ts(value: str) -> Optional[datetime]:
    """Converti unix timestamp stringa in datetime."""
    try:
        return datetime.utcfromtimestamp(int(value))
    except (ValueError, TypeError):
        return None

def clean_script_output(output: str) -> str:
    """Pulisce output script: rimuove escaped entities, normalizza whitespace."""
    output = output.replace('&#xa;', '\n').replace('&#x9;', '\t')
    output = output.replace('&amp;', '&').replace('&lt;', '<').replace('&gt;', '>')
    output = output.replace('&apos;', "'").replace('&quot;', '"')
    return output.strip()


# ---------------------------------------------------------------------------
# Parser degli script NSE → vulnerabilità
# Ogni script noto ha un handler dedicato.
# ---------------------------------------------------------------------------

class NseScriptHandler:
    """
    Base class per handler di script NSE specifici.
    Ogni subclass gestisce uno o più script_id.
    """

    HANDLED_SCRIPTS: list[str] = []

    def can_handle(self, script_id: str) -> bool:
        return script_id in self.HANDLED_SCRIPTS

    def extract(
        self,
        script_el: ET.Element,
        host: CanonicalHost,
        service: CanonicalService,
    ) -> list[NormalizedVulnerability]:
        raise NotImplementedError


class VulnersHandler(NseScriptHandler):
    """
    Script: vulners
    Output: lista CVE/EDB/EXPLOIT con score CVSS per CPE specifico.
    Genera una NormalizedVulnerability per ogni entry con CVSS >= soglia.
    Le entry *EXPLOIT* alzano la severity di un livello.
    """
    HANDLED_SCRIPTS = ["vulners"]
    MIN_CVSS = 0.0  # include tutto, il filtro lo fa il chiamante

    def extract(self, script_el: ET.Element, host: CanonicalHost, service: CanonicalService) -> list[NormalizedVulnerability]:
        vulns: list[NormalizedVulnerability] = []

        # Itera sui <table key="cpe:/...">
        for cpe_table in script_el.findall("table"):
            cpe_key = cpe_table.get("key", "")
            for entry_table in cpe_table.findall("table"):
                entry = {el.get("key"): el.text for el in entry_table.findall("elem")}
                vuln_id    = entry.get("id", "")
                cvss_raw   = entry.get("cvss", "0")
                is_exploit = entry.get("is_exploit", "false").lower() == "true"
                ref_type   = entry.get("type", "")
                ref_url    = entry.get("url", f"https://vulners.com/{ref_type}/{vuln_id}")

                cvss = normalize_cvss(cvss_raw) or 0.0
                if cvss < self.MIN_CVSS:
                    continue

                severity = cvss_to_severity(cvss)
                # exploit disponibile → alza severity di un livello
                if is_exploit:
                    order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
                    idx = order.index(severity)
                    severity = order[min(idx + 1, 4)]

                cve_ids = [vuln_id] if vuln_id.upper().startswith("CVE-") else []

                title = f"{service.product or service.service_name} — {vuln_id}"
                if is_exploit:
                    title += " [EXPLOIT AVAILABLE]"

                vuln = NormalizedVulnerability(
                    affected_host     = host.hostname or host.ip_address,
                    affected_ip       = host.ip_address,
                    affected_port     = service.port,
                    affected_protocol = service.protocol.value,
                    affected_service  = f"{service.product} {service.version}".strip() or service.service_name,
                    title             = title,
                    description       = f"Vulnerability {vuln_id} (CVSS: {cvss}) found on {cpe_key}",
                    severity          = severity,
                    cvss_score        = cvss,
                    cve_ids           = cve_ids,
                    cpe               = cpe_key,
                    evidence          = clean_script_output(script_el.get("output", "")),
                    references        = [{"id": vuln_id, "type": ref_type, "url": ref_url,
                                          "cvss": cvss, "is_exploit": is_exploit}],
                    source_tool       = "nmap",
                    source_script     = "vulners",
                    raw_output        = script_el.get("output", ""),
                )
                vulns.append(vuln)

        return vulns


class SmbVulnHandler(NseScriptHandler):
    """
    Script: smb-vuln-ms17-010, smb-vuln-ms08-067, smb-vuln-cve2009-3103, smb-vuln-*
    Output: testuale, indica VULNERABLE o NOT VULNERABLE.
    """
    HANDLED_SCRIPTS = [
        "smb-vuln-ms17-010", "smb-vuln-ms08-067", "smb-vuln-cve2009-3103",
        "smb-vuln-ms10-054", "smb-vuln-ms10-061", "smb-vuln-regsvc-dos",
    ]

    SCRIPT_CVE_MAP = {
        "smb-vuln-ms17-010":    ("CVE-2017-0143", "EternalBlue — Remote Code Execution via SMB", 9.8),
        "smb-vuln-ms08-067":    ("CVE-2008-4250", "MS08-067 — NetAPI Remote Code Execution",    10.0),
        "smb-vuln-cve2009-3103": ("CVE-2009-3103", "MS09-050 — SMB2 Remote Code Execution",    10.0),
        "smb-vuln-ms10-054":    ("CVE-2010-2550", "MS10-054 — SMB Remote Memory Corruption",   7.1),
        "smb-vuln-ms10-061":    ("CVE-2010-2729", "MS10-061 — Print Spooler Remote Code Exec", 9.3),
    }

    def extract(self, script_el: ET.Element, host: CanonicalHost, service: CanonicalService) -> list[NormalizedVulnerability]:
        output = clean_script_output(script_el.get("output", ""))
        if "VULNERABLE" not in output.upper():
            return []

        script_id = script_el.get("id", "")
        cve, title, cvss = self.SCRIPT_CVE_MAP.get(script_id, ("", script_id, 9.0))

        return [NormalizedVulnerability(
            affected_host     = host.hostname or host.ip_address,
            affected_ip       = host.ip_address,
            affected_port     = service.port,
            affected_protocol = service.protocol.value,
            affected_service  = service.service_name,
            title             = title,
            description       = output,
            severity          = cvss_to_severity(cvss),
            cvss_score        = cvss,
            cve_ids           = [cve] if cve else [],
            evidence          = output,
            source_tool       = "nmap",
            source_script     = script_id,
            raw_output        = script_el.get("output", ""),
        )]


class SslHandler(NseScriptHandler):
    """
    Script: ssl-heartbleed, ssl-poodle, ssl-ccs-injection, ssl-dh-params, ssl-enum-ciphers
    """
    HANDLED_SCRIPTS = [
        "ssl-heartbleed", "ssl-poodle", "ssl-ccs-injection",
        "ssl-dh-params", "ssl-enum-ciphers",
    ]

    SCRIPT_META = {
        "ssl-heartbleed":     ("CVE-2014-0160", "OpenSSL Heartbleed — Memory Disclosure",             7.5),
        "ssl-poodle":         ("CVE-2014-3566", "POODLE — SSL 3.0 Downgrade Attack",                  3.4),
        "ssl-ccs-injection":  ("CVE-2014-0224", "OpenSSL CCS Injection",                              5.8),
        "ssl-dh-params":      ("",               "Weak Diffie-Hellman Parameters (LOGJAM risk)",       4.3),
        "ssl-enum-ciphers":   ("",               "SSL/TLS Weak Cipher Suites",                        4.0),
    }

    def extract(self, script_el: ET.Element, host: CanonicalHost, service: CanonicalService) -> list[NormalizedVulnerability]:
        output = clean_script_output(script_el.get("output", ""))
        script_id = script_el.get("id", "")

        # ssl-heartbleed, poodle, ccs: solo se VULNERABLE
        if script_id in ("ssl-heartbleed", "ssl-poodle", "ssl-ccs-injection"):
            if "VULNERABLE" not in output.upper():
                return []

        # ssl-dh-params: solo se weak key < 2048
        if script_id == "ssl-dh-params":
            if not re.search(r'\b(512|768|1024)\s*bits?\b', output):
                return []

        # ssl-enum-ciphers: solo se ci sono cipher weak
        if script_id == "ssl-enum-ciphers":
            if not re.search(r'\b(weak|export|null|anon|rc4|des\b|3des\b)', output, re.IGNORECASE):
                return []

        cve, title, cvss = self.SCRIPT_META.get(script_id, ("", script_id, 4.0))
        return [NormalizedVulnerability(
            affected_host     = host.hostname or host.ip_address,
            affected_ip       = host.ip_address,
            affected_port     = service.port,
            affected_protocol = service.protocol.value,
            affected_service  = service.service_name,
            title             = title,
            description       = output,
            severity          = cvss_to_severity(cvss),
            cvss_score        = cvss,
            cve_ids           = [cve] if cve else [],
            evidence          = output,
            source_tool       = "nmap",
            source_script     = script_id,
            raw_output        = script_el.get("output", ""),
        )]


class HttpVulnHandler(NseScriptHandler):
    """
    Script: http-vuln-*, http-shellshock, http-slowloris-check,
            http-csrf, http-dombased-xss, http-stored-xss
    """
    HANDLED_SCRIPTS = [
        "http-shellshock", "http-slowloris-check", "http-csrf",
        "http-dombased-xss", "http-stored-xss",
    ]

    SCRIPT_META = {
        "http-shellshock":      ("CVE-2014-6271", "Shellshock — Remote Command Execution via CGI",    9.8),
        "http-slowloris-check": ("",               "Slowloris DoS Vulnerability",                     5.0),
        "http-csrf":            ("",               "Cross-Site Request Forgery (CSRF)",                4.3),
        "http-dombased-xss":    ("",               "DOM-Based Cross-Site Scripting (XSS)",             4.3),
        "http-stored-xss":      ("",               "Stored Cross-Site Scripting (XSS)",                6.1),
    }

    def __init__(self):
        # Aggiungi dinamicamente tutti http-vuln-*
        pass

    def can_handle(self, script_id: str) -> bool:
        return script_id in self.HANDLED_SCRIPTS or script_id.startswith("http-vuln-")

    def extract(self, script_el: ET.Element, host: CanonicalHost, service: CanonicalService) -> list[NormalizedVulnerability]:
        output   = clean_script_output(script_el.get("output", ""))
        script_id = script_el.get("id", "")

        # Scarta esplicitamente i "non trovato"
        negative_patterns = [
            "couldn't find", "couldn't detect", "not vulnerable",
            "doesn't seem", "no open", "all tests failed",
        ]
        if any(p in output.lower() for p in negative_patterns):
            return []

        cve, title, cvss = self.SCRIPT_META.get(script_id, ("", script_id, 5.0))

        # Per http-vuln-* generici, estrai CVE dal nome
        if not cve:
            cve_match = _CVE_RE.search(script_id)
            if cve_match:
                cve = cve_match.group(0).upper()

        return [NormalizedVulnerability(
            affected_host     = host.hostname or host.ip_address,
            affected_ip       = host.ip_address,
            affected_port     = service.port,
            affected_protocol = service.protocol.value,
            affected_service  = service.service_name,
            title             = title or script_id,
            description       = output,
            severity          = cvss_to_severity(cvss),
            cvss_score        = cvss,
            cve_ids           = [cve] if cve else normalize_cve_list(output),
            evidence          = output,
            source_tool       = "nmap",
            source_script     = script_id,
            raw_output        = script_el.get("output", ""),
        )]


class FtpAnonHandler(NseScriptHandler):
    """Script: ftp-anon — Anonymous FTP access."""
    HANDLED_SCRIPTS = ["ftp-anon"]

    def extract(self, script_el: ET.Element, host: CanonicalHost, service: CanonicalService) -> list[NormalizedVulnerability]:
        output = clean_script_output(script_el.get("output", ""))
        if "anonymous ftp login allowed" not in output.lower():
            return []
        return [NormalizedVulnerability(
            affected_host     = host.hostname or host.ip_address,
            affected_ip       = host.ip_address,
            affected_port     = service.port,
            affected_protocol = service.protocol.value,
            affected_service  = "ftp",
            title             = "Anonymous FTP Login Allowed",
            description       = "The FTP server allows anonymous access without authentication.",
            severity          = Severity.MEDIUM,
            cvss_score        = 5.3,
            evidence          = output,
            source_tool       = "nmap",
            source_script     = "ftp-anon",
            raw_output        = script_el.get("output", ""),
        )]


class SmtpOpenRelayHandler(NseScriptHandler):
    """Script: smtp-open-relay."""
    HANDLED_SCRIPTS = ["smtp-open-relay"]

    def extract(self, script_el: ET.Element, host: CanonicalHost, service: CanonicalService) -> list[NormalizedVulnerability]:
        output = clean_script_output(script_el.get("output", ""))
        if "doesn't seem to be an open relay" in output.lower():
            return []
        return [NormalizedVulnerability(
            affected_host     = host.hostname or host.ip_address,
            affected_ip       = host.ip_address,
            affected_port     = service.port,
            affected_protocol = service.protocol.value,
            affected_service  = "smtp",
            title             = "SMTP Open Relay Detected",
            description       = "The mail server can be used to relay email to arbitrary destinations.",
            severity          = Severity.HIGH,
            cvss_score        = 7.5,
            evidence          = output,
            source_tool       = "nmap",
            source_script     = "smtp-open-relay",
            raw_output        = script_el.get("output", ""),
        )]


class DnsRecursionHandler(NseScriptHandler):
    """Script: dns-recursion."""
    HANDLED_SCRIPTS = ["dns-recursion"]

    def extract(self, script_el: ET.Element, host: CanonicalHost, service: CanonicalService) -> list[NormalizedVulnerability]:
        output = clean_script_output(script_el.get("output", ""))
        if "recursion" not in output.lower() or "enabled" not in output.lower():
            return []
        return [NormalizedVulnerability(
            affected_host     = host.hostname or host.ip_address,
            affected_ip       = host.ip_address,
            affected_port     = service.port,
            affected_protocol = service.protocol.value,
            affected_service  = "dns",
            title             = "DNS Recursive Query Enabled",
            description       = "The DNS server allows recursive queries from external hosts, enabling amplification attacks.",
            severity          = Severity.MEDIUM,
            cvss_score        = 5.3,
            evidence          = output,
            source_tool       = "nmap",
            source_script     = "dns-recursion",
            raw_output        = script_el.get("output", ""),
        )]


class SshWeakAlgoHandler(NseScriptHandler):
    """
    Script: ssh2-enum-algos
    Identifica algoritmi deboli (MD5, SHA1, diffie-hellman-group1/14, CBC mode).
    """
    HANDLED_SCRIPTS = ["ssh2-enum-algos"]

    WEAK_KEX    = {"diffie-hellman-group1-sha1", "diffie-hellman-group14-sha1"}
    WEAK_MAC    = {"hmac-md5", "hmac-md5-96", "hmac-sha1", "hmac-sha1-96",
                   "hmac-md5-etm@openssh.com", "hmac-md5-96-etm@openssh.com"}
    WEAK_CIPHER = {"arcfour", "arcfour128", "arcfour256",
                   "aes128-cbc", "aes192-cbc", "aes256-cbc", "3des-cbc", "blowfish-cbc"}

    def _parse_algos(self, script_el: ET.Element) -> dict[str, list[str]]:
        result: dict[str, list[str]] = {}
        for table in script_el.findall("table"):
            key = table.get("key", "")
            result[key] = [el.text for el in table.findall("elem") if el.text]
        return result

    def extract(self, script_el: ET.Element, host: CanonicalHost, service: CanonicalService) -> list[NormalizedVulnerability]:
        algos = self._parse_algos(script_el)
        weak: dict[str, list[str]] = {}

        for kex in algos.get("kex_algorithms", []):
            if kex.lower() in self.WEAK_KEX:
                weak.setdefault("kex", []).append(kex)
        for mac in algos.get("mac_algorithms", []):
            if mac.lower() in self.WEAK_MAC:
                weak.setdefault("mac", []).append(mac)
        for cipher in algos.get("encryption_algorithms", []):
            if cipher.lower() in self.WEAK_CIPHER:
                weak.setdefault("cipher", []).append(cipher)

        if not weak:
            return []

        description_parts = []
        if "kex" in weak:
            description_parts.append(f"Weak KEX algorithms: {', '.join(weak['kex'])}")
        if "mac" in weak:
            description_parts.append(f"Weak MAC algorithms: {', '.join(weak['mac'])}")
        if "cipher" in weak:
            description_parts.append(f"Weak cipher algorithms: {', '.join(weak['cipher'])}")

        return [NormalizedVulnerability(
            affected_host     = host.hostname or host.ip_address,
            affected_ip       = host.ip_address,
            affected_port     = service.port,
            affected_protocol = service.protocol.value,
            affected_service  = "ssh",
            title             = "SSH Weak Algorithms Supported",
            description       = "\n".join(description_parts),
            severity          = Severity.MEDIUM,
            cvss_score        = 4.3,
            evidence          = clean_script_output(script_el.get("output", "")),
            source_tool       = "nmap",
            source_script     = "ssh2-enum-algos",
            raw_output        = script_el.get("output", ""),
        )]


# ---------------------------------------------------------------------------
# Registry degli handler
# ---------------------------------------------------------------------------

NSE_HANDLERS: list[NseScriptHandler] = [
    VulnersHandler(),
    SmbVulnHandler(),
    SslHandler(),
    HttpVulnHandler(),
    FtpAnonHandler(),
    SmtpOpenRelayHandler(),
    DnsRecursionHandler(),
    SshWeakAlgoHandler(),
]

def get_handler(script_id: str) -> Optional[NseScriptHandler]:
    for handler in NSE_HANDLERS:
        if handler.can_handle(script_id):
            return handler
    return None


# ---------------------------------------------------------------------------
# Parsing strutturato <table>/<elem>
# ---------------------------------------------------------------------------

def parse_table_recursive(element: ET.Element) -> dict | list | str:
    """
    Converti struttura <table>/<elem> Nmap in Python dict/list ricorsivamente.
    """
    tables  = element.findall("table")
    elems   = element.findall("elem")

    if not tables and not elems:
        return element.text or ""

    result: dict | list = {}

    # Se tutti i figli <table> non hanno key → è una lista
    all_tables_unnamed = tables and all(t.get("key") is None for t in tables)
    if all_tables_unnamed and not elems:
        return [parse_table_recursive(t) for t in tables]

    for elem in elems:
        key = elem.get("key")
        if key:
            result[key] = elem.text or ""
        # elem senza key: ignorato (raro)

    for tbl in tables:
        key = tbl.get("key")
        parsed = parse_table_recursive(tbl)
        if key:
            result[key] = parsed
        else:
            # tabella unnamed dentro una keyed: usa lista
            if "_list" not in result:
                result["_list"] = []
            result["_list"].append(parsed)

    return result


# ---------------------------------------------------------------------------
# Parser principale
# ---------------------------------------------------------------------------

class NmapParser:
    """
    Parser completo per Nmap XML (-oX).

    Produce:
      - hosts:         List[CanonicalHost]         → Asset nel DB
      - vulnerabilities: List[NormalizedVulnerability] → Vulnerability nel DB
      - scan_meta:     dict                         → metadati della scansione
    """

    def __init__(self, xml_source: str | Path | bytes):
        if isinstance(xml_source, Path):
            xml_source = xml_source.read_bytes()
        if isinstance(xml_source, str):
            xml_source = xml_source.encode("utf-8")
        try:
            self.root = ET.fromstring(xml_source)
        except ET.ParseError as e:
            raise ValueError(f"XML non valido o corrotto: {e}") from e

        self.hosts:           list[CanonicalHost]           = []
        self.vulnerabilities: list[NormalizedVulnerability] = []
        self.scan_meta:       dict                          = {}
        self._errors:         list[str]                     = []

    # ------------------------------------------------------------------
    # Entry point
    # ------------------------------------------------------------------

    def parse(self) -> "NmapParser":
        self._parse_scan_meta()
        for host_el in self.root.findall("host"):
            try:
                host = self._parse_host(host_el)
                self.hosts.append(host)
                vulns = self._extract_vulnerabilities(host_el, host)
                self.vulnerabilities.extend(vulns)
            except Exception as e:
                ip = self._get_ip(host_el) or "unknown"
                self._errors.append(f"Errore parsing host {ip}: {e}")
        return self

    # ------------------------------------------------------------------
    # Metadati scansione
    # ------------------------------------------------------------------

    def _parse_scan_meta(self) -> None:
        self.scan_meta = {
            "scanner":         self.root.get("scanner", "nmap"),
            "version":         self.root.get("version", ""),
            "args":            self.root.get("args", ""),
            "scan_date":       parse_unix_ts(self.root.get("start", "")),
            "scan_type":       "",
            "scan_protocol":   "",
            "hosts_up":        0,
            "hosts_down":      0,
            "scan_duration_s": 0.0,
        }
        scaninfo = self.root.find("scaninfo")
        if scaninfo is not None:
            self.scan_meta["scan_type"]     = scaninfo.get("type", "")
            self.scan_meta["scan_protocol"] = scaninfo.get("protocol", "")

        runstats = self.root.find("runstats")
        if runstats is not None:
            hosts_el    = runstats.find("hosts")
            finished_el = runstats.find("finished")
            if hosts_el is not None:
                self.scan_meta["hosts_up"]   = int(hosts_el.get("up", 0))
                self.scan_meta["hosts_down"] = int(hosts_el.get("down", 0))
            if finished_el is not None:
                try:
                    self.scan_meta["scan_duration_s"] = float(finished_el.get("elapsed", 0))
                except ValueError:
                    pass

    # ------------------------------------------------------------------
    # Host
    # ------------------------------------------------------------------

    def _get_ip(self, host_el: ET.Element) -> Optional[str]:
        for addr in host_el.findall("address"):
            if addr.get("addrtype") == "ipv4":
                return addr.get("addr")
        return None

    def _parse_host(self, host_el: ET.Element) -> CanonicalHost:
        ip = self._get_ip(host_el) or ""
        mac = next(
            (a.get("addr") for a in host_el.findall("address") if a.get("addrtype") == "mac"),
            None
        )

        # Hostname: preferisci PTR, fallback su user
        hostname = None
        for hn in host_el.findall("hostnames/hostname"):
            if hn.get("type") == "PTR":
                hostname = hn.get("name")
                break

        status = host_el.find("status")
        state  = status.get("state", "up")   if status is not None else "up"
        reason = status.get("reason", "")    if status is not None else ""

        host = CanonicalHost(
            ip_address   = ip,
            mac_address  = mac,
            hostname     = hostname,
            state        = state,
            state_reason = reason,
            scan_start   = parse_unix_ts(host_el.get("starttime", "")),
            scan_end     = parse_unix_ts(host_el.get("endtime", "")),
        )

        host.os_matches  = self._parse_os(host_el)
        host.services    = self._parse_services(host_el)
        host.traceroute  = self._parse_traceroute(host_el)

        return host

    def _parse_os(self, host_el: ET.Element) -> list[CanonicalOsMatch]:
        matches: list[CanonicalOsMatch] = []
        os_el = host_el.find("os")
        if os_el is None:
            return matches

        for osmatch in os_el.findall("osmatch"):
            name     = osmatch.get("name", "")
            accuracy = int(osmatch.get("accuracy", 0))

            # Prendi il primo osclass con accuracy massima
            os_type = vendor = family = gen = ""
            cpes: list[str] = []
            for osclass in osmatch.findall("osclass"):
                os_type = osclass.get("type", "")
                vendor  = osclass.get("vendor", "")
                family  = osclass.get("osfamily", "")
                gen     = osclass.get("osgen", "")
                cpes   += [c.text for c in osclass.findall("cpe") if c.text]

            matches.append(CanonicalOsMatch(
                name=name, accuracy=accuracy,
                os_type=os_type, vendor=vendor, family=family, generation=gen,
                cpes=list(dict.fromkeys(cpes)),  # dedup mantenendo ordine
            ))

        return matches

    def _parse_services(self, host_el: ET.Element) -> list[CanonicalService]:
        services: list[CanonicalService] = []
        ports_el = host_el.find("ports")
        if ports_el is None:
            return services

        for port_el in ports_el.findall("port"):
            port_num  = int(port_el.get("portid", 0))
            protocol  = Protocol(port_el.get("protocol", "tcp"))

            state_el  = port_el.find("state")
            state_str = state_el.get("state", "")   if state_el is not None else ""
            state_rsn = state_el.get("reason", "")  if state_el is not None else ""

            try:
                port_state = PortState(state_str)
            except ValueError:
                port_state = PortState.FILTERED

            svc_el  = port_el.find("service")
            svc = CanonicalService(
                port              = port_num,
                protocol          = protocol,
                state             = port_state,
                state_reason      = state_rsn,
            )
            if svc_el is not None:
                svc.service_name        = svc_el.get("name", "")
                svc.product             = svc_el.get("product", "")
                svc.version             = svc_el.get("version", "")
                svc.extra_info          = svc_el.get("extrainfo", "")
                svc.hostname            = svc_el.get("hostname", "").strip()
                svc.detection_method    = svc_el.get("method", "")
                svc.detection_confidence = int(svc_el.get("conf", 0))
                svc.cpes = [c.text for c in svc_el.findall("cpe") if c.text]

            # Script associati alla porta
            for script_el in port_el.findall("script"):
                svc.scripts.append(CanonicalScript(
                    script_id       = script_el.get("id", ""),
                    output          = clean_script_output(script_el.get("output", "")),
                    structured_data = parse_table_recursive(script_el)
                                      if script_el.findall("table") or script_el.findall("elem")
                                      else {},
                ))

            services.append(svc)

        return services

    def _parse_traceroute(self, host_el: ET.Element) -> list[dict]:
        hops: list[dict] = []
        trace_el = host_el.find("trace")
        if trace_el is None:
            return hops
        for hop in trace_el.findall("hop"):
            hops.append({
                "ttl":    int(hop.get("ttl", 0)),
                "ip":     hop.get("ipaddr", ""),
                "rtt":    hop.get("rtt", ""),
                "host":   hop.get("host", ""),
            })
        return hops

    # ------------------------------------------------------------------
    # Vulnerabilità
    # ------------------------------------------------------------------

    def _extract_vulnerabilities(
        self,
        host_el: ET.Element,
        host: CanonicalHost,
    ) -> list[NormalizedVulnerability]:
        vulns: list[NormalizedVulnerability] = []

        ports_el = host_el.find("ports")
        if ports_el is None:
            return vulns

        for port_el in ports_el.findall("port"):
            port_num = int(port_el.get("portid", 0))
            protocol = port_el.get("protocol", "tcp")

            # Trova il CanonicalService corrispondente (già parsato)
            svc = next(
                (s for s in host.services if s.port == port_num and s.protocol.value == protocol),
                None
            )
            if svc is None:
                continue

            for script_el in port_el.findall("script"):
                script_id = script_el.get("id", "")
                handler   = get_handler(script_id)
                if handler:
                    try:
                        found = handler.extract(script_el, host, svc)
                        vulns.extend(found)
                    except Exception as e:
                        self._errors.append(
                            f"Handler {script_id} su {host.ip_address}:{port_num}: {e}"
                        )

        return vulns

    # ------------------------------------------------------------------
    # Risultati
    # ------------------------------------------------------------------

    @property
    def errors(self) -> list[str]:
        return self._errors

    def summary(self) -> dict:
        return {
            "scan_meta":    self.scan_meta,
            "hosts_total":  len(self.hosts),
            "hosts_up":     sum(1 for h in self.hosts if h.state == "up"),
            "services":     sum(len(h.services) for h in self.hosts),
            "open_ports":   sum(
                1 for h in self.hosts
                for s in h.services if s.state == PortState.OPEN
            ),
            "vulns_total":  len(self.vulnerabilities),
            "vulns_by_severity": {
                sev.value: sum(1 for v in self.vulnerabilities if v.severity == sev)
                for sev in Severity
            },
            "errors": self._errors,
        }
