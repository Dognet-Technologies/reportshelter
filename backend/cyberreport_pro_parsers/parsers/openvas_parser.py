"""
CyberReport Pro — OpenVAS/Greenbone Parser
==========================================
Gestisce 3 formati di output OpenVAS/Greenbone e Nessus CSV:

FORMAT 1 — OpenVAS XML (GMP format)
  Root: <report> → <report> → <results> → <result>
  Campi chiave per result:
    name                     → title
    host/text()              → affected_ip
    host/hostname            → affected_host
    host/asset/@asset_id     → asset_id OpenVAS
    port                     → affected_port + protocol ("443/tcp")
    nvt/@oid                 → source_script (NVT OID)
    nvt/name                 → title (alternativo)
    nvt/family               → vuln_family
    nvt/cvss_base            → cvss_score_tool
    nvt/severities/severity[@type='cvss_base_v3']/value → cvss_vector
    nvt/severities/severity/score                        → cvss_score
    nvt/tags                 → pipe-separated: cvss_base_vector|summary|insight|
                               affected|impact|solution|vuldetect|solution_type
    nvt/solution/@type       → solution_type (WillNotFix/Mitigation/VendorFix/...)
    nvt/solution/text()      → remediation_tool
    nvt/refs/ref[@type='cve']/@id  → cve_ids_tool
    nvt/refs/ref[@type='url']/@id  → references_tool
    threat                   → severity_tool (High/Medium/Low)
    severity                 → cvss_score_tool (float)
    qod/value                → quality of detection (0-100)
    description              → evidence (specific scan output)

FORMAT 2 — OpenVAS CSV
  Colonne: IP|Hostname|Port|Port Protocol|CVSS|Severity|Solution Type|
           NVT Name|Summary|Specific Result|NVT OID|CVEs|Task ID|Task Name|
           Timestamp|Result ID|Impact|Solution|Affected Software/OS|
           Vulnerability Insight|Vulnerability Detection Method|
           Product Detection Result|BIDs|CERTs|Other References

FORMAT 3 — Nessus CSV
  Colonne: Plugin ID|CVE|CVSS v2.0 Base Score|Risk|Host|Protocol|Port|
           Name|Synopsis|Description|Solution|See Also|Plugin Output|
           Risk Factor|BID|XREF|MSKB

Author: CyberReport Pro
"""

from __future__ import annotations

import csv
import io
import logging
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from cyberreport_pro_parsers.parsers.canonical_schema import (
    BaseParser, NormalizedHost, NormalizedVulnerability,
    ScanImportResult, Severity, EnrichmentStatus,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Severity mapping
# ---------------------------------------------------------------------------

OPENVAS_THREAT_MAP: dict[str, Severity] = {
    "high":     Severity.HIGH,
    "medium":   Severity.MEDIUM,
    "low":      Severity.LOW,
    "log":      Severity.INFO,
    "alarm":    Severity.INFO,
    "debug":    Severity.INFO,
    "false positive": Severity.INFO,
}

NESSUS_RISK_MAP: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high":     Severity.HIGH,
    "medium":   Severity.MEDIUM,
    "low":      Severity.LOW,
    "none":     Severity.INFO,
    "info":     Severity.INFO,
}


# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------

def parse_port_protocol(raw: str) -> tuple[Optional[int], str]:
    """
    "443/tcp" → (443, "tcp")
    "general/tcp" → (None, "tcp")
    "80" → (80, "tcp")
    """
    if not raw:
        return None, "tcp"
    raw = raw.strip()
    if '/' in raw:
        parts = raw.split('/')
        proto = parts[1].lower() if len(parts) > 1 else "tcp"
        try:
            port = int(parts[0])
            return (port if 1 <= port <= 65535 else None), proto
        except ValueError:
            return None, proto
    try:
        p = int(raw)
        return (p if 1 <= p <= 65535 else None), "tcp"
    except ValueError:
        return None, "tcp"


def parse_openvas_tags(tags_raw: str) -> dict[str, str]:
    """
    Parsa il campo tags OpenVAS: pipe-separated key=value.
    "cvss_base_vector=CVSS:3.1/...|summary=...|insight=..."
    → {"cvss_base_vector": "CVSS:3.1/...", "summary": "...", ...}
    """
    result: dict[str, str] = {}
    if not tags_raw:
        return result
    for part in tags_raw.split('|'):
        if '=' in part:
            key, _, value = part.partition('=')
            result[key.strip()] = value.strip()
    return result


def parse_openvas_datetime(raw: str) -> Optional[datetime]:
    """Parsa timestamp OpenVAS: "2022-10-21T15:03:44Z" """
    if not raw:
        return None
    for fmt in ('%Y-%m-%dT%H:%M:%SZ', '%Y-%m-%dT%H:%M:%S', '%Y-%m-%d'):
        try:
            return datetime.strptime(raw.strip(), fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def extract_cve_list(raw: str) -> list[str]:
    """Estrai CVE ID multipli da stringa (comma-separated o space-separated)."""
    found = re.findall(r'\bCVE-\d{4}-\d{4,7}\b', raw, re.IGNORECASE)
    return list(dict.fromkeys(cve.upper() for cve in found))


def build_description(tags: dict, summary_fallback: str = "") -> str:
    """Assembla description_tool dai campi tags OpenVAS."""
    parts = []
    if tags.get('summary'):
        parts.append(tags['summary'])
    if tags.get('insight'):
        parts.append(f"Insight: {tags['insight']}")
    if tags.get('affected'):
        parts.append(f"Affected: {tags['affected']}")
    if tags.get('impact'):
        parts.append(f"Impact: {tags['impact']}")
    if tags.get('vuldetect'):
        parts.append(f"Detection: {tags['vuldetect']}")
    return "\n\n".join(p for p in parts if p) or summary_fallback


# ---------------------------------------------------------------------------
# FORMAT 1 — OpenVAS XML Parser
# ---------------------------------------------------------------------------

class OpenVasXmlParser(BaseParser):
    """
    Parser per OpenVAS/Greenbone XML (formato GMP).
    Struttura: <report> → <report> → <results> → <result>
    """

    SOURCE_TOOL = "openvas"

    def parse(self, source: bytes | str | Path) -> ScanImportResult:
        if isinstance(source, Path):
            source = source.read_bytes()
        if isinstance(source, str):
            source = source.encode('utf-8')

        try:
            root = ET.fromstring(source)
        except ET.ParseError as e:
            raise ValueError(f"XML OpenVAS non parsabile: {e}") from e

        result = ScanImportResult(source_tool=self.SOURCE_TOOL)

        # Naviga report > report (formato GMP nidificato)
        inner = root.find('report') if root.tag == 'report' else root
        if inner is None:
            inner = root

        # Metadati scansione
        result.scanner_version = ""
        gmp = inner.find('gmp')
        if gmp is not None:
            result.scanner_version = gmp.findtext('version') or ""

        scan_start = inner.findtext('scan_start') or ""
        result.scan_date = parse_openvas_datetime(scan_start)

        task_el = inner.find('task')
        if task_el is not None:
            result.scan_args = task_el.findtext('name') or ""

        # Raccolta host dalla sezione <host>
        hosts_map: dict[str, NormalizedHost] = {}
        for host_el in inner.findall('host'):
            ip  = host_el.findtext('ip') or ""
            if not ip:
                continue
            start = parse_openvas_datetime(host_el.findtext('start') or "")
            end   = parse_openvas_datetime(host_el.findtext('end') or "")
            h = NormalizedHost(
                ip_address  = ip,
                source_tool = self.SOURCE_TOOL,
                scan_start  = start,
                scan_end    = end,
            )
            hosts_map[ip] = h

        # Parsing results
        results_el = inner.find('results')
        if results_el is None:
            result.hosts = list(hosts_map.values())
            return result

        for res_el in results_el.findall('result'):
            try:
                vuln = self._parse_result(res_el)
                result.vulnerabilities.append(vuln)

                # Aggiorna hostname nell'host se presente nel result
                if vuln.affected_ip and vuln.affected_ip in hosts_map:
                    if vuln.affected_host and not hosts_map[vuln.affected_ip].hostname:
                        hosts_map[vuln.affected_ip].hostname = vuln.affected_host
                    # Aggiungi porta aperta
                    if vuln.affected_port:
                        hosts_map[vuln.affected_ip].open_ports.append({
                            "port": vuln.affected_port,
                            "protocol": vuln.affected_protocol,
                            "service": vuln.affected_service,
                            "state": "open",
                        })
                elif vuln.affected_ip:
                    # Host non in sezione <host> → crea on-the-fly
                    hosts_map[vuln.affected_ip] = NormalizedHost(
                        ip_address  = vuln.affected_ip,
                        hostname    = vuln.affected_host,
                        source_tool = self.SOURCE_TOOL,
                    )

            except Exception as e:
                rid = res_el.get('id', 'unknown')
                result.parse_errors.append(f"Result {rid}: {e}")
                logger.warning("Errore parsing result %s: %s", rid, e)

        result.hosts = list(hosts_map.values())
        return result

    def _parse_result(self, res_el: ET.Element) -> NormalizedVulnerability:
        result_id = res_el.get('id', '')

        # --- Host ---
        host_el   = res_el.find('host')
        ip        = (host_el.text or "").strip() if host_el is not None else ""
        hostname  = ""
        asset_id  = ""
        if host_el is not None:
            hostname_el = host_el.find('hostname')
            if hostname_el is not None:
                hostname = (hostname_el.text or "").strip()
            asset_el = host_el.find('asset')
            if asset_el is not None:
                asset_id = asset_el.get('asset_id', '')

        # --- Port ---
        port_raw = res_el.findtext('port') or ""
        port, protocol = parse_port_protocol(port_raw)

        # --- NVT ---
        nvt_el  = res_el.find('nvt')
        nvt_oid = nvt_el.get('oid', '') if nvt_el is not None else ''
        nvt_name   = ""
        nvt_family = ""
        cvss_score_tool: Optional[float] = None
        cvss_vector = ""
        solution_type = ""
        remediation = ""
        cve_ids: list[str] = []
        references: list[dict] = []
        tags: dict[str, str] = {}

        if nvt_el is not None:
            nvt_name   = nvt_el.findtext('name') or ""
            nvt_family = nvt_el.findtext('family') or ""

            # CVSS da severities (più preciso di cvss_base)
            severities_el = nvt_el.find('severities')
            if severities_el is not None:
                for sev_el in severities_el.findall('severity'):
                    if sev_el.get('type') in ('cvss_base_v3', 'cvss_base_v2'):
                        score_el = sev_el.find('score')
                        if score_el is not None and score_el.text:
                            cvss_score_tool = self.normalize_cvss(score_el.text)
                        value_el = sev_el.find('value')
                        if value_el is not None and value_el.text:
                            cvss_vector = value_el.text.strip()
                        break  # prendi il primo (v3 preferito)

            # Fallback cvss_base
            if cvss_score_tool is None:
                cvss_score_tool = self.normalize_cvss(nvt_el.findtext('cvss_base') or "")

            # Tags — contengono summary, insight, affected, impact, solution, vuldetect
            tags = parse_openvas_tags(nvt_el.findtext('tags') or "")

            # Solution
            sol_el = nvt_el.find('solution')
            if sol_el is not None:
                solution_type = sol_el.get('type', '')
                remediation   = (sol_el.text or "").strip()

            # Refs — CVE, URL, cert-bund, dfn-cert
            refs_el = nvt_el.find('refs')
            if refs_el is not None:
                for ref in refs_el.findall('ref'):
                    ref_type = ref.get('type', '')
                    ref_id   = ref.get('id', '')
                    if ref_type == 'cve' and ref_id:
                        cve_ids.extend(extract_cve_list(ref_id))
                    elif ref_type == 'url' and ref_id:
                        references.append({"url": ref_id, "type": "url"})
                    elif ref_type in ('cert-bund', 'dfn-cert') and ref_id:
                        references.append({"id": ref_id, "type": ref_type})

        # --- Severity ---
        threat_raw    = res_el.findtext('threat') or ""
        severity_tool = OPENVAS_THREAT_MAP.get(threat_raw.lower(), Severity.INFO)

        # CVSS dal campo severity (più affidabile di nvt/cvss_base)
        severity_raw = res_el.findtext('severity') or ""
        if severity_raw:
            parsed_score = self.normalize_cvss(severity_raw)
            if parsed_score is not None:
                cvss_score_tool = parsed_score
                # Se severity_tool è ancora INFO ma abbiamo uno score, ricalcola
                if severity_tool == Severity.INFO and parsed_score > 0:
                    severity_tool = Severity.from_cvss(parsed_score)

        # --- QOD (Quality of Detection) ---
        qod_el = res_el.find('qod')
        qod_value = ""
        if qod_el is not None:
            qod_val = qod_el.findtext('value') or ""
            qod_type = qod_el.findtext('type') or ""
            if qod_val:
                qod_value = f"QoD: {qod_val}%" + (f" ({qod_type})" if qod_type else "")

        # --- Description/Evidence ---
        description_raw = res_el.findtext('description') or ""
        description_tool = build_description(tags, nvt_name)
        evidence = description_raw.strip()
        if qod_value:
            evidence = f"{qod_value}\n\n{evidence}" if evidence else qod_value

        # --- Title ---
        title = nvt_name or res_el.findtext('name') or f"OpenVAS Finding {result_id[:8]}"

        # --- Remediation ---
        if not remediation and tags.get('solution'):
            remediation = tags['solution']

        # --- Enrichment status ---
        enrichment_status = (
            EnrichmentStatus.PENDING if cve_ids
            else EnrichmentStatus.SKIPPED
        )

        return NormalizedVulnerability(
            affected_ip       = ip,
            affected_host     = hostname,
            affected_port     = port,
            affected_protocol = protocol,
            affected_service  = nvt_family,
            title             = title,
            description_tool  = description_tool,
            severity_tool     = severity_tool,
            cvss_score_tool   = cvss_score_tool,
            cve_ids_tool      = list(dict.fromkeys(cve_ids)),  # dedup
            evidence          = evidence,
            remediation_tool  = remediation,
            references_tool   = references,
            source_tool       = self.SOURCE_TOOL,
            source_script     = nvt_oid,
            raw_output        = ET.tostring(res_el, encoding='unicode'),
            nvd_enrichment_status = enrichment_status,
        )


# ---------------------------------------------------------------------------
# FORMAT 2 — OpenVAS CSV Parser
# ---------------------------------------------------------------------------

class OpenVasCsvParser(BaseParser):
    """
    Parser per OpenVAS/Greenbone CSV export.
    Header fisso: IP|Hostname|Port|Port Protocol|CVSS|Severity|
                  Solution Type|NVT Name|Summary|Specific Result|
                  NVT OID|CVEs|Task ID|Task Name|Timestamp|Result ID|
                  Impact|Solution|Affected Software/OS|
                  Vulnerability Insight|Vulnerability Detection Method|
                  Product Detection Result|BIDs|CERTs|Other References
    """

    SOURCE_TOOL = "openvas"

    # Mapping colonne OpenVAS CSV → campo interno
    COLUMN_MAP = {
        'IP':                          'ip',
        'Hostname':                    'hostname',
        'Port':                        'port',
        'Port Protocol':               'protocol',
        'CVSS':                        'cvss_score',
        'Severity':                    'severity',
        'Solution Type':               'solution_type',
        'NVT Name':                    'title',
        'Summary':                     'summary',
        'Specific Result':             'specific_result',
        'NVT OID':                     'nvt_oid',
        'CVEs':                        'cves',
        'Task ID':                     'task_id',
        'Task Name':                   'task_name',
        'Timestamp':                   'timestamp',
        'Result ID':                   'result_id',
        'Impact':                      'impact',
        'Solution':                    'solution',
        'Affected Software/OS':        'affected',
        'Vulnerability Insight':       'insight',
        'Vulnerability Detection Method': 'vuldetect',
        'Product Detection Result':    'product_detection',
        'BIDs':                        'bids',
        'CERTs':                       'certs',
        'Other References':            'other_refs',
    }

    def parse(self, source: bytes | str | Path) -> ScanImportResult:
        if isinstance(source, Path):
            source = source.read_bytes()
        if isinstance(source, bytes):
            source = source.decode('utf-8', errors='replace')

        result = ScanImportResult(source_tool=self.SOURCE_TOOL)
        hosts_map: dict[str, NormalizedHost] = {}

        reader = csv.DictReader(io.StringIO(source))

        for row_num, row in enumerate(reader, start=2):
            try:
                vuln = self._parse_row(row)
                if vuln is None:
                    continue
                result.vulnerabilities.append(vuln)

                ip_key = vuln.affected_ip or vuln.affected_host
                if ip_key and ip_key not in hosts_map:
                    hosts_map[ip_key] = NormalizedHost(
                        ip_address  = vuln.affected_ip,
                        hostname    = vuln.affected_host,
                        source_tool = self.SOURCE_TOOL,
                    )
            except Exception as e:
                result.parse_errors.append(f"Row {row_num}: {e}")

        result.hosts = list(hosts_map.values())
        return result

    def _parse_row(self, row: dict) -> Optional[NormalizedVulnerability]:
        get = lambda k: (row.get(k) or "").strip()

        ip       = get('IP')
        hostname = get('Hostname')
        if not ip and not hostname:
            return None

        port, protocol = parse_port_protocol(
            get('Port') + ('/' + get('Port Protocol') if get('Port Protocol') else '')
        )

        cvss_score = self.normalize_cvss(get('CVSS'))
        severity_raw = get('Severity').lower()
        severity_tool = OPENVAS_THREAT_MAP.get(severity_raw)
        if severity_tool is None and cvss_score is not None:
            severity_tool = Severity.from_cvss(cvss_score)
        severity_tool = severity_tool or Severity.INFO

        title     = get('NVT Name') or get('NVT_Name') or "OpenVAS Finding"
        summary   = get('Summary')
        insight   = get('Vulnerability Insight')
        impact    = get('Impact')
        vuldetect = get('Vulnerability Detection Method')
        affected  = get('Affected Software/OS')
        specific  = get('Specific Result')
        solution  = get('Solution')
        nvt_oid   = get('NVT OID')
        cves_raw  = get('CVEs')
        timestamp = get('Timestamp')

        # Assembla description
        desc_parts = []
        if summary:   desc_parts.append(summary)
        if insight:   desc_parts.append(f"Insight: {insight}")
        if affected:  desc_parts.append(f"Affected: {affected}")
        if impact:    desc_parts.append(f"Impact: {impact}")
        if vuldetect: desc_parts.append(f"Detection: {vuldetect}")
        description_tool = "\n\n".join(desc_parts)

        # Evidence = specific result (output effettivo della scansione)
        evidence = specific

        cve_ids = extract_cve_list(cves_raw)

        scan_date = parse_openvas_datetime(timestamp)

        enrichment_status = (
            EnrichmentStatus.PENDING if cve_ids
            else EnrichmentStatus.SKIPPED
        )

        return NormalizedVulnerability(
            affected_ip       = ip,
            affected_host     = hostname,
            affected_port     = port,
            affected_protocol = protocol,
            title             = title,
            description_tool  = description_tool,
            severity_tool     = severity_tool,
            cvss_score_tool   = cvss_score,
            cve_ids_tool      = cve_ids,
            evidence          = evidence,
            remediation_tool  = solution,
            source_tool       = self.SOURCE_TOOL,
            source_script     = nvt_oid,
            raw_output        = str(row),
            nvd_enrichment_status = enrichment_status,
        )


# ---------------------------------------------------------------------------
# FORMAT 3 — Nessus CSV Parser
# ---------------------------------------------------------------------------

class NessusCsvParser(BaseParser):
    """
    Parser per Nessus CSV export.
    Header: Plugin ID|CVE|CVSS v2.0 Base Score|Risk|Host|Protocol|Port|
            Name|Synopsis|Description|Solution|See Also|Plugin Output|
            Risk Factor|BID|XREF|MSKB
    """

    SOURCE_TOOL = "nessus"

    def parse(self, source: bytes | str | Path) -> ScanImportResult:
        if isinstance(source, Path):
            source = source.read_bytes()
        if isinstance(source, bytes):
            source = source.decode('utf-8', errors='replace')

        result = ScanImportResult(source_tool=self.SOURCE_TOOL)
        hosts_map: dict[str, NormalizedHost] = {}

        reader = csv.DictReader(io.StringIO(source))

        for row_num, row in enumerate(reader, start=2):
            try:
                vuln = self._parse_row(row)
                if vuln is None:
                    continue
                result.vulnerabilities.append(vuln)

                ip_key = vuln.affected_ip
                if ip_key and ip_key not in hosts_map:
                    hosts_map[ip_key] = NormalizedHost(
                        ip_address  = ip_key,
                        source_tool = self.SOURCE_TOOL,
                    )
            except Exception as e:
                result.parse_errors.append(f"Row {row_num}: {e}")

        result.hosts = list(hosts_map.values())
        return result

    def _parse_row(self, row: dict) -> Optional[NormalizedVulnerability]:
        get = lambda k: (row.get(k) or "").strip()

        ip   = get('Host')
        port_raw = get('Port')
        proto_raw = get('Protocol')

        if not ip:
            return None

        port, protocol = parse_port_protocol(
            port_raw + ('/' + proto_raw if proto_raw else '')
        )

        cvss_raw   = get('CVSS v2.0 Base Score')
        cvss_score = self.normalize_cvss(cvss_raw)

        risk_raw      = get('Risk').lower()
        risk_factor   = get('Risk Factor').lower()
        severity_raw  = risk_factor or risk_raw
        severity_tool = NESSUS_RISK_MAP.get(severity_raw)
        if severity_tool is None and cvss_score is not None:
            severity_tool = Severity.from_cvss(cvss_score)
        severity_tool = severity_tool or Severity.INFO

        title       = get('Name') or f"Nessus Plugin {get('Plugin ID')}"
        synopsis    = get('Synopsis')
        description = get('Description')
        solution    = get('Solution')
        see_also    = get('See Also')
        output      = get('Plugin Output')
        plugin_id   = get('Plugin ID')
        cve_raw     = get('CVE')
        bid         = get('BID')
        xref        = get('XREF')

        # description_tool: synopsis + description
        desc_parts = []
        if synopsis:    desc_parts.append(synopsis)
        if description: desc_parts.append(description)
        description_tool = "\n\n".join(desc_parts)

        # references
        refs = []
        if see_also:
            for url in re.split(r'[\n,;]+', see_also):
                url = url.strip()
                if url.startswith('http'):
                    refs.append({"url": url, "type": "reference"})
        if xref:
            for x in re.split(r'[,;]+', xref):
                x = x.strip()
                if x:
                    refs.append({"id": x, "type": "xref"})

        cve_ids = extract_cve_list(cve_raw)

        enrichment_status = (
            EnrichmentStatus.PENDING if cve_ids
            else EnrichmentStatus.SKIPPED
        )

        return NormalizedVulnerability(
            affected_ip       = ip,
            affected_port     = port,
            affected_protocol = protocol,
            title             = title,
            description_tool  = description_tool,
            severity_tool     = severity_tool,
            cvss_score_tool   = cvss_score,
            cve_ids_tool      = cve_ids,
            evidence          = output,
            remediation_tool  = solution,
            references_tool   = refs,
            source_tool       = self.SOURCE_TOOL,
            source_script     = plugin_id,
            raw_output        = str(row),
            nvd_enrichment_status = enrichment_status,
        )


# ---------------------------------------------------------------------------
# Auto-detect parser
# ---------------------------------------------------------------------------

def detect_and_parse(source: bytes | str | Path) -> ScanImportResult:
    """
    Rileva automaticamente il formato e usa il parser corretto.
    Ordine di detection:
      1. Se bytes/str contiene <report ... format_id="a994b278..."> → OpenVAS XML
      2. Se CSV con header 'IP,Hostname,Port,Port Protocol' → OpenVAS CSV
      3. Se CSV con header 'Plugin ID,CVE,CVSS v2.0 Base Score' → Nessus CSV
    """
    if isinstance(source, Path):
        raw = source.read_bytes()
        source_bytes = raw
    elif isinstance(source, str):
        source_bytes = source.encode('utf-8')
        raw = source_bytes
    else:
        source_bytes = source
        raw = source

    # Prova XML
    if raw.lstrip()[:1] == b'<':
        return OpenVasXmlParser().parse(source_bytes)

    # CSV detection
    try:
        text = raw.decode('utf-8', errors='replace')
        first_line = text.split('\n')[0]
        # Nessus: ha 'CVSS v2.0 Base Score' e 'Risk Factor' (con o senza Plugin ID)
        if 'CVSS v2.0 Base Score' in first_line and 'Risk' in first_line:
            return NessusCsvParser().parse(text)
        if 'NVT Name' in first_line or ('IP' in first_line and 'NVT OID' in first_line):
            return OpenVasCsvParser().parse(text)
    except Exception:
        pass

    raise ValueError("Formato non riconosciuto. Attesi: OpenVAS XML, OpenVAS CSV, Nessus CSV")
