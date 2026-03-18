"""
CyberReport Pro — Burp Suite XML Parser
========================================
Parser per export XML di Burp Suite Pro/Enterprise.

Gestisce:
  - XML v1.0 e v1.1 (Burp usa 1.1 che Python xml non supporta nativamente)
  - Request/Response in chiaro e in base64
  - Tutti i tipi di issue: DAST, DOM-based, staticAnalysis, dynamicAnalysis,
    collaboratorEvent (SSRF/Out-of-band), prototypePollution
  - HTML entities e CDATA nei campi testuali
  - vulnerabilityClassifications con CWE links embedded
  - issueDetailItems (lista di occorrenze multiple)

Struttura XML Burp:
  <issues burpVersion="..." exportTime="...">
    <issue>
      <serialNumber>     → ID univoco Burp
      <type>             → tipo numerico Burp (es. 134217728)
      <name>             → titolo issue (CDATA)
      <host ip="...">    → hostname con IP come attributo (CDATA)
      <path>             → path URL (CDATA)
      <location>         → location con parametro (CDATA)
      <severity>         → High|Medium|Low|Information|False positive
      <confidence>       → Certain|Firm|Tentative
      <issueBackground>  → descrizione generale (HTML+CDATA)
      <remediationBackground> → remediation generale (HTML+CDATA)
      <references>       → link HTML (CDATA)
      <vulnerabilityClassifications> → CWE links HTML (CDATA)
      <issueDetail>      → dettaglio specifico occorrenza (HTML+CDATA)
      <issueDetailItems> → lista <issueDetailItem> per occorrenze multiple
      <remediationDetail> → fix specifico (HTML+CDATA)
      <requestresponse>  → request + response (base64 o plain)
      <dynamicAnalysis>  → source/sink/poc per DOM-based
      <staticAnalysis>   → source/sink/codeSnippets per static
      <collaboratorEvent> → SSRF/OOB interaction details
      <prototypePollution> → poc/technique/type
    </issue>
  </issues>

Mapping → canonical_schema.NormalizedVulnerability:
  Sezione A (parser fills):
    affected_ip          ← host/@ip
    affected_host        ← host/text() (strippato schema)
    affected_port        ← derivato da host (https→443, http→80)
    affected_protocol    ← "tcp"
    affected_service     ← derivato da schema host
    affected_url         ← host + path
    http_method          ← request/@method
    title                ← name (CDATA cleaned)
    description_tool     ← issueBackground + issueDetail (HTML→plain)
    severity_tool        ← severity (Burp → Severity enum)
    cve_ids_tool         ← estratti da references + vulnerabilityClassifications
    cpe_tool             ← ""  (Burp non fornisce CPE)
    evidence             ← issueDetail + issueDetailItems
    evidence_request     ← request (decoded se base64)
    evidence_response    ← response (decoded se base64, troncato)
    remediation_tool     ← remediationBackground + remediationDetail
    references_tool      ← estratti da references (HTML links)
    source_tool          ← "burp"
    source_script        ← type (numerico Burp)
    raw_output           ← issue XML grezzo

  Sezione B (NVD enricher fills — parser lascia None):
    cwe_id               ← estratto da vulnerabilityClassifications (CWE link)
    [tutti gli altri campi NVD]

Author: CyberReport Pro
"""

from __future__ import annotations

import base64
import html
import logging
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional

from cyberreport_pro_parsers.parsers.canonical_schema import (
    BaseParser,
    NormalizedHost,
    NormalizedVulnerability,
    ScanImportResult,
    Severity,
    EnrichmentStatus,
)

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Costanti Burp
# ---------------------------------------------------------------------------

# Severity Burp → Severity enum
BURP_SEVERITY_MAP: dict[str, Severity] = {
    "high":            Severity.HIGH,
    "medium":          Severity.MEDIUM,
    "low":             Severity.LOW,
    "information":     Severity.INFO,
    "informational":   Severity.INFO,
    "info":            Severity.INFO,
    "false positive":  Severity.INFO,
}

# Burp type ID noti → nome canonico (subset dei più comuni)
BURP_TYPE_NAMES: dict[str, str] = {
    "1":          "SQL Injection",
    "2":          "Blind SQL Injection",
    "3":          "OS Command Injection",
    "4":          "XML/SOAP Injection",
    "5":          "LDAP Injection",
    "6":          "XPath Injection",
    "16777216":   "Reflected XSS",
    "16777217":   "Stored XSS",
    "5243392":    "DOM-based XSS",
    "5244416":    "DOM-based open redirection",
    "5245696":    "DOM-based cookie manipulation",
    "5246208":    "DOM-based JavaScript injection",
    "134217728":  "SSRF / Out-of-band interaction",
    "134217984":  "Blind SSRF",
    "2097152":    "Cross-site request forgery",
    "33554432":   "Path traversal",
    "2359296":    "HTTP header injection",
    "33554688":   "File path traversal",
}


# ---------------------------------------------------------------------------
# Utilità
# ---------------------------------------------------------------------------

def xml11_to_xml10(raw: bytes) -> bytes:
    """
    Burp esporta XML 1.1 che Python xml.etree non supporta.
    Soluzione: sostituisci la dichiarazione XML 1.1 → 1.0.
    I NULL bytes vengono rimossi (il commento Burp lo avvisa).
    """
    raw = raw.replace(b'\x00', b'')
    raw = raw.replace(b'<?xml version="1.1"?>', b'<?xml version="1.0"?>')
    raw = raw.replace(b"<?xml version='1.1'?>", b"<?xml version='1.0'?>")
    return raw


def strip_html(text: str) -> str:
    """
    Rimuovi tag HTML e decodifica entities.
    Mantieni newline dai <br> e fine paragrafo dai <p>.
    """
    if not text:
        return ""
    # <br> → newline
    text = re.sub(r'<br\s*/?>', '\n', text, flags=re.IGNORECASE)
    # </p> → doppio newline
    text = re.sub(r'</p>', '\n\n', text, flags=re.IGNORECASE)
    # <li> → bullet
    text = re.sub(r'<li>', '• ', text, flags=re.IGNORECASE)
    # Rimuovi tutti i tag rimasti
    text = re.sub(r'<[^>]+>', '', text)
    # Decodifica HTML entities
    text = html.unescape(text)
    # Normalizza whitespace multipli (ma preserva newline)
    text = re.sub(r'[ \t]+', ' ', text)
    text = re.sub(r'\n{3,}', '\n\n', text)
    return text.strip()


def extract_cdata(element: Optional[ET.Element]) -> str:
    """Estrai testo da un elemento, gestendo CDATA e text() normale."""
    if element is None:
        return ""
    text = element.text or ""
    return text.strip()


def extract_cwe_ids(html_text: str) -> list[str]:
    """
    Estrai CWE ID da testo HTML con link tipo:
    <a href="https://cwe.mitre.org/data/definitions/79.html">CWE-79: ...</a>
    """
    cwe_ids: list[str] = []
    # Pattern 1: da href CWE mitre
    for m in re.finditer(r'cwe\.mitre\.org/data/definitions/(\d+)\.html', html_text):
        cwe_ids.append(f"CWE-{m.group(1)}")
    # Pattern 2: testo esplicito CWE-NNN
    for m in re.finditer(r'\bCWE-(\d+)\b', html_text, re.IGNORECASE):
        cwe_ids.append(f"CWE-{m.group(1).upper()}")
    # Dedup mantenendo ordine
    return list(dict.fromkeys(cwe_ids))


def extract_reference_urls(html_text: str) -> list[dict]:
    """
    Estrai URL da HTML con link tipo:
    <a href="https://...">testo</a>
    Ritorna: [{"url": "...", "title": "..."}]
    """
    refs = []
    for m in re.finditer(r'<a\s+href="([^"]+)"[^>]*>(.*?)</a>', html_text, re.IGNORECASE | re.DOTALL):
        url   = m.group(1).strip()
        title = strip_html(m.group(2)).strip()
        if url and url.startswith('http'):
            refs.append({"url": url, "title": title, "type": "reference"})
    return refs


def parse_host(host_text: str, host_ip: str) -> tuple[str, str, Optional[int], str]:
    """
    Estrai (ip, hostname, port, service) da host Burp.
    host_text es: "https://www.ikea.com" o "http://10.0.0.1:8080"
    host_ip: attributo ip dell'elemento host
    Ritorna: (ip, hostname, port, service)
    """
    ip = host_ip.strip() if host_ip else ""

    # Rimuovi CDATA wrapper se presente
    host_clean = re.sub(r'<!\[CDATA\[|\]\]>', '', host_text).strip()

    # Determina schema e porta di default
    if host_clean.startswith('https://'):
        default_port = 443
        service = "https"
        host_clean = host_clean[8:]
    elif host_clean.startswith('http://'):
        default_port = 80
        service = "http"
        host_clean = host_clean[7:]
    else:
        default_port = 443
        service = "https"

    # Gestisci porta esplicita: host:8080
    port = default_port
    hostname = host_clean
    port_match = re.search(r':(\d+)$', host_clean)
    if port_match:
        port = int(port_match.group(1))
        hostname = host_clean[:port_match.start()]

    # Se hostname è un IP, spostalo in ip
    if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', hostname):
        if not ip:
            ip = hostname
        hostname = ""

    return ip, hostname, port, service


def decode_request(req_element: Optional[ET.Element]) -> tuple[str, str]:
    """
    Decodifica request element.
    Ritorna: (method, request_text)
    base64=true → decodifica
    base64=false → usa testo diretto
    """
    if req_element is None:
        return "", ""

    method = req_element.get("method", "")
    b64    = req_element.get("base64", "false").lower() == "true"
    text   = req_element.text or ""

    if b64:
        try:
            decoded = base64.b64decode(text.strip()).decode("utf-8", errors="replace")
            return method, decoded
        except Exception as e:
            logger.warning("Errore decode base64 request: %s", e)
            return method, text
    return method, text


def decode_response(resp_element: Optional[ET.Element], max_bytes: int = 4096) -> str:
    """
    Decodifica response element, troncata a max_bytes.
    """
    if resp_element is None:
        return ""

    b64  = resp_element.get("base64", "false").lower() == "true"
    text = resp_element.text or ""

    if b64:
        try:
            decoded = base64.b64decode(text.strip()).decode("utf-8", errors="replace")
            return decoded[:max_bytes]
        except Exception:
            return text[:max_bytes]
    return text[:max_bytes]


def extract_dynamic_analysis(dyn_el: Optional[ET.Element]) -> str:
    """
    Estrai informazioni utili da <dynamicAnalysis>.
    Ritorna una stringa formattata con source/sink/poc/origin.
    """
    if dyn_el is None:
        return ""

    parts = []
    for field_name, label in [
        ("source",    "Source"),
        ("sink",      "Sink"),
        ("sourceValue", "Source Value"),
        ("sinkValue",   "Sink Value"),
        ("poc",         "PoC"),
        ("origin",      "Origin"),
        ("isOriginChecked", "Origin Checked"),
    ]:
        el = dyn_el.find(field_name)
        if el is not None and el.text:
            val = el.text.strip()
            if val:
                parts.append(f"{label}: {val[:200]}")

    return "\n".join(parts)


def extract_static_analysis(static_el: Optional[ET.Element]) -> str:
    """Estrai source/sink/codeSnippets da <staticAnalysis>."""
    if static_el is None:
        return ""
    parts = []
    for field_name, label in [("source","Source"), ("sink","Sink")]:
        el = static_el.find(field_name)
        if el is not None and el.text:
            parts.append(f"{label}: {el.text.strip()[:200]}")
    snippets = static_el.findall("codeSnippets/codeSnippet")
    for i, s in enumerate(snippets[:3]):
        if s.text:
            parts.append(f"Code Snippet {i+1}: {s.text.strip()[:200]}")
    return "\n".join(parts)


def extract_collaborator_event(collab_el: Optional[ET.Element]) -> str:
    """Estrai info SSRF/OOB da <collaboratorEvent>."""
    if collab_el is None:
        return ""
    parts = []
    for field_name, label in [
        ("interactionType", "Interaction Type"),
        ("originIp",        "Origin IP"),
        ("time",            "Time"),
        ("lookupType",      "Lookup Type"),
        ("lookupHost",      "Lookup Host"),
    ]:
        el = collab_el.find(field_name)
        if el is not None and el.text:
            parts.append(f"{label}: {el.text.strip()}")
    return "\n".join(parts)


# ---------------------------------------------------------------------------
# Parser principale
# ---------------------------------------------------------------------------

class BurpParser(BaseParser):
    """
    Parser per Burp Suite XML export.

    Gestisce XML v1.0 e v1.1, request/response base64 o plain,
    tutti i tipi di analysis (dynamic, static, collaborator).

    Mapping verso canonical_schema.NormalizedVulnerability:
    - Sezione A compilata dal parser
    - Sezione B lasciata None (NVD Enricher)
    - CWE estratti da vulnerabilityClassifications → cwe_id (pre-enrichment hint)
    """

    SOURCE_TOOL = "burp"

    def parse(self, source: bytes | str | Path) -> ScanImportResult:
        if isinstance(source, Path):
            source = source.read_bytes()
        if isinstance(source, str):
            source = source.encode("utf-8")

        # Fix XML 1.1 → 1.0 e rimuovi NULL bytes
        source = xml11_to_xml10(source)

        try:
            root = ET.fromstring(source)
        except ET.ParseError as e:
            # Tentativo di recupero: rimuovi DOCTYPE per parser più permissivo
            cleaned = re.sub(rb'<!DOCTYPE[^>]*>', b'', source, flags=re.DOTALL)
            cleaned = re.sub(rb'<!ELEMENT[^>]*>', b'', cleaned)
            cleaned = re.sub(rb'<!ATTLIST[^>]*>', b'', cleaned)
            try:
                root = ET.fromstring(cleaned)
            except ET.ParseError as e2:
                raise ValueError(f"XML Burp non parsabile: {e2}") from e2

        result = ScanImportResult(source_tool=self.SOURCE_TOOL)

        # Metadati scansione
        result.scanner_version = root.get("burpVersion", "")
        export_time_str = root.get("exportTime", "")
        result.scan_date = self._parse_burp_date(export_time_str)

        # Host univoci (un host per hostname+ip)
        hosts_seen: dict[str, NormalizedHost] = {}

        # Itera tutti gli issue
        for issue_el in root.findall("issue"):
            try:
                vuln, host = self._parse_issue(issue_el)
                result.vulnerabilities.append(vuln)

                # Aggiungi host se non già visto
                host_key = host.ip_address or host.hostname
                if host_key and host_key not in hosts_seen:
                    hosts_seen[host_key] = host

            except Exception as e:
                serial = ""
                sn_el = issue_el.find("serialNumber")
                if sn_el is not None:
                    serial = sn_el.text or ""
                result.parse_errors.append(f"Issue {serial}: {e}")
                logger.warning("Errore parsing issue %s: %s", serial, e)

        result.hosts = list(hosts_seen.values())
        return result

    # ------------------------------------------------------------------
    # Issue parsing
    # ------------------------------------------------------------------

    def _parse_issue(self, issue_el: ET.Element) -> tuple[NormalizedVulnerability, NormalizedHost]:
        """Converte un <issue> element in (NormalizedVulnerability, NormalizedHost)."""

        # --- Campi base ---
        serial    = extract_cdata(issue_el.find("serialNumber"))
        type_id   = extract_cdata(issue_el.find("type"))
        name_raw  = extract_cdata(issue_el.find("name"))
        title     = strip_html(name_raw) or BURP_TYPE_NAMES.get(type_id, f"Burp Issue {type_id}")

        # --- Host ---
        host_el   = issue_el.find("host")
        host_text = extract_cdata(host_el) if host_el is not None else ""
        host_ip_attr = host_el.get("ip", "") if host_el is not None else ""
        ip, hostname, port, service = parse_host(host_text, host_ip_attr)

        # --- Path e Location ---
        path_raw  = extract_cdata(issue_el.find("path"))
        path      = strip_html(path_raw)
        location  = strip_html(extract_cdata(issue_el.find("location")))
        affected_url = (host_text.rstrip('/') + path) if host_text and path else ""

        # --- Severity e Confidence ---
        severity_raw  = extract_cdata(issue_el.find("severity")).strip().lower()
        confidence_raw = extract_cdata(issue_el.find("confidence")).strip()
        severity_tool = BURP_SEVERITY_MAP.get(severity_raw, Severity.INFO)

        # --- Testi descrittivi ---
        issue_bg   = extract_cdata(issue_el.find("issueBackground"))
        issue_det  = extract_cdata(issue_el.find("issueDetail"))
        remed_bg   = extract_cdata(issue_el.find("remediationBackground"))
        remed_det  = extract_cdata(issue_el.find("remediationDetail"))
        references_raw = extract_cdata(issue_el.find("references"))
        vuln_class_raw = extract_cdata(issue_el.find("vulnerabilityClassifications"))

        # issueDetailItems → lista di occorrenze
        detail_items_el = issue_el.find("issueDetailItems")
        detail_items: list[str] = []
        if detail_items_el is not None:
            for item_el in detail_items_el.findall("issueDetailItem"):
                item_text = strip_html(extract_cdata(item_el))
                if item_text:
                    detail_items.append(item_text)

        # Assembla description_tool: background + detail
        description_parts = []
        if issue_bg:
            description_parts.append(strip_html(issue_bg))
        if issue_det:
            description_parts.append(strip_html(issue_det))
        description_tool = "\n\n".join(p for p in description_parts if p)

        # Evidence: detail + items
        evidence_parts = []
        if issue_det:
            evidence_parts.append(strip_html(issue_det))
        for item in detail_items:
            evidence_parts.append(f"• {item}")
        evidence = "\n".join(evidence_parts)

        # Remediation: background + detail
        remed_parts = []
        if remed_bg:
            remed_parts.append(strip_html(remed_bg))
        if remed_det:
            remed_parts.append(strip_html(remed_det))
        remediation_tool = "\n\n".join(p for p in remed_parts if p)

        # --- CWE da vulnerabilityClassifications ---
        cwe_ids = extract_cwe_ids(vuln_class_raw)
        primary_cwe = cwe_ids[0] if cwe_ids else ""

        # --- CVE da references ---
        cve_ids = self.normalize_cve_ids(references_raw + " " + issue_det)

        # --- References ---
        references_tool = extract_reference_urls(references_raw)
        # Aggiungi vuln classifications come reference
        vuln_class_links = extract_reference_urls(vuln_class_raw)
        references_tool.extend(vuln_class_links)

        # --- Request / Response ---
        rr_el = issue_el.find("requestresponse")
        method = ""
        evidence_request = ""
        evidence_response = ""

        if rr_el is not None:
            req_el  = rr_el.find("request")
            resp_el = rr_el.find("response")
            method, evidence_request  = decode_request(req_el)
            evidence_response = decode_response(resp_el)

            # Se method non era nell'attributo, prova a estrarlo dalla prima riga
            if not method and evidence_request:
                first_line = evidence_request.split('\n')[0].strip()
                m = re.match(r'^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS|TRACE)\s', first_line)
                if m:
                    method = m.group(1)

        # --- Analisi speciale per tipi DOM/Static/Collaborator ---
        extra_evidence_parts: list[str] = []

        dyn_el    = issue_el.find("dynamicAnalysis")
        static_el = issue_el.find("staticAnalysis")
        pp_el     = issue_el.find("prototypePollution")

        for collab_el in issue_el.findall("collaboratorEvent"):
            collab_info = extract_collaborator_event(collab_el)
            if collab_info:
                extra_evidence_parts.append(f"[Collaborator Event]\n{collab_info}")

        if dyn_el is not None:
            dyn_info = extract_dynamic_analysis(dyn_el)
            if dyn_info:
                extra_evidence_parts.append(f"[Dynamic Analysis]\n{dyn_info}")

        if static_el is not None:
            static_info = extract_static_analysis(static_el)
            if static_info:
                extra_evidence_parts.append(f"[Static Analysis]\n{static_info}")

        if pp_el is not None:
            poc_el  = pp_el.find("poc")
            tech_el = pp_el.find("pollutionTechnique")
            type_el = pp_el.find("pollutionType")
            pp_parts = []
            if poc_el is not None and poc_el.text:
                pp_parts.append(f"PoC: {poc_el.text.strip()[:200]}")
            if tech_el is not None and tech_el.text:
                pp_parts.append(f"Technique: {tech_el.text.strip()}")
            if type_el is not None and type_el.text:
                pp_parts.append(f"Type: {type_el.text.strip()}")
            if pp_parts:
                extra_evidence_parts.append(f"[Prototype Pollution]\n" + "\n".join(pp_parts))

        if extra_evidence_parts:
            if evidence:
                evidence += "\n\n"
            evidence += "\n\n".join(extra_evidence_parts)

        # Aggiungi location all'evidence se informativa
        if location and location not in evidence:
            evidence = f"Location: {location}\n\n" + evidence if evidence else f"Location: {location}"

        # --- Confidence nell'evidence ---
        if confidence_raw:
            evidence = f"Confidence: {confidence_raw}\n" + evidence

        # --- Determina enrichment status ---
        enrichment_status = (
            EnrichmentStatus.PENDING if cve_ids
            else EnrichmentStatus.SKIPPED
        )

        # --- NormalizedVulnerability ---
        vuln = NormalizedVulnerability(
            # Host
            affected_ip       = ip,
            affected_host     = hostname,
            affected_port     = port,
            affected_protocol = "tcp",
            affected_service  = service,
            affected_url      = affected_url,
            http_method       = method,
            # Vuln
            title             = title,
            description_tool  = description_tool,
            severity_tool     = severity_tool,
            cvss_score_tool   = None,       # Burp non fornisce CVSS → NVD
            cve_ids_tool      = cve_ids,
            cpe_tool          = "",
            # Evidence
            evidence          = evidence,
            evidence_request  = evidence_request,
            evidence_response = evidence_response,
            # Remediation
            remediation_tool  = remediation_tool,
            references_tool   = references_tool,
            # Metadati
            source_tool       = self.SOURCE_TOOL,
            source_script     = type_id,
            raw_output        = ET.tostring(issue_el, encoding="unicode"),
            # Stato
            nvd_enrichment_status = enrichment_status,
        )

        # CWE hint pre-enrichment: salvato in cwe_id come hint
        # (NVD Enricher sovrascriverà con il valore autoritativo)
        if primary_cwe:
            vuln.cwe_id = primary_cwe
            vuln.cwe_ids = cwe_ids

        # --- NormalizedHost ---
        host = NormalizedHost(
            ip_address  = ip,
            hostname    = hostname,
            source_tool = self.SOURCE_TOOL,
            open_ports  = [{"port": port, "protocol": "tcp",
                            "service": service, "state": "open"}],
        )

        return vuln, host

    # ------------------------------------------------------------------
    # Utilities
    # ------------------------------------------------------------------

    @staticmethod
    def _parse_burp_date(date_str: str) -> Optional[datetime]:
        """
        Parse Burp exportTime: "Fri May 16 16:32:00 CEST 2025"
        → datetime (UTC approssimato, timezone ignorata)
        """
        if not date_str:
            return None
        # Rimuovi timezone abbreviata (CEST, CET, UTC, etc.)
        clean = re.sub(r'\s+[A-Z]{2,5}\s+', ' ', date_str).strip()
        for fmt in (
            "%a %b %d %H:%M:%S %Y",
            "%Y-%m-%dT%H:%M:%S",
            "%Y-%m-%d %H:%M:%S",
        ):
            try:
                return datetime.strptime(clean, fmt)
            except ValueError:
                continue
        return None
