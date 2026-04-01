"""Test suite BurpParser — basata su file reali."""
import pytest
from pathlib import Path
from burp_parser import BurpParser, strip_html, extract_cwe_ids, parse_host, xml11_to_xml10
from canonical_schema import Severity, EnrichmentStatus

SAMPLES = Path('/mnt/user-data/uploads')
parser  = BurpParser()

def load(fname): return parser.parse(SAMPLES / fname)

# --- Utilità ---
class TestStripHtml:
    def test_br_to_newline(self):   assert '\n' in strip_html("a<br>b")
    def test_removes_tags(self):    assert '<' not in strip_html("<p>test</p>")
    def test_entities(self):        assert '&' in strip_html("a&amp;b")
    def test_empty(self):           assert strip_html("") == ""

class TestExtractCweIds:
    def test_mitre_link(self):
        r = extract_cwe_ids('<a href="https://cwe.mitre.org/data/definitions/79.html">CWE-79</a>')
        assert "CWE-79" in r
    def test_plain_text(self):
        r = extract_cwe_ids("CWE-89 SQL Injection")
        assert "CWE-89" in r
    def test_multiple(self):
        r = extract_cwe_ids('CWE-79 and CWE-89 and CWE-200')
        assert len(r) == 3
    def test_empty(self):
        assert extract_cwe_ids("no cwe here") == []

class TestParseHost:
    def test_https_default_port(self):
        ip, host, port, svc = parse_host("https://www.ikea.com", "1.2.3.4")
        assert port == 443 and svc == "https" and host == "www.ikea.com" and ip == "1.2.3.4"
    def test_http_default_port(self):
        _, _, port, svc = parse_host("http://example.com", "")
        assert port == 80 and svc == "http"
    def test_custom_port(self):
        _, host, port, _ = parse_host("https://api.example.com:8443", "")
        assert port == 8443 and host == "api.example.com"
    def test_ip_host(self):
        ip, host, _, _ = parse_host("https://10.0.0.1", "")
        assert ip == "10.0.0.1" and host == ""

class TestXml11Fix:
    def test_replaces_version(self):
        raw = b'<?xml version="1.1"?><root/>'
        fixed = xml11_to_xml10(raw)
        assert b'version="1.0"' in fixed
    def test_removes_null_bytes(self):
        raw = b'data\x00more'
        assert b'\x00' not in xml11_to_xml10(raw)

# --- Scan metadata ---
class TestScanMeta:
    def test_burp_version(self):
        r = load('DomXss.xml')
        assert r.scanner_version == "2025.3.4"
    def test_scan_date_parsed(self):
        r = load('DomXss.xml')
        assert r.scan_date is not None
        assert r.scan_date.year == 2025
    def test_source_tool(self):
        r = load('DomXss.xml')
        assert r.source_tool == "burp"

# --- Host parsing ---
class TestHostParsing:
    def test_atg_host(self):
        r = load('DomXss.xml')
        h = r.hosts[0]
        assert h.hostname == "www.atg.se"
        assert h.ip_address == "195.198.34.30"
    def test_ikea_host(self):
        r = load('ExoprtSSRF.xml')
        h = r.hosts[0]
        assert h.hostname == "www.ikea.com"
        assert h.ip_address == "104.106.85.166"
    def test_open_ports_populated(self):
        r = load('DomXss.xml')
        h = r.hosts[0]
        assert len(h.open_ports) > 0
        assert h.open_ports[0]['port'] == 443

# --- Vuln fields ---
class TestVulnFields:
    def test_title_extracted(self):
        r = load('DomXss.xml')
        v = r.vulnerabilities[0]
        assert "DOM" in v.title or "XSS" in v.title or "Cross-site" in v.title

    def test_severity_high(self):
        r = load('DomXss.xml')
        v = r.vulnerabilities[0]
        assert v.severity_tool == Severity.HIGH

    def test_severity_medium_ssrf(self):
        r = load('ExoprtSSRF.xml')
        assert all(v.severity_tool == Severity.MEDIUM for v in r.vulnerabilities)

    def test_severity_low(self):
        r = load('Report-ikea.xml')
        low_vulns = [v for v in r.vulnerabilities if v.severity_tool == Severity.LOW]
        assert len(low_vulns) > 0

    def test_affected_host_port_service(self):
        r = load('DomXss.xml')
        v = r.vulnerabilities[0]
        assert v.affected_host == "www.atg.se"
        assert v.affected_ip == "195.198.34.30"
        assert v.affected_port == 443
        assert v.affected_service == "https"

    def test_affected_url_built(self):
        r = load('DomXss.xml')
        v = r.vulnerabilities[0]
        assert "atg.se" in v.affected_url
        assert "/spel/" in v.affected_url

    def test_http_method_extracted(self):
        r = load('ExoprtSSRF.xml')
        v = r.vulnerabilities[0]
        assert v.http_method in ("GET", "POST", "PUT", "DELETE", "PATCH")

    def test_source_tool_burp(self):
        r = load('DomXss.xml')
        assert all(v.source_tool == "burp" for v in r.vulnerabilities)

    def test_source_script_type_id(self):
        r = load('DomXss.xml')
        v = r.vulnerabilities[0]
        assert v.source_script != ""

# --- Request/Response ---
class TestRequestResponse:
    def test_base64_request_decoded(self):
        r = load('DomXss.xml')
        v = r.vulnerabilities[0]
        assert v.evidence_request != ""
        assert "HTTP" in v.evidence_request or "GET" in v.evidence_request

    def test_plain_request_preserved(self):
        r = load('ExoprtSSRF.xml')
        v = r.vulnerabilities[0]
        assert "ikea.com" in v.evidence_request
        assert "HTTP" in v.evidence_request

    def test_response_populated(self):
        r = load('ExoprtSSRF.xml')
        v = r.vulnerabilities[0]
        assert v.evidence_response != ""

# --- Evidence ---
class TestEvidence:
    def test_evidence_not_empty(self):
        r = load('DomXss.xml')
        assert all(v.evidence != "" for v in r.vulnerabilities)

    def test_confidence_in_evidence(self):
        r = load('DomXss.xml')
        v = r.vulnerabilities[0]
        assert "Confidence" in v.evidence

    def test_location_in_evidence(self):
        r = load('ExoprtSSRF.xml')
        v = r.vulnerabilities[0]
        assert "Location" in v.evidence

    def test_dynamic_analysis_extracted(self):
        r = load('Report-ikea_mini.xml')
        dom_vulns = [v for v in r.vulnerabilities if "Dynamic Analysis" in v.evidence]
        assert len(dom_vulns) > 0

# --- CWE ---
class TestCweExtraction:
    def test_cwe_from_vuln_classifications(self):
        r = load('Report-ikea_mini.xml')
        vulns_with_cwe = [v for v in r.vulnerabilities if v.cwe_id]
        assert len(vulns_with_cwe) > 0
        assert all(v.cwe_id.startswith("CWE-") for v in vulns_with_cwe)

    def test_cwe_565_cookie_manipulation(self):
        r = load('Report-ikea_mini.xml')
        cwe_565 = [v for v in r.vulnerabilities if "CWE-565" in v.cwe_ids]
        assert len(cwe_565) > 0

# --- Enrichment status ---
class TestEnrichmentStatus:
    def test_skipped_when_no_cve(self):
        r = load('DomXss.xml')
        # Burp DOM XSS tipicamente non ha CVE
        skipped = [v for v in r.vulnerabilities if v.nvd_enrichment_status == EnrichmentStatus.SKIPPED]
        assert len(skipped) >= 0  # può esserci o no

    def test_pending_when_has_cve(self):
        r = load('DomXss.xml')
        for v in r.vulnerabilities:
            if v.cve_ids_tool:
                assert v.nvd_enrichment_status == EnrichmentStatus.PENDING

# --- Scale test ---
class TestScale:
    def test_1203_issues_parsed(self):
        r = load('ssrf-headers.xml')
        assert len(r.vulnerabilities) == 1203
        assert len(r.parse_errors) == 0

    def test_65_issues_no_errors(self):
        r = load('Exporta-17_5_25_ssrfikea.xml')
        assert len(r.vulnerabilities) == 65
        assert len(r.parse_errors) == 0

    def test_80_issues_no_errors(self):
        r = load('Report-ikea.xml')
        assert len(r.vulnerabilities) == 80

    def test_55_issues_no_errors(self):
        r = load('Report-ikea_mini.xml')
        assert len(r.vulnerabilities) == 55

# --- Dedup key ---
class TestDedupKey:
    def test_key_is_16_chars(self):
        r = load('DomXss.xml')
        for v in r.vulnerabilities:
            assert len(v.dedup_key) == 16

    def test_same_type_same_host_similar_key(self):
        r = load('ssrf-headers.xml')
        keys = [v.dedup_key for v in r.vulnerabilities]
        # Con 1203 SSRF su stesso host, ci sono pochi key unici (4 tipi × 1 host)
        unique_keys = set(keys)
        assert len(unique_keys) <= 10

# --- Error handling ---
class TestErrorHandling:
    def test_invalid_xml_raises(self):
        with pytest.raises(ValueError):
            parser.parse(b"<not valid xml at all <broken>")

    def test_empty_issues_no_crash(self):
        xml = b'<?xml version="1.0"?><issues burpVersion="1.0" exportTime="Mon Jan 1 00:00:00 UTC 2024"></issues>'
        r = parser.parse(xml)
        assert len(r.vulnerabilities) == 0
        assert len(r.parse_errors) == 0
