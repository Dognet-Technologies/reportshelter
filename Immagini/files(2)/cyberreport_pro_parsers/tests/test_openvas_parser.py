"""Test suite OpenVAS/Nessus parser — file reali."""
import pytest
from pathlib import Path
from openvas_parser import OpenVasXmlParser, OpenVasCsvParser, NessusCsvParser, detect_and_parse
from canonical_schema import Severity, EnrichmentStatus

S = Path('/mnt/user-data/uploads')

class TestOpenVasXml:
    def test_vuln_count(self):
        r = OpenVasXmlParser().parse(S / 'report-747cbd29-56a6-47aa-bfa1-d04a4713b83c.xml')
        assert len(r.vulnerabilities) == 32

    def test_host_count(self):
        r = OpenVasXmlParser().parse(S / 'report-747cbd29-56a6-47aa-bfa1-d04a4713b83c.xml')
        assert len(r.hosts) == 9

    def test_no_errors(self):
        r = OpenVasXmlParser().parse(S / 'report-747cbd29-56a6-47aa-bfa1-d04a4713b83c.xml')
        assert r.parse_errors == []

    def test_source_tool(self):
        r = OpenVasXmlParser().parse(S / 'report-747cbd29-56a6-47aa-bfa1-d04a4713b83c.xml')
        assert all(v.source_tool == 'openvas' for v in r.vulnerabilities)

    def test_ip_extracted(self):
        r = OpenVasXmlParser().parse(S / 'report-747cbd29-56a6-47aa-bfa1-d04a4713b83c.xml')
        v = r.vulnerabilities[0]
        assert v.affected_ip == '109.168.113.18'

    def test_hostname_extracted(self):
        r = OpenVasXmlParser().parse(S / 'report-747cbd29-56a6-47aa-bfa1-d04a4713b83c.xml')
        v = r.vulnerabilities[0]
        assert 'kpnqwest' in v.affected_host

    def test_port_extracted(self):
        r = OpenVasXmlParser().parse(S / 'report-747cbd29-56a6-47aa-bfa1-d04a4713b83c.xml')
        v = r.vulnerabilities[0]
        assert v.affected_port == 443
        assert v.affected_protocol == 'tcp'

    def test_cvss_score(self):
        r = OpenVasXmlParser().parse(S / 'report-747cbd29-56a6-47aa-bfa1-d04a4713b83c.xml')
        v = r.vulnerabilities[0]
        assert v.cvss_score_tool == 7.5

    def test_severity_high(self):
        r = OpenVasXmlParser().parse(S / 'report-747cbd29-56a6-47aa-bfa1-d04a4713b83c.xml')
        v = r.vulnerabilities[0]
        assert v.severity_tool == Severity.HIGH

    def test_cve_extracted(self):
        r = OpenVasXmlParser().parse(S / 'report-747cbd29-56a6-47aa-bfa1-d04a4713b83c.xml')
        v = r.vulnerabilities[0]
        assert 'CVE-2016-2183' in v.cve_ids_tool

    def test_nvt_oid_as_source_script(self):
        r = OpenVasXmlParser().parse(S / 'report-747cbd29-56a6-47aa-bfa1-d04a4713b83c.xml')
        v = r.vulnerabilities[0]
        assert v.source_script.startswith('1.3.6.1.4.1.25623')

    def test_enrichment_pending_with_cve(self):
        r = OpenVasXmlParser().parse(S / 'report-747cbd29-56a6-47aa-bfa1-d04a4713b83c.xml')
        cve_vulns = [v for v in r.vulnerabilities if v.cve_ids_tool]
        assert all(v.nvd_enrichment_status == EnrichmentStatus.PENDING for v in cve_vulns)

    def test_with_cve_count(self):
        r = OpenVasXmlParser().parse(S / 'report-747cbd29-56a6-47aa-bfa1-d04a4713b83c.xml')
        assert r.stats['with_cve'] == 17

    def test_dedup_key_16_chars(self):
        r = OpenVasXmlParser().parse(S / 'report-747cbd29-56a6-47aa-bfa1-d04a4713b83c.xml')
        for v in r.vulnerabilities:
            assert len(v.dedup_key) == 16

    def test_second_file(self):
        r = OpenVasXmlParser().parse(S / 'report-c700a50c-4c10-49fe-a3e8-0cc10178d356.xml')
        assert len(r.vulnerabilities) == 28
        assert r.stats['with_cve'] == 19


class TestOpenVasCsv:
    def test_same_count_as_xml(self):
        r = OpenVasCsvParser().parse(S / 'report-747cbd29-56a6-47aa-bfa1-d04a4713b83c.csv')
        assert len(r.vulnerabilities) == 32

    def test_ip_extracted(self):
        r = OpenVasCsvParser().parse(S / 'report-747cbd29-56a6-47aa-bfa1-d04a4713b83c.csv')
        assert r.vulnerabilities[0].affected_ip == '109.168.113.18'

    def test_cve_extracted(self):
        r = OpenVasCsvParser().parse(S / 'report-747cbd29-56a6-47aa-bfa1-d04a4713b83c.csv')
        v = r.vulnerabilities[0]
        assert 'CVE-2016-2183' in v.cve_ids_tool

    def test_cvss_score(self):
        r = OpenVasCsvParser().parse(S / 'report-747cbd29-56a6-47aa-bfa1-d04a4713b83c.csv')
        assert r.vulnerabilities[0].cvss_score_tool == 7.5

    def test_severity_high(self):
        r = OpenVasCsvParser().parse(S / 'report-747cbd29-56a6-47aa-bfa1-d04a4713b83c.csv')
        assert r.vulnerabilities[0].severity_tool == Severity.HIGH

    def test_no_errors(self):
        r = OpenVasCsvParser().parse(S / 'report-dde48fcc-36e7-4757-b26a-087b9d909f26.csv')
        assert len(r.parse_errors) == 0

    def test_csv3_medium_severity(self):
        r = OpenVasCsvParser().parse(S / 'report-dde48fcc-36e7-4757-b26a-087b9d909f26.csv')
        assert r.vulnerabilities[0].severity_tool == Severity.MEDIUM


class TestNessusCsv:
    def test_vuln_count(self):
        r = NessusCsvParser().parse(S / 'VAPT_2022_j491j4.csv')
        assert len(r.vulnerabilities) == 166

    def test_host_extraction(self):
        r = NessusCsvParser().parse(S / 'VAPT_2022_j491j4.csv')
        ips = {v.affected_ip for v in r.vulnerabilities}
        assert '109.168.113.18' in ips

    def test_info_severity_for_none_risk(self):
        r = NessusCsvParser().parse(S / 'VAPT_2022_j491j4.csv')
        none_risk = [v for v in r.vulnerabilities if v.severity_tool == Severity.INFO]
        assert len(none_risk) > 0

    def test_source_tool_nessus(self):
        r = NessusCsvParser().parse(S / 'VAPT_2022_j491j4.csv')
        assert all(v.source_tool == 'nessus' for v in r.vulnerabilities)

    def test_cve_extracted_when_present(self):
        r = NessusCsvParser().parse(S / 'VAPT_2022_j491j4.csv')
        cve_vulns = [v for v in r.vulnerabilities if v.cve_ids_tool]
        assert len(cve_vulns) > 0
        for v in cve_vulns:
            for cve in v.cve_ids_tool:
                assert cve.startswith('CVE-')

    def test_skipped_when_no_cve(self):
        r = NessusCsvParser().parse(S / 'VAPT_2022_j491j4.csv')
        no_cve = [v for v in r.vulnerabilities if not v.cve_ids_tool]
        assert all(v.nvd_enrichment_status == EnrichmentStatus.SKIPPED for v in no_cve)

    def test_bi_file(self):
        r = NessusCsvParser().parse(S / 'VAPT_BI_2022_sw1gq2.csv')
        assert len(r.vulnerabilities) == 28

    def test_no_errors(self):
        r = NessusCsvParser().parse(S / 'VAPT_2022_j491j4.csv')
        assert len(r.parse_errors) == 0


class TestAutoDetect:
    def test_xml_detected(self):
        r = detect_and_parse(S / 'report-747cbd29-56a6-47aa-bfa1-d04a4713b83c.xml')
        assert r.source_tool == 'openvas'
        assert len(r.vulnerabilities) == 32

    def test_openvas_csv_detected(self):
        r = detect_and_parse(S / 'report-747cbd29-56a6-47aa-bfa1-d04a4713b83c.csv')
        assert r.source_tool == 'openvas'
        assert len(r.vulnerabilities) == 32

    def test_nessus_csv_detected(self):
        r = detect_and_parse(S / 'VAPT_2022_j491j4.csv')
        assert r.source_tool == 'nessus'
        assert len(r.vulnerabilities) == 166

    def test_invalid_raises(self):
        import pytest
        with pytest.raises((ValueError, Exception)):
            detect_and_parse(b'random garbage that is not xml or csv')
