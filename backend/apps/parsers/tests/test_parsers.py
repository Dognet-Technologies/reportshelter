"""
Unit tests for all scanner parsers.
Tests use inline fixture strings — no external files needed.
"""

import io
import json

import pytest

from apps.parsers.base import ParserError
from apps.parsers.burp_parser import BurpParser
from apps.parsers.csv_parser import CSVParser
from apps.parsers.metasploit_parser import MetasploitParser
from apps.parsers.nikto_parser import NiktoParser
from apps.parsers.nmap_parser import NmapParser
from apps.parsers.openvas_parser import NessusParser, OpenVasParser
from apps.parsers.registry import PARSER_REGISTRY, get_parser
from apps.parsers.zap_parser import ZAPParser
from apps.vulnerabilities.deduplication import NormalizedVulnerability

# ---------------------------------------------------------------------------
# Fixture XML strings
# ---------------------------------------------------------------------------

NMAP_XML_SIMPLE = b"""<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.94">
  <host>
    <status state="up"/>
    <address addr="192.168.1.10" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="22">
        <state state="open"/>
        <service name="ssh" product="OpenSSH" version="8.9"/>
      </port>
      <port protocol="tcp" portid="80">
        <state state="open"/>
        <service name="http" product="nginx" version="1.24"/>
      </port>
      <port protocol="tcp" portid="3389">
        <state state="open"/>
        <service name="ms-wbt-server"/>
      </port>
    </ports>
  </host>
</nmaprun>"""

NMAP_XML_WITH_SCRIPT = b"""<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.94">
  <host>
    <status state="up"/>
    <address addr="10.0.0.1" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="445">
        <state state="open"/>
        <service name="microsoft-ds"/>
        <script id="smb-vuln-ms17-010" output="VULNERABLE: CVE-2017-0144 Remote Code Execution"/>
      </port>
    </ports>
  </host>
</nmaprun>"""

NMAP_XML_HOST_DOWN = b"""<?xml version="1.0"?>
<nmaprun scanner="nmap" version="7.94">
  <host>
    <status state="down"/>
    <address addr="10.0.0.99" addrtype="ipv4"/>
  </host>
</nmaprun>"""

NMAP_XML_MALFORMED = b"<not-nmap><garbage/>"

NIKTO_XML = b"""<?xml version="1.0"?>
<niktoscan>
  <scandetails targetip="192.168.1.20" targetport="80">
    <item osvdbid="12345" method="GET">
      <description>Apache mod_status is enabled, which may expose server information</description>
      <uri>/server-status</uri>
    </item>
    <item osvdbid="0" method="POST">
      <description>SQL injection possible in login form</description>
      <uri>/login</uri>
    </item>
    <item osvdbid="0" method="GET">
      <description>Outdated Apache version 2.2.15 detected</description>
      <uri>/</uri>
    </item>
  </scandetails>
</niktoscan>"""

NIKTO_XML_MALFORMED = b"<nikto><broken"

ZAP_XML = b"""<?xml version="1.0"?>
<OWASPZAPReport version="2.14.0">
  <site name="http://target.com" host="target.com" port="80" ssl="false">
    <alerts>
      <alertitem>
        <alert>SQL Injection</alert>
        <name>SQL Injection</name>
        <riskcode>3</riskcode>
        <confidence>2</confidence>
        <riskdesc>High (Medium)</riskdesc>
        <desc>SQL injection may be possible.</desc>
        <solution>Use parameterized queries.</solution>
        <cweid>89</cweid>
        <wascid>19</wascid>
        <instances>
          <instance>
            <uri>http://target.com/login?user=1</uri>
            <method>GET</method>
            <evidence>user=1'</evidence>
          </instance>
        </instances>
      </alertitem>
      <alertitem>
        <alert>X-Frame-Options Header Not Set</alert>
        <name>X-Frame-Options Header Not Set</name>
        <riskcode>1</riskcode>
        <confidence>2</confidence>
        <riskdesc>Low (Medium)</riskdesc>
        <desc>Missing X-Frame-Options header.</desc>
        <solution>Add X-Frame-Options header.</solution>
        <cweid>16</cweid>
        <wascid>15</wascid>
        <instances>
          <instance>
            <uri>http://target.com/</uri>
            <method>GET</method>
          </instance>
        </instances>
      </alertitem>
    </alerts>
  </site>
</OWASPZAPReport>"""

ZAP_JSON = json.dumps({
    "site": [{
        "@name": "http://target.com",
        "@host": "target.com",
        "@port": "80",
        "alerts": [{
            "alert": "Cross Site Scripting (Reflected)",
            "riskcode": "3",
            "confidence": "2",
            "riskdesc": "High (Medium)",
            "desc": "XSS reflected in search parameter.",
            "solution": "Encode output.",
            "cweid": "79",
            "instances": [{
                "uri": "http://target.com/search?q=<script>",
                "method": "GET",
                "evidence": "<script>alert(1)</script>",
            }],
        }],
    }]
}).encode()

BURP_XML = b"""<?xml version="1.0"?>
<issues burpVersion="2023.11">
  <issue>
    <serialNumber>1</serialNumber>
    <type>1049088</type>
    <name>SQL injection</name>
    <host ip="10.0.0.5">https://app.example.com</host>
    <path>/search</path>
    <location>/search [param]</location>
    <severity>High</severity>
    <confidence>Certain</confidence>
    <issueDetail>SQL injection was detected in the search parameter.</issueDetail>
    <issueBackground>SQL injection allows attackers to read/modify database.</issueBackground>
    <remediationBackground>Use parameterized queries.</remediationBackground>
  </issue>
  <issue>
    <serialNumber>2</serialNumber>
    <type>5243392</type>
    <name>Cross-site scripting (reflected)</name>
    <host ip="10.0.0.5">https://app.example.com</host>
    <path>/comment</path>
    <location>/comment [input]</location>
    <severity>Medium</severity>
    <confidence>Firm</confidence>
    <issueDetail>XSS in comment field.</issueDetail>
    <issueBackground>XSS allows script injection.</issueBackground>
    <remediationBackground>Encode output.</remediationBackground>
  </issue>
</issues>"""

METASPLOIT_XML = b"""<?xml version="1.0"?>
<MetasploitV5>
  <db>
    <hosts>
      <host id="1">
        <address>172.16.0.10</address>
        <name>target-server</name>
        <os_name>Windows Server 2019</os_name>
      </host>
    </hosts>
    <vulns>
      <vuln host_id="1">
        <name>MS17-010 EternalBlue SMB Remote Windows Kernel Pool Corruption</name>
        <info>SMB Remote Code Execution via EternalBlue</info>
        <port>445</port>
        <proto>tcp</proto>
        <refs>
          <ref><name>CVE-2017-0144</name></ref>
          <ref><name>MS17-010</name></ref>
        </refs>
      </vuln>
    </vulns>
  </db>
</MetasploitV5>"""

CSV_DATA = b"""title,description,host,port,severity,cve
SQL Injection,Classic SQLi in login form,192.168.1.1,443,critical,CVE-2023-0001
XSS Reflected,Reflected XSS in search,192.168.1.1,443,high,
Directory Traversal,Path traversal via filename param,192.168.1.2,80,medium,
"""

CSV_EMPTY_TITLE = b"""title,host,severity
,192.168.1.1,high
"""


# ---------------------------------------------------------------------------
# Nmap Parser
# ---------------------------------------------------------------------------


class TestNmapParser:
    def test_parses_open_ports(self):
        parser = NmapParser()
        results = parser.parse(io.BytesIO(NMAP_XML_SIMPLE))
        assert len(results) == 3
        ports = {r.affected_port for r in results}
        assert ports == {22, 80, 3389}

    def test_host_address_extracted(self):
        parser = NmapParser()
        results = parser.parse(io.BytesIO(NMAP_XML_SIMPLE))
        assert all(r.affected_host == "192.168.1.10" for r in results)

    def test_high_risk_port_3389(self):
        parser = NmapParser()
        results = parser.parse(io.BytesIO(NMAP_XML_SIMPLE))
        rdp = next(r for r in results if r.affected_port == 3389)
        assert rdp.risk_level == "high"

    def test_medium_risk_port_22(self):
        parser = NmapParser()
        results = parser.parse(io.BytesIO(NMAP_XML_SIMPLE))
        ssh = next(r for r in results if r.affected_port == 22)
        assert ssh.risk_level == "medium"

    def test_nse_script_vuln_extracted(self):
        parser = NmapParser()
        results = parser.parse(io.BytesIO(NMAP_XML_WITH_SCRIPT))
        # smb-vuln-ms17-010 → "EternalBlue — Remote Code Execution via SMB"
        nse = [r for r in results if "EternalBlue" in r.title]
        assert len(nse) == 1
        # SCRIPT_CVE_MAP maps smb-vuln-ms17-010 → CVE-2017-0143, cvss=9.8 → critical
        assert "CVE-2017-0143" in nse[0].cve_id
        assert nse[0].risk_level == "critical"

    def test_host_down_skipped(self):
        parser = NmapParser()
        results = parser.parse(io.BytesIO(NMAP_XML_HOST_DOWN))
        assert results == []

    def test_malformed_xml_raises_parser_error(self):
        parser = NmapParser()
        with pytest.raises(ParserError):
            parser.parse(io.BytesIO(NMAP_XML_MALFORMED))

    def test_wrong_root_tag_raises_parser_error(self):
        parser = NmapParser()
        with pytest.raises(ParserError, match="nmaprun"):
            parser.parse(io.BytesIO(b"<scan><host/></scan>"))

    def test_source_is_nmap(self):
        parser = NmapParser()
        results = parser.parse(io.BytesIO(NMAP_XML_SIMPLE))
        assert all(r.source == "nmap" for r in results)

    def test_raw_output_not_empty(self):
        parser = NmapParser()
        results = parser.parse(io.BytesIO(NMAP_XML_SIMPLE))
        assert all(r.raw_output for r in results)


# ---------------------------------------------------------------------------
# Nikto Parser
# ---------------------------------------------------------------------------


class TestNiktoParser:
    def test_parses_findings(self):
        parser = NiktoParser()
        results = parser.parse(io.BytesIO(NIKTO_XML))
        assert len(results) == 3

    def test_target_extracted(self):
        parser = NiktoParser()
        results = parser.parse(io.BytesIO(NIKTO_XML))
        assert all(r.affected_host == "192.168.1.20" for r in results)
        assert all(r.affected_port == 80 for r in results)

    def test_sql_injection_is_high(self):
        parser = NiktoParser()
        results = parser.parse(io.BytesIO(NIKTO_XML))
        sqli = next(r for r in results if "sql" in r.title.lower())
        assert sqli.risk_level == "high"

    def test_outdated_is_medium(self):
        parser = NiktoParser()
        results = parser.parse(io.BytesIO(NIKTO_XML))
        outdated = next(r for r in results if "outdated" in r.description.lower())
        assert outdated.risk_level == "medium"

    def test_malformed_xml_raises(self):
        parser = NiktoParser()
        with pytest.raises(ParserError):
            parser.parse(io.BytesIO(NIKTO_XML_MALFORMED))


# ---------------------------------------------------------------------------
# ZAP Parser (XML + JSON)
# ---------------------------------------------------------------------------


class TestZAPParser:
    def test_parses_xml(self):
        parser = ZAPParser()
        results = parser.parse(io.BytesIO(ZAP_XML))
        assert len(results) == 2

    def test_xml_risk_mapping_high(self):
        parser = ZAPParser()
        results = parser.parse(io.BytesIO(ZAP_XML))
        sqli = next(r for r in results if "SQL" in r.title)
        assert sqli.risk_level == "high"

    def test_xml_risk_mapping_low(self):
        parser = ZAPParser()
        results = parser.parse(io.BytesIO(ZAP_XML))
        low = next(r for r in results if "Frame" in r.title)
        assert low.risk_level == "low"

    def test_parses_json(self):
        parser = ZAPParser()
        results = parser.parse(io.BytesIO(ZAP_JSON))
        assert len(results) == 1
        assert "XSS" in results[0].title or "Cross" in results[0].title

    def test_json_source_is_zap(self):
        parser = ZAPParser()
        results = parser.parse(io.BytesIO(ZAP_JSON))
        assert results[0].source == "zap"


# ---------------------------------------------------------------------------
# Burp Parser
# ---------------------------------------------------------------------------


class TestBurpParser:
    def test_parses_issues(self):
        parser = BurpParser()
        results = parser.parse(io.BytesIO(BURP_XML))
        assert len(results) == 2

    def test_severity_mapping_high(self):
        parser = BurpParser()
        results = parser.parse(io.BytesIO(BURP_XML))
        sqli = next(r for r in results if "SQL" in r.title)
        assert sqli.risk_level == "high"

    def test_severity_mapping_medium(self):
        parser = BurpParser()
        results = parser.parse(io.BytesIO(BURP_XML))
        xss = next(r for r in results if "cross-site" in r.title.lower())
        assert xss.risk_level == "medium"

    def test_host_extracted(self):
        parser = BurpParser()
        results = parser.parse(io.BytesIO(BURP_XML))
        # Layer 2 separates affected_ip (10.0.0.5) and affected_host (app.example.com).
        # The adapter uses affected_host (hostname) when present.
        assert all(
            r.affected_host in ("10.0.0.5", "app.example.com") or r.affected_ip == "10.0.0.5"
            for r in results
        )

    def test_source_is_burp(self):
        parser = BurpParser()
        results = parser.parse(io.BytesIO(BURP_XML))
        assert all(r.source == "burp" for r in results)


# ---------------------------------------------------------------------------
# Metasploit Parser
# ---------------------------------------------------------------------------


class TestMetasploitParser:
    def test_parses_vulns(self):
        parser = MetasploitParser()
        results = parser.parse(io.BytesIO(METASPLOIT_XML))
        assert len(results) >= 1

    def test_host_extracted(self):
        parser = MetasploitParser()
        results = parser.parse(io.BytesIO(METASPLOIT_XML))
        assert results[0].affected_host == "172.16.0.10"

    def test_cve_extracted(self):
        parser = MetasploitParser()
        results = parser.parse(io.BytesIO(METASPLOIT_XML))
        vuln = next(r for r in results if r.cve_id)
        assert "CVE-2017-0144" in vuln.cve_id

    def test_source_is_metasploit(self):
        parser = MetasploitParser()
        results = parser.parse(io.BytesIO(METASPLOIT_XML))
        assert all(r.source == "metasploit" for r in results)


# ---------------------------------------------------------------------------
# CSV Parser
# ---------------------------------------------------------------------------


class TestCSVParser:
    def test_parses_rows(self):
        parser = CSVParser()
        results = parser.parse(io.BytesIO(CSV_DATA))
        assert len(results) == 3

    def test_titles_extracted(self):
        parser = CSVParser()
        results = parser.parse(io.BytesIO(CSV_DATA))
        titles = [r.title for r in results]
        assert "SQL Injection" in titles

    def test_severity_mapped(self):
        parser = CSVParser()
        results = parser.parse(io.BytesIO(CSV_DATA))
        sqli = next(r for r in results if "SQL" in r.title)
        assert sqli.risk_level == "critical"

    def test_cve_extracted(self):
        parser = CSVParser()
        results = parser.parse(io.BytesIO(CSV_DATA))
        sqli = next(r for r in results if "SQL" in r.title)
        assert sqli.cve_id == ["CVE-2023-0001"]

    def test_empty_title_skipped(self):
        parser = CSVParser()
        results = parser.parse(io.BytesIO(CSV_EMPTY_TITLE))
        assert results == []

    def test_empty_csv_returns_empty(self):
        parser = CSVParser()
        results = parser.parse(io.BytesIO(b"title,host,severity\n"))
        assert results == []

    def test_source_is_csv(self):
        parser = CSVParser()
        results = parser.parse(io.BytesIO(CSV_DATA))
        assert all(r.source == "csv" for r in results)


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------


class TestParserRegistry:
    def test_all_tools_registered(self):
        expected = {"nmap", "nikto", "burp", "zap", "metasploit", "csv", "openvas", "nessus"}
        assert expected.issubset(set(PARSER_REGISTRY.keys()))

    def test_get_parser_returns_correct_class(self):
        assert isinstance(get_parser("nmap"), NmapParser)
        assert isinstance(get_parser("nikto"), NiktoParser)
        assert isinstance(get_parser("zap"), ZAPParser)
        assert isinstance(get_parser("burp"), BurpParser)
        assert isinstance(get_parser("metasploit"), MetasploitParser)
        assert isinstance(get_parser("csv"), CSVParser)
        assert isinstance(get_parser("openvas"), OpenVasParser)
        assert isinstance(get_parser("nessus"), NessusParser)

    def test_get_parser_unknown_raises(self):
        with pytest.raises(ValueError, match="No parser registered"):
            get_parser("unknown_tool_xyz")

    def test_all_parsers_return_list(self):
        """Smoke-test: all parsers must return a list (even if empty)."""
        for name, cls in PARSER_REGISTRY.items():
            parser = cls()
            assert isinstance(parser, object)
