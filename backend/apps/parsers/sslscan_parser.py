"""
SSLScan XML parser.

sslscan --xml=report.xml produces:
  <document>
    <ssltest host="..." port="443">
      <heartbleed sslversion="TLSv1.0" vulnerable="1"/>
      <renegotiation supported="1" secure="0"/>
      <cipher status="preferred|accepted" sslversion="TLSv1.2"
              bits="256" cipher="..." strength="weak|acceptable|strong"/>
      <certificate>
        <subject>...</subject>
        <issuer>...</issuer>
        <expired>false</expired>
        <self-signed>false</self-signed>
      </certificate>
    </ssltest>
  </document>

Findings generated:
- Heartbleed (per SSL version, if vulnerable="1")
- Insecure renegotiation (if supported="1" and secure="0")
- Deprecated protocol support (SSLv2, SSLv3, TLSv1.0, TLSv1.1)
- Weak ciphers (strength="weak")
- Expired certificate
- Self-signed certificate
"""

from __future__ import annotations

import logging
import xml.etree.ElementTree as ET
from typing import IO

from apps.vulnerabilities.deduplication import NormalizedVulnerability

from .base import BaseParser, ParserError

logger = logging.getLogger(__name__)

_DEPRECATED_PROTOS = {"SSLv2", "SSLv3", "TLSv1.0", "TLSv1.1"}
_PROTO_RISK = {"SSLv2": "critical", "SSLv3": "high", "TLSv1.0": "medium", "TLSv1.1": "low"}


class SSLScanParser(BaseParser):
    """Parser for SSLScan XML reports."""

    tool_name = "sslscan"

    def parse(self, file_obj: IO[bytes]) -> list[NormalizedVulnerability]:
        try:
            root = ET.fromstring(file_obj.read())
        except ET.ParseError as exc:
            raise ParserError(f"Invalid SSLScan XML: {exc}") from exc

        results: list[NormalizedVulnerability] = []

        for test in root.iter("ssltest"):
            host = test.get("host") or test.get("sniname") or ""
            port_str = test.get("port") or "443"
            try:
                port = int(port_str)
            except ValueError:
                port = 443

            seen_protos: set[str] = set()

            # --- Heartbleed ---
            for hb in test.findall("heartbleed"):
                if hb.get("vulnerable") == "1":
                    version = hb.get("sslversion") or "unknown"
                    results.append(NormalizedVulnerability(
                        title=f"Heartbleed Vulnerability ({version})",
                        description=(
                            f"The server at {host}:{port} is vulnerable to Heartbleed "
                            f"(CVE-2014-0160) on {version}. "
                            "An attacker can read up to 64KB of server memory per request."
                        ),
                        remediation="Upgrade OpenSSL to 1.0.1g or later and reissue all TLS certificates.",
                        affected_host=host,
                        affected_port=port,
                        affected_service="https",
                        cve_id=["CVE-2014-0160"],
                        risk_level="critical",
                        category="CWE-126",
                        evidence_code=f"Heartbleed vulnerable on {version} at {host}:{port}",
                        source="sslscan",
                    ))

            # --- Insecure renegotiation ---
            reneg = test.find("renegotiation")
            if reneg is not None:
                if reneg.get("supported") == "1" and reneg.get("secure") == "0":
                    results.append(NormalizedVulnerability(
                        title="Insecure TLS Renegotiation Supported",
                        description=(
                            f"{host}:{port} supports insecure TLS renegotiation (RFC 5746 not enforced). "
                            "This allows MITM attacks to inject data into TLS sessions."
                        ),
                        remediation="Disable insecure renegotiation and enable only secure renegotiation (RFC 5746).",
                        affected_host=host,
                        affected_port=port,
                        affected_service="https",
                        cve_id=["CVE-2009-3555"],
                        risk_level="medium",
                        category="CWE-264",
                        evidence_code=f"Insecure renegotiation at {host}:{port}",
                        source="sslscan",
                    ))

            # --- Deprecated protocols and weak ciphers ---
            for cipher in test.findall("cipher"):
                version = cipher.get("sslversion") or ""
                strength = (cipher.get("strength") or "").lower()
                cipher_name = cipher.get("cipher") or ""
                bits = cipher.get("bits") or ""

                # Deprecated protocol
                if version in _DEPRECATED_PROTOS and version not in seen_protos:
                    seen_protos.add(version)
                    results.append(NormalizedVulnerability(
                        title=f"Deprecated Protocol Supported: {version}",
                        description=(
                            f"{host}:{port} supports the deprecated protocol {version}. "
                            "Deprecated TLS/SSL versions are vulnerable to downgrade attacks."
                        ),
                        remediation=f"Disable {version} and enforce TLS 1.2 or TLS 1.3 only.",
                        affected_host=host,
                        affected_port=port,
                        affected_service="https",
                        risk_level=_PROTO_RISK.get(version, "medium"),
                        category="CWE-326",
                        evidence_code=f"Protocol: {version} at {host}:{port}",
                        source="sslscan",
                    ))

                # Weak cipher
                if strength == "weak":
                    results.append(NormalizedVulnerability(
                        title=f"Weak Cipher Supported: {cipher_name}",
                        description=(
                            f"{host}:{port} supports the weak cipher {cipher_name} ({bits} bits) "
                            f"on {version}."
                        ),
                        remediation=f"Disable cipher suite {cipher_name} from the server configuration.",
                        affected_host=host,
                        affected_port=port,
                        affected_service="https",
                        risk_level="medium",
                        category="CWE-326",
                        evidence_code=f"Cipher: {cipher_name} ({bits} bits, {version}) at {host}:{port}",
                        source="sslscan",
                    ))

            # --- Certificate issues ---
            cert = test.find("certificate")
            if cert is not None:
                if (cert.findtext("expired") or "").lower() == "true":
                    subject = (cert.findtext("subject") or "").strip()
                    results.append(NormalizedVulnerability(
                        title="Expired TLS Certificate",
                        description=f"The TLS certificate at {host}:{port} has expired.\nSubject: {subject}",
                        remediation="Renew the TLS certificate before or upon expiration.",
                        affected_host=host,
                        affected_port=port,
                        affected_service="https",
                        risk_level="high",
                        category="CWE-298",
                        evidence_code=f"Subject: {subject}",
                        source="sslscan",
                    ))

                if (cert.findtext("self-signed") or "").lower() == "true":
                    subject = (cert.findtext("subject") or "").strip()
                    results.append(NormalizedVulnerability(
                        title="Self-Signed TLS Certificate",
                        description=f"The TLS certificate at {host}:{port} is self-signed.\nSubject: {subject}",
                        remediation="Replace the self-signed certificate with one issued by a trusted CA.",
                        affected_host=host,
                        affected_port=port,
                        affected_service="https",
                        risk_level="medium",
                        category="CWE-296",
                        evidence_code=f"Subject: {subject}",
                        source="sslscan",
                    ))

        return results
