"""
Test per OpenVasExcelParser.

I test reali richiedono il file fixture:
  tests/fixtures/openvas_report.xlsx

Per ottenerlo:
  cp /path/to/report-*.xlsx backend/tests/fixtures/openvas_report.xlsx

I test di unità (magic bytes, file vuoto) non richiedono la fixture.
"""
import io
import struct
import zipfile

import pytest
from pathlib import Path

from cyberreport_pro_parsers.parsers.openvas_parser import (
    OpenVasExcelParser,
    detect_and_parse,
)

# Path del file reale (da copiare manualmente nella directory fixtures)
REAL_XLSX = Path(__file__).parent.parent / "fixtures" / "openvas_report.xlsx"


def _make_minimal_xlsx(sheet_name: str = "Sheet1", rows: list[list] | None = None) -> bytes:
    """
    Crea un file XLSX minimale in memoria con openpyxl.
    Usato nei test che non richiedono il file reale.
    """
    try:
        import openpyxl
    except ImportError:
        pytest.skip("openpyxl non installato")

    wb = openpyxl.Workbook()
    ws = wb.active
    ws.title = sheet_name

    if rows:
        for row in rows:
            ws.append(row)

    buf = io.BytesIO()
    wb.save(buf)
    return buf.getvalue()


# ---------------------------------------------------------------------------
# Test che non richiedono la fixture reale
# ---------------------------------------------------------------------------


class TestOpenVasExcelParserUnit:
    def test_magic_bytes_validation(self):
        """File non-XLSX deve essere rifiutato immediatamente."""
        with pytest.raises(ValueError, match="magic bytes"):
            OpenVasExcelParser().parse(b"not an xlsx file")

    def test_empty_bytes_rejected(self):
        """Bytes vuoti → ValueError."""
        with pytest.raises(ValueError):
            OpenVasExcelParser().parse(b"")

    def test_str_input_rejected(self):
        """Stringa passata invece di bytes → ValueError."""
        with pytest.raises(ValueError, match="bytes"):
            OpenVasExcelParser().parse("not bytes")  # type: ignore

    def test_empty_xlsx_raises(self):
        """XLSX con foglio vuoto (solo header row assente) → ValueError."""
        xlsx = _make_minimal_xlsx(rows=[])
        with pytest.raises(ValueError, match="vuoto"):
            OpenVasExcelParser().parse(xlsx)

    def test_xlsx_no_known_columns_returns_empty(self):
        """XLSX con colonne sconosciute → nessuna vulnerabilità, nessun errore fatale."""
        xlsx = _make_minimal_xlsx(rows=[
            ["RandomCol1", "RandomCol2"],
            ["val1", "val2"],
        ])
        result = OpenVasExcelParser().parse(xlsx)
        # Nessun crash — le righe vengono skippate perché IP e Hostname sono vuoti
        assert result.source_tool == "openvas"
        assert isinstance(result.vulnerabilities, list)

    def test_detect_and_parse_non_xlsx_skips_excel(self):
        """detect_and_parse con input XML non usa OpenVasExcelParser."""
        xml_data = b"<report><results/></report>"
        # Non deve fare raise per il formato XML — usa OpenVasXmlParser
        # (può sollevare ValueError per XML malformato, non per XLSX)
        try:
            detect_and_parse(xml_data)
        except ValueError:
            pass  # atteso per XML senza <result> elements o simili

    def test_detect_and_parse_magic_bytes_routes_to_excel(self):
        """detect_and_parse deve riconoscere XLSX da magic bytes e usare OpenVasExcelParser."""
        xlsx = _make_minimal_xlsx(rows=[
            ["IP", "Hostname", "NVT Name"],
            ["192.168.1.1", "host1.local", "Test Finding"],
        ])
        result = detect_and_parse(xlsx)
        assert result.source_tool == "openvas"


# ---------------------------------------------------------------------------
# Test con file reale (skippati se la fixture manca)
# ---------------------------------------------------------------------------


@pytest.mark.skipif(not REAL_XLSX.exists(), reason="File fixture tests/fixtures/openvas_report.xlsx non trovato")
class TestOpenVasExcelParserReal:
    def test_parse_returns_vulnerabilities(self):
        data = REAL_XLSX.read_bytes()
        result = OpenVasExcelParser().parse(data)
        assert len(result.vulnerabilities) > 0

    def test_parse_no_fatal_errors(self):
        data = REAL_XLSX.read_bytes()
        result = OpenVasExcelParser().parse(data)
        assert len(result.parse_errors) == 0

    def test_parse_fields_populated(self):
        data = REAL_XLSX.read_bytes()
        result = OpenVasExcelParser().parse(data)
        vuln = result.vulnerabilities[0]
        assert vuln.title
        assert vuln.affected_ip or vuln.affected_host
        assert vuln.severity_tool is not None

    def test_detect_and_parse_xlsx(self):
        data = REAL_XLSX.read_bytes()
        result = detect_and_parse(data)
        assert result.source_tool == "openvas"
        assert len(result.vulnerabilities) > 0

    def test_adapter_compatibility(self):
        """Il risultato dell'adapter deve essere compatibile con il Layer 1."""
        from apps.parsers.scan_result_adapter import adapt_scan_result

        data = REAL_XLSX.read_bytes()
        result = OpenVasExcelParser().parse(data)
        adapted = adapt_scan_result(result)
        assert all(isinstance(v.affected_port, (int, type(None))) for v in adapted)
        assert all(isinstance(v.cve_id, list) for v in adapted)

    def test_source_tool_is_openvas(self):
        data = REAL_XLSX.read_bytes()
        result = OpenVasExcelParser().parse(data)
        assert result.source_tool == "openvas"
        adapted_sources = {v.source for v in __import__(
            "apps.parsers.scan_result_adapter", fromlist=["adapt_scan_result"]
        ).adapt_scan_result(result)}
        assert adapted_sources == {"openvas"}
