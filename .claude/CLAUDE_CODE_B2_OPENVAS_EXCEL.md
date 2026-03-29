# TASK: Strada B2 — Integrazione Layer 2 in Django + OpenVAS Excel Parser

## Contesto generale

ReportShelter ha due layer di parser paralleli che devono essere unificati:

- **Layer 1** (`backend/apps/parsers/`) — attivo in produzione, interfaccia Django, schema semplice
- **Layer 2** (`backend/cyberreport_pro_parsers/parsers/`) — schema ricco, non collegato a Django

L'obiettivo è **sostituire il Layer 1 con il Layer 2** come sorgente autoritativa,
aggiornando il modello DB `Vulnerability` per allinearsi allo schema ricco,
e infine aggiungere il supporto `.xlsx` per OpenVAS Excel export.

L'ambiente è **solo sviluppo locale** — nessun dato di produzione da preservare.
I 153 test esistenti devono rimanere verdi al termine.

---

## Analisi del gap (già verificata — non ripetere questa analisi)

| Campo | Layer 1 / DB attuale | Layer 2 (canonical_schema) | Azione |
|---|---|---|---|
| `affected_port` | `CharField` (str) | `Optional[int]` | Cambia a `IntegerField(null=True)` |
| `cve_id` | `CharField` singola | `list[str]` | Cambia a `JSONField(default=list)` |
| `risk_level` | `str` | `Severity` enum | Mantieni `CharField`, aggiungi `"critical"` |
| `description` | campo unico | `description_tool` (str) | Rinomina o mappa |
| `remediation` | campo unico | `remediation_tool` (str) | Mantieni nome, mappa in adapter |
| `affected_host` | unico | `affected_ip` + `affected_host` | Aggiungi `affected_ip CharField` |
| `evidence_code` | TextField | `evidence` (str) | Rinomina campo o mappa |
| `source` | str singola | `source_tool` (str) | Già in `sources` JSONField |
| `nvd_enrichment_status` | assente | `EnrichmentStatus` enum | Aggiungi campo al modello |

---

## FASE 1 — Aggiornamento modello `Vulnerability`

**File:** `backend/apps/vulnerabilities/models.py`

### Modifiche al modello

1. **Aggiungi `affected_ip`** — nuovo `CharField(max_length=45, blank=True)` per IPv4/IPv6
   (il campo esistente `affected_host` resta per hostname/FQDN)

2. **Cambia `affected_port`** da `CharField` a `IntegerField(null=True, blank=True)`
   - Rimuovi `max_length=16`
   - Aggiungi `validators=[MinValueValidator(1), MaxValueValidator(65535)]`

3. **Cambia `cve_id`** da `CharField(max_length=32)` a `JSONField(default=list)`
   - Questo campo ora contiene una lista di stringhe CVE: `["CVE-2022-1234", "CVE-2022-5678"]`
   - Rimuovi `db_index=True` dal campo (metti l'indice separatamente se serve)
   - Aggiungi property `primary_cve_id` → `return self.cve_id[0] if self.cve_id else ""`

4. **Aggiungi `nvd_enrichment_status`** — `CharField` con choices:
   ```python
   class EnrichmentStatus(models.TextChoices):
       PENDING  = "pending",  "Pending"
       DONE     = "done",     "Done"
       FAILED   = "failed",   "Failed"
       SKIPPED  = "skipped",  "Skipped"
       PARTIAL  = "partial",  "Partial"
   ```
   Default: `"pending"` se `cve_id` non è vuota, `"skipped"` altrimenti.
   Gestisci questo nella `save()` override.

5. **Aggiorna `RiskLevel`** — aggiungi `CRITICAL = "critical", "Critical"` se mancante
   (verificare se già presente — dal codice sembra assente nel modello ma presente in deduplication)

6. **Aggiorna `dedup_key`** property — ora usa `affected_ip or affected_host`:
   ```python
   @property
   def dedup_key(self) -> tuple[str, str, str]:
       host = (self.affected_ip or self.affected_host).lower().strip()
       port = str(self.affected_port) if self.affected_port else ""
       return (self.title.lower().strip(), host, port)
   ```

7. **Aggiorna indici** — rimuovi l'indice su `["subproject", "title", "affected_host", "affected_port"]`
   e aggiungi `["subproject", "title", "affected_ip", "affected_host", "affected_port"]`

### Migrazione

Dopo le modifiche al modello, genera la migrazione:
```bash
python manage.py makemigrations vulnerabilities
```

Verifica che la migrazione generata:
- Cambi `affected_port` da `CharField` a `IntegerField` nullable
- Cambi `cve_id` da `CharField` a `JSONField`
- Aggiunga `affected_ip`
- Aggiunga `nvd_enrichment_status`

Se Django genera `RunSQL` per la conversione di tipo, verifica che sia corretta
per PostgreSQL (il `cve_id` CharField → JSONField richiede una conversione esplicita).

Forza la migrazione con dati nulli se necessario aggiungendo:
```python
# Nella migrazione generata, per cve_id CharField → JSONField su PostgreSQL:
migrations.RunSQL(
    "ALTER TABLE vulnerabilities_vulnerability ALTER COLUMN cve_id TYPE jsonb USING to_jsonb(cve_id);",
    reverse_sql="ALTER TABLE vulnerabilities_vulnerability ALTER COLUMN cve_id TYPE varchar(32) USING cve_id->>0;",
)
```

---

## FASE 2 — Aggiornamento `NormalizedVulnerability` in `deduplication.py`

**File:** `backend/apps/vulnerabilities/deduplication.py`

Questa è la struttura intermedia che i parser Layer 1 producono. Va allineata
al Layer 2 (`canonical_schema.NormalizedVulnerability`) ma mantenuta compatibile
con la pipeline Django esistente.

### Modifiche al dataclass `NormalizedVulnerability`

Aggiorna il dataclass per accettare i campi del Layer 2:

```python
@dataclass
class NormalizedVulnerability:
    # Campi base (invariati)
    title: str
    description: str = ""          # mappa da description_tool
    remediation: str = ""          # mappa da remediation_tool
    affected_host: str = ""        # hostname/FQDN
    affected_ip: str = ""          # NUOVO: indirizzo IP grezzo
    affected_port: int | None = None   # CAMBIATO: da str a int|None
    affected_service: str = ""
    affected_protocol: str = "tcp"     # NUOVO
    
    # CVE — ora lista
    cve_id: list[str] = field(default_factory=list)   # CAMBIATO: da str a list
    
    # Scoring
    cvss_score: float | None = None
    cvss_vector: str = ""
    epss_score: float | None = None
    risk_level: str = "medium"
    
    # Evidence
    evidence_code: str = ""        # mappa da evidence
    
    # Meta
    source: str = ""
    raw_output: str = ""
    
    # Enrichment
    nvd_enrichment_status: str = "pending"   # NUOVO
```

### Aggiornamento `deduplicate_and_save()`

Aggiorna la funzione per mappare i nuovi campi al modello DB:

- `norm.cve_id` (lista) → `vuln.cve_id` (JSONField lista)
- `norm.affected_port` (int|None) → `vuln.affected_port` (IntegerField)
- `norm.affected_ip` → `vuln.affected_ip`
- `norm.nvd_enrichment_status` → `vuln.nvd_enrichment_status`
- Il merge delle CVE in caso di deduplicazione deve fare union delle liste:
  ```python
  # Merge CVE lists (dedup)
  existing_cves = set(vuln.cve_id or [])
  new_cves = set(norm.cve_id or [])
  vuln.cve_id = sorted(existing_cves | new_cves)
  ```

### Aggiornamento `tasks.py`

**File:** `backend/apps/parsers/tasks.py`

Nel task `enrich_vulnerabilities_with_nvd`, aggiorna il filtro per CVE:
```python
# PRIMA (cve_id CharField):
vulns = Vulnerability.objects.filter(pk__in=vulnerability_ids, cve_id__gt="")

# DOPO (cve_id JSONField lista):
vulns = Vulnerability.objects.filter(pk__in=vulnerability_ids, cve_id__len__gt=0)
```

E aggiorna la logica di schedule in `parse_scan_file`:
```python
# PRIMA:
vuln_ids_with_cve = [v.pk for v in saved if v.cve_id]

# DOPO:
vuln_ids_with_cve = [v.pk for v in saved if v.cve_id]  # JSONField lista, truthy se non vuota
```

---

## FASE 3 — Adapter: Layer 2 → Layer 1

**File nuovo:** `backend/apps/parsers/scan_result_adapter.py`

Questo modulo converte `ScanImportResult` (Layer 2) in `list[NormalizedVulnerability]`
(Layer 1 aggiornato). È il bridge tra i due layer.

```python
"""
Adapter: converte ScanImportResult (cyberreport_pro_parsers) →
         list[NormalizedVulnerability] (apps.vulnerabilities.deduplication).

Questo modulo è il punto di integrazione tra il layer di parsing avanzato
(cyberreport_pro_parsers) e la pipeline Django (apps/parsers → tasks → DB).

Principio: nessuna logica di business qui — solo mappatura di campi.
Tutta la logica di parsing rimane nel Layer 2.
"""
from __future__ import annotations
from cyberreport_pro_parsers.parsers.canonical_schema import (
    ScanImportResult, NormalizedVulnerability as L2Vuln, Severity
)
from apps.vulnerabilities.deduplication import NormalizedVulnerability as L1Vuln


def adapt_scan_result(result: ScanImportResult) -> list[L1Vuln]:
    """
    Converte ScanImportResult → list[NormalizedVulnerability] Layer 1.
    
    Mapping fields:
      L2.affected_ip         → L1.affected_ip
      L2.affected_host       → L1.affected_host
      L2.affected_port       → L1.affected_port  (Optional[int] → int|None)
      L2.affected_protocol   → L1.affected_protocol
      L2.affected_service    → L1.affected_service
      L2.title               → L1.title
      L2.description_tool    → L1.description
      L2.remediation_tool    → L1.remediation
      L2.severity_tool       → L1.risk_level  (Severity enum → str lowercase)
      L2.cvss_score_tool     → L1.cvss_score
      L2.cve_ids_tool        → L1.cve_id  (list[str])
      L2.evidence            → L1.evidence_code
      L2.source_tool         → L1.source
      L2.raw_output          → L1.raw_output
      L2.nvd_enrichment_status → L1.nvd_enrichment_status  (.value)
    """
    out: list[L1Vuln] = []
    
    for v in result.vulnerabilities:
        # Severity enum → str lowercase per risk_level
        risk_level = (v.severity_tool.value.lower() if v.severity_tool else "medium")
        
        # EnrichmentStatus enum → str
        enrichment_status = (
            v.nvd_enrichment_status.value
            if v.nvd_enrichment_status else "pending"
        )
        
        out.append(L1Vuln(
            title=v.title,
            description=v.description_tool or "",
            remediation=v.remediation_tool or "",
            affected_ip=v.affected_ip or "",
            affected_host=v.affected_host or "",
            affected_port=v.affected_port,           # int|None
            affected_service=v.affected_service or "",
            affected_protocol=v.affected_protocol or "tcp",
            cve_id=list(v.cve_ids_tool or []),       # list[str]
            cvss_score=v.cvss_score_tool,
            cvss_vector="",                          # popolato da NVD enricher
            risk_level=risk_level,
            evidence_code=(v.evidence or "")[:4096],
            source=v.source_tool or "",
            raw_output=(v.raw_output or "")[:2048],
            nvd_enrichment_status=enrichment_status,
        ))
    
    return out
```

---

## FASE 4 — Aggiornamento parser Django (`apps/parsers/openvas_parser.py`)

**File:** `backend/apps/parsers/openvas_parser.py`

Sostituisci l'implementazione esistente con una versione che delega al Layer 2
e usa l'adapter. Mantieni la stessa interfaccia esterna (`tool_name`, `parse(IO[bytes])`).

```python
"""
OpenVAS / Greenbone e Nessus parsers — Django layer.

Questo modulo è un thin wrapper che:
  1. Legge il file (IO[bytes])
  2. Delega il parsing al Layer 2 (cyberreport_pro_parsers)
  3. Converte il risultato via scan_result_adapter
  4. Ritorna list[NormalizedVulnerability] compatibile con la pipeline Django

NON contiene logica di parsing — tutta nel Layer 2.
"""
from __future__ import annotations
import logging
from typing import IO

from apps.vulnerabilities.deduplication import NormalizedVulnerability
from .base import BaseParser, ParserError
from .scan_result_adapter import adapt_scan_result

logger = logging.getLogger(__name__)


class OpenVasParser(BaseParser):
    """
    Parser OpenVAS/Greenbone — supporta XML, CSV, Excel (.xlsx).
    Delega al Layer 2 (cyberreport_pro_parsers).
    """
    tool_name = "openvas"

    def parse(self, file_obj: IO[bytes]) -> list[NormalizedVulnerability]:
        from cyberreport_pro_parsers.parsers.openvas_parser import detect_and_parse
        
        data = file_obj.read()
        if not data:
            raise ParserError("OpenVAS: file vuoto.")
        
        try:
            result = detect_and_parse(data)
        except ValueError as exc:
            raise ParserError(str(exc)) from exc
        
        if result.parse_errors:
            for err in result.parse_errors:
                logger.warning("[openvas] Parse warning: %s", err)
        
        adapted = adapt_scan_result(result)
        logger.info("[openvas] Parsed %d vulnerabilities (%d errors).",
                    len(adapted), len(result.parse_errors))
        return adapted


class NessusParser(BaseParser):
    """
    Parser Nessus CSV — delega al Layer 2.
    """
    tool_name = "nessus"

    def parse(self, file_obj: IO[bytes]) -> list[NormalizedVulnerability]:
        from cyberreport_pro_parsers.parsers.openvas_parser import NessusCsvParser
        
        data = file_obj.read()
        if not data:
            raise ParserError("Nessus: file vuoto.")
        
        try:
            result = NessusCsvParser().parse(data)
        except Exception as exc:
            raise ParserError(f"Nessus parse error: {exc}") from exc
        
        return adapt_scan_result(result)
```

**IMPORTANTE:** Aggiorna anche il registry in `backend/apps/parsers/registry.py`
aggiungendo `"openvas_excel": OpenVasParser` — il parser riconosce già `.xlsx`
via `detect_and_parse()` dopo la Fase 5. Non serve un parser separato nel registry.

---

## FASE 5 — OpenVAS Excel Parser (Layer 2)

**File:** `backend/cyberreport_pro_parsers/parsers/openvas_parser.py`

Aggiungi la classe `OpenVasExcelParser` e aggiorna `detect_and_parse()`.

### Classe `OpenVasExcelParser`

```python
class OpenVasExcelParser(BaseParser):
    """
    Parser per OpenVAS/Greenbone Excel export (.xlsx).
    
    Il formato Excel di OpenVAS è strutturalmente identico al CSV:
    stesse colonne, stesso significato, stessa pipeline di parsing.
    Questo parser legge il foglio Sheet1 con pandas/openpyxl,
    converte ogni riga in un dict compatibile con OpenVasCsvParser._parse_row(),
    e delega la logica di normalizzazione a quest'ultimo.
    
    Dipendenza: openpyxl (aggiungere a requirements.txt)
    
    Sicurezza:
    - Validazione magic bytes prima di aprire con openpyxl (OWASP: file upload validation)
    - Limite righe (MAX_ROWS = 50_000) per prevenire DoS su file enormi
    - Nessuna esecuzione di macro/formula (data_only=True)
    - Timeout implicito dal limite righe
    """

    SOURCE_TOOL = "openvas"
    MAX_ROWS = 50_000
    # Magic bytes XLSX: PK\x03\x04 (ZIP container)
    XLSX_MAGIC = b'PK\x03\x04'

    def parse(self, source: bytes | str | Path) -> ScanImportResult:
        if isinstance(source, Path):
            source = source.read_bytes()
        if isinstance(source, str):
            raise ValueError("OpenVasExcelParser richiede bytes, non str.")
        
        # Validazione magic bytes (OWASP: non fidarsi dell'estensione)
        if not source[:4] == self.XLSX_MAGIC:
            raise ValueError("File non riconosciuto come XLSX (magic bytes errati).")
        
        try:
            import openpyxl
        except ImportError:
            raise ValueError(
                "openpyxl non installato. Aggiungere 'openpyxl' a requirements.txt."
            )
        
        import io as _io
        
        try:
            # data_only=True: ignora formule, legge solo valori calcolati
            # read_only=True: streaming mode, efficiente su file grandi
            wb = openpyxl.load_workbook(
                _io.BytesIO(source),
                read_only=True,
                data_only=True,
            )
        except Exception as exc:
            raise ValueError(f"Impossibile aprire file XLSX: {exc}") from exc
        
        # OpenVAS esporta sempre su Sheet1
        sheet_name = wb.sheetnames[0] if wb.sheetnames else None
        if not sheet_name:
            raise ValueError("File XLSX vuoto: nessun foglio trovato.")
        
        ws = wb[sheet_name]
        
        # Estrai righe come lista di tuple
        rows = list(ws.iter_rows(max_row=self.MAX_ROWS + 1, values_only=True))
        wb.close()
        
        if not rows:
            raise ValueError("Foglio Excel vuoto.")
        
        # Prima riga = header
        header = [str(cell).strip() if cell is not None else "" for cell in rows[0]]
        
        if len(rows) > self.MAX_ROWS + 1:
            logger.warning(
                "[openvas_excel] File con più di %d righe — troncato per sicurezza.",
                self.MAX_ROWS
            )
        
        # Converti righe in dict compatibili con OpenVasCsvParser._parse_row()
        csv_parser = OpenVasCsvParser()
        result = ScanImportResult(source_tool=self.SOURCE_TOOL)
        hosts_map: dict[str, NormalizedHost] = {}
        
        for row_num, row in enumerate(rows[1:self.MAX_ROWS + 1], start=2):
            try:
                # Costruisci dict {header: valore} normalizzando i tipi
                row_dict = {}
                for col_name, cell_val in zip(header, row):
                    if cell_val is None:
                        row_dict[col_name] = ""
                    elif isinstance(cell_val, (int, float)):
                        row_dict[col_name] = str(cell_val)
                    else:
                        row_dict[col_name] = str(cell_val).strip()
                
                vuln = csv_parser._parse_row(row_dict)
                if vuln is None:
                    continue
                
                result.vulnerabilities.append(vuln)
                
                ip_key = vuln.affected_ip or vuln.affected_host
                if ip_key and ip_key not in hosts_map:
                    hosts_map[ip_key] = NormalizedHost(
                        ip_address=vuln.affected_ip,
                        hostname=vuln.affected_host,
                        source_tool=self.SOURCE_TOOL,
                    )
            except Exception as exc:
                result.parse_errors.append(f"Row {row_num}: {exc}")
                logger.warning("[openvas_excel] Row %d error: %s", row_num, exc)
        
        result.hosts = list(hosts_map.values())
        return result
```

### Aggiornamento `detect_and_parse()`

Aggiorna la funzione esistente aggiungendo il riconoscimento XLSX **prima** del check XML:

```python
def detect_and_parse(source: bytes | str | Path) -> ScanImportResult:
    """
    Ordine di detection:
      1. Magic bytes PK\x03\x04 → XLSX → OpenVasExcelParser
      2. Primo byte '<' → XML → OpenVasXmlParser
      3. Header CSV con 'NVT Name'/'NVT OID' → OpenVasCsvParser
      4. Header CSV con 'CVSS v2.0 Base Score'/'Risk' → NessusCsvParser
    """
    if isinstance(source, Path):
        raw = source.read_bytes()
    elif isinstance(source, str):
        raw = source.encode('utf-8')
    else:
        raw = source

    # 1. XLSX detection (magic bytes)
    if raw[:4] == b'PK\x03\x04':
        logger.info("[detect_and_parse] Detected XLSX format.")
        return OpenVasExcelParser().parse(raw)

    # 2. XML detection
    if raw.lstrip()[:1] == b'<':
        logger.info("[detect_and_parse] Detected XML format.")
        return OpenVasXmlParser().parse(raw)

    # 3. CSV detection
    try:
        text = raw.decode('utf-8', errors='replace')
        first_line = text.split('\n')[0]
        if 'CVSS v2.0 Base Score' in first_line and 'Risk' in first_line:
            logger.info("[detect_and_parse] Detected Nessus CSV format.")
            return NessusCsvParser().parse(text)
        if 'NVT Name' in first_line or ('IP' in first_line and 'NVT OID' in first_line):
            logger.info("[detect_and_parse] Detected OpenVAS CSV format.")
            return OpenVasCsvParser().parse(text)
    except Exception:
        pass

    raise ValueError(
        "Formato non riconosciuto. "
        "Attesi: OpenVAS XLSX, OpenVAS XML, OpenVAS CSV, Nessus CSV."
    )
```

---

## FASE 6 — Dipendenze

**File:** `backend/requirements.txt`

Aggiungi dopo `pillow`:
```
openpyxl==3.1.5
```

Verifica la versione più recente stabile con:
```bash
pip index versions openpyxl
```

**NON aggiungere pandas per questa feature** — il parsing Excel viene fatto
con openpyxl direttamente (pandas è già in requirements.txt per altri scopi
ma non va usato qui perché openpyxl in read_only mode è più efficiente
su file grandi e non richiede la costruzione di un DataFrame intermedio).

---

## FASE 7 — Aggiornamento `ScanImport.Tool`

**File:** `backend/apps/vulnerabilities/models.py`

Aggiungi il tool `OPENVAS_EXCEL` se vuoi distinguerlo nell'UI, oppure lascia
tutto sotto `OPENVAS` (il parser lo gestisce in entrambi i casi tramite `detect_and_parse`).

**Raccomandazione:** lascia `OPENVAS` come tool unico. Il formato del file
è un dettaglio implementativo, non una scelta dell'utente.

---

## FASE 8 — Test

**File nuovo:** `backend/tests/parsers/test_openvas_excel.py`

```python
"""
Test per OpenVasExcelParser.
Usa il file reale: report-7d66719c-9bd9-46cd-b13c-48a84e53ffd6.xlsx
"""
import pytest
from pathlib import Path
from cyberreport_pro_parsers.parsers.openvas_parser import (
    OpenVasExcelParser, detect_and_parse
)
from apps.parsers.scan_result_adapter import adapt_scan_result

# Path del file reale (da aggiustare al path corretto nel repo)
REAL_XLSX = Path("tests/fixtures/openvas_report.xlsx")


@pytest.mark.skipif(not REAL_XLSX.exists(), reason="File fixture non trovato")
class TestOpenVasExcelParser:
    
    def test_parse_returns_vulnerabilities(self):
        data = REAL_XLSX.read_bytes()
        result = OpenVasExcelParser().parse(data)
        assert len(result.vulnerabilities) > 0
        assert len(result.parse_errors) == 0

    def test_parse_fields_populated(self):
        data = REAL_XLSX.read_bytes()
        result = OpenVasExcelParser().parse(data)
        vuln = result.vulnerabilities[0]
        assert vuln.title
        assert vuln.affected_ip or vuln.affected_host
        assert vuln.severity_tool is not None

    def test_detect_and_parse_xlsx(self):
        """detect_and_parse deve riconoscere XLSX da magic bytes."""
        data = REAL_XLSX.read_bytes()
        result = detect_and_parse(data)
        assert result.source_tool == "openvas"
        assert len(result.vulnerabilities) > 0

    def test_adapter_compatibility(self):
        """Il risultato dell'adapter deve essere compatibile con il Layer 1."""
        data = REAL_XLSX.read_bytes()
        result = OpenVasExcelParser().parse(data)
        adapted = adapt_scan_result(result)
        assert all(isinstance(v.affected_port, (int, type(None))) for v in adapted)
        assert all(isinstance(v.cve_id, list) for v in adapted)

    def test_magic_bytes_validation(self):
        """File non-XLSX deve essere rifiutato."""
        with pytest.raises(ValueError, match="magic bytes"):
            OpenVasExcelParser().parse(b"not an xlsx file")

    def test_empty_file_raises(self):
        """File XLSX vuoto (solo magic bytes) non deve crashare silenziosamente."""
        with pytest.raises(ValueError):
            OpenVasExcelParser().parse(b'PK\x03\x04' + b'\x00' * 100)


class TestOpenVasExcelVsCsv:
    """
    Verifica che Excel e CSV dello stesso scan producano risultati equivalenti.
    Se hai il CSV corrispondente all'XLSX, aggiungilo come fixture e attiva questi test.
    """
    pass  # Da implementare quando disponibile il CSV corrispondente
```

**Copia il file reale nella directory fixtures:**
```bash
cp /path/to/report-7d66719c-9bd9-46cd-b13c-48a84e53ffd6.xlsx \
   backend/tests/fixtures/openvas_report.xlsx
```

---

## Ordine di esecuzione obbligatorio

```
1. FASE 1  — Modifica models.py + genera migrazione
2. FASE 2  — Aggiorna deduplication.py (NormalizedVulnerability + deduplicate_and_save)
3. FASE 3  — Crea scan_result_adapter.py
4. FASE 4  — Aggiorna apps/parsers/openvas_parser.py (thin wrapper)
5. FASE 5  — Aggiungi OpenVasExcelParser in cyberreport_pro_parsers/
6. FASE 6  — Aggiorna requirements.txt
7. FASE 7  — Valuta ScanImport.Tool (probabilmente nessuna modifica)
8. FASE 8  — Scrivi e lancia i test
```

**Non saltare fasi e non invertire l'ordine.** Le Fasi 1-2 devono essere
applicate prima delle Fasi 3-5 perché l'adapter dipende dallo schema aggiornato.

---

## Verifica finale

Dopo tutte le fasi, esegui in sequenza:

```bash
# 1. Migrazione DB
python manage.py migrate

# 2. Test suite completa — deve rimanere verde
pytest --tb=short -q

# 3. Test specifici Excel
pytest tests/parsers/test_openvas_excel.py -v

# 4. Smoke test manuale (opzionale)
python manage.py shell -c "
from apps.parsers.registry import get_parser
from pathlib import Path

p = get_parser('openvas')
with open('tests/fixtures/openvas_report.xlsx', 'rb') as f:
    vulns, err = p.safe_parse(f)
print(f'Parsed: {len(vulns)} vulns, error: {err}')
print(f'First: {vulns[0].title if vulns else None}')
print(f'Port type: {type(vulns[0].affected_port) if vulns else None}')
print(f'CVE type: {type(vulns[0].cve_id) if vulns else None}')
"
```

---

## Segnali di conflitto da rilevare

Prima di iniziare, Claude Code deve verificare:

1. **Altri parser** (`burp_parser.py`, `nmap_parser.py`, ecc.) che producono `NormalizedVulnerability`
   con `affected_port` come stringa o `cve_id` come stringa — **devono essere aggiornati**
   per allinearsi al nuovo schema. Non farlo causerebbe errori a runtime nel `deduplicate_and_save()`.

2. **Serializers/Views** che accedono a `vulnerability.cve_id` come stringa — verificare
   in `apps/vulnerabilities/` e aggiornare di conseguenza.

3. **Test esistenti** che asseriscono su `affected_port` come stringa o `cve_id` come stringa —
   aggiornare le asserzioni.

⚠️ **REGOLA CRITICA**: Non aggiornare gli altri parser (Burp, Nmap, ecc.) con logica diversa
da quella esistente. Il cambio richiesto è solo sui tipi di dato (`str → int` per port,
`str → list` per cve_id). La logica di parsing rimane invariata.

---

## Note architetturali finali

- `cyberreport_pro_parsers/` rimane una libreria Python pura, senza dipendenze Django.
  Non importare mai modelli Django lì dentro.
- `apps/parsers/` rimane il layer di integrazione Django. Tutta la logica di parsing
  vive nel Layer 2; il Layer 1 è solo un thin wrapper + adapter.
- L'adapter `scan_result_adapter.py` è l'unico punto di contatto tra i due layer.
  Se in futuro il Layer 2 cambia schema, si aggiorna solo l'adapter.
- I parse_errors del `ScanImportResult` vengono loggati come warning, non propagati
  come errori fatali — coerente con il comportamento esistente degli altri parser.
