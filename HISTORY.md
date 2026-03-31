# Shelter — Decision History

Questo file documenta le decisioni architetturali, i bug risolti e le motivazioni
che hanno guidato ogni scelta non ovvia. Consultarlo all'inizio di ogni sessione
per evitare di ripercorrere strade già esplorate.

---

## 2026-03-30 — Parser coverage, Style fixes, Editable Sections

### Contesto

Sessione di continuazione. Parser e style erano parzialmente completati nella
sessione precedente. Editable sections è stata progettata nella sessione
precedente e implementata in questa.

---

### 1. Fix parser: Trivy legacy array format e Qualys XML

**Problema:**
- `trivy_parser.py`: file con formato Trivy v1 dove la root è una lista
  (non `{Results:[...]}`). Il parser crashava su `isinstance(None, dict)` e
  `isinstance(None, list)` per il caso `null`.
- `qualys_parser.py`: file XML `ASSET_DATA_REPORT` — il parser CSV tentava di
  leggere chiavi `None` su contenuto XML.
- `nuclei_parser.py`: `raw_output=line[:2048]` crashava per input JSON array
  perché `line` è definita solo nel loop JSONL.
- `github_vulnerability_parser.py`: lista flat REST API non riconosciuta
  (atteso formato GraphQL Security Alerts).

**Decisioni:**

*Trivy*: aggiunto `if data is None: return []` prima dei check isinstance, poi
branch `isinstance(data, list)`. Alternativa scartata: parser separato
`trivy_legacy` — overhead non giustificato, il formato è distinguibile in runtime.

*Qualys*: rilevamento XML tramite `stripped.startswith("<?xml")` o
`"<ASSET_DATA_REPORT"`, routing a `_parse_xml()` separato. Glossario QID
costruito una volta sola.

*Nuclei*: `raw_output=line[:2048]` → `json.dumps(obj, default=str)[:2048]`.

*GitHub*: aggiunto `isinstance(data, list) → _parse_code_scanning(data)`.
Scartato: parametro `format_hint` — la detection automatica è più robusta.

---

### 2. Fix Style: Border Radius e Evidence Highlight

**Problema:** le opzioni stile non avevano effetto visibile:
- Border radius 0/2/6/12px indistinguibili in PDF.
- Evidence highlight ignorato per audience `executive`.
- Default `"code"` nel generator vs `"box"` nel frontend.

**Fix:** valori aggiornati a 0/4/10/20px; rimosso gate `audience == 'technical'`
(il contenuto è scritto manualmente dall'utente — sempre pertinente); default
allineato a `"box"` ovunque.

---

### 3. Fix: Nuovi parser non visibili nel dropdown

`SCANNER_OPTIONS` in `SubProjectPage.tsx` conteneva solo 8 entry originali.
Espanso a 37 entry, organizzate in 5 gruppi logici (Original, Cloud & Infra,
Web & Application, Code & Secret Scanning, Network & Credential).

Scartato: endpoint dinamico `/parsers/available/` — over-engineering per una
lista statica che cambia solo quando si aggiungono parser.

---

### 4. Feature: Report Sections editabili

**Struttura dati:** `options.section_overrides = {section_id: {custom_text: str}}`
nel JSONField esistente di `ReportExport`.

**Perché JSONField e non nuovo modello DB:** nessuna migration, la sezione
override è parte della configurazione del report (non ha lifecycle proprio),
coerente con `style`, `extra`, `charts_*` già in `options`.

**Scartato:** `SectionOverride(export, section_id, custom_text)` — complessità
relazionale inutile per dati che vivono e muoiono con l'export.
**Scartato:** localStorage — perderebbe i dati alla riapertura di un export.

**Template — macro `_ci(sid)`:** helper centralizzato che legge
`section_overrides.get(sid, {}).get('custom_text', '')`, applica `nl2br`
(con `Markup` per evitare double-escaping), e renderizza solo se non vuoto.
Guard `is defined` + `is mapping` proteggono da `UndefinedError` e input
malformato.

**Sanitizzazione in views.py:** filtra entry non-dict e `custom_text` vuoto
prima di salvare; forza `str()` per sicurezza di tipo.

**UI — inline editor:** espansione inline sotto la riga (non modal/drawer).
Chips cliccabili per inserire finding, limitate alle prime 30 vuln filtrate.
Blue dot sull'header di riga per sezioni con testo.

---

### Bug risolti (2026-03-30)

| Bug | Fix |
|-----|-----|
| Trivy root=null crash | `if data is None: return []` |
| Trivy v1 root=list crash | `isinstance(data, list)` branch |
| Nuclei `UnboundLocalError` per `line` | `json.dumps(obj)[:2048]` |
| GitHub Code Scanning list format | `isinstance(data, list) → _parse_code_scanning()` |
| Evidence non visibile per executive | Rimosso gate `audience == 'technical'` |
| Border radius indistinguibile in PDF | Valori 0/4/10/20px (erano 0/2/6/12) |
| Evidence default mismatch | `s.get("evidenceStyle", "box")` |
| Nuovi parser non nel dropdown | `SCANNER_OPTIONS` espanso a 37 entry |
| `_ci` macro crash se `section_overrides` undefined | Guard `is defined` in macro |
| `section_overrides` invia entry vuote | Filtra `v.custom_text.trim()` prima di inviare |

**Stato parser al 2026-03-30:** 209 test OK / 12 WARN intenzionali (file
non-parseable, formati alternativi documentati come non supportati).
Parser registrati: 37 nel `PARSER_REGISTRY`, 37 nel `SCANNER_OPTIONS` frontend.

---

## 2026-03-31 — NVD enrichment fix, CI/CD, fix licenza

### 1. Fix `cve_id` type mismatch

Backend: `cve_id = models.JSONField(default=list)` restituisce `string[]`.
Frontend aveva `cve_id: string` in `types.ts`. Fix: cambiato in `string[]`
ovunque; `[0]` per il CVE primario; `.join(", ")` per il display; form wrappa
il valore in `[value]` al submit.

### 2. Fix licenza: `_configured` AttributeError

`_validate_pro_online` chiamava `client._configured` ma la property non era
definita su `WPLicenseClient`. Dopo 12h dall'attivazione il check online
scatenava `AttributeError`, il middleware silenziava l'eccezione → licenza
risultava inattiva.

Fix: aggiunta property `_configured` a `WPLicenseClient`; aggiunto
try/except difensivo attorno a `_validate_pro_online` in `refresh_status()`.

### 3. GitHub Actions CI + Security

Aggiunti: `.github/workflows/ci.yml` (pytest + PostgreSQL/Redis services, tsc,
vite build), `.github/workflows/security.yml` (pip-audit, npm audit, Gitleaks),
`.github/dependabot.yml` (pip/npm/actions settimanale con grouping).

---

## 2026-04-01 — Bulk status, scan import filtering, paginazione

### 1. Endpoint bulk status (`PATCH /api/v1/vulnerabilities/bulk-status/`)

`BulkStatusUpdateView` con `QuerySet.update()` — O(1) query DB invece di N
chiamate PATCH individuali. IDOR protection: filter per
`organization=request.user.organization` prima dell'update. Limite 500 ID per
request (`max_length=500`) per evitare query unbounded.

Scartato: N `PATCH /vulnerabilities/<pk>/` in loop — N round-trip, race condition.
Scartato: action su ViewSet — il progetto non usa ViewSet.

### 2. Scan import filtering — propagazione dello stato

`selectedScanIds: Set<number>` in `SubProjectPage`, propagato come:
- `disabledIds` → `VulnerabilityTable` (filtraggio puramente client-side,
  nessun re-fetch)
- `scan_import_ids` → `navigate state` → `ReportBuilderPage` → payload report

Generator backend: `Q(scan_import__isnull=True) | Q(scan_import_id__in=ids)` —
le vuln create manualmente sono sempre incluse nel report.

**Bug fix — loose null check:** `v.scan_import != null` (loose) invece di
`!== null` (strict). Il check loose cattura anche `undefined`, che si presentava
quando il backend non era stato riavviato e il vecchio serializer non restituiva
il campo `scan_import`. Senza questo, tutte le vuln venivano disabilitate.

Scartato: re-fetch server-side per ogni toggle scan import — latenza visibile,
romperebbe la selezione bulk.
Scartato: `deselectedScanIds` (logica invertita) — gestione dello stato iniziale
più complessa.

### 3. Context menu con React Portal

`createPortal(…, document.body)` con `position: fixed` + coordinate
`clientX/clientY`. Necessario perché la tabella è dentro `overflow-x-auto`:
un elemento `position: absolute` figlio verrebbe clippato.

Comportamento right-click: se la riga è selezionata → applica a tutti i
selezionati; se non selezionata → seleziona quella e applica solo ad essa;
righe disabilitate → nessuna azione.

Scartato: menu dropdown inline nella riga — clippato da `overflow-x-auto`.
Scartato: toolbar fissa — nasconde il contesto.

### 4. Paginazione client-side

Selector 10 / 25 / 50 / All, default 25. Navigazione con numeri di pagina e
ellissi (finestra ±2 attorno alla corrente). Reset automatico a pagina 1 su
cambio sort o lunghezza dati.

Scartato: paginazione server-side — le vuln sono già tutte in memoria, e
romperebbe la selezione bulk (non puoi "seleziona tutti" su pagine separate).
Scartato: virtual list — complessità elevata, incompatibile con select-all.

---

## Note architetturali permanenti

### Jinja2 macros e template context
Le macro definite nello stesso file template **possono** accedere alle variabili
passate a `template.render()`. Diverso dalle macro importate da altri file
(che non hanno accesso al context). Confermato da: `vulnerabilities`, `rpt_style`,
`audience`, `charts`, `hosts` usati direttamente nelle macro senza passarli
come argomenti.

### `section_overrides` vs `ReportExport.options`
`options` è il "cargo" di configurazione dell'export. Tutto ciò che configura
COME generare il report va in `options`. I dati del report (vulnerability, host)
vengono letti dal DB al momento della generazione. Non mescolare i due.

### Parser error handling
I parser restituiscono `[]` per input vuoti/null. Lanciano `ParserError` solo
per formato malformato. "Nessuna vulnerability trovata" è un risultato valido,
non un errore.

### `SCANNER_OPTIONS` vs `PARSER_REGISTRY`
Devono essere sincronizzati manualmente quando si aggiunge un parser. Non esiste
un endpoint che espone i parser disponibili. Considerare di aggiungerne uno se
la lista supera 50 entry o si implementa un meccanismo di plugin.

### `scan_import` field nei serializer
`VulnerabilityListSerializer` include `scan_import` (aggiunto il 2026-04-01).
Se il backend non è riavviato dopo la modifica, il campo non è presente nella
risposta e il client riceve `undefined` — proteggersi con `!= null` (loose).
