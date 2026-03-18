# CyberReport Pro — Decisioni di Sessione
> Documento generato al termine della sessione di design e sviluppo.
> Raccoglie tutte le decisioni architetturali, di prodotto e implementative prese.

---

## 1. TIPOLOGIE DI REPORT

### 1.1 Report Cybersecurity
| Tipo | Scopo |
|---|---|
| Penetration Test Report | Risultati pentest black/grey/white box |
| Vulnerability Assessment Report | Scansione sistematica senza exploitation |
| Red Team Report | Simulazione APT con narrative attack path |
| Web Application Security Report | Focus OWASP Top 10, DAST/SAST |
| Mobile Application Security Report | iOS/Android, OWASP MASVS |
| Cloud Security Assessment | AWS/Azure/GCP misconfig, IAM, exposure |
| Network Security Assessment | Segmentazione, firewall rules, esposizione |
| Social Engineering / Phishing Report | Campagne phishing/vishing, risultati |
| Incident Response Report | Post-incident: timeline, IoC, containment |
| Threat Intelligence Report | TTPs, attori, vulnerabilità emergenti |
| Compliance Gap Assessment | ISO 27001, NIS2, GDPR, PCI-DSS, DORA |
| OSINT Report | Esposizione pubblica, footprint digitale |
| Executive Summary (standalone) | Sintesi non tecnica per board/management |

### 1.2 Report IT Generale
| Tipo | Scopo |
|---|---|
| IT Infrastructure Assessment | Stato generale infrastruttura |
| Code Review Report | Analisi statica del codice |
| Architecture Review | Valutazione architetturale |
| Disaster Recovery Assessment | RTO/RPO, backup, continuità |
| Performance & Capacity Report | Metriche sistema, bottleneck |
| Audit IT | Conformità procedure, asset inventory |

### 1.3 Remediation & Follow-up
| Tipo | Scopo |
|---|---|
| Remediation Plan | Piano di rientro con priorità e owner |
| Retest / Verification Report | Verifica fix delle vulnerabilità precedenti |
| Risk Register | Registro rischi con risk acceptance |
| Patch Management Report | Stato aggiornamenti, CVE pendenti |

### 1.4 Breach & Incident
| Tipo | Scopo |
|---|---|
| Breach Notification Report | Per autorità (GDPR Art. 33/34), clienti |
| Forensic Investigation Report | Analisi forense, catena di custodia |
| Malware Analysis Report | Analisi campione, IOC, comportamento |
| Post-Incident Lessons Learned | RCA, miglioramenti processo |

---

## 2. DESTINATARI E COSA VOGLIONO

| Destinatario | Profilo | Vuole sapere | Non vuole |
|---|---|---|---|
| Executive / C-Level | CEO, CTO, Board | Rischio business, impatto economico, trend | Dettagli tecnici, CVE ID, comandi |
| Management / CISO | Responsabile sicurezza | KPI, priorità, gap vs standard, costo remediation | Output grezzi di tool |
| Project Manager | Coordina remediation | Chi fa cosa, tempi, dipendenze, stato avanzamento | Analisi tecnica profonda |
| Technical Lead / Architect | Decide le soluzioni | Dettaglio vuln, attack path, root cause | Grafici executive |
| Sysadmin / DevOps | Implementa i fix | Comandi esatti, patch, configurazioni, PoC | Analisi strategica |
| Sviluppatore | Fixa il codice | Snippet vulnerabile, CWE, esempio di fix, SAST finding | Metriche di business |
| Auditor / Compliance | Verifica conformità | Mappatura a standard (NIST, ISO), evidenze | Narrative di attacco |
| Cliente finale (non tecnico) | Capire l'esposizione | Linguaggio semplice, analogie | Acronimi senza spiegazione |
| Legale / DPO | Gestione GDPR, notifiche | Dati personali esposti, tempistiche, misure adottate | Dettagli exploit |

---

## 3. STRUTTURA OTTIMALE DEL REPORT (Pentest/VA completo)

```
1.  COVER PAGE
    - Logo cliente + logo azienda, titolo, data, versione, classificazione (CONFIDENTIAL)

2.  DOCUMENTO DI CONTROLLO
    - Versioning, autori, revisori, approvatori, disclaimer, distribuzione autorizzata

3.  EXECUTIVE SUMMARY  ← 1-3 pagine, per C-Level
    - Scope in una frase
    - Giudizio complessivo (es. "postura di sicurezza CRITICA")
    - KPI visivi: totale vuln per severity (donut chart)
    - Top 3 rischi con impatto business (NO CVE, SÌ linguaggio business)
    - Risk score complessivo (gauge/semaforo)
    - Trend vs assessment precedente
    - Raccomandazioni strategiche (3-5 bullet)

4.  SCOPE & METODOLOGIA
    - Obiettivi, perimetro (IP, domini, app), esclusioni esplicite
    - Periodo di esecuzione, metodologia (OWASP, PTES, OSSTMM, NIST SP 800-115)
    - Limitazioni, tool utilizzati

5.  RIEPILOGO RISULTATI  ← per Management/CISO
    - Tabella riepilogativa per severity e host
    - Grafici distribuzione (severity, categoria, host)
    - Risk matrix (likelihood × impact)
    - Top vulnerabilità critiche

6.  VULNERABILITY DETAILS  ← per Technical Lead + Sysadmin
    Ordinamento: severity DESC → CVSS DESC → EPSS DESC → host ASC
    Per ogni vuln:
    - ID interno (VUL-001), Titolo, Severity + CVSS + vector
    - EPSS score, CVE/CWE reference
    - Affected host/port/service
    - Descrizione, Impact, Evidenza (screenshot + output), Remediation, Riferimenti

7.  APPENDICI
    - A: Output grezzi scanner (opzionale)
    - B: Glossario
    - C: Mappatura a standard (OWASP/NIST/ISO)
    - D: Metodologia CVSS dettagliata

8.  LAST PAGE — Firma, contatti, disclaimer finale
```

---

## 4. GRAFICI: QUALI E DOVE

### Executive Summary
| Grafico | Tipo | Dato |
|---|---|---|
| Distribuzione severity | Donut chart | N vuln per Critical/High/Medium/Low/Info |
| Risk gauge | Gauge/semaforo | Score complessivo 0-100 |
| Trend storico | Line chart | Vuln totali nel tempo (subprogetti) |
| Top 5 host più esposti | Horizontal bar | N vuln critiche per host |

### Sezione Risultati
| Grafico | Tipo | Dato |
|---|---|---|
| Risk matrix | Bubble/heatmap | Likelihood × Impact per vuln |
| Vuln per categoria | Bar chart | Injection, Auth, Config... |
| Remediation effort | Stacked bar | Effort stimato per severity |
| Fixed vs Open | Progress bar / donut | Stato remediation (nei retest) |

### Dettaglio tecnico
| Grafico | Tipo | Dato |
|---|---|---|
| CVSS breakdown | Radar chart | Vettori AV/AC/PR/UI/S/C/I/A |
| Attack path | Flow diagram | Catena di exploitation |
| Timeline attacco | Gantt/timeline | Sequenza azioni (Red Team) |

---

## 5. REGOLE QUANTITÀ INFORMAZIONI

- **Executive Summary**: max 2-3 pagine. Zero CVE ID. Zero comandi. Solo impatto business.
- **Ogni vulnerabilità**: max 1 pagina (2 se ha molti screenshot).
- **Screenshot**: 1-3 per vulnerabilità. Sempre con caption contestuale.
- **Output grezzi**: mai nel corpo principale. Sempre in appendice.
- **Testo**: paragrafi brevi (3-5 righe). Una vuln = un problema = una soluzione.
- **Tabelle**: preferite alle liste quando ci sono 3+ attributi per elemento.

---

## 6. STACK DIPENDENZE PER REPORT ENTERPRISE

### PDF Generation
| Libreria | Decisione |
|---|---|
| **WeasyPrint** | ✅ Default: HTML→PDF, buon controllo layout |
| **Playwright** | ⭐ Alternativa premium: Chromium headless, CSS perfetto |
| ReportLab | ✅ Per grafici embedded complessi |
| xhtml2pdf | ❌ Evitare |

### Grafici (per embedding in PDF)
| Libreria | Uso |
|---|---|
| **Matplotlib + Seaborn** | ✅ PDF: grafici standard, heatmap, distribuzione |
| **Plotly + Kaleido** | ✅ PDF: grafici complessi (kaleido==0.2.1 versione fissa) |
| **Plotly.js + D3.js** | ✅ HTML report interattivo |

### Stack completo raccomandato
```
weasyprint>=60.0
playwright>=1.40          # alternativa premium
matplotlib>=3.8
seaborn>=0.13
plotly>=5.18
kaleido==0.2.1            # versione fissa, quella nuova ha bug
Jinja2>=3.1
pandas>=2.1
numpy>=1.26
pypdf>=3.0                # merge/manipolazione PDF post-generazione
Pillow>=10.0              # preprocessing immagini/screenshot
cairosvg>=2.7             # SVG→PNG ad alta risoluzione
```

---

## 7. ORDINAMENTO VULNERABILITÀ NEI REPORT

```
Ordinamento primario:   severity DESC (Critical → High → Medium → Low → Info)
Ordinamento secondario: CVSS score DESC
Ordinamento terziario:  EPSS score DESC (probabilità exploit reale)
Ordinamento quaternario: host/IP ASC (raggruppamento logico)
```

Le vulnerabilità **PERSISTENT** (non fixate da assessment precedente) vengono evidenziate
con badge visivo e portate in cima all'interno della loro severity class.

---

## 8. ARCHITETTURA PARSER — DECISIONI CHIAVE

### 8.1 Schema Canonico a 3 Livelli

```
LIVELLO 1 — RAW EXTRACTION
  Estrae dati grezzi dal file senza interpretazione.

LIVELLO 2 — FIELD MAPPING
  Traduce raw fields → canonical fields.
  Usa mapping statico per tool noti, mapping custom per tool sconosciuti,
  fall-back su campo utente-definito se mapping mancante.

LIVELLO 3 — NORMALIZATION & VALIDATION
  Converte i valori nel tipo corretto del DB.
```

### 8.2 Separazione Parser / NVD Enricher

**DECISIONE FONDAMENTALE**: I parser riempiono SOLO i campi Sezione A.
Il NVD Enricher è l'UNICA fonte autoritativa per CVSS/CWE/CPE/KEV.

```
SEZIONE A (Parser fields):
  affected_ip, affected_host, affected_port, affected_protocol,
  affected_service, title, description_tool, severity_tool,
  cvss_score_tool, cve_ids_tool, evidence, evidence_request,
  evidence_response, affected_url, http_method, remediation_tool,
  references_tool, is_exploit_available_tool, source_tool, source_script,
  raw_output

SEZIONE B (NVD Enricher fields — parser lascia None):
  description_nvd, severity, cvss_score, cvss_vector, cvss_version,
  cvss_av, cvss_ac, cvss_pr, cvss_ui, cvss_scope, cvss_c, cvss_i, cvss_a,
  cvss_exploitability_score, cvss_impact_score, cwe_id, cwe_ids,
  cve_published, cve_last_modified, cve_status, references_nvd,
  cpe_affected, is_kev, kev_date_added, kev_action_due, kev_required_action,
  is_exploit_available_nvd

SEZIONE C (Stato e metadati):
  nvd_enrichment_status, diff_status, is_recurring,
  user_severity_override, user_notes, status
```

### 8.3 Gerarchia delle Fonti (priorità decrescente)
1. **user_severity_override** — override manuale utente (massima priorità)
2. **NVD API v2** — CVSS/severity/CWE/CPE/KEV (autoritativo)
3. **Tool output** — host/port/service/evidence/title
4. **Euristica parser** — severity da pattern su description (solo se NO cve_id)

### 8.4 Gestione OSVDB (deprecato dal 2016)

**DECISIONE**: OSVDB è morto. La pipeline corretta è:
1. Parser estrae `cve_ids_tool` dal file
2. Se CVE presente → NVD Enricher popola tutto
3. Se no CVE → euristica su description (pattern matching) → `severity_tool`
4. Nikto: lookup nel suo stesso `db_tests` interno per mappare `item/@id` → CVE

### 8.5 Rate Limiting NVD API
- **Senza API key**: 5 req / 30s → delay 6s tra richieste
- **Con API key**: 50 req / 30s → delay 0.6s tra richieste
- **Celery task** asincrono per enrichment batch post-import
- `nvd_enrichment_status`: PENDING → DONE / PARTIAL / FAILED / SKIPPED

### 8.6 Deduplication Cross-Tool

```python
def dedup_key(vuln) -> str:
    title_norm = re.sub(r'[\d\./\-]+', '', vuln.title.lower().strip())
    host_norm  = vuln.affected_host or vuln.affected_ip or "unknown"
    port_norm  = str(vuln.affected_port) if vuln.affected_port else "any"
    return SHA256(f"{title_norm}|{host_norm}|{port_norm}")[:16]
```

Due vuln da tool diversi con stessa (title_norm, host, port) → stesso record,
campo `sources` unito: `["nmap", "openvas"]`.

### 8.7 Diff Vulnerabilità tra SubProgetti

```
NEW        — nuova, non presente nel subproject precedente
FIXED      — era presente, ora non più
PERSISTENT — presente in entrambi, non fixata → is_recurring=True
CHANGED    — stessa vuln, severity o altri campi cambiati
```

---

## 9. PARSER IMPLEMENTATI

### 9.1 Nmap XML Parser (`nmap_parser.py`)
- File reali testati: 20 file XML (discovery, full_tcp, udp, os, ssl, vuln, smb, ssh, snmp, smtp, ftp, dns, db, web, http_vuln, services, eternal)
- Handler NSE dedicati: `vulners`, `smb-vuln-*`, `ssl-*`, `http-vuln-*`, `ftp-anon`, `smtp-open-relay`, `dns-recursion`, `ssh2-enum-algos`
- Exploit flag dalla vulners: alza severity di 1 livello
- Script negativi (CSRF "not found", relay "doesn't seem"): non producono vuln
- OS detection con accuracy, CPE, vendor, family, generation
- Traceroute parsing
- **71/71 test passati**

### 9.2 Nikto XML Parser
- File reali: 5 file XML (basic, all, complete, scanme.nmap.org)
- Struttura XML Nikto analizzata: `niktoscan > scandetails > item`
- Fixture sintetica con CVE/XSS/traversal reali per coverage completa
- Severity: da db_tests Nikto interno (tuning category) + pattern matching description
- OSVDB mappato via lookup statico → CVE quando possibile
- NVD Enricher per enrichment post-import

### 9.3 Burp Suite XML Parser (`burp_parser.py`)
- File reali testati: DomXss.xml, ExoprtSSRF.xml (4 SSRF), Exporta-17_5_25_ssrfikea.xml (65), Report-ikea.xml (80), Report-ikea_mini.xml (55), ssrf-headers.xml (1203)
- Fix critico: XML 1.1 → 1.0 (Burp usa 1.1 non supportato da Python natively)
- Request/Response base64 decodificate automaticamente
- `dynamicAnalysis`: source/sink/poc/origin estratti
- `collaboratorEvent`: SSRF/OOB interaction details
- `staticAnalysis`: source/sink/codeSnippets
- `prototypePollution`: poc/technique/type
- CWE estratti da `vulnerabilityClassifications` (link `cwe.mitre.org`)
- HTML cleaning con preservazione struttura (br→\n, li→bullet)
- `host/@ip` attribute separato dall'hostname
- **48/48 test passati**

### 9.4 OpenVAS/Greenbone + Nessus Parser (`openvas_parser.py`)
- 3 formati in un unico modulo con `detect_and_parse()` auto-detection
- **OpenVAS XML** (formato GMP): struttura doppiamente nidificata `report→report→results→result`
  - Tags pipe-separated: `summary|insight|affected|impact|vuldetect|solution_type`
  - CVSS da `nvt/severities/severity[@type='cvss_base_v3']` con fallback su `nvt/cvss_base`
  - CVE da `refs/ref[@type='cve']`, URL da `refs/ref[@type='url']`
  - QoD (Quality of Detection 0-100) incluso nell'evidence
  - Host con scan_start/scan_end dalla sezione `<host>`
- **OpenVAS CSV**: 25 colonne standard, risultati identici all'XML per gli stessi file
- **Nessus CSV**: variante con header che inizia da `CVE` (non da `Plugin ID`)
  - Risk Factor e Risk come fonte severity, fallback su CVSS v2
  - source_tool = "nessus" per distinguere da OpenVAS nella deduplication
- **34/34 test passati**

---

## 10. CAMPO DB: FIELD MAPPING CROSS-TOOL

Il file `FIELD_MAPPING.md` documenta la tabella completa di mapping
per ogni campo DB canonico verso tutti i tool supportati.

Sezioni:
- Sezione 1: Host / Asset (ip, mac, hostname, state, scan times)
- Sezione 2: Porta / Servizio (port, protocol, state, service, product, version, CPE)
- Sezione 3: Vulnerabilità (title, description, severity, CVSS, CVE, CWE, evidence, remediation, references)
- Sezione 4: OS Detection (solo Nmap)
- Sezione 5: Scan Metadata (scanner name/version, args, date, type, hosts stats)

---

## 11. NVD ENRICHER — CAMPI MAPPATI

### Tutti i campi NVD API v2 → DB
```
cve.id                                  → cve_id
descriptions[lang=en].value             → description_nvd
metrics.cvssMetricV31[0].cvssData.*     → cvss_score, cvss_vector, cvss_version,
                                           cvss_av, cvss_ac, cvss_pr, cvss_ui,
                                           cvss_scope, cvss_c, cvss_i, cvss_a,
                                           cvss_exploitability_score, cvss_impact_score
weaknesses[].description[lang=en].value → cwe_id, cwe_ids
references[].url / .source / .tags      → references_nvd
configurations[].nodes[].cpeMatch[].criteria → cpe_affected
published / lastModified / vulnStatus   → cve_published, cve_last_modified, cve_status
cisaExploitAdd / cisaActionDue / cisaRequiredAction → is_kev, kev_*
references con tag "Exploit"            → is_exploit_available_nvd
```

### Priorità CVSS
```
v3.1 > v3.0 > v2.0 (fallback per CVE storici pre-2016)
```

### CISA KEV
Campo presente solo se il CVE è nel catalogo Known Exploited Vulnerabilities.
Indica che la vulnerabilità è attivamente sfruttata in-the-wild.

---

## 12. DECISIONI SOSPESE / DA COMPLETARE

- [ ] **Nikto parser**: da implementare completamente (struttura analizzata, decisioni prese)
- [ ] **Nuclei parser**: JSON format, pianificato
- [ ] **Metasploit parser**: XML db_export, pianificato
- [ ] **CSV generico**: con fingerprinting template e mapping utente-definito
- [ ] **Excel asset list**: fingerprint SHA256 dei nomi colonna, mapping salvato per Organization
- [ ] **Template Jinja2 report**: da costruire per tipo (pentest_full, pentest_executive, retest)
- [ ] **Sistema di scoring composito**: risk_score = f(cvss, epss, exposure_factor)
- [ ] **Timeline grafica**: Plotly/D3 per trend vulnerabilità tra subprogetti
- [ ] **Executive Report trasversale**: aggregato su tutti i subprogetti di un progetto

---

## 13. FILE PRODOTTI IN QUESTA SESSIONE

| File | Descrizione | Test |
|---|---|---|
| `CLAUDE.md` | Spec completa per Claude Code (stack, architettura, ordine sviluppo) | — |
| `canonical_schema.py` | Schema canonico condiviso: NormalizedVulnerability, NvdEnrichmentData, BaseParser | ✅ |
| `nvd_enricher.py` | NVD API v2 mapper + enricher con rate limiting e Celery support | ✅ |
| `FIELD_MAPPING.md` | Tabella cross-tool: ogni campo DB → XPath/JSON key per tutti i tool | — |
| `nmap_parser.py` | Parser Nmap XML con 8 NSE handler dedicati | 71/71 ✅ |
| `test_nmap_parser.py` | Test suite Nmap (basati su 20 file reali) | — |
| `burp_parser.py` | Parser Burp Suite XML (v1.0/v1.1, base64, dynamic/static/collaborator) | 48/48 ✅ |
| `test_burp_parser.py` | Test suite Burp (6 file reali, 1203 SSRF issues) | — |
| `openvas_parser.py` | Parser OpenVAS XML + CSV + Nessus CSV con auto-detect | 34/34 ✅ |
| `test_openvas_parser.py` | Test suite OpenVAS/Nessus | — |

**Totale test passati: 153/153**

