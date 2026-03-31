# Shelter — Decision History

Questo file registra le scelte architetturali e implementative significative,
con la motivazione e le alternative scartate.

---

## 2026-04-01 — Bulk status, scan import filtering, paginazione

### Contesto
Richiesta di tre funzionalità integrate:
1. Selezione multipla + cambio status in bulk dalla tabella vulnerabilità
2. Deselezionare uno Scan Import deve escludere le sue vulnerabilità dalla tabella
   e dal conteggio/generazione del report
3. Paginazione della tabella vulnerabilità

---

### 1. Endpoint bulk status (`PATCH /api/v1/vulnerabilities/bulk-status/`)

**Scelta:** endpoint dedicato `BulkStatusUpdateView` con `PATCH` semantics.

**Motivazione:**
- Un singolo `PATCH` con lista di ID è O(1) query sul DB grazie a `QuerySet.update()`
  invece di N chiamate `PATCH /vulnerabilities/<pk>/` in sequenza.
- IDOR protection: il queryset filtra `subproject__project__organization=request.user.organization`
  prima dell'update — l'utente non può modificare vuln di altre org passando ID arbitrari.
- Limite di 500 ID per request (`max_length=500` nel serializer) per evitare query unbounded.

**Scartato:**
- Riusare `VulnerabilityDetailView` in loop dal frontend: N round-trip HTTP, race condition,
  e ogni chiamata recalcola i permessi individualmente.
- Action custom su `ViewSet`: il progetto non usa ViewSet, sarebbe stato refactoring non richiesto.

---

### 2. Scan import filtering — propagazione dello stato

**Scelta:** `selectedScanIds: Set<number>` in `SubProjectPage`, propagato come:
- `disabledIds` → `VulnerabilityTable` (solo UI, nessun re-fetch)
- `scan_import_ids` → `navigate state` → `ReportBuilderPage` → payload del report

**Motivazione:**
- Nessun re-fetch: disabilitare uno scan import non deve ricaricare le vulnerabilità dal server.
  Il filtraggio è puramente client-side sulla lista già caricata.
- Le vuln create manualmente (`scan_import === null`) sono sempre abilitate: ha senso semantico
  (non appartengono a nessun import, non devono mai sparire).
- Il filtro viene passato alla generazione del report come `scan_import_ids` nel payload JSON,
  e il generatore backend applica: `Q(scan_import__isnull=True) | Q(scan_import_id__in=ids)`.
  Questo garantisce che anche le vuln manuali vengano incluse nel report generato.

**Bug fix incluso (loose null check):**
- `v.scan_import != null` invece di `!== null`: il check loose cattura anche `undefined`,
  che si presentava quando il backend non era stato riavviato e il vecchio serializer non
  restituiva il campo `scan_import`. Senza questo, tutte le vuln venivano disabilitate.

**Scartato:**
- Filtrare le vuln con un query param aggiuntivo al server (es. `?scan_import=1,2,3`):
  richiederebbe un re-fetch ogni volta che l'utente seleziona/deseleziona un import,
  con latenza visibile e perdita della selezione precedente.
- `deselectedScanIds` (logica invertita): meno intuitivo e richiede gestione speciale
  dello stato iniziale "nessuno deselezionato = tutto visibile".

---

### 3. Context menu con React Portal

**Scelta:** context menu renderizzato via `createPortal(…, document.body)` con `position: fixed`.

**Motivazione:**
- La tabella è dentro `overflow-x-auto`. Un elemento `position: absolute` figlio di un
  ancestor con `overflow` sarebbe stato clippato. Il portal monta il menu direttamente su
  `<body>`, fuori dal contesto di overflow/stacking della tabella.
- `position: fixed` con le coordinate `clientX/clientY` dell'evento posiziona il menu
  esattamente dove ha cliccato l'utente, indipendentemente dallo scroll della pagina.

**Comportamento right-click:**
- Se la riga è già selezionata: l'azione si applica a tutti i selezionati.
- Se la riga non è selezionata: si seleziona quella singola riga e l'azione si applica ad essa.
- Le righe disabilitate (scan import deselezionato): nessuna azione (guard `if (disabledIds?.has(vuln.id)) return`).

**Scartato:**
- Menu dropdown inline nella riga: clippato da `overflow-x-auto`.
- Toolbar fissa in cima alla tabella: nasconde il contesto (non sai su cosa stai agendo).

---

### 4. Paginazione client-side

**Scelta:** paginazione client-side nella `VulnerabilityTable` con selector 10 / 25 / 50 / All.
Default 25 righe. Navigazione con numeri di pagina + ellissi per set grandi (finestra di ±2
pagine attorno alla corrente).

**Motivazione:**
- Le vulnerabilità sono già tutte in memoria (l'API le restituisce tutte filtrate per subproject).
  La paginazione server-side aggiungerebbe complessità (cursori, stati di loading intermedi)
  senza beneficio reale per dataset tipici di un subproject (decine/centinaia di vuln).
- `useMemo` per lo slice evita ricalcoli inutili.
- Reset automatico a pagina 1 su cambio sort o cambio dati (via `useEffect` su `sorted.length`
  e `sortKey/sortDir`).

**Scartato:**
- Paginazione server-side: overkill per il volume atteso, e romperebbe la selezione bulk
  (non puoi selezionare "tutti" se le vuln arrivano in pagine separate).
- Infinite scroll / virtual list: complessità elevata, incompatibile con select-all e con
  l'ordinamento client-side già presente.

---

## Sessioni precedenti

| Data | Argomento | File chiave |
|---|---|---|
| 2026-03-02 | Setup iniziale: Docker, accounts, licensing, projects, parsers, vulnerabilities, reports, frontend base | vedi MEMORY.md |
| 2026-03-31 | Section editor, NVD enrichment fix (`cve_id` type), CI/CD, Dependabot, fix licenza `_configured` | `.github/workflows/`, `wp_license_client.py`, `management/commands/license_status.py` |
