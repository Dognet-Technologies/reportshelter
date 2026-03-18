# CyberReport Pro — Istruzioni per Claude Code

## Ruolo
Sei un senior full-stack developer con specializzazione in cybersecurity tooling e data pipelines.
Sviluppa l'applicazione seguendo rigorosamente le specifiche qui sotto.
Prima di scrivere codice, leggi l'intero documento. Mantieni coerenza architetturale in ogni fase.

---

## Obiettivo
Applicazione web per la **creazione di report di cybersecurity** destinati a professionisti (pentesters, consulenti).
Permette di importare output da scanner, elaborare vulnerabilità, generare report professionali in PDF/HTML.

---

## Stack Tecnologico

| Layer | Tecnologia |
|---|---|
| Backend | Python 3.11+ / Django 5.x |
| Frontend | React 18 + TypeScript + Vite |
| Database | PostgreSQL 15+ |
| Web server | Nginx (reverse proxy) |
| Task queue | Celery + Redis (per elaborazioni asincrone: parsing, report generation) |
| PDF generation | WeasyPrint + Jinja2 (HTML→PDF) + ReportLab (grafici complessi) |
| Grafici | Matplotlib / Plotly (export immagini per embedding in report) |
| Data processing | Pandas |
| Containerization | Docker + Docker Compose |

---

## Sicurezza (OWASP / NIST)

Applica obbligatoriamente:
- **Autenticazione**: email + password con hashing Argon2, rate limiting su login (max 5 tentativi → lockout 15min)
- **Session management**: JWT con refresh token rotation, blacklist token su logout
- **Input validation**: validazione e sanitizzazione di tutti gli input (form + file upload)
- **File upload**: whitelist estensioni, scan MIME type, quarantena file prima del processing, max size configurabile
- **CSRF protection**: Django CSRF middleware attivo
- **SQL Injection**: uso esclusivo dell'ORM Django, nessuna query raw non parametrizzata
- **XSS**: escape output React (default), Content Security Policy header via Nginx
- **IDOR**: tutti gli oggetti verificati per ownership prima di ogni accesso
- **Secrets**: nessuna credenziale hardcoded, uso di variabili d'ambiente via `.env` (mai committate)
- **HTTPS**: configurazione Nginx con TLS, HSTS header
- **Audit log**: registra ogni azione sensibile (login, creazione progetto, export, invito utente)

---

## Modello di Licenza

### Modalità
- **Solo modalità PRO** (non esiste piano free permanente)
- **Trial gratuito**: 30 giorni dall'attivazione

### Integrazione License Manager
Usa un **placeholder** per l'integrazione con il plugin WordPress License Manager.
Crea un modulo `licensing/wp_license_client.py` con questa interfaccia:

```python
class WPLicenseClient:
    """
    Placeholder per integrazione con WordPress License Manager Plugin.

    Configurazione richiesta (variabili d'ambiente):
        WP_LICENSE_API_URL=https://your-wordpress-site.com/wp-json/lmfwc/v2
        WP_LICENSE_API_KEY=<consumer_key>
        WP_LICENSE_API_SECRET=<consumer_secret>

    Metodi da implementare con le API reali del plugin:
        - activate_license(license_key, instance_id) -> LicenseStatus
        - validate_license(license_key) -> LicenseStatus
        - deactivate_license(license_key, instance_id) -> bool
    """

    def activate_license(self, license_key: str, instance_id: str) -> dict:
        # TODO: chiamata a WP License Manager API /licenses/activate
        raise NotImplementedError("Configurare WP_LICENSE_API_URL e credenziali")

    def validate_license(self, license_key: str) -> dict:
        # TODO: chiamata a WP License Manager API /licenses/{key}
        raise NotImplementedError("Configurare WP_LICENSE_API_URL e credenziali")

    def deactivate_license(self, license_key: str, instance_id: str) -> bool:
        # TODO: chiamata a WP License Manager API /licenses/deactivate
        raise NotImplementedError("Configurare WP_LICENSE_API_URL e credenziali")
```

### Stato Licenza (gestito internamente nel DB)
```
LicenseStatus:
  - TRIAL_ACTIVE       → accesso completo per 30gg dalla registrazione
  - TRIAL_EXPIRED      → limitazioni attive (vedi sotto)
  - PRO_ACTIVE         → accesso completo
  - PRO_EXPIRED        → limitazioni attive
  - INVALID            → accesso negato
```

### Limitazioni post-trial/scadenza
- Impossibile creare nuovi progetti
- Impossibile esportare report
- Impossibile importare file da scanner
- Accesso in sola lettura ai progetti esistenti
- Banner persistente con invito all'acquisto

---

## Autenticazione

- Email + password (Argon2 hashing)
- Nessun OAuth in questa fase
- Email di conferma alla registrazione
- Reset password via email con token temporaneo (scadenza 1h)
- Al login, controllo immediato stato licenza

---

## Modello Dati (schema concettuale)

```
Organization                    # l'azienda che usa il software
  ├── Company profile           # dati aziendali, logo, info per header/footer report
  ├── License                   # stato licenza, date, license_key
  └── Users (1..N)              # utenti dell'organizzazione

User
  ├── role: "admin" | "member"  # admin = chi crea, invita; member = collaboratore
  └── (tutti appartengono a una Organization)

Project                         # progetto per un cliente
  ├── Client info               # dati del cliente (nome, logo, contatti)
  ├── Graphic options           # template, tema, watermark, colori, font
  ├── Header / Footer config    # testo, logo, numerazione pagine
  ├── Timeline                  # storico scansioni con trend vulnerabilità
  ├── ProjectLock               # lock concorrenza (vedi sezione dedicata)
  └── SubProjects (1..N)

SubProject                      # singola scansione / engagement
  ├── ScanImports (1..N)        # file importati da scanner
  ├── Vulnerabilities (1..N)    # vulnerabilità catalogate e deduplicate
  ├── Screenshots (1..N)        # evidenze visive
  └── ReportExports (1..N)      # export generati

Vulnerability
  ├── title, description, remediation
  ├── affected_host (IP / hostname)
  ├── affected_port, affected_service
  ├── cve_id, cvss_score, cvss_vector
  ├── epss_score                # Exploit Prediction Scoring System
  ├── risk_level (Critical/High/Medium/Low/Info)
  ├── status (Open/Fixed/Accepted/Retest)
  ├── sources: [tool1, tool2]   # provenienza multipla dopo deduplicazione
  ├── is_recurring: bool        # non fixata rispetto a subproject precedente
  └── evidence_code: text       # snippet di codice/output come evidenza
```

---

## Flusso Operativo Dettagliato

### Step 0 — Configurazione Iniziale (una tantum per Organization)
- `0a` Inserimento dati aziendali: nome, indirizzo, logo (PNG/SVG), contatti, P.IVA, disclaimer legale
- `0b` Configurazione prima pagina e ultima pagina del report (template WYSIWYG o upload HTML)

### Step 1 — Creazione Progetto
- `1a` Titolo progetto, descrizione, data inizio
- `1b` Dati cliente: ragione sociale, logo, referente, contatti
- `1c` Opzioni grafiche:
  - Selezione template (predefiniti + custom upload)
  - Tema colori (palette primaria/secondaria)
  - Filigrana (testo o immagine, opacità configurabile)
  - Header: logo sx, testo centro, data dx (configurabile)
  - Footer: testo libero + numerazione pagine (formato `N / TOT` o `N`)
  - Font family (da lista predefinita: Inter, Roboto, Source Sans, etc.)

### Step 2 — Lavoro sul Progetto
- `2a` **Invito utenti**: admin può invitare membri via email. I membri vedono il progetto.
- `2b` **SubProgetti**: ogni progetto ha N subprogetti (es. "Scansione Q1 2025", "Retest Marzo 2025")
- `2c` **Import scanner**: upload file, parsing asincrono (Celery), normalizzazione in `Vulnerability`
- `2d` **Upload screenshot**: drag&drop, associazione a specifica vulnerabilità, caption

### Step 3 — Export
- `3a` Generazione report in PDF e/o HTML
  - Selezione vulnerabilità da includere (checklist, filtri per severity/status)
  - Anteprima HTML live
  - Export PDF via WeasyPrint
  - Export HTML standalone (con assets embedded base64)
  - Export XML (formato strutturato per interoperabilità)

---

## Pipeline di Elaborazione Dati (Process1 + Process2)

### Process 1 — Normalizzazione & Deduplicazione
```
Input: file grezzi da scanner
  ↓
Parser specifico per formato (XML Nmap, XML Nikto, XML/JSON Burp, XML ZAP, XML Metasploit, CSV generico)
  ↓
Normalizzazione → oggetto Vulnerability standard
  ↓
Deduplicazione: stessa (vuln_title + affected_host + affected_port) → 1 record
  → campo `sources` = lista dei tool che l'hanno trovata
  → campo `raw_outputs` = lista degli output originali
  ↓
Riprioritizzazione rischio:
  - CVSS base score
  - EPSS score (probabilità exploit reale)
  - Contesto: esposizione internet? presenza di exploit pubblico?
  → risk_score composito = f(cvss, epss, exposure_factor)
```

### Process 2 — Costruzione Report
```
Selezione vulnerabilità da includere (con filtri)
  ↓
Costruzione grafici:
  - Pie chart distribuzione severity
  - Bar chart vulnerabilità per host
  - Timeline trend (se progetto con più subprogetti)
  - Risk matrix (probabilità × impatto)
  ↓
Assemblaggio template Jinja2:
  - Cover page (dati cliente + dati aziendali)
  - Executive summary (KPI, grafici principali)
  - Vulnerability details (per ogni vuln: title, desc, cvss, epss, evidence, remediation)
  - Appendici
  - Last page
  ↓
Rendering: HTML → WeasyPrint → PDF
```

---

## Parser per Scanner Supportati

Implementa un parser dedicato per ciascuno:

| Scanner | Formato input | Note |
|---|---|---|
| Nmap | XML (`-oX`) | Estrai host, porte, servizi, script output |
| Nikto | XML (`-Format xml`) | Estrai finding con OSVDB/CVE ref |
| Burp Suite | XML export | Finding con request/response |
| OWASP ZAP | XML / JSON | Alert con evidence |
| Metasploit | XML (`db_export`) | Vuln e note |
| Generico | CSV | Colonne configurabili con mapping UI |

Ogni parser deve restituire `List[NormalizedVulnerability]`.
Gestisci parsing errors per file malformati con log dettagliato e notifica utente.

---

## Sistema di Lock Concorrenza (Project Lock)

### Comportamento
- Quando un utente **apre un progetto in modifica**, viene acquisito un lock
- Gli altri utenti vedono il progetto in **sola lettura** con banner: `"Progetto in uso da [Nome Utente] dalle [HH:MM]"`
- **Timeout automatico inattività**: se nessuna azione per 30 minuti, il lock viene rilasciato automaticamente
- **Heartbeat**: il frontend invia un heartbeat ogni 60 secondi per mantenere il lock attivo
- Al rilascio del lock (logout, chiusura tab, timeout), gli altri utenti ricevono notifica via WebSocket: `"Progetto ora disponibile"`

### Implementazione
```python
# Model
class ProjectLock(models.Model):
    project = models.OneToOneField(Project, on_delete=models.CASCADE)
    locked_by = models.ForeignKey(User, on_delete=models.SET_NULL, null=True)
    locked_at = models.DateTimeField(auto_now_add=True)
    last_heartbeat = models.DateTimeField(auto_now=True)
    TIMEOUT_MINUTES = 30

    def is_expired(self) -> bool:
        return (now() - self.last_heartbeat).total_seconds() > self.TIMEOUT_MINUTES * 60
```

Usa **Django Channels** (WebSocket) per notifiche real-time del lock.

---

## Feature Timeline & Diff Vulnerabilità

### Timeline Progetto
- Visualizzazione cronologica di tutti i subprogetti
- Per ogni punto nella timeline:
  - Totale vulnerabilità per severity
  - Risk score complessivo
  - Vulnerabilità nuove / fixate / persistenti
- Grafico lineare con trend nel tempo
- Possibilità di generare **Executive Report** trasversale su tutti i subprogetti

### Diff Vulnerabilità tra SubProgetti
- Confronto automatico tra subprogetto corrente e precedente (stesso progetto, ordinati per data)
- Classificazione:
  - NEW: nuova vulnerabilità non presente prima
  - FIXED: presente prima, non più presente ora
  - PERSISTENT: presente in entrambi, non fixata → flag `is_recurring=True`
  - CHANGED: stessa vuln, severity cambiata
- Le vulnerabilità PERSISTENT vengono **evidenziate** nel report con badge visivo

---

## Struttura Progetto (directory layout)

```
cyberreport-pro/
├── backend/
│   ├── config/                  # Django settings (base, dev, prod)
│   ├── apps/
│   │   ├── accounts/            # User, Organization, autenticazione
│   │   ├── licensing/           # License model + WPLicenseClient placeholder
│   │   ├── projects/            # Project, SubProject, ProjectLock
│   │   ├── vulnerabilities/     # Vulnerability model + deduplicazione
│   │   ├── parsers/             # Parser per ogni scanner
│   │   ├── reports/             # Generazione report (Jinja2 + WeasyPrint)
│   │   └── notifications/       # WebSocket (Django Channels)
│   ├── templates/
│   │   └── reports/             # Template Jinja2 per report HTML/PDF
│   └── requirements.txt
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   ├── pages/
│   │   ├── hooks/
│   │   ├── store/               # Zustand o Redux Toolkit
│   │   └── api/                 # API client (Axios + React Query)
│   └── package.json
├── nginx/
│   └── nginx.conf
├── docker-compose.yml
├── docker-compose.prod.yml
└── .env.example
```

---

## Ordine di Sviluppo Suggerito

1. **Setup infrastruttura**: Docker Compose (PostgreSQL, Redis, Django, React, Nginx, Celery)
2. **App `accounts`**: modelli User/Organization, autenticazione JWT, email confirm, reset password
3. **App `licensing`**: modello License, middleware di controllo, placeholder WPLicenseClient, logica trial
4. **App `projects`**: modelli Project/SubProject, CRUD, sistema lock + WebSocket
5. **App `parsers`**: parser Nmap → pipeline completa. Poi gli altri in sequenza.
6. **App `vulnerabilities`**: normalizzazione, deduplicazione, diff/timeline logic
7. **App `reports`**: template Jinja2 base, generazione PDF, grafici Matplotlib/Plotly
8. **Frontend**: routing, autenticazione, dashboard, project management, import wizard, report builder
9. **Feature avanzate**: timeline grafica, executive report, diff visivo, template WYSIWYG
10. **Hardening**: audit log completo, rate limiting, test di sicurezza, performance

---

## Variabili d'Ambiente Richieste (.env.example)

```env
# Django
SECRET_KEY=changeme
DEBUG=False
ALLOWED_HOSTS=localhost,127.0.0.1

# Database
DB_NAME=cyberreport
DB_USER=cyberreport
DB_PASSWORD=changeme
DB_HOST=db
DB_PORT=5432

# Redis / Celery
REDIS_URL=redis://redis:6379/0

# Email
EMAIL_HOST=smtp.example.com
EMAIL_PORT=587
EMAIL_HOST_USER=noreply@example.com
EMAIL_HOST_PASSWORD=changeme
EMAIL_USE_TLS=True

# Frontend
VITE_API_BASE_URL=http://localhost:8000/api

# WordPress License Manager (placeholder)
WP_LICENSE_API_URL=https://your-wordpress-site.com/wp-json/lmfwc/v2
WP_LICENSE_API_KEY=ck_placeholder
WP_LICENSE_API_SECRET=cs_placeholder

# Lock timeout (minuti)
PROJECT_LOCK_TIMEOUT_MINUTES=30
```

---

## Note Finali per Claude Code

- Usa **type hints** Python ovunque
- Scrivi **docstring** per ogni classe e metodo pubblico
- Ogni app Django deve avere **test unitari** (pytest-django) per la logica critica
- Il frontend deve avere gestione centralizzata degli errori API
- Usa **React Query** per caching e stato server
- I report generati devono essere **pixel-perfect**: testa con WeasyPrint prima di finalizzare i template
- Non hardcodare mai colori o loghi: tutto deve venire dalla configurazione Organization/Project
- Per i grafici nel PDF, genera immagini PNG in memoria con Matplotlib e incorporale nel template HTML prima del rendering WeasyPrint
- Mantieni coerenza architetturale: non introdurre pattern o librerie non elencate senza motivazione esplicita
