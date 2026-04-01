# ReportShelter PRO

Strumento web per la creazione di report di cybersecurity professionali destinati a pentesters e consulenti di sicurezza. Permette di importare output da scanner (Nmap, Burp, ZAP, Nikto, Metasploit, OpenVAS, Nessus), elaborare vulnerabilità e generare report in PDF, HTML o XML.

---

## Requisiti

- [Docker](https://docs.docker.com/get-docker/) ≥ 24.x
- [Docker Compose](https://docs.docker.com/compose/install/) ≥ 2.x

Non sono richiesti Python, Node.js o altri tool installati localmente.

---

## Installazione e avvio (sviluppo)

### 1. Clona il repository

```bash
git clone https://github.com/Dognet-Technologies/reportshelter.git
cd reportshelter
```

### 2. Configura le variabili d'ambiente

```bash
cp .env.example .env
```

Apri `.env` e modifica almeno questi valori:

```env
SECRET_KEY=cambia-questa-chiave-segreta-con-una-random
DB_PASSWORD=una-password-sicura

# Email (opzionale in sviluppo, usa console backend)
EMAIL_HOST=smtp.example.com
EMAIL_HOST_USER=noreply@example.com
EMAIL_HOST_PASSWORD=password
```

Per generare una `SECRET_KEY` sicura:

```bash
python3 -c "import secrets; print(secrets.token_hex(50))"
# oppure
openssl rand -hex 50
```

> **Nota:** Il file `.env` non viene mai committato. Non condividerlo.

### 3. Avvia i container

```bash
docker compose up --build
```

Al primo avvio Docker:
- costruisce le immagini backend (Django) e frontend (React + Vite)
- avvia PostgreSQL, Redis, Celery worker, Celery beat, Nginx
- esegue automaticamente le migrazioni del database

L'operazione richiede qualche minuto la prima volta.

### 4. Crea il primo utente amministratore

In un secondo terminale, mentre i container sono attivi:

```bash
docker compose exec backend python manage.py createsuperuser
```

Inserisci email e password quando richiesto.

### 5. Accedi all'applicazione

| Servizio | URL |
|---|---|
| Applicazione web | http://localhost:8088 |
| API backend (Django) | http://localhost:8000/api/v1/ |
| Admin Django | http://localhost:8000/admin/ |
| Frontend dev server (HMR) | http://localhost:5173 |

---

## Comandi utili

```bash
# Avviare in background
docker compose up -d

# Fermare tutti i container
docker compose down

# Vedere i log in tempo reale
docker compose logs -f

# Log di un servizio specifico
docker compose logs -f backend
docker compose logs -f celery_worker

# Eseguire le migrazioni manualmente
docker compose exec backend python manage.py migrate

# Aprire una shell Django
docker compose exec backend python manage.py shell

# Accedere al database PostgreSQL
docker compose exec db psql -U cyberreport -d cyberreport

# Ricostruire solo il backend dopo modifiche al Dockerfile
docker compose build backend
docker compose up -d backend
```

---

## Struttura dei servizi Docker

| Servizio | Immagine / Build | Porta interna | Porta host |
|---|---|---|---|
| `db` | postgres:15-alpine | 5432 | — |
| `redis` | redis:7-alpine | 6379 | — |
| `backend` | build `./backend` | 8000 | 8000 |
| `celery_worker` | build `./backend` | — | — |
| `celery_beat` | build `./backend` | — | — |
| `frontend` | build `./frontend` | 5173 | 5173 |
| `nginx` | nginx:1.25-alpine | 80 | 8088 |

Il traffico entra tramite **Nginx** sulla porta `8088`, che fa da reverse proxy verso backend e frontend.

---

## Aggiornamento

```bash
git pull
docker compose build
docker compose up -d
docker compose exec backend python manage.py migrate
```

---

## Variabili d'ambiente principali

Vedi `.env.example` per l'elenco completo. Le principali:

| Variabile | Descrizione | Default esempio |
|---|---|---|
| `SECRET_KEY` | Chiave segreta Django (cambiare!) | `changeme` |
| `DEBUG` | Modalità debug (`True`/`False`) | `False` |
| `DB_NAME` | Nome database PostgreSQL | `cyberreport` |
| `DB_USER` | Utente database | `cyberreport` |
| `DB_PASSWORD` | Password database | `changeme` |
| `REDIS_URL` | URL Redis per Celery | `redis://redis:6379/0` |
| `EMAIL_HOST` | SMTP server per email | `smtp.example.com` |
| `VITE_API_BASE_URL` | URL base API per il frontend | `http://localhost:8000/api/v1` |
| `WP_LICENSE_API_URL` | URL WordPress License Manager | placeholder |

---

## Troubleshooting

**`No matching distribution found for Django==6.0.3`**
Django 6 richiede Python ≥ 3.12. Il Dockerfile usa già `python:3.12-slim` — se hai un'immagine cached precedente, forza il rebuild:
```bash
docker compose build --no-cache
```

**`celery_beat` si avvia e crasha in loop**
Celery Beat usa `DatabaseScheduler`, che richiede le tabelle create dalle migrazioni Django. Assicurati di usare la versione aggiornata del `docker-compose.yml` (celery_beat dipende da `backend: service_healthy`).

**`Cannot apply unknown utility class` / errori Tailwind CSS**
In Tailwind v4 la sintassi `@tailwind base/components/utilities` non esiste più — è già corretta in `src/index.css` con `@import "tailwindcss"`. Se hai una copia locale modificata, aggiornala.

**Errore PostCSS / `@tailwindcss/postcss`**
Se vedi errori su `@tailwindcss/postcss`, il `package-lock.json` potrebbe essere obsoleto. Rigeneralo con:
```bash
docker run --rm -v $(pwd)/frontend:/app -w /app node:20-alpine npm install
```
Poi rebuilda: `docker compose build frontend`

**`npm ci` fallisce con errore di lock file**
Stesso problema del punto sopra: `package.json` e `package-lock.json` non sono in sync. Rigenera il lock file come indicato sopra.

**Il DB non si avvia / password errata**
Se hai già avviato i container in precedenza con una password diversa, il volume Postgres conserva quella vecchia. Per ripartire da zero:
```bash
docker compose down -v
docker compose up --build
```
> Attenzione: `-v` cancella tutti i dati del database.

---

## Note di sicurezza

- Non usare `DEBUG=True` in produzione
- Cambiare sempre `SECRET_KEY` e le password di default
- Il file `.env` è in `.gitignore` — non committarlo mai
- Per produzione, usare `docker-compose.prod.yml` (TLS via Nginx, variabili separate)
