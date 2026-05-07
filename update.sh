#!/usr/bin/env bash
# update.sh — ReportShelter host-side update script
#
# Usage:
#   ./update.sh           # pull latest stable release and rebuild
#   ./update.sh --check   # only check what version is available, no changes
#
# Prerequisites: git, docker, docker compose
# Run this from the directory where you cloned the repository.

set -euo pipefail

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BRANCH="${UPDATE_BRANCH:-main}"
COMPOSE="docker compose"

# ── colours ──────────────────────────────────────────────────────────────────
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
ok()   { echo -e "${GREEN}[OK]${NC}  $*"; }
warn() { echo -e "${YELLOW}[!!]${NC}  $*"; }
fail() { echo -e "${RED}[KO]${NC}  $*"; exit 1; }
step() { echo -e "\n${YELLOW}──────────────────────────────────────${NC}"; echo -e "  $*"; echo -e "${YELLOW}──────────────────────────────────────${NC}"; }

# ── check mode ───────────────────────────────────────────────────────────────
if [[ "${1:-}" == "--check" ]]; then
    step "Checking for updates..."
    CURRENT=$(grep -E '^APP_VERSION=' "$REPO_DIR/.env" 2>/dev/null | cut -d= -f2 | tr -d '"' || echo "unknown")
    REMOTE=$(git -C "$REPO_DIR" ls-remote --tags origin | grep -oP 'v[\d.]+$' | sort -V | tail -1 || echo "unknown")
    echo "  Installed : ${CURRENT:-unknown}"
    echo "  Available : ${REMOTE:-unknown}"
    [[ "$CURRENT" == "$REMOTE" ]] && ok "Already up to date." || warn "Update available: $REMOTE"
    exit 0
fi

step "ReportShelter Update"
cd "$REPO_DIR"

# ── pre-flight checks ─────────────────────────────────────────────────────────
command -v git   >/dev/null 2>&1 || fail "git not found"
command -v docker >/dev/null 2>&1 || fail "docker not found"
$COMPOSE version >/dev/null 2>&1  || fail "docker compose not found"

# ── step 1: backup via API (if containers are running) ───────────────────────
step "Step 1/4 — Pre-update database backup"
if $COMPOSE ps backend 2>/dev/null | grep -q "Up"; then
    warn "Triggering backup via management command..."
    $COMPOSE exec -T backend python manage.py backup_database --label pre-update \
        && ok "Backup created in /app/backups/" \
        || warn "Backup failed — proceeding anyway (check backup volume manually)"
else
    warn "Containers not running — skipping backup step"
fi

# ── step 2: git pull ──────────────────────────────────────────────────────────
step "Step 2/4 — Pulling latest code (branch: $BRANCH)"
git pull origin "$BRANCH" && ok "Code updated" || fail "git pull failed"

# ── step 2b: sync APP_VERSION, GIT_COMMIT, GIT_DATE from repo → .env ──────────
# Only these three keys are touched — all other user-edited entries are preserved.
_upsert_env() {
    local key="$1" value="$2" file="$3"
    if grep -qE "^${key}=" "$file"; then
        sed -i "s|^${key}=.*|${key}=${value}|" "$file"
    else
        echo "${key}=${value}" >> "$file"
    fi
}

if [[ -f "$REPO_DIR/.env" ]]; then
    NEW_VERSION=$(grep -E '^APP_VERSION=' "$REPO_DIR/.env.example" 2>/dev/null | cut -d= -f2 | tr -d '"' | tr -d "'" | xargs)
    NEW_COMMIT=$(git -C "$REPO_DIR" rev-parse --short HEAD 2>/dev/null || echo "unknown")
    NEW_DATE=$(git -C "$REPO_DIR" log -1 --format=%ci 2>/dev/null || echo "unknown")

    [[ -n "$NEW_VERSION" ]] && { _upsert_env "APP_VERSION" "$NEW_VERSION" "$REPO_DIR/.env"; ok "APP_VERSION=${NEW_VERSION}"; }
    _upsert_env "GIT_COMMIT" "$NEW_COMMIT" "$REPO_DIR/.env"; ok "GIT_COMMIT=${NEW_COMMIT}"
    _upsert_env "GIT_DATE"   "$NEW_DATE"   "$REPO_DIR/.env"; ok "GIT_DATE=${NEW_DATE}"
else
    warn ".env not found — skipping version sync"
fi

# ── step 3: rebuild and restart containers ────────────────────────────────────
step "Step 3/4 — Rebuilding and restarting containers"
$COMPOSE up -d --build && ok "Containers restarted" || fail "docker compose up failed"
# nginx keeps the old upstream IPs in memory when other containers are recreated;
# a targeted restart forces it to re-resolve via Docker's DNS.
$COMPOSE restart nginx && ok "nginx reloaded" || warn "nginx restart failed — you may see 502 until the next nginx restart"

# ── step 4: wait for backend health, then migrate ─────────────────────────────
step "Step 4/4 — Waiting for backend to become healthy..."
RETRIES=30
until $COMPOSE exec -T backend python -c "import socket; s=socket.socket(); s.settimeout(2); s.connect(('localhost', 8000))" 2>/dev/null; do
    RETRIES=$((RETRIES - 1))
    [[ $RETRIES -le 0 ]] && fail "Backend did not become healthy in time"
    echo -n "."
    sleep 3
done
echo ""
ok "Backend is healthy"

# Migrations run automatically at container startup via manage.py migrate,
# but we run an explicit check to surface any failures immediately.
$COMPOSE exec -T backend python manage.py migrate --noinput \
    && ok "Migrations applied" \
    || fail "Migrations failed — restore from the pre-update backup if needed"

# ── done ─────────────────────────────────────────────────────────────────────
NEW_VERSION=$(grep -E '^APP_VERSION=' "$REPO_DIR/.env" 2>/dev/null | cut -d= -f2 | tr -d '"' || echo "unknown")
echo ""
ok "Update complete — version: ${NEW_VERSION}"
echo ""
echo "  If something looks wrong, restore with:"
echo "  docker compose exec backend python manage.py restore_database --yes <backup-file>"
echo ""
