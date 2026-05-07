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

# ── step 2b: sync APP_VERSION from .env.example → .env ───────────────────────
# Only APP_VERSION is touched — every other user-edited entry is preserved.
NEW_VERSION=$(grep -E '^APP_VERSION=' "$REPO_DIR/.env.example" 2>/dev/null | cut -d= -f2 | tr -d '"' | tr -d "'" | xargs)
if [[ -n "$NEW_VERSION" && -f "$REPO_DIR/.env" ]]; then
    if grep -qE '^APP_VERSION=' "$REPO_DIR/.env"; then
        # Line exists — replace it in-place
        sed -i "s|^APP_VERSION=.*|APP_VERSION=${NEW_VERSION}|" "$REPO_DIR/.env"
    else
        # Line missing — append it
        echo "APP_VERSION=${NEW_VERSION}" >> "$REPO_DIR/.env"
    fi
    ok "APP_VERSION set to ${NEW_VERSION} in .env"
else
    warn "Could not read APP_VERSION from .env.example — .env left unchanged"
fi

# ── step 3: rebuild and restart containers ────────────────────────────────────
step "Step 3/4 — Rebuilding and restarting containers"
$COMPOSE up -d --build && ok "Containers restarted" || fail "docker compose up failed"

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
