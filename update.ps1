# update.ps1 — ReportShelter Windows update script
#
# Usage:
#   .\update.ps1           # pull latest stable release and rebuild
#   .\update.ps1 -Check    # only check what version is available, no changes
#
# Prerequisites: git, docker desktop with compose
# Run this from the directory where you cloned the repository.

param([switch]$Check)

$ErrorActionPreference = "Stop"
$RepoDir  = Split-Path -Parent $MyInvocation.MyCommand.Path
$Branch   = if ($env:UPDATE_BRANCH) { $env:UPDATE_BRANCH } else { "main" }
$Compose  = "docker compose"

function Write-OK($msg)   { Write-Host "[OK]  $msg" -ForegroundColor Green }
function Write-Warn($msg) { Write-Host "[!!]  $msg" -ForegroundColor Yellow }
function Write-Fail($msg) { Write-Host "[KO]  $msg" -ForegroundColor Red; exit 1 }
function Write-Step($msg) {
    Write-Host ""
    Write-Host "──────────────────────────────────────" -ForegroundColor Yellow
    Write-Host "  $msg"
    Write-Host "──────────────────────────────────────" -ForegroundColor Yellow
}

# ── check mode ────────────────────────────────────────────────────────────────
if ($Check) {
    Write-Step "Checking for updates..."
    $current = (Get-Content "$RepoDir\.env" -ErrorAction SilentlyContinue |
        Where-Object { $_ -match "^APP_VERSION=" }) -replace "^APP_VERSION=", ""
    $remote = git -C $RepoDir ls-remote --tags origin |
        Select-String 'v[\d.]+$' | ForEach-Object { $_.Matches.Value } |
        Sort-Object | Select-Object -Last 1
    Write-Host "  Installed : $($current  ?? 'unknown')"
    Write-Host "  Available : $($remote ?? 'unknown')"
    if ($current -eq $remote) { Write-OK "Already up to date." }
    else { Write-Warn "Update available: $remote" }
    exit 0
}

Write-Step "ReportShelter Update"

# ── pre-flight ────────────────────────────────────────────────────────────────
foreach ($cmd in @("git", "docker")) {
    if (-not (Get-Command $cmd -ErrorAction SilentlyContinue)) {
        Write-Fail "$cmd not found in PATH"
    }
}
& docker compose version > $null 2>&1
if ($LASTEXITCODE -ne 0) { Write-Fail "docker compose not found" }

# ── step 1: backup ────────────────────────────────────────────────────────────
Write-Step "Step 1/4 — Pre-update database backup"
$running = & docker compose -f "$RepoDir\docker-compose.yml" ps backend 2>$null |
    Select-String "Up"
if ($running) {
    Write-Warn "Triggering backup via management command..."
    & docker compose -f "$RepoDir\docker-compose.yml" exec -T backend `
        python manage.py backup_database --label pre-update
    if ($LASTEXITCODE -eq 0) { Write-OK "Backup created in /app/backups/" }
    else { Write-Warn "Backup failed — proceeding anyway" }
} else {
    Write-Warn "Containers not running — skipping backup step"
}

# ── step 2: git pull ──────────────────────────────────────────────────────────
Write-Step "Step 2/4 — Pulling latest code (branch: $Branch)"
git -C $RepoDir pull origin $Branch
if ($LASTEXITCODE -ne 0) { Write-Fail "git pull failed" }
Write-OK "Code updated"

# ── step 2b: sync APP_VERSION, GIT_COMMIT, GIT_DATE → .env ──────────────────
function Set-EnvKey($key, $value, $file) {
    $lines = Get-Content $file
    if ($lines -match "^$key=") {
        $lines = $lines -replace "^$key=.*", "$key=$value"
    } else {
        $lines += "$key=$value"
    }
    $lines | Set-Content $file -Encoding UTF8
}

$envFile    = "$RepoDir\.env"
$envExample = "$RepoDir\.env.example"
if (Test-Path $envFile) {
    $newVersion = ((Get-Content $envExample | Where-Object { $_ -match "^APP_VERSION=" }) `
        -replace "^APP_VERSION=", "").Trim()
    $newCommit  = (git -C $RepoDir rev-parse --short HEAD 2>$null).Trim()
    $newDate    = (git -C $RepoDir log -1 --format="%ci" 2>$null).Trim()

    if ($newVersion) { Set-EnvKey "APP_VERSION" $newVersion $envFile; Write-OK "APP_VERSION=$newVersion" }
    Set-EnvKey "GIT_COMMIT" ($newCommit  ?? "unknown") $envFile; Write-OK "GIT_COMMIT=$newCommit"
    Set-EnvKey "GIT_DATE"   ($newDate    ?? "unknown") $envFile; Write-OK "GIT_DATE=$newDate"
} else {
    Write-Warn ".env not found — skipping version sync"
}

# ── step 3: rebuild ───────────────────────────────────────────────────────────
Write-Step "Step 3/4 — Rebuilding and restarting containers"
& docker compose -f "$RepoDir\docker-compose.yml" up -d --build
if ($LASTEXITCODE -ne 0) { Write-Fail "docker compose up failed" }
Write-OK "Containers restarted"

& docker compose -f "$RepoDir\docker-compose.yml" restart nginx
if ($LASTEXITCODE -eq 0) { Write-OK "nginx reloaded" }
else { Write-Warn "nginx restart failed — you may see 502 until next restart" }

# ── step 4: health + migrate ──────────────────────────────────────────────────
Write-Step "Step 4/4 — Waiting for backend to become healthy..."
$retries = 30
$healthy = $false
while ($retries -gt 0) {
    & docker compose -f "$RepoDir\docker-compose.yml" exec -T backend `
        python -c "import socket; s=socket.socket(); s.settimeout(2); s.connect(('localhost',8000))" `
        2>$null
    if ($LASTEXITCODE -eq 0) { $healthy = $true; break }
    $retries--
    Write-Host -NoNewline "."
    Start-Sleep 3
}
Write-Host ""
if (-not $healthy) { Write-Fail "Backend did not become healthy in time" }
Write-OK "Backend is healthy"

& docker compose -f "$RepoDir\docker-compose.yml" exec -T backend `
    python manage.py migrate --noinput
if ($LASTEXITCODE -eq 0) { Write-OK "Migrations applied" }
else { Write-Fail "Migrations failed — restore from the pre-update backup if needed" }

# ── done ─────────────────────────────────────────────────────────────────────
$finalVersion = ((Get-Content $envFile | Where-Object { $_ -match "^APP_VERSION=" }) `
    -replace "^APP_VERSION=", "").Trim()
Write-Host ""
Write-OK "Update complete — version: $finalVersion"
Write-Host ""
Write-Host "  If something looks wrong, restore with:"
Write-Host "  docker compose exec backend python manage.py restore_database --yes <backup-file>"
Write-Host ""
