# ============================================================
#  run-dev.ps1 — API Firewall UI Dev Server
#  Author : Usama
#  GitHub : https://github.com/UZYNTRA-Security/uzyntra-ui
#  LinkedIn: https://linkedin.com/in/usamamatrix/
# ============================================================

$ROOT = Split-Path $PSScriptRoot -Parent

function Write-Info  { param($m) Write-Host "  [INFO]  $m" -ForegroundColor Cyan    }
function Write-Ok    { param($m) Write-Host "  [ OK ]  $m" -ForegroundColor Green   }
function Write-Warn  { param($m) Write-Host "  [WARN]  $m" -ForegroundColor Yellow  }
function Write-Fail  { param($m) Write-Host "  [FAIL]  $m" -ForegroundColor Red     }
function Write-Step  { param($m) Write-Host "`n  ──── $m" -ForegroundColor Magenta  }

Clear-Host
Write-Host ""
Write-Host "  ╔══════════════════════════════════════════╗" -ForegroundColor Blue
Write-Host "  ║       API Firewall UI — Dev Runner       ║" -ForegroundColor Blue
Write-Host "  ║  github.com/UZYNTRA-Security/uzyntra-ui  |  @usamamatrix ║" -ForegroundColor DarkBlue
Write-Host "  ╚══════════════════════════════════════════╝" -ForegroundColor Blue
Write-Host ""

# ── 1. Node.js ──────────────────────────────────────────────
Write-Step "Checking Requirements"

if (-not (Get-Command node -ErrorAction SilentlyContinue)) {
    Write-Fail "Node.js not found. Install from https://nodejs.org"
    exit 1
}
$nodeVer = node --version
Write-Ok "Node.js $nodeVer"

# ── 2. npm ───────────────────────────────────────────────────
if (-not (Get-Command npm -ErrorAction SilentlyContinue)) {
    Write-Fail "npm not found. Reinstall Node.js."
    exit 1
}
$npmVer = npm --version
Write-Ok "npm v$npmVer"

# ── 3. node_modules ─────────────────────────────────────────
Write-Step "Checking Dependencies"

if (-not (Test-Path "$ROOT\node_modules")) {
    Write-Warn "node_modules missing — running npm install..."
    Set-Location $ROOT
    npm install
    if ($LASTEXITCODE -ne 0) { Write-Fail "npm install failed."; exit 1 }
    Write-Ok "Dependencies installed."
} else {
    Write-Ok "node_modules present."
}

# ── 4. Launch ────────────────────────────────────────────────
Write-Step "Starting Dev Server"
Write-Info "URL  : http://localhost:3000"
Write-Info "Root : $ROOT"
Write-Host ""

Set-Location $ROOT
npm run dev
