#!/usr/bin/env bash
# ============================================================
#  run-dev.sh — API Firewall UI Dev Server
#  Author : Usama
#  GitHub : https://github.com/UZYNTRA-Security/uzyntra-ui
#  LinkedIn: https://linkedin.com/in/usamamatrix/
# ============================================================

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

# ── ANSI Colors ──────────────────────────────────────────────
R="\033[0m"; CYAN="\033[96m"; GREEN="\033[92m"
YELLOW="\033[93m"; RED="\033[91m"; MAGENTA="\033[95m"; BLUE="\033[94m"

info()  { echo -e "  ${CYAN}[INFO]${R}  $*"; }
ok()    { echo -e "  ${GREEN}[ OK ]${R}  $*"; }
warn()  { echo -e "  ${YELLOW}[WARN]${R}  $*"; }
fail()  { echo -e "  ${RED}[FAIL]${R}  $*"; exit 1; }
step()  { echo -e "\n  ${MAGENTA}──── $*${R}"; }

# ── Banner ───────────────────────────────────────────────────
echo -e "
  ${BLUE}╔══════════════════════════════════════════╗
  ║       API Firewall UI — Dev Runner       ║
  ║  github.com/UZYNTRA-Security/uzyntra-ui  |  @usamamatrix ║
  ╚══════════════════════════════════════════╝${R}
"

# ── 1. Requirements ──────────────────────────────────────────
step "Checking Requirements"

command -v node &>/dev/null || fail "Node.js not found. Install from https://nodejs.org"
ok "Node.js $(node --version)"

command -v npm &>/dev/null  || fail "npm not found. Reinstall Node.js."
ok "npm v$(npm --version)"

# ── 2. Dependencies ──────────────────────────────────────────
step "Checking Dependencies"

if [[ ! -d "$ROOT/node_modules" ]]; then
    warn "node_modules missing — running npm install..."
    npm install --prefix "$ROOT" || fail "npm install failed."
    ok "Dependencies installed."
else
    ok "node_modules present."
fi

# ── 3. Launch ────────────────────────────────────────────────
step "Starting Dev Server"
info "URL  : http://localhost:3000"
info "Root : $ROOT"
echo ""

cd "$ROOT"
trap 'echo -e "\n  ${YELLOW}[STOP]${R}  Dev server stopped."' INT
npm run dev
