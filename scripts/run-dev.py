#!/usr/bin/env python3
# ============================================================
#  run-dev.py — API Firewall UI Dev Server
#  Author : Usama
#  GitHub : https://github.com/UZYNTRA-Security/uzyntra-ui
#  LinkedIn: https://linkedin.com/in/usamamatrix/
# ============================================================

import subprocess, sys, shutil
from pathlib import Path

# ── ANSI Colors ──────────────────────────────────────────────
R="\033[0m"; CYAN="\033[96m"; GREEN="\033[92m"
YELLOW="\033[93m"; RED="\033[91m"; MAGENTA="\033[95m"; BLUE="\033[94m"

def info(m):  print(f"  {CYAN}[INFO]{R}  {m}")
def ok(m):    print(f"  {GREEN}[ OK ]{R}  {m}")
def warn(m):  print(f"  {YELLOW}[WARN]{R}  {m}")
def fail(m):  print(f"  {RED}[FAIL]{R}  {m}"); sys.exit(1)
def step(m):  print(f"\n  {MAGENTA}──── {m}{R}")

ROOT = Path(__file__).resolve().parent.parent

def run(cmd, cwd=ROOT):
    r = subprocess.run(cmd, shell=True, cwd=cwd)
    if r.returncode != 0:
        fail(f"Command failed: {cmd}")

def check(tool, install_hint):
    if not shutil.which(tool):
        fail(f"{tool} not found. {install_hint}")
    ver = subprocess.check_output(f"{tool} --version", shell=True, text=True).strip()
    ok(f"{tool} {ver}")

# ── Banner ───────────────────────────────────────────────────
print(f"""
  {BLUE}╔══════════════════════════════════════════╗
  ║       API Firewall UI — Dev Runner       ║
  ║  github.com/UZYNTRA-Security/uzyntra-ui  |  @usamamatrix ║
  ╚══════════════════════════════════════════╝{R}
""")

# ── 1. Requirements ──────────────────────────────────────────
step("Checking Requirements")
check("node", "Install from https://nodejs.org")
check("npm",  "Reinstall Node.js")

# ── 2. Dependencies ──────────────────────────────────────────
step("Checking Dependencies")
if not (ROOT / "node_modules").exists():
    warn("node_modules missing — running npm install...")
    run("npm install")
    ok("Dependencies installed.")
else:
    ok("node_modules present.")

# ── 3. Launch ────────────────────────────────────────────────
step("Starting Dev Server")
info("URL  : http://localhost:3000")
info(f"Root : {ROOT}")
print()

try:
    subprocess.run("npm run dev", shell=True, cwd=ROOT)
except KeyboardInterrupt:
    print(f"\n  {YELLOW}[STOP]{R}  Dev server stopped.")
