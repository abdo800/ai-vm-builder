#!/usr/bin/env bash
# ══════════════════════════════════════════════════════════════════════════════
#  AI VM Builder — Full Setup Script
#  Challenge 1: Active Cyber Defense — GDG x Duckurity AISprint
#
#  What this script does (in order):
#    1.  Detect your OS (Linux / macOS / Windows Git Bash / WSL)
#    2.  Check Python 3.10+ is installed
#    3.  Check Docker Desktop is running
#    4.  Install all Python dependencies (core + ML + Frida)
#    5.  Create .env from .env.example if not present
#    6.  Prompt for your OpenRouter API key and write it to .env
#    7.  Run a quick LLM connection test (phase1_cli.py)
#    8.  Pull a lightweight Docker image for testing
#    9.  Run a test container with seccomp disabled (required for Frida)
#    10. Set up Frida: install frida-server inside the test container
#    11. Verify Frida injection works (or confirm mock mode is active)
#    12. (Linux only) Check for bcc / eBPF kernel headers
#    13. Run one security scan on the test container
#    14. Run one Red vs Blue battle round
#    15. Launch the Flask web UI
#
#  Usage:
#    chmod +x setup.sh
#    ./setup.sh
#
#  Optional flags:
#    --skip-frida       Skip Frida download/setup
#    --skip-ebpf        Skip eBPF kernel header check
#    --skip-ui          Don't launch web UI at the end
#    --api-key <key>    Pass OpenRouter API key non-interactively
#    --no-color         Disable colored output
# ══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

# ── Parse flags ───────────────────────────────────────────────────────────────
SKIP_FRIDA=false
SKIP_EBPF=false
SKIP_UI=false
API_KEY=""
NO_COLOR=false

for arg in "$@"; do
  case $arg in
    --skip-frida)  SKIP_FRIDA=true ;;
    --skip-ebpf)   SKIP_EBPF=true ;;
    --skip-ui)     SKIP_UI=true ;;
    --no-color)    NO_COLOR=true ;;
    --api-key)     shift; API_KEY="${1:-}" ;;
    --api-key=*)   API_KEY="${arg#*=}" ;;
  esac
done

# ── Colors ────────────────────────────────────────────────────────────────────
if [ "$NO_COLOR" = false ] && [ -t 1 ]; then
  RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
  CYAN='\033[0;36m'; BOLD='\033[1m'; RESET='\033[0m'
  TEAL='\033[0;36m'; GRAY='\033[0;90m'
else
  RED=''; GREEN=''; YELLOW=''; CYAN=''; BOLD=''; RESET=''; TEAL=''; GRAY=''
fi

# ── Print helpers ─────────────────────────────────────────────────────────────
step()    { echo -e "\n${BOLD}${CYAN}[STEP]${RESET} $*"; }
ok()      { echo -e "${GREEN}  ✓${RESET} $*"; }
warn()    { echo -e "${YELLOW}  ⚠${RESET} $*"; }
err()     { echo -e "${RED}  ✗${RESET} $*"; }
info()    { echo -e "${GRAY}    $*${RESET}"; }
banner()  { echo -e "\n${BOLD}$*${RESET}"; }
divider() { echo -e "${GRAY}──────────────────────────────────────────────────${RESET}"; }

# ── Detect OS ─────────────────────────────────────────────────────────────────
detect_os() {
  case "$(uname -s)" in
    Linux*)
      if grep -qi microsoft /proc/version 2>/dev/null; then
        echo "wsl"
      else
        echo "linux"
      fi
      ;;
    Darwin*) echo "macos" ;;
    CYGWIN*|MINGW*|MSYS*) echo "windows" ;;
    *) echo "unknown" ;;
  esac
}

OS=$(detect_os)

# ── Script directory (where setup.sh lives = project root) ───────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ══════════════════════════════════════════════════════════════════════════════
banner "AI VM Builder — Setup Script"
divider
info "Project dir : $SCRIPT_DIR"
info "Detected OS : $OS"
info "Date        : $(date)"
divider

# ══════════════════════════════════════════════════════════════════════════════
# STEP 1 — Python version check
# ══════════════════════════════════════════════════════════════════════════════
step "1/15  Checking Python version"

PYTHON=""
for cmd in python3 python python3.12 python3.11 python3.10; do
  if command -v "$cmd" &>/dev/null; then
    VER=$("$cmd" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')" 2>/dev/null)
    MAJOR=$(echo "$VER" | cut -d. -f1)
    MINOR=$(echo "$VER" | cut -d. -f2)
    if [ "$MAJOR" -ge 3 ] && [ "$MINOR" -ge 10 ]; then
      PYTHON="$cmd"
      ok "Found $cmd $VER"
      break
    fi
  fi
done

if [ -z "$PYTHON" ]; then
  err "Python 3.10+ not found."
  echo ""
  case $OS in
    linux|wsl)
      info "Install: sudo apt-get install python3.11 python3.11-pip"
      ;;
    macos)
      info "Install: brew install python@3.11"
      info "Or download from: https://python.org/downloads"
      ;;
    windows)
      info "Download from: https://python.org/downloads"
      info "Make sure to check 'Add to PATH' during install"
      ;;
  esac
  exit 1
fi

# ══════════════════════════════════════════════════════════════════════════════
# STEP 2 — pip check
# ══════════════════════════════════════════════════════════════════════════════
step "2/15  Checking pip"

PIP=""
for cmd in pip3 pip "python3 -m pip" "$PYTHON -m pip"; do
  if $cmd --version &>/dev/null 2>&1; then
    PIP="$cmd"
    ok "pip available: $($cmd --version 2>&1 | head -1)"
    break
  fi
done

if [ -z "$PIP" ]; then
  err "pip not found. Installing..."
  $PYTHON -m ensurepip --upgrade || {
    err "Could not install pip. Install manually: https://pip.pypa.io"
    exit 1
  }
  PIP="$PYTHON -m pip"
fi

# ══════════════════════════════════════════════════════════════════════════════
# STEP 3 — Docker check
# ══════════════════════════════════════════════════════════════════════════════
step "3/15  Checking Docker"

if ! command -v docker &>/dev/null; then
  err "Docker is not installed."
  echo ""
  case $OS in
    linux|wsl)
      info "Install: https://docs.docker.com/engine/install/"
      info "Quick:   curl -fsSL https://get.docker.com | sh"
      ;;
    macos)
      info "Install Docker Desktop: https://docs.docker.com/desktop/mac/install/"
      ;;
    windows)
      info "Install Docker Desktop: https://docs.docker.com/desktop/windows/install/"
      ;;
  esac
  exit 1
fi

ok "Docker found: $(docker --version)"

# Check Docker daemon is actually running
if ! docker info &>/dev/null 2>&1; then
  err "Docker daemon is not running."
  echo ""
  case $OS in
    linux)   info "Start it: sudo systemctl start docker" ;;
    wsl)     info "Start Docker Desktop on Windows, then restart this terminal" ;;
    macos)   info "Open Docker Desktop from your Applications folder" ;;
    windows) info "Open Docker Desktop from the Start menu" ;;
  esac
  echo ""
  read -r -p "  Press Enter once Docker is running, or Ctrl+C to exit... "
  if ! docker info &>/dev/null 2>&1; then
    err "Docker still not running. Exiting."
    exit 1
  fi
fi

ok "Docker daemon is running"

# ══════════════════════════════════════════════════════════════════════════════
# STEP 4 — Install Python dependencies
# ══════════════════════════════════════════════════════════════════════════════
step "4/15  Installing Python dependencies"

# Determine pip install flags
PIP_FLAGS="--quiet"
if [ "$OS" = "linux" ] || [ "$OS" = "wsl" ]; then
  # Check if we're in a venv or system Python
  if $PYTHON -c "import sys; sys.exit(0 if hasattr(sys, 'real_prefix') or (hasattr(sys, 'base_prefix') and sys.base_prefix != sys.prefix) else 1)" 2>/dev/null; then
    info "Virtual environment detected — installing normally"
    PIP_FLAGS="--quiet"
  else
    # Try without --break-system-packages first
    if $PIP install --quiet --dry-run anthropic &>/dev/null 2>&1; then
      PIP_FLAGS="--quiet"
    else
      PIP_FLAGS="--quiet --break-system-packages"
      info "Using --break-system-packages (system Python)"
    fi
  fi
fi

# Core dependencies
echo "  Installing core packages..."
$PIP install $PIP_FLAGS \
  "anthropic>=0.25.0" \
  "openai>=1.30.0" \
  "python-dotenv>=1.0.0" \
  "docker>=7.0.0" \
  "flask>=3.0.0"
ok "Core packages installed"

# ML packages (optional but strongly recommended)
echo "  Installing ML packages (scikit-learn + numpy)..."
if $PIP install $PIP_FLAGS "scikit-learn>=1.4.0" "numpy>=1.26.0"; then
  ok "ML packages installed — Isolation Forest enabled"
else
  warn "ML packages failed — Z-score + Autoencoder only (still works)"
fi

# Frida (optional)
if [ "$SKIP_FRIDA" = false ]; then
  echo "  Installing Frida..."
  if $PIP install $PIP_FLAGS frida frida-tools; then
    ok "Frida installed — surgical process injection enabled"
    FRIDA_INSTALLED=true
  else
    warn "Frida install failed — mock interception mode will be used"
    FRIDA_INSTALLED=false
  fi
else
  warn "Frida skipped (--skip-frida)"
  FRIDA_INSTALLED=false
fi

# ══════════════════════════════════════════════════════════════════════════════
# STEP 5 — Create .env file
# ══════════════════════════════════════════════════════════════════════════════
step "5/15  Setting up .env"

if [ ! -f ".env" ]; then
  cp .env.example .env
  ok "Created .env from .env.example"
else
  ok ".env already exists — skipping"
fi

# ══════════════════════════════════════════════════════════════════════════════
# STEP 6 — API key
# ══════════════════════════════════════════════════════════════════════════════
step "6/15  Configuring OpenRouter API key"

# Check if key already set in .env
EXISTING_KEY=$(grep "^OPENROUTER_API_KEY=" .env | cut -d= -f2 | tr -d '"' | tr -d "'")

if [ -n "$API_KEY" ]; then
  # Passed as flag
  sed -i.bak "s|^OPENROUTER_API_KEY=.*|OPENROUTER_API_KEY=$API_KEY|" .env && rm -f .env.bak
  ok "API key set from --api-key flag"
elif [ -n "$EXISTING_KEY" ] && [ "$EXISTING_KEY" != "sk-or-your-key-here" ]; then
  ok "API key already configured in .env"
else
  echo ""
  echo -e "  ${BOLD}Get a free OpenRouter key at: https://openrouter.ai/keys${RESET}"
  echo ""
  read -r -p "  Paste your OPENROUTER_API_KEY (or press Enter to skip): " USER_KEY
  if [ -n "$USER_KEY" ]; then
    sed -i.bak "s|^OPENROUTER_API_KEY=.*|OPENROUTER_API_KEY=$USER_KEY|" .env && rm -f .env.bak
    ok "API key saved to .env"
  else
    warn "No API key provided — LLM calls will fail (mock/fallback mode only)"
  fi
fi

# Export so child processes can use it
set -o allexport
source .env
set +o allexport

# ══════════════════════════════════════════════════════════════════════════════
# STEP 7 — LLM connection test
# ══════════════════════════════════════════════════════════════════════════════
step "7/15  Testing LLM connection"

CURRENT_KEY=$(grep "^OPENROUTER_API_KEY=" .env | cut -d= -f2)
if [ -z "$CURRENT_KEY" ] || [ "$CURRENT_KEY" = "sk-or-your-key-here" ]; then
  warn "No API key — skipping LLM test"
else
  echo "  Sending test prompt to OpenRouter (mistral-7b)..."
  LLM_RESULT=$(timeout 30 $PYTHON phase1_cli.py <<< "a simple nginx web server" 2>&1 || true)
  if echo "$LLM_RESULT" | grep -q '"os"'; then
    ok "LLM connection successful — JSON config returned"
  else
    warn "LLM test unclear — check your API key if issues occur"
    info "Output: $(echo "$LLM_RESULT" | tail -3)"
  fi
fi

# ══════════════════════════════════════════════════════════════════════════════
# STEP 8 — Pull Docker image
# ══════════════════════════════════════════════════════════════════════════════
step "8/15  Pulling test Docker image (ubuntu:22.04)"

echo "  Pulling ubuntu:22.04..."
if docker pull ubuntu:22.04 --quiet; then
  ok "ubuntu:22.04 ready"
else
  err "Docker pull failed — check your internet connection"
  exit 1
fi

# ══════════════════════════════════════════════════════════════════════════════
# STEP 9 — Create test container with seccomp disabled (Frida requirement)
# ══════════════════════════════════════════════════════════════════════════════
step "9/15  Creating test container (seccomp:unconfined for Frida)"

# Remove old test container if present
docker rm -f ai-vm-test-container 2>/dev/null || true

TEST_CONTAINER_ID=$(docker run -d \
  --name ai-vm-test-container \
  --security-opt seccomp:unconfined \
  --label ai-vm-builder=true \
  --label purpose="Setup test container" \
  --label security_profile=standard \
  -m 2g \
  ubuntu:22.04 \
  /bin/bash -c "apt-get update -qq && apt-get install -y procps net-tools curl 2>/dev/null; sleep 3600")

if [ -n "$TEST_CONTAINER_ID" ]; then
  SHORT_ID="${TEST_CONTAINER_ID:0:12}"
  ok "Test container running: $SHORT_ID"
  info "Name: ai-vm-test-container"
  info "seccomp: disabled (required for Frida ptrace)"
else
  err "Failed to create test container"
  exit 1
fi

# Wait for container to be ready
sleep 3

# ══════════════════════════════════════════════════════════════════════════════
# STEP 10 — Frida server setup inside container
# ══════════════════════════════════════════════════════════════════════════════
step "10/15  Setting up Frida server inside container"

if [ "$SKIP_FRIDA" = true ]; then
  warn "Frida skipped (--skip-frida) — mock interception will be used"
elif [ "$FRIDA_INSTALLED" = false ]; then
  warn "Frida not installed on host — mock interception will be used"
  info "To enable real injection: pip install frida frida-tools"
else
  # Detect frida version
  FRIDA_VERSION=$($PYTHON -c "import frida; print(frida.__version__)" 2>/dev/null || echo "")

  if [ -z "$FRIDA_VERSION" ]; then
    warn "Could not detect frida version — skipping frida-server setup"
  else
    ok "Frida version: $FRIDA_VERSION"

    # Detect container CPU architecture
    CONTAINER_ARCH=$(docker exec ai-vm-test-container uname -m 2>/dev/null || echo "x86_64")
    case $CONTAINER_ARCH in
      x86_64)  FRIDA_ARCH="x86_64" ;;
      aarch64) FRIDA_ARCH="arm64" ;;
      armv7l)  FRIDA_ARCH="arm" ;;
      *)       FRIDA_ARCH="x86_64" ;;
    esac

    FRIDA_SERVER_NAME="frida-server-${FRIDA_VERSION}-linux-${FRIDA_ARCH}"
    FRIDA_DOWNLOAD_URL="https://github.com/frida/frida/releases/download/${FRIDA_VERSION}/${FRIDA_SERVER_NAME}.xz"

    info "Container arch: $CONTAINER_ARCH → $FRIDA_ARCH"
    info "frida-server: $FRIDA_SERVER_NAME"

    # Check if frida-server already in container
    if docker exec ai-vm-test-container test -f /tmp/frida-server 2>/dev/null; then
      ok "frida-server already in container"
    else
      echo "  Downloading frida-server $FRIDA_VERSION for linux-$FRIDA_ARCH..."
      FRIDA_TMP="/tmp/${FRIDA_SERVER_NAME}"

      DOWNLOAD_OK=false
      # Try curl first, then wget
      if command -v curl &>/dev/null; then
        if curl -sL --max-time 60 -o "${FRIDA_TMP}.xz" "$FRIDA_DOWNLOAD_URL"; then
          DOWNLOAD_OK=true
        fi
      elif command -v wget &>/dev/null; then
        if wget -q --timeout=60 -O "${FRIDA_TMP}.xz" "$FRIDA_DOWNLOAD_URL"; then
          DOWNLOAD_OK=true
        fi
      fi

      if [ "$DOWNLOAD_OK" = true ] && [ -f "${FRIDA_TMP}.xz" ]; then
        # Decompress
        if command -v xz &>/dev/null; then
          xz -d "${FRIDA_TMP}.xz"
          docker cp "$FRIDA_TMP" ai-vm-test-container:/tmp/frida-server
          rm -f "$FRIDA_TMP"
          ok "frida-server downloaded and copied into container"
        else
          warn "xz not found — cannot decompress frida-server"
          info "Install xz: apt-get install xz-utils (Linux) or brew install xz (macOS)"
          rm -f "${FRIDA_TMP}.xz"
          FRIDA_INSTALLED=false
        fi
      else
        warn "frida-server download failed (check internet or GitHub rate limit)"
        info "Manual download: $FRIDA_DOWNLOAD_URL"
        info "Then: docker cp frida-server-linux-$FRIDA_ARCH ai-vm-test-container:/tmp/frida-server"
        FRIDA_INSTALLED=false
      fi
    fi

    # Start frida-server inside container
    if docker exec ai-vm-test-container test -f /tmp/frida-server 2>/dev/null; then
      docker exec ai-vm-test-container chmod +x /tmp/frida-server
      docker exec -d ai-vm-test-container /tmp/frida-server --daemonize 2>/dev/null || \
      docker exec -d ai-vm-test-container /tmp/frida-server &
      sleep 2
      ok "frida-server started inside container on port 27042"
    fi
  fi
fi

# ══════════════════════════════════════════════════════════════════════════════
# STEP 11 — Verify Frida injection (or confirm mock mode)
# ══════════════════════════════════════════════════════════════════════════════
step "11/15  Verifying Frida setup"

FRIDA_TEST=$($PYTHON -c "
import sys; sys.path.insert(0,'.')
from security.ebpf.frida_intercept import FridaIntercept
fi = FridaIntercept(container=None)
r  = fi.inject_process(1, 'connect')
mode = 'MOCK' if r.get('mock') else 'REAL'
print(f'{mode}:{r[\"success\"]}')
" 2>/dev/null || echo "ERROR")

case "$FRIDA_TEST" in
  REAL:True)
    ok "Frida: REAL injection mode active — surgical process hooking enabled"
    ;;
  MOCK:True)
    warn "Frida: MOCK mode — demo-safe, shows mechanism without real injection"
    info "To enable real injection:"
    info "  pip install frida frida-tools"
    info "  Then re-run this script (frida-server will be set up automatically)"
    ;;
  *)
    warn "Frida: could not determine mode — continuing"
    ;;
esac

# ══════════════════════════════════════════════════════════════════════════════
# STEP 12 — eBPF kernel headers check (Linux only)
# ══════════════════════════════════════════════════════════════════════════════
step "12/15  Checking eBPF availability"

if [ "$SKIP_EBPF" = true ]; then
  warn "eBPF check skipped (--skip-ebpf) — /proc fallback will be used"
elif [ "$OS" = "linux" ]; then
  # Check for bcc
  if $PYTHON -c "import bcc" &>/dev/null 2>&1; then
    ok "bcc library found — REAL eBPF kernel hooks available"
    info "Run defense engine as root for full kernel visibility: sudo python security/ai_defense.py"
  else
    warn "bcc not installed — /proc fallback will be used"
    echo ""
    info "To enable real eBPF kernel hooks (Linux only):"
    info "  sudo apt-get install bpfcc-tools linux-headers-\$(uname -r)"
    info "  pip install bcc"
    info "  sudo python security/ai_defense.py --container <id>"
    echo ""

    # Ask if user wants to install now
    read -r -p "  Install eBPF tools now? (requires sudo) [y/N]: " INSTALL_EBPF
    if [[ "${INSTALL_EBPF,,}" == "y" ]]; then
      echo "  Installing bpfcc-tools and kernel headers..."
      if sudo apt-get install -y bpfcc-tools "linux-headers-$(uname -r)" &>/dev/null 2>&1; then
        ok "eBPF tools installed"
        info "Install bcc Python binding: pip install bcc"
      else
        warn "apt-get install failed — try manually: sudo apt-get install bpfcc-tools linux-headers-\$(uname -r)"
      fi
    fi
  fi
elif [ "$OS" = "wsl" ]; then
  warn "WSL detected — real eBPF requires a custom kernel (WSL2 with CONFIG_BPF)"
  info "/proc fallback will be used automatically"
else
  info "eBPF (bcc) is Linux-only — /proc fallback active on $OS"
  ok "ProcFallback provides identical interface — no code changes needed"
fi

# ══════════════════════════════════════════════════════════════════════════════
# STEP 13 — Run one security scan on test container
# ══════════════════════════════════════════════════════════════════════════════
step "13/15  Running security scan on test container"

echo "  Running one dry-run scan (no patches applied)..."
SCAN_OUT=$(timeout 60 $PYTHON security/ai_defense.py \
  --container ai-vm-test-container \
  --once \
  --dry-run 2>&1 || true)

if echo "$SCAN_OUT" | grep -qiE "threat level|summary|scan"; then
  ok "Security scan completed successfully"
  # Print the threat level line
  THREAT_LINE=$(echo "$SCAN_OUT" | grep -i "threat level" | head -1 | sed 's/^[[:space:]]*//')
  ML_LINE=$(echo "$SCAN_OUT" | grep -i "ml score" | head -1 | sed 's/^[[:space:]]*//')
  [ -n "$THREAT_LINE" ] && info "$THREAT_LINE"
  [ -n "$ML_LINE"     ] && info "$ML_LINE"
elif echo "$SCAN_OUT" | grep -qi "api_key\|authentication\|unauthorized"; then
  warn "Scan ran but LLM auth failed — ML-only mode was used"
  info "Set OPENROUTER_API_KEY in .env for full LLM threat analysis"
else
  warn "Scan output unclear — check manually:"
  info "$PYTHON security/ai_defense.py --container ai-vm-test-container --once --dry-run"
  info "Last lines: $(echo "$SCAN_OUT" | tail -4)"
fi

# ══════════════════════════════════════════════════════════════════════════════
# STEP 14 — Run one Red vs Blue battle round
# ══════════════════════════════════════════════════════════════════════════════
step "14/15  Running one Red vs Blue battle round"

echo "  Starting Red vs Blue battle (1 round demo)..."
BATTLE_OUT=$(timeout 90 $PYTHON security/ai_defense.py \
  --container ai-vm-test-container \
  --red-blue \
  --rounds 1 \
  --interval 5 2>&1 || true)

if echo "$BATTLE_OUT" | grep -qiE "round|red|blue|blocked|outcome"; then
  ok "Red vs Blue battle round completed"
  OUTCOME=$(echo "$BATTLE_OUT" | grep -iE "OUTCOME|BLOCKED|UNDETECTED" | head -1 | sed 's/^[[:space:]]*//')
  [ -n "$OUTCOME" ] && info "$OUTCOME"
elif echo "$BATTLE_OUT" | grep -qi "api_key\|authentication"; then
  warn "Battle ran but LLM auth failed — add OPENROUTER_API_KEY for full AI battle"
else
  warn "Battle output unclear:"
  info "$(echo "$BATTLE_OUT" | tail -4)"
fi

# ══════════════════════════════════════════════════════════════════════════════
# STEP 15 — Launch web UI
# ══════════════════════════════════════════════════════════════════════════════
step "15/15  Launching Flask web UI"

if [ "$SKIP_UI" = true ]; then
  warn "Web UI skipped (--skip-ui)"
else
  echo ""
  echo -e "  ${BOLD}Opening http://localhost:5000${RESET}"
  echo ""
  echo -e "  ${BOLD}Web UI tabs:${RESET}"
  echo -e "    ${TEAL}Build VM${RESET}     — describe your VM in plain English"
  echo -e "    ${TEAL}Containers${RESET}  — manage running containers"
  echo -e "    ${TEAL}Security${RESET}    — ML scores, scans, live patches"
  echo -e "    ${TEAL}Defense Log${RESET} — full scan history"
  echo -e "    ${TEAL}Red vs Blue${RESET} — adversarial battle UI"
  echo ""
  echo -e "  ${GRAY}Press Ctrl+C to stop the server${RESET}"
  echo ""
  divider

  # Try to open browser automatically
  case $OS in
    macos)   sleep 1 && open "http://localhost:5000" &>/dev/null & ;;
    linux)   sleep 1 && (xdg-open "http://localhost:5000" &>/dev/null &) 2>/dev/null || true ;;
    windows) sleep 1 && (start "http://localhost:5000" &>/dev/null &) 2>/dev/null || true ;;
    wsl)     sleep 1 && (explorer.exe "http://localhost:5000" &>/dev/null &) 2>/dev/null || true ;;
  esac

  cd phase3_web
  exec $PYTHON app.py
fi

# ══════════════════════════════════════════════════════════════════════════════
# Done (only reached if --skip-ui)
# ══════════════════════════════════════════════════════════════════════════════
divider
echo ""
echo -e "${BOLD}${GREEN}Setup complete!${RESET}"
echo ""
echo -e "  ${BOLD}Quick reference:${RESET}"
echo -e "  ${GRAY}# Launch web UI${RESET}"
echo -e "  cd phase3_web && $PYTHON app.py"
echo ""
echo -e "  ${GRAY}# CLI: test LLM${RESET}"
echo -e "  $PYTHON phase1_cli.py"
echo ""
echo -e "  ${GRAY}# CLI: create container${RESET}"
echo -e "  $PYTHON phase2_docker.py"
echo ""
echo -e "  ${GRAY}# Security scan (dry run)${RESET}"
echo -e "  $PYTHON security/ai_defense.py --container ai-vm-test-container --once --dry-run"
echo ""
echo -e "  ${GRAY}# Security scan (live patches)${RESET}"
echo -e "  $PYTHON security/ai_defense.py --container ai-vm-test-container --interval 60 --auto-patch"
echo ""
echo -e "  ${GRAY}# Red vs Blue battle${RESET}"
echo -e "  $PYTHON security/ai_defense.py --container ai-vm-test-container --red-blue --rounds 10"
echo ""
echo -e "  ${GRAY}# ARIA persona guide (Challenge 5)${RESET}"
echo -e "  $PYTHON security/persona_guide.py"
echo ""
divider
