#!/bin/bash
# CF_AI — Install missing tools
# Run as root: bash install_missing_tools.sh

set -e
VENV_PIP="/opt/CF_AI/venv/bin/pip"
[ -f "$VENV_PIP" ] || VENV_PIP="pip3"

echo "[*] Updating package lists..."
apt-get update -q 2>/dev/null || true

# ── Password tools ────────────────────────────────────────────────────────────
echo "[*] Installing password tools..."
apt-get install -y medusa patator hash-identifier ophcrack 2>/dev/null || true

# ── Binary / PWN tools ────────────────────────────────────────────────────────
echo "[*] Installing binary/PWN tools..."
$VENV_PIP install ropgadget ropper pwntools 2>/dev/null || true

# one_gadget requires Ruby gem
if command -v gem &>/dev/null; then
    gem install one_gadget 2>/dev/null || true
fi

# pwninit — download latest release binary
if ! command -v pwninit &>/dev/null; then
    PWNINIT_URL=$(curl -s https://api.github.com/repos/io12/pwninit/releases/latest \
        | grep browser_download_url | grep -v '.sha256' | cut -d'"' -f4 | head -1)
    if [ -n "$PWNINIT_URL" ]; then
        curl -sL "$PWNINIT_URL" -o /usr/local/bin/pwninit && chmod +x /usr/local/bin/pwninit
        echo "[+] pwninit installed"
    fi
fi

# ── Forensics tools ────────────────────────────────────────────────────────────
echo "[*] Installing forensics tools..."
apt-get install -y hashpump xxd scalpel bulk-extractor outguess 2>/dev/null || true

# zsteg requires Ruby gem
if command -v gem &>/dev/null; then
    gem install zsteg 2>/dev/null || true
fi

# volatility3 (binary: vol3, we alias to vol)
if ! command -v vol &>/dev/null; then
    $VENV_PIP install volatility3 2>/dev/null || true
    # Create 'vol' symlink if vol3 was installed
    if command -v vol3 &>/dev/null && [ ! -f /usr/local/bin/vol ]; then
        ln -sf "$(which vol3)" /usr/local/bin/vol
        echo "[+] vol symlink created -> vol3"
    fi
fi

# ── Cloud security tools ────────────────────────────────────────────────────────
echo "[*] Installing cloud tools..."

# ScoutSuite (binary: scout-suite)
$VENV_PIP install scoutsuite 2>/dev/null || true

# terrascan — download release binary
if ! command -v terrascan &>/dev/null; then
    TERRASCAN_VER=$(curl -s https://api.github.com/repos/tenable/terrascan/releases/latest \
        | grep '"tag_name"' | cut -d'"' -f4)
    if [ -n "$TERRASCAN_VER" ]; then
        curl -sL "https://github.com/tenable/terrascan/releases/download/${TERRASCAN_VER}/terrascan_${TERRASCAN_VER#v}_Linux_x86_64.tar.gz" \
            -o /tmp/terrascan.tar.gz 2>/dev/null \
            && tar -xzf /tmp/terrascan.tar.gz -C /usr/local/bin terrascan 2>/dev/null \
            && chmod +x /usr/local/bin/terrascan \
            && echo "[+] terrascan installed"
    fi
fi

# ── OSINT tools ────────────────────────────────────────────────────────────────
echo "[*] Installing OSINT tools..."
$VENV_PIP install fierce social-analyzer shodan 2>/dev/null || true

# ── Web security tools ────────────────────────────────────────────────────────
echo "[*] Installing web security tools..."
# ZAP proxy (binary: zap.sh)
apt-get install -y zaproxy 2>/dev/null || true

# ── Verify installs ────────────────────────────────────────────────────────────
echo ""
echo "[*] Tool verification:"
for tool in medusa patator hash-identifier hashcat ROPgadget ropper pwn one_gadget pwninit \
            hashpump xxd scalpel outguess zsteg vol \
            scout-suite terrascan checkov trivy \
            fierce social-analyzer shodan \
            zap.sh; do
    if command -v "$tool" &>/dev/null; then
        echo "  [+] $tool"
    else
        echo "  [-] $tool (not found)"
    fi
done

echo ""
echo "[*] Done. Restart the CF_AI server: pkill -f cfai_server.py; bash /opt/CF_AI/run.sh"
