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
apt-get install -y zaproxy 2>/dev/null || true

# ── API Security tools ────────────────────────────────────────────────────────
echo "[*] Installing API security tools..."

# graphql-cop — GraphQL security auditor
if ! command -v graphql-cop &>/dev/null; then
    $VENV_PIP install graphql-cop 2>/dev/null || true
    echo "[+] graphql-cop installed via pip"
fi

# jwt_tool — JWT security testing
if ! command -v jwt_tool &>/dev/null; then
    $VENV_PIP install jwt_tool 2>/dev/null || \
    (git clone https://github.com/ticarpi/jwt_tool /opt/jwt_tool 2>/dev/null \
        && ln -sf /opt/jwt_tool/jwt_tool.py /usr/local/bin/jwt_tool \
        && chmod +x /opt/jwt_tool/jwt_tool.py \
        && echo "[+] jwt_tool installed from source")
fi

# arjun — HTTP parameter discovery
if ! command -v arjun &>/dev/null; then
    $VENV_PIP install arjun 2>/dev/null || true
    echo "[+] arjun installed via pip"
fi

# x8 — hidden parameter discovery (Go binary)
if ! command -v x8 &>/dev/null; then
    X8_VER=$(curl -s https://api.github.com/repos/Sh1Yo/x8/releases/latest \
        | grep '"tag_name"' | cut -d'"' -f4 | head -1)
    if [ -n "$X8_VER" ]; then
        curl -sL "https://github.com/Sh1Yo/x8/releases/download/${X8_VER}/x86_64-linux-x8.tar.gz" \
            -o /tmp/x8.tar.gz 2>/dev/null \
            && tar -xzf /tmp/x8.tar.gz -C /usr/local/bin x8 2>/dev/null \
            && chmod +x /usr/local/bin/x8 \
            && echo "[+] x8 installed"
    fi
fi

# kiterunner — API route discovery (Go binary)
if ! command -v kr &>/dev/null; then
    KR_VER=$(curl -s https://api.github.com/repos/assetnote/kiterunner/releases/latest \
        | grep '"tag_name"' | cut -d'"' -f4 | head -1)
    if [ -n "$KR_VER" ]; then
        curl -sL "https://github.com/assetnote/kiterunner/releases/download/${KR_VER}/kiterunner_${KR_VER#v}_linux_amd64.tar.gz" \
            -o /tmp/kiterunner.tar.gz 2>/dev/null \
            && tar -xzf /tmp/kiterunner.tar.gz -C /usr/local/bin kr 2>/dev/null \
            && chmod +x /usr/local/bin/kr \
            && echo "[+] kiterunner (kr) installed"
    fi
fi

# Download kiterunner routes wordlist if installed
if command -v kr &>/dev/null && [ ! -f /usr/share/kiterunner/routes-large.kite ]; then
    mkdir -p /usr/share/kiterunner
    curl -sL "https://wordlists-cdn.assetnote.io/data/kiterunner/routes-large.kite" \
        -o /usr/share/kiterunner/routes-large.kite 2>/dev/null \
        && echo "[+] kiterunner routes-large.kite downloaded" || true
fi

# ── Verify installs ────────────────────────────────────────────────────────────
echo ""
echo "[*] Tool verification:"

ALL_TOOLS=(
    # Password
    medusa patator hash-identifier hashcat
    ROPgadget ropper pwn one_gadget pwninit
    # Forensics
    hashpump xxd scalpel outguess zsteg vol
    # Cloud
    scout-suite terrascan checkov trivy
    # OSINT
    fierce social-analyzer shodan
    # Web
    zap.sh nuclei dalfox gobuster ffuf feroxbuster nikto wpscan sqlmap
    # API Security
    graphql-cop jwt_tool arjun x8 kr
    # Net
    nmap rustscan subfinder amass
)

PASS=0
FAIL=0
for tool in "${ALL_TOOLS[@]}"; do
    if command -v "$tool" &>/dev/null; then
        echo "  [+] $tool"
        PASS=$((PASS+1))
    else
        echo "  [-] $tool (not found)"
        FAIL=$((FAIL+1))
    fi
done

echo ""
echo "[*] Results: $PASS installed, $FAIL missing"
echo "[*] Done. Restart the CF_AI server:"
echo "      pkill -f cfai_server.py; bash /opt/CF_AI/run.sh"
