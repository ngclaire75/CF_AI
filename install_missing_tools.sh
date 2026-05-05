#!/bin/bash
# CF_AI — Install missing tools
# Run as root: bash install_missing_tools.sh

VENV_PIP="/opt/CF_AI/venv/bin/pip"
[ -f "$VENV_PIP" ] || VENV_PIP="pip3"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'
ok()   { echo -e "  ${GREEN}[+]${NC} $1"; }
warn() { echo -e "  ${YELLOW}[!]${NC} $1"; }

echo "[*] Updating package lists..."
apt-get update -q 2>/dev/null || true

# ── Password / Binary tools ───────────────────────────────────────────────────
echo "[*] Installing password & binary tools..."
apt-get install -y medusa patator hash-identifier ophcrack 2>/dev/null || true
$VENV_PIP install ropper pwntools 2>/dev/null || true
ok "ropper/pwntools via pip"

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
        ok "pwninit installed"
    fi
fi

# ── Forensics tools ───────────────────────────────────────────────────────────
echo "[*] Installing forensics tools..."

# hashpump — try apt first, build from source if needed
if ! command -v hashpump &>/dev/null; then
    apt-get install -y hashpump 2>/dev/null || \
    (apt-get install -y libssl-dev build-essential 2>/dev/null && \
     git clone https://github.com/bwall/HashPump /tmp/hashpump 2>/dev/null && \
     cd /tmp/hashpump && make && cp hashpump /usr/local/bin/ && \
     ok "hashpump built from source") || warn "hashpump install failed"
fi

# xxd — part of vim-common on Debian/Kali
if ! command -v xxd &>/dev/null; then
    apt-get install -y xxd 2>/dev/null || \
    apt-get install -y vim-common 2>/dev/null || warn "xxd not available"
fi

# scalpel
if ! command -v scalpel &>/dev/null; then
    apt-get install -y scalpel 2>/dev/null || warn "scalpel not available in apt"
fi

# outguess
if ! command -v outguess &>/dev/null; then
    apt-get install -y outguess 2>/dev/null || \
    (git clone https://github.com/resurrecting-open-source-projects/outguess /tmp/outguess 2>/dev/null && \
     cd /tmp/outguess && autoreconf -i && ./configure && make && make install && \
     ok "outguess built from source") || warn "outguess install failed"
fi

# bulk-extractor
apt-get install -y bulk-extractor 2>/dev/null || true

# zsteg requires Ruby gem
if command -v gem &>/dev/null; then
    gem install zsteg 2>/dev/null || true
fi

# volatility3
if ! command -v vol &>/dev/null; then
    $VENV_PIP install volatility3 2>/dev/null || true
    if command -v vol3 &>/dev/null && [ ! -f /usr/local/bin/vol ]; then
        ln -sf "$(which vol3)" /usr/local/bin/vol
        ok "vol symlink -> vol3"
    fi
fi

# ── Cloud security tools ──────────────────────────────────────────────────────
echo "[*] Installing cloud tools..."

# ScoutSuite
if ! command -v scout-suite &>/dev/null; then
    $VENV_PIP install scoutsuite 2>/dev/null || true
    # ScoutSuite installs as 'scout' in some versions — create alias
    if command -v scout &>/dev/null && [ ! -f /usr/local/bin/scout-suite ]; then
        ln -sf "$(which scout)" /usr/local/bin/scout-suite
        ok "scout-suite symlink created"
    fi
fi

# checkov
if ! command -v checkov &>/dev/null; then
    $VENV_PIP install checkov 2>/dev/null || true
    ok "checkov installed via pip"
fi

# terrascan
if ! command -v terrascan &>/dev/null; then
    TERRASCAN_VER=$(curl -s https://api.github.com/repos/tenable/terrascan/releases/latest \
        | grep '"tag_name"' | cut -d'"' -f4)
    if [ -n "$TERRASCAN_VER" ]; then
        curl -sL "https://github.com/tenable/terrascan/releases/download/${TERRASCAN_VER}/terrascan_${TERRASCAN_VER#v}_Linux_x86_64.tar.gz" \
            -o /tmp/terrascan.tar.gz 2>/dev/null \
            && tar -xzf /tmp/terrascan.tar.gz -C /usr/local/bin terrascan 2>/dev/null \
            && chmod +x /usr/local/bin/terrascan \
            && ok "terrascan installed"
    fi
fi

# ── OSINT tools ───────────────────────────────────────────────────────────────
echo "[*] Installing OSINT tools..."

# fierce
if ! command -v fierce &>/dev/null; then
    $VENV_PIP install fierce 2>/dev/null || true
    ok "fierce installed via pip"
fi

# social-analyzer
if ! command -v social-analyzer &>/dev/null; then
    $VENV_PIP install social-analyzer 2>/dev/null || true
    ok "social-analyzer installed via pip"
fi

$VENV_PIP install shodan 2>/dev/null || true

# rustscan — download release binary
if ! command -v rustscan &>/dev/null; then
    RS_VER=$(curl -s https://api.github.com/repos/RustScan/RustScan/releases/latest \
        | grep '"tag_name"' | cut -d'"' -f4)
    if [ -n "$RS_VER" ]; then
        curl -sL "https://github.com/RustScan/RustScan/releases/download/${RS_VER}/rustscan_${RS_VER#v}_amd64.deb" \
            -o /tmp/rustscan.deb 2>/dev/null \
            && dpkg -i /tmp/rustscan.deb 2>/dev/null \
            && ok "rustscan installed" \
            || warn "rustscan deb install failed"
    fi
fi

# ── Web security tools ────────────────────────────────────────────────────────
echo "[*] Installing web security tools..."

# ZAP proxy — large download, skip if slow connection
if ! command -v zap.sh &>/dev/null; then
    apt-get install -y zaproxy 2>/dev/null && ok "zaproxy installed" || warn "zaproxy not in apt — download manually from zaproxy.org"
fi

# ── API Security tools ────────────────────────────────────────────────────────
echo "[*] Installing API security tools..."

# graphql-cop
if ! command -v graphql-cop &>/dev/null; then
    $VENV_PIP install graphql-cop 2>/dev/null || true
    # Some versions install as graphql_cop — create symlink
    GQL_BIN=$(find /opt/CF_AI/venv/bin /usr/local/bin -name "graphql*" 2>/dev/null | head -1)
    if [ -n "$GQL_BIN" ] && [ ! -f /usr/local/bin/graphql-cop ]; then
        ln -sf "$GQL_BIN" /usr/local/bin/graphql-cop
        chmod +x /usr/local/bin/graphql-cop
    fi
    ok "graphql-cop installed"
fi

# jwt_tool
if ! command -v jwt_tool &>/dev/null; then
    $VENV_PIP install jwt_tool 2>/dev/null || \
    (git clone https://github.com/ticarpi/jwt_tool /opt/jwt_tool 2>/dev/null \
        && ln -sf /opt/jwt_tool/jwt_tool.py /usr/local/bin/jwt_tool \
        && chmod +x /opt/jwt_tool/jwt_tool.py \
        && ok "jwt_tool installed from source")
fi

# arjun
if ! command -v arjun &>/dev/null; then
    $VENV_PIP install arjun 2>/dev/null || true
    ok "arjun installed via pip"
fi

# x8 — hidden parameter discovery
if ! command -v x8 &>/dev/null; then
    X8_VER=$(curl -s https://api.github.com/repos/Sh1Yo/x8/releases/latest \
        | grep '"tag_name"' | cut -d'"' -f4 | head -1)
    if [ -n "$X8_VER" ]; then
        curl -sL "https://github.com/Sh1Yo/x8/releases/download/${X8_VER}/x86_64-linux-x8.tar.gz" \
            -o /tmp/x8.tar.gz 2>/dev/null \
            && tar -xzf /tmp/x8.tar.gz -C /usr/local/bin 2>/dev/null \
            && chmod +x /usr/local/bin/x8 \
            && ok "x8 installed" \
            || warn "x8 install failed"
    fi
fi

# kiterunner
if ! command -v kr &>/dev/null; then
    KR_VER=$(curl -s https://api.github.com/repos/assetnote/kiterunner/releases/latest \
        | grep '"tag_name"' | cut -d'"' -f4 | head -1)
    if [ -n "$KR_VER" ]; then
        curl -sL "https://github.com/assetnote/kiterunner/releases/download/${KR_VER}/kiterunner_${KR_VER#v}_linux_amd64.tar.gz" \
            -o /tmp/kiterunner.tar.gz 2>/dev/null \
            && tar -xzf /tmp/kiterunner.tar.gz -C /usr/local/bin kr 2>/dev/null \
            && chmod +x /usr/local/bin/kr \
            && ok "kiterunner (kr) installed"
    fi
fi

# kiterunner wordlist
if command -v kr &>/dev/null && [ ! -f /usr/share/kiterunner/routes-large.kite ]; then
    mkdir -p /usr/share/kiterunner
    curl -sL "https://wordlists-cdn.assetnote.io/data/kiterunner/routes-large.kite" \
        -o /usr/share/kiterunner/routes-large.kite 2>/dev/null \
        && ok "kiterunner wordlist downloaded" || true
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
