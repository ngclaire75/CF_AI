#!/bin/bash
# CF_AI Full Setup Script for Kali Linux
# Installs all tools from the AI Automation for Attack and Reconnaissance Platform

# Do NOT use set -e — allow individual installs to fail without stopping the whole script

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

info()    { echo -e "${CYAN}[INFO]${NC} $1"; }
success() { echo -e "${GREEN}[OK]${NC} $1"; }
warn()    { echo -e "${YELLOW}[WARN]${NC} $1"; }
err()     { echo -e "${RED}[ERR]${NC} $1"; }
section() { echo -e "\n${RED}━━━ $1 ━━━${NC}"; }

echo -e "${RED}"
cat << 'BANNER'
  ██████╗███████╗      █████╗ ██╗
 ██╔════╝██╔════╝     ██╔══██╗██║
 ██║     █████╗       ███████║██║
 ██║     ██╔══╝       ██╔══██║██║
 ╚██████╗██║          ██║  ██║██║
  ╚═════╝╚═╝          ╚═╝  ╚═╝╚═╝
  CF_AI Full Setup — Kali Linux
BANNER
echo -e "${NC}"

# ── 1. Fix Chrome repo key issue before update ────────────────────────────
section "Fixing APT Sources"
# Remove broken Google Chrome apt source if present (we install via .deb directly)
rm -f /etc/apt/sources.list.d/google-chrome.list 2>/dev/null || true
rm -f /etc/apt/sources.list.d/google.list 2>/dev/null || true

apt-get update -y 2>/dev/null || true
apt-get upgrade -y 2>/dev/null || true
success "System updated"

# ── 2. Core Dependencies ─────────────────────────────────────────────────
section "Core Dependencies"

# libgconf-2-4 was removed from Kali — skip it
# libatk-bridge2.0-0 → libatk-bridge2.0-0t64 on newer Kali (apt handles alias)
apt-get install -y \
    python3 python3-pip python3-dev python3-venv \
    build-essential libssl-dev libffi-dev \
    curl wget git unzip ca-certificates lsb-release \
    ruby ruby-dev \
    golang-go \
    default-jdk \
    libpcap-dev \
    xvfb libxi6 libnss3-dev libxss1 \
    libdrm2 libnspr4 \
    libx11-xcb1 libxcomposite1 libxcursor1 libxdamage1 \
    libxrandr2 libgbm1 fonts-liberation \
    net-tools dnsutils whois 2>/dev/null || true

# Install optional packages one by one (some may not exist on all Kali versions)
for pkg in httpie libpq-dev libatk-bridge2.0-0 libatk-bridge2.0-0t64 libgtk-3-0 libgtk-3-0t64; do
    apt-get install -y "$pkg" 2>/dev/null || true
done

success "Core dependencies installed"

# ── 3. Networking Tools ───────────────────────────────────────────────────
section "Networking Tools (nmap, rustscan, masscan, autorecon, amass)"

apt-get install -y nmap masscan amass 2>/dev/null || true
success "nmap, masscan, amass installed"

# RustScan — download .deb directly from GitHub releases
if ! command -v rustscan &>/dev/null; then
    info "Installing RustScan..."
    RUSTSCAN_URL=$(curl -s https://api.github.com/repos/RustScan/RustScan/releases/latest \
        | grep "browser_download_url.*amd64.deb" | cut -d '"' -f 4 | head -1)
    if [ -n "$RUSTSCAN_URL" ]; then
        wget -q "$RUSTSCAN_URL" -O /tmp/rustscan.deb && \
        dpkg -i /tmp/rustscan.deb 2>/dev/null || apt-get -f install -y 2>/dev/null || true
        rm -f /tmp/rustscan.deb
        command -v rustscan &>/dev/null && success "RustScan installed" || warn "RustScan install failed"
    else
        warn "Could not find RustScan release URL — install manually: https://github.com/RustScan/RustScan/releases"
    fi
else
    success "RustScan already installed"
fi

# AutoRecon
if ! command -v autorecon &>/dev/null; then
    info "Installing AutoRecon..."
    pip3 install autorecon 2>/dev/null || \
    pip3 install git+https://github.com/Tib3rius/AutoRecon.git 2>/dev/null || \
    warn "AutoRecon install failed — run: pip3 install autorecon"
fi

# ── 4. Web Application Tools ──────────────────────────────────────────────
section "Web Application Tools (gobuster, feroxbuster, ffuf, nuclei, sqlmap)"

apt-get install -y gobuster dirb nikto sqlmap dirsearch wpscan 2>/dev/null || true

# Install Go-based tools
export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin

for tool_pkg in \
    "github.com/ffuf/ffuf/v2@latest" \
    "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest" \
    "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest" \
    "github.com/projectdiscovery/httpx/cmd/httpx@latest" \
    "github.com/hahwul/dalfox/v2@latest" \
    "github.com/projectdiscovery/katana/cmd/katana@latest" \
    "github.com/hakluke/hakrawler@latest" \
    "github.com/lc/gau/v2/cmd/gau@latest"
do
    tool_name=$(basename "${tool_pkg%%@*}")
    if ! command -v "$tool_name" &>/dev/null; then
        info "Installing $tool_name..."
        go install -v "$tool_pkg" 2>/dev/null && success "$tool_name installed" || warn "$tool_name install failed"
    else
        success "$tool_name already installed"
    fi
done

# Update nuclei templates
nuclei -update-templates 2>/dev/null || true

# Feroxbuster
if ! command -v feroxbuster &>/dev/null; then
    info "Installing Feroxbuster..."
    apt-get install -y feroxbuster 2>/dev/null || \
    curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/main/install-nix.sh \
        | bash 2>/dev/null || warn "Feroxbuster install failed"
fi

success "Web application tools done"

# ── 5. Binary Analysis Tools ──────────────────────────────────────────────
section "Binary Analysis Tools (ghidra, pwntools, angr, gdb, radare2)"

apt-get install -y gdb radare2 binwalk ltrace strace file 2>/dev/null || true

# GDB PEDA
if [ ! -d "$HOME/.gdb-peda" ]; then
    git clone --depth=1 https://github.com/longld/peda.git "$HOME/.gdb-peda" 2>/dev/null || true
    echo "source $HOME/.gdb-peda/peda.py" >> "$HOME/.gdbinit" 2>/dev/null || true
fi

# Ghidra
if ! command -v ghidra &>/dev/null; then
    info "Installing Ghidra..."
    GHIDRA_JSON=$(curl -s https://api.github.com/repos/NationalSecurityAgency/ghidra/releases/latest)
    GHIDRA_URL=$(echo "$GHIDRA_JSON" | grep "browser_download_url.*zip" | cut -d '"' -f 4 | head -1)
    if [ -n "$GHIDRA_URL" ]; then
        wget -q "$GHIDRA_URL" -O /tmp/ghidra.zip && \
        unzip -q /tmp/ghidra.zip -d /opt/ && \
        GHIDRA_DIR=$(ls -d /opt/ghidra_* 2>/dev/null | head -1) && \
        ln -sf "$GHIDRA_DIR/ghidraRun" /usr/local/bin/ghidra && \
        rm -f /tmp/ghidra.zip
        success "Ghidra installed at $GHIDRA_DIR"
    else
        warn "Ghidra download failed — install manually from https://ghidra-sre.org"
    fi
else
    success "Ghidra already installed"
fi

# Python binary tools
pip3 install ropgadget pwntools 2>/dev/null || warn "pwntools/ropgadget install failed"
gem install one_gadget --no-document 2>/dev/null || true
apt-get install -y checksec 2>/dev/null || pip3 install checksec 2>/dev/null || true

# Angr (large package — may take several minutes)
info "Installing angr (this may take a few minutes)..."
pip3 install angr 2>/dev/null || warn "angr install failed — run: pip3 install angr"

success "Binary analysis tools done"

# ── 6. Cloud Security Tools ───────────────────────────────────────────────
section "Cloud Security Tools (prowler, scout-suite, trivy, kube-hunter, kube-bench)"

# Prowler
pip3 install prowler 2>/dev/null || warn "prowler install failed"

# Scout Suite
pip3 install scoutsuite 2>/dev/null || warn "scoutsuite install failed"

# Trivy
if ! command -v trivy &>/dev/null; then
    info "Installing Trivy..."
    TRIVY_URL=$(curl -s https://api.github.com/repos/aquasecurity/trivy/releases/latest \
        | grep "browser_download_url.*Linux-64bit.deb" | cut -d '"' -f 4 | head -1)
    if [ -n "$TRIVY_URL" ]; then
        wget -q "$TRIVY_URL" -O /tmp/trivy.deb && \
        dpkg -i /tmp/trivy.deb 2>/dev/null && rm -f /tmp/trivy.deb
        success "Trivy installed"
    else
        warn "Trivy .deb not found — trying apt..."
        apt-get install -y trivy 2>/dev/null || warn "Trivy install failed"
    fi
fi

# Kube-hunter
pip3 install kube-hunter 2>/dev/null || warn "kube-hunter install failed"

# Kube-bench
if ! command -v kube-bench &>/dev/null; then
    info "Installing kube-bench..."
    KBENCH_URL=$(curl -s https://api.github.com/repos/aquasecurity/kube-bench/releases/latest \
        | grep "browser_download_url.*linux_amd64.tar.gz" | cut -d '"' -f 4 | head -1)
    if [ -n "$KBENCH_URL" ]; then
        wget -q "$KBENCH_URL" -O /tmp/kube-bench.tar.gz && \
        tar -xzf /tmp/kube-bench.tar.gz -C /usr/local/bin/ kube-bench 2>/dev/null && \
        rm -f /tmp/kube-bench.tar.gz
        success "kube-bench installed"
    else
        warn "kube-bench download failed"
    fi
fi

pip3 install checkov 2>/dev/null || warn "checkov install failed"

success "Cloud security tools done"

# ── 7. OSINT & Bug Bounty ─────────────────────────────────────────────────
section "OSINT & Bug Bounty (sherlock, recon-ng, spiderfoot)"

apt-get install -y theharvester dnsenum recon-ng 2>/dev/null || true

# Sherlock
if ! command -v sherlock &>/dev/null; then
    pip3 install sherlock-project 2>/dev/null || \
    (git clone --depth=1 https://github.com/sherlock-project/sherlock.git /opt/sherlock 2>/dev/null && \
     ln -sf /opt/sherlock/sherlock/sherlock.py /usr/local/bin/sherlock && \
     chmod +x /usr/local/bin/sherlock && \
     pip3 install -r /opt/sherlock/requirements.txt 2>/dev/null) || \
    warn "Sherlock install failed"
fi

# SpiderFoot
if ! command -v spiderfoot &>/dev/null; then
    apt-get install -y spiderfoot 2>/dev/null || \
    (git clone --depth=1 https://github.com/smicallef/spiderfoot.git /opt/spiderfoot 2>/dev/null && \
     pip3 install -r /opt/spiderfoot/requirements.txt 2>/dev/null && \
     ln -sf /opt/spiderfoot/sf.py /usr/local/bin/spiderfoot && \
     chmod +x /usr/local/bin/spiderfoot) || \
    warn "SpiderFoot install failed"
fi

pip3 install wafw00f arjun shodan censys 2>/dev/null || warn "Some OSINT Python tools failed"

success "OSINT & Bug Bounty tools done"

# ── 8. Password & Exploitation Tools ─────────────────────────────────────
section "Password & Exploitation Tools"

apt-get install -y \
    hydra john hashcat \
    metasploit-framework \
    enum4linux enum4linux-ng \
    smbmap nbtscan arp-scan \
    responder evil-winrm \
    steghide foremost \
    testdisk sleuthkit \
    wireshark tcpdump aircrack-ng 2>/dev/null || true

# rpcclient is part of samba-common-bin
apt-get install -y samba-common-bin 2>/dev/null || true

# exiftool
apt-get install -y exiftool 2>/dev/null || apt-get install -y libimage-exiftool-perl 2>/dev/null || true

# volatility3
pip3 install volatility3 2>/dev/null || apt-get install -y volatility3 2>/dev/null || true

success "Password & exploitation tools done"

# ── 9. Google Chrome (browser agent) ─────────────────────────────────────
section "Google Chrome (browser agent for Selenium)"

if ! command -v google-chrome &>/dev/null && ! command -v google-chrome-stable &>/dev/null; then
    info "Downloading Google Chrome .deb directly (no apt repo needed)..."
    wget -q "https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb" \
        -O /tmp/chrome.deb && \
    dpkg -i /tmp/chrome.deb 2>/dev/null || apt-get -f install -y 2>/dev/null || true
    rm -f /tmp/chrome.deb
    command -v google-chrome-stable &>/dev/null && \
        success "Google Chrome installed" || warn "Chrome install failed"
else
    success "Google Chrome already installed"
fi

# ChromeDriver via Python auto-installer
pip3 install chromedriver-autoinstaller 2>/dev/null || true
python3 -c "import chromedriver_autoinstaller; chromedriver_autoinstaller.install()" 2>/dev/null || true

# ── 10. Python Packages ───────────────────────────────────────────────────
section "Python Packages"

pip3 install --upgrade pip 2>/dev/null || true
pip3 install -r requirements.txt 2>/dev/null || warn "Some requirements.txt packages failed"

pip3 install \
    fastmcp \
    mcp \
    python-dotenv \
    requests beautifulsoup4 aiohttp \
    rich colorama tabulate \
    chromedriver-autoinstaller 2>/dev/null || warn "Some Python packages failed"

success "Python packages installed"

# ── 11. Go PATH setup ─────────────────────────────────────────────────────
section "Go PATH Setup"

for rcfile in "$HOME/.bashrc" "$HOME/.zshrc"; do
    if [ -f "$rcfile" ] && ! grep -q 'go/bin' "$rcfile"; then
        echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> "$rcfile"
        info "Added Go PATH to $rcfile"
    fi
done
export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin

# ── 12. Directories & Environment ────────────────────────────────────────
section "Environment Setup"

mkdir -p logs cache temp wordlists

if [ ! -f .env ]; then
    cp .env.example .env
    warn "Created .env from template — edit it to add your API keys:"
    warn "  nano .env"
fi

chmod +x run.sh setup.sh cfai_server.py 2>/dev/null || true

# ── 13. Systemd Service ────────────────────────────────────────────────────
section "Systemd Service Setup"

if [ -f cfai.service ]; then
    cp cfai.service /etc/systemd/system/cfai.service
    systemctl daemon-reload
    systemctl enable cfai
    success "cfai systemd service installed and enabled"
    info "Start with: systemctl start cfai"
else
    warn "cfai.service not found — skipping systemd setup"
fi

# ── Done ──────────────────────────────────────────────────────────────────
echo ""
echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}  CF_AI Setup Complete!${NC}"
echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "${CYAN}Next steps:${NC}"
echo ""
echo "  1. Add your API keys:"
echo "       nano .env"
echo ""
echo "  2. Start the server:"
echo "       systemctl start cfai"
echo "       # OR for manual test:"
echo "       python3 cfai_server.py"
echo ""
echo "  3. Open the dashboard:"
echo "       http://$(hostname -I | awk '{print $1}'):8888"
echo ""
echo -e "${YELLOW}Optional API keys (add to .env):${NC}"
echo "  SHODAN_API_KEY     → https://account.shodan.io"
echo "  HACKERONE_USERNAME → your HackerOne username"
echo "  HACKERONE_API_KEY  → https://hackerone.com/settings/api_token/edit"
echo "  CENSYS_API_ID      → https://search.censys.io/account"
echo "  VIRUSTOTAL_API_KEY → https://www.virustotal.com/gui/my-apikey"
echo ""
echo -e "${GREEN}Run: source ~/.bashrc   (to reload PATH for Go tools)${NC}"
echo ""
