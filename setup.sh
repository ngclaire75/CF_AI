#!/bin/bash
# CF_AI Full Setup Script for Kali Linux
# Installs all tools listed in the AI Automation for Attack and Reconnaissance Platform

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

info()    { echo -e "${CYAN}[INFO]${NC} $1"; }
success() { echo -e "${GREEN}[OK]${NC} $1"; }
warn()    { echo -e "${YELLOW}[WARN]${NC} $1"; }
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

# ── 1. System Update ──────────────────────────────────────────────────────
section "System Update"
sudo apt-get update -y && sudo apt-get upgrade -y
success "System updated"

# ── 2. Core Dependencies ─────────────────────────────────────────────────
section "Core Dependencies"
sudo apt-get install -y \
    python3 python3-pip python3-dev python3-venv \
    build-essential libssl-dev libffi-dev \
    curl wget git unzip ca-certificates lsb-release \
    ruby ruby-dev \
    golang-go \
    default-jdk \
    libpcap-dev libpq-dev \
    xvfb libxi6 libgconf-2-4 libnss3-dev libxss1 \
    libatk-bridge2.0-0 libdrm2 libgtk-3-0 libnspr4 \
    libx11-xcb1 libxcomposite1 libxcursor1 libxdamage1 \
    libxrandr2 libgbm1 fonts-liberation \
    httpie net-tools dnsutils whois
success "Core dependencies installed"

# ── 3. Networking Tools ───────────────────────────────────────────────────
section "Networking Tools (nmap, rustscan, masscan, autorecon, amass)"

sudo apt-get install -y nmap masscan amass
success "nmap, masscan, amass installed"

# RustScan
if ! command -v rustscan &>/dev/null; then
    info "Installing RustScan..."
    curl -s https://api.github.com/repos/RustScan/RustScan/releases/latest \
        | grep "browser_download_url.*amd64.deb" \
        | cut -d '"' -f 4 \
        | wget -qi - -O /tmp/rustscan.deb 2>/dev/null && \
    sudo dpkg -i /tmp/rustscan.deb || true
    rm -f /tmp/rustscan.deb
    success "RustScan installed"
else
    success "RustScan already installed"
fi

# AutoRecon
if ! command -v autorecon &>/dev/null; then
    info "Installing AutoRecon..."
    pip3 install --user autorecon 2>/dev/null || \
    pip3 install git+https://github.com/Tib3rius/AutoRecon.git 2>/dev/null || \
    warn "AutoRecon install failed — install manually: pip3 install autorecon"
    success "AutoRecon installed"
fi

# ── 4. Web Application Tools ──────────────────────────────────────────────
section "Web Application Tools (gobuster, feroxbuster, ffuf, nuclei, sqlmap)"

sudo apt-get install -y gobuster dirb nikto sqlmap dirsearch wpscan

# Feroxbuster
if ! command -v feroxbuster &>/dev/null; then
    info "Installing Feroxbuster..."
    curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/main/install-nix.sh | bash 2>/dev/null || \
    warn "Feroxbuster install failed — install manually"
fi

# FFUF via Go
if ! command -v ffuf &>/dev/null; then
    info "Installing ffuf..."
    go install github.com/ffuf/ffuf/v2@latest 2>/dev/null || sudo apt-get install -y ffuf
fi

# Nuclei via Go
if ! command -v nuclei &>/dev/null; then
    info "Installing Nuclei..."
    go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest 2>/dev/null || sudo apt-get install -y nuclei
fi
nuclei -update-templates 2>/dev/null || true

# Subfinder
if ! command -v subfinder &>/dev/null; then
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest 2>/dev/null || sudo apt-get install -y subfinder
fi

# HTTPx
if ! command -v httpx &>/dev/null; then
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest 2>/dev/null
fi

# Dalfox (XSS)
if ! command -v dalfox &>/dev/null; then
    go install github.com/hahwul/dalfox/v2@latest 2>/dev/null
fi

# Katana (web crawler)
if ! command -v katana &>/dev/null; then
    go install github.com/projectdiscovery/katana/cmd/katana@latest 2>/dev/null
fi

# Hakrawler
if ! command -v hakrawler &>/dev/null; then
    go install github.com/hakluke/hakrawler@latest 2>/dev/null
fi

# GAU (get all URLs)
if ! command -v gau &>/dev/null; then
    go install github.com/lc/gau/v2/cmd/gau@latest 2>/dev/null
fi

success "Web application tools installed"

# ── 5. Binary Analysis Tools ──────────────────────────────────────────────
section "Binary Analysis Tools (ghidra, pwntools, angr, gdb, radare2)"

sudo apt-get install -y gdb radare2 binwalk ltrace strace file

# GDB PEDA/PWNDBG
if [ ! -d ~/.gdb-peda ]; then
    info "Installing GDB PEDA..."
    git clone https://github.com/longld/peda.git ~/.gdb-peda 2>/dev/null || true
    echo "source ~/.gdb-peda/peda.py" >> ~/.gdbinit 2>/dev/null || true
fi

# Ghidra
if ! command -v ghidra &>/dev/null; then
    info "Installing Ghidra..."
    GHIDRA_VER="11.1.2"
    GHIDRA_DATE="20240709"
    GHIDRA_URL="https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_${GHIDRA_VER}_build/ghidra_${GHIDRA_VER}_PUBLIC_${GHIDRA_DATE}.zip"
    wget -q "$GHIDRA_URL" -O /tmp/ghidra.zip 2>/dev/null && \
    sudo unzip -q /tmp/ghidra.zip -d /opt/ && \
    sudo ln -sf /opt/ghidra_${GHIDRA_VER}_PUBLIC/ghidraRun /usr/local/bin/ghidra && \
    rm -f /tmp/ghidra.zip
    success "Ghidra installed at /opt/ghidra_${GHIDRA_VER}_PUBLIC"
else
    success "Ghidra already installed"
fi

# ROPgadget, one_gadget, checksec
pip3 install ropgadget 2>/dev/null || true
gem install one_gadget --no-document 2>/dev/null || true
sudo apt-get install -y checksec 2>/dev/null || pip3 install checksec 2>/dev/null || true

# Pwntools (Python)
pip3 install pwntools 2>/dev/null || warn "pwntools install failed"

# Angr (Python)
pip3 install angr 2>/dev/null || warn "angr install failed (may take several minutes)"

success "Binary analysis tools installed"

# ── 6. Cloud Security Tools ───────────────────────────────────────────────
section "Cloud Security Tools (prowler, scout-suite, trivy, kube-hunter, kube-bench)"

# Prowler (AWS/Azure/GCP)
if ! command -v prowler &>/dev/null; then
    info "Installing Prowler..."
    pip3 install prowler 2>/dev/null || warn "Prowler install failed"
fi

# Scout Suite
if ! command -v scout &>/dev/null; then
    info "Installing Scout Suite..."
    pip3 install scoutsuite 2>/dev/null || warn "ScoutSuite install failed"
fi

# Trivy (container vulnerability scanning)
if ! command -v trivy &>/dev/null; then
    info "Installing Trivy..."
    wget -qO- https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo gpg --dearmor -o /usr/share/keyrings/trivy.gpg 2>/dev/null
    echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -cs) main" | \
        sudo tee /etc/apt/sources.list.d/trivy.list > /dev/null 2>&1
    sudo apt-get update -y && sudo apt-get install -y trivy 2>/dev/null || \
    warn "Trivy install failed — try: curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin"
fi

# Kube-hunter (Kubernetes pentest)
if ! command -v kube-hunter &>/dev/null; then
    info "Installing kube-hunter..."
    pip3 install kube-hunter 2>/dev/null || warn "kube-hunter install failed"
fi

# Kube-bench (CIS Kubernetes assessment)
if ! command -v kube-bench &>/dev/null; then
    info "Installing kube-bench..."
    KBENCH_VER=$(curl -s https://api.github.com/repos/aquasecurity/kube-bench/releases/latest | grep '"tag_name"' | cut -d '"' -f4)
    wget -q "https://github.com/aquasecurity/kube-bench/releases/download/${KBENCH_VER}/kube-bench_${KBENCH_VER#v}_linux_amd64.tar.gz" \
        -O /tmp/kube-bench.tar.gz 2>/dev/null && \
    sudo tar -xzf /tmp/kube-bench.tar.gz -C /usr/local/bin/ kube-bench && \
    rm -f /tmp/kube-bench.tar.gz
    success "kube-bench installed"
fi

# Checkov (Infrastructure as Code)
pip3 install checkov 2>/dev/null || warn "checkov install failed"

# Terrascan
pip3 install terrascan 2>/dev/null || warn "terrascan install failed"

success "Cloud security tools installed"

# ── 7. OSINT & Bug Bounty Tools ───────────────────────────────────────────
section "OSINT & Bug Bounty (sherlock, recon-ng, spiderfoot)"

# Sherlock (username searching)
if ! command -v sherlock &>/dev/null; then
    info "Installing Sherlock..."
    pip3 install sherlock-project 2>/dev/null || \
    (git clone https://github.com/sherlock-project/sherlock.git /opt/sherlock 2>/dev/null && \
     sudo ln -sf /opt/sherlock/sherlock/sherlock.py /usr/local/bin/sherlock && \
     chmod +x /usr/local/bin/sherlock) || warn "Sherlock install failed"
fi

# Recon-ng (web reconnaissance framework)
if ! command -v recon-ng &>/dev/null; then
    info "Installing Recon-ng..."
    sudo apt-get install -y recon-ng 2>/dev/null || \
    (pip3 install recon-ng 2>/dev/null) || warn "Recon-ng install failed"
fi

# SpiderFoot (OSINT automation)
if ! command -v spiderfoot &>/dev/null; then
    info "Installing SpiderFoot..."
    sudo apt-get install -y spiderfoot 2>/dev/null || \
    (git clone https://github.com/smicallef/spiderfoot.git /opt/spiderfoot 2>/dev/null && \
     pip3 install -r /opt/spiderfoot/requirements.txt 2>/dev/null && \
     sudo ln -sf /opt/spiderfoot/sf.py /usr/local/bin/spiderfoot) || \
    warn "SpiderFoot install failed"
fi

# TheHarvester
sudo apt-get install -y theharvester 2>/dev/null || pip3 install theHarvester 2>/dev/null || true

# DNSenum
sudo apt-get install -y dnsenum 2>/dev/null || true

# Amass (already installed above)
# Wafw00f (WAF detection)
pip3 install wafw00f 2>/dev/null || true

# Arjun (parameter discovery)
pip3 install arjun 2>/dev/null || true

# Shodan CLI
pip3 install shodan 2>/dev/null || true

# Censys CLI
pip3 install censys 2>/dev/null || true

success "OSINT & Bug Bounty tools installed"

# ── 8. Password & Exploitation Tools ─────────────────────────────────────
section "Password & Exploitation Tools"

sudo apt-get install -y \
    hydra john hashcat \
    metasploit-framework \
    enum4linux enum4linux-ng \
    rpcclient smbmap nbtscan arp-scan \
    responder evil-winrm \
    steghide foremost exiftool \
    volatility3 testdisk sleuthkit \
    wireshark tcpdump aircrack-ng

success "Password & exploitation tools installed"

# ── 9. Python Packages ────────────────────────────────────────────────────
section "Python Packages"

pip3 install -r requirements.txt
pip3 install \
    shodan \
    censys \
    wafw00f \
    arjun \
    pwntools \
    fastmcp \
    mcp \
    chromedriver-autoinstaller \
    requests beautifulsoup4 aiohttp \
    anthropic \
    python-dotenv 2>/dev/null || warn "Some Python packages failed — check manually"

success "Python packages installed"

# ── 10. FastMCP / MCP Framework ───────────────────────────────────────────
section "FastMCP Framework (for Claude Desktop integration)"

pip3 install fastmcp mcp 2>/dev/null || warn "FastMCP install failed"
success "FastMCP installed"

# ── 11. Google Chrome + ChromeDriver ──────────────────────────────────────
section "Google Chrome (browser agent)"

if ! command -v google-chrome &>/dev/null; then
    info "Installing Google Chrome..."
    wget -q https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb -O /tmp/chrome.deb
    sudo apt-get install -y /tmp/chrome.deb || sudo apt-get -f install -y
    rm -f /tmp/chrome.deb
fi

# ChromeDriver via python (auto-matches Chrome version)
pip3 install chromedriver-autoinstaller 2>/dev/null || true
python3 -c "import chromedriver_autoinstaller; chromedriver_autoinstaller.install()" 2>/dev/null || true

success "Google Chrome installed"

# ── 12. Environment Setup ─────────────────────────────────────────────────
section "Environment Setup"

mkdir -p logs cache temp wordlists

# Set up .env
if [ ! -f .env ]; then
    cp .env.example .env
    info ".env file created from .env.example"
    warn "Edit .env and add your API keys (Shodan, HackerOne, Censys, VirusTotal)"
fi

chmod +x run.sh setup.sh cfai_server.py cfai_mcp.py 2>/dev/null || true

# ── 13. Go PATH ───────────────────────────────────────────────────────────
section "Go PATH Setup"

if ! grep -q 'go/bin' ~/.bashrc; then
    echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> ~/.bashrc
    info "Added Go to PATH in ~/.bashrc"
fi
if ! grep -q 'go/bin' ~/.zshrc 2>/dev/null; then
    echo 'export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin' >> ~/.zshrc 2>/dev/null || true
fi
export PATH=$PATH:/usr/local/go/bin:$HOME/go/bin

# ── 14. Nuclei Templates ──────────────────────────────────────────────────
section "Nuclei Templates Update"
nuclei -update-templates 2>/dev/null || true
success "Nuclei templates updated"

# ── Done ──────────────────────────────────────────────────────────────────
echo ""
echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo -e "${GREEN}  CF_AI Setup Complete!${NC}"
echo -e "${RED}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
echo ""
echo -e "${CYAN}Next steps:${NC}"
echo "  1. Edit .env and add your API keys:"
echo "       nano .env"
echo ""
echo "  2. Start the server:"
echo "       ./run.sh"
echo "     OR for production:"
echo "       sudo systemctl start cfai"
echo ""
echo "  3. Open dashboard:"
echo "       http://localhost:8888"
echo ""
echo -e "${YELLOW}API Keys needed (see .env):${NC}"
echo "  • SHODAN_API_KEY     — https://account.shodan.io"
echo "  • HACKERONE_API_KEY  — https://hackerone.com/settings/api_token/edit"
echo "  • HACKERONE_USERNAME — your HackerOne username"
echo "  • CENSYS_API_ID      — https://search.censys.io/account"
echo "  • VIRUSTOTAL_API_KEY — https://www.virustotal.com/gui/my-apikey"
echo "  • ANTHROPIC_API_KEY  — https://console.anthropic.com/api-keys"
echo ""
echo -e "${GREEN}Run: source ~/.bashrc  (to reload PATH)${NC}"
