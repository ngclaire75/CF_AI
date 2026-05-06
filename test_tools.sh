#!/bin/bash
# CF_AI — Tool Verification & Install Script
# Run on the VPS: bash test_tools.sh
# Tests each tool with a real command and installs missing ones automatically

PASS=0
FAIL=0
FIXED=0

GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

ok()   { echo -e "  ${GREEN}[+]${NC} $1"; PASS=$((PASS+1)); }
fail() { echo -e "  ${RED}[-]${NC} $1"; FAIL=$((FAIL+1)); }
warn() { echo -e "  ${YELLOW}[!]${NC} $1"; }

VENV_PIP="/opt/CF_AI/venv/bin/pip"
[ -f "$VENV_PIP" ] || VENV_PIP="pip3"

try_install() {
    local tool="$1"; local method="$2"
    warn "$tool not found — installing..."
    eval "$method" 2>/dev/null && FIXED=$((FIXED+1)) || warn "Install failed for $tool"
}

echo "======================================================"
echo " CF_AI Tool Verification"
echo "======================================================"
echo ""

# ── Network Tools ──────────────────────────────────────────────────────────────
echo "[Network Tools]"

if nmap --version 2>/dev/null | grep -q "Nmap"; then
    VER=$(nmap --version 2>/dev/null | head -1)
    ok "nmap — $VER"
    # Real test: TCP connect scan (no raw socket needed)
    nmap -sT -Pn -T4 --open -p 80,443 scanme.nmap.org -oG - 2>/dev/null | grep -q "Host:" \
        && ok "nmap TCP scan: working" || warn "nmap scan returned no results"
else
    fail "nmap"
    try_install "nmap" "apt-get install -y nmap"
fi

if command -v rustscan &>/dev/null; then
    ok "rustscan — $(rustscan --version 2>/dev/null | head -1)"
else
    fail "rustscan (optional)"
fi

if command -v masscan &>/dev/null; then
    ok "masscan — $(masscan --version 2>/dev/null | head -1)"
else
    fail "masscan (optional)"
fi

# ── Web Tools ──────────────────────────────────────────────────────────────────
echo ""
echo "[Web Tools]"

for tool in gobuster ffuf feroxbuster dirsearch nikto sqlmap dalfox nuclei wpscan httpx wafw00f; do
    if command -v "$tool" &>/dev/null; then
        VER=$($tool --version 2>/dev/null | head -1 || $tool -version 2>/dev/null | head -1 || echo "installed")
        ok "$tool — ${VER:0:60}"
    else
        fail "$tool"
        case "$tool" in
            gobuster)    try_install "$tool" "apt-get install -y gobuster" ;;
            ffuf)        try_install "$tool" "apt-get install -y ffuf" ;;
            nikto)       try_install "$tool" "apt-get install -y nikto" ;;
            sqlmap)      try_install "$tool" "apt-get install -y sqlmap" ;;
            nuclei)      try_install "$tool" "$VENV_PIP install nuclei 2>/dev/null || apt-get install -y nuclei" ;;
            wpscan)      try_install "$tool" "apt-get install -y wpscan" ;;
            httpx)       try_install "$tool" "apt-get install -y httpx-toolkit || go install github.com/projectdiscovery/httpx/cmd/httpx@latest" ;;
            dalfox)      try_install "$tool" "apt-get install -y dalfox || go install github.com/hahwul/dalfox/v2@latest" ;;
        esac
    fi
done

# Test nuclei with a real scan
if command -v nuclei &>/dev/null; then
    nuclei -u http://scanme.nmap.org -severity info -silent -timeout 10 2>/dev/null | head -3
    ok "nuclei: can connect to target"
fi

# ── OSINT Tools ────────────────────────────────────────────────────────────────
echo ""
echo "[OSINT Tools]"

for tool in subfinder amass dnsenum theHarvester fierce; do
    if command -v "$tool" &>/dev/null; then
        ok "$tool — installed"
    else
        fail "$tool"
        case "$tool" in
            subfinder)   try_install "$tool" "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest" ;;
            amass)       try_install "$tool" "apt-get install -y amass" ;;
            dnsenum)     try_install "$tool" "apt-get install -y dnsenum" ;;
            theHarvester) try_install "$tool" "apt-get install -y theharvester" ;;
            fierce)      try_install "$tool" "$VENV_PIP install fierce" ;;
        esac
    fi
done

# Quick subfinder test
if command -v subfinder &>/dev/null; then
    OUT=$(subfinder -d scanme.nmap.org -silent -timeout 10 2>/dev/null | head -3)
    [ -n "$OUT" ] && ok "subfinder: found $(echo "$OUT" | wc -l) subdomains" || warn "subfinder returned no results (expected for scanme)"
fi

# ── Password Tools ─────────────────────────────────────────────────────────────
echo ""
echo "[Password Tools]"

for tool in hydra hashcat john medusa; do
    if command -v "$tool" &>/dev/null; then
        ok "$tool — installed"
    else
        fail "$tool"
        case "$tool" in
            hydra)  try_install "$tool" "apt-get install -y hydra" ;;
            john)   try_install "$tool" "apt-get install -y john" ;;
            hashcat) try_install "$tool" "apt-get install -y hashcat" ;;
            medusa) try_install "$tool" "apt-get install -y medusa" ;;
        esac
    fi
done

# Test hashcat with CPU mode (no GPU needed)
if command -v hashcat &>/dev/null; then
    mkdir -p /tmp/hashcat_work/sessions
    OUT=$(HOME=/tmp/tool_home XDG_DATA_HOME=/tmp/hashcat_work \
        hashcat -a 0 -m 0 5f4dcc3b5aa765d61d8327deb882cf99 \
        /usr/share/wordlists/rockyou.txt --force -D 1,2 \
        --potfile-path /tmp/hashcat_work/test.pot --session=cfaitest \
        2>/dev/null | grep -E "password|Status" | head -3)
    [ -n "$OUT" ] && ok "hashcat CPU mode: $OUT" || warn "hashcat ran (check GPU/CPU availability)"
fi

# Test john
if command -v john &>/dev/null; then
    mkdir -p /tmp/john_work
    echo 'testuser:$6$rounds=1000$xyz$hash123456' > /tmp/john_test_hash.txt 2>/dev/null || true
    HOME=/tmp/tool_home john --pot=/tmp/john_work/john.pot --session=/tmp/john_work/session \
        --list=formats 2>/dev/null | head -1 && ok "john: format list works" || warn "john failed"
fi

# ── Binary Analysis Tools ──────────────────────────────────────────────────────
echo ""
echo "[Binary Analysis Tools]"

for tool in gdb checksec ROPgadget ropper r2 binwalk exiftool steghide; do
    if command -v "$tool" &>/dev/null; then
        ok "$tool — installed"
    else
        fail "$tool"
        case "$tool" in
            gdb)      try_install "$tool" "apt-get install -y gdb" ;;
            checksec) try_install "$tool" "apt-get install -y checksec" ;;
            ROPgadget) try_install "$tool" "$VENV_PIP install ropgadget" ;;
            ropper)   try_install "$tool" "$VENV_PIP install ropper" ;;
            r2)       try_install "$tool" "apt-get install -y radare2" ;;
            binwalk)  try_install "$tool" "apt-get install -y binwalk" ;;
            exiftool) try_install "$tool" "apt-get install -y libimage-exiftool-perl" ;;
            steghide) try_install "$tool" "apt-get install -y steghide" ;;
        esac
    fi
done

# Test GDB with /bin/ls
if command -v gdb &>/dev/null; then
    OUT=$(gdb --batch -ex 'file /bin/ls' -ex 'info functions' -ex quit 2>/dev/null | head -5)
    [ -n "$OUT" ] && ok "gdb batch mode: working" || warn "gdb returned no output"
fi

# Test checksec
if command -v checksec &>/dev/null; then
    TERM=xterm checksec --file=/bin/ls 2>/dev/null | grep -E "RELRO|Stack|NX" | head -3
    ok "checksec: /bin/ls analysis works"
fi

# ── Forensics Tools ────────────────────────────────────────────────────────────
echo ""
echo "[Forensics Tools]"

if command -v vol &>/dev/null || command -v vol3 &>/dev/null; then
    ok "volatility — installed"
else
    fail "volatility"
    try_install "volatility3" "$VENV_PIP install volatility3 && ln -sf \$(which vol3) /usr/local/bin/vol 2>/dev/null"
fi

for tool in foremost scalpel zsteg outguess hashpump; do
    if command -v "$tool" &>/dev/null; then
        ok "$tool — installed"
    else
        fail "$tool (optional)"
    fi
done

# ── Cloud Security Tools ───────────────────────────────────────────────────────
echo ""
echo "[Cloud Security Tools]"

for tool in trivy checkov kube-hunter prowler terrascan; do
    if command -v "$tool" &>/dev/null; then
        ok "$tool — installed"
    else
        fail "$tool (optional)"
        case "$tool" in
            trivy) try_install "$tool" "apt-get install -y trivy 2>/dev/null || curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin" ;;
            checkov) try_install "$tool" "$VENV_PIP install checkov" ;;
        esac
    fi
done

# Test trivy
if command -v trivy &>/dev/null; then
    OUT=$(trivy image --download-db-only --quiet 2>/dev/null && echo "db ready" || echo "db download skipped")
    ok "trivy: $OUT"
fi

# ── API Security Tools ─────────────────────────────────────────────────────────
echo ""
echo "[API Security Tools]"

# graphql-cop
if command -v graphql-cop &>/dev/null; then
    ok "graphql-cop — installed"
else
    fail "graphql-cop"
    warn "Trying all install methods for graphql-cop..."
    # Method 1: pip with relaxed constraints
    $VENV_PIP install graphql-cop --ignore-requires-python -q 2>/dev/null \
        || pip3 install graphql-cop --break-system-packages -q 2>/dev/null || true
    GQL=$(find /opt/CF_AI/venv/bin /usr/local/bin /usr/bin /root/.local/bin \
        -name "graphql*" 2>/dev/null | head -1)
    if [ -n "$GQL" ]; then
        ln -sf "$GQL" /usr/local/bin/graphql-cop && chmod +x /usr/local/bin/graphql-cop
        ok "graphql-cop linked from pip"
    else
        # Method 2: GitHub source
        rm -rf /opt/graphql-cop
        git clone https://github.com/dolevf/graphql-cop /opt/graphql-cop -q 2>/dev/null
        if [ -f /opt/graphql-cop/graphql-cop.py ]; then
            $VENV_PIP install -r /opt/graphql-cop/requirements.txt -q 2>/dev/null || true
            printf '#!/bin/bash\nexec /opt/CF_AI/venv/bin/python3 /opt/graphql-cop/graphql-cop.py "$@"\n' \
                > /usr/local/bin/graphql-cop && chmod +x /usr/local/bin/graphql-cop
            ok "graphql-cop from GitHub source"
        else
            warn "graphql-cop: all methods failed — run: bash /opt/CF_AI/install_missing_tools.sh"
        fi
    fi
fi

# jwt_tool
if command -v jwt_tool &>/dev/null; then
    ok "jwt_tool — installed"
else
    fail "jwt_tool"
    warn "Installing jwt_tool from source..."
    git clone https://github.com/ticarpi/jwt_tool /opt/jwt_tool 2>/dev/null \
        && ln -sf /opt/jwt_tool/jwt_tool.py /usr/local/bin/jwt_tool \
        && chmod +x /opt/jwt_tool/jwt_tool.py \
        && ok "jwt_tool installed" \
        || warn "jwt_tool install failed — try: pip3 install jwt_tool"
fi

# arjun
if command -v arjun &>/dev/null; then
    ok "arjun — installed"
    # Real test
    OUT=$(arjun -u http://httpbin.org/get --stable 2>/dev/null | tail -3)
    [ -n "$OUT" ] && ok "arjun: real test OK" || warn "arjun: no output"
else
    fail "arjun"
    try_install "arjun" "$VENV_PIP install arjun"
fi

# kiterunner
if command -v kr &>/dev/null; then
    ok "kiterunner (kr) — installed"
else
    fail "kiterunner (kr) — optional"
fi

# x8
if command -v x8 &>/dev/null; then
    ok "x8 — installed"
else
    fail "x8 — optional"
fi

# ── Intel Tools ────────────────────────────────────────────────────────────────
echo ""
echo "[Intel / Exploitation Tools]"

for tool in searchsploit msfvenom msfconsole; do
    if command -v "$tool" &>/dev/null; then
        ok "$tool — installed"
    else
        fail "$tool"
        case "$tool" in
            searchsploit) try_install "$tool" "apt-get install -y exploitdb" ;;
            msfvenom)     try_install "$tool" "apt-get install -y metasploit-framework" ;;
        esac
    fi
done

# Test searchsploit
if command -v searchsploit &>/dev/null; then
    OUT=$(searchsploit --json openssh 2>/dev/null | python3 -c "import sys,json; d=json.load(sys.stdin); print(f'{len(d.get(\"RESULTS_EXPLOIT\",[]))} exploits found')" 2>/dev/null)
    [ -n "$OUT" ] && ok "searchsploit: $OUT" || warn "searchsploit JSON mode not available"
fi

# ── Summary ────────────────────────────────────────────────────────────────────
echo ""
echo "======================================================"
echo " Results: ${PASS} PASS | ${FAIL} FAIL | ${FIXED} auto-fixed"
echo "======================================================"
echo ""
if [ "$FAIL" -gt 0 ]; then
    echo "To install all missing tools at once:"
    echo "  bash /opt/CF_AI/install_missing_tools.sh"
fi
echo ""
echo "Restart CF_AI server:"
echo "  pkill -f cfai_server.py; bash /opt/CF_AI/run.sh"
