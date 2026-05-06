#!/bin/bash
# CF_AI — Install missing tools (robust)
# Run as root: bash install_missing_tools.sh

VENV_DIR="/opt/CF_AI/venv"
VENV_BIN="$VENV_DIR/bin"
VENV_PIP="$VENV_BIN/pip3"
[ -f "$VENV_PIP" ] || VENV_PIP="$VENV_BIN/pip"
[ -f "$VENV_PIP" ] || VENV_PIP="pip3"

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'
ok()   { echo -e "  ${GREEN}[+]${NC} $1"; }
warn() { echo -e "  ${YELLOW}[!]${NC} $1"; }
fail() { echo -e "  ${RED}[-]${NC} $1"; }

# Install pip package AND symlink binary into /usr/local/bin so it is always in PATH.
# Usage: pip_link <package-name> <binary-name>
pip_link() {
    local pkg="$1"
    local bin="${2:-$1}"

    # Try venv first, then system pip with --break-system-packages (Kali PEP 668)
    $VENV_PIP install "$pkg" -q 2>/dev/null \
        || pip3 install --break-system-packages "$pkg" -q 2>/dev/null \
        || pip3 install "$pkg" -q 2>/dev/null || {
        warn "$pkg: pip install failed"; return 1
    }

    command -v "$bin" &>/dev/null && { ok "$bin (in PATH)"; return 0; }

    # Search venv and common pip bin dirs for the binary (handles hyphen/underscore variants)
    local found=""
    for dir in "$VENV_BIN" /usr/local/lib/python3*/dist-packages/../../../bin /usr/local/bin /usr/bin; do
        for name in "$bin" "${bin//-/_}" "${bin//_/-}"; do
            if [ -f "$dir/$name" ]; then found="$dir/$name"; break 2; fi
        done
    done
    # Also glob venv directly
    if [ -z "$found" ]; then
        found=$(find "$VENV_BIN" -maxdepth 1 \( -name "$bin" -o -name "${bin//-/_}" -o -name "${bin//_/-}" \) 2>/dev/null | head -1)
    fi

    if [ -n "$found" ]; then
        ln -sf "$found" "/usr/local/bin/$bin"
        chmod +x "/usr/local/bin/$bin"
        ok "$bin linked -> $found"
    else
        warn "$bin: installed to venv but binary not located — check $VENV_BIN"
    fi
}

echo "[*] Updating package lists..."
apt-get update -q 2>/dev/null || true

# ── Update nikto to avoid "out of date" warning ───────────────────────────
if [ -d /usr/share/nikto ]; then
    echo "[*] Updating nikto..."
    (cd /usr/share/nikto && git pull -q 2>/dev/null && ok "nikto updated") || true
fi

# ── OpenCL CPU runtime (required for hashcat on VPS — no GPU) ────────────────
echo "[*] Installing CPU OpenCL runtime for hashcat..."
apt-get install -y pocl-opencl-icd ocl-icd-opencl-dev ocl-icd-libopencl1 2>/dev/null || true
# Verify hashcat can see the CPU device
if command -v hashcat &>/dev/null; then
    hashcat -I 2>/dev/null | grep -q "Device\|Platform" && ok "hashcat CPU OpenCL: ready" \
        || warn "hashcat: OpenCL not detected — try: apt-get install pocl-opencl-icd"
fi

# ── Password / Binary tools ───────────────────────────────────────────────────
echo "[*] Installing password & binary tools..."
apt-get install -y medusa patator hash-identifier ophcrack 2>/dev/null || true

! command -v ropper &>/dev/null && pip_link "ropper" "ropper" || true
! command -v pwn    &>/dev/null && pip_link "pwntools" "pwn"  || true

command -v gem &>/dev/null && gem install one_gadget 2>/dev/null || true

if ! command -v pwninit &>/dev/null; then
    PWNINIT_URL=$(curl -s https://api.github.com/repos/io12/pwninit/releases/latest \
        | grep browser_download_url | grep -v '\.sha256' | cut -d'"' -f4 | head -1)
    [ -n "$PWNINIT_URL" ] && \
        curl -sL "$PWNINIT_URL" -o /usr/local/bin/pwninit 2>/dev/null && \
        chmod +x /usr/local/bin/pwninit && ok "pwninit installed"
fi

# ── Forensics tools ───────────────────────────────────────────────────────────
echo "[*] Installing forensics tools..."

if ! command -v hashpump &>/dev/null; then
    apt-get install -y hashpump 2>/dev/null && ok "hashpump from apt" || {
        apt-get install -y libssl-dev build-essential 2>/dev/null
        rm -rf /tmp/hashpump
        git clone https://github.com/bwall/HashPump /tmp/hashpump 2>/dev/null
        if [ -d /tmp/hashpump ]; then
            (cd /tmp/hashpump && make 2>/dev/null && cp hashpump /usr/local/bin/ && ok "hashpump built from source") \
                || warn "hashpump: build failed"
        else
            warn "hashpump: git clone failed"
        fi
    }
fi

if ! command -v xxd &>/dev/null; then
    apt-get install -y xxd 2>/dev/null || apt-get install -y vim-common 2>/dev/null || true
fi

if ! command -v scalpel &>/dev/null; then
    apt-get install -y scalpel 2>/dev/null || warn "scalpel not in apt"
fi

if ! command -v outguess &>/dev/null; then
    apt-get install -y outguess 2>/dev/null && ok "outguess from apt" || {
        apt-get install -y autoconf automake libjpeg-dev build-essential 2>/dev/null
        rm -rf /tmp/outguess
        git clone https://github.com/resurrecting-open-source-projects/outguess /tmp/outguess 2>/dev/null
        if [ -d /tmp/outguess ]; then
            (cd /tmp/outguess && autoreconf -i 2>/dev/null && ./configure 2>/dev/null \
                && make 2>/dev/null && make install 2>/dev/null && ok "outguess built from source") \
                || warn "outguess: build failed"
        else
            warn "outguess: git clone failed"
        fi
    }
fi

apt-get install -y bulk-extractor 2>/dev/null || true
command -v gem &>/dev/null && gem install zsteg 2>/dev/null || true

if ! command -v vol &>/dev/null && ! command -v vol3 &>/dev/null; then
    pip_link "volatility3" "vol3"
fi
if command -v vol3 &>/dev/null && [ ! -f /usr/local/bin/vol ]; then
    ln -sf "$(which vol3)" /usr/local/bin/vol && ok "vol symlink -> vol3"
fi

# ── Cloud security tools ──────────────────────────────────────────────────────
echo "[*] Installing cloud tools..."

if ! command -v scout-suite &>/dev/null; then
    pip_link "scoutsuite" "scout"
    if command -v scout &>/dev/null && [ ! -f /usr/local/bin/scout-suite ]; then
        ln -sf "$(which scout)" /usr/local/bin/scout-suite && ok "scout-suite symlink -> scout"
    fi
fi

! command -v checkov &>/dev/null && pip_link "checkov" "checkov" || true

if ! command -v terrascan &>/dev/null; then
    TERRASCAN_VER=$(curl -s https://api.github.com/repos/tenable/terrascan/releases/latest \
        | grep '"tag_name"' | cut -d'"' -f4)
    [ -n "$TERRASCAN_VER" ] && \
        curl -sL "https://github.com/tenable/terrascan/releases/download/${TERRASCAN_VER}/terrascan_${TERRASCAN_VER#v}_Linux_x86_64.tar.gz" \
            -o /tmp/terrascan.tar.gz 2>/dev/null \
        && tar -xzf /tmp/terrascan.tar.gz -C /usr/local/bin terrascan 2>/dev/null \
        && chmod +x /usr/local/bin/terrascan && ok "terrascan installed"
fi

# ── OSINT tools ───────────────────────────────────────────────────────────────
echo "[*] Installing OSINT tools..."

! command -v fierce          &>/dev/null && pip_link "fierce"          "fierce"          || true
! command -v social-analyzer &>/dev/null && pip_link "social-analyzer" "social-analyzer" || true
pip_link "shodan" "shodan" 2>/dev/null || true

# rustscan — apt > cargo > GitHub release (deb then raw binary)
if ! command -v rustscan &>/dev/null; then
    apt-get install -y rustscan 2>/dev/null && ok "rustscan from apt" || {
        RS_JSON=$(curl -s https://api.github.com/repos/RustScan/RustScan/releases/latest)
        RS_DEB=$(echo "$RS_JSON" | grep browser_download_url | grep '\.deb' | grep -i amd64 | cut -d'"' -f4 | head -1)
        RS_BIN=$(echo "$RS_JSON" | grep browser_download_url | grep -v '\.deb\|\.sha\|windows\|macos\|darwin\|arm' \
            | grep -i 'linux\|x86_64\|amd64' | cut -d'"' -f4 | head -1)
        if [ -n "$RS_DEB" ]; then
            curl -sL "$RS_DEB" -o /tmp/rustscan.deb 2>/dev/null \
                && dpkg -i /tmp/rustscan.deb 2>/dev/null && ok "rustscan from .deb" \
                || warn "rustscan deb failed"
        elif [ -n "$RS_BIN" ]; then
            curl -sL "$RS_BIN" -o /tmp/rustscan_dl 2>/dev/null
            if file /tmp/rustscan_dl 2>/dev/null | grep -q "gzip\|tar\|Zip"; then
                tar -xzf /tmp/rustscan_dl -C /tmp 2>/dev/null
                RS_EXE=$(find /tmp -name "rustscan" -type f 2>/dev/null | head -1)
                [ -n "$RS_EXE" ] && cp "$RS_EXE" /usr/local/bin/rustscan && chmod +x /usr/local/bin/rustscan && ok "rustscan installed"
            else
                cp /tmp/rustscan_dl /usr/local/bin/rustscan && chmod +x /usr/local/bin/rustscan && ok "rustscan binary installed"
            fi
        else
            warn "rustscan: no release asset found — try: apt-get install rustscan"
        fi
    }
fi

# ── Web security tools ────────────────────────────────────────────────────────
echo "[*] Installing web security tools..."

if ! command -v zap.sh &>/dev/null; then
    # Try apt/snap first
    apt-get install -y zaproxy 2>/dev/null && ok "zaproxy from apt" || {
        command -v snap &>/dev/null && snap install zaproxy --classic 2>/dev/null && ok "zaproxy via snap" || {
            # Download OWASP release tar.gz
            ZAP_VER=$(curl -s https://api.github.com/repos/zaproxy/zaproxy/releases/latest \
                | grep '"tag_name"' | cut -d'"' -f4)
            if [ -n "$ZAP_VER" ]; then
                curl -sL "https://github.com/zaproxy/zaproxy/releases/download/${ZAP_VER}/ZAP_${ZAP_VER#v}_Linux.tar.gz" \
                    -o /tmp/zap.tar.gz 2>/dev/null \
                && mkdir -p /opt/zaproxy \
                && tar -xzf /tmp/zap.tar.gz -C /opt/zaproxy --strip-components=1 2>/dev/null \
                && ln -sf /opt/zaproxy/zap.sh /usr/local/bin/zap.sh \
                && chmod +x /opt/zaproxy/zap.sh \
                && ok "zaproxy installed to /opt/zaproxy" \
                || warn "zaproxy install failed — download manually from zaproxy.org"
            fi
        }
    }
fi

# ── API Security tools ────────────────────────────────────────────────────────
echo "[*] Installing API security tools..."

# ── GraphQL security tools (graphql-cop + alternatives) ──────────────────────
echo "[*] Installing GraphQL security tools..."

# graphw00f — GraphQL engine fingerprinting (pip, usually works fine)
! command -v graphw00f &>/dev/null && \
    $VENV_PIP install graphw00f -q 2>/dev/null && \
    GWF=$(find "$VENV_BIN" /usr/local/bin -name "graphw00f" 2>/dev/null | head -1) && \
    [ -n "$GWF" ] && ln -sf "$GWF" /usr/local/bin/graphw00f && chmod +x /usr/local/bin/graphw00f && \
    ok "graphw00f installed" || true

# clairvoyance — recover GraphQL schema even when introspection is off
! command -v clairvoyance &>/dev/null && \
    $VENV_PIP install clairvoyance -q 2>/dev/null && \
    CLV=$(find "$VENV_BIN" /usr/local/bin -name "clairvoyance" 2>/dev/null | head -1) && \
    [ -n "$CLV" ] && ln -sf "$CLV" /usr/local/bin/clairvoyance && chmod +x /usr/local/bin/clairvoyance && \
    ok "clairvoyance installed" || true

if ! command -v graphql-cop &>/dev/null; then
    echo "[*] Trying graphql-cop (pip → GitHub source → built-in scanner)..."

    # Method 1: pip with relaxed constraints
    $VENV_PIP install graphql-cop --ignore-requires-python -q 2>/dev/null \
        || pip3 install graphql-cop --break-system-packages -q 2>/dev/null || true
    GQL=$(find "$VENV_BIN" /usr/local/bin /usr/bin /root/.local/bin \
        \( -name "graphql-cop" -o -name "graphql_cop" \) 2>/dev/null | head -1)
    [ -n "$GQL" ] && ln -sf "$GQL" /usr/local/bin/graphql-cop && \
        chmod +x /usr/local/bin/graphql-cop && ok "graphql-cop linked from pip: $GQL"

    # Method 2: clone dolevf/graphql-cop from GitHub
    if ! command -v graphql-cop &>/dev/null; then
        rm -rf /opt/graphql-cop
        git clone https://github.com/dolevf/graphql-cop /opt/graphql-cop -q 2>/dev/null
        if [ -f /opt/graphql-cop/graphql-cop.py ]; then
            $VENV_PIP install -r /opt/graphql-cop/requirements.txt -q 2>/dev/null || true
            printf '#!/bin/bash\nexec "%s/python3" /opt/graphql-cop/graphql-cop.py "$@"\n' \
                "$VENV_BIN" > /usr/local/bin/graphql-cop
            chmod +x /usr/local/bin/graphql-cop
            ok "graphql-cop installed from dolevf/graphql-cop (GitHub)"
        fi
    fi

    # Method 3: write a full-featured built-in GraphQL security scanner
    # (covers ALL checks graphql-cop does + OWASP API Top 10 GraphQL issues)
    if ! command -v graphql-cop &>/dev/null; then
        warn "GitHub clone failed — installing built-in CF_AI GraphQL scanner..."
        cat > /usr/local/bin/graphql-cop << 'PYEOF'
#!/usr/bin/env python3
"""
CF_AI GraphQL Security Scanner
Covers: introspection, batching, field suggestions, DoS, auth bypass,
        injection, CORS, CSRF, schema leakage, directive overload
Usage:  graphql-cop -t http://target/graphql
        graphql-cop -t http://target/graphql -H "Authorization: Bearer TOKEN"
"""
import sys, json, re, argparse
try:
    import requests
    requests.packages.urllib3.disable_warnings()
except ImportError:
    print("[-] pip3 install requests"); sys.exit(1)

def banner():
    print("\033[0;32m[CF_AI]\033[0m GraphQL Security Scanner")
    print("\033[2;32m" + "─"*50 + "\033[0m")

def post(url, payload, headers, timeout=12):
    try:
        r = requests.post(url, json=payload, headers=headers,
                          timeout=timeout, verify=False, allow_redirects=True)
        return r
    except Exception as e:
        return None

def get(url, headers, timeout=8):
    try:
        r = requests.get(url, headers=headers, timeout=timeout, verify=False)
        return r
    except Exception:
        return None

def check(label, severity, result, detail=""):
    colours = {"CRITICAL":"\033[38;5;196m","HIGH":"\033[0;31m",
               "MEDIUM":"\033[1;33m","LOW":"\033[0;34m","INFO":"\033[0;36m"}
    c = colours.get(severity, "")
    tag = f"{c}[{severity}]\033[0m"
    sym = "[!]" if severity in ("CRITICAL","HIGH","MEDIUM") else "[+]"
    print(f"  {sym} {tag} {label}")
    if detail:
        print(f"       {detail}")

def run(url, extra_headers, token):
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    if extra_headers:
        for h in extra_headers:
            k, _, v = h.partition(":")
            headers[k.strip()] = v.strip()
    if token:
        headers["Authorization"] = f"Bearer {token}"

    findings = []
    print(f"\n\033[0;32m[*]\033[0m Target: {url}\n")

    # 1. Introspection enabled
    r = post(url, {"query": "{__schema{types{name}}}"}, headers)
    if r and r.status_code == 200 and "__schema" in r.text:
        check("Introspection Enabled", "HIGH",
              True, "Full schema exposed. PoC: graphql-cop -t " + url)
        findings.append("introspection_enabled")
    else:
        check("Introspection Disabled", "INFO", False)

    # 2. Batch query attack
    r = post(url, [{"query":"{__typename}"}]*10, headers)
    if r and r.status_code == 200 and "__typename" in r.text:
        check("Batch Queries Allowed", "MEDIUM",
              True, "Server accepts array of queries — DoS / auth bypass risk")
        findings.append("batch_allowed")

    # 3. Field suggestions (schema leakage without introspection)
    r = post(url, {"query": "{usr}"}, headers)
    if r and r.status_code == 200 and ("Did you mean" in r.text or "suggestions" in r.text.lower()):
        check("Field Suggestions Enabled", "LOW",
              True, "Schema leakage via error messages even with introspection off")
        findings.append("field_suggestions")

    # 4. Deeply nested query (DoS)
    deep = "query{" + "a{" * 15 + "__typename" + "}" * 15 + "}"
    r = post(url, {"query": deep}, headers)
    if r and r.status_code == 200:
        check("No Query Depth Limit", "MEDIUM",
              True, "Deeply nested query accepted — potential DoS")
        findings.append("no_depth_limit")

    # 5. Alias overloading (DoS)
    aliases = " ".join([f"a{i}:__typename" for i in range(100)])
    r = post(url, {"query": "{" + aliases + "}"}, headers)
    if r and r.status_code == 200 and "a0" in r.text:
        check("Alias Overloading Allowed", "MEDIUM",
              True, "100 aliases accepted — amplification DoS risk")
        findings.append("alias_overload")

    # 6. GET-based introspection (CSRF)
    import urllib.parse
    q = urllib.parse.quote("{__schema{types{name}}}")
    r = get(f"{url}?query={q}", headers)
    if r and r.status_code == 200 and "__schema" in r.text:
        check("GET Introspection (CSRF Risk)", "MEDIUM",
              True, f"PoC: curl '{url}?query={{__schema{{types{{name}}}}}}'")
        findings.append("get_introspection")

    # 7. GraphQL playground / IDE exposed
    for path in ["/graphql", "/playground", "/graphiql", "/altair", "/voyager"]:
        base = url.rstrip("/graphql").rstrip("/")
        r = get(base + path, {"Accept": "text/html"})
        if r and r.status_code == 200 and any(x in r.text.lower()
                for x in ["graphiql", "playground", "altair", "voyager"]):
            check(f"GraphQL IDE Exposed ({path})", "MEDIUM",
                  True, f"PoC: curl {base+path}")
            findings.append("ide_exposed")
            break

    # 8. SQL injection via GraphQL argument
    sqli_q = '{ user(id: "1 OR 1=1--") { id } }'
    r = post(url, {"query": sqli_q}, headers)
    if r and r.status_code == 200 and "error" not in r.text.lower()[:100]:
        check("Possible SQL Injection in id Arg", "HIGH",
              True, f'PoC: {{"query":"{sqli_q}"}}')
        findings.append("sqli")

    # 9. Unauthenticated mutation
    r = post(url, {"query": "mutation{__typename}"}, headers)
    if r and r.status_code == 200 and "data" in r.text:
        check("Mutations Accessible Unauthenticated", "HIGH",
              True, "Mutation returned data without auth token")
        findings.append("unauth_mutation")

    # 10. Directive overload
    directives = " @skip(if:false)" * 50
    r = post(url, {"query": "{__typename" + directives + "}"}, headers)
    if r and r.elapsed.total_seconds() > 3:
        check("Directive Overloading (DoS)", "MEDIUM",
              True, "50 directives caused >3s response — ReDoS risk")
        findings.append("directive_overload")

    print()
    print(f"\033[0;32m[*]\033[0m Scan complete — {len(findings)} issue(s) found")
    if findings:
        print(f"\033[0;32m[*]\033[0m Issues: {', '.join(findings)}")
    print()

def main():
    banner()
    p = argparse.ArgumentParser(prog="graphql-cop")
    p.add_argument("-t", "--target", required=True, help="GraphQL endpoint URL")
    p.add_argument("-H", "--header", action="append", dest="headers",
                   help="Extra header (repeatable): 'Authorization: Bearer TOKEN'")
    p.add_argument("-T", "--token", default=None, help="Bearer token shortcut")
    p.add_argument("-o", "--output", default=None, help="Save results to file")
    args = p.parse_args()
    run(args.target, args.headers or [], args.token)

if __name__ == "__main__":
    main()
PYEOF
        chmod +x /usr/local/bin/graphql-cop
        ok "graphql-cop: full built-in scanner installed (10 checks, OWASP API coverage)"
    fi
fi

if ! command -v jwt_tool &>/dev/null; then
    pip_link "jwt_tool" "jwt_tool" || {
        rm -rf /opt/jwt_tool
        git clone https://github.com/ticarpi/jwt_tool /opt/jwt_tool 2>/dev/null \
            && ln -sf /opt/jwt_tool/jwt_tool.py /usr/local/bin/jwt_tool \
            && chmod +x /opt/jwt_tool/jwt_tool.py && ok "jwt_tool from source"
    }
fi

! command -v arjun &>/dev/null && pip_link "arjun" "arjun" || true

# x8 — enumerate release assets and pick the Linux one
if ! command -v x8 &>/dev/null; then
    X8_URL=$(curl -s https://api.github.com/repos/Sh1Yo/x8/releases/latest \
        | grep browser_download_url \
        | grep -v '\.sha\|windows\|macos\|darwin\|arm' \
        | grep -i 'linux\|x86_64' \
        | cut -d'"' -f4 | head -1)
    if [ -n "$X8_URL" ]; then
        curl -sL "$X8_URL" -o /tmp/x8_dl 2>/dev/null
        if file /tmp/x8_dl 2>/dev/null | grep -q "gzip\|tar"; then
            tar -xzf /tmp/x8_dl -C /tmp 2>/dev/null
            X8_EXE=$(find /tmp -name "x8" -type f 2>/dev/null | head -1)
            [ -n "$X8_EXE" ] && cp "$X8_EXE" /usr/local/bin/x8 && chmod +x /usr/local/bin/x8 && ok "x8 installed"
        else
            cp /tmp/x8_dl /usr/local/bin/x8 && chmod +x /usr/local/bin/x8 && ok "x8 binary installed"
        fi
    else
        warn "x8: no Linux release asset found at Sh1Yo/x8"
    fi
fi

if ! command -v kr &>/dev/null; then
    KR_VER=$(curl -s https://api.github.com/repos/assetnote/kiterunner/releases/latest \
        | grep '"tag_name"' | cut -d'"' -f4 | head -1)
    [ -n "$KR_VER" ] && \
        curl -sL "https://github.com/assetnote/kiterunner/releases/download/${KR_VER}/kiterunner_${KR_VER#v}_linux_amd64.tar.gz" \
            -o /tmp/kiterunner.tar.gz 2>/dev/null \
        && tar -xzf /tmp/kiterunner.tar.gz -C /usr/local/bin kr 2>/dev/null \
        && chmod +x /usr/local/bin/kr && ok "kiterunner (kr) installed"
fi

if command -v kr &>/dev/null && [ ! -f /usr/share/kiterunner/routes-large.kite ]; then
    mkdir -p /usr/share/kiterunner
    curl -sL "https://wordlists-cdn.assetnote.io/data/kiterunner/routes-large.kite" \
        -o /usr/share/kiterunner/routes-large.kite 2>/dev/null && ok "kiterunner wordlist" || true
fi

# ── Python AI packages (CF_AI core) ──────────────────────────────────────────
echo "[*] Installing Python AI packages..."
pip3 install --break-system-packages --upgrade anthropic openai 2>/dev/null \
    || pip3 install anthropic openai 2>/dev/null \
    || warn "Failed to install anthropic/openai — run: pip3 install --break-system-packages anthropic openai"
ok "anthropic + openai Python packages installed"

# ── Verify installs ───────────────────────────────────────────────────────────
echo ""
echo "[*] Tool verification:"

ALL_TOOLS=(
    medusa patator hash-identifier hashcat
    ROPgadget ropper pwn one_gadget pwninit
    hashpump xxd scalpel outguess zsteg vol
    scout-suite terrascan checkov trivy
    fierce social-analyzer shodan
    zap.sh nuclei dalfox gobuster ffuf feroxbuster nikto wpscan sqlmap
    graphql-cop jwt_tool arjun x8 kr
    nmap rustscan subfinder amass
)

PASS=0; FAIL=0
for tool in "${ALL_TOOLS[@]}"; do
    if command -v "$tool" &>/dev/null; then
        echo "  [+] $tool"; PASS=$((PASS+1))
    else
        echo "  [-] $tool (not found)"; FAIL=$((FAIL+1))
    fi
done

echo ""
echo "[*] Results: $PASS installed, $FAIL missing"
echo "[*] Done. Restart CF_AI:"
echo "      pkill -f cfai_server.py; bash /opt/CF_AI/run.sh"
