# CF_AI Dockerfile — Kali Linux base with security tools
FROM kalilinux/kali-rolling:latest

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    CFAI_HOST=0.0.0.0 \
    CFAI_PORT=8888 \
    PIP_NO_CACHE_DIR=1

# System packages + security tools
RUN apt-get update && apt-get upgrade -y && \
    apt-get install -y --no-install-recommends \
        python3 python3-pip python3-dev python3-venv \
        build-essential libssl-dev libffi-dev \
        curl wget git unzip ca-certificates \
        # Browser deps
        xvfb libxi6 libnss3-dev libxss1 libgconf-2-4 \
        libatk-bridge2.0-0 libdrm2 libgtk-3-0 libnspr4 \
        libx11-xcb1 libxcomposite1 libxcursor1 libxdamage1 \
        libxrandr2 libgbm1 fonts-liberation lsb-release \
        # Network & scanning
        nmap nikto dirb gobuster sqlmap hydra john hashcat \
        ffuf amass subfinder dirsearch \
        enum4linux enum4linux-ng rpcclient smbmap \
        nbtscan arp-scan dnsenum \
        # Forensics & analysis
        binwalk exiftool steghide foremost testdisk \
        sleuthkit bulk-extractor \
        # Web / misc
        curl httpie wireshark tcpdump \
        theharvester spiderfoot \
        # Python headers
        python3-lxml python3-requests \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Install Go-based tools
RUN wget -q https://go.dev/dl/go1.22.0.linux-amd64.tar.gz -O /tmp/go.tar.gz && \
    tar -C /usr/local -xzf /tmp/go.tar.gz && \
    rm /tmp/go.tar.gz

ENV PATH=$PATH:/usr/local/go/bin:/root/go/bin

RUN go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest 2>/dev/null || true && \
    go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest 2>/dev/null || true && \
    go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest 2>/dev/null || true && \
    go install -v github.com/ffuf/ffuf/v2@latest 2>/dev/null || true && \
    go install -v github.com/hahwul/dalfox/v2@latest 2>/dev/null || true && \
    go install -v github.com/projectdiscovery/katana/cmd/katana@latest 2>/dev/null || true && \
    go install -v github.com/lc/gau/v2/cmd/gau@latest 2>/dev/null || true

# Install Google Chrome + ChromeDriver via chromedriver-autoinstaller fallback
RUN wget -q https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb -O /tmp/chrome.deb && \
    apt-get install -y /tmp/chrome.deb || true && \
    rm -f /tmp/chrome.deb && \
    apt-get -f install -y && \
    apt-get clean

# Install WPScan (Ruby gem)
RUN apt-get update && apt-get install -y ruby ruby-dev && \
    gem install wpscan --no-document 2>/dev/null || true && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt && \
    pip3 install --no-cache-dir chromedriver-autoinstaller 2>/dev/null || true

COPY . .

RUN mkdir -p logs cache temp

RUN useradd -m -s /bin/bash cfai && \
    chown -R cfai:cfai /app

USER cfai

EXPOSE 8888

HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:8888/health || exit 1

CMD ["python3", "cfai_server.py"]
