# CF_AI Dockerfile
FROM kalilinux/kali-rolling:latest

# Set environment variables
ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1
ENV CFAI_HOST=0.0.0.0
ENV CFAI_PORT=8888

# Update and install system dependencies
RUN apt update && apt upgrade -y && \
    apt install -y \
        python3 \
        python3-pip \
        python3-dev \
        build-essential \
        libssl-dev \
        libffi-dev \
        curl \
        wget \
        git \
        unzip \
        xvfb \
        libxi6 \
        libgconf-2-4 \
        libnss3-dev \
        libxss1 \
        libappindicator3-1 \
        libasound2-dev \
        libatk-bridge2.0-0 \
        libdrm2 \
        libgtk-3-0 \
        libnspr4 \
        libx11-xcb1 \
        libxcomposite1 \
        libxcursor1 \
        libxdamage1 \
        libxrandr2 \
        libgbm1 \
        fonts-liberation \
        lsb-release \
        # Security tools
        nmap \
        gobuster \
        dirb \
        nikto \
        sqlmap \
        hydra \
        john \
        hashcat \
        nuclei \
        wpscan \
        ffuf \
        feroxbuster \
        dirsearch \
        amass \
        subfinder \
        metasploit-framework \
        burpsuite \
        zaproxy \
        wireshark \
        tcpdump \
        aircrack-ng \
        kismet \
        volatility \
        binwalk \
        exiftool \
        steghide \
        foremost \
        testdisk \
        scalpel \
        bulk-extractor \
        autopsy \
        sleuthkit \
        evil-winrm \
        enum4linux \
        enum4linux-ng \
        rpcclient \
        smbmap \
        responder \
        nbtscan \
        arp-scan \
        dnsenum \
        theharvester \
        sherlock \
        maltego \
        spiderfoot \
        shodan \
        censys \
        curl \
        httpie

# Install Google Chrome
RUN wget -q -O - https://dl.google.com/linux/linux_signing_key.pub | apt-key add - && \
    echo "deb [arch=amd64] http://dl.google.com/linux/chrome/deb/ stable main" > /etc/apt/sources.list.d/google-chrome.list && \
    apt update && \
    apt install -y google-chrome-stable

# Install ChromeDriver
RUN CHROME_VERSION=$(google-chrome --version | grep -oP '\d+\.\d+\.\d+\.\d+') && \
    CHROMEDRIVER_VERSION=$(curl -s "https://chromedriver.storage.googleapis.com/LATEST_RELEASE_$CHROME_VERSION") && \
    wget -O /tmp/chromedriver.zip "https://chromedriver.storage.googleapis.com/$CHROMEDRIVER_VERSION/chromedriver_linux64.zip" && \
    unzip /tmp/chromedriver.zip -d /usr/local/bin/ && \
    chmod +x /usr/local/bin/chromedriver

# Create app directory
WORKDIR /app

# Copy requirements and install Python packages
COPY requirements.txt .
RUN pip3 install --no-cache-dir -r requirements.txt

# Copy application files
COPY . .

# Create necessary directories
RUN mkdir -p logs cache temp

# Create non-root user
RUN useradd -m -s /bin/bash cfai && \
    chown -R cfai:cfai /app

USER cfai

# Expose port
EXPOSE 8888

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8888/health || exit 1

# Start the application
CMD ["python3", "cfai_server.py"]