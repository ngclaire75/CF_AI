#!/bin/bash

# CF_AI Setup Script for Kali Linux
# This script installs dependencies and sets up the environment

echo "CF_AI Setup Script for Kali Linux"
echo "=================================="

# Update system
echo "Updating system packages..."
sudo apt update && sudo apt upgrade -y

# Install Python and pip if not present
echo "Installing Python dependencies..."
sudo apt install -y python3 python3-pip python3-venv

# Install system dependencies
echo "Installing system dependencies..."
sudo apt install -y \
    build-essential \
    libssl-dev \
    libffi-dev \
    python3-dev \
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
    libxss1 \
    libasound2 \
    fonts-liberation \
    lsb-release

# Install Google Chrome for Selenium
echo "Installing Google Chrome..."
wget -q -O - https://dl.google.com/linux/linux_signing_key.pub | sudo apt-key add -
echo "deb [arch=amd64] http://dl.google.com/linux/chrome/deb/ stable main" | sudo tee /etc/apt/sources.list.d/google-chrome.list
sudo apt update
sudo apt install -y google-chrome-stable

# Install ChromeDriver
echo "Installing ChromeDriver..."
CHROME_VERSION=$(google-chrome --version | grep -oP '\d+\.\d+\.\d+\.\d+')
CHROMEDRIVER_VERSION=$(curl -s "https://chromedriver.storage.googleapis.com/LATEST_RELEASE_$CHROME_VERSION")
wget -O /tmp/chromedriver.zip "https://chromedriver.storage.googleapis.com/$CHROMEDRIVER_VERSION/chromedriver_linux64.zip"
sudo unzip /tmp/chromedriver.zip -d /usr/local/bin/
sudo chmod +x /usr/local/bin/chromedriver

# Install security tools
echo "Installing security tools..."
sudo apt install -y \
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
    httpie \
    wget \
    git \
    unzip

# Install Python packages
echo "Installing Python packages..."
pip3 install -r requirements.txt

# Create necessary directories
echo "Creating directories..."
mkdir -p logs
mkdir -p cache
mkdir -p temp

# Set up environment file
if [ ! -f .env ]; then
    echo "Creating .env file from example..."
    cp .env.example .env
fi

# Make scripts executable
chmod +x run.sh
chmod +x setup.sh

echo "Setup complete!"
echo "==============="
echo "To start the server, run: ./run.sh"
echo "Or manually: python3 cfai_server.py"
echo ""
echo "Access the dashboard at: http://localhost:8888"
echo ""
echo "For production deployment, consider using:"
echo "- systemd service (see README.md)"
echo "- Docker container"
echo "- Reverse proxy with nginx/apache"