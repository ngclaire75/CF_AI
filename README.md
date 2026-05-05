# CF_AI — Advanced Penetration Testing Framework

**Bug Bounty | CTF | Red Team | Security Research**

CF_AI is a self-hosted AI-powered penetration testing platform with a modern web dashboard, 150+ integrated security tools, automated recon pipelines, prompt injection protection, and formal WordPress security report generation.

---

## Features

- **AI Chat Assistant** — natural language interface for tool guidance and command execution
- **Prompt Injection Protection** — detects and blocks jailbreaks, command injection, and template injection in all user inputs
- **150+ Security Tools** — nmap, sqlmap, nuclei, gobuster, wpscan, hydra, hashcat, volatility, and many more
- **WordPress Security Reports** — formal assessment report generator for WordPress sites (suitable for client deliverables, bug bounty, and compliance)
- **Bug Bounty Pipelines** — automated recon → discovery → exploitation workflows
- **CTF Toolkit** — challenge solvers for web, crypto, forensics, and binary
- **REST API** — 159 endpoints covering every tool category
- **24/7 Deployment** — Docker, Docker Compose, and systemd service support for Kali Linux VPS

---

## Requirements

- Kali Linux (recommended) or any Debian-based Linux
- Python 3.10+
- Docker & Docker Compose (for containerized deployment)
- 2 GB RAM minimum, 4 GB recommended

---

## Quick Start (Local / VPS — Direct Python)

```bash
# 1. Clone the repository
git clone https://github.com/YOUR_USERNAME/CF_AI.git
cd CF_AI

# 2. Run the automated setup (installs all tools + Python deps)
chmod +x setup.sh run.sh
sudo ./setup.sh

# 3. Configure environment (optional — defaults work out of the box)
cp .env.example .env
nano .env

# 4. Start the server
./run.sh
# OR
python3 cfai_server.py

# 5. Open the dashboard
# http://localhost:8888
```

---

## Docker Deployment (Recommended for VPS)

```bash
# Build the image
docker build -t cfai .

# Run as a container
docker run -d \
  --name cfai \
  -p 8888:8888 \
  --restart unless-stopped \
  cfai

# View logs
docker logs -f cfai
```

### Docker Compose (with volume persistence)

```bash
docker-compose up -d

# Stop
docker-compose down
```

---

## 24/7 Kali Linux VPS Deployment (Systemd)

This is the recommended method for always-on VPS hosting.

### Step 1 — Provision VPS

Order a VPS with:
- Kali Linux 2024+ image
- 2+ GB RAM
- Port 8888 open in firewall (or use Nginx reverse proxy on port 80/443)

### Step 2 — Initial Server Setup

```bash
# Update system
sudo apt update && sudo apt upgrade -y

# Clone project
git clone https://github.com/YOUR_USERNAME/CF_AI.git /opt/CF_AI
cd /opt/CF_AI

# Run setup script
chmod +x setup.sh
sudo ./setup.sh
```

### Step 3 — Install as Systemd Service

```bash
# Create dedicated user
sudo useradd -r -s /bin/false cfai
sudo chown -R cfai:cfai /opt/CF_AI

# Copy and edit the service file
sudo cp cfai.service /etc/systemd/system/cfai.service

# Reload systemd and enable the service
sudo systemctl daemon-reload
sudo systemctl enable cfai
sudo systemctl start cfai

# Verify it is running
sudo systemctl status cfai
```

### Step 4 — Nginx Reverse Proxy (Optional — for HTTPS)

```bash
sudo apt install nginx -y

# Create config
sudo nano /etc/nginx/sites-available/cfai
```

Paste this config:

```nginx
server {
    listen 80;
    server_name yourdomain.com;

    location / {
        proxy_pass http://127.0.0.1:8888;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_read_timeout 300s;
    }
}
```

```bash
sudo ln -s /etc/nginx/sites-available/cfai /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx

# Add HTTPS with Certbot
sudo apt install certbot python3-certbot-nginx -y
sudo certbot --nginx -d yourdomain.com
```

### Step 5 — Firewall

```bash
# Using UFW
sudo ufw allow 22/tcp   # SSH
sudo ufw allow 80/tcp   # HTTP
sudo ufw allow 443/tcp  # HTTPS
sudo ufw enable

# If not using Nginx (direct port):
sudo ufw allow 8888/tcp
```

### Useful Systemd Commands

```bash
sudo systemctl start   cfai    # Start server
sudo systemctl stop    cfai    # Stop server
sudo systemctl restart cfai    # Restart
sudo systemctl status  cfai    # Check status
journalctl -u cfai -f          # Live logs
```

---

## Environment Variables

Copy `.env.example` to `.env` and set as needed:

| Variable             | Default     | Description                       |
|----------------------|-------------|-----------------------------------|
| `CFAI_PORT`          | `8888`      | Server port                       |
| `CFAI_HOST`          | `0.0.0.0`   | Bind address                      |
| `DEBUG_MODE`         | `0`         | Enable Flask debug mode           |
| `LOG_LEVEL`          | `INFO`      | Logging level                     |
| `CACHE_MAX_SIZE`     | `1000`      | Max cache entries                 |
| `CACHE_TTL`          | `3600`      | Cache TTL in seconds              |
| `SHODAN_API_KEY`     | *(empty)*   | Optional Shodan API key           |
| `CENSYS_API_KEY`     | *(empty)*   | Optional Censys API key           |
| `VIRUSTOTAL_API_KEY` | *(empty)*   | Optional VirusTotal API key       |

---

## API Reference

All endpoints accept and return JSON.

### Core

| Method | Endpoint                         | Description                          |
|--------|----------------------------------|--------------------------------------|
| GET    | `/health`                        | Server health and tool availability  |
| GET    | `/`                              | Dashboard UI                         |
| POST   | `/api/chat`                      | AI chat with NLP understanding       |
| POST   | `/api/command`                   | Execute security tool command        |
| GET    | `/api/chat/history`              | Get conversation history             |
| POST   | `/api/chat/clear`                | Clear conversation history           |
| GET    | `/api/security/injection-stats`  | Injection protection statistics      |

### WordPress

| Method | Endpoint                  | Description                       |
|--------|---------------------------|-----------------------------------|
| POST   | `/api/wordpress/report`   | Generate formal WP security report|

### Intelligence

| Method | Endpoint                                    | Description                      |
|--------|---------------------------------------------|----------------------------------|
| POST   | `/api/intelligence/analyze-target`          | AI target analysis               |
| POST   | `/api/intelligence/smart-scan`              | Intelligent scan orchestration   |
| POST   | `/api/intelligence/create-attack-chain`     | Automated attack chain planning  |
| POST   | `/api/intelligence/select-tools`            | Optimal tool selection           |

### Bug Bounty

| Method | Endpoint                                          | Description               |
|--------|---------------------------------------------------|---------------------------|
| POST   | `/api/bugbounty/reconnaissance-workflow`          | Automated recon pipeline  |
| POST   | `/api/bugbounty/vulnerability-hunting-workflow`   | Vuln discovery workflow   |
| POST   | `/api/bugbounty/comprehensive-assessment`         | Full assessment pipeline  |

### CTF

| Method | Endpoint                            | Description                    |
|--------|-------------------------------------|--------------------------------|
| POST   | `/api/ctf/auto-solve-challenge`     | Automated CTF solver           |
| POST   | `/api/ctf/cryptography-solver`      | Crypto challenge solver        |
| POST   | `/api/ctf/binary-analyzer`          | Binary / reverse engineering   |

---

## Dashboard

Navigate to `http://your-server:8888` after starting the server.

- **AI Assistant tab** — chat with the AI, run commands, get tool guidance
- **WP Report tab** — generate formal WordPress security assessment reports
- **API Docs tab** — browse all available endpoints
- **Sidebar** — tool categories with quick-launch shortcuts
- **System Status** — live health, tool count, and injection protection status

---

## Security Notes

- CF_AI is designed for **authorized security testing only**
- All user inputs are screened by the built-in **Prompt Injection Protector**
- Never expose the server to the public internet without authentication
- Use a reverse proxy with HTTPS and restrict access by IP if running on a VPS
- The authors are not responsible for misuse

---

## Troubleshooting

| Problem                         | Solution                                                      |
|---------------------------------|---------------------------------------------------------------|
| Tools not found                 | Run `sudo ./setup.sh` or install tools manually              |
| Server won't start              | Check `journalctl -u cfai -f` for errors                     |
| Port 8888 already in use        | Change `CFAI_PORT` in `.env` or stop the conflicting process |
| mitmproxy import error          | Run `pip3 install mitmproxy==10.1.5` (Linux only)           |
| selenium/ChromeDriver errors    | Ensure Chrome + matching ChromeDriver are installed          |
| Dashboard not loading           | Ensure `templates/` and `static/` are in the working dir    |

---

## License

For authorized penetration testing, security research, CTF, and educational purposes only.
