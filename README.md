# CF_AI - Advanced Penetration Testing Framework

Bug Bounty | CTF | Red Team | Security Research

## Setup Instructions

### Prerequisites
- Python 3.8+
- Kali Linux (recommended) or any Linux distribution
- Internet connection for downloading dependencies

### Installation

1. **Clone or download the repository:**
   ```bash
   git clone <repository-url>
   cd CF_AI
   ```

2. **Run the setup script (Kali Linux):**
   ```bash
   chmod +x setup.sh run.sh
   ./setup.sh
   ```

   Or manually install dependencies:
   ```bash
   pip install -r requirements.txt
   # Install system tools as listed in setup.sh
   ```

3. **Configure environment (optional):**
   ```bash
   cp .env.example .env
   # Edit .env with your settings
   ```

### Running the Server

#### Option 1: Direct execution
```bash
python cfai_server.py
```

#### Option 2: Using the run script
```bash
./run.sh
```

#### Option 3: Docker
```bash
# Build and run with Docker
docker build -t cfai .
docker run -p 8888:8888 cfai
```

#### Option 4: Docker Compose
```bash
docker-compose up -d
```

#### Option 5: Systemd service (for 24/7 hosting)
```bash
# Copy service file
sudo cp cfai.service /etc/systemd/system/
# Edit the paths in the service file
sudo nano /etc/systemd/system/cfai.service
# Create user
sudo useradd -m cfai
sudo chown -R cfai:cfai /path/to/CF_AI
# Enable and start
sudo systemctl enable cfai
sudo systemctl start cfai
```

### Running the MCP Server (Optional)

For AI agent integration:
```bash
python cfai_mcp.py
```

This provides Model Context Protocol (MCP) support for integration with AI assistants.

### Configuration

- **Port:** Set `CFAI_PORT` environment variable (default: 8888)
- **Host:** Set `CFAI_HOST` environment variable (default: 0.0.0.0)
- **Debug:** Set `DEBUG_MODE=1` for debug mode

### Features

- **Web Dashboard:** Interactive interface with chat-based command execution
- **150+ Security Tools:** Integrated penetration testing tools
- **AI-Powered Intelligence:** Automated tool selection and analysis
- **Caching System:** Improved performance with intelligent caching
- **Process Management:** Monitor and control running security processes
- **RESTful API:** Full API access for custom integrations

### Security Note

This tool is designed for authorized security testing only. Ensure you have permission before testing any systems. The authors are not responsible for misuse.

### Troubleshooting

- If tools are not found, check your PATH and ensure they're installed
- For browser automation issues, ensure ChromeDriver is compatible with your Chrome version
- Check logs in `cfai.log` for detailed error information

### API Documentation

The server provides a comprehensive REST API. Key endpoints:
- `GET /health` - System health and tool status
- `POST /api/command` - Execute commands
- `GET /api/processes/dashboard` - Process dashboard
- And many more...

For full API documentation, see the source code or use the dashboard interface.