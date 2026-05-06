"""CF_AI Claude AI Agent — uses Anthropic API for security analysis."""
import os
import json

try:
    import anthropic
    _client = None

    def _get_client():
        global _client
        if _client is None:
            key = os.environ.get('ANTHROPIC_API_KEY', '')
            if not key:
                return None
            _client = anthropic.Anthropic(api_key=key)
        return _client

    CLAUDE_AVAILABLE = True
except ImportError:
    CLAUDE_AVAILABLE = False
    def _get_client(): return None

MODEL = "claude-sonnet-4-6"


def analyze_findings(context: dict) -> str:
    """Generate a prioritized security analysis from findings summary."""
    client = _get_client()
    if not client:
        return "Claude AI unavailable — add ANTHROPIC_API_KEY to your .env file."

    sites    = context.get('sites', 0)
    findings = context.get('findings', 0)
    critical = context.get('critical', 0)
    high     = context.get('high', 0)
    top      = context.get('top_findings', [])

    top_str = '\n'.join(
        f"- [{f['severity'].upper()}] {f['title']} on {f.get('site','unknown')}"
        for f in top
    ) or 'None'

    prompt = f"""You are CF_AI, an autonomous penetration testing AI security analyst.

Current platform state:
- Sites monitored: {sites}
- Total findings: {findings}
- Critical: {critical}
- High: {high}
- Top findings:
{top_str}

Provide a concise (5-8 line) executive security analysis:
1. Overall risk level
2. Top 2-3 immediate actions
3. One sentence on what to do first

Be direct and actionable. No markdown headers."""

    try:
        msg = client.messages.create(
            model=MODEL,
            max_tokens=400,
            messages=[{"role": "user", "content": prompt}],
        )
        return msg.content[0].text
    except Exception as e:
        return f"Analysis error: {e}"


def generate_fix(finding: dict) -> str:
    """Generate a specific remediation command for a finding."""
    client = _get_client()
    if not client:
        return ""

    prompt = f"""You are a security engineer. Generate a single, copy-paste shell command to fix this vulnerability:

Title: {finding.get('title', '')}
Severity: {finding.get('severity', '')}
Description: {finding.get('description', '')}
Site URL: {finding.get('site_url', '')}
Platform: {finding.get('platform', 'unknown')}

Return ONLY the shell command, no explanation. If no command is possible, return empty string."""

    try:
        msg = client.messages.create(
            model=MODEL,
            max_tokens=200,
            messages=[{"role": "user", "content": prompt}],
        )
        return msg.content[0].text.strip()
    except Exception:
        return ""


def analyze_scan_output(tool: str, output: str, site_url: str) -> list:
    """Parse raw tool output into structured findings using Claude."""
    client = _get_client()
    if not client:
        return []

    prompt = f"""You are a security analyst. Parse this {tool} scan output and extract confirmed vulnerabilities.

Target: {site_url}
Tool output:
{output[:3000]}

Return a JSON array of findings. Each finding:
{{
  "title": "short title",
  "severity": "critical|high|medium|low|info",
  "description": "what was found",
  "poc": "curl command or reproduction steps if available",
  "recommendation": "how to fix",
  "wst_id": "WSTG-XXXX-XX if applicable",
  "category": "xss|sqli|ssrf|auth|config|etc",
  "autofix_available": true/false,
  "fix_command": "shell command to fix or empty string"
}}

Return ONLY valid JSON array, no explanation."""

    try:
        msg = client.messages.create(
            model=MODEL,
            max_tokens=2000,
            messages=[{"role": "user", "content": prompt}],
        )
        text = msg.content[0].text.strip()
        if text.startswith('['):
            return json.loads(text)
        start = text.find('[')
        end   = text.rfind(']') + 1
        if start >= 0 and end > start:
            return json.loads(text[start:end])
        return []
    except Exception:
        return []
