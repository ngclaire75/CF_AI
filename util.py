"""CF_AI utilities — config, formatting, helpers."""
import os
import re
from pathlib import Path
from datetime import datetime
from urllib.parse import urlparse


def load_env():
    """Load .env from project root if present."""
    env_path = Path(__file__).parent / '.env'
    if env_path.exists():
        with open(env_path) as f:
            for raw in f:
                line = raw.strip()
                if not line or line.startswith('#') or '=' not in line:
                    continue
                k, _, v = line.partition('=')
                os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


def server_url() -> str:
    return os.environ.get('CFAI_SERVER', 'http://localhost:8888').rstrip('/')


def anthropic_key() -> str:
    return os.environ.get('ANTHROPIC_API_KEY', '')


def truncate(s: str, n: int = 200) -> str:
    s = str(s)
    return s[:n] + ' …' if len(s) > n else s


def format_duration(seconds: float) -> str:
    if seconds < 60:
        return f'{seconds:.1f}s'
    m, s = divmod(int(seconds), 60)
    return f'{m}m{s:02d}s'


def now_iso() -> str:
    return datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')


def parse_target(target: str) -> tuple:
    """Return (url, host) from a URL or bare hostname."""
    if not target.startswith(('http://', 'https://')):
        target = 'https://' + target
    host = urlparse(target).hostname or target
    return target, host


def severity_rank(s: str) -> int:
    return {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}.get(
        str(s).lower(), 5)


def strip_ansi(s: str) -> str:
    return re.sub(r'\033\[[0-9;]*m', '', s)
