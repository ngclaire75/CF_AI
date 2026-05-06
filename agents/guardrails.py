"""CF_AI Guardrails — input/output validation and dangerous command blocking."""
import os
import re
import base64
import binascii
import unicodedata

ENABLED = os.environ.get('CAI_GUARDRAILS', '1') == '1'

# ── Prompt injection patterns ────────────────────────────────────────────────
_INJECTION_PATTERNS = [
    r'ignore\s+(previous|above|all)\s+instructions?',
    r'disregard\s+(your|all)\s+(previous\s+)?instructions?',
    r'you\s+are\s+now\s+(a\s+)?(?:DAN|jailbreak|unrestricted)',
    r'act\s+as\s+(if\s+you\s+are\s+)?(?:a\s+)?(?:hacker|evil|malicious)',
    r'pretend\s+(you\s+are|to\s+be)\s+(?:a\s+)?(?:hacker|DAN)',
    r'system\s*:\s*you\s+are',
    r'<\s*system\s*>',
    r'\[INST\].*override',
    r'bypass\s+(your\s+)?(safety|ethical|content)\s+(filter|guardrail|check)',
    r'jailbreak',
    r'prompt\s+injection',
]
_INJECTION_RE = [re.compile(p, re.I | re.S) for p in _INJECTION_PATTERNS]

# ── Homograph / confusable detection ────────────────────────────────────────
_LATIN_LOOKALIKES = re.compile(
    r'[аеорсхуі'  # Cyrillic a e o p c x y i
    r'αεορυ'                      # Greek a e o r y
    r'١-٩]'                                       # Arabic-Indic digits
)

# ── Dangerous command patterns (OutputGuardrail) ─────────────────────────────
_DANGEROUS_CMDS = [
    # Destructive filesystem
    r'rm\s+-[a-zA-Z]*rf?\s+/',
    r'rm\s+-[a-zA-Z]*f?r\s+/',
    r'shred\s+.*--remove',
    r'>\s*/dev/sda',
    r'dd\s+.*of=/dev/(sd|hd|nvme)',
    # Fork bombs
    r':\(\)\s*\{.*:\|:&\s*\}',
    r'fork\s+bomb',
    # Reverse shells
    r'bash\s+-i\s+>&\s*/dev/tcp/',
    r'nc\s+(-e|-c)\s+.*bash',
    r'python[23]?\s+-c.*socket.*exec',
    r'/bin/sh\s+-i',
    r'mkfifo.*nc.*bash',
    # Pipe-to-shell (code execution from network)
    r'curl\s+.*\|\s*(bash|sh|python|perl|ruby)',
    r'wget\s+.*-O\s*-\s*\|\s*(bash|sh)',
    # Privilege escalation helpers
    r'chmod\s+(777|a\+rwx|ugo\+rwx)\s+/(etc|bin|usr|sbin)',
    r'chown\s+root\s+/etc/(passwd|shadow|sudoers)',
    r'echo\s+.*>>\s*/etc/(passwd|shadow|sudoers|crontab)',
    # Crypto mining
    r'xmrig|minerd|cpuminer',
    # Self-replication
    r'chmod\s+\+x\s+.*&&\s*\./.*&&\s*(crontab|systemctl)',
]
_DANGEROUS_RE = [re.compile(p, re.I | re.S) for p in _DANGEROUS_CMDS]

# ── Allowed scan targets (won't be blocked even if they look scary) ──────────
_SAFE_SCAN_PREFIXES = ('nmap ', 'nikto ', 'nuclei ', 'gobuster ', 'wpscan ',
                       'sqlmap ', 'whatweb ', 'wafw00f ', 'subfinder ',
                       'amass ', 'ffuf ', 'dirsearch ', 'hydra ', 'medusa ',
                       'hashcat ', 'john ', 'metasploit', 'msfconsole')


class GuardrailViolation(Exception):
    def __init__(self, reason: str, blocked_text: str = ''):
        super().__init__(reason)
        self.reason = reason
        self.blocked_text = blocked_text


class InputGuardrail:
    """Validates user-supplied messages before they reach the AI or shell."""

    @staticmethod
    def _decode_b64(text: str) -> str | None:
        """Try Base64 and Base32 decode; return decoded string or None."""
        for strip in (True, False):
            candidate = text.strip() if strip else text
            for decode in (base64.b64decode, base64.b32decode):
                try:
                    decoded = decode(candidate).decode('utf-8', errors='replace')
                    if len(decoded) > 4:
                        return decoded
                except (binascii.Error, ValueError, UnicodeDecodeError):
                    pass
        return None

    @classmethod
    def check(cls, message: str) -> str:
        """Return the (possibly decoded) message, or raise GuardrailViolation."""
        if not ENABLED:
            return message

        # Homograph check
        if _LATIN_LOOKALIKES.search(message):
            raise GuardrailViolation(
                'Message contains unicode homograph characters that may spoof latin text.',
                message,
            )

        # Normalise unicode and re-check
        normalised = unicodedata.normalize('NFKC', message)

        # Prompt injection on raw + normalised
        for text in (message, normalised):
            for pattern in _INJECTION_RE:
                if pattern.search(text):
                    raise GuardrailViolation(
                        f'Prompt injection detected: {pattern.pattern[:60]}',
                        text,
                    )

        # Base64 decode and re-scan
        decoded = cls._decode_b64(message)
        if decoded:
            for pattern in _INJECTION_RE:
                if pattern.search(decoded):
                    raise GuardrailViolation(
                        'Prompt injection detected in base64-encoded payload.',
                        decoded,
                    )

        return normalised


class OutputGuardrail:
    """Validates AI-generated commands before execution."""

    @staticmethod
    def check(command: str) -> str:
        """Return command if safe, raise GuardrailViolation if dangerous."""
        if not ENABLED:
            return command

        cmd_lower = command.lower().strip()

        # Allow known benign security tools
        if any(cmd_lower.startswith(p) for p in _SAFE_SCAN_PREFIXES):
            return command

        for pattern in _DANGEROUS_RE:
            if pattern.search(command):
                raise GuardrailViolation(
                    f'Dangerous command pattern blocked: {pattern.pattern[:60]}',
                    command,
                )

        return command


class Guardian:
    """Convenience wrapper combining both guardrails."""

    input = InputGuardrail()
    output = OutputGuardrail()

    @classmethod
    def check_input(cls, message: str) -> str:
        return InputGuardrail.check(message)

    @classmethod
    def check_output(cls, command: str) -> str:
        return OutputGuardrail.check(command)

    @classmethod
    def safe_check_input(cls, message: str) -> tuple[bool, str]:
        """Returns (is_safe, reason_or_message)."""
        try:
            return True, cls.check_input(message)
        except GuardrailViolation as e:
            return False, e.reason

    @classmethod
    def safe_check_output(cls, command: str) -> tuple[bool, str]:
        """Returns (is_safe, reason_or_command)."""
        try:
            return True, cls.check_output(command)
        except GuardrailViolation as e:
            return False, e.reason
