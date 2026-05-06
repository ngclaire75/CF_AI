"""CF_AI AutoFix Agent — guardrail-validated fix generation and execution."""
import os
import subprocess
import logging
from typing import Optional

from .claude_agent import generate_fix
from .guardrails import Guardian, GuardrailViolation
from .telemetry import traced

log = logging.getLogger('cfai.autofix')

FIX_TIMEOUT = int(os.environ.get('CFAI_FIX_TIMEOUT', '60'))
DRY_RUN     = os.environ.get('CFAI_AUTOFIX_DRY_RUN', '0') == '1'


class AutoFixResult:
    def __init__(self, success: bool, command: str, output: str, blocked: bool = False,
                 block_reason: str = ''):
        self.success      = success
        self.command      = command
        self.output       = output
        self.blocked      = blocked
        self.block_reason = block_reason

    def to_dict(self) -> dict:
        return {
            'success':      self.success,
            'command':      self.command,
            'output':       self.output,
            'blocked':      self.blocked,
            'block_reason': self.block_reason,
        }


class AutoFixAgent:
    """Generates and optionally executes fixes for security findings."""

    @traced('autofix.run')
    def run(self, finding: dict) -> AutoFixResult:
        # 1. Generate fix command via Claude
        command = generate_fix(finding)
        if not command:
            return AutoFixResult(False, '', 'Claude could not generate a fix command.')

        command = command.strip()

        # 2. Guardrail check
        safe, reason = Guardian.safe_check_output(command)
        if not safe:
            log.warning('AutoFix BLOCKED for finding "%s": %s', finding.get('title'), reason)
            return AutoFixResult(
                success=False,
                command=command,
                output='',
                blocked=True,
                block_reason=reason,
            )

        # 3. Dry-run mode — skip execution
        if DRY_RUN:
            return AutoFixResult(True, command, '[dry-run: command not executed]')

        # 4. Execute
        return self._execute(command, finding)

    def _execute(self, command: str, finding: dict) -> AutoFixResult:
        try:
            result = subprocess.run(
                command, shell=True, capture_output=True, text=True,
                timeout=FIX_TIMEOUT, cwd='/root',
                env={**os.environ, 'TERM': 'dumb'},
            )
            output = (result.stdout + result.stderr).strip()
            success = result.returncode == 0
            log.info('AutoFix "%s" exit=%d', finding.get('title', ''), result.returncode)
            return AutoFixResult(success, command, output)
        except subprocess.TimeoutExpired:
            return AutoFixResult(False, command, f'Fix timed out after {FIX_TIMEOUT}s')
        except Exception as exc:
            return AutoFixResult(False, command, f'Execution error: {exc}')

    def preview(self, finding: dict) -> str:
        """Return the fix command without executing it."""
        return generate_fix(finding) or ''


_agent: Optional[AutoFixAgent] = None


def get_autofix() -> AutoFixAgent:
    global _agent
    if _agent is None:
        _agent = AutoFixAgent()
    return _agent
