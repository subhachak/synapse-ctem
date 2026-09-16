"""Small subprocess helper shared across the remediation adapter."""
from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass


@dataclass
class ProcResult:
    ok: bool
    code: int
    out: str  # combined stdout+stderr

    def tail(self, n: int = 1200) -> str:
        return self.out[-n:]


def run(cmd: list[str], cwd: str, timeout: int = 120, env: dict | None = None) -> ProcResult:
    """Run a command, capturing combined output. Never raises on non-zero exit."""
    full_env = {**os.environ, **(env or {})}
    try:
        proc = subprocess.run(
            cmd, cwd=cwd, timeout=timeout, env=full_env,
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        )
        return ProcResult(ok=proc.returncode == 0, code=proc.returncode, out=proc.stdout or "")
    except FileNotFoundError as exc:
        return ProcResult(ok=False, code=127, out=f"command not found: {exc}")
    except subprocess.TimeoutExpired as exc:
        return ProcResult(ok=False, code=124, out=f"timed out after {timeout}s: {exc}")
