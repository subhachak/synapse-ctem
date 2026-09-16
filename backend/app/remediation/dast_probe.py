"""
Black-box DAST prober.

Unlike the SCA scanner (reads the manifest) or the SAST scanner (pattern-matches
the source), this boots the *running* application and probes it over real HTTP —
the defining characteristic of Dynamic Application Security Testing. It has no
knowledge of the source; it only sends a request and inspects the response.

Used by both detection (is the payload reflected unescaped?) and the post-fix
runtime verification (is it now neutralised?), so "found" and "closed" are proven
by the same dynamic method.
"""
from __future__ import annotations

import socket
import subprocess
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass

# A distinctive, harmless marker payload. If it comes back verbatim inside a
# <script> tag, the endpoint reflects unescaped HTML (exploitable). If it comes
# back HTML-entity-encoded (&lt;script&gt;), output encoding neutralised it.
XSS_MARKER = "ctem-dast-probe"
XSS_PAYLOAD = f"<script>{XSS_MARKER}</script>"
_RAW_REFLECTION = XSS_PAYLOAD  # the unescaped form we must NOT see after a fix


@dataclass
class ProbeResult:
    reflected: bool          # True = payload came back unescaped (vulnerable)
    status: int
    body: str
    detail: str
    ok: bool = True          # False only if the app could not be booted/reached


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_healthy(port: int, timeout_s: float = 8.0) -> bool:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/healthz", timeout=1) as r:
                if r.status == 200:
                    return True
        except (urllib.error.URLError, ConnectionError, OSError):
            time.sleep(0.15)
    return False


def probe_reflected_xss(ws_path: str, entry: str = "src/server.js") -> ProbeResult:
    """Boot the app on an ephemeral port, send an XSS payload to /greeting, and
    report whether it is reflected unescaped. Always tears the server down."""
    import os

    port = _free_port()
    proc = subprocess.Popen(
        ["node", entry],
        cwd=ws_path,
        env={**os.environ, "PORT": str(port)},
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    try:
        if not _wait_healthy(port):
            return ProbeResult(reflected=False, status=0, body="", ok=False,
                               detail=f"target app did not become healthy on :{port}")
        url = f"http://127.0.0.1:{port}/greeting?name=" + urllib.parse.quote(XSS_PAYLOAD)
        try:
            with urllib.request.urlopen(url, timeout=3) as r:
                status = r.status
                body = r.read().decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            status, body = e.code, e.read().decode("utf-8", "replace")
        reflected = _RAW_REFLECTION in body
        neutralised = ("&lt;script&gt;" in body) or (XSS_MARKER in body and not reflected)
        if reflected:
            detail = f"Reflected XSS CONFIRMED: payload returned unescaped in HTTP {status} response body."
        elif neutralised:
            detail = f"Payload returned HTML-entity-encoded in HTTP {status} response; reflected XSS not exploitable."
        else:
            detail = f"Payload not reflected in HTTP {status} response."
        return ProbeResult(reflected=reflected, status=status, body=body, detail=detail)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            proc.kill()
