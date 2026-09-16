#!/usr/bin/env python3
"""
Real runtime probe for the Log4Shell (CVE-2021-44228) fix: sends the actual
exploit trigger (a ${jndi:ldap://...} lookup string as a logged message) to
the built app and observes whether log4j-core makes the outbound JNDI/LDAP
connection attempt.

Safe by construction: no LDAP protocol is spoken and no class is ever served
back, so there's no code execution here -- accepting a bare TCP connection is
enough to prove the lookup was ATTEMPTED, which is exactly where vulnerable
and fixed log4j-core diverge (2.15+ disables message-based lookups by
default; 2.17.1 layers additional JNDI restrictions on top of that).

Usage: python3 scripts/jndi_probe.py <path-to-jar>
Prints CTEM_JNDI_PROBE_RESULT=OPEN|CLOSED and exits 1 (open/vulnerable) or
0 (closed/fixed) -- same pass/fail convention as the CTEM demo's other
runtime probes (prototype-pollution, command-injection).
"""
import socket
import subprocess
import sys
import threading

CONNECT_TIMEOUT_SECONDS = 8


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: jndi_probe.py <path-to-jar>", file=sys.stderr)
        return 2
    jar_path = sys.argv[1]

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]

    connected = threading.Event()

    def accept_once():
        listener.settimeout(CONNECT_TIMEOUT_SECONDS)
        try:
            conn, _addr = listener.accept()
            connected.set()
            conn.close()
        except socket.timeout:
            pass
        finally:
            listener.close()

    acceptor = threading.Thread(target=accept_once, daemon=True)
    acceptor.start()

    payload = f"${{jndi:ldap://127.0.0.1:{port}/a}}"
    print(f"[jndi_probe] invoking app with a JNDI payload targeting 127.0.0.1:{port}")
    try:
        result = subprocess.run(
            ["java", "-jar", jar_path, payload],
            timeout=CONNECT_TIMEOUT_SECONDS + 5,
            capture_output=True,
            text=True,
        )
        print(result.stdout)
        if result.stderr:
            print(result.stderr, file=sys.stderr)
    except subprocess.TimeoutExpired:
        print("[jndi_probe] app invocation timed out", file=sys.stderr)

    acceptor.join(timeout=CONNECT_TIMEOUT_SECONDS + 2)

    if connected.is_set():
        print("CTEM_JNDI_PROBE_RESULT=OPEN")
        print("[jndi_probe] a JNDI/LDAP lookup was attempted -- exploit path is OPEN")
        return 1

    print("CTEM_JNDI_PROBE_RESULT=CLOSED")
    print("[jndi_probe] no outbound JNDI/LDAP connection attempt observed -- exploit path is CLOSED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
