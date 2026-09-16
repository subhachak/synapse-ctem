from app.models import ServiceNode, SoftwareNode, OwnerNode, PolicyNode, RawFinding

# ---------------------------------------------------------------------------
# Owners (Layer 1 — Owners)
# ---------------------------------------------------------------------------
OWNERS = [
    OwnerNode(id="own-1", name="Platform Engineering", team="Core Infra"),
    OwnerNode(id="own-2", name="App Security", team="AppSec"),
    OwnerNode(id="own-3", name="Core Platform Services", team="Platform Systems"),
    OwnerNode(id="own-4", name="Data Platform", team="Data Engineering"),
]

# ---------------------------------------------------------------------------
# Services (Layer 1 — Services). Synthetic, domain-neutral app names, since
# real CMDB data isn't available in this demo — tiering uses the reference
# architecture's "business critical assets" / "crown-jewel proximity" language.
# ---------------------------------------------------------------------------
SERVICES = [
    ServiceNode(id="svc-1", name="Customer Portal Gateway", ownerId="own-3", tier="crown-jewel", internetExposed=True, dataResidency="us-east"),
    ServiceNode(id="svc-2", name="Order Intake API", ownerId="own-1", tier="business-critical", internetExposed=True, dataResidency="us-east"),
    ServiceNode(id="svc-3", name="Pricing Engine", ownerId="own-4", tier="crown-jewel", internetExposed=False, dataResidency="us-east"),
    ServiceNode(id="svc-4", name="Partner Portal", ownerId="own-2", tier="standard", internetExposed=True, dataResidency="us-west"),
    ServiceNode(id="svc-5", name="Document Vault Service", ownerId="own-1", tier="business-critical", internetExposed=False, dataResidency="us-east"),
]

# ---------------------------------------------------------------------------
# Software (Layer 1 — Software / EoL components)
# ---------------------------------------------------------------------------
SOFTWARE = [
    SoftwareNode(id="sw-browser-engines", name="Chromium/WebKit/Gecko (embedded render components)", version="various"),
    SoftwareNode(id="sw-linux-kernel", name="Linux Kernel", version="5.15.x", eolDate="2026-12-01"),
    SoftwareNode(id="sw-oss-deps", name="Shared OSS dependency set", version="various"),
    SoftwareNode(id="sw-gnupg", name="GnuPG", version="2.4.1"),
    SoftwareNode(id="sw-gnutls-certtool", name="GnuTLS certtool", version="3.8.2"),
    SoftwareNode(id="sw-gnutls-san", name="GnuTLS (otherName SAN export path)", version="3.8.2"),
    SoftwareNode(id="sw-openssl", name="OpenSSL (PKCS#12 PBMAC1/PBKDF2 path)", version="3.2.1"),
]

# ---------------------------------------------------------------------------
# Policies (Layer 1 — Policies). Natural-language, matching Layer 2's
# "verify proposed actions against natural-language policies" behavior.
# ---------------------------------------------------------------------------
POLICIES = [
    PolicyNode(id="pol-1", description="Auto-remediate only low-blast-radius package upgrades in non-prod"),
    PolicyNode(id="pol-2", description="Require AppSec + service owner approval for prod patching"),
    PolicyNode(id="pol-3", description="If exploitability > threshold and external exposure=true, auto-apply compensating control within 15 minutes"),
    PolicyNode(id="pol-4", description="Any remediation touching customer-facing PII services requires NAIC/NYDFS evidence capture"),
]

# ---------------------------------------------------------------------------
# Findings — 7 representative rows modelled on an AI-discovered exposure
# report (autonomous pentest + code-analysis tooling)
# ---------------------------------------------------------------------------
FINDINGS = [
    RawFinding(
        id="find-1", cve="N/A (exploit chain)", name="Sandbox Escape + Browser Exploit Chain",
        affectedComponent="Browser engines (Chromium/WebKit/Gecko)", severityLabel="Critical",
        # Deliberately scores below the Tier 0 threshold before policy so the
        # demo visibly proves that the KEV floor changes the disposition.
        cvssBase=8.5,
        discoveredBy="Mythos", affectedServiceIds=["svc-4"], softwareId="sw-browser-engines",
        epss=0.85, cisaKev=True, runtimeReachable=True, chainedWith=["find-2"], raOnBooks=True,
    ),
    RawFinding(
        id="find-2", cve="N/A (chain, multiple CVEs)", name="Privilege Escalation Chains",
        affectedComponent="Linux Kernel", severityLabel="Critical", discoveredBy="Mythos",
        cvssBase=9.8,
        affectedServiceIds=["svc-1", "svc-2", "svc-3", "svc-5"], softwareId="sw-linux-kernel",
        epss=0.86, cisaKev=True, runtimeReachable=True, chainedWith=["find-1", "find-3"], raOnBooks=False,
    ),
    RawFinding(
        id="find-3", cve="N/A (multiple OSS CVEs)", name="Remote Code Execution (various OSS libs)",
        affectedComponent="OSS dependencies", severityLabel="Critical", discoveredBy="Mythos",
        cvssBase=9.8,
        affectedServiceIds=["svc-2", "svc-4", "svc-5"], softwareId="sw-oss-deps",
        epss=0.78, cisaKev=True, runtimeReachable=True, chainedWith=["find-2"], raOnBooks=True,
    ),
    RawFinding(
        id="find-4", cve="CVE-2025-15467", name="TPM2 PKDECRYPT Buffer Overflow",
        affectedComponent="GnuPG", severityLabel="High", discoveredBy="Codex",
        cvssBase=8.1,
        affectedServiceIds=["svc-1", "svc-3"], softwareId="sw-gnupg",
        epss=0.42, cisaKev=False, runtimeReachable=True, chainedWith=[], raOnBooks=False,
    ),
    RawFinding(
        id="find-5", cve="CVE-2025-32990", name="GnuTLS certtool Heap-Buffer Overflow (Off-by-One)",
        affectedComponent="GnuTLS", severityLabel="High", discoveredBy="Codex",
        cvssBase=7.5,
        affectedServiceIds=["svc-2", "svc-5"], softwareId="sw-gnutls-certtool",
        epss=0.31, cisaKev=False, runtimeReachable=False, chainedWith=[], raOnBooks=False,
    ),
    RawFinding(
        id="find-6", cve="CVE-2025-32988", name="GnuTLS Double-Free in otherName SAN Export",
        affectedComponent="GnuTLS", severityLabel="High", discoveredBy="Codex",
        cvssBase=7.5,
        affectedServiceIds=["svc-3"], softwareId="sw-gnutls-san",
        epss=0.27, cisaKev=False, runtimeReachable=False, chainedWith=[], raOnBooks=False,
    ),
    RawFinding(
        id="find-7", cve="CVE-2025-11187", name="PKCS#12 PBMAC1 PBKDF2 Overflow + MAC Bypass",
        affectedComponent="OpenSSL", severityLabel="Medium", discoveredBy="Codex",
        cvssBase=5.3,
        affectedServiceIds=["svc-4"], softwareId="sw-openssl",
        epss=0.12, cisaKev=False, runtimeReachable=False, chainedWith=[], raOnBooks=False,
    ),
]
