"""
Bootstrap loader for the graph substitute (backend/app/graphdb.py).

Run directly: `python -m app.scripts.load_graph` (from backend/, venv active).
Idempotent — resets and re-seeds graph.db every run, so it's safe to re-run
after editing seed data or the category taxonomy.
"""
from app import graphdb
from app.retrieval import embed_texts
from app.data.seed import SERVICES, SOFTWARE, OWNERS, FINDINGS

# --------------------------------------------------------------------------
# Synthetic DEPENDS_ON topology across the 5 seed services. Stands in for
# the real CMDB + runtime telemetry + IaC-graph reconciliation described in
# the architecture doc — none of those sources exist for this demo, so this
# is a hand-authored, plausible-looking dependency graph purely so blast
# radius has something non-trivial to traverse.
# --------------------------------------------------------------------------
SYNTHETIC_DEPENDS_ON = [
    ("svc-2", "svc-1"),  # Order Intake API depends on Customer Portal Gateway
    ("svc-2", "svc-5"),  # Order Intake API depends on Document Vault Service
    ("svc-4", "svc-1"),  # Partner Portal depends on Customer Portal Gateway
    ("svc-4", "svc-2"),  # Partner Portal depends on Order Intake API
    ("svc-3", "svc-5"),  # Pricing Engine depends on Document Vault Service
]

# --------------------------------------------------------------------------
# Starter Category taxonomy covering the seed findings' components. Category
# text is embedded through the same governed retrieval boundary as queries.
# --------------------------------------------------------------------------
STARTER_CATEGORIES = [
    ("cat-kernel-privesc", "Linux Kernel Privilege Escalation",
     "Local or remote privilege escalation vulnerabilities in the operating system kernel, "
     "allowing an attacker to gain elevated access beyond their initial foothold."),
    ("cat-browser-sandbox", "Browser Sandbox Escape",
     "Vulnerabilities in browser or embedded render engine sandboxing that allow code "
     "execution to break out of the sandboxed process into the host environment."),
    ("cat-oss-rce", "Open Source Dependency RCE",
     "Remote code execution vulnerabilities in third-party open source libraries and "
     "dependencies pulled into application builds via package managers."),
    ("cat-crypto-overflow", "Cryptographic Library Buffer Overflow",
     "Memory corruption and buffer overflow vulnerabilities in cryptographic libraries "
     "handling key material, certificates, or encrypted payloads."),
    ("cat-cert-parsing", "Certificate and TLS Parsing Vulnerability",
     "Parsing vulnerabilities in certificate handling, X.509 extensions, or TLS handshake "
     "code that can cause crashes, memory corruption, or validation bypass."),
    ("cat-auth-bypass", "Authentication Bypass",
     "Vulnerabilities allowing an attacker to bypass authentication or authorization checks "
     "and access protected resources or elevated functionality without valid credentials."),
    ("cat-supply-chain", "Software Supply Chain Compromise",
     "Compromise of build tooling, package registries, or upstream dependencies that "
     "introduces malicious or vulnerable code into the software supply chain."),
    ("cat-config-hardening", "Insecure Default Configuration",
     "Weaknesses arising from insecure default settings, missing hardening, or "
     "misconfiguration of otherwise-secure software components."),
    ("cat-injection", "Injection Flaws",
     "Improper neutralization of untrusted input that reaches an interpreter — OS "
     "command, SQL, or template injection (CWE-77/78/89)."),
]


def main() -> None:
    graphdb.reset_db()

    for o in OWNERS:
        graphdb.upsert_node(o.id, "Owner", {"name": o.name, "team": o.team})

    for s in SERVICES:
        graphdb.upsert_node(
            s.id, "Service",
            {"name": s.name, "ownerId": s.ownerId, "tier": s.tier,
             "internetExposed": s.internetExposed, "dataResidency": s.dataResidency},
        )
        graphdb.add_edge(s.id, "OWNED_BY", s.ownerId)

    for sw in SOFTWARE:
        graphdb.upsert_node(sw.id, "Software", {"name": sw.name, "version": sw.version, "eolDate": sw.eolDate})

    for f in FINDINGS:
        graphdb.upsert_node(
            f.id, "Vulnerability",
            {"cve": f.cve, "name": f.name, "affectedComponent": f.affectedComponent,
             "severityLabel": f.severityLabel, "discoveredBy": f.discoveredBy, "epss": f.epss,
             "cisaKev": f.cisaKev, "runtimeReachable": f.runtimeReachable, "raOnBooks": f.raOnBooks},
        )
        graphdb.add_edge(f.id, "AFFECTS", f.softwareId)
        for sid in f.affectedServiceIds:
            graphdb.add_edge(f.softwareId, "RUNS_ON", sid)
        for chained_id in f.chainedWith:
            graphdb.add_edge(f.id, "CHAINS_WITH", chained_id)

    for src, dst in SYNTHETIC_DEPENDS_ON:
        graphdb.add_edge(src, "DEPENDS_ON", dst)

    category_vectors, embedding_mode = embed_texts([f"{name}. {definition}" for _, name, definition in STARTER_CATEGORIES], "document")
    for (cat_id, name, definition), embedding in zip(STARTER_CATEGORIES, category_vectors):
        # Persist provider/model provenance with every category vector; the
        # definition remains available for the ontology UI and review queue.
        graphdb.add_category(cat_id, name, definition, embedding, source_taxonomy=f"seed:{embedding_mode}")

    print(f"Graph bootstrap complete: {len(OWNERS)} owners, {len(SERVICES)} services, "
          f"{len(SOFTWARE)} software, {len(FINDINGS)} vulnerabilities, "
          f"{len(SYNTHETIC_DEPENDS_ON)} synthetic DEPENDS_ON edges, "
          f"{len(STARTER_CATEGORIES)} categories. graph.db at {graphdb.DB_PATH}")


if __name__ == "__main__":
    main()
