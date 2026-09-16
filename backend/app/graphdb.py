"""
In-process, SQLite-backed graph store standing in for Neo4j in this demo
environment (no Docker/Java/Homebrew available to run a real graph DB — see
the CTEM Demo v2 plan). Same node/edge schema and the same function
signatures a Neo4j-backed module would expose, so layer1/layer2 never know
the difference: nodes(id, label, props_json, version_no, updated_at),
edges(src_id, edge_type, dst_id, props_json, version_no, updated_at).

Labels: Service | Software | Vulnerability | Category | Owner
Edge types: AFFECTS | RUNS_ON | DEPENDS_ON | CHAINS_WITH | OWNED_BY

CHAINS_WITH edges are written once, at bootstrap, from each seed finding's
own chainedWith field (see scripts/load_graph.py) — not curated/discovered
at runtime. A future curation loop could add more via this same module; this
file's job is just to read/write whatever CHAINS_WITH edges exist, not to
decide when two vulnerabilities chain.
"""
from __future__ import annotations

import json
import math
import os
import re
import sqlite3
from datetime import datetime, timezone
from typing import Optional

from app.models import ServiceNode, SoftwareNode, OwnerNode, RawFinding
from app.retrieval import cosine

DB_PATH = os.path.join(os.path.dirname(__file__), "data", "graph.db")


def _conn() -> sqlite3.Connection:
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def init_db() -> None:
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = _conn()
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS nodes (
            id TEXT PRIMARY KEY,
            label TEXT NOT NULL,
            props_json TEXT NOT NULL,
            version_no INTEGER NOT NULL DEFAULT 1,
            updated_at TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS edges (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            src_id TEXT NOT NULL,
            edge_type TEXT NOT NULL,
            dst_id TEXT NOT NULL,
            props_json TEXT NOT NULL DEFAULT '{}',
            version_no INTEGER NOT NULL DEFAULT 1,
            updated_at TEXT NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_edges_src ON edges(src_id, edge_type);
        CREATE INDEX IF NOT EXISTS idx_edges_dst ON edges(dst_id, edge_type);
        """
    )
    conn.commit()
    conn.close()


def reset_db() -> None:
    """Used only by the bootstrap loader script for a clean re-seed."""
    if os.path.exists(DB_PATH):
        os.remove(DB_PATH)
    init_db()


init_db()  # idempotent (CREATE TABLE IF NOT EXISTS) — safe to run on every import


# --------------------------------------------------------------------------
# Node / edge writes
# --------------------------------------------------------------------------
def upsert_node(node_id: str, label: str, props: dict) -> None:
    conn = _conn()
    row = conn.execute("SELECT version_no FROM nodes WHERE id=?", (node_id,)).fetchone()
    version = (row["version_no"] + 1) if row else 1
    conn.execute(
        """
        INSERT INTO nodes (id, label, props_json, version_no, updated_at)
        VALUES (?, ?, ?, ?, ?)
        ON CONFLICT(id) DO UPDATE SET
            label=excluded.label, props_json=excluded.props_json,
            version_no=excluded.version_no, updated_at=excluded.updated_at
        """,
        (node_id, label, json.dumps(props), version, _now()),
    )
    conn.commit()
    conn.close()


def add_edge(src_id: str, edge_type: str, dst_id: str, props: Optional[dict] = None) -> None:
    conn = _conn()
    conn.execute(
        "INSERT INTO edges (src_id, edge_type, dst_id, props_json, version_no, updated_at) VALUES (?,?,?,?,1,?)",
        (src_id, edge_type, dst_id, json.dumps(props or {}), _now()),
    )
    conn.commit()
    conn.close()


def add_category(category_id: str, name: str, definition_text: str, embedding: list[float], source_taxonomy: str = "seed") -> None:
    upsert_node(
        category_id,
        "Category",
        {"name": name, "definition_text": definition_text, "source_taxonomy": source_taxonomy, "embedding": embedding},
    )


# --------------------------------------------------------------------------
# Reads
# --------------------------------------------------------------------------
def _node_row_to_dict(row: sqlite3.Row) -> dict:
    return {"id": row["id"], "label": row["label"], **json.loads(row["props_json"])}


def get_node(node_id: str) -> Optional[dict]:
    conn = _conn()
    row = conn.execute("SELECT * FROM nodes WHERE id=?", (node_id,)).fetchone()
    conn.close()
    return _node_row_to_dict(row) if row else None


def list_nodes(label: Optional[str] = None) -> list[dict]:
    conn = _conn()
    try:
        if label:
            rows = conn.execute("SELECT * FROM nodes WHERE label=? ORDER BY id", (label,)).fetchall()
        else:
            rows = conn.execute("SELECT * FROM nodes ORDER BY label, id").fetchall()
        return [_node_row_to_dict(r) for r in rows]
    finally:
        conn.close()


def list_edges() -> list[dict]:
    conn = _conn()
    try:
        rows = conn.execute("SELECT src_id, edge_type, dst_id FROM edges ORDER BY edge_type, src_id").fetchall()
        return [{"srcId": r["src_id"], "edgeType": r["edge_type"], "dstId": r["dst_id"]} for r in rows]
    finally:
        conn.close()


def _neighbors(conn: sqlite3.Connection, src_id: str, edge_type: str) -> list[str]:
    rows = conn.execute("SELECT dst_id FROM edges WHERE src_id=? AND edge_type=?", (src_id, edge_type)).fetchall()
    return [r["dst_id"] for r in rows]


def _strip(node: dict) -> dict:
    return {k: v for k, v in node.items() if k != "label"}


def get_service_software_owner(finding: RawFinding) -> tuple[list[ServiceNode], Optional[SoftwareNode], Optional[OwnerNode]]:
    """
    Resolves the Service(s)/Software/Owner for a finding by walking
    Vulnerability(implicit, keyed by softwareId) -AFFECTS-> Software -RUNS_ON-> Service
    -OWNED_BY-> Owner. Falls back to finding.affectedServiceIds directly if the
    software node hasn't been graphed yet (shouldn't happen for seed/injected
    findings, which always upsert their graph nodes before this is called).
    """
    conn = _conn()
    try:
        sw_row = conn.execute("SELECT * FROM nodes WHERE id=?", (finding.softwareId,)).fetchone()
        software = SoftwareNode(**_strip(_node_row_to_dict(sw_row))) if sw_row else None

        service_ids = _neighbors(conn, finding.softwareId, "RUNS_ON") if sw_row else []
        if not service_ids:
            service_ids = finding.affectedServiceIds

        services: list[ServiceNode] = []
        for sid in service_ids:
            row = conn.execute("SELECT * FROM nodes WHERE id=?", (sid,)).fetchone()
            if row:
                services.append(ServiceNode(**_strip(_node_row_to_dict(row))))

        primary = (
            next((s for s in services if s.tier == "crown-jewel"), None)
            or next((s for s in services if s.tier == "business-critical"), None)
            or (services[0] if services else None)
        )
        owner: Optional[OwnerNode] = None
        if primary:
            owner_ids = _neighbors(conn, primary.id, "OWNED_BY")
            if owner_ids:
                orow = conn.execute("SELECT * FROM nodes WHERE id=?", (owner_ids[0],)).fetchone()
                if orow:
                    owner = OwnerNode(**_strip(_node_row_to_dict(orow)))
        return services, software, owner
    finally:
        conn.close()


def compute_blast_radius(vuln_id: str, max_hops: int = 3) -> int:
    """
    BFS over DEPENDS_ON edges from the finding's directly-affected services,
    counting distinct services reached within max_hops (inclusive of the
    starting services). DEPENDS_ON is stored directionally but walked in
    both directions here — in this demo's synthetic topology, an outage on
    either side of a dependency can plausibly propagate impact, and a
    directional-only walk would understate blast radius for heavily-depended-on
    services.
    """
    conn = _conn()
    try:
        software_ids = _neighbors(conn, vuln_id, "AFFECTS")
        start_services: set[str] = set()
        for sw_id in software_ids:
            start_services.update(_neighbors(conn, sw_id, "RUNS_ON"))
        if not start_services:
            return 0

        visited = set(start_services)
        frontier = set(start_services)
        for _ in range(max_hops):
            next_frontier: set[str] = set()
            for sid in frontier:
                fwd = conn.execute("SELECT dst_id FROM edges WHERE src_id=? AND edge_type='DEPENDS_ON'", (sid,)).fetchall()
                rev = conn.execute("SELECT src_id FROM edges WHERE dst_id=? AND edge_type='DEPENDS_ON'", (sid,)).fetchall()
                next_frontier.update(r["dst_id"] for r in fwd)
                next_frontier.update(r["src_id"] for r in rev)
            next_frontier -= visited
            if not next_frontier:
                break
            visited |= next_frontier
            frontier = next_frontier
        return len(visited)
    finally:
        conn.close()


def get_chains_with(vuln_id: str) -> list[str]:
    conn = _conn()
    try:
        return _neighbors(conn, vuln_id, "CHAINS_WITH")
    finally:
        conn.close()


# --------------------------------------------------------------------------
# Category matching — versioned embeddings with exact cosine similarity.
# --------------------------------------------------------------------------
def finding_match_text(name: str, affected_component: str, severity_label: str) -> str:
    """
    Stable input shape for finding/category matching. Keeping approval-time
    re-embedding aligned with the triggering finding prevents a newly
    approved category from immediately falling below the same match gate.
    """
    return f"{name}. {affected_component}. {severity_label} severity."


def _normalized_terms(text: str) -> set[str]:
    stop = {"a", "an", "and", "in", "of", "the", "various", "severity", "finding", "findings"}
    return {token for token in re.findall(r"[a-z0-9]+", text.lower()) if token not in stop}


def _category_summary(node: dict) -> dict:
    return {"id": node["id"], "name": node["name"], "definition_text": node.get("definition_text", "")}


def governed_category_match(finding: RawFinding) -> tuple[Optional[dict], float, str]:
    """Prefer auditable taxonomy mappings before probabilistic similarity."""
    categories = {node["id"]: node for node in list_nodes("Category")}
    finding_terms = _normalized_terms(f"{finding.name} {finding.affectedComponent}")
    component_terms = _normalized_terms(finding.affectedComponent)

    component = finding.affectedComponent.lower()
    name = finding.name.lower()
    aliases = [
        (("browser" in component or any(term in name for term in ("sandbox escape", "chromium", "webkit", "gecko"))), "cat-browser-sandbox"),
        (("linux kernel" in component or "privilege escalation" in name), "cat-kernel-privesc"),
        (("oss" in component or "open source" in name or "remote code execution" in name), "cat-oss-rce"),
        # npm / package-manager dependency findings (e.g. lodash prototype pollution)
        # map to the OSS dependency category so live code-remediation demos flow
        # straight to scoring/governance rather than pausing at ontology curation.
        (("lodash" in component or "npm" in component or "prototype pollution" in name), "cat-oss-rce"),
        # first-party injection flaws (e.g. the agentic command-injection demo).
        (("injection" in name or "cwe-78" in name or "cwe-78" in finding.cve.lower()), "cat-injection"),
        (("gnupg" in component), "cat-crypto-overflow"),
        (("gnutls" in component), "cat-cert-parsing"),
        (("openssl" in component), "cat-crypto-overflow"),
    ]
    for matched, category_id in aliases:
        if matched and category_id in categories:
            return _category_summary(categories[category_id]), 0.95, "governed-alias"

    # Reuse an approved derived category for genuinely custom components,
    # but only after the governed starter aliases above. This prevents stale
    # demo-derived categories from shadowing the platform's base taxonomy.
    for node in categories.values():
        if not str(node.get("source_taxonomy", "")).startswith("derived"):
            continue
        category_terms = _normalized_terms(node["name"])
        if component_terms and component_terms.issubset(category_terms):
            return _category_summary(node), 1.0, "exact-component"

    rules = [
        ({"supply", "chain"}, "cat-supply-chain"),
        ({"authentication", "bypass"}, "cat-auth-bypass"),
        ({"certificate", "parsing"}, "cat-cert-parsing"),
        ({"insecure", "configuration"}, "cat-config-hardening"),
        ({"buffer", "overflow"}, "cat-crypto-overflow"),
    ]
    for required_terms, category_id in rules:
        if required_terms.issubset(finding_terms) and category_id in categories:
            return _category_summary(categories[category_id]), 0.9, "taxonomy-rule"
    return None, 0.0, "unmatched"


def find_duplicate_category(candidate_name: str) -> Optional[dict]:
    candidate_terms = _normalized_terms(candidate_name)
    for node in list_nodes("Category"):
        existing_terms = _normalized_terms(node["name"])
        if candidate_terms and (candidate_terms.issubset(existing_terms) or existing_terms.issubset(candidate_terms)):
            return _category_summary(node)
    return None


def match_category(embedding: list[float]) -> tuple[Optional[dict], float]:
    conn = _conn()
    try:
        rows = conn.execute("SELECT * FROM nodes WHERE label='Category'").fetchall()
        best: Optional[dict] = None
        best_score = -1.0
        for row in rows:
            props = json.loads(row["props_json"])
            score = cosine(embedding, props.get("embedding", []))
            if score > best_score:
                best_score = score
                best = {"id": row["id"], "name": props["name"], "definition_text": props["definition_text"]}
        return best, max(best_score, 0.0)
    finally:
        conn.close()
