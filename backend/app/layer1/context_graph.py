from typing import List
from app.models import RawFinding, ContextGraphRecord, Reachability, ServiceNode
from app.data.seed import OWNERS, POLICIES
from app import graphdb

"""
LAYER 1 — Context Graph & Threat Ontology
A continuously-updated context graph fusing COTS inventory data, business
context, vendor advisories, and threat intelligence.

This module fuses the Services / Software / Vulns / Owners / Policies /
Reachability entities for a given finding into one record — the same six
entity types that make up the Layer 1 band.

Services/Software/Owner resolution is delegated to graphdb.py (CTEM Demo v2
graph substitute — see that module's docstring) instead of filtering the
flat seed.py lists directly. Policy matching and attack-path synthesis stay
here unchanged: the graph substitute's schema has no Policy node/edge type,
so there's nothing to rewire for those two pieces.
"""


def build_context_graph_record(finding: RawFinding) -> ContextGraphRecord:
    affected_services, software_node, owner = graphdb.get_service_software_owner(finding)
    if owner is None:
        owner = OWNERS[0]  # same fallback the pre-graph version used when no services are affected

    primary_service = (
        next((s for s in affected_services if s.tier == "crown-jewel"), None)
        or next((s for s in affected_services if s.tier == "business-critical"), None)
        or (affected_services[0] if affected_services else None)
    )

    applicable_policies = []
    for p in POLICIES:
        if p.id == "pol-3" and any(s.internetExposed for s in affected_services):
            applicable_policies.append(p)
        elif p.id == "pol-2":
            applicable_policies.append(p)
        elif p.id == "pol-4" and primary_service and primary_service.tier != "standard":
            applicable_policies.append(p)
        elif p.id == "pol-1":
            applicable_policies.append(p)

    internet_exposed = affected_services[0].internetExposed if affected_services else False
    attack_path = _build_attack_path(finding, internet_exposed)

    return ContextGraphRecord(
        findingId=finding.id,
        services=affected_services,
        software=software_node,
        owner=owner,
        policies=applicable_policies,
        reachability=Reachability(runtimeReachable=finding.runtimeReachable, attackPath=attack_path),
    )


def _build_attack_path(finding: RawFinding, internet_exposed: bool) -> List[str]:
    """
    Builds a multi-hop attack path, e.g.:
    "Internet-exposed API > vulnerable package > service account token >
     internal queue > sensitive data store"
    """
    path: List[str] = []
    if internet_exposed:
        path.append("Internet-exposed API")
    path.append(f"vulnerable package ({finding.affectedComponent})")
    if finding.chainedWith:
        path.append("service account token")
        path.append("internal queue")
        if finding.severityLabel == "Critical":
            path.append("sensitive data store")
    return path
