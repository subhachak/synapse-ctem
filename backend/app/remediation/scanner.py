"""
Dependency scanner. Prefers the real `npm audit`; falls back to a shipped,
deterministic OSV-shaped database matched against the actually-installed version.

The closure criterion the live adapter cares about is advisory-specific: does the
finding's `targetAdvisory` still affect the installed version? Unrelated residual
advisories on the same package are reported but do not block closure (they are
separate findings), which matches how real remediation certifies a specific CVE.
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field

from app.models import RemediationTarget
from app.remediation._util import run


def _present(target_advisory: str, ids) -> bool:
    """Case-insensitive membership — GHSA ids are conventionally lowercase but sources vary."""
    wanted = target_advisory.casefold()
    return any(str(i).casefold() == wanted for i in ids)

_VULN_DB_PATH = os.path.join(os.path.dirname(__file__), "vuln_db.json")
_GHSA_RE = re.compile(r"GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}", re.IGNORECASE)


@dataclass
class ScanResult:
    scannerName: str
    installedVersion: str
    targetAdvisory: str
    targetPresent: bool
    advisories: list[dict] = field(default_factory=list)  # [{id, severity, title, url}]
    raw: str = ""

    def summary(self) -> str:
        state = "PRESENT" if self.targetPresent else "absent"
        others = [a["id"] for a in self.advisories if a["id"].casefold() != self.targetAdvisory.casefold()]
        extra = f"; {len(others)} unrelated advisory(ies) remain: {', '.join(others)}" if others else ""
        return (
            f"{self.scannerName}: {self.targetAdvisory} {state} on "
            f"{self.installedVersion}{extra}"
        )


def _installed_version(workspace: str, package: str) -> str:
    pkg_json = os.path.join(workspace, "node_modules", package, "package.json")
    if os.path.exists(pkg_json):
        try:
            with open(pkg_json) as handle:
                return json.load(handle).get("version", "unknown")
        except (OSError, json.JSONDecodeError):
            pass
    # Fall back to the lockfile pin.
    lock = os.path.join(workspace, "package-lock.json")
    if os.path.exists(lock):
        try:
            with open(lock) as handle:
                data = json.load(handle)
            node = data.get("packages", {}).get(f"node_modules/{package}")
            if node and node.get("version"):
                return node["version"]
        except (OSError, json.JSONDecodeError):
            pass
    return "unknown"


def _cmp_version(a: str, b: str) -> int:
    def parts(v: str) -> list[int]:
        nums = []
        for token in re.split(r"[.\-+]", v):
            m = re.match(r"\d+", token)
            nums.append(int(m.group()) if m else 0)
        return nums

    pa, pb = parts(a), parts(b)
    for x, y in zip(pa + [0] * (len(pb) - len(pa)), pb + [0] * (len(pa) - len(pb))):
        if x != y:
            return -1 if x < y else 1
    return 0


def _satisfies(version: str, constraints: list[dict]) -> bool:
    ops = {
        "<": lambda c: c < 0, "<=": lambda c: c <= 0,
        ">": lambda c: c > 0, ">=": lambda c: c >= 0, "==": lambda c: c == 0,
    }
    for constraint in constraints:
        cmp = _cmp_version(version, constraint["version"])
        if not ops.get(constraint["op"], lambda _c: False)(cmp):
            return False
    return True


def _scan_offline(workspace: str, target: RemediationTarget, installed: str) -> ScanResult:
    with open(_VULN_DB_PATH) as handle:
        db = json.load(handle)
    advisories = []
    for adv in db.get("advisories", []):
        if adv["package"] != target.vulnerablePackage:
            continue
        if installed != "unknown" and _satisfies(installed, adv.get("vulnerable", [])):
            advisories.append({"id": adv["id"], "severity": adv["severity"], "title": adv["title"], "url": adv["url"]})
    ids = {a["id"] for a in advisories}
    return ScanResult(
        scannerName="offline-osv-db",
        installedVersion=installed,
        targetAdvisory=target.targetAdvisory,
        targetPresent=_present(target.targetAdvisory, ids),
        advisories=advisories,
        raw=json.dumps({"installed": installed, "advisories": advisories}, indent=2),
    )


def _scan_npm_audit(workspace: str, target: RemediationTarget, installed: str) -> ScanResult | None:
    result = run(["npm", "audit", "--json"], cwd=workspace, timeout=90)
    # npm audit exits non-zero when advisories are found — that is expected, not an error.
    if not result.out.strip():
        return None
    try:
        data = json.loads(result.out)
    except json.JSONDecodeError:
        return None
    vulns = data.get("vulnerabilities")
    if vulns is None:
        return None  # legacy npm audit schema; let the offline DB handle it deterministically
    entry = vulns.get(target.vulnerablePackage)
    advisories: list[dict] = []
    if entry:
        for via in entry.get("via", []):
            if not isinstance(via, dict):
                continue
            url = via.get("url", "")
            match = _GHSA_RE.search(url)
            advisories.append({
                "id": match.group() if match else (via.get("title") or url),
                "severity": via.get("severity", entry.get("severity", "unknown")),
                "title": via.get("title", ""),
                "url": url,
            })
    ids = {a["id"] for a in advisories}
    return ScanResult(
        scannerName="npm-audit",
        installedVersion=installed,
        targetAdvisory=target.targetAdvisory,
        targetPresent=_present(target.targetAdvisory, ids),
        advisories=advisories,
        raw=json.dumps({"metadata": data.get("metadata", {}).get("vulnerabilities", {}), "advisories": advisories}, indent=2),
    )


def scan(workspace: str, target: RemediationTarget) -> ScanResult:
    """Scan the workspace for advisories affecting the target package."""
    installed = _installed_version(workspace, target.vulnerablePackage)
    try:
        live = _scan_npm_audit(workspace, target, installed)
    except Exception:  # pragma: no cover - defensive; never fail the pipeline on scanner errors
        live = None
    if live is not None:
        return live
    return _scan_offline(workspace, target, installed)


# ---------------------------------------------------------------------------
# Maven ecosystem (log4j scenario). No JVM needed for this part -- it's a
# real parse of the actual pom.xml, matched against the same offline
# OSV-shaped vuln_db.json used as npm's fallback. There's no live
# `mvn dependency-check`-equivalent wired up here (would need an NVD data
# feed and a JVM); build/test/the runtime exploit probe run for real on
# GitHub Actions instead -- see actions_ci.py and
# strategies/maven_ci_dependency.py.
# ---------------------------------------------------------------------------
import xml.etree.ElementTree as _ET  # noqa: E402 (grouped with the maven-specific block on purpose)

_POM_NS = {"m": "http://maven.apache.org/POM/4.0.0"}


def _installed_version_maven(workspace: str, target: RemediationTarget) -> str:
    """Reads the tracked dependency's version from pom.xml. This target app's
    convention is a <properties> indirection (log4j-core/log4j-api both key
    off target.versionProperty), so that's resolved first; a direct
    <dependency><version> is the fallback for poms that don't use one."""
    pom_path = os.path.join(workspace, target.manifest or "pom.xml")
    if not os.path.exists(pom_path):
        return "unknown"
    try:
        root = _ET.parse(pom_path).getroot()
    except _ET.ParseError:
        return "unknown"

    def _property(name: str) -> str | None:
        el = root.find(f"m:properties/m:{name}", _POM_NS)
        return el.text.strip() if el is not None and el.text else None

    if target.versionProperty:
        prop_value = _property(target.versionProperty)
        if prop_value:
            return prop_value

    artifact = target.vulnerablePackage.split(":")[-1]
    for dep in root.findall(".//m:dependency", _POM_NS):
        artifact_el = dep.find("m:artifactId", _POM_NS)
        version_el = dep.find("m:version", _POM_NS)
        if artifact_el is None or artifact_el.text != artifact or version_el is None or not version_el.text:
            continue
        version = version_el.text.strip()
        if version.startswith("${") and target.versionProperty:
            prop_value = _property(target.versionProperty)
            if prop_value:
                return prop_value
        return version
    return "unknown"


def scan_maven(workspace: str, target: RemediationTarget) -> ScanResult:
    installed = _installed_version_maven(workspace, target)
    result = _scan_offline(workspace, target, installed)
    result.scannerName = "offline-osv-db-maven"
    return result


def mutate_maven(workspace: str, target: RemediationTarget) -> tuple[bool, str]:
    """Bumps the tracked dependency version in pom.xml via a precise, minimal
    text substitution rather than a full XML parse+serialize -- keeps the PR
    diff a clean one-line change instead of a whole-file reformat (same
    reasoning as the npm strategy's targeted dict update to package.json)."""
    pom_path = os.path.join(workspace, target.manifest or "pom.xml")
    with open(pom_path) as handle:
        content = handle.read()
    old_tag = f"<{target.versionProperty}>{target.currentVersion}</{target.versionProperty}>"
    new_tag = f"<{target.versionProperty}>{target.fixedVersion}</{target.versionProperty}>"
    if old_tag not in content:
        return False, f"{old_tag!r} not found in {target.manifest}"
    with open(pom_path, "w") as handle:
        handle.write(content.replace(old_tag, new_tag, 1))
    return True, f"Bumped {target.versionProperty} {target.currentVersion} -> {target.fixedVersion}"
