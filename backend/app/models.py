"""
Type model — mirrors the entity/field names used across the 3-layer CTEM
reference architecture: Context Graph & Threat Ontology, Adversarial Reasoning
Engine, and Agentic AI (Triage / Planning / Implementation / Governance).
"""
from __future__ import annotations
from typing import List, Optional, Literal, Dict
from pydantic import BaseModel, model_validator


# --------------------------------------------------------------------------
# LAYER 1 — Context Graph & Threat Ontology entity types
# --------------------------------------------------------------------------
class ServiceNode(BaseModel):
    id: str
    name: str
    ownerId: str
    tier: Literal["crown-jewel", "business-critical", "standard"]
    internetExposed: bool
    dataResidency: str


class SoftwareNode(BaseModel):
    id: str
    name: str
    version: str
    eolDate: Optional[str] = None


class OwnerNode(BaseModel):
    id: str
    name: str
    team: str


class PolicyNode(BaseModel):
    id: str
    description: str


class RemediationTarget(BaseModel):
    """
    Points a finding at a real code repository so the Implementation/Verification
    stage can execute a live remediation (clone the repo, edit the manifest, run
    the tests, re-scan, push a branch, open a PR) instead of the simulated
    adapter. When absent, the pipeline uses the deterministic simulated-adapter
    evidence path unchanged.

    The primary source of truth is a GitHub repo (`remoteRepo`): the pipeline
    clones it, works on a branch locally, and pushes that branch for a PR. The
    `repoSnapshot` local path is only a fallback for offline/test runs when no
    remote repo is configured.
    """
    # "maven" targets have no local JDK/Maven assumption at all — their
    # scan/mutate are local (pom.xml is just XML), but build/test/runtime-probe
    # run for real on GitHub Actions (see strategies/maven_ci_dependency.py and
    # remediation/actions_ci.py), since the demo host isn't guaranteed to have
    # a JVM available.
    ecosystem: Literal["npm", "maven"] = "npm"
    # Which remediation strategy handles this finding (a classifier hint the
    # scanner sets in production; declared in the demo payload). See
    # app/remediation/strategies/.
    strategy: Literal["dependency", "agentic-code", "dast-web", "maven-dependency"] = "dependency"
    # GitHub "owner/repo" (or a full clone URL) the pipeline clones to work on.
    # May be overridden at runtime by CTEM_REMEDIATION_REPO (npm ecosystem) or
    # CTEM_LOG4J_REMEDIATION_REPO (maven ecosystem) — see github_pr.resolve_repo,
    # deliberately two separate env vars so the two demo targets can't clobber
    # each other.
    remoteRepo: str = ""
    baseBranch: str = "main"
    # Local fallback snapshot, relative to backend/app (e.g.
    # "remediation_targets/node-payments-api"). Used ONLY when no remote repo is
    # configured — offline dev and the test suite.
    repoSnapshot: str = ""
    manifest: str = "package.json"
    testCommand: str = "npm test"
    # --- dependency-strategy fields (a version bump; shared by npm's
    #     DeterministicDependencyStrategy and maven's MavenCiDependencyStrategy) ---
    vulnerablePackage: str = ""
    currentVersion: str = ""
    fixedVersion: str = ""
    # The specific advisory this finding tracks — the closure criterion is that
    # THIS identifier stops affecting the installed version, not that the package
    # has zero advisories (unrelated residual advisories become separate findings).
    targetAdvisory: str = ""  # GHSA id (npm audit) — e.g. "GHSA-jf85-cpcp-j695"
    targetCve: str = ""       # human-facing CVE/CWE alias, e.g. "CVE-2019-10744"
    # --- agentic-code-strategy fields (a first-party source fix) ---
    filePath: str = ""        # source file to remediate, e.g. "src/server.js"
    vulnClass: str = ""       # e.g. "command-injection" (CWE-78)
    # --- maven-dependency-strategy fields (GitHub-Actions-verified) ---
    # The pom.xml property CTEM bumps for the fix (see the target app's pom.xml
    # -- log4j-core/log4j-api both key off this one property).
    versionProperty: str = ""
    # Workflow file name in the target repo (backend triggers it via
    # workflow_dispatch and polls its run) — see actions_ci.py.
    ciWorkflow: str = "ctem-verify.yml"


class RawFinding(BaseModel):
    id: str
    cve: str
    name: str
    affectedComponent: str
    severityLabel: Literal["Critical", "High", "Medium", "Low"]
    cvssBase: float = 0.0  # compatibility for checkpoints created before governed scoring
    cvssSource: Literal["advisory", "analyst-provided", "severity-inferred", "legacy-unknown"] = "advisory"
    demoScenario: Literal["standard", "sandbox-failure"] = "standard"
    discoveredBy: Literal["Mythos", "Codex", "Scanner"]
    affectedServiceIds: List[str]
    softwareId: str
    epss: float
    cisaKev: bool
    runtimeReachable: bool
    chainedWith: List[str]
    raOnBooks: bool
    # Optional live-remediation pointer. Findings without it keep the simulated path.
    remediationTarget: Optional[RemediationTarget] = None


class Reachability(BaseModel):
    runtimeReachable: bool
    attackPath: List[str]


class ContextGraphRecord(BaseModel):
    findingId: str
    services: List[ServiceNode]
    software: SoftwareNode
    owner: OwnerNode
    policies: List[PolicyNode]
    reachability: Reachability


# --------------------------------------------------------------------------
# LAYER 2 — Governed exposure-risk output
# Residual Risk = P(exploitation) x Business Impact x (1 - validated controls)
# Policy rules then determine the final action tier without hiding the
# calculated result. No LLM participates in this calculation.
# --------------------------------------------------------------------------
class ReasoningEngineRecord(BaseModel):
    findingId: str
    exploitationLikelihood: float = 0.0
    businessImpact: float = 0.0
    residualRisk: float = 0.0
    likelihoodInputs: Dict[str, float] = {}
    likelihoodContributions: Dict[str, float] = {}
    impactInputs: Dict[str, float] = {}
    impactContributions: Dict[str, float] = {}
    validatedControlEffectiveness: float = 0.0
    scoringFormula: str = "likelihood × impact × (1 − validated controls)"
    calculatedRiskPriority: float = 0.0
    calculatedActionTier: Literal["Tier 0", "Tier 1", "Tier 2", "Tier 3"] = "Tier 3"
    riskPriority: float
    exploitableIssue: bool
    chainedVulns: List[str]
    businessCriticalAsset: bool
    blastRadius: int
    predictiveRisk: Literal["rising", "stable", "declining"]
    remediationApproach: str
    actionTier: Literal["Tier 0", "Tier 1", "Tier 2", "Tier 3"]
    actionTierLabel: str
    riskModelVersion: str = "legacy-unversioned"
    decisionMethod: Literal[
        "deterministic-model", "deterministic-model+policy-override", "deterministic-model+human-override"
    ] = "deterministic-model"
    policyOverrides: List[str] = []


class DataQualityAssessment(BaseModel):
    findingId: str
    fieldStatus: Dict[str, Literal["present", "inferred", "missing", "simulated"]]
    completenessScore: float
    decision: Literal["ready", "review-required"]
    issues: List[str] = []


class PlausibilityAssessment(BaseModel):
    findingId: str
    assessment: Literal["plausible", "questionable", "inconsistent"]
    confidence: float
    concerns: List[str] = []
    recommendedAction: Literal["proceed", "human-score-review"]
    advisoryNarrative: str
    advisoryMode: Literal["anthropic", "deterministic-fallback"] = "deterministic-fallback"
    authoritative: bool = False


# --------------------------------------------------------------------------
# LAYER 3 — Agent outputs
# --------------------------------------------------------------------------
class TriageAgentOutput(BaseModel):
    findingId: str
    riskScore: float
    tier: str
    reasoningChain: List[str]
    suppressed: bool
    suppressionReason: Optional[str] = None
    confidence: float
    humanOverrideAvailable: bool = True
    retrievalMode: str = "not-run"
    retrievalCitations: List[Dict] = []


class PlanningAgentOutput(BaseModel):
    findingId: str
    fixApproach: str
    targetVersionOrConfig: str
    predictedBreakingChanges: List[str]
    transitiveDependencies: List[str]
    compensatingControls: List[str]
    # How the fix is proven closed — the deterministic validation-gate steps the
    # remediation orchestrator will enforce (re-scan / runtime probe / tests).
    # Distinct from compensatingControls (interim risk reduction while unpatched).
    validationPlan: List[str] = []
    effortEstimate: Literal["low", "medium", "high"]
    routedOwnerId: str
    mitigationRecipe: str
    retrievalMode: str = "not-run"
    retrievalCitations: List[Dict] = []


class ImplementationAgentOutput(BaseModel):
    findingId: str
    generatedTestSuite: List[str]
    coverageDelta: str
    untestablePaths: List[str]
    prTitle: str
    diffSummary: str
    rationale: str
    selfAssessedConfidence: float
    sandboxedExecution: bool = True
    noProdDataOrSecrets: bool = True
    humanInTheLoop: bool = True
    retrievalMode: str = "not-run"
    retrievalCitations: List[Dict] = []


class PolicyCheck(BaseModel):
    policyId: str
    passed: bool
    note: str


class GovernanceAgentOutput(BaseModel):
    findingId: str
    auditArtifactId: str
    provenanceWho: str
    provenanceWhat: str
    provenanceWhy: str
    controlsMapped: List[str]
    policyChecks: List[PolicyCheck]
    crossRegionFlag: bool
    customerNotificationTriggered: bool
    approvalStatus: Literal["auto-approved", "pending human approval", "blocked"]
    retrievalMode: str = "not-run"
    retrievalCitations: List[Dict] = []


class VerificationEvidence(BaseModel):
    evidenceType: Literal["sandbox-test", "deployment-proof", "post-change-rescan", "runtime-path-check"]
    artifactId: str
    result: Literal["pass", "fail", "not-run"]
    source: Literal["simulated-adapter", "live-integration"] = "simulated-adapter"
    detail: str
    issuedBy: str = "legacy-unknown"
    subjectFindingId: str = "legacy-unknown"
    observedAt: str = "legacy-unknown"
    artifactDigest: str = "legacy-unknown"
    # Populated by the live-integration adapter; empty for the simulated path.
    command: str = ""       # the real command executed (e.g. "npm test")
    logExcerpt: str = ""    # tail of that command's real output
    prUrl: str = ""         # deployment-proof only: the real pull-request URL


# --------------------------------------------------------------------------
# Agentic remediation orchestration trace.
# The remediation phase is run by an orchestrator that delegates to named
# sub-agents (scanner, planner, implementer, tester) and, for agentic
# strategies, loops planner->implementer->tester until the deterministic
# validation gate is satisfied or a bounded attempt budget is exhausted. Each
# step records whether it was DETERMINISTIC (a rule/lookup) or AGENTIC (an LLM
# decision/synthesis) — the "agentic execution, deterministic guardrails" story
# made auditable. No step here sets a risk score or an approval outcome.
# --------------------------------------------------------------------------
class AgentStep(BaseModel):
    seq: int
    role: Literal["orchestrator", "scanner", "planner", "implementer", "tester", "verifier"]
    agent: str                       # display name, e.g. "Scanner Agent"
    attempt: int = 1
    mode: Literal["deterministic", "agentic"]
    action: str                      # short label of what it did
    detail: str                      # human-readable narrative
    status: Literal["ok", "fail", "info", "retry"] = "ok"
    llmUsed: bool = False            # did this step make a real model call?
    durationMs: float = 0.0


class AgentTrace(BaseModel):
    runId: str
    strategy: str
    scenarioClass: Literal["SCA", "SAST", "DAST", "generic"] = "generic"
    maxAttempts: int = 1
    attemptsUsed: int = 1
    converged: bool = False          # did the validation gate ultimately pass?
    orchestrator: str = "RemediationOrchestrator"
    steps: List[AgentStep] = []
    summary: str = ""


class VerificationRecord(BaseModel):
    findingId: str
    status: Literal["not-run", "failed", "verified-closed"]
    evidence: List[VerificationEvidence] = []
    verifiedClosed: bool = False
    evidenceMode: Literal["SIMULATED", "LIVE"] = "SIMULATED"


class Timings(BaseModel):
    contextualizedAtMs: float
    validatedAtMs: float
    mitigatedAtMs: float
    exploitPathClosedAtMs: float


class FindingPipelineResult(BaseModel):
    runId: str  # this run's UUID — finding.id alone isn't unique (the same
    # seed/preset finding can be injected more than once), so runId is the
    # only stable per-row identity for lists like GET /api/incidents/results.
    finding: RawFinding
    layer1: ContextGraphRecord
    dataQuality: DataQualityAssessment
    layer2: ReasoningEngineRecord
    plausibility: PlausibilityAssessment
    triage: TriageAgentOutput
    planning: PlanningAgentOutput
    implementation: ImplementationAgentOutput
    governance: GovernanceAgentOutput
    verification: VerificationRecord
    timings: Timings
    routePath: List[str]  # the actual LangGraph node sequence taken for this finding
    finalStatus: str


class ControlEfficacy(BaseModel):
    control: str
    timeBoughtHours: int


class KpiSummary(BaseModel):
    meanTimeToContextualizeMs: float
    meanTimeToValidateMs: float
    meanTimeToMitigateMs: float
    meanExploitPathClosureMs: float
    pctAutoCorrelatedToOwner: float
    pctHighRiskVerifiedReachable: float
    pctRemediationsVerifiedClosed: float
    pctAutoRemediatedVsHumanApproved: float
    falsePositiveRateByAgent: Dict[str, float]
    exceptionDebtOpenCount: int
    controlEfficacy: List[ControlEfficacy]
    slaAtRiskCount: int
    verifiedClosedCount: int
    metricProvenance: Dict[str, str]
    metricSampleCounts: Dict[str, int]
    illustrativeTargets: Dict[str, str]


# --------------------------------------------------------------------------
# VulnOps Settings screen — versioned likelihood, impact, and policy settings.
# --------------------------------------------------------------------------
class AppCriticalityEntry(BaseModel):
    applicationId: str
    tier: Literal["Tier 0", "Tier 1", "Tier 2", "Tier 3"]
    dataSensitivity: str
    accountableOwnerId: str
    crownJewel: bool
    internetExposed: bool
    complianceScope: List[str] = []


class LikelihoodCoefficients(BaseModel):
    intercept: float = -2.0
    epssLogOdds: float = 1.1
    internetExposure: float = 0.7
    runtimeReachability: float = 0.9
    exploitMaturity: float = 0.5
    chainability: float = 0.6
    threatActivity: float = 0.8


class ImpactWeights(BaseModel):
    cvssSeverity: float = 35
    appCriticality: float = 30
    dataSensitivity: float = 15
    blastRadius: float = 10
    regulatorySafety: float = 10


class RiskTierThresholds(BaseModel):
    tier0: float = 90
    tier1: float = 75
    tier2: float = 50


class RiskModelSettings(BaseModel):
    appCriticality: List[AppCriticalityEntry] = []
    likelihoodCoefficients: LikelihoodCoefficients = LikelihoodCoefficients()
    impactWeights: ImpactWeights = ImpactWeights()
    thresholds: RiskTierThresholds = RiskTierThresholds()
    kevOverridesToTier0: bool = True
    maxControlEffectiveness: float = 0.7
    status: Literal["draft", "active"] = "active"
    version: str = "v3.0-explainable-risk"

    @model_validator(mode="after")
    def validate_model_configuration(self):
        total = sum(self.impactWeights.model_dump().values())
        if round(total, 6) != 100:
            raise ValueError(f"impact weights must total 100, got {total}")
        if not (0 <= self.maxControlEffectiveness <= 0.9):
            raise ValueError("max control effectiveness must be between 0 and 0.9")
        t = self.thresholds
        if not (100 >= t.tier0 > t.tier1 > t.tier2 >= 0):
            raise ValueError("thresholds must satisfy 100 >= tier0 > tier1 > tier2 >= 0")
        return self
