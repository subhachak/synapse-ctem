import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import AppShell from "../components/AppShell";
import ScoringBreakdown, { evidenceQualityLabel } from "../components/ScoringBreakdown";
import { fetchSeedFindingResult, fetchFindings, FindingPipelineResult, FindingSummary } from "../lib/api";
import { DEMO_SCRIPT, STEP_NUMBERS, HighlightTarget } from "../lib/demoScript";

const DEFAULT_FINDING_ID = "find-2";

function tierClass(tier: string) {
  if (tier === "Tier 0") return "tier-0";
  if (tier === "Tier 1") return "tier-1";
  if (tier === "Tier 2") return "tier-2";
  return "tier-3";
}

function pct(v: number) {
  return `${(v * 100).toFixed(0)}%`;
}

type Phase = "picker" | "loading" | "walkthrough";

const MAP_NODES: { key: HighlightTarget; label: string; branch?: boolean }[] = [
  { key: "layer1", label: "Layer 1\nContext Graph" },
  { key: "layer2", label: "Layer 2\nReasoning Engine" },
  { key: "triage", label: "Triage\nAgent" },
  { key: "branch1", label: "fork", branch: true },
  { key: "planning", label: "Planning\nAgent" },
  { key: "implementation", label: "Implementation\nAgent" },
  { key: "governance", label: "Governance\nAgent" },
  { key: "branch2", label: "fork", branch: true },
];

function ArchitectureMap({
  active,
  suppressed,
  pastBranch1,
}: {
  active: HighlightTarget;
  suppressed: boolean;
  pastBranch1: boolean;
}) {
  const showSkipped = suppressed && pastBranch1;
  return (
    <div className="demo-map">
      {MAP_NODES.map((n) => {
        const isSkipped = showSkipped && (n.key === "planning" || n.key === "implementation");
        const classes = [
          "demo-map-node",
          n.branch ? "branch" : "",
          active === n.key ? "active" : "dim",
          isSkipped ? "skipped" : "",
        ]
          .filter(Boolean)
          .join(" ");
        return (
          <div key={n.key} className={classes}>
            {n.label.split("\n").map((line, i) => (
              <span key={i} className="demo-map-line">
                {line}
              </span>
            ))}
            {isSkipped && <span className="demo-map-tag">skipped this run</span>}
          </div>
        );
      })}
    </div>
  );
}

export default function Demo() {
  const [phase, setPhase] = useState<Phase>("picker");
  const [findingsList, setFindingsList] = useState<FindingSummary[]>([]);
  const [selectedFindingId, setSelectedFindingId] = useState(DEFAULT_FINDING_ID);
  const [data, setData] = useState<FindingPipelineResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [stepIndex, setStepIndex] = useState(0);
  const [branch1Revealed, setBranch1Revealed] = useState(false);
  const [branch2Revealed, setBranch2Revealed] = useState(false);

  useEffect(() => {
    fetchFindings()
      .then(setFindingsList)
      .catch(() => setFindingsList([]));
  }, []);

  const suppressed = data?.triage.suppressed ?? false;

  const stepSequence = useMemo(() => {
    if (!data) return STEP_NUMBERS;
    return suppressed ? STEP_NUMBERS.filter((n) => n !== 5 && n !== 6) : STEP_NUMBERS;
  }, [data, suppressed]);

  const currentStep = stepSequence[stepIndex] ?? 0;
  const currentScript = DEMO_SCRIPT.find((s) => s.step === currentStep)!;
  const isLastStep = stepIndex === stepSequence.length - 1;
  const isFirstStep = stepIndex === 0;

  function resetWalkthrough() {
    setStepIndex(0);
    setBranch1Revealed(false);
    setBranch2Revealed(false);
  }

  function handleStart() {
    setPhase("loading");
    setError(null);
    fetchSeedFindingResult(selectedFindingId)
      .then((d: FindingPipelineResult) => {
        setData(d);
        resetWalkthrough();
        setPhase("walkthrough");
      })
      .catch(() => {
        setError("Could not load the pipeline trace for this finding. Is the backend running?");
        setPhase("picker");
      });
  }

  function handleChangeFinding() {
    setPhase("picker");
    setData(null);
  }

  function handleNext() {
    if (currentStep === 4 && !branch1Revealed) {
      setBranch1Revealed(true);
      return;
    }
    if (currentStep === 8 && !branch2Revealed) {
      setBranch2Revealed(true);
      return;
    }
    setStepIndex((i) => Math.min(i + 1, stepSequence.length - 1));
  }

  function handleBack() {
    if (currentStep === 4 && branch1Revealed) {
      setBranch1Revealed(false);
      return;
    }
    if (currentStep === 8 && branch2Revealed) {
      setBranch2Revealed(false);
      return;
    }
    setStepIndex((i) => Math.max(i - 1, 0));
  }

  function handleSkipToEnd() {
    setBranch1Revealed(true);
    setBranch2Revealed(true);
    setStepIndex(stepSequence.length - 1);
  }

  useEffect(() => {
    if (phase !== "walkthrough") return;
    function onKeyDown(e: KeyboardEvent) {
      if (e.key === "ArrowRight" || e.key === " ") {
        e.preventDefault();
        handleNext();
      } else if (e.key === "ArrowLeft") {
        e.preventDefault();
        handleBack();
      } else if (e.key === "r" || e.key === "R") {
        e.preventDefault();
        resetWalkthrough();
      }
    }
    window.addEventListener("keydown", onKeyDown);
    return () => window.removeEventListener("keydown", onKeyDown);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [phase, currentStep, branch1Revealed, branch2Revealed, stepSequence.length]);

  if (phase === "picker") {
    return (
      <AppShell>
        <div className="topbar">
          <div>
            <Link href="/dashboard" className="back-link">
              &larr; back to dashboard
            </Link>
            <h1 style={{ marginTop: 8 }}>Client Walkthrough — Demo Mode</h1>
            <div className="sub">Pick one finding and walk the audience through it, stage by stage.</div>
          </div>
        </div>
        <div className="demo-picker panel">
          <label className="demo-picker-label" htmlFor="finding-select">
            Finding to walk through
          </label>
          <select
            id="finding-select"
            className="demo-select"
            value={selectedFindingId}
            onChange={(e) => setSelectedFindingId(e.target.value)}
          >
            {findingsList.length === 0 && <option value={DEFAULT_FINDING_ID}>Loading findings…</option>}
            {findingsList.map((f) => (
              <option key={f.id} value={f.id}>
                {f.name} — {f.cve} ({f.severity})
              </option>
            ))}
          </select>
          {error && <div className="demo-error">{error}</div>}
          <button className="demo-btn primary" onClick={handleStart}>
            Start Walkthrough
          </button>
        </div>
      </AppShell>
    );
  }

  if (phase === "loading" || !data) {
    return (
      <AppShell>
        <div className="sub">Loading pipeline trace for {selectedFindingId}...</div>
      </AppShell>
    );
  }

  const { finding, layer1, layer2, triage, planning, implementation, governance, routePath, finalStatus, timings } =
    data;

  return (
    <AppShell>
      <div className="topbar">
        <div>
          <button className="back-link demo-linkbtn" onClick={handleChangeFinding}>
            &larr; change finding
          </button>
          <h1 style={{ marginTop: 8 }}>{finding.name}</h1>
          <div className="sub">
            {finding.cve} &middot; {finding.affectedComponent} &middot; Step {stepIndex + 1} of{" "}
            {stepSequence.length}
          </div>
        </div>
        <span className={`tier-badge ${tierClass(layer2.actionTier)}`}>{layer2.actionTier}</span>
      </div>

      <ArchitectureMap active={currentScript.highlight} suppressed={suppressed} pastBranch1={currentStep > 4 || (currentStep === 4 && branch1Revealed)} />

      <div className="panel demo-narration">
        <h2 className="demo-step-title">{currentScript.title}</h2>
        <p className="demo-narration-text">{currentScript.narration}</p>
      </div>

      <div className="panel demo-stage">
        {currentStep === 0 && (
          <div>
            <div className="kv">
              <span className="k">CVE:</span> {finding.cve}
            </div>
            <div className="kv">
              <span className="k">Severity:</span> {finding.severityLabel}
            </div>
            <div className="kv">
              <span className="k">EPSS (exploit prediction):</span> {pct(finding.epss)}
            </div>
            <div className="kv">
              <span className="k">CISA KEV listed:</span> {finding.cisaKev ? "yes — known exploited" : "no"}
            </div>
            <div className="kv">
              <span className="k">Discovered by:</span> {finding.discoveredBy}
            </div>
            <div className="kv">
              <span className="k">Runtime reachable:</span> {finding.runtimeReachable ? "yes" : "not observed"}
            </div>
            {finding.chainedWith.length > 0 && (
              <div className="kv">
                <span className="k">Chained with:</span> {finding.chainedWith.join(", ")}
              </div>
            )}
          </div>
        )}

        {currentStep === 1 && (
          <div>
            <div className="kv">
              <span className="k">Services:</span> {layer1.services.map((s) => s.name).join(", ") || "none"}
            </div>
            <div className="kv">
              <span className="k">Software:</span> {layer1.software.name} ({layer1.software.version})
            </div>
            <div className="kv">
              <span className="k">Owner:</span> {layer1.owner.name} ({layer1.owner.team})
            </div>
            <div className="kv">
              <span className="k">Runtime reachability:</span>{" "}
              {layer1.reachability.runtimeReachable ? "reachable" : "not observed reachable"}
              {" "}<span className="badge">SIMULATED SIGNAL</span>
            </div>
            {layer1.reachability.attackPath.length > 0 && (
              <div className="kv">
                <span className="k">Attack path:</span> {layer1.reachability.attackPath.join(" > ")}
              </div>
            )}
            <div className="badge-row">
              {layer1.policies.map((p) => (
                <span key={p.id} className="badge" title={p.description}>
                  {p.id}
                </span>
              ))}
            </div>
          </div>
        )}

        {currentStep === 2 && (
          <div>
            <div className="formula-row">
              <div className="factor-chip">
                <span className="fname">Exploitation likelihood</span>
                <span className="fval">{Math.round(layer2.exploitationLikelihood * 100)}%</span>
              </div>
              <span className="op">&times;</span>
              <div className="factor-chip">
                <span className="fname">Business impact</span>
                <span className="fval">{Math.round(layer2.businessImpact * 100)}%</span>
              </div>
              <span className="op">&times;</span>
              <div className="factor-chip">
                <span className="fname">Residual control factor</span>
                <span className="fval">{Math.round((1 - layer2.validatedControlEffectiveness) * 100)}%</span>
              </div>
              <span className="op">=</span>
              <div className="factor-chip" style={{ borderColor: "var(--accent)" }}>
                <span className="fname">Residual risk</span>
                <span className="fval" style={{ color: "var(--accent)" }}>
                  {layer2.riskPriority}
                </span>
              </div>
            </div>
            <div className="kv">
              <span className="k">Likelihood signals:</span> EPSS, internet exposure, runtime reachability, exploit maturity,
              chainability, and threat activity.
            </div>
            <div className="kv">
              <span className="k">Impact signals:</span> CVSS severity, application criticality, data sensitivity, blast radius,
              and regulatory or safety consequence.
            </div>
            <div className="kv">
              <span className="k">Evidence quality:</span> {evidenceQualityLabel(data.dataQuality.fieldStatus)} &middot;{" "}
              {Math.round(data.dataQuality.completenessScore * 100)}% completeness
            </div>
            <ScoringBreakdown
              likelihoodInputs={layer2.likelihoodInputs}
              likelihoodContributions={layer2.likelihoodContributions}
              impactInputs={layer2.impactInputs}
              impactContributions={layer2.impactContributions}
            />
            <div className="kv">
              <span className="k">Action tier:</span> {layer2.actionTierLabel}
            </div>
            <div className="kv">
              <span className="k">Modeled blast radius:</span> {layer2.blastRadius} services &middot;{" "}
              <span className="k">Modeled predictive risk:</span> {layer2.predictiveRisk}
            </div>
          </div>
        )}

        {currentStep === 3 && (
          <div>
            <div className="kv">
              <span className="k">Confidence:</span> {pct(triage.confidence)}
            </div>
            <div className="kv">
              <span className="k">Decision:</span> {triage.suppressed ? "suppressed" : "not suppressed — proceed"}
            </div>
            {triage.suppressed && triage.suppressionReason && (
              <div className="kv">
                <span className="k">Suppression reason:</span> {triage.suppressionReason}
              </div>
            )}
            <ul className="chain-list">
              {triage.reasoningChain.map((step, i) => (
                <li key={i}>{step}</li>
              ))}
            </ul>
          </div>
        )}

        {currentStep === 4 && (
          <div className="demo-branch">
            <div className="demo-branch-options">
              <div
                className={`demo-branch-option ${
                  branch1Revealed ? (suppressed ? "taken" : "not-taken") : "pending"
                }`}
              >
                skip_remediation
              </div>
              <div
                className={`demo-branch-option ${
                  branch1Revealed ? (!suppressed ? "taken" : "not-taken") : "pending"
                }`}
              >
                planning_agent
              </div>
            </div>
            {branch1Revealed ? (
              <div className="demo-branch-result">
                {suppressed
                  ? "Suppressed — this finding routes straight to Governance. Planning and Implementation are skipped, along with their agent calls."
                  : "Not suppressed — this finding proceeds into Planning."}
              </div>
            ) : (
              <div className="demo-branch-hint">Press Next to reveal the path this finding actually took &rarr;</div>
            )}
          </div>
        )}

        {currentStep === 5 && (
          <div>
            <div className="kv">
              <span className="k">Fix:</span> {planning.fixApproach} &rarr; {planning.targetVersionOrConfig}
            </div>
            <div className="kv">
              <span className="k">Effort estimate:</span> {planning.effortEstimate}
            </div>
            {planning.predictedBreakingChanges.length > 0 && (
              <div className="kv">
                <span className="k">Predicted breaking changes:</span>
                <ul className="chain-list">
                  {planning.predictedBreakingChanges.map((c, i) => (
                    <li key={i}>{c}</li>
                  ))}
                </ul>
              </div>
            )}
            {planning.compensatingControls.length > 0 && (
              <div className="kv">
                <span className="k">Compensating controls:</span> {planning.compensatingControls.join(", ")}
              </div>
            )}
            <div className="kv">
              <span className="k">Mitigation recipe:</span> {planning.mitigationRecipe}
            </div>
          </div>
        )}

        {currentStep === 6 && (
          <div>
            <div className="kv">
              <span className="k">PR:</span> {implementation.prTitle}
            </div>
            <div className="kv">
              <span className="k">Diff:</span> {implementation.diffSummary}
            </div>
            <div className="kv">
              <span className="k">Rationale:</span> {implementation.rationale}
            </div>
            <div className="badge-row">
              <span className="badge">DRAFT ONLY — no self-issued test evidence</span>
              <span className="badge">confidence: {pct(implementation.selfAssessedConfidence)}</span>
              {implementation.generatedTestSuite.map((t, i) => (
                <span className="badge" key={i}>
                  test: {t}
                </span>
              ))}
            </div>
          </div>
        )}

        {currentStep === 7 && (
          <div>
            <div className="kv">
              <span className="k">Provenance (who/what/why):</span> {governance.provenanceWho} &mdash;{" "}
              {governance.provenanceWhat} &mdash; {governance.provenanceWhy}
            </div>
            <div className="kv">
              <span className="k">Controls mapped:</span> {governance.controlsMapped.join(", ")}
            </div>
            <div className="kv">
              <span className="k">Audit artifact:</span> {governance.auditArtifactId}
            </div>
            <div className="badge-row">
              {governance.policyChecks.map((p) => (
                <span key={p.policyId} className={`badge ${p.passed ? "pass" : "fail"}`} title={p.note}>
                  {p.policyId}: {p.passed ? "pass" : "fail"}
                </span>
              ))}
              {governance.crossRegionFlag && <span className="badge fail">cross-region flag</span>}
              {governance.customerNotificationTriggered && (
                <span className="badge fail">customer notification triggered</span>
              )}
            </div>
          </div>
        )}

        {currentStep === 8 && (
          <div className="demo-branch">
            <div className="demo-branch-options">
              {(["auto_close", "blocked_review", "escalate_human"] as const).map((outcome) => {
                const taken = routePath[routePath.length - 1] === outcome;
                return (
                  <div
                    key={outcome}
                    className={`demo-branch-option ${
                      branch2Revealed ? (taken ? "taken" : "not-taken") : "pending"
                    }`}
                  >
                    {outcome}
                  </div>
                );
              })}
            </div>
            {branch2Revealed ? (
              <div className="demo-branch-result">
                Approval status: {governance.approvalStatus} &mdash; final status: {finalStatus}
              </div>
            ) : (
              <div className="demo-branch-hint">Press Next to reveal the final disposition &rarr;</div>
            )}
          </div>
        )}

        {currentStep === 9 && (
          <div>
            <div style={{ fontFamily: "var(--mono)", fontSize: 13, color: "var(--accent)" }}>
              {routePath.join("  ->  ")}
            </div>
            <div className="kv" style={{ marginTop: 10 }}>
              <span className="k">Final status:</span> {finalStatus}
            </div>
            <div className="kv">
              <span className="k">Risk priority:</span> {layer2.riskPriority} ({layer2.actionTier})
            </div>
            <div className="kv">
              <span className="k">Contextualized at:</span> {timings.contextualizedAtMs.toFixed(0)}ms &middot;{" "}
              <span className="k">Validated at:</span> {timings.validatedAtMs.toFixed(0)}ms &middot;{" "}
              <span className="k">Mitigated at:</span> {timings.mitigatedAtMs.toFixed(0)}ms &middot;{" "}
              <span className="k">Exploit-path closed at:</span> {timings.exploitPathClosedAtMs.toFixed(0)}ms
            </div>
          </div>
        )}
      </div>

      <div className="demo-controls">
        <button className="demo-btn" onClick={handleBack} disabled={isFirstStep}>
          &larr; Back
        </button>
        <button className="demo-btn primary" onClick={handleNext} disabled={isLastStep}>
          Next &rarr;
        </button>
        <button className="demo-btn" onClick={resetWalkthrough}>
          Reset
        </button>
        <button className="demo-btn" onClick={handleSkipToEnd}>
          Skip to end
        </button>
      </div>
    </AppShell>
  );
}
