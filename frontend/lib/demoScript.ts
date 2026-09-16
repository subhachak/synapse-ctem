// Presenter narration for the client walkthrough (frontend/pages/demo.tsx).
// Edit the "narration" strings freely for wording/timing — they are plain
// text rendered as-is and don't need to touch component logic. Finding-
// specific facts (numbers, which branch was taken, etc.) are rendered by
// the page itself from the live API response, not from this file.

export type HighlightTarget =
  | "layer1"
  | "layer2"
  | "triage"
  | "branch1"
  | "planning"
  | "implementation"
  | "governance"
  | "branch2"
  | "summary"
  | null;

export interface DemoStep {
  step: number;
  title: string;
  narration: string;
  highlight: HighlightTarget;
}

export const DEMO_SCRIPT: DemoStep[] = [
  {
    step: 0,
    title: "The Trigger",
    narration:
      "This finding was just flagged. Before anything happens, here's exactly what we know about it right now — " +
      "what it is, how severe it is, whether it's being actively exploited in the wild, and who found it. " +
      "Nothing has been decided yet — this is just the raw signal coming in.",
    highlight: null,
  },
  {
    step: 1,
    title: "Layer 1 — Context Graph & Threat Ontology",
    narration:
      "The system just automatically worked out what this finding actually touches — which services run the " +
      "affected software, who owns them, which policies apply, and whether an attacker could actually reach it " +
      "right now. This is the step that used to mean hours of a human digging through spreadsheets and Slack threads.",
    highlight: "layer1",
  },
  {
    step: 2,
    title: "Layer 2 — Adversarial Reasoning Engine",
    narration:
      "Now the system answers two separate questions. First: how likely is exploitation, based on EPSS, exposure, " +
      "runtime reachability, exploit maturity, attack-path chainability, threat activity, and validated controls? " +
      "Second: how damaging would exploitation be, based on technical severity, application criticality, data " +
      "sensitivity, blast radius, and regulatory consequence? Likelihood times impact gives residual risk. Governed " +
      "policy is then applied openly — for example, KEV can set a Tier 0 urgency floor without hiding the calculated " +
      "tier. This is deterministic and versioned; no LLM scores the vulnerability.",
    highlight: "layer2",
  },
  {
    step: 3,
    title: "Layer 3 — Triage Agent",
    narration:
      "An AI agent now looks at that context and that score and makes a judgment call: is this actually worth " +
      "acting on right now, or should it be suppressed as noise? It writes its reasoning out in plain language, " +
      "so a human can check its work rather than just trusting a verdict.",
    highlight: "triage",
  },
  {
    step: 4,
    title: "Branch Point — Suppress or Proceed?",
    narration:
      "This is a real fork, not a scripted path — the system genuinely goes one of two ways from here. If the " +
      "agent found no active exploit and no runtime reachability, the finding skips straight to Governance — no " +
      "wasted engineering time, no unnecessary agent spend on remediation nobody needs. If it's worth acting on, " +
      "it moves into Planning next.",
    highlight: "branch1",
  },
  {
    step: 5,
    title: "Layer 3 — Planning Agent",
    narration:
      "A second agent now works out how to actually fix this — which version or config change resolves it, what " +
      "might break as a result, and what a human reviewer should expect to see before they approve the change.",
    highlight: "planning",
  },
  {
    step: 6,
    title: "Layer 3 — Implementation Agent",
    narration:
      "A third agent drafts the actual fix — a pull request title, a summary of the change, generated tests, and " +
      "a sandbox test result — so a human reviewer starts from a concrete, testable remediation draft instead of a blank page.",
    highlight: "implementation",
  },
  {
    step: 7,
    title: "Layer 3 — Governance Agent",
    narration:
      "Before anything ships, a governance agent checks the proposed action against our actual policies, maps it " +
      "to the controls it satisfies, and records exactly who did what and why — the audit trail an auditor or " +
      "regulator would ask for.",
    highlight: "governance",
  },
  {
    step: 8,
    title: "Branch Point — Final Disposition",
    narration:
      "This is the second real decision point. Depending on the policy checks and how much of the business this " +
      "touches, the finding lands in one of three places: auto-closed with no human needed, blocked pending a " +
      "policy review, or escalated to a person for sign-off.",
    highlight: "branch2",
  },
  {
    step: 9,
    title: "Summary",
    narration:
      "That's the full path this finding took, start to finish — every step auditable end to end. In practice, " +
      "this is what used to take a security analyst days spread across five different tools and several people; " +
      "here it happened as one continuous, reviewable run.",
    highlight: "summary",
  },
];

export const STEP_NUMBERS = DEMO_SCRIPT.map((s) => s.step);
