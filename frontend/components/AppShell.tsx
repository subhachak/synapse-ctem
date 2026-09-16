import { ReactNode } from "react";
import Link from "next/link";

export type NavKey = "dashboard" | "review" | "remediation" | "history" | "settings";

const NAV_ITEMS: { key: NavKey; label: string; href: string }[] = [
  { key: "dashboard", label: "Dashboard", href: "/dashboard" },
  // Review and Remediation are run-scoped (/review/[id], /remediation/[id], id = run UUID) —
  // the nav rail links back to the Dashboard's unified Findings table, where a specific run
  // is picked via its "Review ->" row action, available immediately (the page itself handles
  // both a still-running/paused run — queue panel + telemetry only — and a completed one —
  // full risk summary + remediation link). That table holds every finding regardless of
  // origin — the 7 seeded ones and anything injected live both run through the same incident
  // graph (see graph.bootstrap_seed_incidents) and are indistinguishable here.
  { key: "review", label: "Alerts / Triage", href: "/dashboard#findings" },
  { key: "remediation", label: "Remediation", href: "/dashboard#findings" },
  { key: "history", label: "History & Reports", href: "/history" },
];

const PAGE_TITLES: Record<NavKey, string> = {
  dashboard: "Dashboard",
  review: "Alert Triage",
  remediation: "Remediation workflow",
  history: "History & Reports",
  settings: "Settings · Risk Model & App Criticality",
};

export default function AppShell({ activeNav, children }: { activeNav?: NavKey; children: ReactNode }) {
  return (
    <div className="app-shell">
      <nav className="app-nav">
        <div className="app-nav-wordmark">VulnOps</div>
        <div className="app-nav-items">
          {NAV_ITEMS.map((item) => (
            <Link
              key={item.key}
              href={item.href}
              className={`app-nav-item ${activeNav === item.key ? "active" : ""}`}
            >
              {item.label}
            </Link>
          ))}
        </div>
        <div className="app-nav-spacer" />
        <Link href="/settings" className={`app-nav-item settings ${activeNav === "settings" ? "active" : ""}`}>
          Settings
        </Link>
      </nav>
      <section className="app-workspace">
        <header className="app-header">
          <div className="app-header-title">{activeNav ? PAGE_TITLES[activeNav] : "VulnOps"}</div>
          <div className="app-header-tools">
            <div className="app-search"><span aria-hidden="true">⌕</span><span>Search findings, owners, CVEs…</span></div>
            <div className="app-avatar" title="Demo reviewer">SC</div>
          </div>
        </header>
        <main className={`app-main ${activeNav ? `${activeNav}-page` : ""}`}>{children}</main>
      </section>
    </div>
  );
}
