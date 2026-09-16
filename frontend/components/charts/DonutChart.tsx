/**
 * Small hand-rolled inline-SVG donut chart (stroke-dasharray segments) —
 * no charting library dependency exists in this project yet.
 */
export default function DonutChart({
  segments,
}: {
  segments: { label: string; value: number; color: string }[];
}) {
  const total = segments.reduce((s, seg) => s + seg.value, 0) || 1;
  const radius = 40;
  const circumference = 2 * Math.PI * radius;

  let offset = 0;
  const arcs = segments.map((seg) => {
    const fraction = seg.value / total;
    const dash = fraction * circumference;
    const arc = {
      ...seg,
      dasharray: `${dash} ${circumference - dash}`,
      dashoffset: -offset,
    };
    offset += dash;
    return arc;
  });

  return (
    <div>
      <svg viewBox="0 0 100 100" style={{ width: 140, height: 140, margin: "0 auto", display: "block" }}>
        <circle cx="50" cy="50" r={radius} fill="none" stroke="var(--panel-2)" strokeWidth="14" />
        {arcs.map((arc, i) => (
          <circle
            key={i}
            cx="50"
            cy="50"
            r={radius}
            fill="none"
            style={{ stroke: arc.color }}
            strokeWidth="14"
            strokeDasharray={arc.dasharray}
            strokeDashoffset={arc.dashoffset}
            transform="rotate(-90 50 50)"
          />
        ))}
      </svg>
      <div className="donut-legend">
        {segments.map((seg) => (
          <div className="donut-legend-row" key={seg.label}>
            <span className="donut-legend-swatch" style={{ background: seg.color }} />
            {seg.label} &middot; {seg.value}
          </div>
        ))}
      </div>
    </div>
  );
}
