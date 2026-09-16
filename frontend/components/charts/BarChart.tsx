/**
 * Small hand-rolled inline-SVG bar chart — no charting library dependency
 * exists in this project yet, and a handful of bars doesn't warrant adding one.
 */
export default function BarChart({
  data,
  color = "var(--accent)",
  height = 120,
}: {
  data: { label: string; value: number }[];
  color?: string;
  height?: number;
}) {
  const max = Math.max(1, ...data.map((d) => d.value));
  const barWidth = 100 / data.length;

  return (
    <svg viewBox={`0 0 100 ${height}`} preserveAspectRatio="none" style={{ width: "100%", height }}>
      {data.map((d, i) => {
        const h = (d.value / max) * (height - 16);
        const x = i * barWidth + barWidth * 0.18;
        const w = barWidth * 0.64;
        const isLast = i === data.length - 1;
        return (
          <rect
            key={i}
            x={x}
            y={height - h}
            width={w}
            height={h}
            rx={1.5}
            style={{ fill: isLast ? color : "var(--border)" }}
          />
        );
      })}
    </svg>
  );
}
