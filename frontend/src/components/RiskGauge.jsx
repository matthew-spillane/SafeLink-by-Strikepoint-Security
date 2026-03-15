import React from "react";

function getSeverity(score) {
  if (score <= 25) return { label: "CLEAN", color: "#3fb950", bg: "bg-[#3fb950]/10", text: "text-[#3fb950]" };
  if (score <= 50) return { label: "MEDIUM", color: "#d29922", bg: "bg-[#d29922]/10", text: "text-[#d29922]" };
  if (score <= 75) return { label: "HIGH", color: "#db6d28", bg: "bg-[#db6d28]/10", text: "text-[#db6d28]" };
  return { label: "CRITICAL", color: "#f85149", bg: "bg-[#f85149]/10", text: "text-[#f85149]" };
}

export default function RiskGauge({ score }) {
  const sev = getSeverity(score);

  return (
    <div className="w-full">
      {/* Header row: label + score + severity badge */}
      <div className="flex items-center justify-between mb-2">
        <span className="text-xs font-semibold uppercase tracking-widest text-[#8b949e]">
          Risk Score
        </span>
        <div className="flex items-center gap-3">
          <span className="text-3xl font-bold font-mono text-[#e6edf3]">{score}</span>
          <span className="text-xs text-[#8b949e] font-mono">/100</span>
          <span className={`text-xs font-bold font-mono px-2 py-0.5 rounded-sm ${sev.bg} ${sev.text}`}>
            {sev.label}
          </span>
        </div>
      </div>
      {/* Severity bar */}
      <div className="w-full h-1.5 bg-[#30363d] rounded-sm overflow-hidden">
        <div
          className="h-full rounded-sm transition-all duration-500 ease-out"
          style={{ width: `${Math.max(score, 2)}%`, backgroundColor: sev.color }}
        />
      </div>
    </div>
  );
}
