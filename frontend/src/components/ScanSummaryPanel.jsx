import React from "react";

export default function ScanSummaryPanel({ checks, result }) {
  const passed = checks.filter((c) => c.status === "pass").length;
  const failed = checks.filter((c) => c.status === "fail").length;
  const warned = checks.filter((c) => c.status === "warning").length;
  const skipped = checks.filter((c) => c.status === "skipped").length;

  const ts = result.created_at
    ? new Date(result.created_at).toLocaleString()
    : "—";

  const rows = [
    { label: "MODULES RUN", value: String(checks.length), color: "text-[#e6edf3]" },
    { label: "PASSED", value: String(passed), color: "text-[#3fb950]" },
    { label: "WARNINGS", value: String(warned), color: "text-[#d29922]" },
    { label: "FAILED", value: String(failed), color: "text-[#f85149]" },
    { label: "SKIPPED", value: String(skipped), color: "text-[#484f58]" },
    { label: "SCAN TIME", value: ts, color: "text-[#e6edf3]" },
    { label: "ENGINE", value: "Strikepoint Engine", color: "text-[#e6edf3]" },
  ];

  return (
    <div className="bg-[#161b22] border border-[#30363d] rounded-md overflow-hidden h-full flex flex-col">
      <div className="px-4 py-2.5 border-b border-[#30363d] border-l-2 border-l-[#f85149]">
        <span className="text-xs font-semibold uppercase tracking-widest text-[#8b949e]">
          Scan Summary
        </span>
      </div>
      <div className="flex-1">
        {rows.map((row, i) => (
          <div
            key={row.label}
            className={`flex items-center justify-between px-4 py-1.5 ${
              i < rows.length - 1 ? "border-b border-[#30363d]" : ""
            }`}
          >
            <span className="text-[10px] font-semibold uppercase tracking-widest text-[#8b949e]">
              {row.label}
            </span>
            <span className={`text-xs font-mono font-bold ${row.color}`}>
              {row.value}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
