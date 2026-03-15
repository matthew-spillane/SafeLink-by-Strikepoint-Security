import React from "react";

export default function SummaryBar({ checks }) {
  const passed = checks.filter((c) => c.status === "pass").length;
  const warnings = checks.filter((c) => c.status === "warning").length;
  const failed = checks.filter((c) => c.status === "fail").length;
  const skipped = checks.filter((c) => c.status === "skipped").length;

  const items = [
    { label: "PASSED", count: passed, color: "text-[#3fb950]", dot: "bg-[#3fb950]" },
    { label: "WARNINGS", count: warnings, color: "text-[#d29922]", dot: "bg-[#d29922]" },
    { label: "FAILED", count: failed, color: "text-[#f85149]", dot: "bg-[#f85149]" },
    { label: "SKIPPED", count: skipped, color: "text-[#484f58]", dot: "bg-[#484f58]" },
  ];

  return (
    <div className="grid grid-cols-4 gap-2">
      {items.map((item) => (
        <div
          key={item.label}
          className="bg-[#161b22] border border-[#30363d] rounded-md px-3 py-2.5 flex items-center gap-2.5"
        >
          <span className={`w-2 h-2 rounded-full shrink-0 ${item.dot}`} />
          <span className={`text-lg font-bold font-mono ${item.color}`}>{item.count}</span>
          <span className="text-[10px] font-semibold uppercase tracking-widest text-[#8b949e]">{item.label}</span>
        </div>
      ))}
    </div>
  );
}
