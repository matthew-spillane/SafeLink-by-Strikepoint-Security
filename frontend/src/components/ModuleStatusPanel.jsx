import React from "react";

const dotColor = {
  pass: "bg-[#3fb950]",
  warning: "bg-[#d29922]",
  fail: "bg-[#f85149]",
  skipped: "bg-[#484f58]",
};

const statusLabel = {
  pass: "Pass",
  warning: "Warn",
  fail: "Fail",
  skipped: "N/A",
};

export default function ModuleStatusPanel({ checks }) {
  return (
    <div className="bg-[#161b22] border border-[#30363d] rounded-md overflow-hidden h-full flex flex-col">
      <div className="px-4 py-2.5 border-b border-[#30363d] border-l-2 border-l-[#f85149]">
        <span className="text-xs font-semibold uppercase tracking-widest text-[#8b949e]">
          Module Status
        </span>
      </div>
      <div className="flex-1 overflow-y-auto">
        {checks.map((check, i) => (
          <div
            key={i}
            className={`flex items-center gap-2.5 px-4 py-1.5 ${
              i < checks.length - 1 ? "border-b border-[#30363d]" : ""
            }`}
          >
            <span className={`w-2 h-2 rounded-full shrink-0 ${dotColor[check.status] || dotColor.skipped}`} />
            <span className="text-xs font-mono text-[#e6edf3] flex-1 truncate">
              {check.name}
            </span>
            <span className={`text-[10px] font-mono uppercase ${
              check.status === "pass" ? "text-[#3fb950]" :
              check.status === "warning" ? "text-[#d29922]" :
              check.status === "fail" ? "text-[#f85149]" :
              "text-[#484f58]"
            }`}>
              {statusLabel[check.status] || check.status}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}
