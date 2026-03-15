import React from "react";

const statusDotColor = {
  pass: "bg-[#3fb950]",
  warning: "bg-[#d29922]",
  fail: "bg-[#f85149]",
  skipped: "bg-[#484f58]",
};

export default function CheckCard({ check }) {
  const dot = statusDotColor[check.status] || statusDotColor.skipped;

  return (
    <div className="grid grid-cols-12 gap-2 items-center px-4 py-2 border-b border-[#30363d] text-sm">
      {/* MODULE */}
      <div className="col-span-3 font-mono text-[#e6edf3] truncate text-xs">
        {check.name}
      </div>
      {/* STATUS */}
      <div className="col-span-2 flex items-center gap-2">
        <span className={`w-2 h-2 rounded-full shrink-0 ${dot}`} />
        <span className="text-xs font-mono uppercase text-[#8b949e]">{check.status}</span>
      </div>
      {/* FINDING */}
      <div className="col-span-7 text-xs text-[#8b949e] truncate" title={check.summary}>
        {check.summary}
      </div>
    </div>
  );
}
