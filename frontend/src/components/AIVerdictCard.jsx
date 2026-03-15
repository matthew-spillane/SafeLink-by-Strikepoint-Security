import React from "react";
import { BrainCircuit } from "lucide-react";

const verdictColors = {
  Safe: { text: "text-[#3fb950]", bg: "bg-[#3fb950]/10", border: "border-[#3fb950]/30" },
  Suspicious: { text: "text-[#d29922]", bg: "bg-[#d29922]/10", border: "border-[#d29922]/30" },
  "Likely Phishing": { text: "text-[#db6d28]", bg: "bg-[#db6d28]/10", border: "border-[#db6d28]/30" },
  Phishing: { text: "text-[#f85149]", bg: "bg-[#f85149]/10", border: "border-[#f85149]/30" },
};

export default function AIVerdictCard({ aiVerdict }) {
  if (!aiVerdict) return null;

  const c = verdictColors[aiVerdict.verdict] || verdictColors.Suspicious;

  return (
    <div className="bg-[#161b22] border border-[#30363d] rounded-md overflow-hidden animate-fade-in-up">
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-2.5 border-b border-[#30363d] border-l-2 border-l-[#f85149]">
        <div className="flex items-center gap-2">
          <BrainCircuit className="w-4 h-4 text-[#8b949e]" />
          <span className="text-xs font-semibold uppercase tracking-widest text-[#8b949e]">
            AI Analyst
          </span>
        </div>
        <div className="flex items-center gap-2">
          <span className={`text-xs font-bold font-mono px-2 py-0.5 rounded-sm ${c.bg} ${c.text}`}>
            {aiVerdict.verdict}
          </span>
          <span className="text-xs font-mono px-2 py-0.5 rounded-sm bg-[#1c2128] text-[#8b949e] border border-[#30363d]">
            {aiVerdict.confidence}
          </span>
        </div>
      </div>
      {/* Body */}
      <div className="px-4 py-3">
        <p className="text-sm text-[#e6edf3] leading-relaxed">
          {aiVerdict.explanation}
        </p>
      </div>
    </div>
  );
}
