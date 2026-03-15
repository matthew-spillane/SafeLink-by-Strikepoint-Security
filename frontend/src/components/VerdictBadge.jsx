import React from "react";

const config = {
  Safe: { bg: "bg-[#3fb950]/10", text: "text-[#3fb950]", border: "border-[#3fb950]/30" },
  Suspicious: { bg: "bg-[#d29922]/10", text: "text-[#d29922]", border: "border-[#d29922]/30" },
  "Likely Phishing": { bg: "bg-[#db6d28]/10", text: "text-[#db6d28]", border: "border-[#db6d28]/30" },
  Phishing: { bg: "bg-[#f85149]/10", text: "text-[#f85149]", border: "border-[#f85149]/30" },
};

export default function VerdictBadge({ verdict }) {
  const c = config[verdict] || config.Suspicious;
  return (
    <span className={`inline-flex items-center px-2.5 py-0.5 rounded-sm border text-xs font-bold font-mono uppercase tracking-wide ${c.bg} ${c.text} ${c.border}`}>
      {verdict}
    </span>
  );
}
