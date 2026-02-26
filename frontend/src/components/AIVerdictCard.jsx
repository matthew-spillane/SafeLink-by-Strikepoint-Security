import React from "react";
import { BrainCircuit, ShieldCheck, AlertTriangle, ShieldAlert, ShieldX } from "lucide-react";

const verdictConfig = {
  Safe: {
    bg: "bg-green-500/10",
    border: "border-green-500/30",
    text: "text-green-400",
    badgeBg: "bg-green-500/20",
    Icon: ShieldCheck,
  },
  Suspicious: {
    bg: "bg-yellow-500/10",
    border: "border-yellow-500/30",
    text: "text-yellow-400",
    badgeBg: "bg-yellow-500/20",
    Icon: AlertTriangle,
  },
  "Likely Phishing": {
    bg: "bg-orange-500/10",
    border: "border-orange-500/30",
    text: "text-orange-400",
    badgeBg: "bg-orange-500/20",
    Icon: ShieldAlert,
  },
  Phishing: {
    bg: "bg-red-500/10",
    border: "border-red-500/30",
    text: "text-red-400",
    badgeBg: "bg-red-500/20",
    Icon: ShieldX,
  },
};

export default function AIVerdictCard({ aiVerdict }) {
  if (!aiVerdict) return null;

  const c = verdictConfig[aiVerdict.verdict] || verdictConfig.Suspicious;
  const VerdictIcon = c.Icon;

  return (
    <div className={`rounded-xl border ${c.border} ${c.bg} p-5 animate-fade-in-up`}>
      <div className="flex items-center gap-2 mb-3">
        <BrainCircuit className="w-5 h-5 text-purple-400" />
        <h3 className="text-sm font-semibold uppercase tracking-wider text-gray-600 dark:text-gray-300">
          AI Analyst Verdict
        </h3>
      </div>
      <div className="flex items-start gap-4">
        <div className={`p-3 rounded-xl ${c.badgeBg} shrink-0`}>
          <VerdictIcon className={`w-8 h-8 ${c.text}`} />
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-3 flex-wrap">
            <span className={`text-lg font-bold ${c.text}`}>
              {aiVerdict.verdict}
            </span>
            <span className={`text-xs px-2.5 py-1 rounded-full font-medium ${c.badgeBg} ${c.text}`}>
              {aiVerdict.confidence} Confidence
            </span>
          </div>
          <p className="mt-2 text-sm text-gray-600 dark:text-gray-300 leading-relaxed">
            {aiVerdict.explanation}
          </p>
        </div>
      </div>
    </div>
  );
}
