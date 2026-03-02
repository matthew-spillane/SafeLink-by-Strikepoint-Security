import React from "react";
import { Link2, RotateCcw } from "lucide-react";
import AIVerdictCard from "./AIVerdictCard";
import RiskGauge from "./RiskGauge";
import VerdictBadge from "./VerdictBadge";
import PagePreview from "./PagePreview";
import SummaryBar from "./SummaryBar";
import CheckCard from "./CheckCard";
import RedirectChain from "./RedirectChain";

export default function ResultsDashboard({ result, onReset }) {
  const copyLink = () => {
    const link = `${window.location.origin}/scan/${result.id}`;
    navigator.clipboard.writeText(link);
  };

  return (
    <div className="space-y-6 animate-fade-in-up">
      {/* 1. AI Analyst Verdict */}
      <AIVerdictCard aiVerdict={result.ai_verdict} />

      {/* 2. Score + Verdict */}
      <div className="glass-card bg-[#111111] rounded-xl flex flex-col items-center gap-3 py-5 px-4">
        <RiskGauge score={result.risk_score} />
        <VerdictBadge verdict={result.verdict} />
        <p className="text-sm text-sp-text font-mono truncate max-w-md" title={result.url}>
          {result.url}
        </p>
      </div>

      {/* 3. Page Preview (URLscan screenshot) */}
      <PagePreview urlscan={result.urlscan} scanId={result.id} />

      {/* Action buttons */}
      <div className="flex justify-center gap-3">
        <button
          onClick={copyLink}
          className="flex items-center gap-2 px-4 py-2 text-sm rounded-lg glass-card bg-[#111111] text-sp-text hover:text-white hover:bg-sp-card-light transition-colors"
        >
          <Link2 className="w-4 h-4" />
          Copy Report Link
        </button>
        <button
          onClick={onReset}
          className="flex items-center gap-2 px-4 py-2 text-sm rounded-lg glass-card bg-[#111111] text-sp-text hover:text-white hover:bg-sp-card-light transition-colors"
        >
          <RotateCcw className="w-4 h-4" />
          Scan Another URL
        </button>
      </div>

      {/* 4. Summary */}
      <SummaryBar checks={result.checks} />

      {/* Redirect chain */}
      <RedirectChain chain={result.redirect_chain} />

      {/* 5. Individual checks (Detailed Results) */}
      <div className="space-y-3">
        <h3 className="text-sm font-semibold text-sp-red uppercase tracking-wider">
          Detailed Results
        </h3>
        {result.checks.map((check, i) => (
          <CheckCard key={i} check={check} />
        ))}
      </div>
    </div>
  );
}
