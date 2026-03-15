import React from "react";
import { Link2, RotateCcw } from "lucide-react";
import AIVerdictCard from "./AIVerdictCard";
import RiskGauge from "./RiskGauge";
import VerdictBadge from "./VerdictBadge";
import PagePreview from "./PagePreview";
import SummaryBar from "./SummaryBar";
import CheckCard from "./CheckCard";
import RedirectChain from "./RedirectChain";
import CloudflareCard from "./CloudflareCard";
import URLReputationCard from "./URLReputationCard";
import HostIntelCard from "./HostIntelCard";
import ThreatIntelCard from "./ThreatIntelCard";
import ScanSummaryPanel from "./ScanSummaryPanel";
import ModuleStatusPanel from "./ModuleStatusPanel";

// Check names that are consolidated into ThreatIntelCard
const threatIntelCheckNames = new Set(["VirusTotal", "Google Safe Browsing"]);

export default function ResultsDashboard({ result, onReset }) {
  const copyLink = () => {
    const link = `${window.location.origin}/scan/${result.id}`;
    navigator.clipboard.writeText(link);
  };

  // Remaining checks not covered by the new consolidated cards
  const remainingChecks = result.checks.filter(
    (c) => !threatIntelCheckNames.has(c.name)
  );

  const moduleCount = result.checks.length;

  return (
    <div className="space-y-4 animate-fade-in-up">

      {/* ── Row 1: Risk Score + Metadata — full width ── */}
      <div className="bg-[#161b22] border border-[#30363d] rounded-md p-4">
        <RiskGauge score={result.risk_score} />
      </div>

      <div className="bg-[#161b22] border border-[#30363d] rounded-md px-4 py-2.5 flex flex-wrap items-center gap-x-4 gap-y-1">
        <div className="flex items-center gap-2">
          <span className="text-xs uppercase text-[#8b949e] font-mono">Verdict</span>
          <VerdictBadge verdict={result.verdict} />
        </div>
        <span className="text-[#30363d]">|</span>
        <div className="flex items-center gap-2">
          <span className="text-xs uppercase text-[#8b949e] font-mono">Risk</span>
          <span className="text-sm font-bold font-mono text-[#e6edf3]">{result.risk_score}/100</span>
        </div>
        <span className="text-[#30363d]">|</span>
        <div className="flex items-center gap-2">
          <span className="text-xs uppercase text-[#8b949e] font-mono">Modules</span>
          <span className="text-sm font-mono text-[#e6edf3]">{moduleCount} run</span>
        </div>
        <span className="text-[#30363d] hidden sm:inline">|</span>
        <div className="flex items-center gap-2 min-w-0">
          <span className="text-xs uppercase text-[#8b949e] font-mono shrink-0">URL</span>
          <span className="text-sm font-mono text-[#e6edf3] truncate" title={result.url}>{result.url}</span>
        </div>
      </div>

      {/* ── Row 2: AI Analyst (65%) + Scan Summary (35%) ── */}
      <div className="grid grid-cols-1 md:grid-cols-12 gap-4">
        <div className="md:col-span-8">
          <AIVerdictCard aiVerdict={result.ai_verdict} />
        </div>
        <div className="md:col-span-4">
          <ScanSummaryPanel checks={result.checks} result={result} />
        </div>
      </div>

      {/* ── Row 3: Three equal columns — Cloudflare / IPQS / Shodan ── */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="h-full">
          <CloudflareCard data={result.cloudflare_radar} />
        </div>
        <div className="h-full">
          <URLReputationCard data={result.ipqualityscore} />
        </div>
        <div className="h-full">
          <HostIntelCard data={result.shodan} />
        </div>
      </div>

      {/* ── Row 4: Threat Intel (70%) + Module Status (30%) ── */}
      <div className="grid grid-cols-1 md:grid-cols-12 gap-4">
        <div className="md:col-span-8">
          <ThreatIntelCard checks={result.checks} otxData={result.alienvault_otx} />
        </div>
        <div className="md:col-span-4">
          <ModuleStatusPanel checks={result.checks} />
        </div>
      </div>

      {/* ── Row 4.5: Redirect chain (if present) ── */}
      <RedirectChain chain={result.redirect_chain} />

      {/* ── Row 5: Summary bar — full width ── */}
      <SummaryBar checks={result.checks} />

      {/* ── Row 6: Detailed Analysis table — full width ── */}
      <div className="bg-[#161b22] border border-[#30363d] rounded-md overflow-hidden">
        <div className="px-4 py-2.5 border-b border-[#30363d] border-l-2 border-l-[#f85149]">
          <span className="text-xs font-semibold uppercase tracking-widest text-[#8b949e]">
            Detailed Analysis
          </span>
        </div>
        {/* Table header */}
        <div className="grid grid-cols-12 gap-2 px-4 py-1.5 border-b border-[#30363d] bg-[#0d1117]">
          <div className="col-span-3 text-[10px] font-semibold uppercase tracking-widest text-[#484f58]">Module</div>
          <div className="col-span-2 text-[10px] font-semibold uppercase tracking-widest text-[#484f58]">Status</div>
          <div className="col-span-7 text-[10px] font-semibold uppercase tracking-widest text-[#484f58]">Finding</div>
        </div>
        {remainingChecks.map((check, i) => (
          <CheckCard key={i} check={check} />
        ))}
      </div>

      {/* ── Row 7: Page Capture — collapsed by default ── */}
      <PagePreview urlscan={result.urlscan} scanId={result.id} />

      {/* Action buttons */}
      <div className="flex justify-center gap-3 pt-2">
        <button
          onClick={copyLink}
          className="flex items-center gap-2 px-4 py-2 text-xs font-mono rounded-md bg-[#161b22] border border-[#30363d] text-[#8b949e] hover:text-[#e6edf3] hover:bg-[#1c2128] transition-colors"
        >
          <Link2 className="w-3.5 h-3.5" />
          Copy Report Link
        </button>
        <button
          onClick={onReset}
          className="flex items-center gap-2 px-4 py-2 text-xs font-mono rounded-md bg-[#161b22] border border-[#30363d] text-[#8b949e] hover:text-[#e6edf3] hover:bg-[#1c2128] transition-colors"
        >
          <RotateCcw className="w-3.5 h-3.5" />
          Scan Another
        </button>
      </div>
    </div>
  );
}
