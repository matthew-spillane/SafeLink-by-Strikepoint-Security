import React, { useState } from "react";
import { ChevronDown, ChevronUp, AlertTriangle } from "lucide-react";

function StatusPill({ value, trueLabel, falseLabel }) {
  return value ? (
    <span className="text-xs font-mono font-bold px-2 py-0.5 rounded-sm bg-[#f85149]/10 text-[#f85149]">{trueLabel}</span>
  ) : (
    <span className="text-xs font-mono font-bold px-2 py-0.5 rounded-sm bg-[#3fb950]/10 text-[#3fb950]">{falseLabel}</span>
  );
}

function Row({ label, children, border = true }) {
  return (
    <div className={`flex items-start justify-between py-2 ${border ? "border-b border-[#30363d]" : ""}`}>
      <span className="text-xs uppercase text-[#8b949e] shrink-0 w-36">{label}</span>
      <div className="text-sm font-mono text-[#e6edf3] text-right">{children}</div>
    </div>
  );
}

function ScoreBar({ score }) {
  const color =
    score <= 25 ? "#3fb950" : score <= 50 ? "#d29922" : score <= 75 ? "#db6d28" : "#f85149";
  const textColor =
    score <= 25 ? "text-[#3fb950]" : score <= 50 ? "text-[#d29922]" : score <= 75 ? "text-[#db6d28]" : "text-[#f85149]";

  return (
    <div className="flex items-center gap-3">
      <div className="flex-1 h-1.5 bg-[#30363d] rounded-sm overflow-hidden">
        <div className="h-full rounded-sm" style={{ width: `${Math.min(score, 100)}%`, backgroundColor: color }} />
      </div>
      <span className={`text-sm font-bold font-mono ${textColor}`}>{score}</span>
    </div>
  );
}

export default function URLReputationCard({ data }) {
  const [expanded, setExpanded] = useState(false);
  const isUnavailable = !data || data.status === "error" || data.status === "skipped";
  const score = data?.risk_score ?? null;

  const hasFlags = data?.phishing || data?.malware || data?.suspicious;

  return (
    <div className="bg-[#161b22] border border-[#30363d] rounded-md overflow-hidden animate-fade-in-up">
      {/* Header */}
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full flex items-center justify-between px-4 py-2.5 border-l-2 border-l-[#f85149] hover:bg-[#1c2128] transition-colors"
      >
        <div className="flex items-center gap-2">
          <span className="text-xs font-semibold uppercase tracking-widest text-[#8b949e]">
            URL Reputation
          </span>
        </div>
        <div className="flex items-center gap-2">
          {isUnavailable ? (
            <span className="text-xs font-mono px-2 py-0.5 rounded-sm bg-[#1c2128] text-[#8b949e] border border-[#30363d]">unavailable</span>
          ) : hasFlags ? (
            <>
              {data.phishing && <StatusPill value={true} trueLabel="PHISHING" falseLabel="" />}
              {data.malware && <StatusPill value={true} trueLabel="MALWARE" falseLabel="" />}
              {data.suspicious && <span className="text-xs font-mono font-bold px-2 py-0.5 rounded-sm bg-[#d29922]/10 text-[#d29922]">SUSPICIOUS</span>}
            </>
          ) : (
            <StatusPill value={false} trueLabel="" falseLabel="CLEAN" />
          )}
          {score !== null && !isUnavailable && (
            <span className="text-xs font-mono text-[#8b949e]">{score}/100</span>
          )}
          {expanded ? <ChevronUp className="w-3.5 h-3.5 text-[#8b949e]" /> : <ChevronDown className="w-3.5 h-3.5 text-[#8b949e]" />}
        </div>
      </button>

      {expanded && (
        <div className="border-t border-[#30363d] px-4 py-1">
          {isUnavailable ? (
            <div className="flex items-center gap-2 py-4 text-[#8b949e]">
              <AlertTriangle className="w-4 h-4 opacity-50" />
              <span className="text-xs font-mono">{data?.error || "IPQualityScore data could not be retrieved"}</span>
            </div>
          ) : (
            <>
              {score !== null && (
                <div className="py-2 border-b border-[#30363d]">
                  <div className="flex items-center justify-between mb-1">
                    <span className="text-xs uppercase text-[#8b949e]">Risk Score</span>
                  </div>
                  <ScoreBar score={score} />
                </div>
              )}

              <Row label="Phishing"><StatusPill value={data.phishing} trueLabel="TRUE" falseLabel="FALSE" /></Row>
              <Row label="Malware"><StatusPill value={data.malware} trueLabel="TRUE" falseLabel="FALSE" /></Row>
              <Row label="Suspicious"><StatusPill value={data.suspicious} trueLabel="TRUE" falseLabel="FALSE" /></Row>
              {data.parking !== undefined && <Row label="Parked Domain"><StatusPill value={data.parking} trueLabel="TRUE" falseLabel="FALSE" /></Row>}
              {data.spamming !== undefined && <Row label="Spamming"><StatusPill value={data.spamming} trueLabel="TRUE" falseLabel="FALSE" /></Row>}
              {data.domain_age && <Row label="Domain Age">{data.domain_age}</Row>}
              {data.category && <Row label="Category">{data.category}</Row>}
              {data.country_code && <Row label="Country">{data.country_code}</Row>}
              {data.isp && <Row label="ISP" border={false}>{data.isp}</Row>}
            </>
          )}

          {/* Attribution */}
          <div className="flex justify-end pt-2 pb-1">
            <span className="text-xs font-mono text-[#484f58] px-2 py-0.5 rounded-sm border border-[#30363d]">
              IPQualityScore
            </span>
          </div>
        </div>
      )}
    </div>
  );
}
