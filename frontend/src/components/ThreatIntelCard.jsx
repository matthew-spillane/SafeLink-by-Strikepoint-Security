import React, { useState } from "react";
import { ChevronDown, ChevronUp } from "lucide-react";

function StatusDot({ status }) {
  const color = status === "pass" || status === "clean"
    ? "bg-[#3fb950]"
    : status === "warning" || status === "caution"
    ? "bg-[#d29922]"
    : status === "fail" || status === "danger"
    ? "bg-[#f85149]"
    : "bg-[#484f58]";
  return <span className={`inline-block w-2 h-2 rounded-full ${color}`} />;
}

export default function ThreatIntelCard({ checks, otxData }) {
  const [expanded, setExpanded] = useState(true);

  const vtCheck = checks.find((c) => c.name === "VirusTotal");
  const gsbCheck = checks.find((c) => c.name === "Google Safe Browsing");

  const vtDetails = vtCheck?.details && typeof vtCheck.details === "object" ? vtCheck.details : null;
  const vtMalicious = vtDetails?.malicious || 0;
  const vtSuspicious = vtDetails?.suspicious || 0;
  const vtTotal = vtDetails
    ? (vtDetails.malicious || 0) + (vtDetails.suspicious || 0) + (vtDetails.harmless || 0) + (vtDetails.undetected || 0)
    : 0;
  const vtFlagged = vtMalicious + vtSuspicious;

  const gsbFail = gsbCheck?.status === "fail";
  const otxUnavailable = !otxData || otxData.status === "error" || otxData.status === "skipped" || otxData.status === "unavailable";
  const pulseCount = otxData?.pulse_count ?? 0;

  const hasThreats = vtFlagged > 0 || gsbFail || pulseCount > 0;

  const engines = [
    {
      name: "VirusTotal",
      status: vtCheck?.status === "skipped" ? "skipped" : vtFlagged > 0 ? "fail" : "pass",
      detail: vtCheck?.status === "skipped" ? "Unavailable" : vtFlagged > 0 ? `${vtFlagged}/${vtTotal} flagged` : `${vtTotal} engines clean`,
    },
    {
      name: "Google Safe Browsing",
      status: gsbCheck?.status === "skipped" ? "skipped" : gsbFail ? "fail" : "pass",
      detail: gsbCheck?.status === "skipped" ? "Unavailable" : gsbFail ? "Flagged" : "Clean",
    },
    {
      name: "AlienVault OTX",
      status: otxUnavailable ? "skipped" : pulseCount > 0 ? "warning" : "pass",
      detail: otxUnavailable ? "Unavailable" : pulseCount > 0 ? `${pulseCount} pulse${pulseCount !== 1 ? "s" : ""}` : "No threats found",
    },
  ];

  return (
    <div className="bg-[#161b22] border border-[#30363d] rounded-md overflow-hidden animate-fade-in-up h-full">
      {/* Header */}
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full flex items-center justify-between px-4 py-2.5 border-l-2 border-l-[#f85149] hover:bg-[#1c2128] transition-colors"
      >
        <div className="flex items-center gap-2">
          <span className="text-xs font-semibold uppercase tracking-widest text-[#8b949e]">
            Threat Intelligence
          </span>
        </div>
        <div className="flex items-center gap-2">
          {hasThreats ? (
            <span className="text-xs font-mono font-bold px-2 py-0.5 rounded-sm bg-[#f85149]/10 text-[#f85149]">DETECTIONS</span>
          ) : (
            <span className="text-xs font-mono font-bold px-2 py-0.5 rounded-sm bg-[#3fb950]/10 text-[#3fb950]">CLEAN</span>
          )}
          {expanded ? <ChevronUp className="w-3.5 h-3.5 text-[#8b949e]" /> : <ChevronDown className="w-3.5 h-3.5 text-[#8b949e]" />}
        </div>
      </button>

      {expanded && (
        <div className="border-t border-[#30363d]">
          {engines.map((engine, i) => (
            <div
              key={engine.name}
              className={`flex items-center justify-between px-4 py-2.5 ${i < engines.length - 1 ? "border-b border-[#30363d]" : ""}`}
            >
              <div className="flex items-center gap-2.5">
                <StatusDot status={engine.status} />
                <span className="text-sm font-mono text-[#e6edf3]">{engine.name}</span>
              </div>
              <span className={`text-xs font-mono ${
                engine.status === "fail" ? "text-[#f85149]" :
                engine.status === "warning" ? "text-[#d29922]" :
                engine.status === "pass" ? "text-[#3fb950]" : "text-[#484f58]"
              }`}>
                {engine.detail}
              </span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
