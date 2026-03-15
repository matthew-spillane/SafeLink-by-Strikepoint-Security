import React, { useState } from "react";
import { ChevronDown, ChevronUp, ShieldAlert, AlertTriangle, Shield, ShieldCheck } from "lucide-react";

function Badge({ children, color = "default" }) {
  const colors = {
    red: "bg-sp-red/10 text-sp-red",
    green: "bg-green-500/10 text-green-400",
    amber: "bg-amber-500/10 text-amber-400",
    default: "bg-white/5 text-sp-text",
  };
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium ${colors[color] || colors.default}`}>
      {children}
    </span>
  );
}

export default function ThreatIntelCard({ checks, otxData }) {
  const [expanded, setExpanded] = useState(false);

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
  const otxUnavailable = !otxData || otxData.status === "error" || otxData.status === "skipped";
  const pulseCount = otxData?.pulse_count ?? 0;

  const hasThreats = vtFlagged > 0 || gsbFail || pulseCount > 0;

  return (
    <div className="glass-card bg-[#111111] rounded-xl overflow-hidden animate-fade-in-up">
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full flex items-center gap-3 p-4 text-left hover:bg-sp-card-light transition-colors"
      >
        <div className={`p-2 rounded-lg ${hasThreats ? "bg-sp-red/10" : "bg-green-500/10"}`}>
          <ShieldAlert className={`w-5 h-5 ${hasThreats ? "text-sp-red" : "text-green-400"}`} />
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <span className="font-medium text-sm text-white">Threat Intelligence</span>
            {hasThreats ? (
              <Badge color="red">Detections Found</Badge>
            ) : (
              <Badge color="green">No Detections</Badge>
            )}
          </div>
          <p className="text-sm text-sp-text mt-0.5 truncate">
            Consolidated view of VirusTotal, Google Safe Browsing & AlienVault OTX
          </p>
        </div>
        {expanded ? (
          <ChevronUp className="w-4 h-4 text-sp-muted shrink-0" />
        ) : (
          <ChevronDown className="w-4 h-4 text-sp-muted shrink-0" />
        )}
      </button>

      {expanded && (
        <div className="px-4 pb-4 border-t border-sp-border">
          <div className="mt-3 space-y-3">
            {/* VirusTotal */}
            <div className="flex items-center justify-between p-3 rounded-lg bg-[#0d0d0d]">
              <div className="flex items-center gap-2">
                <ShieldCheck className={`w-4 h-4 ${vtFlagged > 0 ? "text-sp-red" : "text-green-400"}`} />
                <span className="text-sm text-white">VirusTotal</span>
              </div>
              {vtCheck?.status === "skipped" ? (
                <span className="text-xs text-sp-muted">Unavailable</span>
              ) : (
                <div className="flex items-center gap-2">
                  {vtFlagged > 0 ? (
                    <Badge color="red">{vtFlagged} / {vtTotal} flagged</Badge>
                  ) : (
                    <Badge color="green">{vtTotal} engines clean</Badge>
                  )}
                </div>
              )}
            </div>

            {/* Google Safe Browsing */}
            <div className="flex items-center justify-between p-3 rounded-lg bg-[#0d0d0d]">
              <div className="flex items-center gap-2">
                <Shield className={`w-4 h-4 ${gsbFail ? "text-sp-red" : "text-green-400"}`} />
                <span className="text-sm text-white">Google Safe Browsing</span>
              </div>
              {gsbCheck?.status === "skipped" ? (
                <span className="text-xs text-sp-muted">Unavailable</span>
              ) : gsbFail ? (
                <Badge color="red">Flagged</Badge>
              ) : (
                <Badge color="green">Clean</Badge>
              )}
            </div>

            {/* AlienVault OTX */}
            <div className="flex items-center justify-between p-3 rounded-lg bg-[#0d0d0d]">
              <div className="flex items-center gap-2">
                <AlertTriangle className={`w-4 h-4 ${pulseCount > 0 ? "text-amber-400" : otxUnavailable ? "text-sp-muted" : "text-green-400"}`} />
                <span className="text-sm text-white">AlienVault OTX</span>
              </div>
              {otxUnavailable ? (
                <span className="text-xs text-sp-muted">Unavailable</span>
              ) : pulseCount > 0 ? (
                <Badge color="amber">{pulseCount} pulse{pulseCount !== 1 ? "s" : ""}</Badge>
              ) : (
                <Badge color="green">No pulses</Badge>
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
