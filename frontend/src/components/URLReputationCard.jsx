import React, { useState } from "react";
import { ChevronDown, ChevronUp, Gauge, AlertTriangle } from "lucide-react";

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

function ScoreBar({ score }) {
  const color =
    score <= 25 ? "bg-green-500" : score <= 50 ? "bg-amber-500" : score <= 75 ? "bg-orange-500" : "bg-sp-red";
  const textColor =
    score <= 25 ? "text-green-400" : score <= 50 ? "text-amber-400" : score <= 75 ? "text-orange-400" : "text-sp-red";

  return (
    <div className="flex items-center gap-3">
      <div className="flex-1 h-2 bg-white/5 rounded-full overflow-hidden">
        <div className={`h-full rounded-full ${color}`} style={{ width: `${Math.min(score, 100)}%` }} />
      </div>
      <span className={`text-sm font-bold ${textColor} w-8 text-right`}>{score}</span>
    </div>
  );
}

function BoolBadge({ label, value }) {
  return <Badge color={value ? "red" : "green"}>{value ? label : `No ${label}`}</Badge>;
}

export default function URLReputationCard({ data }) {
  const [expanded, setExpanded] = useState(false);

  const isUnavailable = !data || data.status === "error" || data.status === "skipped";
  const score = data?.risk_score ?? null;

  return (
    <div className="glass-card bg-[#111111] rounded-xl overflow-hidden animate-fade-in-up">
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full flex items-center gap-3 p-4 text-left hover:bg-sp-card-light transition-colors"
      >
        <div className="p-2 rounded-lg bg-purple-500/10">
          <Gauge className="w-5 h-5 text-purple-400" />
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <span className="font-medium text-sm text-white">URL Reputation</span>
            {isUnavailable ? (
              <Badge>unavailable</Badge>
            ) : (
              <>
                {data.phishing && <Badge color="red">Phishing</Badge>}
                {data.malware && <Badge color="red">Malware</Badge>}
                {data.suspicious && <Badge color="amber">Suspicious</Badge>}
                {!data.phishing && !data.malware && !data.suspicious && <Badge color="green">Clean</Badge>}
              </>
            )}
          </div>
          <p className="text-sm text-sp-text mt-0.5 truncate">
            {isUnavailable
              ? "IP quality score data not available for this scan"
              : score !== null
              ? `Risk score: ${score}/100`
              : "URL reputation analysis"}
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
          {isUnavailable ? (
            <div className="flex items-center gap-2 py-4 text-sp-muted">
              <AlertTriangle className="w-4 h-4 opacity-50" />
              <p className="text-sm">{data?.error || "IPQualityScore data could not be retrieved"}</p>
            </div>
          ) : (
            <div className="mt-3 space-y-4">
              {/* Risk score bar */}
              {score !== null && (
                <div>
                  <p className="text-xs text-sp-muted mb-1.5 uppercase tracking-wider">Risk Score</p>
                  <ScoreBar score={score} />
                </div>
              )}

              {/* Boolean flags */}
              <div className="flex flex-wrap gap-2">
                <BoolBadge label="Phishing" value={data.phishing} />
                <BoolBadge label="Malware" value={data.malware} />
                <BoolBadge label="Suspicious" value={data.suspicious} />
                {data.parking && <Badge color="amber">Parked Domain</Badge>}
                {data.spamming && <Badge color="amber">Spamming</Badge>}
              </div>

              {/* Domain details */}
              <div className="text-xs text-sp-text bg-[#0d0d0d] rounded-lg p-3 space-y-1">
                {data.domain_age && (
                  <p><span className="text-sp-muted">Domain Age:</span> {data.domain_age}</p>
                )}
                {data.category && (
                  <p><span className="text-sp-muted">Category:</span> {data.category}</p>
                )}
                {data.country_code && (
                  <p><span className="text-sp-muted">Country:</span> {data.country_code}</p>
                )}
                {data.isp && (
                  <p><span className="text-sp-muted">ISP:</span> {data.isp}</p>
                )}
              </div>
            </div>
          )}

          {/* Attribution */}
          <div className="mt-3 flex justify-end">
            <span className="text-[10px] text-sp-muted/60 flex items-center gap-1">
              <Gauge className="w-3 h-3" /> IPQualityScore
            </span>
          </div>
        </div>
      )}
    </div>
  );
}
