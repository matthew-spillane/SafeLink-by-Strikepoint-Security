import React, { useState } from "react";
import { Cloud, ChevronDown, ChevronUp, Shield, Lock, Cpu, ArrowRight, AlertTriangle } from "lucide-react";

function Badge({ children, color = "default" }) {
  const colors = {
    red: "bg-sp-red/10 text-sp-red",
    green: "bg-green-500/10 text-green-400",
    amber: "bg-amber-500/10 text-amber-400",
    blue: "bg-blue-500/10 text-blue-400",
    default: "bg-white/5 text-sp-text",
  };
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium ${colors[color] || colors.default}`}>
      {children}
    </span>
  );
}

function UnavailableState({ message }) {
  return (
    <div className="flex items-center gap-2 py-4 text-sp-muted">
      <AlertTriangle className="w-4 h-4 opacity-50" />
      <p className="text-sm">{message || "Data unavailable"}</p>
    </div>
  );
}

export default function CloudflareCard({ data }) {
  const [expanded, setExpanded] = useState(false);

  const isUnavailable = !data || data.status === "error" || data.status === "skipped";

  return (
    <div className="glass-card bg-[#111111] rounded-xl overflow-hidden animate-fade-in-up">
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full flex items-center gap-3 p-4 text-left hover:bg-sp-card-light transition-colors"
      >
        <div className="p-2 rounded-lg bg-orange-500/10">
          <Cloud className="w-5 h-5 text-orange-400" />
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <span className="font-medium text-sm text-white">Cloudflare Radar</span>
            {isUnavailable ? (
              <Badge>unavailable</Badge>
            ) : (
              <>
                {data.is_malicious && <Badge color="red">Malicious</Badge>}
                {data.is_phishing && <Badge color="red">Phishing</Badge>}
                {!data.is_malicious && !data.is_phishing && <Badge color="green">Clean</Badge>}
              </>
            )}
          </div>
          <p className="text-sm text-sp-text mt-0.5 truncate">
            {isUnavailable
              ? "Cloudflare Radar data not available for this scan"
              : data.radar_rank
              ? `Radar rank #${data.radar_rank}`
              : "Domain intelligence from Cloudflare Radar"}
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
            <UnavailableState message={data?.error || "Cloudflare Radar data could not be retrieved"} />
          ) : (
            <div className="mt-3 space-y-4">
              {/* Verdicts */}
              <div className="flex flex-wrap gap-2">
                <Badge color={data.is_malicious ? "red" : "green"}>
                  {data.is_malicious ? "Malicious" : "Not Malicious"}
                </Badge>
                <Badge color={data.is_phishing ? "red" : "green"}>
                  {data.is_phishing ? "Phishing" : "Not Phishing"}
                </Badge>
                {data.radar_rank && <Badge color="blue">Rank #{data.radar_rank}</Badge>}
              </div>

              {/* Categories */}
              {data.categories && data.categories.length > 0 && (
                <div>
                  <p className="text-xs text-sp-muted mb-1.5 uppercase tracking-wider">Categories</p>
                  <div className="flex flex-wrap gap-1.5">
                    {data.categories.map((cat, i) => (
                      <Badge key={i}>{cat}</Badge>
                    ))}
                  </div>
                </div>
              )}

              {/* Redirect chain summary */}
              {data.redirect_chain && data.redirect_chain.length > 1 && (
                <div>
                  <p className="text-xs text-sp-muted mb-1.5 uppercase tracking-wider">Redirect Chain</p>
                  <div className="flex flex-wrap items-center gap-1.5">
                    {data.redirect_chain.map((url, i) => {
                      let hostname;
                      try { hostname = new URL(url).hostname; } catch { hostname = url; }
                      return (
                        <React.Fragment key={i}>
                          <span className="px-2 py-1 rounded text-xs font-mono bg-white/5 text-sp-text">
                            {hostname}
                          </span>
                          {i < data.redirect_chain.length - 1 && (
                            <ArrowRight className="w-3 h-3 text-sp-muted shrink-0" />
                          )}
                        </React.Fragment>
                      );
                    })}
                  </div>
                </div>
              )}

              {/* TLS Certificate */}
              {data.tls && (
                <div>
                  <p className="text-xs text-sp-muted mb-1.5 uppercase tracking-wider flex items-center gap-1">
                    <Lock className="w-3 h-3" /> TLS Certificate
                  </p>
                  <div className="text-xs text-sp-text bg-[#0d0d0d] rounded-lg p-3 space-y-1">
                    {data.tls.issuer && <p><span className="text-sp-muted">Issuer:</span> {data.tls.issuer}</p>}
                    {data.tls.subject && <p><span className="text-sp-muted">Subject:</span> {data.tls.subject}</p>}
                    {data.tls.validity && <p><span className="text-sp-muted">Valid:</span> {data.tls.validity}</p>}
                  </div>
                </div>
              )}

              {/* Technologies */}
              {data.technologies && data.technologies.length > 0 && (
                <div>
                  <p className="text-xs text-sp-muted mb-1.5 uppercase tracking-wider flex items-center gap-1">
                    <Cpu className="w-3 h-3" /> Technologies
                  </p>
                  <div className="flex flex-wrap gap-1.5">
                    {data.technologies.map((tech, i) => (
                      <Badge key={i} color="blue">{tech}</Badge>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Attribution */}
          <div className="mt-3 flex justify-end">
            <span className="text-[10px] text-sp-muted/60 flex items-center gap-1">
              <Cloud className="w-3 h-3" /> Powered by Cloudflare Radar
            </span>
          </div>
        </div>
      )}
    </div>
  );
}
