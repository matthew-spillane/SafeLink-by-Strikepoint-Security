import React, { useState } from "react";
import { Cloud, ChevronDown, ChevronUp, ArrowRight, AlertTriangle } from "lucide-react";

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

export default function CloudflareCard({ data }) {
  const [expanded, setExpanded] = useState(false);
  const isUnavailable = !data || data.status === "error" || data.status === "skipped";

  return (
    <div className="bg-[#161b22] border border-[#30363d] rounded-md overflow-hidden animate-fade-in-up h-full">
      {/* Header */}
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full flex items-center justify-between px-4 py-2.5 border-l-2 border-l-[#f85149] hover:bg-[#1c2128] transition-colors"
      >
        <div className="flex items-center gap-2">
          <span className="text-xs font-semibold uppercase tracking-widest text-[#8b949e]">
            Cloudflare Radar
          </span>
        </div>
        <div className="flex items-center gap-2">
          {isUnavailable ? (
            <span className="text-xs font-mono px-2 py-0.5 rounded-sm bg-[#1c2128] text-[#8b949e] border border-[#30363d]">unavailable</span>
          ) : (
            <>
              <StatusPill value={data.is_malicious} trueLabel="MALICIOUS" falseLabel="CLEAN" />
              {data.is_phishing && <StatusPill value={true} trueLabel="PHISHING" falseLabel="" />}
            </>
          )}
          {expanded ? <ChevronUp className="w-3.5 h-3.5 text-[#8b949e]" /> : <ChevronDown className="w-3.5 h-3.5 text-[#8b949e]" />}
        </div>
      </button>

      {expanded && (
        <div className="border-t border-[#30363d] px-4 py-1">
          {isUnavailable ? (
            <div className="flex items-center gap-2 py-4 text-[#8b949e]">
              <AlertTriangle className="w-4 h-4 opacity-50" />
              <span className="text-xs font-mono">{data?.error || "Cloudflare Radar data could not be retrieved"}</span>
            </div>
          ) : (
            <>
              <Row label="Malicious"><StatusPill value={data.is_malicious} trueLabel="TRUE" falseLabel="FALSE" /></Row>
              <Row label="Phishing"><StatusPill value={data.is_phishing} trueLabel="TRUE" falseLabel="FALSE" /></Row>
              {data.radar_rank && <Row label="Radar Rank"><span>#{data.radar_rank}</span></Row>}

              {data.categories && data.categories.length > 0 && (
                <Row label="Categories">
                  <div className="flex flex-wrap gap-1 justify-end">
                    {data.categories.map((cat, i) => (
                      <span key={i} className="text-xs font-mono px-1.5 py-0.5 rounded-sm bg-[#1c2128] text-[#8b949e] border border-[#30363d]">{cat}</span>
                    ))}
                  </div>
                </Row>
              )}

              {data.redirect_chain && data.redirect_chain.length > 1 && (
                <Row label="Redirects">
                  <div className="flex flex-wrap items-center gap-1 justify-end">
                    {data.redirect_chain.map((url, i) => {
                      let hostname;
                      try { hostname = new URL(url).hostname; } catch { hostname = url; }
                      return (
                        <React.Fragment key={i}>
                          <span className="text-xs font-mono text-[#8b949e]">{hostname}</span>
                          {i < data.redirect_chain.length - 1 && <ArrowRight className="w-3 h-3 text-[#30363d]" />}
                        </React.Fragment>
                      );
                    })}
                  </div>
                </Row>
              )}

              {data.tls && (
                <>
                  {data.tls.issuer && <Row label="TLS Issuer">{data.tls.issuer}</Row>}
                  {data.tls.subject && <Row label="TLS Subject">{data.tls.subject}</Row>}
                  {data.tls.validity && <Row label="TLS Validity">{data.tls.validity}</Row>}
                </>
              )}

              {data.technologies && data.technologies.length > 0 && (
                <Row label="Technologies" border={false}>
                  <div className="flex flex-wrap gap-1 justify-end">
                    {data.technologies.map((tech, i) => (
                      <span key={i} className="text-xs font-mono px-1.5 py-0.5 rounded-sm bg-[#1c2128] text-[#8b949e] border border-[#30363d]">{tech}</span>
                    ))}
                  </div>
                </Row>
              )}
            </>
          )}

          {/* Attribution */}
          <div className="flex justify-end pt-2 pb-1">
            <span className="text-xs font-mono text-[#484f58] px-2 py-0.5 rounded-sm border border-[#30363d]">
              Cloudflare Radar
            </span>
          </div>
        </div>
      )}
    </div>
  );
}
