import React, { useState } from "react";
import { ChevronDown, ChevronUp, AlertTriangle } from "lucide-react";

function Row({ label, children, border = true }) {
  return (
    <div className={`flex items-start justify-between py-2 ${border ? "border-b border-[#30363d]" : ""}`}>
      <span className="text-xs uppercase text-[#8b949e] shrink-0 w-36">{label}</span>
      <div className="text-sm font-mono text-[#e6edf3] text-right">{children}</div>
    </div>
  );
}

const warningTags = new Set(["vpn", "tor", "proxy", "scanner", "compromised", "c2", "botnet"]);

export default function HostIntelCard({ data }) {
  const [expanded, setExpanded] = useState(false);
  const isUnavailable = !data || data.status === "error" || data.status === "skipped" || data.status === "unavailable";

  // Map backend field names
  const ip = data?.ip;
  const ports = data?.ports;
  const tags = data?.tags;
  const vulns = data?.vulns;          // backend uses "vulns" not "cves"
  const hostnames = data?.hostnames;
  const cpes = data?.cpes;
  const highRiskTags = data?.high_risk_tags;

  const hasWarningTags = tags && tags.some((t) => warningTags.has(t.toLowerCase()));
  const hasHighRiskTags = highRiskTags && highRiskTags.length > 0;
  const vulnCount = vulns?.length || 0;

  return (
    <div className="bg-[#161b22] border border-[#30363d] rounded-md overflow-hidden animate-fade-in-up h-full">
      {/* Header */}
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full flex items-center justify-between px-4 py-2.5 border-l-2 border-l-[#f85149] hover:bg-[#1c2128] transition-colors"
      >
        <div className="flex items-center gap-2">
          <span className="text-xs font-semibold uppercase tracking-widest text-[#8b949e]">
            Host Intelligence
          </span>
        </div>
        <div className="flex items-center gap-2">
          {isUnavailable ? (
            <span className="text-xs font-mono px-2 py-0.5 rounded-sm bg-[#1c2128] text-[#8b949e] border border-[#30363d]">unavailable</span>
          ) : (
            <>
              {(hasWarningTags || hasHighRiskTags) && (
                <span className="text-xs font-mono font-bold px-2 py-0.5 rounded-sm bg-[#d29922]/10 text-[#d29922]">TAGS</span>
              )}
              {vulnCount > 0 && (
                <span className="text-xs font-mono font-bold px-2 py-0.5 rounded-sm bg-[#f85149]/10 text-[#f85149]">{vulnCount} CVE{vulnCount !== 1 ? "S" : ""}</span>
              )}
              {!hasWarningTags && !hasHighRiskTags && vulnCount === 0 && (
                <span className="text-xs font-mono font-bold px-2 py-0.5 rounded-sm bg-[#3fb950]/10 text-[#3fb950]">CLEAN</span>
              )}
            </>
          )}
          {ip && !isUnavailable && (
            <span className="text-xs font-mono text-[#8b949e]">{ip}</span>
          )}
          {expanded ? <ChevronUp className="w-3.5 h-3.5 text-[#8b949e]" /> : <ChevronDown className="w-3.5 h-3.5 text-[#8b949e]" />}
        </div>
      </button>

      {expanded && (
        <div className="border-t border-[#30363d] px-4 py-1">
          {isUnavailable ? (
            <div className="flex items-center gap-2 py-4 text-[#8b949e]">
              <AlertTriangle className="w-4 h-4 opacity-50" />
              <span className="text-xs font-mono">{data?.error || "Shodan InternetDB data could not be retrieved"}</span>
            </div>
          ) : (
            <>
              {ip && <Row label="IP Address">{ip}</Row>}

              {hostnames && hostnames.length > 0 && (
                <Row label="Hostnames">
                  <div className="space-y-0.5">
                    {hostnames.map((h, i) => <div key={i}>{h}</div>)}
                  </div>
                </Row>
              )}

              {ports && ports.length > 0 && (
                <Row label="Open Ports">
                  <div className="flex flex-wrap gap-1 justify-end">
                    {ports.map((port) => (
                      <span key={port} className="text-xs font-mono px-1.5 py-0.5 rounded-sm bg-[#0d1117] text-[#8b949e] border border-[#30363d]">
                        {port}
                      </span>
                    ))}
                  </div>
                </Row>
              )}

              {tags && tags.length > 0 && (
                <Row label="Host Tags">
                  <div className="flex flex-wrap gap-1 justify-end">
                    {tags.map((tag) => {
                      const isWarn = warningTags.has(tag.toLowerCase());
                      return (
                        <span
                          key={tag}
                          className={`text-xs font-mono font-bold px-1.5 py-0.5 rounded-sm ${
                            isWarn
                              ? "bg-[#d29922]/10 text-[#d29922]"
                              : "bg-[#1c2128] text-[#8b949e] border border-[#30363d]"
                          }`}
                        >
                          {tag}
                        </span>
                      );
                    })}
                  </div>
                </Row>
              )}

              {highRiskTags && highRiskTags.length > 0 && (
                <Row label="High Risk Tags">
                  <div className="flex flex-wrap gap-1 justify-end">
                    {highRiskTags.map((tag) => (
                      <span key={tag} className="text-xs font-mono font-bold px-1.5 py-0.5 rounded-sm bg-[#f85149]/10 text-[#f85149]">
                        {tag}
                      </span>
                    ))}
                  </div>
                </Row>
              )}

              {vulns && vulns.length > 0 && (
                <Row label="Vulnerabilities">
                  <div className="flex flex-wrap gap-1 justify-end">
                    {vulns.map((cve) => (
                      <span key={cve} className="text-xs font-mono font-bold px-1.5 py-0.5 rounded-sm bg-[#f85149]/10 text-[#f85149]">
                        {cve}
                      </span>
                    ))}
                  </div>
                </Row>
              )}

              {cpes && cpes.length > 0 && (
                <Row label="CPEs" border={false}>
                  <div className="flex flex-wrap gap-1 justify-end">
                    {cpes.map((cpe, i) => (
                      <span key={i} className="text-xs font-mono px-1.5 py-0.5 rounded-sm bg-[#1c2128] text-[#8b949e] border border-[#30363d]">
                        {cpe}
                      </span>
                    ))}
                  </div>
                </Row>
              )}
            </>
          )}

          {/* Attribution */}
          <div className="flex justify-end pt-2 pb-1">
            <span className="text-xs font-mono text-[#484f58] px-2 py-0.5 rounded-sm border border-[#30363d]">
              Shodan InternetDB
            </span>
          </div>
        </div>
      )}
    </div>
  );
}
