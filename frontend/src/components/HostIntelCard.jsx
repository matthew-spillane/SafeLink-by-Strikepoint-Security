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
  const isUnavailable = !data || data.status === "error" || data.status === "skipped";
  const hasWarningTags = data?.tags && data.tags.some((t) => warningTags.has(t.toLowerCase()));
  const cveCount = data?.cves?.length || 0;

  return (
    <div className="bg-[#161b22] border border-[#30363d] rounded-md overflow-hidden animate-fade-in-up">
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
              {hasWarningTags && (
                <span className="text-xs font-mono font-bold px-2 py-0.5 rounded-sm bg-[#d29922]/10 text-[#d29922]">TAGS</span>
              )}
              {cveCount > 0 && (
                <span className="text-xs font-mono font-bold px-2 py-0.5 rounded-sm bg-[#f85149]/10 text-[#f85149]">{cveCount} CVE{cveCount !== 1 ? "S" : ""}</span>
              )}
              {!hasWarningTags && cveCount === 0 && (
                <span className="text-xs font-mono font-bold px-2 py-0.5 rounded-sm bg-[#3fb950]/10 text-[#3fb950]">CLEAN</span>
              )}
            </>
          )}
          {data?.ip && !isUnavailable && (
            <span className="text-xs font-mono text-[#8b949e]">{data.ip}</span>
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
              {data.ip && <Row label="IP Address">{data.ip}</Row>}
              {data.asn && <Row label="ASN">{data.asn}</Row>}
              {data.org && <Row label="Organization">{data.org}</Row>}
              {data.hostnames && data.hostnames.length > 0 && (
                <Row label="Hostnames">
                  <div className="space-y-0.5">
                    {data.hostnames.map((h, i) => <div key={i}>{h}</div>)}
                  </div>
                </Row>
              )}

              {data.ports && data.ports.length > 0 && (
                <Row label="Open Ports">
                  <div className="flex flex-wrap gap-1 justify-end">
                    {data.ports.map((port) => (
                      <span key={port} className="text-xs font-mono px-1.5 py-0.5 rounded-sm bg-[#0d1117] text-[#8b949e] border border-[#30363d]">
                        {port}
                      </span>
                    ))}
                  </div>
                </Row>
              )}

              {data.tags && data.tags.length > 0 && (
                <Row label="Host Tags">
                  <div className="flex flex-wrap gap-1 justify-end">
                    {data.tags.map((tag) => {
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

              {data.cves && data.cves.length > 0 && (
                <Row label="CVEs" border={false}>
                  <div className="flex flex-wrap gap-1 justify-end">
                    {data.cves.map((cve) => (
                      <span key={cve} className="text-xs font-mono font-bold px-1.5 py-0.5 rounded-sm bg-[#f85149]/10 text-[#f85149]">
                        {cve}
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
