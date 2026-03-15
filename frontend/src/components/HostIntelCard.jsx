import React, { useState } from "react";
import { ChevronDown, ChevronUp, Server, AlertTriangle, Bug } from "lucide-react";

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

const warningTags = new Set(["vpn", "tor", "proxy", "scanner", "compromised", "c2", "botnet"]);

export default function HostIntelCard({ data }) {
  const [expanded, setExpanded] = useState(false);

  const isUnavailable = !data || data.status === "error" || data.status === "skipped";
  const hasWarningTags = data?.tags && data.tags.some((t) => warningTags.has(t.toLowerCase()));

  return (
    <div className="glass-card bg-[#111111] rounded-xl overflow-hidden animate-fade-in-up">
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full flex items-center gap-3 p-4 text-left hover:bg-sp-card-light transition-colors"
      >
        <div className="p-2 rounded-lg bg-cyan-500/10">
          <Server className="w-5 h-5 text-cyan-400" />
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <span className="font-medium text-sm text-white">Host Intelligence</span>
            {isUnavailable ? (
              <Badge>unavailable</Badge>
            ) : (
              <>
                {hasWarningTags && <Badge color="amber">Warning Tags</Badge>}
                {data.cves && data.cves.length > 0 && (
                  <Badge color="red">{data.cves.length} CVE{data.cves.length !== 1 ? "s" : ""}</Badge>
                )}
                {!hasWarningTags && (!data.cves || data.cves.length === 0) && (
                  <Badge color="green">Clean</Badge>
                )}
              </>
            )}
          </div>
          <p className="text-sm text-sp-text mt-0.5 truncate">
            {isUnavailable
              ? "Shodan host data not available for this scan"
              : data.ip
              ? `${data.ip}${data.asn ? ` · ${data.asn}` : ""}`
              : "Host infrastructure analysis"}
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
              <p className="text-sm">{data?.error || "Shodan InternetDB data could not be retrieved"}</p>
            </div>
          ) : (
            <div className="mt-3 space-y-4">
              {/* IP & ASN */}
              <div className="text-xs text-sp-text bg-[#0d0d0d] rounded-lg p-3 space-y-1">
                {data.ip && <p><span className="text-sp-muted">IP:</span> {data.ip}</p>}
                {data.asn && <p><span className="text-sp-muted">ASN:</span> {data.asn}</p>}
                {data.org && <p><span className="text-sp-muted">Org:</span> {data.org}</p>}
                {data.hostnames && data.hostnames.length > 0 && (
                  <p><span className="text-sp-muted">Hostnames:</span> {data.hostnames.join(", ")}</p>
                )}
              </div>

              {/* Open Ports */}
              {data.ports && data.ports.length > 0 && (
                <div>
                  <p className="text-xs text-sp-muted mb-1.5 uppercase tracking-wider">Open Ports</p>
                  <div className="flex flex-wrap gap-1.5">
                    {data.ports.map((port) => (
                      <span
                        key={port}
                        className="px-2 py-0.5 rounded text-xs font-mono bg-white/5 text-sp-text border border-sp-border"
                      >
                        {port}
                      </span>
                    ))}
                  </div>
                </div>
              )}

              {/* Host Tags */}
              {data.tags && data.tags.length > 0 && (
                <div>
                  <p className="text-xs text-sp-muted mb-1.5 uppercase tracking-wider">Host Tags</p>
                  <div className="flex flex-wrap gap-1.5">
                    {data.tags.map((tag) => (
                      <Badge key={tag} color={warningTags.has(tag.toLowerCase()) ? "amber" : "default"}>
                        {tag}
                      </Badge>
                    ))}
                  </div>
                </div>
              )}

              {/* CVEs */}
              {data.cves && data.cves.length > 0 && (
                <div>
                  <p className="text-xs text-sp-muted mb-1.5 uppercase tracking-wider flex items-center gap-1">
                    <Bug className="w-3 h-3" /> Known Vulnerabilities
                  </p>
                  <div className="flex flex-wrap gap-1.5">
                    {data.cves.map((cve) => (
                      <Badge key={cve} color="red">{cve}</Badge>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* Attribution */}
          <div className="mt-3 flex justify-end">
            <span className="text-[10px] text-sp-muted/60 flex items-center gap-1">
              <Server className="w-3 h-3" /> Data from Shodan
            </span>
          </div>
        </div>
      )}
    </div>
  );
}
