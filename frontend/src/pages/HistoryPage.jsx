import React, { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Loader2, ExternalLink } from "lucide-react";
import { getHistory } from "../api";

const verdictStyles = {
  Safe: "text-[#3fb950]",
  Suspicious: "text-[#d29922]",
  "Likely Phishing": "text-[#db6d28]",
  Phishing: "text-[#f85149]",
};

const rowBorder = {
  Safe: "border-l-[#3fb950]",
  Suspicious: "border-l-[#d29922]",
  "Likely Phishing": "border-l-[#db6d28]",
  Phishing: "border-l-[#f85149]",
};

export default function HistoryPage() {
  const [scans, setScans] = useState([]);
  const [loading, setLoading] = useState(true);
  const navigate = useNavigate();

  useEffect(() => {
    getHistory()
      .then(setScans)
      .catch(() => {})
      .finally(() => setLoading(false));
  }, []);

  if (loading) {
    return (
      <div className="flex flex-col items-center gap-4 py-24">
        <Loader2 className="w-6 h-6 text-[#f85149] animate-spin" />
        <p className="text-[#8b949e] text-xs font-mono">Loading scan history...</p>
      </div>
    );
  }

  return (
    <div className="pt-8">
      <div className="flex items-center gap-2 mb-4">
        <h2 className="text-xs font-semibold uppercase tracking-widest text-[#8b949e]">Scan History</h2>
      </div>

      {scans.length === 0 ? (
        <div className="text-center py-16 text-[#484f58] text-xs font-mono">
          <p>No scans yet. Go scan a URL.</p>
        </div>
      ) : (
        <div className="bg-[#161b22] border border-[#30363d] rounded-md overflow-hidden">
          {/* Header (desktop) */}
          <div className="hidden sm:grid grid-cols-12 gap-4 px-4 py-2 border-b border-[#30363d] bg-[#0d1117]">
            <div className="col-span-5 text-[10px] font-semibold uppercase tracking-widest text-[#484f58]">URL</div>
            <div className="col-span-3 text-[10px] font-semibold uppercase tracking-widest text-[#484f58]">Time</div>
            <div className="col-span-1 text-center text-[10px] font-semibold uppercase tracking-widest text-[#484f58]">Score</div>
            <div className="col-span-2 text-center text-[10px] font-semibold uppercase tracking-widest text-[#484f58]">Verdict</div>
            <div className="col-span-1" />
          </div>

          {scans.map((scan) => {
            let hostname;
            try {
              hostname = new URL(scan.url).hostname;
            } catch {
              hostname = scan.url;
            }
            const time = new Date(scan.created_at).toLocaleString();
            return (
              <button
                key={scan.id}
                onClick={() => navigate(`/scan/${scan.id}`)}
                className={`w-full border-l-2 ${
                  rowBorder[scan.verdict] || "border-l-[#484f58]"
                } hover:bg-[#1c2128] transition-colors text-left border-b border-[#30363d] last:border-b-0`}
              >
                {/* Desktop */}
                <div className="hidden sm:grid grid-cols-12 gap-4 items-center px-4 py-2.5">
                  <div className="col-span-5 truncate font-mono text-sm text-[#e6edf3]" title={scan.url}>
                    {hostname}
                  </div>
                  <div className="col-span-3 text-xs font-mono text-[#8b949e]">{time}</div>
                  <div className="col-span-1 text-center font-bold font-mono text-[#e6edf3]">{scan.risk_score}</div>
                  <div className="col-span-2 flex justify-center">
                    <span className={`text-xs font-mono font-bold ${verdictStyles[scan.verdict] || verdictStyles.Suspicious}`}>
                      {scan.verdict}
                    </span>
                  </div>
                  <div className="col-span-1 flex justify-end">
                    <ExternalLink className="w-3.5 h-3.5 text-[#484f58]" />
                  </div>
                </div>
                {/* Mobile */}
                <div className="sm:hidden p-3 space-y-1">
                  <div className="flex items-center justify-between">
                    <span className="font-mono text-sm truncate max-w-[200px] text-[#e6edf3]">
                      {hostname}
                    </span>
                    <span className={`text-xs font-mono font-bold ${verdictStyles[scan.verdict] || verdictStyles.Suspicious}`}>
                      {scan.verdict}
                    </span>
                  </div>
                  <div className="flex items-center justify-between text-xs text-[#8b949e] font-mono">
                    <span>{time}</span>
                    <span className="font-bold text-[#e6edf3]">{scan.risk_score}</span>
                  </div>
                </div>
              </button>
            );
          })}
        </div>
      )}
    </div>
  );
}
