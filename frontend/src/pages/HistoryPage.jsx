import React, { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { History, Loader2, ExternalLink } from "lucide-react";
import { getHistory } from "../api";

const verdictStyles = {
  Safe: "bg-green-500/10 text-green-400",
  Suspicious: "bg-sp-red/10 text-sp-red",
  "Likely Phishing": "bg-sp-red/10 text-sp-red",
  Phishing: "bg-sp-red/10 text-sp-red",
};

const rowBorder = {
  Safe: "border-l-green-500",
  Suspicious: "border-l-sp-red",
  "Likely Phishing": "border-l-sp-red",
  Phishing: "border-l-sp-red",
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
        <Loader2 className="w-8 h-8 text-sp-red animate-spin" />
        <p className="text-sp-text text-sm">Loading scan history...</p>
      </div>
    );
  }

  return (
    <div className="pt-8">
      <div className="flex items-center gap-2 mb-6">
        <History className="w-5 h-5 text-sp-red" />
        <h2 className="text-xl font-bold text-white">Scan History</h2>
      </div>

      {scans.length === 0 ? (
        <div className="text-center py-16 text-sp-text">
          <p>No scans yet. Go scan a URL!</p>
        </div>
      ) : (
        <div className="space-y-2">
          {/* Header (desktop) */}
          <div className="hidden sm:grid grid-cols-12 gap-4 px-4 py-2 text-xs font-semibold text-sp-muted uppercase tracking-wider">
            <div className="col-span-5">URL</div>
            <div className="col-span-3">Time</div>
            <div className="col-span-1 text-center">Score</div>
            <div className="col-span-2 text-center">Verdict</div>
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
                className={`w-full glass-card rounded-xl border-l-4 ${
                  rowBorder[scan.verdict] || "border-l-sp-muted"
                } hover:bg-sp-card-light transition-colors text-left`}
              >
                {/* Desktop */}
                <div className="hidden sm:grid grid-cols-12 gap-4 items-center px-4 py-3">
                  <div className="col-span-5 truncate font-mono text-sm text-white" title={scan.url}>
                    {hostname}
                  </div>
                  <div className="col-span-3 text-sm text-sp-text">{time}</div>
                  <div className="col-span-1 text-center font-bold text-white">{scan.risk_score}</div>
                  <div className="col-span-2 flex justify-center">
                    <span
                      className={`px-2.5 py-1 rounded-full text-xs font-semibold ${
                        verdictStyles[scan.verdict] || verdictStyles.Suspicious
                      }`}
                    >
                      {scan.verdict}
                    </span>
                  </div>
                  <div className="col-span-1 flex justify-end">
                    <ExternalLink className="w-4 h-4 text-sp-muted" />
                  </div>
                </div>
                {/* Mobile */}
                <div className="sm:hidden p-4 space-y-1">
                  <div className="flex items-center justify-between">
                    <span className="font-mono text-sm truncate max-w-[200px] text-white">
                      {hostname}
                    </span>
                    <span
                      className={`px-2 py-0.5 rounded-full text-xs font-semibold ${
                        verdictStyles[scan.verdict] || verdictStyles.Suspicious
                      }`}
                    >
                      {scan.verdict}
                    </span>
                  </div>
                  <div className="flex items-center justify-between text-xs text-sp-text">
                    <span>{time}</span>
                    <span className="font-bold text-white">Score: {scan.risk_score}</span>
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
