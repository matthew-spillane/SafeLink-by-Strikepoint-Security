import React, { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { History, Loader2, ExternalLink } from "lucide-react";
import { getHistory } from "../api";

const verdictStyles = {
  Safe: "bg-green-500/10 text-green-400",
  Suspicious: "bg-yellow-500/10 text-yellow-400",
  "Likely Phishing": "bg-orange-500/10 text-orange-400",
  Phishing: "bg-red-500/10 text-red-400",
};

const rowBorder = {
  Safe: "border-l-green-500",
  Suspicious: "border-l-yellow-500",
  "Likely Phishing": "border-l-orange-500",
  Phishing: "border-l-red-500",
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
        <Loader2 className="w-8 h-8 text-blue-500 animate-spin" />
        <p className="text-gray-400 text-sm">Loading scan history...</p>
      </div>
    );
  }

  return (
    <div className="pt-8">
      <div className="flex items-center gap-2 mb-6">
        <History className="w-5 h-5 text-blue-400" />
        <h2 className="text-xl font-bold">Scan History</h2>
      </div>

      {scans.length === 0 ? (
        <div className="text-center py-16 text-gray-400">
          <p>No scans yet. Go scan a URL!</p>
        </div>
      ) : (
        <div className="space-y-2">
          {/* Header (desktop) */}
          <div className="hidden sm:grid grid-cols-12 gap-4 px-4 py-2 text-xs font-semibold text-gray-400 uppercase tracking-wider">
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
                  rowBorder[scan.verdict] || "border-l-gray-500"
                } hover:bg-white/5 transition-colors text-left`}
              >
                {/* Desktop */}
                <div className="hidden sm:grid grid-cols-12 gap-4 items-center px-4 py-3">
                  <div className="col-span-5 truncate font-mono text-sm" title={scan.url}>
                    {hostname}
                  </div>
                  <div className="col-span-3 text-sm text-gray-400">{time}</div>
                  <div className="col-span-1 text-center font-bold">{scan.risk_score}</div>
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
                    <ExternalLink className="w-4 h-4 text-gray-500" />
                  </div>
                </div>
                {/* Mobile */}
                <div className="sm:hidden p-4 space-y-1">
                  <div className="flex items-center justify-between">
                    <span className="font-mono text-sm truncate max-w-[200px]">
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
                  <div className="flex items-center justify-between text-xs text-gray-400">
                    <span>{time}</span>
                    <span className="font-bold">Score: {scan.risk_score}</span>
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
