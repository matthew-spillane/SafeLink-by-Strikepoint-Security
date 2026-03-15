import React, { useState, useEffect } from "react";
import { useNavigate, useLocation } from "react-router-dom";
import { Shield } from "lucide-react";
import ScanInput from "../components/ScanInput";
import ScanProgress from "../components/ScanProgress";
import ResultsDashboard from "../components/ResultsDashboard";
import { scanUrl, getHistory } from "../api";

export default function HomePage() {
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [error, setError] = useState("");
  const [recentScans, setRecentScans] = useState([]);
  const navigate = useNavigate();
  const location = useLocation();

  // Reset results when user navigates to home (e.g. clicking Home/logo)
  useEffect(() => {
    setResult(null);
    setError("");
  }, [location.key]);

  useEffect(() => {
    getHistory()
      .then((data) => setRecentScans(data.slice(0, 5)))
      .catch(() => {});
  }, []);

  const handleScan = async (url) => {
    setLoading(true);
    setError("");
    setResult(null);
    try {
      const data = await scanUrl(url);
      setResult(data);
      // Refresh recent scans
      getHistory()
        .then((h) => setRecentScans(h.slice(0, 5)))
        .catch(() => {});
    } catch (err) {
      setError(err.message || "Scan failed. Please try again.");
    } finally {
      setLoading(false);
    }
  };

  const handleReset = () => {
    setResult(null);
    setError("");
  };

  const verdictColor = {
    Safe: "bg-[#3fb950]/10 text-[#3fb950] border-[#3fb950]/30",
    Suspicious: "bg-[#d29922]/10 text-[#d29922] border-[#d29922]/30",
    "Likely Phishing": "bg-[#db6d28]/10 text-[#db6d28] border-[#db6d28]/30",
    Phishing: "bg-[#f85149]/10 text-[#f85149] border-[#f85149]/30",
  };

  return (
    <div className="pt-12 sm:pt-20">
      {/* Hero */}
      {!result && (
        <div className="text-center mb-10 animate-fade-in-up">
          <div className="flex justify-center mb-4">
            <div className="p-3 rounded-md bg-[#f85149]/10">
              <Shield className="w-10 h-10 text-[#f85149]" />
            </div>
          </div>
          <h1 className="text-2xl sm:text-3xl font-bold mb-1 text-[#e6edf3] font-mono tracking-tight">
            SAFELINK
          </h1>
          <p className="text-[#8b949e] text-sm font-mono">
            Enterprise phishing URL detection
          </p>
        </div>
      )}

      {/* Scan input */}
      <div className="mb-8">
        <ScanInput onScan={handleScan} loading={loading} />
      </div>

      {/* Loading state */}
      {loading && <ScanProgress />}

      {/* Error */}
      {error && !loading && (
        <div className="max-w-md mx-auto p-3 rounded-md bg-[#f85149]/10 border border-[#f85149]/30 text-[#f85149] text-xs font-mono text-center animate-fade-in-up">
          {error}
        </div>
      )}

      {/* Results */}
      {result && !loading && (
        <ResultsDashboard result={result} onReset={handleReset} />
      )}

      {/* Recent scans */}
      {!result && !loading && recentScans.length > 0 && (
        <div className="mt-12 animate-fade-in-up">
          <h3 className="text-xs font-semibold uppercase tracking-widest text-[#8b949e] mb-3 text-center">
            Recent Scans
          </h3>
          <div className="flex flex-wrap justify-center gap-2">
            {recentScans.map((scan) => {
              let hostname;
              try {
                hostname = new URL(scan.url).hostname;
              } catch {
                hostname = scan.url;
              }
              return (
                <button
                  key={scan.id}
                  onClick={() => navigate(`/scan/${scan.id}`)}
                  className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-sm border text-xs font-mono transition-colors hover:brightness-125 ${
                    verdictColor[scan.verdict] || verdictColor.Suspicious
                  }`}
                >
                  <span className="truncate max-w-[140px]">{hostname}</span>
                  <span className="opacity-60">{scan.risk_score}</span>
                </button>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}
