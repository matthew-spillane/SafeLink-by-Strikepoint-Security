import React, { useState, useEffect } from "react";
import { useNavigate, useLocation } from "react-router-dom";
import { Shield, Loader2 } from "lucide-react";
import ScanInput from "../components/ScanInput";
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
    Safe: "bg-green-500/10 text-green-400 border-green-500/30",
    Suspicious: "bg-sp-red/10 text-sp-red border-sp-red/30",
    "Likely Phishing": "bg-sp-red/10 text-sp-red border-sp-red/30",
    Phishing: "bg-sp-red/10 text-sp-red border-sp-red/30",
  };

  return (
    <div className="pt-12 sm:pt-20">
      {/* Hero */}
      {!result && (
        <div className="text-center mb-10 animate-fade-in-up">
          <div className="flex justify-center mb-4">
            <div className="p-3 rounded-2xl bg-sp-red/10">
              <Shield className="w-12 h-12 text-sp-red" />
            </div>
          </div>
          <h1 className="text-3xl sm:text-4xl font-extrabold mb-2 text-white">
            SafeLink
          </h1>
          <p className="text-sp-text text-lg">
            Enterprise-grade phishing URL detection
          </p>
        </div>
      )}

      {/* Scan input */}
      <div className={result ? "mb-8" : "mb-8"}>
        <ScanInput onScan={handleScan} loading={loading} />
      </div>

      {/* Loading state */}
      {loading && (
        <div className="flex flex-col items-center gap-4 py-16 animate-fade-in-up">
          <div className="relative">
            <div className="w-16 h-16 rounded-full border-4 border-sp-red/20 animate-pulse-ring" />
            <Loader2 className="w-8 h-8 text-sp-red animate-spin absolute top-4 left-4" />
          </div>
          <p className="text-sp-text text-sm">Analyzing URL across 10 security checks...</p>
        </div>
      )}

      {/* Error */}
      {error && !loading && (
        <div className="max-w-md mx-auto p-4 rounded-xl bg-sp-red/10 border border-sp-red/30 text-sp-red text-sm text-center animate-fade-in-up">
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
          <h3 className="text-sm font-semibold text-sp-red uppercase tracking-wider mb-3 text-center">
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
                  className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-full border text-xs font-medium transition-colors hover:brightness-125 ${
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
