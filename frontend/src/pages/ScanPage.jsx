import React, { useEffect, useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { Loader2 } from "lucide-react";
import ResultsDashboard from "../components/ResultsDashboard";
import { getScan } from "../api";

export default function ScanPage() {
  const { id } = useParams();
  const navigate = useNavigate();
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");

  useEffect(() => {
    setLoading(true);
    getScan(id)
      .then((data) => setResult(data))
      .catch((err) => setError(err.message || "Failed to load scan."))
      .finally(() => setLoading(false));
  }, [id]);

  if (loading) {
    return (
      <div className="flex flex-col items-center gap-4 py-24">
        <Loader2 className="w-8 h-8 text-sp-red animate-spin" />
        <p className="text-sp-text text-sm">Loading scan results...</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex flex-col items-center gap-4 py-24">
        <div className="p-4 rounded-xl bg-sp-red/10 border border-sp-red/30 text-sp-red text-sm text-center max-w-md">
          {error}
        </div>
        <button
          onClick={() => navigate("/")}
          className="text-sm text-sp-red hover:underline"
        >
          Go back to scanner
        </button>
      </div>
    );
  }

  const glowColor = result
    ? {
        Safe: "rgba(34, 197, 94, 0.15)",
        Suspicious: "rgba(234, 179, 8, 0.15)",
      }[result.verdict] || "rgba(180, 30, 20, 0.35)"
    : undefined;

  return (
    <div className="pt-8">
      {glowColor && (
        <div
          className="verdict-glow"
          style={{
            background: `radial-gradient(ellipse at 50% 50%, transparent 55%, rgba(0, 0, 0, 0.5) 100%), radial-gradient(ellipse at 12% 15%, ${glowColor} 0%, transparent 50%), #0a0a0a`,
          }}
        />
      )}
      <ResultsDashboard result={result} onReset={() => navigate("/")} />
    </div>
  );
}
