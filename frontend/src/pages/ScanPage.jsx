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
        <Loader2 className="w-6 h-6 text-[#f85149] animate-spin" />
        <p className="text-[#8b949e] text-xs font-mono">Loading scan results...</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex flex-col items-center gap-4 py-24">
        <div className="p-3 rounded-md bg-[#f85149]/10 border border-[#f85149]/30 text-[#f85149] text-xs font-mono text-center max-w-md">
          {error}
        </div>
        <button
          onClick={() => navigate("/")}
          className="text-xs font-mono text-[#f85149] hover:underline"
        >
          Go back to scanner
        </button>
      </div>
    );
  }

  return (
    <div className="pt-6">
      <ResultsDashboard result={result} onReset={() => navigate("/")} />
    </div>
  );
}
