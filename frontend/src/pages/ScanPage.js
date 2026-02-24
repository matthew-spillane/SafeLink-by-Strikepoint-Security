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
        <Loader2 className="w-8 h-8 text-blue-500 animate-spin" />
        <p className="text-gray-400 text-sm">Loading scan results...</p>
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex flex-col items-center gap-4 py-24">
        <div className="p-4 rounded-xl bg-red-500/10 border border-red-500/30 text-red-400 text-sm text-center max-w-md">
          {error}
        </div>
        <button
          onClick={() => navigate("/")}
          className="text-sm text-blue-400 hover:underline"
        >
          Go back to scanner
        </button>
      </div>
    );
  }

  return (
    <div className="pt-8">
      <ResultsDashboard result={result} onReset={() => navigate("/")} />
    </div>
  );
}
