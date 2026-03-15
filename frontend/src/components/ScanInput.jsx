import React, { useState } from "react";
import { Search, Loader2 } from "lucide-react";

function isValidUrl(str) {
  try {
    const url = new URL(str.startsWith("http") ? str : `https://${str}`);
    return url.hostname.includes(".");
  } catch {
    return false;
  }
}

export default function ScanInput({ onScan, loading }) {
  const [url, setUrl] = useState("");
  const [error, setError] = useState("");

  const handleSubmit = (e) => {
    e.preventDefault();
    const trimmed = url.trim();
    if (!trimmed) {
      setError("Please enter a URL to scan.");
      return;
    }
    if (!isValidUrl(trimmed)) {
      setError("Please enter a valid URL (e.g. https://example.com).");
      return;
    }
    setError("");
    onScan(trimmed);
  };

  return (
    <form onSubmit={handleSubmit} className="w-full max-w-2xl mx-auto">
      <div className="relative flex items-center">
        <Search className="absolute left-4 w-4 h-4 text-[#484f58] pointer-events-none" />
        <input
          type="text"
          value={url}
          onChange={(e) => {
            setUrl(e.target.value);
            if (error) setError("");
          }}
          placeholder="Enter a URL to scan..."
          disabled={loading}
          className="w-full pl-11 pr-28 py-3 rounded-md bg-[#161b22] border border-[#30363d] text-[#e6edf3] text-sm font-mono focus:outline-none focus:ring-1 focus:ring-[#f85149] focus:border-[#f85149] placeholder-[#484f58] disabled:opacity-50 transition-all"
        />
        <button
          type="submit"
          disabled={loading}
          className="absolute right-1.5 px-4 py-2 bg-[#f85149] hover:bg-[#da3633] disabled:bg-[#f85149]/40 text-white text-xs font-semibold font-mono rounded-md transition-colors flex items-center gap-2"
        >
          {loading ? (
            <>
              <Loader2 className="w-3.5 h-3.5 animate-spin" />
              SCANNING
            </>
          ) : (
            "SCAN"
          )}
        </button>
      </div>
      {error && <p className="mt-2 text-xs font-mono text-[#f85149] text-center">{error}</p>}
    </form>
  );
}
