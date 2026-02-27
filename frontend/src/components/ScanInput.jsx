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
        <Search className="absolute left-4 w-5 h-5 text-sp-muted pointer-events-none" />
        <input
          type="text"
          value={url}
          onChange={(e) => {
            setUrl(e.target.value);
            if (error) setError("");
          }}
          placeholder="Enter a URL to scan..."
          disabled={loading}
          className="w-full pl-12 pr-28 py-4 rounded-2xl bg-sp-card border border-sp-border text-white text-base focus:outline-none focus:ring-2 focus:ring-sp-red focus:border-transparent placeholder-sp-muted disabled:opacity-50 transition-all"
        />
        <button
          type="submit"
          disabled={loading}
          className="absolute right-2 px-5 py-2.5 bg-sp-red hover:bg-sp-red-hover disabled:bg-sp-red/50 text-white text-sm font-semibold rounded-xl transition-colors flex items-center gap-2"
        >
          {loading ? (
            <>
              <Loader2 className="w-4 h-4 animate-spin" />
              Scanning
            </>
          ) : (
            "Scan"
          )}
        </button>
      </div>
      {error && <p className="mt-2 text-sm text-sp-red text-center">{error}</p>}
    </form>
  );
}
