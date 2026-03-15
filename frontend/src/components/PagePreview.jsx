import React, { useState, useEffect, useRef } from "react";
import { ChevronDown, ChevronUp, ExternalLink, ImageOff, Loader2 } from "lucide-react";
import { getUrlscanResult } from "../api";

const verdictStyle = {
  Clean: "text-[#3fb950]",
  "Potentially Suspicious": "text-[#d29922]",
  Suspicious: "text-[#d29922]",
  Malicious: "text-[#f85149]",
};

export default function PagePreview({ urlscan, scanId }) {
  const [data, setData] = useState(urlscan);
  const [imgError, setImgError] = useState(false);
  const [polling, setPolling] = useState(false);
  const [expanded, setExpanded] = useState(false);
  const timerRef = useRef(null);
  const attemptsRef = useRef(0);

  useEffect(() => {
    setData(urlscan);
    setImgError(false);
    attemptsRef.current = 0;

    const shouldPoll = urlscan && urlscan.urlscan_uuid && !urlscan.available && scanId;
    if (!shouldPoll) {
      setPolling(false);
      return;
    }

    setPolling(true);

    const poll = async () => {
      try {
        const result = await getUrlscanResult(scanId);
        if (result.available) {
          setData(result);
          setPolling(false);
          return;
        }
      } catch {
        // ignore fetch errors, keep polling
      }

      attemptsRef.current += 1;
      if (attemptsRef.current >= 12) {
        setPolling(false);
        return;
      }
      timerRef.current = setTimeout(poll, 5000);
    };

    timerRef.current = setTimeout(poll, 5000);

    return () => clearTimeout(timerRef.current);
  }, [urlscan, scanId]);

  // No URLscan data at all
  if (!data || (!data.available && !data.urlscan_uuid)) {
    return (
      <div className="bg-[#161b22] border border-[#30363d] rounded-md overflow-hidden">
        <button
          onClick={() => setExpanded(!expanded)}
          className="w-full flex items-center justify-between px-4 py-2.5 border-l-2 border-l-[#f85149] hover:bg-[#1c2128] transition-colors"
        >
          <span className="text-xs font-semibold uppercase tracking-widest text-[#8b949e]">Page Capture</span>
          <div className="flex items-center gap-2">
            <span className="text-xs font-mono text-[#484f58]">unavailable</span>
            {expanded ? <ChevronUp className="w-3.5 h-3.5 text-[#8b949e]" /> : <ChevronDown className="w-3.5 h-3.5 text-[#8b949e]" />}
          </div>
        </button>
        {expanded && (
          <div className="border-t border-[#30363d] flex flex-col items-center justify-center py-10 text-[#484f58]">
            <ImageOff className="w-8 h-8 mb-2 opacity-50" />
            <p className="text-xs font-mono">URLscan.io API key not configured</p>
          </div>
        )}
      </div>
    );
  }

  // Polling state
  if (!data.available && polling) {
    return (
      <div className="bg-[#161b22] border border-[#30363d] rounded-md overflow-hidden">
        <button
          onClick={() => setExpanded(!expanded)}
          className="w-full flex items-center justify-between px-4 py-2.5 border-l-2 border-l-[#f85149] hover:bg-[#1c2128] transition-colors"
        >
          <span className="text-xs font-semibold uppercase tracking-widest text-[#8b949e]">Page Capture</span>
          <div className="flex items-center gap-2">
            <Loader2 className="w-3.5 h-3.5 text-[#8b949e] animate-spin" />
            <span className="text-xs font-mono text-[#8b949e]">loading...</span>
            {expanded ? <ChevronUp className="w-3.5 h-3.5 text-[#8b949e]" /> : <ChevronDown className="w-3.5 h-3.5 text-[#8b949e]" />}
          </div>
        </button>
        {expanded && (
          <div className="border-t border-[#30363d] flex flex-col items-center justify-center py-10 text-[#8b949e]">
            <Loader2 className="w-6 h-6 mb-2 animate-spin opacity-60" />
            <p className="text-xs font-mono">URLscan.io is capturing this page</p>
          </div>
        )}
      </div>
    );
  }

  // Timed out
  if (!data.available && !polling) {
    return (
      <div className="bg-[#161b22] border border-[#30363d] rounded-md overflow-hidden">
        <button
          onClick={() => setExpanded(!expanded)}
          className="w-full flex items-center justify-between px-4 py-2.5 border-l-2 border-l-[#f85149] hover:bg-[#1c2128] transition-colors"
        >
          <span className="text-xs font-semibold uppercase tracking-widest text-[#8b949e]">Page Capture</span>
          <div className="flex items-center gap-2">
            <span className="text-xs font-mono text-[#484f58]">pending</span>
            {data.report_url && (
              <a
                href={data.report_url}
                target="_blank"
                rel="noopener noreferrer"
                onClick={(e) => e.stopPropagation()}
                className="text-xs font-mono text-[#f85149] hover:underline flex items-center gap-1"
              >
                Report <ExternalLink className="w-3 h-3" />
              </a>
            )}
            {expanded ? <ChevronUp className="w-3.5 h-3.5 text-[#8b949e]" /> : <ChevronDown className="w-3.5 h-3.5 text-[#8b949e]" />}
          </div>
        </button>
        {expanded && (
          <div className="border-t border-[#30363d] flex flex-col items-center justify-center py-10 text-[#484f58]">
            <ImageOff className="w-8 h-8 mb-2 opacity-50" />
            <p className="text-xs font-mono">Preview not yet available</p>
          </div>
        )}
      </div>
    );
  }

  // Ready — show screenshot
  const vStyle = data.verdict ? (verdictStyle[data.verdict] || "text-[#d29922]") : null;

  return (
    <div className="bg-[#161b22] border border-[#30363d] rounded-md overflow-hidden">
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full flex items-center justify-between px-4 py-2.5 border-l-2 border-l-[#f85149] hover:bg-[#1c2128] transition-colors"
      >
        <span className="text-xs font-semibold uppercase tracking-widest text-[#8b949e]">Page Capture</span>
        <div className="flex items-center gap-2">
          {data.verdict && (
            <span className={`text-xs font-mono font-bold ${vStyle}`}>{data.verdict}</span>
          )}
          {data.report_url && (
            <a
              href={data.report_url}
              target="_blank"
              rel="noopener noreferrer"
              onClick={(e) => e.stopPropagation()}
              className="text-xs font-mono text-[#f85149] hover:underline flex items-center gap-1"
            >
              Report <ExternalLink className="w-3 h-3" />
            </a>
          )}
          {expanded ? <ChevronUp className="w-3.5 h-3.5 text-[#8b949e]" /> : <ChevronDown className="w-3.5 h-3.5 text-[#8b949e]" />}
        </div>
      </button>

      {expanded && (
        <div className="border-t border-[#30363d] bg-[#0d1117]">
          {data.screenshot_url && !imgError ? (
            <img
              src={data.screenshot_url}
              alt="Page screenshot from URLscan.io"
              className="w-full max-h-[400px] object-contain object-top"
              onError={() => setImgError(true)}
            />
          ) : (
            <div className="flex flex-col items-center justify-center py-12 text-[#484f58]">
              <ImageOff className="w-8 h-8 mb-2 opacity-50" />
              <p className="text-xs font-mono">Screenshot unavailable</p>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
