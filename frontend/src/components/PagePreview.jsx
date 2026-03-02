import React, { useState, useEffect, useRef } from "react";
import { Monitor, ExternalLink, ImageOff, ShieldCheck, ShieldAlert, Loader2 } from "lucide-react";
import { getUrlscanResult } from "../api";

const verdictConfig = {
  Clean: { bg: "bg-green-500/20", text: "text-green-400", Icon: ShieldCheck },
  "Potentially Suspicious": { bg: "bg-sp-red/20", text: "text-sp-red", Icon: ShieldAlert },
  Suspicious: { bg: "bg-sp-red/20", text: "text-sp-red", Icon: ShieldAlert },
  Malicious: { bg: "bg-sp-red/20", text: "text-sp-red", Icon: ShieldAlert },
};

export default function PagePreview({ urlscan, scanId }) {
  const [data, setData] = useState(urlscan);
  const [imgError, setImgError] = useState(false);
  const [polling, setPolling] = useState(false);
  const timerRef = useRef(null);
  const attemptsRef = useRef(0);

  useEffect(() => {
    setData(urlscan);
    setImgError(false);
    attemptsRef.current = 0;

    // Start polling if we have a UUID but result isn't ready yet
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
          return; // stop polling
        }
      } catch {
        // ignore fetch errors, keep polling
      }

      attemptsRef.current += 1;
      if (attemptsRef.current >= 12) {
        // 12 attempts × 5s = 60s max
        setPolling(false);
        return;
      }
      timerRef.current = setTimeout(poll, 5000);
    };

    // First poll after 5s
    timerRef.current = setTimeout(poll, 5000);

    return () => clearTimeout(timerRef.current);
  }, [urlscan, scanId]);

  // No URLscan UUID at all — API key not configured
  if (!data || (!data.available && !data.urlscan_uuid)) {
    return (
      <div className="glass-card bg-[#111111] rounded-xl p-6 animate-fade-in-up">
        <div className="flex items-center gap-2 mb-4">
          <Monitor className="w-5 h-5 text-sp-red" />
          <h3 className="text-sm font-semibold uppercase tracking-wider text-sp-red">
            Page Preview
          </h3>
        </div>
        <div className="flex flex-col items-center justify-center py-12 text-sp-muted">
          <ImageOff className="w-10 h-10 mb-3 opacity-50" />
          <p className="text-sm">Preview unavailable</p>
          <p className="text-xs mt-1 text-sp-muted">URLscan.io API key not configured</p>
        </div>
      </div>
    );
  }

  // Loading state — UUID exists but result not ready yet
  if (!data.available && polling) {
    return (
      <div className="glass-card bg-[#111111] rounded-xl p-6 animate-fade-in-up">
        <div className="flex items-center gap-2 mb-4">
          <Monitor className="w-5 h-5 text-sp-red" />
          <h3 className="text-sm font-semibold uppercase tracking-wider text-sp-red">
            Page Preview
          </h3>
        </div>
        <div className="flex flex-col items-center justify-center py-12 text-sp-text">
          <Loader2 className="w-8 h-8 mb-3 animate-spin opacity-60" />
          <p className="text-sm">Loading preview...</p>
          <p className="text-xs mt-1 text-sp-muted">URLscan.io is capturing this page</p>
        </div>
      </div>
    );
  }

  // Timed out waiting — show unavailable with report link if we have one
  if (!data.available && !polling) {
    return (
      <div className="glass-card bg-[#111111] rounded-xl p-6 animate-fade-in-up">
        <div className="flex items-center justify-between mb-4">
          <div className="flex items-center gap-2">
            <Monitor className="w-5 h-5 text-sp-red" />
            <h3 className="text-sm font-semibold uppercase tracking-wider text-sp-red">
              Page Preview
            </h3>
          </div>
          {data.report_url && (
            <a
              href={data.report_url}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-sp-red hover:bg-sp-red-hover text-white transition-colors"
            >
              View Full Report
              <ExternalLink className="w-3.5 h-3.5" />
            </a>
          )}
        </div>
        <div className="flex flex-col items-center justify-center py-12 text-sp-muted">
          <ImageOff className="w-10 h-10 mb-3 opacity-50" />
          <p className="text-sm">Preview not yet available</p>
          <p className="text-xs mt-1 text-sp-muted">URLscan.io is still processing — check the report link</p>
        </div>
      </div>
    );
  }

  // Result ready — show screenshot + verdict
  const vc = data.verdict ? (verdictConfig[data.verdict] || verdictConfig.Suspicious) : null;

  return (
    <div className="glass-card bg-[#111111] rounded-xl overflow-hidden animate-fade-in-up">
      <div className="flex items-center justify-between p-4 border-b border-sp-border">
        <div className="flex items-center gap-2">
          <Monitor className="w-5 h-5 text-sp-red" />
          <h3 className="text-sm font-semibold uppercase tracking-wider text-sp-red">
            Page Preview
          </h3>
        </div>
        <div className="flex items-center gap-3">
          {vc && data.verdict && (
            <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold ${vc.bg} ${vc.text}`}>
              <vc.Icon className="w-3.5 h-3.5" />
              {data.verdict}
            </span>
          )}
          {data.report_url && (
            <a
              href={data.report_url}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-sp-red hover:bg-sp-red-hover text-white transition-colors"
            >
              View Full Report
              <ExternalLink className="w-3.5 h-3.5" />
            </a>
          )}
        </div>
      </div>

      <div className="bg-[#0d0d0d]">
        {data.screenshot_url && !imgError ? (
          <img
            src={data.screenshot_url}
            alt="Page screenshot from URLscan.io"
            className="w-full max-h-[400px] object-contain object-top"
            onError={() => setImgError(true)}
          />
        ) : (
          <div className="flex flex-col items-center justify-center py-16 text-sp-muted">
            <ImageOff className="w-10 h-10 mb-3 opacity-50" />
            <p className="text-sm">Screenshot unavailable</p>
          </div>
        )}
      </div>
    </div>
  );
}
