import React, { useState } from "react";
import { Monitor, ExternalLink, ImageOff, ShieldCheck, ShieldAlert } from "lucide-react";

const verdictConfig = {
  Clean: { bg: "bg-green-500/20", text: "text-green-400", Icon: ShieldCheck },
  "Potentially Suspicious": { bg: "bg-yellow-500/20", text: "text-yellow-400", Icon: ShieldAlert },
  Suspicious: { bg: "bg-orange-500/20", text: "text-orange-400", Icon: ShieldAlert },
  Malicious: { bg: "bg-red-500/20", text: "text-red-400", Icon: ShieldAlert },
};

export default function PagePreview({ urlscan }) {
  const [imgError, setImgError] = useState(false);

  if (!urlscan || !urlscan.available) {
    return (
      <div className="glass-card rounded-xl p-6 animate-fade-in-up">
        <div className="flex items-center gap-2 mb-4">
          <Monitor className="w-5 h-5 text-blue-400" />
          <h3 className="text-sm font-semibold uppercase tracking-wider text-gray-300">
            Page Preview
          </h3>
        </div>
        <div className="flex flex-col items-center justify-center py-12 text-gray-500">
          <ImageOff className="w-10 h-10 mb-3 opacity-50" />
          <p className="text-sm">Preview unavailable</p>
          <p className="text-xs mt-1 text-gray-600">URLscan could not capture this page</p>
        </div>
      </div>
    );
  }

  const vc = urlscan.verdict ? (verdictConfig[urlscan.verdict] || verdictConfig.Suspicious) : null;

  return (
    <div className="glass-card rounded-xl overflow-hidden animate-fade-in-up">
      <div className="flex items-center justify-between p-4 border-b border-white/5">
        <div className="flex items-center gap-2">
          <Monitor className="w-5 h-5 text-blue-400" />
          <h3 className="text-sm font-semibold uppercase tracking-wider text-gray-300">
            Page Preview
          </h3>
        </div>
        <div className="flex items-center gap-3">
          {vc && urlscan.verdict && (
            <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs font-semibold ${vc.bg} ${vc.text}`}>
              <vc.Icon className="w-3.5 h-3.5" />
              {urlscan.verdict}
            </span>
          )}
          {urlscan.report_url && (
            <a
              href={urlscan.report_url}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-blue-600 hover:bg-blue-700 text-white transition-colors"
            >
              View Full Report
              <ExternalLink className="w-3.5 h-3.5" />
            </a>
          )}
        </div>
      </div>

      <div className="bg-black/20">
        {urlscan.screenshot_url && !imgError ? (
          <img
            src={urlscan.screenshot_url}
            alt="Page screenshot from URLscan.io"
            className="w-full max-h-[400px] object-contain object-top"
            onError={() => setImgError(true)}
          />
        ) : (
          <div className="flex flex-col items-center justify-center py-16 text-gray-500">
            <ImageOff className="w-10 h-10 mb-3 opacity-50" />
            <p className="text-sm">Screenshot unavailable</p>
          </div>
        )}
      </div>
    </div>
  );
}
