import React from "react";
import { ArrowRight, Globe } from "lucide-react";

export default function RedirectChain({ chain }) {
  if (!chain || chain.length <= 1) return null;

  return (
    <div className="glass-card rounded-xl p-4 animate-fade-in-up">
      <h3 className="text-sm font-semibold mb-3 flex items-center gap-2">
        <Globe className="w-4 h-4 text-blue-400" />
        Redirect Chain ({chain.length - 1} hop{chain.length - 1 !== 1 ? "s" : ""})
      </h3>
      <div className="flex flex-wrap items-center gap-2">
        {chain.map((url, i) => {
          let hostname;
          try {
            hostname = new URL(url).hostname;
          } catch {
            hostname = url;
          }
          return (
            <React.Fragment key={i}>
              <div
                className={`px-3 py-1.5 rounded-lg text-xs font-mono border ${
                  i === 0
                    ? "bg-blue-500/10 border-blue-500/30 text-blue-300"
                    : i === chain.length - 1
                    ? "bg-green-500/10 border-green-500/30 text-green-300"
                    : "bg-gray-100 dark:bg-white/5 border-gray-200 dark:border-white/10 text-gray-600 dark:text-gray-300"
                }`}
                title={url}
              >
                {hostname}
              </div>
              {i < chain.length - 1 && (
                <ArrowRight className="w-3 h-3 text-gray-500 shrink-0" />
              )}
            </React.Fragment>
          );
        })}
      </div>
    </div>
  );
}
