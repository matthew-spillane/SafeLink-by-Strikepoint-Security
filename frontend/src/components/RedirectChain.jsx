import React from "react";
import { ArrowRight, Globe } from "lucide-react";

export default function RedirectChain({ chain }) {
  if (!chain || chain.length <= 1) return null;

  return (
    <div className="glass-card rounded-xl p-4 animate-fade-in-up">
      <h3 className="text-sm font-semibold mb-3 flex items-center gap-2">
        <Globe className="w-4 h-4 text-sp-red" />
        <span className="uppercase tracking-wider text-sp-red">
          Redirect Chain
        </span>
        <span className="text-sp-text text-xs normal-case tracking-normal">
          ({chain.length - 1} hop{chain.length - 1 !== 1 ? "s" : ""})
        </span>
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
                    ? "bg-sp-red/10 border-sp-red/30 text-sp-red"
                    : i === chain.length - 1
                    ? "bg-green-500/10 border-green-500/30 text-green-300"
                    : "bg-sp-card-light border-sp-border text-sp-text"
                }`}
                title={url}
              >
                {hostname}
              </div>
              {i < chain.length - 1 && (
                <ArrowRight className="w-3 h-3 text-sp-muted shrink-0" />
              )}
            </React.Fragment>
          );
        })}
      </div>
    </div>
  );
}
