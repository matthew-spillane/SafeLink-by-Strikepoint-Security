import React from "react";
import { ArrowRight } from "lucide-react";

export default function RedirectChain({ chain }) {
  if (!chain || chain.length <= 1) return null;

  return (
    <div className="bg-[#161b22] border border-[#30363d] rounded-md overflow-hidden animate-fade-in-up">
      <div className="flex items-center justify-between px-4 py-2.5 border-b border-[#30363d] border-l-2 border-l-[#f85149]">
        <span className="text-xs font-semibold uppercase tracking-widest text-[#8b949e]">
          Redirect Chain
        </span>
        <span className="text-xs font-mono text-[#484f58]">
          {chain.length - 1} hop{chain.length - 1 !== 1 ? "s" : ""}
        </span>
      </div>
      <div className="flex flex-wrap items-center gap-1.5 px-4 py-3">
        {chain.map((url, i) => {
          let hostname;
          try {
            hostname = new URL(url).hostname;
          } catch {
            hostname = url;
          }
          return (
            <React.Fragment key={i}>
              <span
                className={`px-2 py-1 rounded-sm text-xs font-mono border ${
                  i === 0
                    ? "bg-[#f85149]/10 border-[#f85149]/30 text-[#f85149]"
                    : i === chain.length - 1
                    ? "bg-[#3fb950]/10 border-[#3fb950]/30 text-[#3fb950]"
                    : "bg-[#0d1117] border-[#30363d] text-[#8b949e]"
                }`}
                title={url}
              >
                {hostname}
              </span>
              {i < chain.length - 1 && (
                <ArrowRight className="w-3 h-3 text-[#484f58] shrink-0" />
              )}
            </React.Fragment>
          );
        })}
      </div>
    </div>
  );
}
