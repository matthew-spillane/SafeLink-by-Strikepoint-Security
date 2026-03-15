import React, { useState, useEffect } from "react";
import { Shield, Search, Database, CheckCircle2 } from "lucide-react";

const stages = [
  { label: "Submitting", Icon: Shield, duration: 1500 },
  { label: "Analyzing", Icon: Search, duration: 4000 },
  { label: "Enriching", Icon: Database, duration: 6000 },
  { label: "Complete", Icon: CheckCircle2, duration: Infinity },
];

export default function ScanProgress() {
  const [activeStage, setActiveStage] = useState(0);

  useEffect(() => {
    let elapsed = 0;
    const timers = [];

    for (let i = 0; i < stages.length - 1; i++) {
      elapsed += stages[i].duration;
      timers.push(setTimeout(() => setActiveStage(i + 1), elapsed));
    }

    return () => timers.forEach(clearTimeout);
  }, []);

  return (
    <div className="flex flex-col items-center gap-6 py-16 animate-fade-in-up">
      {/* Spinner */}
      <div className="relative">
        <div className="w-14 h-14 rounded-full border-2 border-[#f85149]/20 animate-pulse-ring" />
        <div className="absolute top-3 left-3 w-8 h-8 flex items-center justify-center">
          {React.createElement(stages[activeStage].Icon, {
            className: `w-5 h-5 text-[#f85149] ${activeStage < stages.length - 1 ? "animate-spin-slow" : ""}`,
          })}
        </div>
      </div>

      {/* Stage indicators */}
      <div className="flex items-center gap-2">
        {stages.map((stage, i) => {
          const isActive = i === activeStage;
          const isDone = i < activeStage;
          return (
            <React.Fragment key={stage.label}>
              <div className="flex items-center gap-1.5">
                <div
                  className={`w-1.5 h-1.5 rounded-full transition-colors duration-300 ${
                    isDone
                      ? "bg-[#3fb950]"
                      : isActive
                      ? "bg-[#f85149] animate-pulse"
                      : "bg-[#30363d]"
                  }`}
                />
                <span
                  className={`text-xs font-mono transition-colors duration-300 ${
                    isDone
                      ? "text-[#3fb950]"
                      : isActive
                      ? "text-[#e6edf3]"
                      : "text-[#484f58]"
                  }`}
                >
                  {stage.label}
                </span>
              </div>
              {i < stages.length - 1 && (
                <div
                  className={`w-6 h-px transition-colors duration-300 ${
                    isDone ? "bg-[#3fb950]" : "bg-[#30363d]"
                  }`}
                />
              )}
            </React.Fragment>
          );
        })}
      </div>

      <p className="text-[#8b949e] text-xs font-mono">
        Analyzing URL across multiple security engines...
      </p>
    </div>
  );
}
