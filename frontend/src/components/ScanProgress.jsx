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
        <div className="w-16 h-16 rounded-full border-4 border-sp-red/20 animate-pulse-ring" />
        <div className="absolute top-3 left-3 w-10 h-10 flex items-center justify-center">
          {React.createElement(stages[activeStage].Icon, {
            className: `w-6 h-6 text-sp-red ${activeStage < stages.length - 1 ? "animate-spin-slow" : ""}`,
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
                  className={`w-2 h-2 rounded-full transition-colors duration-300 ${
                    isDone
                      ? "bg-green-400"
                      : isActive
                      ? "bg-sp-red animate-pulse"
                      : "bg-sp-border"
                  }`}
                />
                <span
                  className={`text-xs font-medium transition-colors duration-300 ${
                    isDone
                      ? "text-green-400"
                      : isActive
                      ? "text-white"
                      : "text-sp-muted"
                  }`}
                >
                  {stage.label}
                </span>
              </div>
              {i < stages.length - 1 && (
                <div
                  className={`w-6 h-px transition-colors duration-300 ${
                    isDone ? "bg-green-400" : "bg-sp-border"
                  }`}
                />
              )}
            </React.Fragment>
          );
        })}
      </div>

      <p className="text-sp-text text-sm">
        Analyzing URL across multiple security engines...
      </p>
    </div>
  );
}
