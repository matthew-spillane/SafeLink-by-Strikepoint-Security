import React from "react";
import { CheckCircle2, AlertTriangle, XCircle, MinusCircle } from "lucide-react";

export default function SummaryBar({ checks }) {
  const passed = checks.filter((c) => c.status === "pass").length;
  const warnings = checks.filter((c) => c.status === "warning").length;
  const failed = checks.filter((c) => c.status === "fail").length;
  const skipped = checks.filter((c) => c.status === "skipped").length;

  const items = [
    { label: "Passed", count: passed, color: "text-green-400", Icon: CheckCircle2 },
    { label: "Warnings", count: warnings, color: "text-gray-300", Icon: AlertTriangle },
    { label: "Failed", count: failed, color: "text-sp-red", Icon: XCircle },
    { label: "Skipped", count: skipped, color: "text-sp-muted", Icon: MinusCircle },
  ];

  return (
    <div className="grid grid-cols-4 gap-3">
      {items.map((item) => (
        <div
          key={item.label}
          className="glass-card rounded-xl p-3 flex flex-col items-center gap-1"
        >
          <item.Icon className={`w-5 h-5 ${item.color}`} />
          <span className="text-xl font-bold text-white">{item.count}</span>
          <span className="text-xs text-sp-text">{item.label}</span>
        </div>
      ))}
    </div>
  );
}
