import React from "react";
import { CheckCircle2, AlertTriangle, XCircle, MinusCircle } from "lucide-react";

export default function SummaryBar({ checks }) {
  const passed = checks.filter((c) => c.status === "pass").length;
  const warnings = checks.filter((c) => c.status === "warning").length;
  const failed = checks.filter((c) => c.status === "fail").length;
  const skipped = checks.filter((c) => c.status === "skipped").length;

  const items = [
    { label: "Passed", count: passed, color: "text-green-400", Icon: CheckCircle2 },
    { label: "Warnings", count: warnings, color: "text-yellow-400", Icon: AlertTriangle },
    { label: "Failed", count: failed, color: "text-red-400", Icon: XCircle },
    { label: "Skipped", count: skipped, color: "text-gray-400", Icon: MinusCircle },
  ];

  return (
    <div className="grid grid-cols-4 gap-3">
      {items.map((item) => (
        <div
          key={item.label}
          className="glass-card rounded-xl p-3 flex flex-col items-center gap-1"
        >
          <item.Icon className={`w-5 h-5 ${item.color}`} />
          <span className="text-xl font-bold">{item.count}</span>
          <span className="text-xs text-gray-400">{item.label}</span>
        </div>
      ))}
    </div>
  );
}
