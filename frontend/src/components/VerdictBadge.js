import React from "react";
import { ShieldCheck, ShieldAlert, ShieldX, AlertTriangle } from "lucide-react";

const config = {
  Safe: {
    bg: "bg-green-500/10 border-green-500/30",
    text: "text-green-400",
    Icon: ShieldCheck,
  },
  Suspicious: {
    bg: "bg-yellow-500/10 border-yellow-500/30",
    text: "text-yellow-400",
    Icon: AlertTriangle,
  },
  "Likely Phishing": {
    bg: "bg-orange-500/10 border-orange-500/30",
    text: "text-orange-400",
    Icon: ShieldAlert,
  },
  Phishing: {
    bg: "bg-red-500/10 border-red-500/30",
    text: "text-red-400",
    Icon: ShieldX,
  },
};

export default function VerdictBadge({ verdict }) {
  const c = config[verdict] || config.Suspicious;
  const { Icon } = c;
  return (
    <div
      className={`inline-flex items-center gap-2 px-4 py-2 rounded-full border text-sm font-semibold ${c.bg} ${c.text}`}
    >
      <Icon className="w-5 h-5" />
      {verdict}
    </div>
  );
}
