import React from "react";
import { ShieldCheck, ShieldAlert, ShieldX, AlertTriangle } from "lucide-react";

const config = {
  Safe: {
    bg: "bg-green-500/10 border-green-500/30",
    text: "text-green-400",
    Icon: ShieldCheck,
  },
  Suspicious: {
    bg: "bg-sp-red/10 border-sp-red/30",
    text: "text-sp-red",
    Icon: AlertTriangle,
  },
  "Likely Phishing": {
    bg: "bg-sp-red/10 border-sp-red/30",
    text: "text-sp-red",
    Icon: ShieldAlert,
  },
  Phishing: {
    bg: "bg-sp-red/10 border-sp-red/30",
    text: "text-sp-red",
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
