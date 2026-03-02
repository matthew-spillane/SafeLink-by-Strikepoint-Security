import React, { useState } from "react";
import {
  ChevronDown,
  ChevronUp,
  CheckCircle2,
  AlertTriangle,
  XCircle,
  MinusCircle,
  Globe,
  Lock,
  Link2,
  Search,
  Eye,
  MapPin,
  Code,
  FileText,
  ShieldCheck,
  Shield,
} from "lucide-react";

const statusConfig = {
  pass: { color: "text-green-400", bg: "bg-green-500/10", Icon: CheckCircle2 },
  warning: { color: "text-amber-400", bg: "bg-amber-500/10", Icon: AlertTriangle },
  fail: { color: "text-sp-red", bg: "bg-sp-red/10", Icon: XCircle },
  skipped: { color: "text-sp-muted", bg: "bg-white/5", Icon: MinusCircle },
};

const iconMap = {
  VirusTotal: ShieldCheck,
  "Google Safe Browsing": Shield,
  "WHOIS / Domain Age": Globe,
  "SSL Certificate": Lock,
  "Redirect Chain": Link2,
  "Suspicious Keywords": Search,
  "Lookalike Domain": Eye,
  "IP Geolocation": MapPin,
  "URL Structure": Code,
  "Page Content": FileText,
};

export default function CheckCard({ check }) {
  const [expanded, setExpanded] = useState(false);
  const sc = statusConfig[check.status] || statusConfig.skipped;
  const CheckIcon = iconMap[check.name] || Shield;

  return (
    <div className="glass-card rounded-xl overflow-hidden animate-fade-in-up">
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full flex items-center gap-3 p-4 text-left hover:bg-sp-card-light transition-colors"
      >
        <div className={`p-2 rounded-lg ${sc.bg}`}>
          <CheckIcon className={`w-5 h-5 ${sc.color}`} />
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <span className="font-medium text-sm text-white">{check.name}</span>
            <span
              className={`text-xs px-2 py-0.5 rounded-full font-medium ${sc.bg} ${sc.color}`}
            >
              {check.status}
            </span>
          </div>
          <p className="text-sm text-sp-text mt-0.5 truncate">{check.summary}</p>
        </div>
        {expanded ? (
          <ChevronUp className="w-4 h-4 text-sp-muted shrink-0" />
        ) : (
          <ChevronDown className="w-4 h-4 text-sp-muted shrink-0" />
        )}
      </button>
      {expanded && check.details && (
        <div className="px-4 pb-4 border-t border-sp-border">
          <pre className="mt-3 text-xs bg-[#0d0d0d] rounded-lg p-3 overflow-x-auto text-gray-300">
            {JSON.stringify(check.details, null, 2)}
          </pre>
        </div>
      )}
    </div>
  );
}
