import React from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { Home, History } from "lucide-react";

export default function Header() {
  const location = useLocation();
  const navigate = useNavigate();

  const navTo = (path) => (e) => {
    e.preventDefault();
    navigate(path);
  };

  const linkClass = (path) =>
    `flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium transition-colors cursor-pointer ${
      location.pathname === path
        ? "text-[#e6edf3] bg-[#1c2128]"
        : "text-[#8b949e] hover:text-[#e6edf3] hover:bg-[#1c2128]"
    }`;

  return (
    <header className="sticky top-0 z-50 bg-[#0d1117]/95 border-b border-[#30363d]">
      <div className="max-w-7xl mx-auto px-6 h-12 flex items-center justify-between">
        <a
          href="/"
          onClick={navTo("/")}
          className="flex items-center gap-2.5 cursor-pointer"
        >
          <img src="/logoclose.png" alt="SafeLink" className="h-7 w-auto" />
          <span className="font-bold text-sm text-[#e6edf3] tracking-tight font-mono">SAFELINK</span>
        </a>

        <nav className="flex items-center gap-1">
          <a href="/" onClick={navTo("/")} className={linkClass("/")}>
            <Home className="w-3.5 h-3.5" />
            <span className="hidden sm:inline">Home</span>
          </a>
          <a href="/history" onClick={navTo("/history")} className={linkClass("/history")}>
            <History className="w-3.5 h-3.5" />
            <span className="hidden sm:inline">History</span>
          </a>
          <button
            onClick={() => navigate("/")}
            className="ml-2 px-3 py-1.5 bg-[#f85149] hover:bg-[#da3633] text-white text-xs font-semibold rounded-md transition-colors"
          >
            New Scan
          </button>
        </nav>
      </div>
    </header>
  );
}
