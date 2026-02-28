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
    `flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-sm font-medium transition-colors cursor-pointer ${
      location.pathname === path
        ? "text-white bg-white/10"
        : "text-sp-text hover:text-white hover:bg-white/5"
    }`;

  return (
    <header className="sticky top-0 z-50 bg-sp-bg/90 backdrop-blur-xl border-b border-sp-border">
      <div className="max-w-5xl mx-auto px-4 h-14 flex items-center justify-between">
        <a
          href="/"
          onClick={navTo("/")}
          className="flex items-center gap-2.5 cursor-pointer"
        >
          <img src="/logoclose.png" alt="SafeLink" className="h-8 w-auto" />
          <span className="font-bold text-lg text-white tracking-tight">SafeLink</span>
        </a>

        <nav className="flex items-center gap-2">
          <a href="/" onClick={navTo("/")} className={linkClass("/")}>
            <Home className="w-4 h-4" />
            <span className="hidden sm:inline">Home</span>
          </a>
          <a href="/history" onClick={navTo("/history")} className={linkClass("/history")}>
            <History className="w-4 h-4" />
            <span className="hidden sm:inline">History</span>
          </a>
          <button
            onClick={() => navigate("/")}
            className="ml-2 px-4 py-1.5 bg-sp-red hover:bg-sp-red-hover text-white text-sm font-semibold rounded-lg transition-colors"
          >
            New Scan
          </button>
        </nav>
      </div>
    </header>
  );
}
