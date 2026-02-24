import React from "react";
import { Link, useLocation } from "react-router-dom";
import { Shield, Sun, Moon, History, Home } from "lucide-react";
import { useTheme } from "../context/ThemeContext";

export default function Header() {
  const { dark, toggle } = useTheme();
  const location = useLocation();

  const linkClass = (path) =>
    `flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-sm font-medium transition-colors ${
      location.pathname === path
        ? "bg-blue-600 text-white"
        : "text-gray-400 hover:text-white hover:bg-white/10 dark:hover:bg-white/10"
    }`;

  return (
    <header className="sticky top-0 z-50 backdrop-blur-xl bg-white/80 dark:bg-navy-900/80 border-b border-gray-200 dark:border-white/10">
      <div className="max-w-5xl mx-auto px-4 h-14 flex items-center justify-between">
        <Link to="/" className="flex items-center gap-2 font-bold text-lg">
          <Shield className="w-6 h-6 text-blue-500" />
          <span className="bg-gradient-to-r from-blue-400 to-cyan-400 bg-clip-text text-transparent">
            PhishScan
          </span>
        </Link>

        <nav className="flex items-center gap-2">
          <Link to="/" className={linkClass("/")}>
            <Home className="w-4 h-4" />
            <span className="hidden sm:inline">Home</span>
          </Link>
          <Link to="/history" className={linkClass("/history")}>
            <History className="w-4 h-4" />
            <span className="hidden sm:inline">History</span>
          </Link>
          <button
            onClick={toggle}
            className="ml-2 p-2 rounded-lg text-gray-400 hover:text-white hover:bg-white/10 transition-colors"
            aria-label="Toggle theme"
          >
            {dark ? <Sun className="w-4 h-4" /> : <Moon className="w-4 h-4" />}
          </button>
        </nav>
      </div>
    </header>
  );
}
