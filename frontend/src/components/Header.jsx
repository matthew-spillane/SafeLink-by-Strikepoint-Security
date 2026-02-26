import React from "react";
import { useLocation, useNavigate } from "react-router-dom";
import { Shield, Sun, Moon, History, Home } from "lucide-react";
import { useTheme } from "../context/ThemeContext";

export default function Header() {
  const { dark, toggle } = useTheme();
  const location = useLocation();
  const navigate = useNavigate();

  const navTo = (path) => (e) => {
    e.preventDefault();
    navigate(path);
  };

  const linkClass = (path) =>
    `flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-sm font-medium transition-colors cursor-pointer ${
      location.pathname === path
        ? "bg-blue-600 text-white"
        : "text-gray-500 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white hover:bg-gray-200 dark:hover:bg-white/10"
    }`;

  return (
    <header className="sticky top-0 z-50 backdrop-blur-xl bg-white/80 dark:bg-navy-900/80 border-b border-gray-200 dark:border-white/10">
      <div className="max-w-5xl mx-auto px-4 h-14 flex items-center justify-between">
        <a
          href="/"
          onClick={navTo("/")}
          className="flex items-center gap-2 font-bold text-lg cursor-pointer"
        >
          <Shield className="w-6 h-6 text-blue-500" />
          <span className="bg-gradient-to-r from-blue-400 to-cyan-400 bg-clip-text text-transparent">
            SafeLink
          </span>
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
            onClick={toggle}
            className="ml-2 p-2 rounded-lg text-gray-500 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white hover:bg-gray-200 dark:hover:bg-white/10 transition-colors"
            aria-label="Toggle theme"
          >
            {dark ? <Sun className="w-4 h-4" /> : <Moon className="w-4 h-4" />}
          </button>
        </nav>
      </div>
    </header>
  );
}
