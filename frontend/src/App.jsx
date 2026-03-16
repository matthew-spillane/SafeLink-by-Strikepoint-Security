import React from "react";
import { Routes, Route } from "react-router-dom";
import { ThemeProvider } from "./context/ThemeContext";
import Header from "./components/Header";
import HomePage from "./pages/HomePage";
import ScanPage from "./pages/ScanPage";
import HistoryPage from "./pages/HistoryPage";

export default function App() {
  return (
    <ThemeProvider>
      <div className="min-h-screen sp-hero-bg text-[#e6edf3]">
        <Header />
        <main className="max-w-7xl mx-auto px-6 pb-16">
          <Routes>
            <Route path="/" element={<HomePage />} />
            <Route path="/scan/:id" element={<ScanPage />} />
            <Route path="/history" element={<HistoryPage />} />
          </Routes>
        </main>
      </div>
    </ThemeProvider>
  );
}
