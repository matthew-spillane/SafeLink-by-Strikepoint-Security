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
      <div className="min-h-screen bg-sp-bg text-sp-text">
        <Header />
        <main className="max-w-5xl mx-auto px-4 pb-16">
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
