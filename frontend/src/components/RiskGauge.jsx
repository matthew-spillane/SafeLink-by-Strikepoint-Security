import React, { useEffect, useState } from "react";

function getColor(score) {
  if (score <= 25) return "#22c55e";
  if (score <= 50) return "#eab308";
  return "#e8412a";
}

export default function RiskGauge({ score }) {
  const [animated, setAnimated] = useState(0);
  const color = getColor(score);
  const radius = 80;
  const stroke = 12;
  const circumference = Math.PI * radius;
  const offset = circumference - (animated / 100) * circumference;

  useEffect(() => {
    let frame;
    let start = null;
    const duration = 1200;
    const animate = (ts) => {
      if (!start) start = ts;
      const progress = Math.min((ts - start) / duration, 1);
      const eased = 1 - Math.pow(1 - progress, 3);
      setAnimated(Math.round(eased * score));
      if (progress < 1) frame = requestAnimationFrame(animate);
    };
    frame = requestAnimationFrame(animate);
    return () => cancelAnimationFrame(frame);
  }, [score]);

  return (
    <div className="flex flex-col items-center">
      <svg width="200" height="120" viewBox="0 0 200 120">
        {/* Background arc */}
        <path
          d="M 10 110 A 80 80 0 0 1 190 110"
          fill="none"
          stroke="#2a2a2a"
          strokeWidth={stroke}
          strokeLinecap="round"
        />
        {/* Score arc */}
        <path
          d="M 10 110 A 80 80 0 0 1 190 110"
          fill="none"
          stroke={color}
          strokeWidth={stroke}
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          style={{ transition: "stroke-dashoffset 0.1s ease-out" }}
        />
        {/* Score text */}
        <text
          x="100"
          y="95"
          textAnchor="middle"
          fill="white"
          style={{ fontSize: "36px", fontWeight: 700 }}
        >
          {animated}
        </text>
        <text
          x="100"
          y="112"
          textAnchor="middle"
          fill="#666666"
          style={{ fontSize: "11px" }}
        >
          / 100
        </text>
      </svg>
    </div>
  );
}
