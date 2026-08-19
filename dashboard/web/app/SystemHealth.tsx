"use client";

import { useEffect, useState } from "react";

interface SystemMetrics {
  cpu: number;
  ram: number;
  disk: number;
}

function barColor(value: number): string {
  if (value >= 85) return "bg-[#EF5350]";
  if (value >= 70) return "bg-[#FBC02D]";
  return "bg-[#7BDCB5]";
}

interface MetricBlockProps {
  label: string;
  value: number | null;
  icon: string;
}

function MetricBlock({ label, value, icon }: MetricBlockProps) {
  const display = value !== null ? value.toFixed(1) : "--";
  const color = value !== null ? barColor(value) : "bg-gray-600";
  const width = value !== null ? Math.min(value, 100) : 0;

  function textColor(): string {
    if (value === null) return "text-[#7BDCB5]";
    if (value >= 85) return "text-[#EF5350]";
    if (value >= 70) return "text-[#FBC02D]";
    return "text-[#7BDCB5]";
  }

  return (
    <div className="flex flex-col gap-1 w-full">
      <div className="flex items-center justify-between">
        <span className="flex items-center gap-1 text-xs font-medium text-gray-400 truncate">
          <span className="text-[11px]">{icon}</span>
          {label}
        </span>
        <span className={`text-xs font-bold tabular-nums shrink-0 ml-1 ${textColor()}`}>
          {display}%
        </span>
      </div>

      {/* Progress bar */}
      <div className="h-1 w-full bg-gray-800 rounded-full overflow-hidden">
        <div
          className={`h-full rounded-full transition-all duration-700 ease-in-out ${color}`}
          style={{ width: `${width}%` }}
        />
      </div>
    </div>
  );
}

export default function SystemHealth() {
  const [metrics, setMetrics] = useState<SystemMetrics | null>(null);

  const fetchMetrics = async () => {
    try {
      const res = await fetch("/api/system");
      if (!res.ok) return;
      const data: SystemMetrics = await res.json();
      setMetrics(data);
    } catch {
      // Silent failure — retry on next interval
    }
  };

  useEffect(() => {
    fetchMetrics(); // fetch immediately on mount

    const interval = setInterval(fetchMetrics, 5000);
    return () => clearInterval(interval); // cleanup on unmount
  }, []);

  return (
    <div className="mx-3 mb-3 p-3 bg-[#111827] border border-gray-800/60 rounded-lg">
      <p className="text-[9px] font-semibold uppercase tracking-widest text-gray-600 mb-2">
        System Health
      </p>
      <div className="flex flex-col gap-2">
        <MetricBlock label="CPU" value={metrics?.cpu ?? null} icon="⚙️" />
        <MetricBlock label="RAM" value={metrics?.ram ?? null} icon="🧠" />
        <MetricBlock label="Disco" value={metrics?.disk ?? null} icon="💾" />
      </div>
    </div>
  );
}
