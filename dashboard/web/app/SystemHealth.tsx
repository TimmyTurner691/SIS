"use client";

import { useEffect, useState } from "react";
import { Cpu, CircuitBoard, Database, Activity } from "lucide-react"; // <-- Íconos profesionales

interface SystemMetrics {
  cpu: number;
  ram: number;
  disk: number;
}

// Usamos colores estándar de Tailwind que brillan mejor en fondos oscuros
function barColor(value: number): string {
  if (value >= 85) return "bg-red-500";
  if (value >= 70) return "bg-yellow-500";
  return "bg-emerald-500";
}

interface MetricBlockProps {
  label: string;
  value: number | null;
  icon: React.ReactNode; // <-- Ahora acepta componentes (íconos) en lugar de texto
}

function MetricBlock({ label, value, icon }: MetricBlockProps) {
  const display = value !== null ? value.toFixed(1) : "--";
  const color = value !== null ? barColor(value) : "bg-gray-700";
  const width = value !== null ? Math.min(value, 100) : 0;

  function textColor(): string {
    if (value === null) return "text-gray-500";
    if (value >= 85) return "text-red-400";
    if (value >= 70) return "text-yellow-400";
    return "text-emerald-400";
  }

  return (
    <div className="flex flex-col gap-1.5 w-full">
      <div className="flex items-center justify-between">
        <span className="flex items-center gap-2 text-xs font-medium text-gray-400 truncate">
          {/* El ícono se renderiza aquí con un tamaño uniforme */}
          <span className="text-gray-500">{icon}</span>
          {label}
        </span>
        <span className={`text-xs font-bold tabular-nums shrink-0 ml-1 ${textColor()}`}>
          {display}%
        </span>
      </div>

      {/* Progress bar (ligeramente más gruesa h-1.5 y con fondo más integrado) */}
      <div className="h-1.5 w-full bg-gray-800/80 rounded-full overflow-hidden shadow-inner">
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
    <div className="mx-4 mb-4 p-4 bg-[#111827] border border-gray-800/50 rounded-lg shadow-md relative overflow-hidden">
      {/* Brillo superior sutil para dar profundidad */}
      <div className="absolute top-0 left-0 right-0 h-px bg-gradient-to-r from-transparent via-gray-600/50 to-transparent" />

      <div className="flex items-center justify-between mb-4">
        <p className="text-[10px] font-semibold uppercase tracking-widest text-gray-500 flex items-center gap-1.5">
          <Activity className="w-3.5 h-3.5 text-[#5F13CF]" />
          Salud del Motor
        </p>
        {/* Puntito verde parpadeante simulando "Live" */}
        <span className="flex h-2 w-2 relative">
          <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
          <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
        </span>
      </div>

      <div className="flex flex-col space-y-4">
        <MetricBlock
          label="CPU Core"
          value={metrics?.cpu ?? null}
          icon={<Cpu className="w-3.5 h-3.5" />}
        />
        <MetricBlock
          label="Memoria RAM"
          value={metrics?.ram ?? null}
          icon={<CircuitBoard className="w-3.5 h-3.5" />}
        />
        <MetricBlock
          label="Almacenamiento"
          value={metrics?.disk ?? null}
          icon={<Database className="w-3.5 h-3.5" />}
        />
      </div>
    </div>
  );
}