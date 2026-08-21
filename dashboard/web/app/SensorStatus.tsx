"use client";

import { useEffect, useState } from "react";
import { Activity, Shield } from "lucide-react";

interface SensorHealth {
  status: string;
  info: string;
}

interface SensorsData {
  zeek: SensorHealth;
  snort: SensorHealth;
}

export default function SensorStatus() {
  const [data, setData] = useState<SensorsData | null>(null);

  const fetchStatus = async () => {
    try {
      const res = await fetch("/api/sensors");
      if (res.ok) {
        const json = await res.json();
        setData(json);
      }
    } catch (error) {
      console.error("Error fetching sensor status:", error);
    }
  };

  useEffect(() => {
    fetchStatus();
    const interval = setInterval(fetchStatus, 5000);
    return () => clearInterval(interval);
  }, []);

  if (!data) {
    return (
      <div className="flex items-center gap-2 text-xs text-gray-500 animate-pulse">
        <Activity className="w-4 h-4" /> Cargando sensores...
      </div>
    );
  }

  // Función para asignar colores según el estado (verde, rojo o gris)
  const getStatusStyle = (status: string) => {
    if (status.includes("🔴")) return "text-red-400 bg-red-900/10 border-red-900/50";
    if (status.includes("⚪")) return "text-gray-400 bg-gray-800/30 border-gray-700/50";
    return "text-emerald-400 bg-emerald-900/10 border-emerald-900/30";
  };

  return (
    <div className="flex items-center gap-4">
      {/* Etiqueta de sección */}
      <span className="text-xs font-semibold text-gray-400 uppercase tracking-wider hidden lg:block mr-2">
        Telemetría
      </span>

      {/* Sensor Zeek */}
      <div className={`flex items-center gap-2 px-3 py-1.5 rounded-md border shadow-sm ${getStatusStyle(data.zeek.status)}`}>
        <Activity className="w-4 h-4 shrink-0" />
        <div className="flex flex-col">
          <span className="text-[10px] font-bold uppercase tracking-wider leading-none">Zeek</span>
          <span className="text-[10px] opacity-80 leading-none mt-1">{data.zeek.info}</span>
        </div>
      </div>

      {/* Sensor Snort */}
      <div className={`flex items-center gap-2 px-3 py-1.5 rounded-md border shadow-sm ${getStatusStyle(data.snort.status)}`}>
        <Shield className="w-4 h-4 shrink-0" />
        <div className="flex flex-col">
          <span className="text-[10px] font-bold uppercase tracking-wider leading-none">Snort</span>
          <span className="text-[10px] opacity-80 leading-none mt-1">{data.snort.info}</span>
        </div>
      </div>
    </div>
  );
}