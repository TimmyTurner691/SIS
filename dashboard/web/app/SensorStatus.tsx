"use client";

import { useState, useEffect } from "react";

interface SensorData {
  status: string;
  info: string;
}

interface SensorsResponse {
  zeek: SensorData;
  snort: SensorData;
}

export default function SensorStatus() {
  const [sensors, setSensors] = useState<SensorsResponse | null>(null);

  const fetchSensors = async () => {
    try {
      const res = await fetch("/api/sensors");
      if (res.ok) {
        const data = await res.json();
        setSensors(data);
      }
    } catch (error) {
      console.error("Error fetching sensor status", error);
    }
  };

  useEffect(() => {
    fetchSensors();
    const interval = setInterval(fetchSensors, 15000);
    
    // Limpieza del intervalo
    return () => clearInterval(interval);
  }, []);

  if (!sensors) {
    return (
      <div className="px-4 py-5 border-b border-gray-800/50 bg-[#1a2235]">
        <p className="text-xs text-gray-500 text-center animate-pulse">Cargando telemetría...</p>
      </div>
    );
  }

  return (
    <div className="px-4 py-5 border-b border-gray-800/50 bg-[#1a2235] space-y-4 shrink-0">
      <h3 className="text-xs font-semibold text-gray-400 uppercase tracking-wider">
        📡 Telemetría Sensores
      </h3>
      
      <div className="space-y-3">
        {/* Sensor Zeek */}
        <div className="bg-[#111827] rounded-md p-3 border border-gray-800/50 shadow-inner">
          <div className="flex items-center justify-between mb-1">
            <span className="text-sm font-medium text-gray-200">Zeek</span>
            <span className="text-xs">{sensors.zeek.status}</span>
          </div>
          <p className="text-xs text-gray-500 truncate" title={sensors.zeek.info}>
            {sensors.zeek.info}
          </p>
        </div>

        {/* Sensor Snort */}
        <div className="bg-[#111827] rounded-md p-3 border border-gray-800/50 shadow-inner">
          <div className="flex items-center justify-between mb-1">
            <span className="text-sm font-medium text-gray-200">Snort</span>
            <span className="text-xs">{sensors.snort.status}</span>
          </div>
          <p className="text-xs text-gray-500 truncate" title={sensors.snort.info}>
            {sensors.snort.info}
          </p>
        </div>
      </div>
    </div>
  );
}
