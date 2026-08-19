"use client";

import { useState, useEffect } from "react";

interface MatrixCell {
  impact: number;
  probability: number;
  count: number;
}

interface AlertsData {
  maxRisk: number;
  criticalIncidents: number;
  uniqueDstIps: number;
  matrix: MatrixCell[];
}

export default function RiskDashboard() {
  const [data, setData] = useState<AlertsData | null>(null);

  const fetchData = async () => {
    try {
      const res = await fetch("/api/alerts");
      if (res.ok) {
        const json = await res.json();
        if (json.success) {
          setData(json.data);
        }
      }
    } catch (error) {
      console.error("Error fetching alerts data:", error);
    }
  };

  useEffect(() => {
    fetchData();
    const interval = setInterval(fetchData, 60000);
    return () => clearInterval(interval);
  }, []);

  if (!data) {
    return (
      <div className="flex justify-center items-center h-64 bg-[#1a2235] rounded-lg border border-gray-800/50">
        <p className="text-gray-500 animate-pulse">Consultando estado global de seguridad...</p>
      </div>
    );
  }

  const getRiskStyle = (impact: number, probability: number) => {
    const score = impact * probability;
    if (score <= 4) return "bg-green-500/10 text-green-400 border-green-500/30";
    if (score <= 9) return "bg-yellow-500/10 text-yellow-400 border-yellow-500/30";
    if (score <= 14) return "bg-orange-500/10 text-orange-400 border-orange-500/30";
    return "bg-red-500/20 text-red-400 border-red-500/40 shadow-[inset_0_0_15px_rgba(239,68,68,0.15)]";
  };

  const getCount = (impact: number, probability: number) => {
    const cell = data.matrix.find(
      (c) => Number(c.impact) === impact && Number(c.probability) === probability
    );
    return cell ? cell.count : 0;
  };

  return (
    <div className="space-y-8">
      {/* KPIs Cards */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        <div className="bg-[#1a2235] border border-gray-800/50 border-t-2 border-t-[#5F13CF] rounded-lg p-6 flex flex-col justify-between shadow-lg">
          <h2 className="text-sm font-medium text-gray-300">Riesgo Máximo Detectado</h2>
          <div className="mt-4 flex items-baseline gap-2">
            <span className="text-4xl font-bold text-orange-500">{data.maxRisk}</span>
            <span className="text-xs text-gray-500">Score de Riesgo</span>
          </div>
        </div>

        <div className="bg-[#1a2235] border border-gray-800/50 border-t-2 border-t-[#5F13CF] rounded-lg p-6 flex flex-col justify-between shadow-lg">
          <h2 className="text-sm font-medium text-gray-300">Críticos (Score ≥ 17)</h2>
          <div className="mt-4 flex items-baseline gap-2">
            <span className="text-4xl font-bold text-red-500">{data.criticalIncidents}</span>
            <span className="text-xs text-red-500/80 bg-red-500/10 px-2 py-0.5 rounded-full">Incidentes</span>
          </div>
        </div>

        <div className="bg-[#1a2235] border border-gray-800/50 border-t-2 border-t-[#5F13CF] rounded-lg p-6 flex flex-col justify-between shadow-lg">
          <h2 className="text-sm font-medium text-gray-300">Activos Afectados</h2>
          <div className="mt-4 flex items-baseline gap-2">
            <span className="text-4xl font-bold text-[#7BDCB5]">{data.uniqueDstIps}</span>
            <span className="text-xs text-[#7BDCB5]/80 bg-[#7BDCB5]/10 px-2 py-0.5 rounded-full">IPs Destino Únicas</span>
          </div>
        </div>
      </div>

      {/* Risk Matrix */}
      <div className="bg-[#1a2235] border border-gray-800/50 rounded-lg p-6 shadow-lg">
        <h2 className="text-lg font-semibold text-gray-200 mb-6 flex items-center">
          <span className="mr-2">🔥</span> Matriz de Calor Global (60 mins)
        </h2>
        
        <div className="flex">
          {/* Y-axis label */}
          <div className="flex flex-col justify-center items-center mr-4 w-6">
            <span className="text-xs text-gray-400 -rotate-90 tracking-widest whitespace-nowrap uppercase">
              Impacto
            </span>
          </div>

          <div className="flex-1 max-w-4xl">
            <div className="grid grid-cols-5 gap-2">
              {[5, 4, 3, 2, 1].map((impact) =>
                [1, 2, 3, 4, 5].map((probability) => {
                  const count = getCount(impact, probability);
                  const isEmpty = count === 0;
                  return (
                    <div
                      key={`${impact}-${probability}`}
                      className={`flex flex-col items-center justify-center h-24 rounded border transition-all ${
                        isEmpty ? "opacity-40 hover:opacity-100" : "hover:scale-[1.02] z-10"
                      } ${getRiskStyle(impact, probability)}`}
                      title={`Impacto: ${impact}, Probabilidad: ${probability}`}
                    >
                      <span className="text-2xl font-bold">{count}</span>
                      <span className="text-[10px] opacity-70 mt-1">
                        I:{impact} x P:{probability}
                      </span>
                    </div>
                  );
                })
              )}
            </div>
            
            {/* X-axis label */}
            <div className="mt-6 text-center">
              <span className="text-xs text-gray-400 tracking-widest uppercase">
                Probabilidad
              </span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}
