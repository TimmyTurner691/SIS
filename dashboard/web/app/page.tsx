import { LayoutDashboard } from "lucide-react";
import RiskDashboard from "./RiskDashboard";
import CriticalFeed from "./CriticalFeed";
import RiskTrendChart from "./RiskTrendChart"; // Importamos el gráfico

export default function Home() {
  return (
    <div className="p-8 max-w-6xl mx-auto space-y-8">
      <div className="mb-8">
        <h1 className="text-2xl font-bold text-gray-100 flex items-center gap-3">
          <LayoutDashboard className="w-7 h-7 text-[#0ea5e9]" />
          SIS - Resumen Operativo
        </h1>
        <p className="text-slate-400 text-sm mt-2">
          Métricas principales de los sensores OT/IT en tiempo real.
        </p>
      </div>

      {/* Fila 1: KPIs y Matriz */}
      <RiskDashboard />

      {/* Fila 2: Gráfico de Tendencia */}
      <RiskTrendChart />

      {/* Fila 3: Feed de Alertas Críticas (ahora ocupa todo el ancho) */}
      <CriticalFeed />
    </div>
  );
}