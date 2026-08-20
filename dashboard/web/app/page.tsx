import RiskDashboard from "./RiskDashboard";
import DiscoveredAssets from "./DiscoveredAssets";
import CriticalFeed from "./CriticalFeed";
import RiskTrendChart from "./RiskTrendChart"; // Importamos el gráfico

export default function Home() {
  return (
    <div className="p-8 max-w-6xl mx-auto space-y-8">
      <header>
        <h1 className="text-2xl font-semibold text-gray-200">SIS - Resumen Operativo</h1>
        <p className="text-sm text-gray-400 mt-1">Métricas principales de los sensores OT/IT en tiempo real.</p>
      </header>

      {/* Fila 1: KPIs y Matriz */}
      <RiskDashboard />

      {/* Fila 2: Gráfico de Tendencia */}
      <RiskTrendChart />

      {/* Fila 3: Feed de Alertas Críticas (ahora ocupa todo el ancho) */}
      <CriticalFeed />
    </div>
  );
}