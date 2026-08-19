import RiskDashboard from "./RiskDashboard";
import DiscoveredAssets from "./DiscoveredAssets";


export default function Home() {
  return (
    <div className="p-8 max-w-6xl mx-auto">
      <header className="mb-8">
        <h1 className="text-2xl font-semibold text-gray-200">SIS - Resumen Operativo</h1>
        <p className="text-sm text-gray-400 mt-1">Métricas principales de los sensores OT/IT en tiempo real.</p>
      </header>

      <RiskDashboard />
    </div>
  );
}
