import RiskDashboard from "./RiskDashboard";
import DiscoveredAssets from "./DiscoveredAssets";
import CriticalFeed from "./CriticalFeed";
import AlertConfig from "./AlertConfig";

export default function Home() {
  return (
    <div className="p-8 max-w-6xl mx-auto">
      <header className="mb-8">
        <h1 className="text-2xl font-semibold text-gray-200">SIS - Resumen Operativo</h1>
        <p className="text-sm text-gray-400 mt-1">Métricas principales de los sensores OT/IT en tiempo real.</p>
      </header>

      <RiskDashboard />

      <div className="mt-8 grid grid-cols-1 md:grid-cols-3 gap-6">
        <div className="md:col-span-2">
          <CriticalFeed />
        </div>
        <div className="md:col-span-1">
          <AlertConfig />
        </div>
      </div>
    </div>
  );
}