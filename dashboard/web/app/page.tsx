export default function Home() {
  return (
    <div className="p-8 max-w-6xl mx-auto">
      <header className="mb-8">
        <h1 className="text-2xl font-semibold text-gray-200">SIS - Resumen Operativo</h1>
        <p className="text-sm text-gray-400 mt-1">Métricas principales de los sensores OT/IT en tiempo real.</p>
      </header>
      
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
        {/* KPI 1 */}
        <div className="border border-gray-800/50 border-t-2 border-t-[#5F13CF] bg-[#1a2235] p-6 rounded-lg flex flex-col justify-between">
          <h2 className="text-sm font-medium text-gray-300">Alertas Críticas (Snort)</h2>
          <div className="mt-4 flex items-baseline gap-2">
            <span className="text-4xl font-bold text-red-500">24</span>
            <span className="text-xs text-red-500/80 bg-red-500/10 px-2 py-0.5 rounded-full">+3 hoy</span>
          </div>
        </div>

        {/* KPI 2 */}
        <div className="border border-gray-800/50 border-t-2 border-t-[#5F13CF] bg-[#1a2235] p-6 rounded-lg flex flex-col justify-between">
          <h2 className="text-sm font-medium text-gray-300">Dispositivos OT Activos</h2>
          <div className="mt-4 flex items-baseline gap-2">
            <span className="text-4xl font-bold text-[#7BDCB5]">142</span>
            <span className="text-xs text-[#7BDCB5]/80 bg-[#7BDCB5]/10 px-2 py-0.5 rounded-full">Estable</span>
          </div>
        </div>

        {/* KPI 3 */}
        <div className="border border-gray-800/50 border-t-2 border-t-[#5F13CF] bg-[#1a2235] p-6 rounded-lg flex flex-col justify-between">
          <h2 className="text-sm font-medium text-gray-300">Último Escaneo de Red</h2>
          <div className="mt-4 flex items-baseline gap-2">
            <span className="text-3xl font-bold text-blue-400">Hace 5 min</span>
          </div>
        </div>
      </div>
    </div>
  );
}
