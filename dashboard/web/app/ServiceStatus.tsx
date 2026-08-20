'use client';

import { useEffect, useState } from 'react';

type HealthState = 'loading' | 'ok' | 'error';

export default function ServiceStatus() {
  const [state, setState] = useState<HealthState>('loading');

  useEffect(() => {
    async function check() {
      try {
        const res = await fetch('/api/health');
        const json = await res.json();
        setState(json.elastic === true ? 'ok' : 'error');
      } catch {
        setState('error');
      }
    }

    check();
    const interval = setInterval(check, 10_000);
    return () => clearInterval(interval);
  }, []);

  // Durante la carga inicial no renderizamos nada para evitar flash
  if (state === 'loading') return null;

  if (state === 'error') {
    return (
      <div className="fixed top-0 left-0 right-0 z-50 flex items-center justify-center gap-2 bg-red-600/90 backdrop-blur-sm px-4 py-1.5 border-b border-red-500/50">
        <span className="inline-block w-2 h-2 rounded-full bg-red-200 animate-pulse shrink-0" />
        <p className="text-xs font-semibold text-red-100 tracking-wide">
          🔴 ALERTA: Conexión con Elasticsearch perdida
        </p>
      </div>
    );
  }

  return (
    <div className="fixed top-0 left-0 right-0 z-50 flex items-center justify-center gap-2 bg-[#0e1624]/80 backdrop-blur-sm px-4 py-1 border-b border-gray-800/60">
      <span className="inline-block w-2 h-2 rounded-full bg-green-500 animate-pulse shrink-0" />
      <p className="text-xs text-gray-400 tracking-wide">
        🟢 Sistema En Línea — Base de Datos en Línea (Elasticsearch)
      </p>
    </div>
  );
}
