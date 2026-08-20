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

  if (state === 'loading') return null;

  if (state === 'error') {
    return (
      <div className="flex items-center gap-2 px-3 py-2 mx-4 mb-4 rounded-md bg-red-900/20 border border-red-900/50 shadow-sm">
        <span className="w-2.5 h-2.5 rounded-full bg-red-500 animate-pulse shrink-0" />
        <p className="text-xs font-medium text-red-400 tracking-wide">
          Elasticsearch: Desconectado
        </p>
      </div>
    );
  }

  return (
    <div className="flex items-center gap-2 px-3 py-2 mx-4 mb-4 rounded-md bg-[#111827] border border-gray-800/50 shadow-sm">
      <span className="w-2.5 h-2.5 rounded-full bg-green-500 animate-pulse shrink-0" />
      <p className="text-xs font-medium text-gray-400 tracking-wide">
        Elasticsearch: En Línea
      </p>
    </div>
  );
}