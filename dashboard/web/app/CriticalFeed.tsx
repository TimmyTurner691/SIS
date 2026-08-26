'use client';

import { useEffect, useState } from 'react';
import { formatSantiagoTimestamp } from './lib/time';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------
interface CriticalEvent {
  '@timestamp'?: string;
  mitre_msg?: string;
  src_ip?: string;
  dst_ip?: string;
  risk_total_score?: number;
  [key: string]: unknown;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// Component
// ---------------------------------------------------------------------------
export default function CriticalFeed() {
  const [events, setEvents] = useState<CriticalEvent[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function fetchCritical() {
      try {
        const res = await fetch('/api/alerts/critical');
        const json = await res.json();
        setEvents(json.data || []);
      } catch {
        setEvents([]);
      } finally {
        setLoading(false);
      }
    }
    fetchCritical();
  }, []);

  return (
    <div className="rounded-xl border border-red-500/20 border-t-2 border-t-red-500 bg-[#1a2235] shadow-lg shadow-black/20 overflow-hidden">
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-3 border-b border-gray-800/60">
        <h2 className="text-sm font-semibold text-gray-200 flex items-center gap-2">
          🚨 Últimos Incidentes Críticos
        </h2>
        {!loading && events.length > 0 && (
          <span className="inline-flex items-center gap-1 text-[10px] font-bold uppercase tracking-wide text-red-400 bg-red-500/10 border border-red-500/20 rounded-full px-2 py-0.5">
            <span className="w-1.5 h-1.5 rounded-full bg-red-500 animate-pulse" />
            {events.length} activos
          </span>
        )}
      </div>

      {/* Loading */}
      {loading && (
        <div className="flex items-center gap-2 px-4 py-6 text-xs text-gray-500 animate-pulse">
          <span className="w-3 h-3 rounded-full border-2 border-red-500 border-t-transparent animate-spin" />
          Consultando incidentes críticos…
        </div>
      )}

      {/* Empty state */}
      {!loading && events.length === 0 && (
        <div className="px-4 py-8 text-center text-xs text-gray-500">
          No se han detectado incidentes críticos recientes
        </div>
      )}

      {/* Table */}
      {!loading && events.length > 0 && (
        <table className="w-full text-xs border-collapse">
          <thead>
            <tr className="text-[10px] uppercase tracking-wider text-red-500/70 border-b border-gray-800/50">
              <th className="text-left px-4 py-2 font-semibold whitespace-nowrap">Timestamp</th>
              <th className="text-left px-4 py-2 font-semibold">Amenaza</th>
              <th className="text-left px-4 py-2 font-semibold whitespace-nowrap">IP Origen</th>
              <th className="text-left px-4 py-2 font-semibold whitespace-nowrap">IP Destino</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-800/40">
            {events.map((ev, i) => (
              <tr
                key={i}
                className="hover:bg-red-500/5 transition-colors group"
              >
                {/* Timestamp */}
                <td className="px-4 py-2.5 whitespace-nowrap font-mono text-[10px] text-gray-500">
                  {formatSantiagoTimestamp(ev['@timestamp'])}
                </td>

                {/* Amenaza — campo mitre_msg */}
                <td className="px-4 py-2.5 max-w-[200px]">
                  <span
                    className="block truncate text-red-300 font-medium leading-snug"
                    title={ev.mitre_msg || '—'}
                  >
                    {ev.mitre_msg || <span className="text-gray-600 italic">sin clasificar</span>}
                  </span>
                </td>

                {/* IP Origen */}
                <td className="px-4 py-2.5 font-mono text-[10px] text-gray-400 whitespace-nowrap">
                  {ev.src_ip || '—'}
                </td>

                {/* IP Destino */}
                <td className="px-4 py-2.5 font-mono text-[10px] text-gray-400 whitespace-nowrap">
                  {ev.dst_ip || '—'}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </div>
  );
}
