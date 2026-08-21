"use client";

import { useEffect, useState } from "react";
import { Factory } from "lucide-react";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------
interface ScadaEvent {
  "@timestamp"?: string;
  comando_humano?: string;
  src_ip?: string;
  dst_ip?: string;
  risk_total_score?: number;
  protocol?: string;
  [key: string]: unknown;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
function formatTimestamp(ts?: string): string {
  if (!ts) return "—";
  try {
    return new Date(ts).toLocaleString("es-ES", {
      dateStyle: "short",
      timeStyle: "medium",
    });
  } catch {
    return ts;
  }
}

function ScoreBadge({ score }: { score?: number }) {
  if (score == null) return <span className="text-gray-500">—</span>;

  const isHigh = score > 17;
  const isMedium = score >= 10 && score <= 17;

  const color = isHigh
    ? "bg-red-500/15 text-red-400 border-red-500/30"
    : isMedium
    ? "bg-amber-500/15 text-amber-400 border-amber-500/30"
    : "bg-emerald-500/15 text-emerald-400 border-emerald-500/30";

  return (
    <span
      className={`inline-flex items-center justify-center w-10 rounded-full px-2 py-0.5 text-[11px] font-bold border tabular-nums ${color}`}
    >
      {score}
    </span>
  );
}

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------
export default function ScadaPage() {
  const [events, setEvents] = useState<ScadaEvent[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    async function fetchScada() {
      try {
        setLoading(true);
        const res = await fetch("/api/scada");
        const json = await res.json();
        if (!res.ok) throw new Error(json.error || "Error en la respuesta");
        setEvents(json.data || []);
      } catch (err: any) {
        setError(err.message);
      } finally {
        setLoading(false);
      }
    }

    fetchScada();
  }, []);

  return (
    <div className="p-8 max-w-7xl mx-auto">
      {/* ------------------------------------------------------------------ */}
      {/* Header                                                              */}
      {/* ------------------------------------------------------------------ */}
      <header className="mb-8">
        <div className="flex items-center gap-3 mb-1">
          {/* Protocol badge */}
          <span className="inline-flex items-center px-2 py-0.5 rounded-md text-[10px] font-bold uppercase tracking-widest border bg-[#5F13CF]/10 text-[#5F13CF] border-[#5F13CF]/30">
            IEC-104
          </span>
          <span className="inline-flex items-center px-2 py-0.5 rounded-md text-[10px] font-bold uppercase tracking-widest border bg-emerald-500/10 text-emerald-400 border-emerald-500/30">
            SCADA
          </span>
        </div>

        <h1 className="text-2xl font-semibold text-gray-200 flex items-center gap-2">
          <Factory className="w-6 h-6 text-blue-500" />
          Telemetría Industrial (SCADA)
        </h1>
        <p className="text-sm text-gray-400 mt-1">
          Eventos del protocolo IEC-104 capturados en tiempo real desde el
          índice{" "}
          <code className="text-[#5F13CF] bg-[#5F13CF]/10 px-1 rounded">
            sis-logs-v1
          </code>
          . Filtrado por{" "}
          <code className="text-[#5F13CF] bg-[#5F13CF]/10 px-1 rounded">
            protocol = iec104
          </code>
          .
        </p>
      </header>

      {/* ------------------------------------------------------------------ */}
      {/* States: loading / error / empty                                     */}
      {/* ------------------------------------------------------------------ */}
      {loading && (
        <div className="flex items-center gap-3 text-gray-400 text-sm animate-pulse">
          <span className="inline-block w-4 h-4 rounded-full border-2 border-[#5F13CF] border-t-transparent animate-spin" />
          Cargando telemetría SCADA…
        </div>
      )}

      {!loading && error && (
        <div className="rounded-lg border border-red-500/30 bg-red-500/10 px-5 py-4 text-sm text-red-400">
          <strong>Error al conectar con Elasticsearch:</strong> {error}
        </div>
      )}

      {!loading && !error && events.length === 0 && (
        <div className="rounded-lg border border-gray-700/50 bg-[#1a2235] px-5 py-10 text-center text-gray-500 text-sm">
          No se encontraron eventos IEC-104 en los últimos registros.
        </div>
      )}

      {/* ------------------------------------------------------------------ */}
      {/* Table                                                               */}
      {/* ------------------------------------------------------------------ */}
      {!loading && !error && events.length > 0 && (
        <div className="overflow-x-auto rounded-xl border border-[#5F13CF]/20 shadow-lg shadow-black/30">
          <table className="w-full text-sm border-collapse">
            <thead>
              <tr className="bg-[#5F13CF]/10 border-b border-[#5F13CF]/20 text-[#5F13CF] text-xs uppercase tracking-wider">
                <th className="text-left px-4 py-3 font-semibold whitespace-nowrap">
                  Timestamp
                </th>
                <th className="text-left px-4 py-3 font-semibold">
                  Comando{" "}
                  <span className="normal-case text-[10px] text-[#5F13CF]/60 font-normal ml-1">
                    (traducción IA)
                  </span>
                </th>
                <th className="text-left px-4 py-3 font-semibold whitespace-nowrap">
                  IP Origen
                </th>
                <th className="text-left px-4 py-3 font-semibold whitespace-nowrap">
                  IP Destino
                </th>
                <th className="text-right px-4 py-3 font-semibold whitespace-nowrap">
                  Score IA
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800/60">
              {events.map((ev, i) => (
                <tr
                  key={i}
                  className="bg-[#1a2235] transition-colors hover:bg-[#5F13CF]/5"
                >
                  {/* Timestamp */}
                  <td className="px-4 py-3 whitespace-nowrap text-gray-400 font-mono text-xs">
                    {formatTimestamp(ev["@timestamp"])}
                  </td>

                  {/* Comando Humano — campo destacado */}
                  <td className="px-4 py-3 max-w-sm">
                    {ev.comando_humano ? (
                      <span className="text-base font-semibold text-gray-100 leading-snug">
                        {ev.comando_humano}
                      </span>
                    ) : (
                      <span className="text-xs text-gray-500 italic">
                        sin traducción
                      </span>
                    )}
                  </td>

                  {/* IP Origen */}
                  <td className="px-4 py-3 font-mono text-xs text-gray-300 whitespace-nowrap">
                    {ev.src_ip || "—"}
                  </td>

                  {/* IP Destino */}
                  <td className="px-4 py-3 font-mono text-xs text-gray-300 whitespace-nowrap">
                    {ev.dst_ip || "—"}
                  </td>

                  {/* Score IA */}
                  <td className="px-4 py-3 text-right">
                    <ScoreBadge score={ev.risk_total_score} />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>

          {/* Footer */}
          <div className="bg-[#111827] border-t border-gray-800/60 px-4 py-2 flex items-center justify-between">
            <span className="text-xs text-gray-600">
              Mostrando{" "}
              <span className="text-gray-400 font-medium">{events.length}</span>{" "}
              eventos IEC-104
            </span>
            <span className="text-xs text-gray-600">
              Score crítico ({">"} 17):{" "}
              <span className="text-red-400 font-bold">
                {events.filter((e) => (e.risk_total_score ?? 0) > 17).length}
              </span>
            </span>
          </div>
        </div>
      )}
    </div>
  );
}
