"use client";

import { useEffect, useState } from "react";
import { ShieldAlert } from "lucide-react";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------
interface SnortAlert {
  "@timestamp"?: string;
  message?: string;
  risk_label?: string;
  risk_total_score?: number;
  src_ip?: string;
  dst_ip?: string;
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

function isHighRisk(alert: SnortAlert): boolean {
  const label = (alert.risk_label || "").toUpperCase();
  const score = alert.risk_total_score ?? 0;
  return label === "ALTO" || label === "CRÍTICO" || score > 17;
}

function RiskBadge({ label, score }: { label?: string; score?: number }) {
  const text = label || "—";
  const high = isHighRisk({ risk_label: label, risk_total_score: score });
  return (
    <span
      className={`inline-flex items-center px-2 py-0.5 rounded-full text-[11px] font-bold uppercase tracking-wide border ${
        high
          ? "bg-red-500/15 text-red-400 border-red-500/30"
          : "bg-gray-700/40 text-gray-400 border-gray-700/60"
      }`}
    >
      {text}
    </span>
  );
}

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------
export default function SnortPage() {
  const [alerts, setAlerts] = useState<SnortAlert[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    async function fetchAlerts() {
      try {
        setLoading(true);
        const res = await fetch("/api/snort");
        const json = await res.json();
        if (!res.ok) throw new Error(json.error || "Error en la respuesta");
        setAlerts(json.data || []);
      } catch (err: any) {
        setError(err.message);
      } finally {
        setLoading(false);
      }
    }

    fetchAlerts();
  }, []);

  return (
    <div className="p-8 max-w-7xl mx-auto">
      {/* Header */}
      <header className="mb-8">
        <h1 className="text-2xl font-semibold text-gray-200 flex items-center gap-2">
          <ShieldAlert className="w-6 h-6 text-red-500" />
          Sistema de Detección de Intrusos (IDS)
        </h1>
        <p className="text-sm text-gray-400 mt-1">
          Alertas Snort capturadas en tiempo real desde el índice{" "}
          <code className="text-[#5F13CF] bg-[#5F13CF]/10 px-1 rounded">
            sis-logs-v1
          </code>
          .
        </p>
      </header>

      {/* States: loading / error / empty */}
      {loading && (
        <div className="flex items-center gap-3 text-gray-400 text-sm animate-pulse">
          <span className="inline-block w-4 h-4 rounded-full border-2 border-[#5F13CF] border-t-transparent animate-spin" />
          Cargando alertas Snort…
        </div>
      )}

      {!loading && error && (
        <div className="rounded-lg border border-red-500/30 bg-red-500/10 px-5 py-4 text-sm text-red-400">
          <strong>Error al conectar con Elasticsearch:</strong> {error}
        </div>
      )}

      {!loading && !error && alerts.length === 0 && (
        <div className="rounded-lg border border-gray-700/50 bg-[#1a2235] px-5 py-10 text-center text-gray-500 text-sm">
          No se encontraron alertas Snort en los últimos registros.
        </div>
      )}

      {/* Table */}
      {!loading && !error && alerts.length > 0 && (
        <div className="overflow-x-auto rounded-xl border border-[#5F13CF]/20 shadow-lg shadow-black/30">
          <table className="w-full text-sm border-collapse">
            <thead>
              <tr className="bg-[#5F13CF]/10 border-b border-[#5F13CF]/20 text-[#5F13CF] text-xs uppercase tracking-wider">
                <th className="text-left px-4 py-3 font-semibold whitespace-nowrap">
                  Timestamp
                </th>
                <th className="text-left px-4 py-3 font-semibold">Mensaje</th>
                <th className="text-left px-4 py-3 font-semibold whitespace-nowrap">
                  Etiqueta Riesgo
                </th>
                <th className="text-right px-4 py-3 font-semibold whitespace-nowrap">
                  Score
                </th>
                <th className="text-left px-4 py-3 font-semibold whitespace-nowrap">
                  IP Origen
                </th>
                <th className="text-left px-4 py-3 font-semibold whitespace-nowrap">
                  IP Destino
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800/60">
              {alerts.map((alert, i) => {
                const high = isHighRisk(alert);
                return (
                  <tr
                    key={i}
                    className={`bg-[#1a2235] transition-colors hover:bg-[#5F13CF]/5 ${
                      high ? "border-l-2 border-red-500" : ""
                    }`}
                  >
                    {/* Timestamp */}
                    <td className="px-4 py-3 whitespace-nowrap text-gray-400 font-mono text-xs">
                      {formatTimestamp(alert["@timestamp"])}
                    </td>

                    {/* Mensaje */}
                    <td
                      className={`px-4 py-3 max-w-xs truncate ${
                        high ? "text-red-400 font-medium" : "text-gray-300"
                      }`}
                      title={alert.message || "—"}
                    >
                      {alert.message || "—"}
                    </td>

                    {/* Etiqueta de riesgo */}
                    <td className="px-4 py-3 whitespace-nowrap">
                      <RiskBadge
                        label={alert.risk_label}
                        score={alert.risk_total_score}
                      />
                    </td>

                    {/* Score */}
                    <td
                      className={`px-4 py-3 text-right font-bold tabular-nums ${
                        high ? "text-red-400" : "text-gray-300"
                      }`}
                    >
                      {alert.risk_total_score ?? "—"}
                    </td>

                    {/* IP Origen */}
                    <td className="px-4 py-3 font-mono text-xs text-gray-300 whitespace-nowrap">
                      {alert.src_ip || "—"}
                    </td>

                    {/* IP Destino */}
                    <td className="px-4 py-3 font-mono text-xs text-gray-300 whitespace-nowrap">
                      {alert.dst_ip || "—"}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>

          {/* Footer con conteo */}
          <div className="bg-[#111827] border-t border-gray-800/60 px-4 py-2 flex items-center justify-between">
            <span className="text-xs text-gray-600">
              Mostrando{" "}
              <span className="text-gray-400 font-medium">{alerts.length}</span>{" "}
              alertas
            </span>
            <span className="text-xs text-gray-600">
              Alertas críticas:{" "}
              <span className="text-red-400 font-bold">
                {alerts.filter(isHighRisk).length}
              </span>
            </span>
          </div>
        </div>
      )}
    </div>
  );
}
