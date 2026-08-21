"use client";

import { useEffect, useRef, useState } from "react";
import { TerminalSquare } from "lucide-react";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------
interface RawLog {
  "@timestamp"?: string;
  source?: string;
  protocol?: string;
  raw_log?: string;
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

/** Badge de color para el protocolo detectado */
function ProtocolBadge({ proto }: { proto?: string }) {
  if (!proto) return <span className="text-gray-600">—</span>;

  const colors: Record<string, string> = {
    iec104:
      "bg-amber-500/15 text-amber-400 border-amber-500/30",
    snort:
      "bg-red-500/15 text-red-400 border-red-500/30",
    modbus:
      "bg-blue-500/15 text-blue-400 border-blue-500/30",
    dnp3:
      "bg-purple-500/15 text-purple-400 border-purple-500/30",
  };
  const cls =
    colors[proto.toLowerCase()] ||
    "bg-gray-700/40 text-gray-400 border-gray-700/60";

  return (
    <span
      className={`inline-flex items-center px-1.5 py-0 rounded text-[10px] font-bold uppercase tracking-wide border ${cls}`}
    >
      {proto}
    </span>
  );
}

/** Celda de Raw Log: texto truncado con tooltip y botón para expandir */
function RawLogCell({ value }: { value?: string }) {
  const [expanded, setExpanded] = useState(false);
  const text = value || "—";
  const isLong = text.length > 120;

  return (
    <td className="px-3 py-2 max-w-0 w-full">
      {isLong && !expanded ? (
        <div className="flex items-start gap-2">
          <span
            className="font-mono text-gray-400 text-[10px] leading-relaxed break-all line-clamp-2 flex-1"
            title={text}
          >
            {text}
          </span>
          <button
            onClick={() => setExpanded(true)}
            className="shrink-0 text-[9px] font-bold uppercase tracking-wide text-[#5F13CF] border border-[#5F13CF]/30 rounded px-1 py-0.5 hover:bg-[#5F13CF]/10 transition-colors mt-0.5"
          >
            +ver
          </button>
        </div>
      ) : expanded ? (
        <div className="flex items-start gap-2">
          <div className="flex-1 overflow-x-auto rounded bg-[#111827] border border-gray-700/50 p-2">
            <pre className="font-mono text-gray-300 text-[10px] leading-relaxed whitespace-pre-wrap break-all">
              {text}
            </pre>
          </div>
          <button
            onClick={() => setExpanded(false)}
            className="shrink-0 text-[9px] font-bold uppercase tracking-wide text-gray-500 border border-gray-700/60 rounded px-1 py-0.5 hover:bg-gray-700/20 transition-colors mt-0.5"
          >
            −ocultar
          </button>
        </div>
      ) : (
        <span className="font-mono text-gray-400 text-[10px] leading-relaxed break-all">
          {text}
        </span>
      )}
    </td>
  );
}

// ---------------------------------------------------------------------------
// Page
// ---------------------------------------------------------------------------
export default function RawPage() {
  const [logs, setLogs] = useState<RawLog[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [filter, setFilter] = useState("");
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    async function fetchRaw() {
      try {
        setLoading(true);
        const res = await fetch("/api/raw");
        const json = await res.json();
        if (!res.ok) throw new Error(json.error || "Error en la respuesta");
        setLogs(json.data || []);
      } catch (err: any) {
        setError(err.message);
      } finally {
        setLoading(false);
      }
    }
    fetchRaw();
  }, []);

  // Filtro local rápido por cualquier campo de texto
  const filtered = filter.trim()
    ? logs.filter((l) => {
        const q = filter.toLowerCase();
        return (
          (l["@timestamp"] || "").toLowerCase().includes(q) ||
          (l.source || "").toLowerCase().includes(q) ||
          (l.protocol || "").toLowerCase().includes(q) ||
          (l.raw_log || "").toLowerCase().includes(q)
        );
      })
    : logs;

  return (
    <div className="p-8 max-w-full mx-auto">
      {/* ------------------------------------------------------------------ */}
      {/* Header                                                              */}
      {/* ------------------------------------------------------------------ */}
      <header className="mb-6">
        <h1 className="text-2xl font-semibold text-gray-200 flex items-center gap-2">
          <TerminalSquare className="w-6 h-6 text-gray-300" />
          Logs Raw (Datos Crudos)
        </h1>
        <p className="text-sm text-gray-400 mt-1">
          Todos los eventos sin filtrar del índice{" "}
          <code className="text-[#5F13CF] bg-[#5F13CF]/10 px-1 rounded">
            sis-logs-v1
          </code>
          . Límite: <span className="text-gray-300 font-medium">200</span>{" "}
          registros más recientes.
        </p>
      </header>

      {/* ------------------------------------------------------------------ */}
      {/* Toolbar                                                             */}
      {/* ------------------------------------------------------------------ */}
      {!loading && !error && logs.length > 0 && (
        <div className="mb-4 flex items-center gap-3">
          <div className="relative flex-1 max-w-sm">
            <span className="absolute left-2.5 top-1/2 -translate-y-1/2 text-gray-500 text-xs select-none">
              🔍
            </span>
            <input
              ref={inputRef}
              type="text"
              placeholder="Filtrar por source, protocolo, raw log…"
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
              className="w-full pl-7 pr-3 py-1.5 text-xs rounded-md bg-[#1a2235] border border-gray-700/60 text-gray-200 placeholder-gray-600 focus:outline-none focus:border-[#5F13CF]/50 transition-colors"
            />
          </div>
          {filter && (
            <button
              onClick={() => setFilter("")}
              className="text-xs text-gray-500 hover:text-gray-300 transition-colors"
            >
              ✕ limpiar
            </button>
          )}
          <span className="text-xs text-gray-600 ml-auto">
            {filtered.length !== logs.length ? (
              <>
                <span className="text-[#5F13CF] font-medium">{filtered.length}</span>
                {" / "}
                <span className="text-gray-500">{logs.length}</span>
              </>
            ) : (
              <span className="text-gray-500">{logs.length} registros</span>
            )}
          </span>
        </div>
      )}

      {/* ------------------------------------------------------------------ */}
      {/* States: loading / error / empty                                     */}
      {/* ------------------------------------------------------------------ */}
      {loading && (
        <div className="flex items-center gap-3 text-gray-400 text-sm animate-pulse">
          <span className="inline-block w-4 h-4 rounded-full border-2 border-[#5F13CF] border-t-transparent animate-spin" />
          Cargando logs raw…
        </div>
      )}

      {!loading && error && (
        <div className="rounded-lg border border-red-500/30 bg-red-500/10 px-5 py-4 text-sm text-red-400">
          <strong>Error al conectar con Elasticsearch:</strong> {error}
        </div>
      )}

      {!loading && !error && filtered.length === 0 && (
        <div className="rounded-lg border border-gray-700/50 bg-[#1a2235] px-5 py-10 text-center text-gray-500 text-sm">
          {filter
            ? "No hay registros que coincidan con el filtro."
            : "No se encontraron logs en el índice."}
        </div>
      )}

      {/* ------------------------------------------------------------------ */}
      {/* Table — densa, técnica, texto xs                                    */}
      {/* ------------------------------------------------------------------ */}
      {!loading && !error && filtered.length > 0 && (
        <div className="overflow-x-auto rounded-xl border border-[#5F13CF]/20 shadow-lg shadow-black/30">
          <table className="w-full text-xs border-collapse table-fixed">
            <colgroup>
              <col style={{ width: "130px" }} />
              <col style={{ width: "130px" }} />
              <col style={{ width: "90px" }} />
              <col />
            </colgroup>
            <thead className="sticky top-0 z-10">
              <tr className="bg-[#0e1624] border-b border-[#5F13CF]/20 text-[#5F13CF] text-[10px] uppercase tracking-wider">
                <th className="text-left px-3 py-2 font-semibold whitespace-nowrap">
                  Timestamp
                </th>
                <th className="text-left px-3 py-2 font-semibold">
                  Source
                </th>
                <th className="text-left px-3 py-2 font-semibold">
                  Protocol
                </th>
                <th className="text-left px-3 py-2 font-semibold">
                  Raw Log
                </th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800/40">
              {filtered.map((log, i) => (
                <tr
                  key={i}
                  className="bg-[#1a2235] transition-colors hover:bg-[#5F13CF]/5 group"
                >
                  {/* Timestamp */}
                  <td className="px-3 py-2 whitespace-nowrap text-gray-500 font-mono leading-relaxed align-top">
                    {formatTimestamp(log["@timestamp"])}
                  </td>

                  {/* Source */}
                  <td className="px-3 py-2 text-gray-400 font-mono truncate align-top leading-relaxed">
                    {log.source || "—"}
                  </td>

                  {/* Protocol */}
                  <td className="px-3 py-2 align-top leading-relaxed">
                    <ProtocolBadge proto={log.protocol} />
                  </td>

                  {/* Raw Log — expande al hacer clic */}
                  <RawLogCell value={log.raw_log} />
                </tr>
              ))}
            </tbody>
          </table>

          {/* Footer */}
          <div className="bg-[#0e1624] border-t border-gray-800/60 px-3 py-1.5 flex items-center justify-between">
            <span className="text-[10px] text-gray-600">
              Total:{" "}
              <span className="text-gray-400 font-medium">{filtered.length}</span>{" "}
              entradas
            </span>
            <span className="text-[10px] text-gray-600">
              Índice:{" "}
              <code className="text-[#5F13CF]/70">sis-logs-v1</code>
            </span>
          </div>
        </div>
      )}
    </div>
  );
}
