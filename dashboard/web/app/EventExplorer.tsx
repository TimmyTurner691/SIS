"use client";

import { useEffect, useMemo, useState } from "react";

type EventDoc = Record<string, unknown>;

type Props = {
  kind: string;
  title: string;
  description: string;
};

const value = (row: EventDoc, key: string) => String(row[key] ?? "—");

export default function EventExplorer({ kind, title, description }: Props) {
  const [rows, setRows] = useState<EventDoc[]>([]);
  const [query, setQuery] = useState("");
  const [protocol, setProtocol] = useState("");
  const [risk, setRisk] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const isIds = kind === "ids";

  useEffect(() => {
    const controller = new AbortController();
    const params = new URLSearchParams({ kind, q: query, protocol, risk, size: "200" });
    const timer = setTimeout(() => {
      setLoading(true);
      fetch(`/api/events?${params}`, { signal: controller.signal })
        .then(async (response) => {
          const body = await response.json();
          if (!response.ok) throw new Error(body.error);
          return body;
        })
        .then((body) => {
          setRows(body.data ?? []);
          setError("");
        })
        .catch((requestError) => {
          if (requestError.name !== "AbortError") setError(requestError.message);
        })
        .finally(() => setLoading(false));
    }, 250);
    return () => {
      clearTimeout(timer);
      controller.abort();
    };
  }, [kind, query, protocol, risk]);

  const protocols = useMemo(
    () => [...new Set(rows.map((row) => value(row, "protocol")).filter((item) => item !== "—"))],
    [rows],
  );

  const messageCell = (row: EventDoc) => {
    const message = String(row.message ?? row.raw_log ?? "—");
    return <td className="min-w-[420px] max-w-3xl p-3" title={message}>{message}</td>;
  };

  return (
    <div className="space-y-5">
      <div>
        <h1 className="text-3xl font-bold text-white">{title}</h1>
        <p className="text-gray-400">{description}</p>
      </div>
      <div className="grid gap-3 rounded-xl border border-slate-700 bg-[#1a2235] p-4 md:grid-cols-3">
        <input aria-label="Buscar" value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Buscar IP, mensaje, firma…" className="rounded bg-[#0f172a] px-3 py-2 text-sm text-white" />
        <select aria-label="Protocolo" value={protocol} onChange={(event) => setProtocol(event.target.value)} className="rounded bg-[#0f172a] px-3 py-2 text-sm text-white">
          <option value="">Todos los protocolos</option>
          {protocols.map((item) => <option key={item} value={item}>{item.toUpperCase()}</option>)}
        </select>
        <select aria-label="Riesgo" value={risk} onChange={(event) => setRisk(event.target.value)} className="rounded bg-[#0f172a] px-3 py-2 text-sm text-white">
          <option value="">Todos los riesgos</option>
          {["CRÍTICO", "ALTO", "MEDIO", "BAJO"].map((item) => <option key={item}>{item}</option>)}
        </select>
      </div>
      {loading && <p className="text-sky-400">Consultando telemetría…</p>}
      {error && <p className="text-red-400">{error}</p>}
      {!loading && !error && (
        <div className="overflow-x-auto rounded-xl border border-slate-700">
          <table className="w-full text-xs text-gray-300">
            <thead className="bg-[#0e1624] text-sky-400">
              <tr>
                {isIds && <th className="p-3 text-left">Mensaje</th>}
                <th className="p-3 text-left">Timestamp</th>
                <th className="p-3 text-left">Origen</th>
                <th className="p-3 text-left">Destino</th>
                <th className="p-3 text-left">Protocolo</th>
                <th className="p-3 text-left">Riesgo</th>
                {!isIds && <th className="p-3 text-left">Mensaje</th>}
              </tr>
            </thead>
            <tbody>
              {rows.map((row, index) => (
                <tr key={String(row._id ?? index)} className="border-t border-slate-800 align-top">
                  {isIds && messageCell(row)}
                  <td className="p-3 whitespace-nowrap">{value(row, "@timestamp")}</td>
                  <td className="p-3 font-mono">{value(row, "src_ip")}</td>
                  <td className="p-3 font-mono">{value(row, "dst_ip")}</td>
                  <td className="p-3 font-semibold text-sky-300">{value(row, "protocol").toUpperCase()}</td>
                  <td className="p-3">{value(row, "risk_label")}</td>
                  {!isIds && messageCell(row)}
                </tr>
              ))}
            </tbody>
          </table>
          {rows.length === 0 && <p className="p-8 text-center text-gray-500">Sin eventos visibles.</p>}
        </div>
      )}
    </div>
  );
}
