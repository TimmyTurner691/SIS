"use client";

import { useEffect, useMemo, useState } from "react";
import Link from "next/link";

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
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [saving, setSaving] = useState(false);
  const isIds = kind === "ids";
  const isNetwork = kind === "red";

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

  const toggleSelected = (id: string) => {
    setSelected((current) => {
      const next = new Set(current);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  const markFalsePositive = async () => {
    const alerts = rows.filter((row) => selected.has(String(row._id)));
    if (!alerts.length) return;
    setSaving(true);
    try {
      const response = await fetch("/api/ids/exceptions", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ alerts }),
      });
      const body = await response.json();
      if (!response.ok) throw new Error(body.error);
      setRows((current) => current.filter((row) => !selected.has(String(row._id))));
      setSelected(new Set());
    } catch (requestError) {
      setError(requestError instanceof Error ? requestError.message : "No se pudo crear la excepción");
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="space-y-5">
      <div>
        <h1 className="text-3xl font-bold text-white">{title}</h1>
        <p className="text-gray-400">{description}</p>
      </div>
      <div className={`grid gap-3 rounded-xl border border-slate-700 bg-[#1a2235] p-4 ${isNetwork ? "md:grid-cols-2" : "md:grid-cols-3"}`}>
        <input aria-label="Buscar" value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Buscar IP, mensaje, firma…" className="rounded bg-[#0f172a] px-3 py-2 text-sm text-white" />
        <select aria-label="Protocolo" value={protocol} onChange={(event) => setProtocol(event.target.value)} className="rounded bg-[#0f172a] px-3 py-2 text-sm text-white">
          <option value="">Todos los protocolos</option>
          {protocols.map((item) => <option key={item} value={item}>{item.toUpperCase()}</option>)}
        </select>
        {!isNetwork && (
          <select aria-label="Riesgo" value={risk} onChange={(event) => setRisk(event.target.value)} className="rounded bg-[#0f172a] px-3 py-2 text-sm text-white">
            <option value="">Todos los riesgos</option>
            {["CRÍTICO", "ALTO", "MEDIO", "BAJO"].map((item) => <option key={item}>{item}</option>)}
          </select>
        )}
      </div>
      {isIds && (
        <div className="flex flex-wrap items-center justify-between gap-3">
          <button onClick={markFalsePositive} disabled={!selected.size || saving} className="rounded border border-amber-500 px-4 py-2 text-sm text-amber-300 disabled:cursor-not-allowed disabled:opacity-40">
            {saving ? "Guardando excepción…" : `Marcar falso positivo (${selected.size})`}
          </button>
          <Link href="/ids/excepciones" className="rounded bg-slate-800 px-4 py-2 text-sm text-sky-300 hover:bg-slate-700">Ver excepciones IDS</Link>
        </div>
      )}
      {loading && <p className="text-sky-400">Consultando telemetría…</p>}
      {error && <p className="text-red-400">{error}</p>}
      {!loading && !error && (
        <div className="overflow-x-auto rounded-xl border border-slate-700">
          <table className="w-full text-xs text-gray-300">
            <thead className="bg-[#0e1624] text-sky-400">
              <tr>
                <th className="p-3 text-left">Timestamp</th>
                {isIds && <th className="p-3 text-left">Mensaje</th>}
                <th className="p-3 text-left">Origen</th>
                <th className="p-3 text-left">Destino</th>
                <th className="p-3 text-left">Protocolo</th>
                {isNetwork && <th className="p-3 text-left">Puerto destino</th>}
                {!isNetwork && <th className="p-3 text-left">Riesgo</th>}
                {!isIds && !isNetwork && <th className="p-3 text-left">Mensaje</th>}
              </tr>
            </thead>
            <tbody>
              {rows.map((row, index) => (
                <tr key={String(row._id ?? index)} className="border-t border-slate-800 align-top">
                  <td className="p-3 whitespace-nowrap">
                    {isIds && <input aria-label="Seleccionar alerta" type="checkbox" checked={selected.has(String(row._id))} onChange={() => toggleSelected(String(row._id))} className="mr-3 accent-amber-500" />}
                    {value(row, "@timestamp")}
                  </td>
                  {isIds && messageCell(row)}
                  <td className="p-3 font-mono">{value(row, "src_ip")}</td>
                  <td className="p-3 font-mono">{value(row, "dst_ip")}</td>
                  <td className="p-3 font-semibold text-sky-300">{value(row, "protocol").toUpperCase()}</td>
                  {isNetwork && <td className="p-3 font-mono">{value(row, "dst_port")}</td>}
                  {!isNetwork && <td className="p-3">{value(row, "risk_label")}</td>}
                  {!isIds && !isNetwork && messageCell(row)}
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
