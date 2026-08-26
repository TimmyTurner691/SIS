"use client";

import Link from "next/link";
import { useEffect, useState } from "react";

type ExceptionRow = Record<string, unknown>;
const value = (row: ExceptionRow, key: string) => String(row[key] ?? "—");

export default function IdsExceptionsPage() {
  const [rows, setRows] = useState<ExceptionRow[]>([]);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(true);

  const load = () => {
    setLoading(true);
    fetch("/api/ids/exceptions")
      .then(async response => { const body = await response.json(); if (!response.ok) throw new Error(body.error); return body; })
      .then(body => { setRows(body.data || []); setError(""); })
      .catch(requestError => setError(requestError.message))
      .finally(() => setLoading(false));
  };
  useEffect(() => { void Promise.resolve().then(load); }, []);

  const toggle = (id: string) => setSelected(current => {
    const next = new Set(current);
    if (next.has(id)) next.delete(id); else next.add(id);
    return next;
  });
  const restore = async () => {
    const response = await fetch("/api/ids/exceptions", { method: "DELETE", headers: { "content-type": "application/json" }, body: JSON.stringify({ ids: [...selected] }) });
    const body = await response.json();
    if (!response.ok) { setError(body.error); return; }
    setSelected(new Set()); load();
  };

  return <div className="space-y-5">
    <div className="flex items-start justify-between gap-4">
      <div><h1 className="text-3xl font-bold text-white">Excepciones IDS</h1><p className="text-gray-400">Solo se conserva el evento seleccionado como referencia; no se agregan logs automáticamente.</p></div>
      <Link href="/ids" className="rounded bg-slate-800 px-4 py-2 text-sm text-sky-300">Volver a IDS</Link>
    </div>
    <button onClick={restore} disabled={!selected.size} className="rounded border border-emerald-500 px-4 py-2 text-sm text-emerald-300 disabled:opacity-40">Restaurar monitoreo ({selected.size})</button>
    {loading && <p className="text-sky-400">Cargando excepciones…</p>}{error && <p className="text-red-400">{error}</p>}
    {!loading && !error && <div className="overflow-x-auto rounded-xl border border-slate-700"><table className="w-full text-xs text-gray-300"><thead className="bg-[#0e1624] text-sky-400"><tr><th className="p-3 text-left">Timestamp</th><th className="p-3 text-left">Mensaje</th><th className="p-3 text-left">Origen</th><th className="p-3 text-left">Destino</th><th className="p-3 text-left">Protocolo</th><th className="p-3 text-left">Riesgo</th></tr></thead><tbody>{rows.map(row => {const id=String(row._id);return <tr key={id} className="border-t border-slate-800 align-top"><td className="p-3 whitespace-nowrap"><input aria-label="Seleccionar excepción" type="checkbox" checked={selected.has(id)} onChange={()=>toggle(id)} className="mr-3 accent-emerald-500"/>{value(row,"@timestamp")}</td><td className="min-w-[420px] p-3">{String(row.message||row.raw_log||"—")}</td><td className="p-3 font-mono">{value(row,"src_ip")}</td><td className="p-3 font-mono">{value(row,"dst_ip")}</td><td className="p-3 font-semibold text-sky-300">{value(row,"protocol").toUpperCase()}</td><td className="p-3">{value(row,"risk_label")}</td></tr>})}</tbody></table>{!rows.length&&<p className="p-8 text-center text-gray-500">No hay alertas excepcionadas.</p>}</div>}
  </div>;
}
