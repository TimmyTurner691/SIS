"use client";
import { useEffect, useMemo, useState } from "react";

type EventDoc = Record<string, unknown>;
export default function EventExplorer({ kind, title, description }: { kind: string; title: string; description: string }) {
  const [rows, setRows] = useState<EventDoc[]>([]);
  const [query, setQuery] = useState("");
  const [protocol, setProtocol] = useState("");
  const [risk, setRisk] = useState("");
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  useEffect(() => {
    const controller = new AbortController();
    const params = new URLSearchParams({ kind, q: query, protocol, risk, size: "200" });
    const timer = setTimeout(() => {
      setLoading(true);
      fetch(`/api/events?${params}`, { signal: controller.signal })
        .then(async r => { const body = await r.json(); if (!r.ok) throw new Error(body.error); return body; })
        .then(body => { setRows(body.data ?? []); setError(""); })
        .catch(e => { if (e.name !== "AbortError") setError(e.message); })
        .finally(() => setLoading(false));
    }, 250);
    return () => { clearTimeout(timer); controller.abort(); };
  }, [kind, query, protocol, risk]);
  const protocols = useMemo(() => [...new Set(rows.map(r => String(r.protocol ?? "")).filter(Boolean))], [rows]);
  return <div className="space-y-5">
    <div><h1 className="text-3xl font-bold text-white">{title}</h1><p className="text-gray-400">{description}</p></div>
    <div className="grid gap-3 rounded-xl border border-slate-700 bg-[#1a2235] p-4 md:grid-cols-3">
      <input aria-label="Buscar" value={query} onChange={e=>setQuery(e.target.value)} placeholder="Buscar IP, mensaje, firma…" className="rounded bg-[#0f172a] px-3 py-2 text-sm text-white" />
      <select aria-label="Protocolo" value={protocol} onChange={e=>setProtocol(e.target.value)} className="rounded bg-[#0f172a] px-3 py-2 text-sm text-white"><option value="">Todos los protocolos</option>{protocols.map(p=><option key={p}>{p}</option>)}</select>
      <select aria-label="Riesgo" value={risk} onChange={e=>setRisk(e.target.value)} className="rounded bg-[#0f172a] px-3 py-2 text-sm text-white"><option value="">Todos los riesgos</option>{["CRÍTICO","ALTO","MEDIO","BAJO"].map(x=><option key={x}>{x}</option>)}</select>
    </div>
    {loading && <p className="text-sky-400">Consultando telemetría…</p>}{error && <p className="text-red-400">{error}</p>}
    {!loading && !error && <div className="overflow-x-auto rounded-xl border border-slate-700"><table className="w-full text-xs text-gray-300"><thead className="bg-[#0e1624] text-sky-400"><tr>{["Timestamp","Origen","Destino","Protocolo","Riesgo","Mensaje"].map(h=><th key={h} className="p-3 text-left">{h}</th>)}</tr></thead><tbody>{rows.map((r,i)=><tr key={String(r._id ?? i)} className="border-t border-slate-800"><td className="p-3 whitespace-nowrap">{String(r["@timestamp"] ?? "—")}</td><td className="p-3 font-mono">{String(r.src_ip ?? "—")}</td><td className="p-3 font-mono">{String(r.dst_ip ?? "—")}</td><td className="p-3">{String(r.protocol ?? "—")}</td><td className="p-3">{String(r.risk_label ?? "—")}</td><td className="p-3 max-w-xl truncate" title={String(r.message ?? r.raw_log ?? "")}>{String(r.message ?? r.raw_log ?? "—")}</td></tr>)}</tbody></table>{rows.length===0&&<p className="p-8 text-center text-gray-500">Sin eventos visibles.</p>}</div>}
  </div>;
}
