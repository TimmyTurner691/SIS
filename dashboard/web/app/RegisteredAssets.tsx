"use client";
import { useEffect, useState } from 'react';
import { Network } from 'lucide-react';

type RegisteredAsset = {
    ip: string;
    name?: string;
    type?: string;
    mac?: string;
    vendor?: string;
    criticidad?: string;
    criticality?: string;
};

export default function RegisteredAssets() {
    const [assets, setAssets] = useState<RegisteredAsset[]>([]);
    const [query, setQuery] = useState('');
    const [selected, setSelected] = useState<Set<string>>(new Set());
    const [deleting, setDeleting] = useState(false);
    const visibleAssets = assets.filter(asset => JSON.stringify(asset).toLowerCase().includes(query.toLowerCase()));
    const allVisibleSelected = visibleAssets.length > 0 && visibleAssets.every(asset => selected.has(asset.ip));

    const toggle = (ip: string) => {
        const next = new Set(selected);
        if (next.has(ip)) next.delete(ip); else next.add(ip);
        setSelected(next);
    };

    const toggleAll = () => {
        const next = new Set(selected);
        if (allVisibleSelected) visibleAssets.forEach(asset => next.delete(asset.ip));
        else visibleAssets.forEach(asset => asset.ip && next.add(asset.ip));
        setSelected(next);
    };

    const deleteSelected = async () => {
        if (!selected.size || !confirm(`¿Eliminar ${selected.size} activo(s) registrados?`)) return;
        setDeleting(true);
        try {
            const response = await fetch('/api/assets/registered', { method: 'DELETE', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ ips: [...selected] }) });
            const body = await response.json();
            if (!response.ok) throw new Error(body.error);
            setAssets(current => current.filter(asset => !selected.has(asset.ip)));
            setSelected(new Set());
        } catch (error) {
            alert(error instanceof Error ? error.message : 'No se pudieron eliminar los activos');
        } finally {
            setDeleting(false);
        }
    };

    useEffect(() => {
        fetch('/api/assets/registered')
            .then(res => res.json())
            .then(data => setAssets(Array.isArray(data) ? data : []));
    }, []);

    return (
        <div className="bg-[#1a2235] rounded-lg border-t-2 border-t-[#7BDCB5] p-6 shadow-lg">
            <div className="mb-4 flex flex-wrap items-center justify-between gap-3">
                <h2 className="text-xl text-white font-bold flex items-center gap-2"><Network className="w-6 h-6 text-emerald-500" />Activos Registrados (Oficiales)</h2>
                <div className="flex flex-wrap gap-2">
                    <button onClick={toggleAll} disabled={!visibleAssets.length || deleting} className="rounded border border-emerald-500 px-4 py-2 text-emerald-300 disabled:opacity-40">{allVisibleSelected ? 'Deseleccionar visibles' : `Seleccionar todos (${visibleAssets.length})`}</button>
                    <button onClick={deleteSelected} disabled={!selected.size || deleting} className="rounded border border-red-500 px-4 py-2 text-red-300 disabled:opacity-40">{deleting ? 'Eliminando…' : `Eliminar seleccionados (${selected.size})`}</button>
                </div>
            </div>
            <input value={query} onChange={e => setQuery(e.target.value)} placeholder="Buscar IP, nombre, tipo, MAC, fabricante o criticidad" className="mb-4 w-full rounded bg-[#111827] px-3 py-2 text-sm text-white" />
            <div className="overflow-x-auto">
                <table className="w-full text-left text-sm text-gray-300">
                    <thead className="bg-[#111827] text-[#7BDCB5]">
                        <tr>
                            <th className="p-3 rounded-tl-lg">Sel.</th>
                            <th className="p-3">IP</th>
                            <th className="p-3">Nombre</th>
                            <th className="p-3">Tipo</th>
                            <th className="p-3">MAC</th>
                            <th className="p-3">Fabricante</th>
                            <th className="p-3 rounded-tr-lg">Criticidad</th>
                        </tr>
                    </thead>
                    <tbody>
                        {assets.length === 0 ? (
                            <tr><td colSpan={7} className="p-4 text-center text-gray-500">No hay activos registrados aún.</td></tr>
                        ) : (
                            visibleAssets.map((asset, i) => (
                                <tr key={i} className="border-b border-gray-800 hover:bg-[#7BDCB5]/10 transition-colors">
                                    <td className="p-3"><input aria-label={`Seleccionar ${asset.ip}`} type="checkbox" checked={selected.has(asset.ip)} onChange={() => toggle(asset.ip)} className="h-4 w-4 accent-emerald-500" /></td>
                                    <td className="p-3 font-mono">{asset.ip}</td>
                                    <td className="p-3 font-bold text-white">{asset.name}</td>
                                    <td className="p-3">{asset.type}</td>
                                    <td className="p-3 font-mono">{asset.mac}</td>
                                    <td className="p-3">{asset.vendor}</td>
                                    <td className="p-3">{asset.criticidad || asset.criticality}</td>
                                </tr>
                            ))
                        )}
                    </tbody>
                </table>
            </div>
        </div>
    );
}
