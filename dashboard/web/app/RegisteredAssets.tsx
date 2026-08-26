"use client";
import { useEffect, useState } from 'react';
import { Network } from 'lucide-react';

export default function RegisteredAssets() {
    const [assets, setAssets] = useState<any[]>([]);
    const [query, setQuery] = useState('');

    useEffect(() => {
        fetch('/api/assets/registered')
            .then(res => res.json())
            .then(data => setAssets(Array.isArray(data) ? data : []));
    }, []);

    return (
        <div className="bg-[#1a2235] rounded-lg border-t-2 border-t-[#7BDCB5] p-6 shadow-lg">
            <h2 className="text-xl text-white font-bold mb-4 flex items-center gap-2">
                <Network className="w-6 h-6 text-emerald-500" />
                Activos Registrados (Oficiales)
            </h2>
            <input value={query} onChange={e => setQuery(e.target.value)} placeholder="Buscar IP, nombre, tipo, MAC, fabricante o criticidad" className="mb-4 w-full rounded bg-[#111827] px-3 py-2 text-sm text-white" />
            <div className="overflow-x-auto">
                <table className="w-full text-left text-sm text-gray-300">
                    <thead className="bg-[#111827] text-[#7BDCB5]">
                        <tr>
                            <th className="p-3 rounded-tl-lg">IP</th>
                            <th className="p-3">Nombre</th>
                            <th className="p-3">Tipo</th>
                            <th className="p-3">MAC</th>
                            <th className="p-3">Fabricante</th>
                            <th className="p-3 rounded-tr-lg">Criticidad</th>
                        </tr>
                    </thead>
                    <tbody>
                        {assets.length === 0 ? (
                            <tr><td colSpan={6} className="p-4 text-center text-gray-500">No hay activos registrados aún.</td></tr>
                        ) : (
                            assets.filter(asset => JSON.stringify(asset).toLowerCase().includes(query.toLowerCase())).map((asset, i) => (
                                <tr key={i} className="border-b border-gray-800 hover:bg-[#7BDCB5]/10 transition-colors">
                                    <td className="p-3 font-mono">{asset.ip}</td>
                                    <td className="p-3 font-bold text-white">{asset.name}</td>
                                    <td className="p-3">{asset.type}</td>
                                    <td className="p-3 font-mono">{asset.mac}</td>
                                    <td className="p-3">{asset.vendor}</td>
                                    <td className="p-3">{asset.criticidad}</td>
                                </tr>
                            ))
                        )}
                    </tbody>
                </table>
            </div>
        </div>
    );
}
