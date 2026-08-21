"use client";
import { useEffect, useState } from 'react';
import { Radar } from 'lucide-react';

export default function DiscoveredAssets() {
    const [assets, setAssets] = useState<any[]>([]);
    const [selected, setSelected] = useState<Set<string>>(new Set());
    const [loading, setLoading] = useState(false);

    useEffect(() => {
        fetch('/api/assets/discovered')
            .then(res => res.json())
            .then(data => setAssets(Array.isArray(data) ? data : []));
    }, []);

    const toggleSelect = (ip: string) => {
        const newSelected = new Set(selected);
        if (newSelected.has(ip)) newSelected.delete(ip);
        else newSelected.add(ip);
        setSelected(newSelected);
    };

    const promoteSelected = async () => {
        if (selected.size === 0) return;
        setLoading(true);

        // Filtramos los objetos completos basados en las IPs seleccionadas
        const assetsToPromote = assets.filter(a => selected.has(a.ip));

        try {
            const res = await fetch('/api/assets/promote', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ assets: assetsToPromote })
            });
            const data = await res.json();
            alert(data.message || data.error);
            setSelected(new Set()); // Limpiamos selección
        } catch (err) {
            alert("Error al comunicarse con el servidor.");
        } finally {
            setLoading(false);
        }
    };

    return (
        <div className="bg-[#1a2235] rounded-lg border-t-2 border-t-[#5F13CF] p-6 mt-8 shadow-lg">
            <div className="flex justify-between items-center mb-4">
                <h2 className="text-xl text-white font-bold flex items-center gap-2">
                    <Radar className="w-5 h-5 text-gray-400" />
                    Equipos Descubiertos
                </h2>
                <button
                    onClick={promoteSelected}
                    disabled={selected.size === 0 || loading}
                    className="bg-[#5F13CF] hover:bg-purple-700 disabled:bg-gray-600 text-white px-4 py-2 rounded transition-colors"
                >
                    {loading ? 'Procesando...' : `Promover Seleccionados (${selected.size})`}
                </button>
            </div>

            <div className="overflow-x-auto">
                <table className="w-full text-left text-sm text-gray-300">
                    <thead className="bg-[#111827] text-gray-400">
                        <tr>
                            <th className="p-3 rounded-tl-lg">Sel.</th>
                            <th className="p-3">IP</th>
                            <th className="p-3">Hostname</th>
                            <th className="p-3">MAC</th>
                            <th className="p-3">Fabricante</th>
                            <th className="p-3 rounded-tr-lg">Criticidad</th>
                        </tr>
                    </thead>
                    <tbody>
                        {assets.map((asset, i) => (
                            <tr key={i} className="border-b border-gray-800 hover:bg-[#5F13CF]/10 transition-colors">
                                <td className="p-3">
                                    <input
                                        type="checkbox"
                                        checked={selected.has(asset.ip)}
                                        onChange={() => toggleSelect(asset.ip)}
                                        className="accent-[#5F13CF] w-4 h-4 cursor-pointer"
                                    />
                                </td>
                                <td className="p-3 font-mono">{asset.ip || 'N/A'}</td>
                                <td className="p-3">{asset.hostname || 'N/A'}</td>
                                <td className="p-3 font-mono">{asset.mac || 'N/A'}</td>
                                <td className="p-3">{asset.vendor_oui || 'Desconocido'}</td>
                                <td className={`p-3 font-bold ${asset.criticidad_sugerida === 'CRITICAL' ? 'text-red-500' : 'text-[#7BDCB5]'}`}>
                                    {asset.criticidad_sugerida || 'LOW'}
                                </td>
                            </tr>
                        ))}
                    </tbody>
                </table>
            </div>
        </div>
    );
}