"use client";

import { AreaChart, Area, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';

// Datos simulados para visualizar la tendencia (luego vendrán de tu API)
const data = [
    { time: '10:00', criticos: 2, altos: 5 },
    { time: '10:05', criticos: 0, altos: 2 },
    { time: '10:10', criticos: 1, altos: 8 },
    { time: '10:15', criticos: 8, altos: 15 }, // Pico de ataque
    { time: '10:20', criticos: 3, altos: 6 },
    { time: '10:25', criticos: 0, altos: 3 },
];

export default function RiskTrendChart() {
    return (
        <div className="bg-[#1a2235] rounded-lg border border-gray-800/50 p-6 shadow-lg w-full h-[350px]">
            <h2 className="text-lg font-semibold text-gray-200 mb-4 flex items-center">
                <span className="mr-2">📈</span> Evolución de Incidentes
            </h2>

            <div className="w-full h-[250px]">
                <ResponsiveContainer width="100%" height="100%">
                    <AreaChart data={data} margin={{ top: 10, right: 10, left: -20, bottom: 0 }}>
                        <defs>
                            <linearGradient id="colorCritico" x1="0" y1="0" x2="0" y2="1">
                                <stop offset="5%" stopColor="#ef4444" stopOpacity={0.3} />
                                <stop offset="95%" stopColor="#ef4444" stopOpacity={0} />
                            </linearGradient>
                            <linearGradient id="colorAlto" x1="0" y1="0" x2="0" y2="1">
                                <stop offset="5%" stopColor="#f97316" stopOpacity={0.3} />
                                <stop offset="95%" stopColor="#f97316" stopOpacity={0} />
                            </linearGradient>
                        </defs>
                        <CartesianGrid strokeDasharray="3 3" stroke="#374151" vertical={false} />
                        <XAxis dataKey="time" stroke="#9ca3af" fontSize={12} tickLine={false} axisLine={false} />
                        <YAxis stroke="#9ca3af" fontSize={12} tickLine={false} axisLine={false} />
                        <Tooltip
                            contentStyle={{ backgroundColor: '#111827', borderColor: '#374151', borderRadius: '8px', color: '#f3f4f6' }}
                            itemStyle={{ fontSize: '14px' }}
                        />
                        <Area type="monotone" dataKey="altos" name="Riesgo Alto" stroke="#f97316" fillOpacity={1} fill="url(#colorAlto)" />
                        <Area type="monotone" dataKey="criticos" name="Críticos" stroke="#ef4444" fillOpacity={1} fill="url(#colorCritico)" />
                    </AreaChart>
                </ResponsiveContainer>
            </div>
        </div>
    );
}