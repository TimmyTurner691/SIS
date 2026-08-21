"use client";

import { useEffect, useState } from "react";
import {
    AreaChart,
    Area,
    XAxis,
    YAxis,
    CartesianGrid,
    Tooltip,
    ResponsiveContainer
} from "recharts";
import { Activity } from "lucide-react";

interface TrendData {
    time: string;
    criticos: number;
    altos: number;
    total: number;
}

export default function RiskTrendChart() {
    const [data, setData] = useState<TrendData[]>([]);
    const [loading, setLoading] = useState(true);

    const fetchTrendData = async () => {
        try {
            // Pedimos las últimas 12 horas con intervalos de 30 minutos para mayor granularidad visual
            const res = await fetch("/api/trend?hours=12&interval=30m");
            if (res.ok) {
                const json = await res.json();
                if (json.success) {
                    setData(json.data);
                }
            }
        } catch (error) {
            console.error("Error al cargar la tendencia de riesgos:", error);
        } finally {
            setLoading(false);
        }
    };

    useEffect(() => {
        fetchTrendData();
        // Actualizamos el gráfico cada 60 segundos
        const interval = setInterval(fetchTrendData, 60000);
        return () => clearInterval(interval);
    }, []);

    return (
        <div className="bg-[#1a2235] rounded-lg border border-gray-800/50 p-4 shadow-lg w-full h-80 flex flex-col">

            {/* Cabecera del Gráfico */}
            <div className="flex items-center justify-between mb-4">
                <h2 className="text-sm font-semibold text-gray-200 flex items-center gap-2">
                    <Activity className="w-4 h-4 text-[#5F13CF]" />
                    Tendencia de Incidentes (Últimas 12h)
                </h2>

                {/* Leyenda manual estilo SOC */}
                <div className="flex gap-4 text-xs font-medium">
                    <span className="flex items-center gap-1.5 text-red-400">
                        <span className="w-2 h-2 rounded-full bg-red-500 shadow-[0_0_8px_rgba(239,68,68,0.8)]"></span>
                        Críticos
                    </span>
                    <span className="flex items-center gap-1.5 text-orange-400">
                        <span className="w-2 h-2 rounded-full bg-orange-500 shadow-[0_0_8px_rgba(249,115,22,0.8)]"></span>
                        Altos
                    </span>
                </div>
            </div>

            {/* Contenedor del Gráfico de Recharts */}
            <div className="flex-1 w-full min-h-0 relative">
                {loading ? (
                    <div className="absolute inset-0 flex items-center justify-center text-xs text-gray-500 animate-pulse">
                        Consultando telemetría histórica...
                    </div>
                ) : data.length === 0 ? (
                    <div className="absolute inset-0 flex items-center justify-center text-xs text-gray-500">
                        No hay datos suficientes en este periodo.
                    </div>
                ) : (
                    <ResponsiveContainer width="100%" height="100%">
                        <AreaChart data={data} margin={{ top: 10, right: 0, left: -20, bottom: 0 }}>

                            {/* Cuadrícula de fondo muy sutil */}
                            <CartesianGrid strokeDasharray="3 3" stroke="#374151" vertical={false} opacity={0.3} />

                            <XAxis
                                dataKey="timestamp"
                                tickFormatter={(tick) => {
                                    const d = new Date(tick);
                                    return `${d.getHours().toString().padStart(2, '0')}:${d.getMinutes().toString().padStart(2, '0')}`;
                                }}
                                stroke="#6B7280"
                                fontSize={10}
                                tickLine={false}
                                axisLine={false}
                                minTickGap={20}
                            />

                            <YAxis
                                stroke="#6B7280"
                                fontSize={10}
                                tickLine={false}
                                axisLine={false}
                                allowDecimals={false}
                            />

                            {/* Tooltip personalizado (hover) */}
                            <Tooltip
                                labelFormatter={(label) => {
                                    const d = new Date(label);
                                    return `Hora: ${d.getHours().toString().padStart(2, '0')}:${d.getMinutes().toString().padStart(2, '0')}`;
                                }}
                                contentStyle={{
                                    backgroundColor: '#111827',
                                    borderColor: '#374151',
                                    borderRadius: '0.5rem',
                                    fontSize: '12px',
                                    boxShadow: '0 10px 15px -3px rgba(0, 0, 0, 0.5)'
                                }}
                                itemStyle={{ color: '#E5E7EB' }}
                            />

                            {/* Área de Incidentes Altos (Naranja) */}
                            <Area
                                type="monotone"
                                dataKey="altos"
                                name="Riesgo Alto"
                                stroke="#F97316"
                                strokeWidth={2}
                                fillOpacity={1}
                                fill="url(#colorAltos)"
                            />

                            {/* Área de Incidentes Críticos (Rojo puro) */}
                            <Area
                                type="monotone"
                                dataKey="criticos"
                                name="Riesgo Crítico"
                                stroke="#EF4444"
                                strokeWidth={2}
                                fillOpacity={1}
                                fill="url(#colorCriticos)"
                            />

                            {/* Definición de los gradientes para rellenar las áreas */}
                            <defs>
                                <linearGradient id="colorCriticos" x1="0" y1="0" x2="0" y2="1">
                                    <stop offset="5%" stopColor="#EF4444" stopOpacity={0.4} />
                                    <stop offset="95%" stopColor="#EF4444" stopOpacity={0} />
                                </linearGradient>
                                <linearGradient id="colorAltos" x1="0" y1="0" x2="0" y2="1">
                                    <stop offset="5%" stopColor="#F97316" stopOpacity={0.3} />
                                    <stop offset="95%" stopColor="#F97316" stopOpacity={0} />
                                </linearGradient>
                            </defs>
                        </AreaChart>
                    </ResponsiveContainer>
                )}
            </div>
        </div>
    );
}