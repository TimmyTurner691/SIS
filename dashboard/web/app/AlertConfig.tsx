"use client";

import { useState, useEffect } from "react";

export default function AlertConfig() {
    const [email, setEmail] = useState("");
    const [loading, setLoading] = useState(false);
    const [statusMessage, setStatusMessage] = useState<{ type: "success" | "error"; text: string } | null>(null);

    useEffect(() => {
        const fetchConfig = async () => {
            try {
                const res = await fetch("/api/config");
                if (res.ok) {
                    const data = await res.json();
                    if (data.email) setEmail(data.email);
                }
            } catch (error) {
                console.error("Error cargando configuración:", error);
            }
        };
        fetchConfig();
    }, []);

    const handleSave = async () => {
        setLoading(true);
        setStatusMessage(null);

        try {
            const res = await fetch("/api/config", {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify({ email }),
            });

            const data = await res.json();

            if (res.ok && data.success) {
                setStatusMessage({ type: "success", text: "Correo actualizado exitosamente" });
            } else {
                setStatusMessage({ type: "error", text: data.error || "Error al actualizar" });
            }
        } catch (error) {
            setStatusMessage({ type: "error", text: "Error de conexión" });
        } finally {
            setLoading(false);
            setTimeout(() => setStatusMessage(null), 3000); // Limpiar mensaje después de 3s
        }
    };

    return (
        <div className="bg-[#1a2235] rounded-lg border border-gray-800/50 border-t-2 border-t-[#5F13CF] p-4 shadow-lg w-full">
            <h2 className="text-base font-semibold text-gray-200 flex items-center gap-2">
                <span className="shrink-0 text-lg">📧</span>
                <span>Notificaciones SIS</span>
            </h2>
            <p className="text-xs text-gray-400 mt-1 mb-4 leading-relaxed">
                E-mail para recibir avisos de incidentes SCADA de alto impacto.
            </p>

            <div className="flex flex-col space-y-3">
                <input
                    type="email"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    placeholder="analista@soc-local.local"
                    className="w-full bg-[#111827] text-gray-200 text-sm rounded border border-gray-700 px-3 py-2 focus:outline-none focus:border-[#5F13CF] transition-colors"
                />

                <button
                    onClick={handleSave}
                    disabled={loading}
                    className={`w-full py-2 rounded text-sm font-medium transition-colors ${loading
                        ? "bg-gray-700 text-gray-400 cursor-not-allowed"
                        : "bg-[#5F13CF] text-white hover:bg-[#7221e6]"
                        }`}
                >
                    {loading ? "Guardando..." : "Guardar Configuración"}
                </button>

                {statusMessage && (
                    <p className={`text-xs text-center mt-2 ${statusMessage.type === "success" ? "text-green-400" : "text-red-400"}`}>
                        {statusMessage.text}
                    </p>
                )}
            </div>
        </div>
    );
}