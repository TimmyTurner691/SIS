"use client";

import { useState } from "react";
import { Cpu, RefreshCw, Trash2, RotateCcw, Zap } from "lucide-react"; // <-- Íconos corporativos

export default function CommandCenter() {
  const [loading, setLoading] = useState(false);

  const sendCommand = async (instruction: string) => {
    // ... tu lógica de fetch se mantiene exactamente igual ...
    setLoading(true);
    try {
      const res = await fetch("/api/command", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ instruction }),
      });
      const data = await res.json();
      if (res.ok && data.success) {
        alert(`Éxito: ${data.message}`);
      } else {
        alert(`Error: ${data.message || "No se pudo completar la operación."}`);
      }
    } catch (error) {
      console.error(error);
      alert("Error de red al intentar enviar el comando.");
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="flex items-center space-x-4">
      {/* Etiqueta visible solo en pantallas medianas o grandes */}
      <div className="hidden md:flex items-center space-x-2 border-r border-gray-800/50 pr-4">
        <Cpu className="w-4 h-4 text-gray-400" />
        <span className="text-xs font-semibold text-gray-400 uppercase tracking-wider">
          Control Motor IA
        </span>
      </div>

      {/* Contenedor Horizontal de Botones */}
      <div className="flex flex-row items-center space-x-3">
        <button
          onClick={() => window.location.reload()}
          className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md bg-sky-900/10 text-sky-400 border border-sky-800/50 hover:bg-sky-600 hover:text-white transition-colors shadow-sm"
          title="Actualizar todos los datos del dashboard"
        >
          <RefreshCw className="w-3.5 h-3.5" />
          Actualizar
        </button>
        <button
          onClick={() => sendCommand("reset_demo")}
          disabled={loading}
          className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md bg-red-900/10 text-red-400 border border-red-900/50 hover:bg-red-600 hover:text-white transition-colors disabled:opacity-50 disabled:cursor-not-allowed shadow-sm"
        >
          <Trash2 className="w-3.5 h-3.5" />
          Reset Demo Total
        </button>

        <button
          onClick={() => sendCommand("reset_ia")}
          disabled={loading}
          className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md bg-yellow-900/10 text-yellow-400 border border-yellow-900/50 hover:bg-yellow-600 hover:text-white transition-colors disabled:opacity-50 disabled:cursor-not-allowed shadow-sm"
        >
          <RotateCcw className="w-3.5 h-3.5" />
          Reset Memoria IA
        </button>

        <button
          onClick={() => sendCommand("force_train")}
          disabled={loading}
          className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-md bg-[#5F13CF]/10 text-[#a06ef0] border border-[#5F13CF]/30 hover:bg-[#5F13CF] hover:text-white transition-colors disabled:opacity-50 disabled:cursor-not-allowed shadow-sm"
        >
          <Zap className="w-3.5 h-3.5" />
          Forzar Re-entrenamiento
        </button>
      </div>
    </div>
  );
}
