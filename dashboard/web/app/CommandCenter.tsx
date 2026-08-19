"use client";

import { useState } from "react";

export default function CommandCenter() {
  const [loading, setLoading] = useState(false);

  const sendCommand = async (instruction: string) => {
    setLoading(true);
    try {
      const res = await fetch("/api/command", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
        },
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
    <div className="px-4 py-6 border-t border-gray-800/50 mt-auto">
      <h3 className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-3">
        🧠 Control IA & Memoria
      </h3>
      <div className="space-y-2">
        <button
          onClick={() => sendCommand("reset_ia")}
          disabled={loading}
          className="w-full text-left px-3 py-2 text-sm font-medium rounded-md bg-[#1a2235] text-gray-300 border border-gray-800/50 hover:bg-[#5F13CF] hover:text-white transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
        >
          ♻️ RESET IA
        </button>
        <button
          onClick={() => sendCommand("reset_demo")}
          disabled={loading}
          className="w-full text-left px-3 py-2 text-sm font-medium rounded-md bg-[#1a2235] text-gray-300 border border-gray-800/50 hover:bg-[#5F13CF] hover:text-white transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
        >
          🧹 RESET DEMO TOTAL
        </button>
        <button
          onClick={() => sendCommand("force_train")}
          disabled={loading}
          className="w-full text-left px-3 py-2 text-sm font-medium rounded-md bg-[#1a2235] text-gray-300 border border-gray-800/50 hover:bg-[#5F13CF] hover:text-white transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
        >
          🎓 Forzar Re-entrenamiento
        </button>
      </div>
    </div>
  );
}
