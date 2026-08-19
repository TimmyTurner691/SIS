import { NextResponse } from "next/server";
import fs from "fs/promises";

interface SensorData {
  status: string;
  info: string;
}

async function getSensorHealth(filePath: string): Promise<SensorData> {
  try {
    const fileContent = await fs.readFile(filePath, "utf-8");
    const data = JSON.parse(fileContent);

    // Determinar si el timestamp está en segundos o milisegundos
    let timestampMs = data.timestamp;
    if (timestampMs && timestampMs < 1e12) {
      timestampMs *= 1000; // Convertir de segundos a milisegundos
    }

    // Si por alguna razón no hay timestamp válido, caerá en el catch o se evaluará como NaN -> falso en las condiciones
    if (!timestampMs) {
      throw new Error("Invalid timestamp");
    }

    const diffSeconds = (Date.now() - timestampMs) / 1000;

    let status = "🔴 Caído";
    if (diffSeconds <= 30) {
      status = "🟢 Escuchando";
    } else if (diffSeconds <= 120) {
      status = "🟡 Degradado";
    }

    const iface = data.interface || "N/A";
    const mode = data.mode || "N/A";
    const promisc = data.promiscuous ? "PROMISC" : "NORMAL";

    const info = `Int: ${iface} | Modo: ${mode} | ${promisc}`;

    return { status, info };
  } catch (error) {
    return { status: "🔴 Caído", info: "Sin heartbeat" };
  }
}

export async function GET() {
  const [zeek, snort] = await Promise.all([
    getSensorHealth("/sensor-health/zeek.json"),
    getSensorHealth("/sensor-health/snort.json"),
  ]);

  return NextResponse.json({ zeek, snort });
}
