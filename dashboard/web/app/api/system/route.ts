import { NextResponse } from "next/server";
import os from "os";
import { exec } from "child_process";

// ---------------------------------------------------------------------------
// CPU: calcula el porcentaje de carga comparando dos snapshots con 100 ms de
// intervalo, igual que hace la mayoría de herramientas de monitoreo.
// ---------------------------------------------------------------------------
function getCpuSnapshot(): { idle: number; total: number } {
  const cpus = os.cpus();
  let idle = 0;
  let total = 0;

  for (const cpu of cpus) {
    for (const type of Object.values(cpu.times)) {
      total += type;
    }
    idle += cpu.times.idle;
  }

  return { idle, total };
}

function measureCpuUsage(intervalMs = 100): Promise<number> {
  return new Promise((resolve) => {
    const start = getCpuSnapshot();

    setTimeout(() => {
      const end = getCpuSnapshot();

      const idleDiff = end.idle - start.idle;
      const totalDiff = end.total - start.total;

      const usagePercent =
        totalDiff === 0 ? 0 : ((totalDiff - idleDiff) / totalDiff) * 100;

      resolve(Math.round(usagePercent * 10) / 10);
    }, intervalMs);
  });
}

// ---------------------------------------------------------------------------
// RAM: usa os.totalmem() y os.freemem() directamente.
// ---------------------------------------------------------------------------
function getRamUsage(): number {
  const total = os.totalmem();
  const free = os.freemem();
  const used = total - free;
  return Math.round((used / total) * 1000) / 10; // un decimal
}

// ---------------------------------------------------------------------------
// Disco: ejecuta `df -k /` y parsea la columna de porcentaje de uso.
// ---------------------------------------------------------------------------
function getDiskUsage(): Promise<number> {
  return new Promise((resolve, reject) => {
    exec("df -k /", (error, stdout) => {
      if (error) {
        reject(error);
        return;
      }

      // Formato típico de df:
      // Filesystem  1K-blocks  Used  Available  Use%  Mounted on
      // /dev/sda1   ...        ...   ...        42%   /
      const lines = stdout.trim().split("\n");
      if (lines.length < 2) {
        reject(new Error("Unexpected df output"));
        return;
      }

      const dataLine = lines[1];
      // La columna Use% es la quinta (índice 4) en la mayoría de sistemas
      const columns = dataLine.split(/\s+/);
      const usePercent = columns[4]; // e.g. "42%"

      if (!usePercent) {
        reject(new Error("Could not parse disk usage"));
        return;
      }

      const value = parseFloat(usePercent.replace("%", ""));
      resolve(isNaN(value) ? 0 : value);
    });
  });
}

// ---------------------------------------------------------------------------
// Handler GET
// ---------------------------------------------------------------------------
export async function GET() {
  try {
    const [cpu, disk] = await Promise.all([
      measureCpuUsage(100),
      getDiskUsage(),
    ]);

    const ram = getRamUsage();

    return NextResponse.json({ cpu, ram, disk });
  } catch (err) {
    console.error("[/api/system] Error collecting metrics:", err);
    return NextResponse.json(
      { error: "Failed to collect system metrics" },
      { status: 500 }
    );
  }
}
