import { NextResponse } from 'next/server';
import Docker from 'dockerode';

// Inicializamos Dockerode apuntando al socket del sistema operativo (montado vía volumen)
const docker = new Docker({ socketPath: '/var/run/docker.sock' });

async function getContainerHealth(containerName: string) {
  try {
    const container = docker.getContainer(containerName);
    const info = await container.inspect();

    // Validamos si el contenedor se encuentra ejecutándose activamente
    if (info.State && info.State.Running) {
      const startedAt = new Date(info.State.StartedAt).getTime();
      const uptimeMs = Date.now() - startedAt;
      const uptimeMin = Math.floor(uptimeMs / 1000 / 60);

      return {
        status: 'activo',
        info: uptimeMin === 0 ? 'Iniciado hace un momento' : `Uptime: ${uptimeMin} min`
      };
    } else {
      return {
        status: 'caido',
        info: `Estado: ${info.State?.Status || 'Detenido'}`
      };
    }
  } catch (error) {
    return {
      status: 'caido',
      info: 'Contenedor no encontrado'
    };
  }
}

export async function GET() {
  // Consultamos en paralelo el estado real de ambos sensores definidos en tu docker-compose
  const [zeekHealth, snortHealth] = await Promise.all([
    getContainerHealth('siem_zeek'),
    getContainerHealth('siem_snort')
  ]);

  return NextResponse.json({
    zeek: {
      status: zeekHealth.status === 'activo' ? "🟢 Escuchando" : "🔴 Caído",
      info: zeekHealth.info
    },
    snort: {
      status: snortHealth.status === 'activo' ? "🟢 Escuchando" : "🔴 Caído",
      info: snortHealth.info
    }
  });
}