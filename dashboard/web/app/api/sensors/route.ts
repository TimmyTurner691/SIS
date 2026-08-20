import { NextResponse } from 'next/server';
import { Client } from '@elastic/elasticsearch';

const es = new Client({
  node: `http://${process.env.SIS_DASHBOARD_ELASTIC_HOST || 'elasticsearch'}:${process.env.SIS_DASHBOARD_ELASTIC_PORT || '9200'}`
});

async function getLastSensorLog(sourceName: string) {
  try {
    const res = await es.search({
      index: process.env.SIS_INDEX_NAME || 'sis-logs-v1',
      size: 1,
      sort: [{ '@timestamp': { order: 'desc' } }],
      query: { term: { source: sourceName } }
    });

    if (res.hits.hits.length > 0) {
      const lastLog = res.hits.hits[0]._source as any;
      return new Date(lastLog['@timestamp']).getTime();
    }
    return 0;
  } catch (error) {
    return 0;
  }
}

export async function GET() {
  const now = Date.now();
  // 5 minutos sin datos = Sensor Caído
  const UMBRAL_CAIDO_MS = 5 * 60 * 1000;

  const [lastZeek, lastSnort] = await Promise.all([
    getLastSensorLog('zeek'),
    getLastSensorLog('snort')
  ]);

  const zeekAlive = lastZeek > 0 && (now - lastZeek) < UMBRAL_CAIDO_MS;
  const snortAlive = lastSnort > 0 && (now - lastSnort) < UMBRAL_CAIDO_MS;

  return NextResponse.json({
    zeek: {
      status: zeekAlive ? "🟢 Activo" : "🔴 Caído",
      info: zeekAlive ? `Último log: hace ${Math.floor((now - lastZeek) / 1000)}s` : "Sin telemetría"
    },
    snort: {
      status: snortAlive ? "🟢 Activo" : "🔴 Caído",
      info: snortAlive ? `Último log: hace ${Math.floor((now - lastSnort) / 1000)}s` : "Sin telemetría"
    }
  });
}