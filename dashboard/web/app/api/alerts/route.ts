import { NextResponse } from 'next/server';
import { Client } from '@elastic/elasticsearch';

// Conexión segura usando variables de entorno
const es = new Client({
  node: `http://${process.env.SIS_DASHBOARD_ELASTIC_HOST || 'elasticsearch'}:${process.env.SIS_DASHBOARD_ELASTIC_PORT || '9200'}`
});

export async function GET() {
  try {
    // Traemos los últimos 1000 eventos para calcular las métricas recientes
    const res = await es.search({
      index: process.env.SIS_INDEX_NAME || 'sis-logs-v1',
      size: 1000,
      sort: [{ '@timestamp': { order: 'desc' } }]
    });

    const hits = res.hits.hits.map((h: any) => h._source);

    let maxRisk = 0;
    let criticalIncidents = 0;
    const uniqueIps = new Set<string>();

    // Objeto temporal para contar cuántos eventos caen en cada celda de la matriz
    const matrixMap: Record<string, number> = {};

    hits.forEach((doc: any) => {
      // 1. Extraer los valores (con valores por defecto por seguridad)
      const impact = doc.risk_impact || 1;
      const prob = doc.risk_probability || 1;
      const score = doc.risk_total_score || (impact * prob);
      const label = doc.risk_label || "BAJO";

      // 2. Calcular KPIs
      if (score > maxRisk) maxRisk = score;

      // Contamos como crítico si la etiqueta es CRÍTICO o el score >= 17
      if (label === 'CRÍTICO' || score >= 17) {
        criticalIncidents++;
        if (doc.dst_ip && doc.dst_ip !== "0.0.0.0") {
          uniqueIps.add(doc.dst_ip);
        }
      }

      // 3. Agrupar para la Matriz de Calor
      const key = `${impact}-${prob}`;
      matrixMap[key] = (matrixMap[key] || 0) + 1;
    });

    // 4. Formatear la matriz como lo espera tu frontend
    const matrix = Object.keys(matrixMap).map(key => {
      const [i, p] = key.split('-');
      return {
        impact: Number(i),
        probability: Number(p),
        count: matrixMap[key]
      };
    });

    // Devolvemos el JSON exactamente con la interfaz AlertsData que definiste
    return NextResponse.json({
      success: true,
      data: {
        maxRisk,
        criticalIncidents,
        uniqueDstIps: uniqueIps.size,
        matrix
      }
    });

  } catch (error) {
    console.error("Error consultando Elastic:", error);
    return NextResponse.json(
      { success: false, error: 'Error conectando a Elasticsearch' },
      { status: 500 }
    );
  }
}