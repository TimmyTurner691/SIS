import { NextResponse } from "next/server";
import { Client } from "@elastic/elasticsearch";

const ES_HOST = process.env.SIS_DASHBOARD_ELASTIC_HOST || "elasticsearch";
const ES_PORT = process.env.SIS_DASHBOARD_ELASTIC_PORT || "9200";
const INDEX_NAME = process.env.SIS_DASHBOARD_INDEX || "sis-logs-v1";

const client = new Client({
  node: `http://${ES_HOST}:${ES_PORT}`,
});

export async function GET() {
  try {
    const response = await client.search({
      index: INDEX_NAME,
      body: {
        query: {
          range: {
            "@timestamp": {
              gte: "now-60m", // Últimos 60 minutos
            },
          },
        },
        aggs: {
          max_risk: { max: { field: "risk_total_score" } },
          critical_incidents: {
            filter: { range: { risk_total_score: { gte: 17 } } },
          },
          unique_dst_ips: { cardinality: { field: "dst_ip.keyword" } },
          impact_matrix: {
            terms: { field: "risk_impact", size: 10 },
            aggs: {
              probability: {
                terms: { field: "risk_probability", size: 10 },
              },
            },
          },
        },
        size: 0, // No necesitamos los documentos crudos, solo los KPIs (agregaciones)
      },
    });

    // Compatibilidad para @elastic/elasticsearch v7 o v8
    const aggs = (response.aggregations || (response as any).body?.aggregations) as any;

    const maxRisk = aggs?.max_risk?.value || 0;
    const criticalIncidents = aggs?.critical_incidents?.doc_count || 0;
    const uniqueDstIps = aggs?.unique_dst_ips?.value || 0;

    // Procesar los resultados de la matriz de riesgo agrupada
    const matrix = [];
    if (aggs?.impact_matrix?.buckets) {
      for (const impactBucket of aggs.impact_matrix.buckets) {
        if (impactBucket.probability && impactBucket.probability.buckets) {
          for (const probBucket of impactBucket.probability.buckets) {
            matrix.push({
              impact: impactBucket.key,
              probability: probBucket.key,
              count: probBucket.doc_count,
            });
          }
        }
      }
    }

    return NextResponse.json({
      success: true,
      data: {
        maxRisk,
        criticalIncidents,
        uniqueDstIps,
        matrix,
      },
    });
  } catch (error: any) {
    console.error("Error consultando Elastic:", error);
    
    // Se devuelve un payload limpio de fallbacks para que el frontend no rompa si Elastic falla
    return NextResponse.json(
      {
        success: false,
        error: error.message,
        data: {
          maxRisk: 0,
          criticalIncidents: 0,
          uniqueDstIps: 0,
          matrix: [],
        },
      },
      { status: 500 }
    );
  }
}
