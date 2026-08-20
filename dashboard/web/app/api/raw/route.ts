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
          match_all: {},
        },
        sort: [{ "@timestamp": { order: "desc" } }],
        size: 200,
        _source: true,
      },
    });

    // Compatibilidad con @elastic/elasticsearch v7 y v8
    const hits =
      (response.hits?.hits ||
        (response as any).body?.hits?.hits ||
        []) as any[];

    const data = hits.map((h: any) => h._source);

    return NextResponse.json({ success: true, data });
  } catch (error: any) {
    console.error("Error consultando Raw Logs en Elastic:", error);
    return NextResponse.json(
      { success: false, error: error.message, data: [] },
      { status: 500 }
    );
  }
}
