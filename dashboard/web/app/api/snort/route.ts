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
          term: {
            "source.keyword": "snort",
          },
        },
        sort: [{ "@timestamp": { order: "desc" } }],
        size: 100,
      },
    });

    // Compatibilidad con v7/v8/v9
    const hits =
      (response.hits?.hits as any[]) ||
      ((response as any).body?.hits?.hits as any[]) ||
      [];

    const results = hits.map((hit: any) => hit._source);

    return NextResponse.json({ success: true, data: results });
  } catch (error: any) {
    console.error("[/api/snort] Error consultando Elastic:", error);
    return NextResponse.json(
      { success: false, error: error.message, data: [] },
      { status: 500 }
    );
  }
}
