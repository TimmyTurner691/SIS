import { NextRequest, NextResponse } from "next/server";
import { Client } from "@elastic/elasticsearch";

const ES_HOST = process.env.SIS_DASHBOARD_ELASTIC_HOST || process.env.SIS_ELASTIC_HOST || "elasticsearch";
const ES_PORT = process.env.SIS_DASHBOARD_ELASTIC_PORT || process.env.SIS_ELASTIC_PORT || "9200";
const INDEX_NAME = process.env.SIS_DASHBOARD_INDEX || process.env.SIS_INDEX_NAME || "sis-logs-v1";

const client = new Client({
  node: `http://${ES_HOST}:${ES_PORT}`,
});

interface SubBucketFilter {
  doc_count: number;
}

interface DateHistogramBucket {
  key: number | string;
  key_as_string?: string;
  doc_count: number;
  criticos?: SubBucketFilter;
  altos?: SubBucketFilter;
}

interface TrendAggregations {
  incidents_over_time?: {
    buckets?: DateHistogramBucket[];
  };
}

export async function GET(request: NextRequest) {
  try {
    const { searchParams } = new URL(request.url);
    const hours = parseInt(searchParams.get("hours") || "24", 10);
    const interval = searchParams.get("interval") || "1h";

    const response = await client.search<unknown, TrendAggregations>({
      index: INDEX_NAME,
      size: 0,
      body: {
        query: {
          range: {
            "@timestamp": {
              gte: `now-${hours}h`,
              lte: "now",
            },
          },
        },
        aggs: {
          incidents_over_time: {
            date_histogram: {
              field: "@timestamp",
              fixed_interval: interval,
              min_doc_count: 0,
              extended_bounds: {
                min: `now-${hours}h`,
                max: "now",
              },
            },
            aggs: {
              criticos: {
                filter: {
                  bool: {
                    should: [
                      { term: { "risk_label.keyword": "CRÍTICO" } },
                      { term: { "risk_label.keyword": "CRITICO" } },
                      { term: { "risk_label.keyword": "Crítico" } },
                      { term: { "risk_label.keyword": "Critico" } },
                      { range: { risk_total_score: { gte: 20 } } },
                    ],
                    minimum_should_match: 1,
                  },
                },
              },
              altos: {
                filter: {
                  bool: {
                    should: [
                      { term: { "risk_label.keyword": "ALTO" } },
                      { term: { "risk_label.keyword": "Alto" } },
                      {
                        bool: {
                          must: [
                            { range: { risk_total_score: { gte: 8, lt: 20 } } },
                          ],
                        },
                      },
                    ],
                    minimum_should_match: 1,
                  },
                },
              },
            },
          },
        },
      },
    });

    const aggs = (response.aggregations ||
      (response as unknown as { body?: { aggregations?: TrendAggregations } }).body?.aggregations) as
      | TrendAggregations
      | undefined;

    const buckets = aggs?.incidents_over_time?.buckets || [];

    const data = buckets.map((bucket: DateHistogramBucket) => {
      const date = new Date(bucket.key);
      const hoursStr = date.getHours().toString().padStart(2, "0");
      const minutesStr = date.getMinutes().toString().padStart(2, "0");
      const time = `${hoursStr}:${minutesStr}`;

      return {
        timestamp: bucket.key_as_string || date.toISOString(),
        time,
        criticos: bucket.criticos?.doc_count ?? 0,
        altos: bucket.altos?.doc_count ?? 0,
        total: bucket.doc_count ?? 0,
      };
    });

    return NextResponse.json({
      success: true,
      data,
    });
  } catch (error: unknown) {
    const errorMessage =
      error instanceof Error ? error.message : "Error al conectar con Elasticsearch";
    console.error("[/api/trend] Error consultando Elasticsearch:", error);
    return NextResponse.json(
      {
        success: false,
        error: errorMessage,
        data: [],
      },
      { status: 500 }
    );
  }
}
