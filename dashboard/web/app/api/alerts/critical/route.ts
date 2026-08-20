import { NextResponse } from 'next/server';
import { Client } from '@elastic/elasticsearch';

const es = new Client({
  node: `http://${process.env.SIS_DASHBOARD_ELASTIC_HOST || 'elasticsearch'}:${process.env.SIS_DASHBOARD_ELASTIC_PORT || '9200'}`
});

export async function GET() {
  try {
    const res = await es.search({
      index: process.env.SIS_INDEX_NAME || 'sis-logs-v1',
      size: 5,
      sort: [{ '@timestamp': { order: 'desc' } }],
      body: {
        query: {
          bool: {
            should: [
              { term:  { 'risk_label.keyword': 'CRÍTICO' } },
              { range: { risk_total_score: { gte: 15 } } },
            ],
            minimum_should_match: 1,
          },
        },
      },
    });

    const hits = res.hits.hits.map((h: any) => h._source);
    return NextResponse.json({ success: true, data: hits });
  } catch (error) {
    console.error('Error consultando Critical Feed:', error);
    return NextResponse.json(
      { success: false, error: 'Error conectando a Elasticsearch', data: [] },
      { status: 500 }
    );
  }
}
