import { NextResponse } from 'next/server';
import { Client } from '@elastic/elasticsearch';

const es = new Client({
  node: `http://${process.env.SIS_DASHBOARD_ELASTIC_HOST || 'elasticsearch'}:${process.env.SIS_DASHBOARD_ELASTIC_PORT || '9200'}`
});

export async function GET() {
  try {
    const alive = await es.ping();
    if (alive) {
      return NextResponse.json({ status: 'ok', elastic: true });
    }
    return NextResponse.json({ status: 'error', elastic: false }, { status: 503 });
  } catch {
    return NextResponse.json({ status: 'error', elastic: false }, { status: 503 });
  }
}
