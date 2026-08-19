import { NextResponse } from 'next/server';
import { Client } from '@elastic/elasticsearch';

// Conexión segura usando variables de entorno
const es = new Client({
    node: `http://${process.env.SIS_DASHBOARD_ELASTIC_HOST || 'elasticsearch'}:${process.env.SIS_DASHBOARD_ELASTIC_PORT || '9200'}`
});

export async function GET() {
    try {
        const res = await es.search({
            index: process.env.SIS_DASHBOARD_DISCOVERED_ASSETS_INDEX || 'sis-discovered-assets-v3',
            size: 100,
            sort: [{ ultima_vez_visto: { order: 'desc' } }]
        });

        // Extraemos solo el origen de los datos
        const hits = res.hits.hits.map((h: any) => h._source);
        return NextResponse.json(hits);
    } catch (error) {
        return NextResponse.json({ error: 'Error conectando a Elastic' }, { status: 500 });
    }
}