import { Client } from "@elastic/elasticsearch";
import Redis from "ioredis";
import { NextRequest, NextResponse } from "next/server";

const es = new Client({ node: `http://${process.env.SIS_DASHBOARD_ELASTIC_HOST || "elasticsearch"}:${process.env.SIS_DASHBOARD_ELASTIC_PORT || "9200"}` });
const redis = new Redis({ host: process.env.SIS_DASHBOARD_REDIS_HOST || "redis", port: Number(process.env.SIS_DASHBOARD_REDIS_PORT || 6379), maxRetriesPerRequest: 1 });
const eventIndex = process.env.SIS_DASHBOARD_INDEX || "sis-logs-v1";
const exceptionIndex = process.env.SIS_IDS_EXCEPTIONS_INDEX || "sis-ids-exceptions-v1";
const redisKey = "sis:ids:exceptions";
type Alert = Record<string, unknown>;

function signatureSid(alert: Alert) {
  return String(alert.signature_sid || String(alert.message || alert.raw_log || "").match(/\[\s*\d+\s*:\s*(\d+)\s*:\s*\d+\s*\]/)?.[1] || "unknown");
}
function fingerprint(alert: Alert) {
  return [signatureSid(alert), alert.src_ip, alert.dst_ip, alert.protocol].map(value => String(value || "").toLowerCase()).join("|");
}

export async function GET() {
  try {
    const response = await es.search<Alert>({ index: exceptionIndex, size: 500, sort: [{ created_at: "desc" }] });
    return NextResponse.json({ data: response.hits.hits.map(hit => ({ _id: hit._id, ...hit._source })) });
  } catch (error: unknown) {
    const status = (error as { meta?: { statusCode?: number } }).meta?.statusCode;
    if (status === 404) return NextResponse.json({ data: [] });
    return NextResponse.json({ error: error instanceof Error ? error.message : "No se pudieron leer las excepciones" }, { status: 500 });
  }
}

export async function POST(request: NextRequest) {
  try {
    const { alerts } = await request.json() as { alerts: Alert[] };
    if (!Array.isArray(alerts) || alerts.length === 0) return NextResponse.json({ error: "Selecciona al menos una alerta" }, { status: 400 });
    let deleted = 0;
    for (const alert of alerts) {
      const sid = signatureSid(alert);
      const key = fingerprint({ ...alert, signature_sid: sid });
      const snapshot = { ...alert, signature_sid: sid, exception_fingerprint: key, created_at: new Date().toISOString() };
      delete snapshot._id;
      await es.index({ index: exceptionIndex, id: Buffer.from(key).toString("base64url"), document: snapshot, refresh: true });
      await redis.sadd(redisKey, key);
      const protocolTerms = [...new Set([alert.protocol, alert.transport_protocol].filter(Boolean))]
        .map(protocol => ({ term: { "protocol.keyword": protocol } }));
      const clauses: Record<string, unknown>[] = [
        { term: { "src_ip.keyword": alert.src_ip } },
        { term: { "dst_ip.keyword": alert.dst_ip } },
        { bool: { should: protocolTerms, minimum_should_match: 1 } },
      ];
      if (sid !== "unknown") clauses.push({ query_string: { query: sid, fields: ["signature_sid", "message", "raw_log"] } });
      const result = await es.deleteByQuery({ index: eventIndex, query: { bool: { filter: clauses } }, refresh: true, conflicts: "proceed" });
      deleted += result.deleted || 0;
    }
    return NextResponse.json({ success: true, exceptions: alerts.length, deleted });
  } catch (error: unknown) {
    return NextResponse.json({ error: error instanceof Error ? error.message : "No se pudo crear la excepción" }, { status: 500 });
  }
}

export async function DELETE(request: NextRequest) {
  try {
    const { ids } = await request.json() as { ids: string[] };
    if (!Array.isArray(ids) || ids.length === 0) return NextResponse.json({ error: "Selecciona una excepción" }, { status: 400 });
    for (const id of ids) {
      const found = await es.get<Alert>({ index: exceptionIndex, id });
      const key = String(found._source?.exception_fingerprint || fingerprint(found._source || {}));
      await redis.srem(redisKey, key);
      await redis.del(...["BAJO", "MEDIO", "ALTO", "CRÍTICO"].map(risk => `sis:ids:throttle:${risk}:${key}`));
      await es.delete({ index: exceptionIndex, id, refresh: true });
    }
    return NextResponse.json({ success: true, restored: ids.length });
  } catch (error: unknown) {
    return NextResponse.json({ error: error instanceof Error ? error.message : "No se pudo restaurar la excepción" }, { status: 500 });
  }
}
