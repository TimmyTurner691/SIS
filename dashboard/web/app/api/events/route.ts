/* eslint-disable @typescript-eslint/no-explicit-any */
import { Client } from "@elastic/elasticsearch";
import { NextRequest, NextResponse } from "next/server";
const client = new Client({ node: `http://${process.env.SIS_DASHBOARD_ELASTIC_HOST || "elasticsearch"}:${process.env.SIS_DASHBOARD_ELASTIC_PORT || "9200"}` });
const index = process.env.SIS_DASHBOARD_INDEX || "sis-logs-v1";
const ignoredManagementPorts = (process.env.SIS_IGNORE_MANAGEMENT_PORTS || "8080")
  .split(",").map(Number).filter(Number.isInteger);
const commonServices: Record<number, string> = {
  20:"ftp-data",21:"ftp",22:"ssh",23:"telnet",25:"smtp",53:"dns",67:"dhcp",68:"dhcp",
  69:"tftp",80:"http",88:"kerberos",110:"pop3",123:"ntp",135:"msrpc",137:"netbios",
  138:"netbios",139:"smb",143:"imap",161:"snmp",162:"snmptrap",389:"ldap",443:"https",
  445:"smb",465:"smtps",500:"isakmp",514:"syslog",587:"smtp",636:"ldaps",993:"imaps",
  995:"pop3s",102:"iec61850",502:"modbus",2404:"iec104",3389:"rdp",5985:"winrm",5986:"winrm",
};
function enrichProtocol(source: Record<string, unknown>) {
  const current=String(source.protocol||"").toLowerCase(), text=String(source.message||source.raw_log||"").toLowerCase();
  const markers: Array<[string,string]>=[["ssh","ssh"],["modbus","modbus"],["iec-104","iec104"],["iec104","iec104"],["smb","smb"],["dns","dns"],["https","https"],["http","http"],["rdp","rdp"],["winrm","winrm"]];
  const marked=markers.find(([marker])=>text.includes(marker))?.[1];
  const ports=[Number(source.dst_port||0),Number(source.src_port||0)];
  if(!ports.some(Boolean)){const match=text.match(/:\s*(\d+)\s*(?:-|=)>[^\n]*?:\s*(\d+)/);if(match)ports.push(Number(match[2]),Number(match[1]));}
  const inferred=marked||ports.map(port=>commonServices[port]).find(Boolean);
  return {...source,transport_protocol:source.transport_protocol||current,protocol:inferred||(current==="ids_alert"?"unknown":current)};
}
const riskIntervals: Record<string, number> = { "BAJO":300, "MEDIO":120, "ALTO":60, "CRÍTICO":30 };
function throttleIds(rows: Array<Record<string, unknown>>) {
  const lastSeen = new Map<string, number>();
  return rows.filter(row => {
    const sid=String(row.signature_sid||String(row.message||row.raw_log||"").match(/\[\s*\d+\s*:\s*(\d+)\s*:\s*\d+\s*\]/)?.[1]||"unknown");
    const key=[sid,row.src_ip,row.dst_ip,row.protocol].map(value=>String(value||"").toLowerCase()).join("|");
    const timestamp=Date.parse(String(row["@timestamp"]||""))/1000;
    const interval=riskIntervals[String(row.risk_label||"BAJO").toUpperCase()]||300;
    const previous=lastSeen.get(key);
    if(previous!==undefined && previous-timestamp<interval)return false;
    lastSeen.set(key,timestamp);
    return true;
  });
}
export async function GET(request: NextRequest) {
  const p=request.nextUrl.searchParams, kind=p.get("kind")||"raw", q=p.get("q")?.trim(), protocol=p.get("protocol"), risk=p.get("risk");
  const filter:any[]=[]; if(kind==="ids") filter.push({term:{"source.keyword":"snort"}}); if(kind==="red") filter.push({bool:{must_not:[{term:{"protocol.keyword":"iec104"}}]}}); if(kind==="scada") filter.push({term:{"protocol.keyword":"iec104"}}); if(protocol) filter.push({bool:{should:[{term:{"protocol.keyword":protocol}},{match_phrase:{message:protocol}},{match_phrase:{raw_log:protocol}}],minimum_should_match:1}}); if(risk) filter.push({term:{"risk_label.keyword":risk}});
  const must:any[]=[]; if(q) must.push({simple_query_string:{query:q,fields:["message^2","raw_log","src_ip","dst_ip","mitre_msg"],default_operator:"and"}});
  const must_not:any[]=[
    {terms:{dst_port:ignoredManagementPorts}},
    {query_string:{query:'"[TEST]" OR "TESTFR" OR "localhost" OR "1000005"',fields:["message","raw_log"]}},
    {terms:{"src_ip.keyword":["127.0.0.1","::1"]}},{terms:{"dst_ip.keyword":["127.0.0.1","::1"]}},
    {bool:{filter:[{term:{"src_ip.keyword":"0.0.0.0"}},{term:{"dst_ip.keyword":"0.0.0.0"}}]}}
  ];
  try { const result=await client.search({index,size:Math.min(Number(p.get("size")||100),500),sort:[{"@timestamp":"desc"}],query:{bool:{filter,must,must_not}}} as any); const enriched=result.hits.hits.map((h:any)=>enrichProtocol({_id:h._id,...h._source})); const data=kind==="ids"?throttleIds(enriched):enriched; return NextResponse.json({data,total:typeof result.hits.total==="number"?result.hits.total:(result.hits.total as any)?.value||0}); }
  catch(e:any){ return NextResponse.json({error:e.message,data:[]},{status:500}); }
}
