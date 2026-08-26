import { Client } from "@elastic/elasticsearch";
import { NextRequest, NextResponse } from "next/server";
const client = new Client({ node: `http://${process.env.SIS_DASHBOARD_ELASTIC_HOST || "elasticsearch"}:${process.env.SIS_DASHBOARD_ELASTIC_PORT || "9200"}` });
const index = process.env.SIS_DASHBOARD_INDEX || "sis-logs-v1";
export async function GET(request: NextRequest) {
  const p=request.nextUrl.searchParams, kind=p.get("kind")||"raw", q=p.get("q")?.trim(), protocol=p.get("protocol"), risk=p.get("risk");
  const filter:any[]=[]; if(kind==="ids") filter.push({term:{"source.keyword":"snort"}}); if(kind==="red") filter.push({bool:{must_not:[{term:{"protocol.keyword":"iec104"}}]}}); if(kind==="scada") filter.push({term:{"protocol.keyword":"iec104"}}); if(protocol) filter.push({term:{"protocol.keyword":protocol}}); if(risk) filter.push({term:{"risk_label.keyword":risk}});
  const must:any[]=[]; if(q) must.push({simple_query_string:{query:q,fields:["message^2","raw_log","src_ip","dst_ip","mitre_msg"],default_operator:"and"}});
  const must_not:any[]=[
    {query_string:{query:'"[TEST]" OR "TESTFR" OR "localhost" OR "1000005"',fields:["message","raw_log"]}},
    {terms:{"src_ip.keyword":["127.0.0.1","::1"]}},{terms:{"dst_ip.keyword":["127.0.0.1","::1"]}},
    {bool:{filter:[{term:{"src_ip.keyword":"0.0.0.0"}},{term:{"dst_ip.keyword":"0.0.0.0"}}]}}
  ];
  try { const result=await client.search({index,size:Math.min(Number(p.get("size")||100),500),sort:[{"@timestamp":"desc"}],query:{bool:{filter,must,must_not}}} as any); return NextResponse.json({data:result.hits.hits.map((h:any)=>({_id:h._id,...h._source})),total:typeof result.hits.total==="number"?result.hits.total:(result.hits.total as any)?.value||0}); }
  catch(e:any){ return NextResponse.json({error:e.message,data:[]},{status:500}); }
}
