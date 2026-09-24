from __future__ import annotations
import asyncio, json, os, traceback
from fastmcp import Client
from fastmcp.client.auth import BearerAuth
from fastapi import FastAPI
from fastapi.responses import JSONResponse
import uvicorn

ENDPOINT=os.environ["NEXUS_MCP_URL"].rstrip("/")+"/mcp"
TOKEN=os.environ["NEXUS_MCP_TOKEN"]
EXPECTED_FP=os.environ.get("EXPECTED_FP","")
EXPECTED_COUNT=int(os.environ.get("EXPECTED_COUNT","0"))
EXPECTED_TOOLS={"get_authority_status","get_recovery_state","get_state_record"}
ALLOWED_RECORD="project.state/016-npb1-minimum-production-scope-2026-09-24"

RESULT={"status":"not_run"}

def _content(result):
    if hasattr(result,"data") and result.data is not None:
        return result.data
    if hasattr(result,"structured_content") and result.structured_content:
        return result.structured_content
    if hasattr(result,"content") and result.content:
        for item in result.content:
            text=getattr(item,"text",None)
            if text:
                try:return json.loads(text)
                except Exception:return text
    return result

async def run_probe():
    out={"endpoint":ENDPOINT,"checks":{},"errors":[]}
    try:
        async with Client(ENDPOINT) as c:
            await c.list_tools()
        out["checks"]["unauthorized_rejected"]=False
    except Exception as exc:
        out["checks"]["unauthorized_rejected"]=True
        out["unauthorized_error_type"]=type(exc).__name__

    try:
        async with Client(ENDPOINT,auth=BearerAuth(TOKEN)) as c:
            tools=await c.list_tools()
            names={getattr(t,"name","") for t in tools}
            out["tool_names"]=sorted(names)
            out["checks"]["exact_three_tools"]=names==EXPECTED_TOOLS

            a=_content(await c.call_tool("get_authority_status",{}))
            out["authority"]=a
            out["checks"]["authority_validated"]=bool(a.get("consistency",{}).get("validated"))
            out["checks"]["generation_2"]=a.get("authority_registry",{}).get("generation")==2
            if EXPECTED_FP:
                out["checks"]["fingerprint_match"]=a.get("state_store",{}).get("fingerprint")==EXPECTED_FP
            if EXPECTED_COUNT:
                out["checks"]["record_count_match"]=a.get("state_store",{}).get("record_count")==EXPECTED_COUNT

            rec=_content(await c.call_tool("get_recovery_state",{}))
            out["recovery"]=rec
            out["checks"]["released_v0510"]=rec.get("framework",{}).get("released_control_version")=="0.5.10"
            out["checks"]["npb1_next_action"]="NPB-1" in str(rec.get("continuity",{}).get("exact_next_action",""))

            sr=_content(await c.call_tool("get_state_record",{"record_id":ALLOWED_RECORD}))
            out["scope_record"]={
                "record_id":sr.get("record_id"),"title":sr.get("title"),
                "revision":sr.get("revision"),"status":sr.get("status"),
                "authority":sr.get("authority")
            }
            out["checks"]["allowed_exact_record"]=sr.get("record_id")==ALLOWED_RECORD

            try:
                await c.call_tool("get_state_record",{"record_id":"project.state/does-not-exist"})
                out["checks"]["unknown_record_rejected"]=False
            except Exception as exc:
                out["checks"]["unknown_record_rejected"]=True
                out["unknown_record_error_type"]=type(exc).__name__

            try:
                await c.call_tool("apply_mutation",{})
                out["checks"]["mutation_tool_absent"]=False
            except Exception as exc:
                out["checks"]["mutation_tool_absent"]=True
                out["mutation_error_type"]=type(exc).__name__
    except Exception as exc:
        out["errors"].append({"type":type(exc).__name__,"message":str(exc),"traceback":traceback.format_exc(limit=8)})

    required=[
        "unauthorized_rejected","exact_three_tools","authority_validated","generation_2",
        "released_v0510","npb1_next_action","allowed_exact_record",
        "unknown_record_rejected","mutation_tool_absent"
    ]
    if EXPECTED_FP: required.append("fingerprint_match")
    if EXPECTED_COUNT: required.append("record_count_match")
    out["verified"]=all(out["checks"].get(k) is True for k in required) and not out["errors"]
    out["required_checks"]=required
    out["status"]="PASS" if out["verified"] else "FAIL"
    return out

app=FastAPI()

@app.on_event("startup")
async def startup():
    global RESULT
    RESULT=await run_probe()
    print("NPB1_REMOTE_MCP_PROBE="+json.dumps(RESULT,sort_keys=True),flush=True)

@app.get("/health")
def health():
    return JSONResponse(RESULT,status_code=200 if RESULT.get("verified") else 503)

@app.get("/")
def root():
    return JSONResponse({"status":RESULT.get("status"),"verified":RESULT.get("verified",False)})

if __name__=="__main__":
    uvicorn.run(app,host="0.0.0.0",port=int(os.environ.get("PORT","10000")))
