from __future__ import annotations

import asyncio
import json
import os
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import httpx
import httpx2
from mcp import ClientSession
from mcp.client.streamable_http import streamable_http_client

URL = os.environ["MCP_URL"].rstrip("/")
TOKEN = os.environ["MCP_TOKEN"]
PORT = int(os.environ.get("PORT", "10000"))
MODE = os.environ.get("GATE_MODE", "normal")
EXPECTED_TOOLS = {"get_authority_status", "get_recovery_state", "get_state_record"}
EXPECTED_FP = "23d883309c241cd5743a4918670a7ebcc6dcac797210848f4fdcc61149e8cab4"
EXPECTED_REG_REV = "96528ecbf19cf4b3d76aed82c37e4cd6f1241db684060759200f530b687cf11c"

result: dict[str, object] = {"status": "starting"}


def unwrap(call_result):
    structured = getattr(call_result, "structuredContent", None)
    if structured is None:
        structured = getattr(call_result, "structured_content", None)
    if isinstance(structured, dict):
        if "result" in structured and isinstance(structured["result"], dict):
            return structured["result"]
        return structured
    for item in getattr(call_result, "content", []) or []:
        text = getattr(item, "text", None)
        if text:
            try:
                data = json.loads(text)
                if isinstance(data, dict):
                    return data.get("result", data)
            except Exception:
                pass
    raise RuntimeError("tool result was not structured JSON")


async def run_outage_gate():
    out: dict[str, object] = {"endpoint": URL, "mode": "outage", "checks": {}}
    async with httpx2.AsyncClient(
        headers={"Authorization": f"Bearer {TOKEN}"}
    ) as mcp_http:
        async with streamable_http_client(
            URL, http_client=mcp_http
        ) as (read_stream, write_stream):
            async with ClientSession(read_stream, write_stream) as session:
                await session.initialize()
                tools = await session.list_tools()
                names = {tool.name for tool in tools.tools}
                out["checks"]["exact_three_tools"] = names == EXPECTED_TOOLS
                failed_closed = False
                try:
                    response = await session.call_tool("get_authority_status", {})
                    failed_closed = bool(
                        getattr(
                            response,
                            "isError",
                            getattr(response, "is_error", False),
                        )
                    )
                except Exception:
                    failed_closed = True
                out["checks"]["authority_fails_closed"] = failed_closed
    out["verified"] = all(out["checks"].values())
    out["status"] = "pass" if out["verified"] else "fail"
    return out


async def run_gate():
    out: dict[str, object] = {"endpoint": URL, "checks": {}}

    async with httpx.AsyncClient(timeout=20, follow_redirects=True) as client:
        unauth = await client.post(
            URL,
            headers={"Accept": "application/json, text/event-stream"},
            json={
                "jsonrpc": "2.0",
                "id": 1,
                "method": "initialize",
                "params": {
                    "protocolVersion": "2026-07-28",
                    "capabilities": {},
                    "clientInfo": {"name": "npb1-unauthorized-probe", "version": "1"},
                },
            },
        )
        out["checks"]["unauthorized_rejected"] = unauth.status_code in (401, 403)
        out["unauthorized_status"] = unauth.status_code

    async with httpx2.AsyncClient(
        headers={"Authorization": f"Bearer {TOKEN}"}
    ) as mcp_http:
        async with streamable_http_client(
            URL, http_client=mcp_http
        ) as (read_stream, write_stream):
            async with ClientSession(read_stream, write_stream) as session:
                init = await session.initialize()
                out["protocol_version"] = str(
                    getattr(init, "protocolVersion", getattr(init, "protocol_version", ""))
                )

                tools = await session.list_tools()
                names = {tool.name for tool in tools.tools}
                out["tool_names"] = sorted(names)
                out["checks"]["exact_three_tools"] = names == EXPECTED_TOOLS

                authority = unwrap(
                    await session.call_tool("get_authority_status", {})
                )
                out["authority"] = authority
                reg = authority["authority_registry"]
                state = authority["state_store"]
                out["checks"]["authority_live"] = (
                    state["fingerprint"] == EXPECTED_FP
                    and reg["generation"] == 2
                    and reg["revision"] == EXPECTED_REG_REV
                    and reg["current_authority_mode"] == "typed_state_store"
                    and reg["activation_status"] == "ACTIVE_VERIFIED"
                    and authority["consistency"]["validated"] is True
                )

                recovery = unwrap(
                    await session.call_tool("get_recovery_state", {})
                )
                out["recovery"] = recovery
                out["checks"]["recovery_direct"] = (
                    recovery.get("evidence_basis")
                    == "direct_authenticated_state_store"
                    and recovery["authority"]["generation"] == 2
                    and recovery["authority"]["fingerprint"] == EXPECTED_FP
                    and recovery["framework"]["released_control_version"] == "0.5.10"
                )

                rec = unwrap(
                    await session.call_tool(
                        "get_state_record",
                        {
                            "record_id":
                            "project.state/016-npb1-minimum-production-scope-2026-09-24"
                        },
                    )
                )
                out["allowed_record"] = {
                    "record_id": rec.get("record_id"),
                    "revision": rec.get("revision"),
                    "title": rec.get("title"),
                }
                out["checks"]["allowed_exact_record"] = (
                    rec.get("record_id")
                    == "project.state/016-npb1-minimum-production-scope-2026-09-24"
                )

                unknown_failed = False
                try:
                    unknown = await session.call_tool(
                        "get_state_record",
                        {"record_id": "project.state/does-not-exist"},
                    )
                    unknown_failed = bool(
                        getattr(
                            unknown,
                            "isError",
                            getattr(unknown, "is_error", False),
                        )
                    )
                except Exception:
                    unknown_failed = True
                out["checks"]["unknown_fails_closed"] = unknown_failed

                disallowed_failed = False
                try:
                    disallowed = await session.call_tool(
                        "get_state_record",
                        {"record_id": "project.secret/example"},
                    )
                    disallowed_failed = bool(
                        getattr(
                            disallowed,
                            "isError",
                            getattr(disallowed, "is_error", False),
                        )
                    )
                except Exception:
                    disallowed_failed = True
                out["checks"]["disallowed_fails_closed"] = disallowed_failed

    out["verified"] = all(out["checks"].values())
    out["status"] = "pass" if out["verified"] else "fail"
    return out


def worker():
    global result
    try:
        result = asyncio.run(run_outage_gate() if MODE == "outage" else run_gate())
    except Exception as exc:
        result={"status":"error","verified":False,"error_type":type(exc).__name__,"error":str(exc)[:1000]}
    print("NPB1_REMOTE_MCP_GATE="+json.dumps(result,sort_keys=True),flush=True)


class Handler(BaseHTTPRequestHandler):
    def log_message(self,*args): return
    def do_GET(self):
        if self.path == "/health":
            body=b"ok"
            self.send_response(200); self.send_header("Content-Type","text/plain"); self.send_header("Content-Length",str(len(body))); self.end_headers(); self.wfile.write(body); return
        if self.path == "/result":
            body=json.dumps(result,sort_keys=True).encode()
            self.send_response(200); self.send_header("Content-Type","application/json"); self.send_header("Content-Length",str(len(body))); self.end_headers(); self.wfile.write(body); return
        self.send_response(404); self.end_headers()


threading.Thread(target=worker,daemon=True).start()
ThreadingHTTPServer(("0.0.0.0",PORT),Handler).serve_forever()
