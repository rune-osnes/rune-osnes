from __future__ import annotations

import json
import os
import secrets
import uuid
from datetime import datetime, timezone
from typing import Any

import psycopg
from mcp.server.mcpserver import MCPServer
from mcp.server.transport_security import TransportSecuritySettings
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse

SERVICE_VERSION = "0.20.1"
ROUTER_ROOT = "modernization.router/bootstrap"
WRITE_ENABLED = os.getenv("ROUTER_WRITE_ENABLED", "false").lower() == "true"
DATABASE_URL = os.getenv("DATABASE_URL", "")
ROUTER_BEARER_TOKEN = os.getenv("ROUTER_BEARER_TOKEN", "")
CONFIG_REVISION = os.getenv("ROUTER_CONFIG_REVISION", "nmr-production-2026-09-24-v1")

COMMAND_BINDINGS: dict[str, dict[str, str]] = {
    "Consolidate Project": {
        "framework_id": "project_consolidator",
        "discovery_root": "project_consolidator.framework/bootstrap",
    },
    "Update Nexus": {
        "framework_id": "nexus",
        "discovery_root": "nexus.framework/bootstrap",
    },
}
ALLOWED_RECEIPT_STATUSES = {"completed", "blocked", "awaiting_approval", "route_next", "failed"}

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS modernization_runs (
    run_id UUID PRIMARY KEY,
    project_ref TEXT NOT NULL,
    command TEXT NOT NULL,
    status TEXT NOT NULL,
    current_stage TEXT NOT NULL,
    context_fingerprint TEXT,
    observed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL,
    paused_reason TEXT,
    route_history JSONB NOT NULL DEFAULT '[]'::jsonb,
    framework_receipts JSONB NOT NULL DEFAULT '[]'::jsonb
);
CREATE INDEX IF NOT EXISTS modernization_runs_updated_idx
    ON modernization_runs(updated_at DESC);
"""


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def db_connection() -> psycopg.Connection[Any]:
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL is not configured")
    return psycopg.connect(DATABASE_URL, autocommit=True)


def ensure_schema() -> None:
    with db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(SCHEMA_SQL)


def row_to_dict(row: tuple[Any, ...]) -> dict[str, Any]:
    return {
        "run_id": str(row[0]),
        "project_ref": row[1],
        "command": row[2],
        "status": row[3],
        "current_stage": row[4],
        "context_fingerprint": row[5],
        "observed_at": row[6].isoformat() if row[6] else None,
        "created_at": row[7].isoformat(),
        "updated_at": row[8].isoformat(),
        "paused_reason": row[9],
        "route_history": row[10] or [],
        "framework_receipts": row[11] or [],
    }


def load_run(run_id: str) -> dict[str, Any]:
    try:
        parsed = uuid.UUID(run_id)
    except ValueError as exc:
        raise ValueError("run_id must be a UUID") from exc
    with db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT run_id, project_ref, command, status, current_stage,
                       context_fingerprint, observed_at, created_at, updated_at,
                       paused_reason, route_history, framework_receipts
                FROM modernization_runs WHERE run_id = %s
                """,
                (parsed,),
            )
            row = cur.fetchone()
    if row is None:
        raise ValueError("run_not_found")
    return row_to_dict(row)


def expected_framework(run: dict[str, Any]) -> str:
    history = run["route_history"]
    if history:
        last = history[-1]
        if last.get("requested_next_command") in COMMAND_BINDINGS:
            return COMMAND_BINDINGS[last["requested_next_command"]]["framework_id"]
    return COMMAND_BINDINGS[run["command"]]["framework_id"]


mcp = MCPServer(
    "Neutral Modernization Router",
    version=SERVICE_VERSION,
    instructions=(
        "Framework-neutral orchestration control plane. It owns only command bindings and "
        "neutral run/checkpoint/receipt-reference state. It never owns target Project truth, "
        "Nexus release/adoption/migration semantics, or Project Consolidator procedure state."
    ),
)


@mcp.custom_route("/health", methods=["GET"])
async def health(_: Request) -> JSONResponse:
    db_status = "missing"
    if DATABASE_URL:
        try:
            ensure_schema()
            db_status = "ok"
        except Exception:
            db_status = "error"
    status = "ok" if ROUTER_BEARER_TOKEN and (not WRITE_ENABLED or db_status == "ok") else "degraded"
    return JSONResponse(
        {
            "status": status,
            "service": "neutral-modernization-router",
            "version": SERVICE_VERSION,
            "router_root": ROUTER_ROOT,
            "config_revision": CONFIG_REVISION,
            "database": db_status,
            "authentication_configured": bool(ROUTER_BEARER_TOKEN),
            "write_enabled": WRITE_ENABLED,
        },
        status_code=200 if status == "ok" else 503,
    )


@mcp.custom_route("/", methods=["GET"])
async def root(_: Request) -> PlainTextResponse:
    return PlainTextResponse("Neutral Modernization Router MCP service. Use /mcp or /health.\n")


@mcp.tool()
def router_status() -> dict[str, Any]:
    """Read neutral router identity, bindings, ownership boundary, and persistence status."""
    db_status = "missing"
    if DATABASE_URL:
        try:
            ensure_schema()
            db_status = "ok"
        except Exception:
            db_status = "error"
    return {
        "router_root": ROUTER_ROOT,
        "service_version": SERVICE_VERSION,
        "config_revision": CONFIG_REVISION,
        "owner": "neutral_router",
        "owned_state": [
            "stable_command_bindings",
            "orchestration_run_control_state",
            "pause_resume_checkpoint_state",
            "opaque_framework_receipt_references",
            "router_audit_timestamps",
        ],
        "forbidden_state": [
            "target_project_canonical_truth",
            "target_project_authority_registry",
            "nexus_release_or_migration_semantics",
            "project_consolidator_procedure_or_release_semantics",
            "framework_authentication_secrets",
        ],
        "command_bindings": COMMAND_BINDINGS,
        "database": db_status,
        "write_enabled": WRITE_ENABLED,
    }


@mcp.tool()
def resolve_command(command: str) -> dict[str, Any]:
    """Resolve a public command to its framework discovery root without choosing a release."""
    binding = COMMAND_BINDINGS.get(command)
    if binding is None:
        return {"resolution_status": "unsupported_command", "supported_commands": sorted(COMMAND_BINDINGS)}
    return {
        "resolution_status": "framework_discovery_required",
        "command": command,
        "framework_id": binding["framework_id"],
        "discovery_root": binding["discovery_root"],
        "release_selection_owner": binding["framework_id"],
        "router_selects_release": False,
    }


@mcp.tool()
def create_modernization_run(
    project_ref: str,
    command: str,
    observed_at: str | None = None,
    context_fingerprint: str | None = None,
) -> dict[str, Any]:
    """Create router-owned orchestration state; never creates framework or Project authority."""
    if not WRITE_ENABLED:
        return {"status": "blocked", "blocker": "router_writes_disabled"}
    if command not in COMMAND_BINDINGS:
        raise ValueError("unsupported command")
    if not project_ref.strip():
        raise ValueError("project_ref is required")
    ensure_schema()
    run_id = uuid.uuid4()
    now = utc_now()
    observed = datetime.fromisoformat(observed_at) if observed_at else now
    initial_route = [{
        "command": command,
        "framework_id": COMMAND_BINDINGS[command]["framework_id"],
        "discovery_root": COMMAND_BINDINGS[command]["discovery_root"],
        "requested_next_command": None,
        "at": now.isoformat(),
    }]
    with db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                INSERT INTO modernization_runs(
                    run_id, project_ref, command, status, current_stage,
                    context_fingerprint, observed_at, created_at, updated_at,
                    route_history, framework_receipts
                ) VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s::jsonb,%s::jsonb)
                """,
                (
                    run_id, project_ref.strip(), command, "planned", "framework_discovery",
                    context_fingerprint, observed, now, now, json.dumps(initial_route), "[]",
                ),
            )
    return load_run(str(run_id))


@mcp.tool()
def get_modernization_run(run_id: str) -> dict[str, Any]:
    """Read router-owned orchestration state for one run."""
    ensure_schema()
    return load_run(run_id)


@mcp.tool()
def record_framework_receipt(
    run_id: str,
    framework_id: str,
    status: str,
    receipt_ref: str,
    receipt_fingerprint: str | None = None,
    requested_next_command: str | None = None,
) -> dict[str, Any]:
    """Record an opaque framework receipt and advance only neutral orchestration state."""
    if not WRITE_ENABLED:
        return {"status": "blocked", "blocker": "router_writes_disabled"}
    if status not in ALLOWED_RECEIPT_STATUSES:
        raise ValueError("unsupported receipt status")
    if requested_next_command is not None and requested_next_command not in COMMAND_BINDINGS:
        raise ValueError("unsupported requested_next_command")
    run = load_run(run_id)
    expected = expected_framework(run)
    if framework_id != expected:
        raise ValueError(f"framework_route_mismatch: expected {expected}")
    if not receipt_ref.strip():
        raise ValueError("receipt_ref is required")
    receipt = {
        "framework_id": framework_id,
        "status": status,
        "receipt_ref": receipt_ref.strip(),
        "receipt_fingerprint": receipt_fingerprint,
        "requested_next_command": requested_next_command,
        "recorded_at": utc_now().isoformat(),
    }
    receipts = list(run["framework_receipts"])
    if receipt_fingerprint and any(item.get("receipt_fingerprint") == receipt_fingerprint for item in receipts):
        return run
    receipts.append(receipt)
    route_history = list(run["route_history"])
    run_status, stage = "running", "framework_execution"
    if status == "awaiting_approval":
        run_status, stage = "awaiting_approval", "approval_boundary"
    elif status == "blocked":
        run_status, stage = "blocked", "framework_blocked"
    elif status == "failed":
        run_status, stage = "failed", "framework_failed"
    elif status == "route_next" and requested_next_command:
        binding = COMMAND_BINDINGS[requested_next_command]
        route_history.append({
            "command": requested_next_command,
            "framework_id": binding["framework_id"],
            "discovery_root": binding["discovery_root"],
            "requested_next_command": requested_next_command,
            "at": utc_now().isoformat(),
        })
        run_status, stage = "running", "framework_discovery"
    elif status == "completed":
        run_status, stage = "complete", "complete"
    now = utc_now()
    with db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                """
                UPDATE modernization_runs
                   SET status=%s, current_stage=%s, updated_at=%s,
                       paused_reason=NULL, route_history=%s::jsonb,
                       framework_receipts=%s::jsonb
                 WHERE run_id=%s
                """,
                (
                    run_status, stage, now, json.dumps(route_history),
                    json.dumps(receipts), uuid.UUID(run_id),
                ),
            )
    return load_run(run_id)


@mcp.tool()
def pause_modernization_run(run_id: str, reason: str) -> dict[str, Any]:
    """Pause neutral orchestration state without mutating framework or Project authority."""
    if not WRITE_ENABLED:
        return {"status": "blocked", "blocker": "router_writes_disabled"}
    run = load_run(run_id)
    if run["status"] in {"complete", "failed"}:
        raise ValueError("terminal_run_cannot_be_paused")
    now = utc_now()
    with db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE modernization_runs SET status='paused', current_stage='paused', paused_reason=%s, updated_at=%s WHERE run_id=%s",
                (reason.strip() or "operator_pause", now, uuid.UUID(run_id)),
            )
    return load_run(run_id)


@mcp.tool()
def resume_modernization_run(run_id: str) -> dict[str, Any]:
    """Resume a paused run; owning frameworks must revalidate their own authority before action."""
    if not WRITE_ENABLED:
        return {"status": "blocked", "blocker": "router_writes_disabled"}
    run = load_run(run_id)
    if run["status"] != "paused":
        raise ValueError("run_is_not_paused")
    now = utc_now()
    with db_connection() as conn:
        with conn.cursor() as cur:
            cur.execute(
                "UPDATE modernization_runs SET status='running', current_stage='framework_discovery', paused_reason=NULL, updated_at=%s WHERE run_id=%s",
                (now, uuid.UUID(run_id)),
            )
    return load_run(run_id)


class BearerAuthASGI:
    """Protect MCP traffic while leaving liveness routes available to Railway."""

    def __init__(self, app: Any) -> None:
        self.app = app

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        if scope.get("type") != "http" or scope.get("path") in {"/health", "/"}:
            await self.app(scope, receive, send)
            return
        if not ROUTER_BEARER_TOKEN:
            response = PlainTextResponse("Router authentication is not configured", status_code=503)
            await response(scope, receive, send)
            return
        headers = {k.decode("latin1").lower(): v.decode("latin1") for k, v in scope.get("headers", [])}
        expected = f"Bearer {ROUTER_BEARER_TOKEN}"
        if not secrets.compare_digest(headers.get("authorization", ""), expected):
            response = PlainTextResponse("Unauthorized", status_code=401, headers={"WWW-Authenticate": "Bearer"})
            await response(scope, receive, send)
            return
        await self.app(scope, receive, send)


security = TransportSecuritySettings(enable_dns_rebinding_protection=False)
_mcp_app = mcp.streamable_http_app(
    json_response=True,
    stateless_http=True,
    transport_security=security,
)
app = BearerAuthASGI(_mcp_app)
