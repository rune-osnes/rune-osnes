from __future__ import annotations

import hmac
import json
import logging
import os
import re
import time
from dataclasses import asdict, is_dataclass
from enum import Enum
from typing import Any, Iterable

from fastmcp import FastMCP
from fastmcp.server.auth import AccessToken, TokenVerifier
from fastmcp.server.auth.providers.github import GitHubProvider
from fastmcp.server.dependencies import get_access_token

from starlette.responses import PlainTextResponse

from nexus_core.shared_state_client import SharedProjectStateStoreClient

ADAPTER_NAME = "nexus-state-mcp-adapter"
ADAPTER_VERSION = "0.1.0"
EVIDENCE_BASIS = "direct_authenticated_state_store"

TOOL_NAMES = (
    "get_authority_status",
    "get_recovery_state",
    "get_state_record",
)

DEFAULT_ALLOWED_NAMESPACES = (
    "project.profile",
    "project.state",
    "project.constraints",
    "project.decisions",
    "project.continuity",
    "project.governance",
    "project.assets",
    "project.evidence",
)

RECORD_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:/-]{0,255}$")
FRAMEWORK_VERSION_RE = re.compile(r"Nexus Bridge\s+v(\d+\.\d+\.\d+)", re.I)
TIMEZONE_RE = re.compile(r'(?:timezone|Timezone)\s*[:=]\s*"?([A-Za-z_]+/[A-Za-z_]+)"?')
NAME_RE = re.compile(r"(?:\*\*)?Name:(?:\*\*)?\s*(.+)")
HOST_PROJECT_RE = re.compile(r"(?:\*\*)?Host ChatGPT Project:(?:\*\*)?\s*(.+)")

logger = logging.getLogger(ADAPTER_NAME)


class AdapterError(RuntimeError):
    """Base fail-closed adapter error."""


class AuthorityValidationError(AdapterError):
    """Direct State Store authority could not be validated."""


class RecoveryStateIncomplete(AdapterError):
    """Required recovery fields were not available from direct State Store records."""


class RecordAccessError(AdapterError):
    """Exact record access failed or the namespace is not allowed."""


class StaticTokenVerifier(TokenVerifier):
    """Prototype-only high-entropy bearer-token verifier."""

    def __init__(self, expected_token: str) -> None:
        if not expected_token:
            raise RuntimeError("NEXUS_MCP_BOOTSTRAP_TOKEN is required in bootstrap auth mode")
        super().__init__(required_scopes=["nexus:read"])
        self._expected_token = expected_token

    async def verify_token(self, token: str) -> AccessToken | None:
        if not hmac.compare_digest(token, self._expected_token):
            return None
        return AccessToken(
            token=token,
            client_id="nexus-bootstrap-client",
            scopes=["nexus:read"],
            expires_at=None,
            claims={"sub": "nexus-bootstrap-client", "auth_method": "bootstrap"},
        )


def _enum_value(value: Any) -> Any:
    return value.value if isinstance(value, Enum) else value


def _get(obj: Any, name: str, default: Any = None) -> Any:
    if isinstance(obj, dict):
        return obj.get(name, default)
    return getattr(obj, name, default)


def _record_id(record: Any) -> str:
    return str(_get(record, "record_id", ""))


def _record_namespace(record: Any) -> str:
    return str(_get(record, "namespace", ""))


def _record_title(record: Any) -> str:
    return str(_get(record, "title", ""))


def _record_content(record: Any) -> str:
    return str(_get(record, "content", ""))


def _record_revision(record: Any) -> str | None:
    value = _get(record, "revision")
    return None if value is None else str(value)


def _record_public_dict(record: Any) -> dict[str, Any]:
    attrs = _get(record, "attributes", {})
    if is_dataclass(attrs):
        attrs = asdict(attrs)
    if not isinstance(attrs, dict):
        attrs = {}

    return {
        "record_id": _record_id(record),
        "namespace": _record_namespace(record),
        "title": _record_title(record),
        "content": _record_content(record),
        "kind": _enum_value(_get(record, "kind")),
        "scope": _enum_value(_get(record, "scope")),
        "status": _enum_value(_get(record, "status")),
        "authority": _enum_value(_get(record, "authority")),
        "revision": _record_revision(record),
        "attributes": attrs,
        "evidence_basis": EVIDENCE_BASIS,
    }


def _required_env(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise RuntimeError(f"{name} is required")
    return value


def _normalized_url(value: str | None) -> str:
    return (value or "").rstrip("/")


def _state_client() -> SharedProjectStateStoreClient:
    locator = _required_env("NEXUS_STATE_SERVICE_LOCATOR")
    if not locator.startswith("https://") and not locator.startswith("http://"):
        raise RuntimeError("NEXUS_STATE_SERVICE_LOCATOR must be an HTTP(S) URL")
    token = _required_env("NEXUS_STATE_SERVICE_TOKEN")
    timeout = float(os.environ.get("NEXUS_STATE_SERVICE_TIMEOUT", "20"))
    return SharedProjectStateStoreClient(locator.rstrip("/"), token, timeout=timeout)


def _allowed_namespaces() -> frozenset[str]:
    configured = os.environ.get("NEXUS_MCP_ALLOWED_NAMESPACES", "").strip()
    if not configured:
        return frozenset(DEFAULT_ALLOWED_NAMESPACES)
    values = {item.strip() for item in configured.split(",") if item.strip()}
    if not values:
        raise RuntimeError("NEXUS_MCP_ALLOWED_NAMESPACES resolved to an empty set")
    return frozenset(values)


def _all_records(client: Any) -> tuple[Any, ...]:
    records = tuple(client.list_records())
    if not records:
        raise RecoveryStateIncomplete("State Store returned no Project records")
    return records


def _first_record(
    records: Iterable[Any],
    *,
    namespace: str | None = None,
    title_exact: Iterable[str] = (),
    title_contains: Iterable[str] = (),
    content_contains: Iterable[str] = (),
) -> Any | None:
    exact = {value.casefold() for value in title_exact}
    contains = tuple(value.casefold() for value in title_contains)
    content_terms = tuple(value.casefold() for value in content_contains)

    ranked: list[tuple[int, Any]] = []
    for record in records:
        if namespace and _record_namespace(record) != namespace:
            continue
        title = _record_title(record)
        content = _record_content(record)
        title_cf = title.casefold()
        content_cf = content.casefold()

        score = 0
        if exact and title_cf in exact:
            score += 100
        if contains and any(term in title_cf for term in contains):
            score += 40
        if content_terms and any(term in content_cf for term in content_terms):
            score += 10
        if score:
            ranked.append((score, record))

    if not ranked:
        return None
    ranked.sort(key=lambda item: (-item[0], _record_id(item[1])))
    return ranked[0][1]


def _markdown_value(pattern: re.Pattern[str], text: str) -> str | None:
    match = pattern.search(text)
    if not match:
        return None
    return match.group(1).strip().strip(chr(96)).strip()


def _clean_markdown_line(text: str) -> str:
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        line = line.strip("*").strip()
        if line:
            return line
    return ""


def _completed_milestone_from_text(text: str) -> str | None:
    for raw in text.splitlines():
        line = raw.strip().strip("*").strip()
        if "Prototype" in line and ("COMPLETE" in line.upper() or "PASS_" in line.upper()):
            return line
    return None


def compute_authority_status(client: Any) -> dict[str, Any]:
    """Validate live typed State Store authority against the canonical Authority Registry record."""
    try:
        health = client.health()
        registry_record = client.get_record("project.governance/native-authority-registry")
    except Exception as exc:
        raise AuthorityValidationError(
            f"Direct authenticated State Store authority read failed: {type(exc).__name__}"
        ) from exc

    health_fp = str(health.get("state_store_fingerprint") or "")
    health_locator = str(health.get("stable_locator") or "")
    registry_revision = _record_revision(registry_record)
    registry_authority = _enum_value(_get(registry_record, "authority"))
    registry_status = _enum_value(_get(registry_record, "status"))

    try:
        registry = json.loads(_record_content(registry_record))
    except Exception as exc:
        raise AuthorityValidationError("Authority Registry content is not valid JSON") from exc

    generation = registry.get("generation")
    mode = registry.get("authority_mode")
    activation_status = registry.get("activation_status")
    registry_locator = str(registry.get("backend_stable_locator") or "")

    missing = [
        name
        for name, value in (
            ("health.state_store_fingerprint", health_fp),
            ("health.stable_locator", health_locator),
            ("registry.generation", generation),
            ("registry.authority_mode", mode),
            ("registry.activation_status", activation_status),
            ("registry.backend_stable_locator", registry_locator),
            ("registry.revision", registry_revision),
        )
        if value in (None, "")
    ]
    if missing:
        raise AuthorityValidationError(
            "Direct State Store authority response is incomplete: " + ", ".join(missing)
        )

    issues: list[str] = []
    if str(mode) != "typed_state_store":
        issues.append("authority_mode_not_typed_state_store")
    if str(activation_status) != "ACTIVE_VERIFIED":
        issues.append("activation_status_not_active_verified")
    if _normalized_url(health_locator) != _normalized_url(registry_locator):
        issues.append("stable_locator_mismatch")
    if str(registry_authority) != "canonical":
        issues.append("authority_registry_not_canonical")
    if str(registry_status) != "verified":
        issues.append("authority_registry_not_verified")

    if issues:
        raise AuthorityValidationError(
            "Direct State Store authority validation failed: " + ", ".join(issues)
        )

    timezone = (
        health.get("project_timezone")
        or health.get("timezone")
        or os.environ.get("NEXUS_PROJECT_TIMEZONE")
    )

    return {
        "adapter": {
            "name": ADAPTER_NAME,
            "version": ADAPTER_VERSION,
            "status": "ready",
        },
        "state_store": {
            "authenticated": True,
            "record_count": health.get("record_count"),
            "fingerprint": health_fp,
            "stable_locator": health_locator,
            "timezone": timezone,
        },
        "authority_registry": {
            "record_id": _record_id(registry_record),
            "generation": generation,
            "revision": str(registry_revision),
            "current_authority_mode": str(mode),
            "activation_status": str(activation_status),
            "backend_stable_locator": registry_locator,
        },
        "consistency": {
            "validated": True,
            "issues": [],
        },
        "evidence_basis": EVIDENCE_BASIS,
    }

def compute_recovery_state(client: Any) -> dict[str, Any]:
    authority = compute_authority_status(client)
    records = _all_records(client)

    project_record = _first_record(
        records,
        namespace="project.profile",
        title_exact=("Project",),
        content_contains=("Host ChatGPT Project", "Name:"),
    )
    timezone_record = _first_record(
        records,
        namespace="project.constraints",
        title_exact=("Temporal Convention",),
        title_contains=("temporal", "timezone"),
        content_contains=("Europe/Oslo", "timezone"),
    )
    framework_record = _first_record(
        records,
        namespace="project.profile",
        title_exact=("Project Instructions",),
        title_contains=("project instructions",),
        content_contains=("Current toolkit baseline", "v0."),
    )
    phase_record = _first_record(
        records,
        namespace="project.state",
        title_exact=("Current Phase",),
        title_contains=("current phase",),
        content_contains=("Prototype",),
    )
    current_status_record = _first_record(
        records,
        namespace="project.state",
        title_exact=("Current Status",),
        title_contains=("current status",),
        content_contains=("Released control baseline", "Prototype 0.17", "Prototype 0.18"),
    )
    next_action_record = _first_record(
        records,
        namespace="project.state",
        title_exact=("Exact Next Action",),
        title_contains=("next action",),
    )
    resume_record = _first_record(
        records,
        namespace="project.continuity",
        title_exact=("Exact Resume Point",),
        title_contains=("resume",),
        content_contains=("Prototype 0.18", "Exact next action"),
    )
    state_hold_record = _first_record(
        records,
        namespace="project.state",
        title_exact=("Hold Points",),
        title_contains=("hold",),
    )
    continuity_hold_record = _first_record(
        records,
        namespace="project.continuity",
        title_exact=("Hold Points",),
        title_contains=("hold",),
    )

    selected = [
        record
        for record in (
            project_record,
            timezone_record,
            framework_record,
            phase_record,
            current_status_record,
            next_action_record,
            resume_record,
            state_hold_record,
            continuity_hold_record,
        )
        if record is not None
    ]

    project_name = _markdown_value(NAME_RE, _record_content(project_record)) if project_record else None
    host_project = (
        _markdown_value(HOST_PROJECT_RE, _record_content(project_record)) if project_record else None
    )

    timezone = None
    if timezone_record is not None:
        timezone = _markdown_value(TIMEZONE_RE, _record_content(timezone_record))
    timezone = timezone or authority["state_store"].get("timezone")

    framework_text = "\n".join(
        _record_content(record)
        for record in (framework_record, current_status_record)
        if record is not None
    )
    framework_match = FRAMEWORK_VERSION_RE.search(framework_text)
    framework_version = framework_match.group(1) if framework_match else None

    current_phase = _clean_markdown_line(_record_content(phase_record)) if phase_record else None

    exact_next_action = None
    if next_action_record is not None:
        exact_next_action = _record_content(next_action_record).strip()
    elif resume_record is not None:
        exact_next_action = _record_content(resume_record).strip()

    continuity_text = "\n".join(
        _record_content(record)
        for record in (current_status_record, phase_record, resume_record)
        if record is not None
    )
    completed_milestone = _completed_milestone_from_text(continuity_text)

    hold_record = state_hold_record or continuity_hold_record
    hold_point = _record_content(hold_record).strip() if hold_record else None

    required = {
        "project_identity": project_name,
        "timezone": timezone,
        "framework_version": framework_version,
        "current_phase": current_phase,
        "exact_next_action": exact_next_action,
    }
    missing = [name for name, value in required.items() if not value]
    if missing:
        raise RecoveryStateIncomplete(
            "Direct State Store recovery is incomplete: " + ", ".join(missing)
        )

    seen_record_ids: set[str] = set()
    source_records: list[dict[str, Any]] = []
    for record in selected:
        record_id = _record_id(record)
        if not record_id or record_id in seen_record_ids:
            continue
        seen_record_ids.add(record_id)
        source_records.append(
            {
                "record_id": record_id,
                "namespace": _record_namespace(record),
                "title": _record_title(record),
                "revision": _record_revision(record),
            }
        )

    return {
        "project": {
            "name": project_name,
            "host_chatgpt_project": host_project,
            "timezone": timezone,
        },
        "framework": {
            "released_control_version": framework_version,
        },
        "authority": {
            "backend": "typed_state_store",
            "mode": authority["authority_registry"]["current_authority_mode"],
            "generation": authority["authority_registry"]["generation"],
            "fingerprint": authority["state_store"]["fingerprint"],
            "registry_revision": authority["authority_registry"]["revision"],
            "stable_locator": authority["state_store"]["stable_locator"],
        },
        "continuity": {
            "current_phase": current_phase,
            "most_recent_completed_milestone": completed_milestone,
            "exact_next_action": exact_next_action,
            "hold_point": hold_point,
        },
        "source_records": source_records,
        "evidence_basis": EVIDENCE_BASIS,
    }


def compute_state_record(client: Any, record_id: str) -> dict[str, Any]:
    record_id = record_id.strip()
    if not RECORD_ID_RE.fullmatch(record_id):
        raise RecordAccessError("record_id is invalid")

    matches = [record for record in _all_records(client) if _record_id(record) == record_id]
    if len(matches) != 1:
        raise RecordAccessError("record not found or not allowed")

    record = matches[0]
    if _record_namespace(record) not in _allowed_namespaces():
        raise RecordAccessError("record not found or not allowed")

    return _record_public_dict(record)


def _build_auth() -> Any:
    mode = os.environ.get("NEXUS_MCP_AUTH_MODE", "bootstrap").strip().lower()

    if mode == "bootstrap":
        return StaticTokenVerifier(_required_env("NEXUS_MCP_BOOTSTRAP_TOKEN"))

    if mode == "github":
        return GitHubProvider(
            client_id=_required_env("NEXUS_MCP_GITHUB_CLIENT_ID"),
            client_secret=_required_env("NEXUS_MCP_GITHUB_CLIENT_SECRET"),
            base_url=_required_env("NEXUS_MCP_PUBLIC_BASE_URL"),
        )

    raise RuntimeError("NEXUS_MCP_AUTH_MODE must be 'bootstrap' or 'github'")


def _assert_operator_identity() -> None:
    mode = os.environ.get("NEXUS_MCP_AUTH_MODE", "bootstrap").strip().lower()
    if mode != "github":
        return

    token = get_access_token()
    if token is None:
        raise PermissionError("authenticated operator identity is required")

    allowed = {
        item.strip().casefold()
        for item in os.environ.get("NEXUS_MCP_ALLOWED_GITHUB_USERS", "").split(",")
        if item.strip()
    }
    if not allowed:
        raise PermissionError("NEXUS_MCP_ALLOWED_GITHUB_USERS must be configured")

    claims = token.claims or {}
    login = str(
        claims.get("login")
        or claims.get("preferred_username")
        or claims.get("username")
        or ""
    ).casefold()

    if not login or login not in allowed:
        raise PermissionError("authenticated GitHub user is not allowed")


def _tool_call(name: str, fn: Any) -> Any:
    started = time.monotonic()
    try:
        _assert_operator_identity()
        result = fn()
        logger.info(
            "tool_call tool=%s status=success latency_ms=%d",
            name,
            int((time.monotonic() - started) * 1000),
        )
        return result
    except Exception as exc:
        logger.warning(
            "tool_call tool=%s status=failure category=%s latency_ms=%d",
            name,
            type(exc).__name__,
            int((time.monotonic() - started) * 1000),
        )
        raise


def create_server() -> FastMCP:
    mcp = FastMCP(name=ADAPTER_NAME, auth=_build_auth())

    @mcp.custom_route("/health", methods=["GET"], include_in_schema=False)
    async def health_check(_request: Any) -> PlainTextResponse:
        """Process liveness only; does not expose or validate Project authority."""
        return PlainTextResponse("ok")

    @mcp.tool()
    def get_authority_status() -> dict[str, Any]:
        """Validate and return current authoritative Nexus State Store status."""
        return _tool_call(
            "get_authority_status",
            lambda: compute_authority_status(_state_client()),
        )

    @mcp.tool()
    def get_recovery_state() -> dict[str, Any]:
        """Return the minimum direct-authority Project state needed to resume safely."""
        return _tool_call(
            "get_recovery_state",
            lambda: compute_recovery_state(_state_client()),
        )

    @mcp.tool()
    def get_state_record(record_id: str) -> dict[str, Any]:
        """Return one exact allowed typed State Store record by record_id."""
        return _tool_call(
            "get_state_record",
            lambda: compute_state_record(_state_client(), record_id),
        )

    return mcp


def main() -> None:
    logging.basicConfig(
        level=os.environ.get("LOG_LEVEL", "INFO").upper(),
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    port = int(os.environ.get("PORT", "8000"))
    server = create_server()
    server.run(transport="http", host="0.0.0.0", port=port)


if __name__ == "__main__":
    main()
