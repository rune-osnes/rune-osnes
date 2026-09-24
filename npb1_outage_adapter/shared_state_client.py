from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any, Iterable

from .shared_state_service import SharedStateConflict, TestAuthorityRecord
from .state_store import StateRecord, StateStoreSnapshot, StoreMutation


class SharedStateClientError(RuntimeError):
    pass


class SharedStateAuthError(PermissionError):
    pass


class SharedProjectStateStoreClient:
    """Network client implementing the ProjectStateStore surface used by Nexus Core."""

    def __init__(self, base_url: str, bearer_token: str, *, timeout: float = 10.0) -> None:
        self.base_url = base_url.rstrip("/")
        self.bearer_token = bearer_token
        self.timeout = float(timeout)

    @property
    def store_id(self) -> str:
        return f"shared-state+{self.base_url}"

    def _request(
        self,
        method: str,
        path: str,
        *,
        payload: dict[str, Any] | None = None,
        raw: bytes | None = None,
        content_type: str | None = None,
        expect_json: bool = True,
    ) -> Any:
        if payload is not None and raw is not None:
            raise ValueError("payload and raw are mutually exclusive")
        data = raw
        headers = {
            "Authorization": f"Bearer {self.bearer_token}",
            "Accept": "application/json" if expect_json else "application/octet-stream",
        }
        if payload is not None:
            data = json.dumps(payload, ensure_ascii=False, sort_keys=True).encode("utf-8")
            headers["Content-Type"] = "application/json"
        elif raw is not None:
            headers["Content-Type"] = content_type or "application/octet-stream"
        request = urllib.request.Request(
            self.base_url + path,
            data=data,
            headers=headers,
            method=method,
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:
                body = response.read()
                if expect_json:
                    return json.loads(body.decode("utf-8")) if body else {}
                return body
        except urllib.error.HTTPError as exc:
            body = exc.read()
            try:
                detail = json.loads(body.decode("utf-8")) if body else {}
            except Exception:
                detail = {"detail": body.decode("utf-8", errors="replace")}
            message = str(detail.get("detail") or detail.get("error") or exc.reason)
            if exc.code == 401:
                raise SharedStateAuthError(message) from exc
            if exc.code == 409:
                raise SharedStateConflict(message) from exc
            if exc.code == 404 and path.startswith("/v1/records/"):
                raise KeyError(path.rsplit("/", 1)[-1]) from exc
            if exc.code == 404 and path == "/v1/test-authority":
                raise KeyError("test-authority") from exc
            raise SharedStateClientError(f"HTTP {exc.code}: {message}") from exc
        except urllib.error.URLError as exc:
            raise SharedStateClientError(str(exc.reason)) from exc

    def health(self) -> dict[str, Any]:
        return dict(self._request("GET", "/v1/health"))

    def list_namespaces(self) -> tuple[str, ...]:
        payload = self._request("GET", "/v1/namespaces")
        return tuple(str(item) for item in payload["namespaces"])

    def list_records(self, namespace: str | None = None) -> tuple[StateRecord, ...]:
        payload = self._request("GET", "/v1/records")
        records = tuple(StateRecord.from_dict(item) for item in payload["records"])
        if namespace is None:
            return records
        return tuple(record for record in records if record.namespace == namespace)

    def get_record(self, record_id: str) -> StateRecord:
        quoted = urllib.parse.quote(record_id, safe="")
        payload = self._request("GET", f"/v1/records/{quoted}")
        return StateRecord.from_dict(payload["record"])

    def metadata(self) -> dict[str, str]:
        payload = self._request("GET", "/v1/metadata")
        return {str(key): str(value) for key, value in payload["metadata"].items()}

    def snapshot(self) -> StateStoreSnapshot:
        payload = self._request("GET", "/v1/snapshot")
        records = {
            record.record_id: record
            for record in (StateRecord.from_dict(item) for item in payload["records"])
        }
        snapshot = StateStoreSnapshot(self.store_id, records, {str(k): str(v) for k, v in payload["metadata"].items()})
        # Network payload carries the server-computed fingerprint; fail closed on serialization drift.
        if snapshot.fingerprint != payload["fingerprint"]:
            raise SharedStateClientError(
                f"snapshot fingerprint mismatch: local {snapshot.fingerprint}, service {payload['fingerprint']}"
            )
        return snapshot

    def apply_mutations(self, mutations: Iterable[StoreMutation]) -> tuple[StateRecord, ...]:
        mutations = tuple(mutations)
        payload = {
            "mutations": [
                {
                    "action": item.action,
                    "expected_revision": item.expected_revision,
                    "record": item.record.to_dict(),
                }
                for item in mutations
            ]
        }
        response = self._request("POST", "/v1/mutations", payload=payload)
        return tuple(StateRecord.from_dict(item) for item in response["applied"])

    def backup_to(self, destination: Path) -> Path:
        destination = Path(destination).resolve()
        destination.parent.mkdir(parents=True, exist_ok=True)
        data = self._request("GET", "/v1/backup", expect_json=False)
        destination.write_bytes(data)
        return destination

    def restore_from_backup(self, backup: Path) -> None:
        backup = Path(backup).resolve()
        self._request(
            "PUT",
            "/v1/restore",
            raw=backup.read_bytes(),
            content_type="application/vnd.sqlite3",
        )

    def audit_events(self) -> list[dict[str, Any]]:
        payload = self._request("GET", "/v1/audit")
        return list(payload["events"])

    def authority_get(self) -> TestAuthorityRecord:
        payload = self._request("GET", "/v1/test-authority")
        return TestAuthorityRecord.from_dict(payload["authority"])

    def authority_initialize(self, record: TestAuthorityRecord) -> TestAuthorityRecord:
        payload = self._request(
            "POST",
            "/v1/test-authority/initialize",
            payload={"authority": record.to_dict()},
        )
        return TestAuthorityRecord.from_dict(payload["authority"])

    def authority_cas(
        self,
        *,
        expected_generation: int,
        expected_revision: str,
        replacement: TestAuthorityRecord,
    ) -> TestAuthorityRecord:
        payload = self._request(
            "POST",
            "/v1/test-authority/cas",
            payload={
                "expected_generation": expected_generation,
                "expected_revision": expected_revision,
                "replacement": replacement.to_dict(),
            },
        )
        return TestAuthorityRecord.from_dict(payload["authority"])
