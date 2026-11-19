import hashlib
import hmac
import json
import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import Request
from psycopg_pool import ConnectionPool

AUDIT_GENESIS_HASH = "0" * 64


def derive_audit_hmac_key(field_encryption_key: bytes) -> bytes:
    return hmac.digest(
        field_encryption_key,
        b"secure-biovault:audit-log-hmac:v1",
        "sha256",
    )


def get_client_ip(request: Request) -> str:
    forwarded_for = request.headers.get("x-forwarded-for")
    if forwarded_for:
        return forwarded_for.split(",")[0].strip()[:45]
    if request.client and request.client.host:
        return request.client.host[:45]
    return "unknown"


def compute_log_hash(
    *,
    hmac_key: bytes,
    prev_hash: str,
    user_id: uuid.UUID | str | None,
    action: str,
    resource_id: uuid.UUID | str | None,
    decision: str,
    reason: str | None,
    ip_address: str | None,
    timestamp: datetime,
) -> str:
    canonical_payload = {
        "prev_hash": prev_hash,
        "user_id": str(user_id) if user_id is not None else None,
        "action": action,
        "resource_id": str(resource_id) if resource_id is not None else None,
        "decision": decision,
        "reason": reason,
        "ip_address": ip_address,
        "timestamp": timestamp.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"),
    }
    encoded = json.dumps(canonical_payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hmac.new(hmac_key, encoded, hashlib.sha256).hexdigest()


def record_audit_log(
    request: Request,
    *,
    action: str,
    decision: str,
    user_id: uuid.UUID | None = None,
    resource_id: uuid.UUID | None = None,
    reason: str | None = None,
) -> None:
    ip_address = get_client_ip(request)
    ts = datetime.now(timezone.utc)
    truncated_reason = reason[:255] if reason else None
    audit_pool: ConnectionPool = request.app.state.audit_db_pool
    hmac_key: bytes = request.app.state.audit_hmac_key

    with audit_pool.connection() as audit_conn:
        with audit_conn.transaction():
            audit_conn.execute("LOCK TABLE access_logs IN EXCLUSIVE MODE")
            last_row = audit_conn.execute(
                "SELECT current_hash FROM access_logs ORDER BY log_id DESC LIMIT 1"
            ).fetchone()
            prev_hash = last_row["current_hash"] if last_row else AUDIT_GENESIS_HASH
            current_hash = compute_log_hash(
                hmac_key=hmac_key,
                prev_hash=prev_hash,
                user_id=user_id,
                action=action,
                resource_id=resource_id,
                decision=decision,
                reason=truncated_reason,
                ip_address=ip_address,
                timestamp=ts,
            )
            audit_conn.execute(
                """
                INSERT INTO access_logs (
                    user_id, action, resource_id, decision, reason, ip_address, timestamp,
                    prev_hash, current_hash
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
                """,
                (
                    user_id,
                    action,
                    resource_id,
                    decision,
                    truncated_reason,
                    ip_address,
                    ts,
                    prev_hash,
                    current_hash,
                ),
            )


def verify_audit_chain(rows: list[dict[str, Any]], hmac_key: bytes) -> dict[str, Any]:
    expected_prev_hash = AUDIT_GENESIS_HASH
    for row in rows:
        if not hmac.compare_digest(row["prev_hash"], expected_prev_hash):
            return {
                "valid": False,
                "total_logs": len(rows),
                "broken_at_log_id": row["log_id"],
                "reason": "Broken chain link: prev_hash does not match previous record (deleted or reordered row)",
            }
        expected_hash = compute_log_hash(
            hmac_key=hmac_key,
            prev_hash=row["prev_hash"],
            user_id=row["user_id"],
            action=row["action"],
            resource_id=row["resource_id"],
            decision=row["decision"],
            reason=row["reason"],
            ip_address=row["ip_address"],
            timestamp=row["timestamp"],
        )
        if not hmac.compare_digest(row["current_hash"], expected_hash):
            return {
                "valid": False,
                "total_logs": len(rows),
                "broken_at_log_id": row["log_id"],
                "reason": "Tampered record: recomputed HMAC-SHA256 does not match stored current_hash",
            }
        expected_prev_hash = row["current_hash"]

    return {
        "valid": True,
        "total_logs": len(rows),
        "broken_at_log_id": None,
        "reason": "Audit log hash chain is intact",
    }