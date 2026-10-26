"""
middleware/interceptor.py — V3.0 Intelligence Maestro Zero-Trust DLP Middleware

Enterprise Security Capabilities:
  1. Automated Threat IP Quarantine (Blacklisting)
  2. Sliding-Window Rate Limiting & Byte-Size Anomaly Detection
  3. Four-Eyes Principle Gate: Quarantines exports > 20 records for Manager Approval
  4. DPDP Act (2023) Consent Enforcement & Non-Consenting Record Suppression
  5. Indian Banking PII Engine (PAN, Verhoeff Aadhaar, UPI, Mobile, Email, CIF, DOB)
  6. Role-Based Dynamic Masking (RBAC via X-User-Role)
  7. Covert Zero-Width Forensic Steganography: Invisibly stamps employee provenance
  8. Real-Time Security Telemetry & JSON Audit Stream
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from core.anomaly import (
    RateLimiter,
    check_bulk_export,
    check_payload_size,
    telemetry,
)
from core.approval import BULK_APPROVAL_THRESHOLD, approval_manager
from core.consent import filter_by_dpdp_consent
from core.tokenizer import MaskingMode, tokenize_payload
from core.watermark import WatermarkPayload, inject_covert_watermark

logger = logging.getLogger("datafort.middleware")

PROTECTED_PREFIXES: tuple[str, ...] = ("/api/v1/",)


def _is_protected_route(path: str) -> bool:
    return any(path.startswith(prefix) for prefix in PROTECTED_PREFIXES)


def _resolve_masking_mode(role_header: str | None) -> MaskingMode:
    if not role_header:
        return MaskingMode.FULL_TOKEN
    role = role_header.strip().lower()
    if role in ("investigator", "fraud_officer", "admin"):
        return MaskingMode.UNMASKED
    elif role in ("manager", "supervisor", "auditor"):
        return MaskingMode.PARTIAL_MASK
    return MaskingMode.FULL_TOKEN


def _make_log_entry(
    *,
    level: str,
    event: str,
    client_ip: str,
    route: str,
    request_id: str,
    action: str,
    role: str = "staff",
    emp_id: str = "EMP_ANON",
    extra: dict[str, Any] | None = None,
) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "level": level,
        "event": event,
        "client_ip": client_ip,
        "route": route,
        "request_id": request_id,
        "role": role,
        "emp_id": emp_id,
        "action": action,
    }
    if extra:
        entry.update(extra)
    return entry


class DLPInterceptorMiddleware(BaseHTTPMiddleware):
    def __init__(self, app: Any) -> None:
        super().__init__(app)
        self._rate_limiter = RateLimiter()

    async def dispatch(
        self, request: Request, call_next: Callable[..., Any]
    ) -> Response:
        request_id = str(uuid.uuid4())
        client_ip = request.client.host if request.client else "unknown"
        route = request.url.path

        # Bypass monitoring and dashboard endpoints from DLP interception
        if route in (
            "/api/v1/stats",
            "/api/v1/audit-logs",
            "/api/v1/approvals",
            "/api/v1/approvals/action",
            "/api/v1/decode-leak",
            "/dashboard",
            "/health",
            "/ready",
            "/viewer",
        ):
            return await call_next(request)

        if not _is_protected_route(route):
            return await call_next(request)

        telemetry.record_request()
        user_role_str = request.headers.get("X-User-Role", "staff")
        emp_id = request.headers.get("X-Employee-ID", "EMP_94821")
        branch_code = request.headers.get("X-Branch-Code", "CHENNAI_MAIN_001")
        masking_mode = _resolve_masking_mode(user_role_str)

        # =====================================================================
        # 1. Threat Quarantine & Rate-Limiting Gate
        # =====================================================================
        rate_result = self._rate_limiter.check(client_ip)
        if rate_result.is_anomalous:
            telemetry.record_blocked()
            log_entry = _make_log_entry(
                level="WARNING",
                event=rate_result.anomaly_type.value,
                client_ip=client_ip,
                route=route,
                request_id=request_id,
                action="BLOCKED",
                role=user_role_str,
                emp_id=emp_id,
                extra={"detail": rate_result.detail},
            )
            telemetry.log_event(log_entry)
            logger.warning(json.dumps(log_entry))
            return JSONResponse(
                status_code=rate_result.http_status,
                content={"error": rate_result.detail, "request_id": request_id},
            )

        # =====================================================================
        # 2. Payload Byte-Size Gate
        # =====================================================================
        body_bytes = await request.body()
        content_length = len(body_bytes)

        size_result = check_payload_size(content_length)
        if size_result.is_anomalous:
            self._rate_limiter.record_violation(client_ip)
            telemetry.record_blocked()
            log_entry = _make_log_entry(
                level="WARNING",
                event=size_result.anomaly_type.value,
                client_ip=client_ip,
                route=route,
                request_id=request_id,
                action="BLOCKED",
                role=user_role_str,
                emp_id=emp_id,
                extra={"payload_size_bytes": content_length, "detail": size_result.detail},
            )
            telemetry.log_event(log_entry)
            logger.warning(json.dumps(log_entry))
            return JSONResponse(
                status_code=size_result.http_status,
                content={"error": size_result.detail, "request_id": request_id},
            )

        # =====================================================================
        # 3. Payload Parsing & Bulk Data Verification
        # =====================================================================
        if content_length > 0:
            try:
                payload = json.loads(body_bytes.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                self._rate_limiter.record_violation(client_ip)
                telemetry.record_blocked()
                log_entry = _make_log_entry(
                    level="WARNING",
                    event="INVALID_PAYLOAD",
                    client_ip=client_ip,
                    route=route,
                    request_id=request_id,
                    action="BLOCKED",
                    role=user_role_str,
                    emp_id=emp_id,
                    extra={"detail": f"Payload not valid UTF-8 JSON: {type(exc).__name__}"},
                )
                telemetry.log_event(log_entry)
                logger.warning(json.dumps(log_entry))
                return JSONResponse(
                    status_code=400,
                    content={"error": "Request body must be valid UTF-8 JSON.", "request_id": request_id},
                )

            # Check absolute bulk limit (100 records max)
            bulk_result = check_bulk_export(payload)
            if bulk_result.is_anomalous:
                self._rate_limiter.record_violation(client_ip)
                telemetry.record_blocked()
                log_entry = _make_log_entry(
                    level="WARNING",
                    event=bulk_result.anomaly_type.value,
                    client_ip=client_ip,
                    route=route,
                    request_id=request_id,
                    action="BLOCKED",
                    role=user_role_str,
                    emp_id=emp_id,
                    extra={"detail": bulk_result.detail},
                )
                telemetry.log_event(log_entry)
                logger.warning(json.dumps(log_entry))
                return JSONResponse(
                    status_code=bulk_result.http_status,
                    content={"error": bulk_result.detail, "request_id": request_id},
                )

            # Check Four-Eyes Quorum Threshold (Quarantine if records > 20 and not yet approved)
            array_items = []
            if isinstance(payload, list):
                array_items = payload
            elif isinstance(payload, dict):
                for v in payload.values():
                    if isinstance(v, list) and len(v) > len(array_items):
                        array_items = v

            approval_token = request.headers.get("X-Approval-Token")
            if len(array_items) > BULK_APPROVAL_THRESHOLD and not approval_token:
                staged = approval_manager.stage_request(
                    requester_emp_id=emp_id,
                    payload=payload,
                    record_count=len(array_items),
                    justification=request.headers.get("X-Export-Justification", "Bulk Customer Account Export"),
                )
                log_entry = _make_log_entry(
                    level="INFO",
                    event="FOUR_EYES_QUORUM_QUARANTINE",
                    client_ip=client_ip,
                    route=route,
                    request_id=request_id,
                    action="STAGED_FOR_APPROVAL",
                    role=user_role_str,
                    emp_id=emp_id,
                    extra={"approval_request_id": staged.request_id, "record_count": len(array_items)},
                )
                telemetry.log_event(log_entry)
                return JSONResponse(
                    status_code=202,
                    content={
                        "status": "PENDING_SUPERVISORY_APPROVAL",
                        "message": (
                            f"Export of {len(array_items)} records exceeds the Four-Eyes threshold ({BULK_APPROVAL_THRESHOLD}). "
                            f"Staged in supervisory queue. Approval Request ID: {staged.request_id}"
                        ),
                        "approval_request_id": staged.request_id,
                    },
                )

            # Apply DPDP Consent Filtering if records are present
            if isinstance(payload, list) and all(isinstance(r, dict) for r in payload):
                payload, suppressed = filter_by_dpdp_consent(payload)
                if suppressed > 0:
                    log_entry = _make_log_entry(
                        level="INFO",
                        event="DPDP_CONSENT_SUPPRESSION",
                        client_ip=client_ip,
                        route=route,
                        request_id=request_id,
                        action="RECORDS_SUPPRESSED",
                        role=user_role_str,
                        emp_id=emp_id,
                        extra={"suppressed_records_count": suppressed},
                    )
                    telemetry.log_event(log_entry)

            # 4. Tokenize Inbound Request Payload
            tokenization = tokenize_payload(payload, mode=masking_mode)
            if tokenization.had_pii:
                telemetry.record_redaction(tokenization.total_substitutions)
                log_entry = _make_log_entry(
                    level="WARNING",
                    event="PII_DETECTED_AND_TOKENIZED",
                    client_ip=client_ip,
                    route=route,
                    request_id=request_id,
                    action="SANITIZED_AND_FORWARDED",
                    role=user_role_str,
                    emp_id=emp_id,
                    extra={
                        "fields_tokenized": tokenization.fields_tokenized,
                        "fields_count": len(tokenization.fields_tokenized),
                        "total_substitutions": tokenization.total_substitutions,
                        "masking_mode": masking_mode.value,
                        "payload_size_bytes": content_length,
                    },
                )
                telemetry.log_event(log_entry)
                logger.warning(json.dumps(log_entry))

            request.state.sanitized_body = tokenization.sanitized_payload
            request.state.request_id = request_id
            request.state.masking_mode = masking_mode.value
            request.state.user_role = user_role_str
        else:
            request.state.sanitized_body = None
            request.state.request_id = request_id
            request.state.masking_mode = masking_mode.value
            request.state.user_role = user_role_str

        # Forward to route handler
        response: Response = await call_next(request)

        # =====================================================================
        # 5. Outbound Inspection & Covert Provenance Steganography
        # =====================================================================
        if hasattr(response, "body") or hasattr(response, "body_iterator"):
            try:
                response_body = b""
                if hasattr(response, "body") and response.body:
                    response_body = response.body
                elif hasattr(response, "body_iterator"):
                    chunks = []
                    async for chunk in response.body_iterator:
                        if isinstance(chunk, bytes):
                            chunks.append(chunk)
                        else:
                            chunks.append(chunk.encode("utf-8"))
                    response_body = b"".join(chunks)

                if response_body:
                    resp_payload = json.loads(response_body.decode("utf-8"))
                    resp_tokenization = tokenize_payload(resp_payload, mode=masking_mode)

                    if resp_tokenization.had_pii:
                        telemetry.record_redaction(resp_tokenization.total_substitutions)

                    # Inject invisible zero-width provenance watermark
                    watermark_meta = WatermarkPayload(
                        emp_id=emp_id,
                        branch_code=branch_code,
                        client_ip=client_ip,
                        timestamp=datetime.now(timezone.utc).isoformat(),
                        export_token=request_id[:8],
                    )
                    watermarked_payload = inject_covert_watermark(
                        resp_tokenization.sanitized_payload, watermark_meta
                    )

                    sanitized_body = json.dumps(watermarked_payload)
                    resp_headers = {k: v for k, v in response.headers.items() if k.lower() != "content-length"}
                    return Response(
                        content=sanitized_body,
                        status_code=response.status_code,
                        headers=resp_headers,
                        media_type="application/json",
                    )
            except (UnicodeDecodeError, json.JSONDecodeError):
                pass

        return response
