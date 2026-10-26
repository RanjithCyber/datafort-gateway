"""
core/anomaly.py — V2.0 Enterprise Anomaly Detection & Threat Intelligence

Features:
  1. Payload size guard (MAX_PAYLOAD_BYTES -> 413)
  2. IP sliding-window rate limiter (MAX_REQUESTS_PER_WINDOW -> 429)
  3. Bulk export detector (MAX_RECORDS_PER_EXPORT -> 403)
  4. Auto-Threat IP Blacklist (repeated violations trigger automated lockout)
  5. Real-Time Telemetry & Audit Buffer for the SOC Dashboard
"""

from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any


# ---------------------------------------------------------------------------
# Configurable Thresholds
# ---------------------------------------------------------------------------
MAX_PAYLOAD_BYTES: int = 102_400          # 100 KB
MAX_REQUESTS_PER_WINDOW: int = 50         # 50 req per client IP
RATE_WINDOW_SECONDS: int = 60             # 60s window
MAX_RECORDS_PER_EXPORT: int = 100         # Max items in an export array
BLACKLIST_THRESHOLD: int = 3              # Violations within window before auto-ban
BLACKLIST_DURATION_SECONDS: int = 300     # 5-minute lockout


class AnomalyType(str, Enum):
    PAYLOAD_TOO_LARGE = "PAYLOAD_TOO_LARGE"
    RATE_LIMIT_EXCEEDED = "RATE_LIMIT_EXCEEDED"
    BULK_EXPORT_BLOCKED = "BULK_EXPORT_BLOCKED"
    IP_BLACKLISTED = "IP_BLACKLISTED"


@dataclass(frozen=True)
class AnomalyResult:
    is_anomalous: bool
    anomaly_type: AnomalyType | None = None
    detail: str = ""
    http_status: int = 200


# ---------------------------------------------------------------------------
# Global Telemetry & In-Memory Audit Event Buffer
# ---------------------------------------------------------------------------
@dataclass
class TelemetryStats:
    total_requests_inspected: int = 0
    total_pii_redactions: int = 0
    total_blocked_attacks: int = 0
    active_blacklisted_ips: int = 0
    started_at: str = ""


class SecurityTelemetry:
    """Thread-safe real-time telemetry and audit ring buffer."""

    def __init__(self, max_audit_events: int = 100) -> None:
        self._lock = threading.Lock()
        self._inspected = 0
        self._redactions = 0
        self._blocked = 0
        self._started_at = datetime.now(timezone.utc).isoformat()
        self._audit_events: deque[dict[str, Any]] = deque(maxlen=max_audit_events)

    def record_request(self) -> None:
        with self._lock:
            self._inspected += 1

    def record_redaction(self, count: int = 1) -> None:
        with self._lock:
            self._redactions += count

    def record_blocked(self) -> None:
        with self._lock:
            self._blocked += 1

    def log_event(self, event_dict: dict[str, Any]) -> None:
        with self._lock:
            self._audit_events.appendleft(event_dict)

    def get_snapshot(self, blacklisted_count: int = 0) -> dict[str, Any]:
        with self._lock:
            return {
                "total_requests_inspected": self._inspected,
                "total_pii_redactions": self._redactions,
                "total_blocked_attacks": self._blocked,
                "active_blacklisted_ips": blacklisted_count,
                "started_at": self._started_at,
            }

    def get_recent_events(self, limit: int = 50) -> list[dict[str, Any]]:
        with self._lock:
            return list(self._audit_events)[:limit]

    def reset(self) -> None:
        with self._lock:
            self._inspected = 0
            self._redactions = 0
            self._blocked = 0
            self._audit_events.clear()


# Global Singleton for the Gateway
telemetry = SecurityTelemetry()


# ---------------------------------------------------------------------------
# Payload Size Check
# ---------------------------------------------------------------------------
def check_payload_size(content_length: int) -> AnomalyResult:
    if content_length > MAX_PAYLOAD_BYTES:
        return AnomalyResult(
            is_anomalous=True,
            anomaly_type=AnomalyType.PAYLOAD_TOO_LARGE,
            detail=(
                f"Payload size {content_length} bytes exceeds "
                f"maximum allowed {MAX_PAYLOAD_BYTES} bytes."
            ),
            http_status=413,
        )
    return AnomalyResult(is_anomalous=False)


# ---------------------------------------------------------------------------
# Bulk Export Check
# ---------------------------------------------------------------------------
def check_bulk_export(payload: Any) -> AnomalyResult:
    arrays_to_check: list[tuple[str, list[Any]]] = []

    if isinstance(payload, list):
        arrays_to_check.append(("root", payload))
    elif isinstance(payload, dict):
        for key, value in payload.items():
            if isinstance(value, list):
                arrays_to_check.append((key, value))

    for field_name, arr in arrays_to_check:
        if len(arr) > MAX_RECORDS_PER_EXPORT:
            return AnomalyResult(
                is_anomalous=True,
                anomaly_type=AnomalyType.BULK_EXPORT_BLOCKED,
                detail=(
                    f"Array field '{field_name}' contains {len(arr)} records, "
                    f"exceeding maximum allowed {MAX_RECORDS_PER_EXPORT}."
                ),
                http_status=403,
            )

    return AnomalyResult(is_anomalous=False)


# ---------------------------------------------------------------------------
# Rate Limiter with Automated Threat Blacklisting
# ---------------------------------------------------------------------------
class RateLimiter:
    """Sliding-window rate limiter with automated threat IP quarantine."""

    def __init__(
        self,
        max_requests: int = MAX_REQUESTS_PER_WINDOW,
        window_seconds: int = RATE_WINDOW_SECONDS,
        blacklist_threshold: int = BLACKLIST_THRESHOLD,
        blacklist_duration: int = BLACKLIST_DURATION_SECONDS,
    ) -> None:
        self._max_requests = max_requests
        self._window_seconds = window_seconds
        self._blacklist_threshold = blacklist_threshold
        self._blacklist_duration = blacklist_duration
        self._store: dict[str, list[float]] = {}
        self._violations: dict[str, list[float]] = {}
        self._blacklisted: dict[str, float] = {}  # ip -> ban expiry timestamp
        self._lock = threading.Lock()

    def is_blacklisted(self, client_ip: str) -> bool:
        with self._lock:
            now = time.monotonic()
            if client_ip in self._blacklisted:
                if now < self._blacklisted[client_ip]:
                    return True
                # Ban expired
                del self._blacklisted[client_ip]
            return False

    def check(self, client_ip: str) -> AnomalyResult:
        now = time.monotonic()
        cutoff = now - self._window_seconds

        with self._lock:
            # 1. Check if currently blacklisted
            if client_ip in self._blacklisted:
                if now < self._blacklisted[client_ip]:
                    remaining = int(self._blacklisted[client_ip] - now)
                    return AnomalyResult(
                        is_anomalous=True,
                        anomaly_type=AnomalyType.IP_BLACKLISTED,
                        detail=f"Client IP {client_ip} is quarantined due to repeated violations. Unbans in {remaining}s.",
                        http_status=403,
                    )
                del self._blacklisted[client_ip]

            # 2. Check request sliding window
            timestamps = self._store.get(client_ip, [])
            timestamps = [ts for ts in timestamps if ts > cutoff]

            if len(timestamps) >= self._max_requests:
                self._store[client_ip] = timestamps
                self._record_violation_locked(client_ip, now)
                return AnomalyResult(
                    is_anomalous=True,
                    anomaly_type=AnomalyType.RATE_LIMIT_EXCEEDED,
                    detail=(
                        f"Client {client_ip} exceeded {self._max_requests} "
                        f"requests in {self._window_seconds}s window."
                    ),
                    http_status=429,
                )

            timestamps.append(now)
            self._store[client_ip] = timestamps

        return AnomalyResult(is_anomalous=False)

    def record_violation(self, client_ip: str) -> None:
        """Called when an IP triggers any security anomaly (e.g. bulk export attempt)."""
        with self._lock:
            self._record_violation_locked(client_ip, time.monotonic())

    def _record_violation_locked(self, client_ip: str, now: float) -> None:
        cutoff = now - self._window_seconds
        v_list = self._violations.get(client_ip, [])
        v_list = [t for t in v_list if t > cutoff]
        v_list.append(now)
        self._violations[client_ip] = v_list

        if len(v_list) >= self._blacklist_threshold:
            self._blacklisted[client_ip] = now + self._blacklist_duration

    def get_blacklisted_count(self) -> int:
        now = time.monotonic()
        with self._lock:
            # Clean expired
            active = {ip: exp for ip, exp in self._blacklisted.items() if exp > now}
            self._blacklisted = active
            return len(self._blacklisted)

    def reset(self) -> None:
        with self._lock:
            self._store.clear()
            self._violations.clear()
            self._blacklisted.clear()
