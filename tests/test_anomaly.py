"""
tests/test_anomaly.py — V2.0 Anomaly Detection & Threat Intelligence Tests
"""

from __future__ import annotations

import pytest

from core.anomaly import (
    MAX_PAYLOAD_BYTES,
    MAX_RECORDS_PER_EXPORT,
    AnomalyType,
    RateLimiter,
    check_bulk_export,
    check_payload_size,
    telemetry,
)


class TestPayloadSizeCheck:
    def test_within_limit_passes(self) -> None:
        result = check_payload_size(1024)
        assert result.is_anomalous is False

    def test_exceeds_limit_blocked(self) -> None:
        result = check_payload_size(MAX_PAYLOAD_BYTES + 1)
        assert result.is_anomalous is True
        assert result.anomaly_type == AnomalyType.PAYLOAD_TOO_LARGE
        assert result.http_status == 413


class TestBulkExportCheck:
    def test_small_array_passes(self) -> None:
        payload = {"records": [{"id": i} for i in range(10)]}
        assert check_bulk_export(payload).is_anomalous is False

    def test_exceeds_limit_blocked(self) -> None:
        payload = {"records": [{"id": i} for i in range(MAX_RECORDS_PER_EXPORT + 1)]}
        result = check_bulk_export(payload)
        assert result.is_anomalous is True
        assert result.anomaly_type == AnomalyType.BULK_EXPORT_BLOCKED
        assert result.http_status == 403


class TestRateLimiterAndBlacklist:
    def test_rate_limit_exceeded(self) -> None:
        limiter = RateLimiter(max_requests=2, window_seconds=60)
        limiter.check("192.168.1.50")
        limiter.check("192.168.1.50")
        result = limiter.check("192.168.1.50")
        assert result.is_anomalous is True
        assert result.anomaly_type == AnomalyType.RATE_LIMIT_EXCEEDED
        assert result.http_status == 429

    def test_automated_ip_quarantine_blacklist(self) -> None:
        limiter = RateLimiter(
            max_requests=10,
            window_seconds=60,
            blacklist_threshold=3,
            blacklist_duration=60,
        )
        bad_ip = "10.10.10.99"
        
        # Simulate 3 security violations
        limiter.record_violation(bad_ip)
        limiter.record_violation(bad_ip)
        limiter.record_violation(bad_ip)

        # IP should now be quarantined
        assert limiter.is_blacklisted(bad_ip) is True
        result = limiter.check(bad_ip)
        assert result.is_anomalous is True
        assert result.anomaly_type == AnomalyType.IP_BLACKLISTED
        assert result.http_status == 403


class TestTelemetryBuffer:
    def test_telemetry_recording(self) -> None:
        telemetry.reset()
        telemetry.record_request()
        telemetry.record_redaction(4)
        telemetry.record_blocked()
        
        snap = telemetry.get_snapshot()
        assert snap["total_requests_inspected"] == 1
        assert snap["total_pii_redactions"] == 4
        assert snap["total_blocked_attacks"] == 1
