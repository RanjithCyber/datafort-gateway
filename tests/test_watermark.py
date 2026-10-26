"""
tests/test_watermark.py — Covert Forensic Steganography & Leak Tracer Tests
"""

from __future__ import annotations

import pytest

from core.watermark import (
    WatermarkPayload,
    decode_zero_width_provenance,
    encode_provenance_to_zero_width,
    inject_covert_watermark,
)


def test_zero_width_roundtrip() -> None:
    meta = WatermarkPayload(
        emp_id="EMP_94821",
        branch_code="CHENNAI_MAIN_001",
        client_ip="192.168.1.15",
        timestamp="2026-10-26T18:25:00Z",
        export_token="TXN-A1B2",
    )
    
    # 1. Encode into zero-width
    zw_str = encode_provenance_to_zero_width(meta)
    assert len(zw_str) > 0
    
    # 2. Embed into carrier text
    carrier = f"Customer Ranjith{zw_str} Kumar Account Statement"
    
    # 3. Decode
    decoded = decode_zero_width_provenance(carrier)
    assert decoded is not None
    assert decoded["status"] == "PROVENANCE_IDENTIFIED"
    assert decoded["leaker_emp_id"] == "EMP_94821"
    assert decoded["branch_code"] == "CHENNAI_MAIN_001"
    assert decoded["terminal_ip"] == "192.168.1.15"


def test_clean_text_no_watermark() -> None:
    clean = "Plain text with no invisible zero-width characters"
    assert decode_zero_width_provenance(clean) is None


def test_payload_injection() -> None:
    meta = WatermarkPayload(
        emp_id="EMP_12345",
        branch_code="BLR_001",
        client_ip="10.0.0.1",
        timestamp="2026-10-26T18:00:00Z",
        export_token="EXP-99",
    )
    payload = {"name": "Arun Kumar", "balance": 50000}
    watermarked = inject_covert_watermark(payload, meta)
    
    # Text looks normal
    assert "Arun" in watermarked["name"]
    # But decoder extracts the metadata
    decoded = decode_zero_width_provenance(watermarked["name"])
    assert decoded is not None
    assert decoded["leaker_emp_id"] == "EMP_12345"
