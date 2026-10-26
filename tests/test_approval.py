"""
tests/test_approval.py — Four-Eyes Dual Approval & Honeytrap Tests
"""

from __future__ import annotations

import pytest

from core.approval import ApprovalStatus, approval_manager
from core.consent import filter_by_dpdp_consent
from core.honeytrap import generate_decoy_customer, generate_tarpit_dataset
from core.tokenizer import validate_verhoeff_aadhaar


def test_four_eyes_approval_lifecycle() -> None:
    # 1. Stage an export request
    staged = approval_manager.stage_request(
        requester_emp_id="EMP_TELLER_01",
        payload=[{"id": i} for i in range(30)],
        record_count=30,
        justification="Branch Audit",
    )
    assert staged.status == ApprovalStatus.PENDING
    
    # 2. Check in pending queue
    pending_list = approval_manager.get_pending_requests()
    assert any(item["request_id"] == staged.request_id for item in pending_list)
    
    # 3. Approve
    approved = approval_manager.approve_request(staged.request_id, "MGR_AUDIT_99")
    assert approved is not None
    assert approved.status == ApprovalStatus.APPROVED
    assert approved.approver_emp_id == "MGR_AUDIT_99"


def test_dpdp_consent_suppression() -> None:
    records = [
        {"cif_id": "CIF1234567890AB", "name": "Active Consent User"},
        {"cif_id": "CIF9988776655AA", "name": "Revoked Consent User"},
    ]
    allowed, suppressed_count = filter_by_dpdp_consent(records)
    assert len(allowed) == 1
    assert suppressed_count == 1
    assert allowed[0]["cif_id"] == "CIF1234567890AB"


def test_honeytrap_synthetic_generator() -> None:
    decoy = generate_decoy_customer(1, "192.168.1.100")
    assert "pan_card" in decoy
    assert "aadhaar" in decoy
    assert "TRAP_SEED_IP_192.168.1.100" in decoy["honeytoken_flag"]
    
    # Verify generated Aadhaar has valid Verhoeff checksum
    raw_digits = decoy["aadhaar"].replace(" ", "")
    assert validate_verhoeff_aadhaar(raw_digits) is True
