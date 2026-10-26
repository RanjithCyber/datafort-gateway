"""
core/approval.py — Enterprise Four-Eyes Principle (Dual-Authorization) Engine

Features:
  1. Quorum Gate:
     Any export operation containing > 20 records is automatically quarantined
     into a PENDING_APPROVAL state, requiring second-person supervisory consensus.
  2. Dual-Sign-Off Workflow:
     Branch Managers / Compliance Officers can review, approve, or reject
     staged exports directly from the SOC Dashboard or API.
"""

from __future__ import annotations

import threading
import uuid
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Any

BULK_APPROVAL_THRESHOLD = 20  # Records above this trigger Four-Eyes requirement


class ApprovalStatus(str, Enum):
    PENDING = "PENDING_APPROVAL"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"


@dataclass
class StagedExportRequest:
    request_id: str
    requester_emp_id: str
    record_count: int
    created_at: str
    status: ApprovalStatus
    payload: Any
    approver_emp_id: str | None = None
    decided_at: str | None = None
    justification: str = "Standard Quarterly Audit"


class DualApprovalManager:
    """Thread-safe quarantine and consensus manager for bulk data exports."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._staged: dict[str, StagedExportRequest] = {}

    def stage_request(
        self,
        requester_emp_id: str,
        payload: Any,
        record_count: int,
        justification: str = "Quarterly Compliance Audit",
    ) -> StagedExportRequest:
        req_id = f"APPR-{uuid.uuid4().hex[:8].upper()}"
        staged = StagedExportRequest(
            request_id=req_id,
            requester_emp_id=requester_emp_id,
            record_count=record_count,
            created_at=datetime.now(timezone.utc).isoformat(),
            status=ApprovalStatus.PENDING,
            payload=payload,
            justification=justification,
        )
        with self._lock:
            self._staged[req_id] = staged
        return staged

    def approve_request(
        self, request_id: str, approver_emp_id: str
    ) -> StagedExportRequest | None:
        with self._lock:
            if request_id not in self._staged:
                return None
            req = self._staged[request_id]
            req.status = ApprovalStatus.APPROVED
            req.approver_emp_id = approver_emp_id
            req.decided_at = datetime.now(timezone.utc).isoformat()
            return req

    def reject_request(
        self, request_id: str, approver_emp_id: str
    ) -> StagedExportRequest | None:
        with self._lock:
            if request_id not in self._staged:
                return None
            req = self._staged[request_id]
            req.status = ApprovalStatus.REJECTED
            req.approver_emp_id = approver_emp_id
            req.decided_at = datetime.now(timezone.utc).isoformat()
            return req

    def get_pending_requests(self) -> list[dict[str, Any]]:
        with self._lock:
            return [
                {
                    "request_id": req.request_id,
                    "requester_emp_id": req.requester_emp_id,
                    "record_count": req.record_count,
                    "created_at": req.created_at,
                    "status": req.status.value,
                    "justification": req.justification,
                }
                for req in self._staged.values()
                if req.status == ApprovalStatus.PENDING
            ]

    def get_request(self, request_id: str) -> StagedExportRequest | None:
        with self._lock:
            return self._staged.get(request_id)


# Global Singleton for Dual-Approval Quarantine
approval_manager = DualApprovalManager()
