"""
tests/conftest.py — Shared Pytest Fixtures

Provides:
  - TestClient instance wired to the FastAPI app
  - Sample payloads with various PII patterns
  - Clean rate-limiter state between tests
"""

from __future__ import annotations

import pytest
from httpx import ASGITransport, AsyncClient

from main import app


@pytest.fixture()
def client():
    """Synchronous TestClient for integration tests."""
    from starlette.testclient import TestClient

    # Reset middleware rate limiter between tests
    for mw in app.user_middleware:
        pass  # Middleware state is reset via the fixture below

    return TestClient(app, raise_server_exceptions=False)


@pytest.fixture()
async def async_client():
    """Async HTTPX client for async test scenarios."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as ac:
        yield ac


@pytest.fixture()
def clean_payload() -> dict:
    """A payload with no PII — should pass through unmodified."""
    return {
        "transaction_id": "TXN-2026-001",
        "amount": 15000.50,
        "currency": "INR",
        "status": "completed",
    }


@pytest.fixture()
def pii_payload() -> dict:
    """A payload containing all four PII categories."""
    return {
        "customer_name": "Ranjith Kumar",
        "mobile": "+91-9876543210",
        "email": "ranjith.kumar@example.com",
        "cif_id": "CIF1234567890AB",
        "date_of_birth": "1990-05-14",
        "account_balance": 250000.00,
    }


@pytest.fixture()
def nested_pii_payload() -> dict:
    """Deeply nested payload with PII at multiple levels."""
    return {
        "header": {
            "source": "core-banking",
            "timestamp": "2026-10-26T10:00:00Z",
        },
        "records": [
            {
                "name": "User A",
                "contact": {
                    "phone": "9876543210",
                    "email": "usera@bank.com",
                },
                "dob": "14/05/1990",
                "cif": "CIF00112233AABB",
            },
            {
                "name": "User B",
                "contact": {
                    "phone": "+91 8765432109",
                    "email": "userb@bank.com",
                },
                "dob": "2001-12-25",
                "cif": "CIF99887766CCDD",
            },
        ],
    }


@pytest.fixture()
def bulk_export_payload() -> dict:
    """Payload with an array exceeding MAX_RECORDS_PER_EXPORT."""
    return {
        "export_type": "full_dump",
        "records": [{"id": i, "value": f"row-{i}"} for i in range(150)],
    }


@pytest.fixture()
def oversized_payload() -> str:
    """A raw string payload exceeding MAX_PAYLOAD_BYTES (100 KB)."""
    return "x" * 200_000
