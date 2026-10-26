# DataFort-Gateway — Enterprise Project Blueprint

> **Version**: 2.0.0 (Enterprise DLP & Threat Intelligence Edition)  
> **Author**: Senior Security & Backend Engineering  
> **Classification**: CONFIDENTIAL — Banking Data-Leak Prevention & Tokenization Gateway  
> **Last Updated**: 2026-10-26

---

## 1. Mission Statement

DataFort-Gateway V2.0 is an enterprise-grade, zero-trust data-leak prevention (DLP) reverse proxy and middleware built on FastAPI. It protects sensitive banking ecosystems (such as SBI Core Banking & Export APIs) by:
1. Deterministically intercepting and scrubbing high-risk Indian banking & personal identifiers.
2. Providing **Role-Based Dynamic Masking (RBAC)** across Tellers, Branch Managers, and Fraud Officers.
3. Automatically detecting and quarantining malicious IPs attempting bulk data exfiltration.
4. Serving a real-time **Cyber Security Operations Center (SOC) Console** with live telemetry and audit event logs.

---

## 2. Directory Structure

```
datafort-gateway/
├── PROJECT_MAP.md            # Architecture blueprint & security constraints
├── requirements.txt          # Production dependencies
├── main.py                   # FastAPI factory, SOC Dashboard (/dashboard), & Routes
│
├── core/
│   ├── __init__.py
│   ├── tokenizer.py          # V2.0 Engine: PAN, Aadhaar (Verhoeff), UPI, Mobile, Email, CIF, DOB + RBAC
│   └── anomaly.py            # V2.0 Telemetry, Auto-Threat IP Blacklist, & Anomaly Engine
│
├── middleware/
│   ├── __init__.py
│   └── interceptor.py        # Dual-Pass Zero-Trust DLP Middleware with RBAC injection
│
├── tests/
│   ├── __init__.py
│   ├── conftest.py           # Pytest fixtures & sample banking datasets
│   ├── test_tokenizer.py     # PII pattern, checksum, and dynamic masking tests
│   ├── test_anomaly.py       # Rate limits, blacklist, and telemetry tests
│   └── test_interceptor.py   # End-to-end middleware integration & role tests
│
└── logs/
    └── datafort.log          # Rotated structured JSON security logs (no raw PII)
```

---

## 3. Supported PII Identifiers (V2.0 Matrix)

| Identifier | Format / Checksum | Staff / Public Mode | Branch Manager Mode | Fraud Officer Mode |
|------------|-------------------|---------------------|---------------------|--------------------|
| **PAN Card** | 10-char `[A-Z]{5}[0-9]{4}[A-Z]{1}` | `[TOKENIZED_PAN]` | `AB*****F` | Unmasked (Audited) |
| **Aadhaar** | 12 digits + Verhoeff Checksum | `[TOKENIZED_AADHAAR]` | `XXXX-XXXX-1234` | Unmasked (Audited) |
| **UPI / VPA** | Handle (e.g. `user@sbi`, `id@okaxis`) | `[TOKENIZED_UPI]` | `***@sbi` | Unmasked (Audited) |
| **Mobile** | +91 / 0 / 10 digits starting 6-9 | `[TOKENIZED_MOBILE]` | `******3210` | Unmasked (Audited) |
| **Email** | RFC-5322 pattern | `[TOKENIZED_EMAIL]` | `r***h@domain.com` | Unmasked (Audited) |
| **CIF ID** | Banking `CIF` + 10-15 chars | `[TOKENIZED_CIF]` | `CIF******1234` | Unmasked (Audited) |
| **Date of Birth** | ISO-8601, DD/MM/YYYY | `[TOKENIZED_DOB]` | `**/**/****` | Unmasked (Audited) |

---

## 4. Anomaly Thresholds & Threat Mitigation

| Control | Value | Consequence on Violation |
|---------|-------|--------------------------|
| `MAX_PAYLOAD_BYTES` | 102,400 bytes (100 KB) | Immediate `413 Payload Too Large` + Violation Recorded |
| `MAX_REQUESTS_PER_WINDOW` | 50 req / 60 seconds | `429 Too Many Requests` + Violation Recorded |
| `MAX_RECORDS_PER_EXPORT` | 100 items / array | `403 Forbidden` (Mass Dump Blocked) + Violation Recorded |
| `BLACKLIST_THRESHOLD` | 3 violations / window | **Automated IP Quarantine (5-minute ban)** |

---

## 5. Security Dashboard & API Surface

| Method | Endpoint | Description | Access |
|--------|----------|-------------|--------|
| `GET` | `/dashboard` | Cyber SOC Real-Time Console with Live DLP Sandbox | Public / Operator |
| `GET` | `/api/v1/stats` | Live telemetry counters (Requests, Redactions, Attacks) | Monitoring |
| `GET` | `/api/v1/audit-logs` | Stream of recent security audit events | Monitoring |
| `POST` | `/api/v1/export` | Core banking export route (DLP protected) | Tokenized / RBAC |
| `POST` | `/api/v1/ingest` | Core banking ingest route (DLP protected) | Tokenized / RBAC |
| `GET` | `/health` | Gateway Liveness probe | Public |
| `GET` | `/ready` | Gateway Readiness probe | Public |

---

## 6. Verification Status

- [x] Phase 1: V1.0 Architecture & Core DLP
- [x] Phase 2: Complete Rebrand to DataFort-Gateway
- [x] Phase 3: V2.0 PAN, Aadhaar (Verhoeff), & UPI Tokenization
- [x] Phase 4: Role-Based Dynamic Masking (RBAC via `X-User-Role`)
- [x] Phase 5: Automated Threat IP Quarantine & Blacklisting
- [x] Phase 6: Interactive Cyber SOC Web Dashboard (`/dashboard`)
- [x] Phase 7: 100% Automated Test Suite Passed (54/54)
