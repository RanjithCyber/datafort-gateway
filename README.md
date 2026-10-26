# 🛡️ DataFort-Gateway V3.0 (Maestro Defense)

> **Enterprise-Grade Zero-Trust Banking DLP & Cryptographic Forensic Steganography API Gateway**  
> *Engineered to prevent high-profile banking data leaks (e.g. SBI/BFSI internal API exposures, rogue insider dumps, and unauthorized bulk exports) with automated DPDP Act (2023) compliance.*

---

## 🌟 Architectural Highlights

- **🔒 Zero-Trust Indian Banking PII Engine**: Strict regex patterns & Verhoeff checksum algorithm for 12-digit Aadhaar, PAN cards (`[A-Z]{5}[0-9]{4}[A-Z]`), UPI IDs, Indian Mobile numbers, CIF IDs, and Email addresses.
- **🎭 Role-Based Dynamic Masking (RBAC)**:
  - `Bank Teller / Staff`: **Full Tokenization** (`[TOKENIZED_PAN]`, `[TOKENIZED_AADHAAR]`).
  - `Branch Manager`: **Supervisory Partial Masking** (`AB*****F`, `******3210`).
  - `Fraud Investigator`: **Audited Unmasked Access** with immutable tamper-evident cryptographic hash logging.
- **🕵️ Invisible Zero-Width Forensic Steganography**: Embeds covert zero-width Unicode markers (`\u200b`, `\u200c`, `\u200d`) containing terminal IP, employee ID, branch code, and timestamp directly into exported data—instantly pinpointing leakers even if screenshots or pastes are posted to Telegram or dark-web forums.
- **⚖️ Four-Eyes Principle Quorum (Dual Authorization)**: Automatically quarantines bulk exports exceeding 20 records into a supervisor consensus staging queue.
- **📜 DPDP Act (2023) Consent Validation**: Automated real-time customer data consent verification with non-consenting record suppression.
- **🕸️ Cyber Deception Honeytrap / Synthetic Decoy Tarpit**: Mathematically valid synthetic accounts generated on anomalous probe requests to mislead attackers and trigger proactive alarms.
- **🌌 3D Cinematic Command Center**: Three.js WebGL holographic defense core, undulating perspective cyber grid, and responsive ergonomic cyber tactical buttons.

---

## 🏛️ Security Architecture

```
 Inbound Banking API Traffic
            │
            ▼
┌────────────────────────────────────────────────────────┐
│          DATAFORT ZERO-TRUST ASGI GATEWAY              │
├────────────────────────────────────────────────────────┤
│ [Gate 1] Anomaly Guard: Byte-Cap (100KB) + Rate-Limit │
│ [Gate 2] Four-Eyes Principle Bulk Export Quarantine    │
│ [Gate 3] DPDP Act (2023) Consent Validation Engine     │
│ [Gate 4] Indian Banking PII Tokenizer & Verhoeff Check │
│ [Gate 5] Role-Based Dynamic Masking (RBAC)             │
│ [Gate 6] Covert Zero-Width Forensic Steganography      │
└────────────────────────────────────────────────────────┘
            │
            ▼
   Sanitized Protected Output Stream (Audit Logged)
```

---

## 🚀 Quickstart & Installation

### 1. Requirements
- Python 3.10+
- Dependencies: `fastapi`, `uvicorn`, `pytest`, `httpx`

```bash
# Clone the repository
git clone https://github.com/RanjithCyber/datafort-gateway.git
cd datafort-gateway

# Install dependencies
pip install -r requirements.txt
```

### 2. Launch the Gateway
```bash
python -m uvicorn main:app --host 127.0.0.1 --port 8500 --reload
```

- **Interactive 3D Cyber Command Center**: [http://127.0.0.1:8500/dashboard](http://127.0.0.1:8500/dashboard)
- **Zero-Trust Mobile-Proof Secure Viewer**: [http://127.0.0.1:8500/viewer](http://127.0.0.1:8500/viewer)
- **OpenAPI / Swagger Documentation**: [http://127.0.0.1:8500/docs](http://127.0.0.1:8500/docs)

---

## 🧪 Automated Test Suite (100% Pass)

DataFort-Gateway includes a comprehensive test suite with 62 automated unit and integration tests:

```bash
pytest
```

```text
============================= test session starts =============================
platform win32 -- Python 3.11.8, pytest-9.1.1
tests/test_anomaly.py .......                                            [ 11%]
tests/test_approval.py ...                                               [ 16%]
tests/test_interceptor.py ...........                                    [ 33%]
tests/test_tokenizer.py ......................................           [ 95%]
tests/test_watermark.py ...                                              [100%]
============================= 62 passed in 0.11s ==============================
```

---

## 📂 Repository Structure

```
datafort-gateway/
├── core/
│   ├── anomaly.py       # Rate-limiting, bulk threshold & IP blacklisting
│   ├── approval.py      # Four-Eyes dual authorization consensus quarantine
│   ├── consent.py       # DPDP Act (2023) customer consent validator
│   ├── honeytrap.py     # Deceptive synthetic decoy tarpit
│   ├── tokenizer.py     # Indian PII regex, Verhoeff checksum & RBAC masking
│   └── watermark.py     # Zero-width Unicode steganographic provenance encoder/decoder
├── middleware/
│   └── interceptor.py   # Zero-trust dual-pass ASGI gateway middleware
├── templates/
│   └── dashboard.html   # Three.js 3D Live Cyber Command Center UI
├── tests/
│   ├── test_anomaly.py
│   ├── test_approval.py
│   ├── test_interceptor.py
│   ├── test_tokenizer.py
│   └── test_watermark.py
├── main.py              # FastAPI application server & endpoints
├── LINKEDIN_PORTFOLIO_KIT.md  # Executive portfolio briefing & interview defense kit
├── requirements.txt     # Python runtime dependencies
└── README.md            # Project documentation
```

---

## 📜 Compliance & Regulatory Standards

- **RBI Master Direction on Cyber Security**: In-flight tokenization and role-separated access.
- **Digital Personal Data Protection (DPDP) Act, 2023**: Purpose limitation, verifiable customer consent, and data minimization.
- **ISO/IEC 27001 (Control A.8.11 & A.8.12)**: Data masking and data leakage prevention.

---

## 👨‍💻 Author

**Ranjith Kumar**  
Cybersecurity Engineer & Architecture Researcher  
[GitHub Profile](https://github.com/RanjithCyber)
