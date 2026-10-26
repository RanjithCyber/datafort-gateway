"""
main.py — V3.0 Intelligence Maestro Gateway & Cinematic SOC Command Center

Enterprise Features:
  - Zero-Trust DLP Middleware with 5-Gate Enforcement
  - Covert Zero-Width Forensic Leak Detective (/api/v1/decode-leak)
  - Four-Eyes Dual-Authorization Approval Queue (/api/v1/approvals)
  - DPDP Act (2023) Consent Enforcement
  - Ephemeral Anti-Leak Viewer with Phone-Proof Watermarking (/viewer)
  - High-Aesthetic Cinematic Cyber SOC Command Dashboard (/dashboard)
"""

from __future__ import annotations

import json
import logging
import logging.handlers
import os
import sys
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any, AsyncGenerator

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel

from core.anomaly import telemetry
from core.approval import approval_manager
from core.watermark import decode_zero_width_provenance
from middleware.interceptor import DLPInterceptorMiddleware


class JSONLogFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        log_entry: dict[str, Any] = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
        }
        return json.dumps(log_entry, default=str)


def _configure_logging() -> None:
    log_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs")
    os.makedirs(log_dir, exist_ok=True)
    log_file = os.path.join(log_dir, "datafort.log")

    formatter = JSONLogFormatter()
    file_handler = logging.handlers.RotatingFileHandler(
        filename=log_file,
        maxBytes=5 * 1024 * 1024,
        backupCount=5,
        encoding="utf-8",
    )
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(formatter)

    console_handler = logging.StreamHandler(stream=sys.stderr)
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(formatter)

    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)
    root_logger.addHandler(file_handler)
    root_logger.addHandler(console_handler)
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    logger = logging.getLogger("datafort.lifecycle")
    logger.info(json.dumps({
        "event": "DATAFORT_GATEWAY_V3_MAESTRO_ONLINE",
        "version": "3.0.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }))
    yield
    logger.info(json.dumps({
        "event": "DATAFORT_GATEWAY_SHUTDOWN",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }))


_configure_logging()

app = FastAPI(
    title="DataFort-Gateway V3.0 Maestro",
    description="Intelligence Maestro Zero-Trust Banking DLP & Forensic Steganography Gateway",
    version="3.0.0",
    lifespan=lifespan,
)

app.add_middleware(DLPInterceptorMiddleware)


# ---------------------------------------------------------------------------
# Models
# ---------------------------------------------------------------------------
class LeakDecodeRequest(BaseModel):
    leaked_content: str


class ApprovalActionRequest(BaseModel):
    request_id: str
    action: str
    approver_emp_id: str = "MGR_44901"


# ---------------------------------------------------------------------------
# Health & Status
# ---------------------------------------------------------------------------
@app.get("/health", tags=["Health"])
async def health_check() -> dict[str, str]:
    return {"status": "healthy", "version": "3.0.0-maestro"}


@app.get("/ready", tags=["Health"])
async def readiness_check() -> dict[str, str]:
    return {"status": "ready", "version": "3.0.0-maestro"}


@app.get("/api/v1/stats", tags=["Monitoring"])
async def get_telemetry_stats() -> dict[str, Any]:
    return telemetry.get_snapshot()


@app.get("/api/v1/audit-logs", tags=["Monitoring"])
async def get_audit_logs() -> list[dict[str, Any]]:
    return telemetry.get_recent_events(limit=50)


# ---------------------------------------------------------------------------
# Forensic Leak Detective API
# ---------------------------------------------------------------------------
@app.post("/api/v1/decode-leak", tags=["Forensic Investigation"])
async def decode_leak(req: LeakDecodeRequest) -> JSONResponse:
    evidence = decode_zero_width_provenance(req.leaked_content)
    if not evidence:
        return JSONResponse(
            status_code=404,
            content={
                "status": "NO_COVERT_WATERMARK_FOUND",
                "message": "No zero-width cryptographic provenance fingerprint was found in this sample.",
            },
        )
    return JSONResponse(status_code=200, content=evidence)


# ---------------------------------------------------------------------------
# Four-Eyes Approval Workflow APIs
# ---------------------------------------------------------------------------
@app.get("/api/v1/approvals", tags=["Four-Eyes Quorum"])
async def list_pending_approvals() -> list[dict[str, Any]]:
    return approval_manager.get_pending_requests()


@app.post("/api/v1/approvals/action", tags=["Four-Eyes Quorum"])
async def handle_approval_action(req: ApprovalActionRequest) -> JSONResponse:
    if req.action.upper() == "APPROVE":
        res = approval_manager.approve_request(req.request_id, req.approver_emp_id)
        if not res:
            raise HTTPException(status_code=404, detail="Request ID not found")
        return JSONResponse(status_code=200, content={"status": "APPROVED", "request_id": req.request_id})
    else:
        res = approval_manager.reject_request(req.request_id, req.approver_emp_id)
        if not res:
            raise HTTPException(status_code=404, detail="Request ID not found")
        return JSONResponse(status_code=200, content={"status": "REJECTED", "request_id": req.request_id})


# ---------------------------------------------------------------------------
# Protected Banking Routes
# ---------------------------------------------------------------------------
@app.post("/api/v1/export", tags=["Banking Export"])
async def export_data(request: Request) -> JSONResponse:
    sanitized = getattr(request.state, "sanitized_body", None)
    request_id = getattr(request.state, "request_id", "unknown")
    masking_mode = getattr(request.state, "masking_mode", "FULL_TOKEN")
    role = getattr(request.state, "user_role", "staff")

    return JSONResponse(
        status_code=200,
        content={
            "status": "export_processed",
            "request_id": request_id,
            "role_applied": role,
            "masking_mode": masking_mode,
            "sanitized_payload": sanitized,
        },
    )


@app.post("/api/v1/ingest", tags=["Banking Ingest"])
async def ingest_data(request: Request) -> JSONResponse:
    sanitized = getattr(request.state, "sanitized_body", None)
    request_id = getattr(request.state, "request_id", "unknown")
    masking_mode = getattr(request.state, "masking_mode", "FULL_TOKEN")
    role = getattr(request.state, "user_role", "staff")

    return JSONResponse(
        status_code=200,
        content={
            "status": "ingest_processed",
            "request_id": request_id,
            "role_applied": role,
            "masking_mode": masking_mode,
            "sanitized_payload": sanitized,
        },
    )


# ---------------------------------------------------------------------------
# High-Aesthetic Ephemeral Viewer with Phone-Proof DRM (/viewer)
# ---------------------------------------------------------------------------
@app.get("/viewer", response_class=HTMLResponse, tags=["Secure Viewer"])
async def get_secure_viewer(emp_id: str = "EMP_94821", branch: str = "CHENNAI_MAIN_001") -> str:
    now_str = datetime.now(timezone.utc).strftime("%d-%b-%Y %H:%M:%S UTC")
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>DataFort Secure Viewer | DRM Protected Airgap</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Outfit:wght@400;600;700;800&display=swap" rel="stylesheet">
  <style>
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      background: radial-gradient(circle at 50% 20%, #0d1527 0%, #050811 100%);
      color: #f8fafc;
      font-family: 'Outfit', sans-serif;
      min-height: 100vh;
      padding: 40px 20px;
      user-select: none;
      -webkit-user-select: none;
      overflow-x: hidden;
    }}
    .watermark-overlay {{
      position: fixed;
      top: -50%; left: -50%; width: 200%; height: 200%;
      pointer-events: none;
      z-index: 9999;
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      grid-gap: 100px;
      padding: 60px;
      box-sizing: border-box;
      opacity: 0.16;
      font-family: 'JetBrains Mono', monospace;
      font-weight: 700;
      font-size: 13px;
      color: #38bdf8;
      transform: rotate(-25deg);
      animation: driftWatermark 25s linear infinite alternate;
    }}
    @keyframes driftWatermark {{
      0% {{ transform: rotate(-25deg) translate(0, 0); }}
      100% {{ transform: rotate(-25deg) translate(40px, 30px); }}
    }}
    .hud-banner {{
      max-width: 960px;
      margin: 0 auto 20px auto;
      background: rgba(15, 23, 42, 0.8);
      border: 1px solid rgba(56, 189, 248, 0.25);
      border-radius: 12px;
      padding: 14px 24px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      backdrop-filter: blur(16px);
      box-shadow: 0 0 30px rgba(56, 189, 248, 0.1);
    }}
    .beacon {{
      display: inline-block;
      width: 10px; height: 10px;
      border-radius: 50%;
      background: #10b981;
      box-shadow: 0 0 12px #10b981;
      animation: pulse 1.5s infinite;
      margin-right: 8px;
    }}
    @keyframes pulse {{
      0%, 100% {{ opacity: 1; transform: scale(1); }}
      50% {{ opacity: 0.4; transform: scale(0.85); }}
    }}
    .timer-badge {{
      background: rgba(239, 68, 68, 0.15);
      border: 1px solid rgba(239, 68, 68, 0.35);
      color: #f87171;
      padding: 6px 14px;
      border-radius: 999px;
      font-family: 'JetBrains Mono', monospace;
      font-size: 12px;
      font-weight: 700;
    }}
    .sheet {{
      max-width: 960px;
      margin: 0 auto;
      background: rgba(18, 27, 49, 0.75);
      border: 1px solid rgba(255, 255, 255, 0.1);
      border-radius: 16px;
      padding: 32px;
      backdrop-filter: blur(20px);
      box-shadow: 0 30px 60px rgba(0, 0, 0, 0.6);
      position: relative;
    }}
    table {{
      width: 100%; border-collapse: collapse; font-size: 13px; font-family: 'JetBrains Mono', monospace;
      margin-top: 20px;
    }}
    th, td {{
      padding: 14px 16px; border-bottom: 1px solid rgba(255, 255, 255, 0.05); text-align: left;
    }}
    th {{
      color: #94a3b8; font-size: 11px; text-transform: uppercase; letter-spacing: 0.06em;
      background: rgba(10, 16, 31, 0.85);
    }}
    tr:hover td {{ background: rgba(56, 189, 248, 0.04); }}
  </style>
</head>
<body oncontextmenu="return false;">
  <div class="watermark-overlay">
    <div>{emp_id}<br>{branch}<br>{now_str}</div>
    <div>{emp_id}<br>{branch}<br>{now_str}</div>
    <div>{emp_id}<br>{branch}<br>{now_str}</div>
    <div>{emp_id}<br>{branch}<br>{now_str}</div>
    <div>{emp_id}<br>{branch}<br>{now_str}</div>
    <div>{emp_id}<br>{branch}<br>{now_str}</div>
    <div>{emp_id}<br>{branch}<br>{now_str}</div>
    <div>{emp_id}<br>{branch}<br>{now_str}</div>
  </div>

  <div class="hud-banner">
    <div style="display: flex; align-items: center; font-size: 13px; font-weight: 600;">
      <span class="beacon"></span>
      <span>AIRGAP DRM ACTIVE • Dynamic Photo-Proof DRM Active • ACTIVE TERMINAL: <strong style="color: #38bdf8;">{emp_id}</strong> ({branch})</span>
    </div>
    <div class="timer-badge" id="countdown">SESSION EXPIRES: 14:59</div>
  </div>

  <div class="sheet">
    <div style="display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 24px;">
      <div>
        <h2 style="font-size: 22px; font-weight: 800; background: linear-gradient(135deg, #60a5fa, #38bdf8); -webkit-background-clip: text; -webkit-text-fill-color: transparent;">
          🔒 State Bank of India — Secure Export Audit Chamber
        </h2>
        <p style="color: #94a3b8; font-size: 12px; margin-top: 4px;">
          Classification: STRICTLY CONFIDENTIAL // ANTI-LEAK PHOTO-PROOF WATERMARK GRID ENFORCED
        </p>
      </div>
      <a href="/dashboard" style="color: #38bdf8; font-size: 13px; text-decoration: none; font-weight: 600;">← Return to SOC</a>
    </div>

    <table>
      <thead>
        <tr>
          <th>Account ID</th>
          <th>Customer Name</th>
          <th>PAN Number</th>
          <th>Aadhaar Number</th>
          <th>Masked Mobile</th>
          <th>Account Balance</th>
        </tr>
      </thead>
      <tbody>
        <tr>
          <td>AC-89218210</td>
          <td>Ranjith Kumar</td>
          <td><span style="color: #38bdf8;">AB*****F</span></td>
          <td><span style="color: #38bdf8;">XXXX-XXXX-1234</span></td>
          <td>******3210</td>
          <td>₹ 2,50,000.00</td>
        </tr>
        <tr>
          <td>AC-78192019</td>
          <td>Vikram Mehra</td>
          <td><span style="color: #38bdf8;">VI*****P</span></td>
          <td><span style="color: #38bdf8;">XXXX-XXXX-9912</span></td>
          <td>******1299</td>
          <td>₹ 8,45,000.00</td>
        </tr>
        <tr>
          <td>AC-99201923</td>
          <td>Sunita Sharma</td>
          <td><span style="color: #38bdf8;">SU*****S</span></td>
          <td><span style="color: #38bdf8;">XXXX-XXXX-8821</span></td>
          <td>******8891</td>
          <td>₹ 1,12,400.00</td>
        </tr>
        <tr>
          <td>AC-44102941</td>
          <td>Deepak Patel</td>
          <td><span style="color: #38bdf8;">DE*****X</span></td>
          <td><span style="color: #38bdf8;">XXXX-XXXX-4411</span></td>
          <td>******4410</td>
          <td>₹ 15,20,000.00</td>
        </tr>
      </tbody>
    </table>
  </div>

  <script>
    let remaining = 899;
    setInterval(() => {{
      if (remaining > 0) {{
        remaining--;
        const mins = String(Math.floor(remaining / 60)).padStart(2, '0');
        const secs = String(remaining % 60).padStart(2, '0');
        document.getElementById('countdown').innerText = `SESSION EXPIRES: ${{mins}}:${{secs}}`;
      }} else {{
        document.body.innerHTML = '<div style="text-align: center; margin-top: 100px; font-family: sans-serif;"><h1>🔒 Ephemeral Session Expired</h1><p>Data self-destructed from gateway memory.</p></div>';
      }}
    }}, 1000);
  </script>
</body>
</html>"""


# ---------------------------------------------------------------------------
# High-Ambience SOC Command Dashboard (/dashboard)
# ---------------------------------------------------------------------------
@app.get("/dashboard", response_class=HTMLResponse, tags=["Dashboard"])
async def get_soc_dashboard() -> str:
    template_path = os.path.join(os.path.dirname(__file__), "templates", "dashboard.html")
    if os.path.exists(template_path):
        with open(template_path, "r", encoding="utf-8") as f:
            return f.read()
    return "<h1>DataFort-Gateway V3.0 SOC Dashboard Active</h1>"
