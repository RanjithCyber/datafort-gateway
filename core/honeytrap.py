"""
core/honeytrap.py — Cyber Deception & Synthetic Honeytoken Engine

Features:
  1. Tarpit / Decoy Routing:
     Seamlessly diverts hostile scraping bots to synthetic honeypot data
     instead of returning blunt 403 errors, wasting the attacker's resources.
  2. Realistic Synthetic Banking Generator:
     Generates mathematically valid decoy records (Valid PANs, Verhoeff Aadhaar,
     simulated balances) embedded with silent tracking seeds.
"""

from __future__ import annotations

import random
from typing import Any

from core.tokenizer import _VERHOEFF_D, _VERHOEFF_P

_FIRST_NAMES = ["Amit", "Sunita", "Rajesh", "Pooja", "Vikram", "Deepak", "Ananya", "Rohan"]
_LAST_NAMES = ["Sharma", "Verma", "Mehra", "Patel", "Singh", "Gupta", "Rao", "Nair"]
_BRANCHES = ["MUMBAI_FORT_001", "DELHI_CP_002", "CHENNAI_MAIN_003", "BLR_MG_004"]


def _generate_valid_decoy_aadhaar() -> str:
    """Generate mathematically valid 12-digit Aadhaar with Verhoeff checksum."""
    base = f"{random.randint(2000, 9999)}{random.randint(1000000, 9999999)}"[:11]
    c = 0
    for i, item in enumerate([int(d) for d in reversed(base)]):
        c = _VERHOEFF_D[c][_VERHOEFF_P[(i + 1) % 8][item]]
    checksum = _VERHOEFF_D[c].index(0)
    full_aadhaar = f"{base}{checksum}"
    return f"{full_aadhaar[:4]} {full_aadhaar[4:8]} {full_aadhaar[8:]}"


def _generate_valid_decoy_pan() -> str:
    """Generate valid 10-char PAN format for decoy data."""
    letters = "".join(random.choices("ABCDEFGHIJKLMNOPQRSTUVWXYZ", k=3))
    fourth = random.choice(["P", "C", "H", "F"])  # Individual, Company, HUF, Firm
    fifth = random.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    digits = f"{random.randint(1000, 9999)}"
    last = random.choice("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
    return f"{letters}{fourth}{fifth}{digits}{last}"


def generate_decoy_customer(record_id: int, attacker_ip: str) -> dict[str, Any]:
    """Create a high-fidelity synthetic banking record tagged for threat hunting."""
    fname = random.choice(_FIRST_NAMES)
    lname = random.choice(_LAST_NAMES)
    return {
        "account_id": f"AC-{random.randint(10000000, 99999999)}",
        "customer_name": f"{fname} {lname}",
        "cif_id": f"CIF{random.randint(1000000000, 9999999999)}",
        "pan_card": _generate_valid_decoy_pan(),
        "aadhaar": _generate_valid_decoy_aadhaar(),
        "mobile": f"+91-9{random.randint(100000000, 999999999)}",
        "email": f"{fname.lower()}.{lname.lower()}{random.randint(10, 99)}@gmail.com",
        "account_type": random.choice(["SAVINGS_PREMIUM", "SALARY_CORPORATE", "CURRENT_BUSINESS"]),
        "account_balance": round(random.uniform(50000.0, 1500000.0), 2),
        "branch": random.choice(_BRANCHES),
        "honeytoken_flag": f"TRAP_SEED_IP_{attacker_ip}",
    }


def generate_tarpit_dataset(count: int, attacker_ip: str) -> list[dict[str, Any]]:
    """Generate an entire batch of realistic honeypot records."""
    return [generate_decoy_customer(i, attacker_ip) for i in range(count)]
