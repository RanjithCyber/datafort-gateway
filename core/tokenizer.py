"""
core/tokenizer.py — V2.0 Enhanced Regex + Checksum PII Tokenization Engine

Provides deterministic scrubbing of sensitive Indian banking & personal PII:
  - Mobile numbers (Indian format +91, 0, 10 digits)
  - Email addresses (RFC-5322 compliant)
  - CIF IDs (Customer Information File identifiers)
  - Dates of Birth (ISO-8601, DD/MM/YYYY, DD.MM.YYYY)
  - PAN Cards (Permanent Account Number, 10-char alphanumeric with pattern)
  - Aadhaar Numbers (12 digits with Verhoeff checksum algorithm validation)
  - UPI IDs / VPAs (Virtual Payment Addresses like user@okaxis, id@sbi)

Supports Role-Based Dynamic Masking Modes:
  - FULL_TOKEN: Replaces with deterministic labels [TOKENIZED_*]
  - PARTIAL_MASK: Masks partially for supervisory review (e.g., ******3210)
  - UNMASKED: Preserves raw values for audited high-privilege fraud investigations
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Callable


# ---------------------------------------------------------------------------
# Token Labels
# ---------------------------------------------------------------------------
TOKEN_MOBILE = "[TOKENIZED_MOBILE]"
TOKEN_EMAIL = "[TOKENIZED_EMAIL]"
TOKEN_CIF = "[TOKENIZED_CIF]"
TOKEN_DOB = "[TOKENIZED_DOB]"
TOKEN_PAN = "[TOKENIZED_PAN]"
TOKEN_AADHAAR = "[TOKENIZED_AADHAAR]"
TOKEN_UPI = "[TOKENIZED_UPI]"


class MaskingMode(str, Enum):
    FULL_TOKEN = "FULL_TOKEN"         # Default for regular staff / untrusted
    PARTIAL_MASK = "PARTIAL_MASK"     # For Branch Managers / Supervisors
    UNMASKED = "UNMASKED"             # For Audited Fraud Investigators


# ---------------------------------------------------------------------------
# Verhoeff Algorithm for Aadhaar Checksum Validation
# ---------------------------------------------------------------------------
_VERHOEFF_D = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 2, 3, 4, 0, 6, 7, 8, 9, 5],
    [2, 3, 4, 0, 1, 7, 8, 9, 5, 6],
    [3, 4, 0, 1, 2, 8, 9, 5, 6, 7],
    [4, 0, 1, 2, 3, 9, 5, 6, 7, 8],
    [5, 9, 8, 7, 6, 0, 4, 3, 2, 1],
    [6, 5, 9, 8, 7, 1, 0, 4, 3, 2],
    [7, 6, 5, 9, 8, 2, 1, 0, 4, 3],
    [8, 7, 6, 5, 9, 3, 2, 1, 0, 4],
    [9, 8, 7, 6, 5, 4, 3, 2, 1, 0],
]

_VERHOEFF_P = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    [1, 5, 7, 6, 2, 8, 3, 0, 9, 4],
    [5, 8, 0, 3, 7, 9, 6, 1, 4, 2],
    [8, 9, 1, 6, 0, 4, 3, 5, 2, 7],
    [9, 4, 5, 3, 1, 2, 6, 8, 7, 0],
    [4, 2, 8, 6, 5, 7, 3, 9, 0, 1],
    [2, 7, 9, 3, 8, 0, 6, 4, 1, 5],
    [7, 0, 4, 6, 9, 1, 3, 2, 5, 8],
]


def validate_verhoeff_aadhaar(aadhaar_digits: str) -> bool:
    """Validate 12-digit Aadhaar using the official Verhoeff checksum."""
    if len(aadhaar_digits) != 12 or not aadhaar_digits.isdigit():
        return False
    if aadhaar_digits[0] in ("0", "1"):
        return False
    
    c = 0
    reversed_digits = [int(d) for d in reversed(aadhaar_digits)]
    for i, item in enumerate(reversed_digits):
        c = _VERHOEFF_D[c][_VERHOEFF_P[i % 8][item]]
    return c == 0


# ---------------------------------------------------------------------------
# Regex Patterns
# ---------------------------------------------------------------------------
# Indian PAN Card: 5 uppercase letters, 4 digits, 1 uppercase letter
_PAN_RE = re.compile(r"\b[A-Z]{5}[0-9]{4}[A-Z]{1}\b", re.IGNORECASE)

# Aadhaar: 12 digits (with optional spaces or dashes)
_AADHAAR_RE = re.compile(r"\b[2-9]\d{3}[\s\-]?[0-9]{4}[\s\-]?[0-9]{4}\b")

# Email
_EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}")

# UPI / VPA: Virtual Payment Addresses without domain dot (e.g. user@okaxis, id@sbi)
_UPI_RE = re.compile(r"\b[a-zA-Z0-9.\-_]{2,64}@[a-zA-Z]{2,32}\b(?!\.)", re.IGNORECASE)

# CIF ID (banking customer identification)
_CIF_RE = re.compile(r"\bCIF[A-Za-z0-9]{10,15}\b", re.IGNORECASE)

# DOB
_DOB_RE = re.compile(
    r"\b(?:"
    r"(?:19|20)\d{2}[\-](0[1-9]|1[0-2])[\-](0[1-9]|[12]\d|3[01])"
    r"|"
    r"(0[1-9]|[12]\d|3[01])[\/\.](0[1-9]|1[0-2])[\/\.](19|20)\d{2}"
    r")\b"
)

# Indian Mobile
_MOBILE_RE = re.compile(
    r"(?<!\d)(?:\+?91[\s\-]?)?(?:0[\s\-]?)?[6-9]\d{9}(?!\d)"
)


# ---------------------------------------------------------------------------
# Partial Masking Formatters
# ---------------------------------------------------------------------------
def _partial_mask_mobile(match: str) -> str:
    cleaned = re.sub(r"\D", "", match)
    last4 = cleaned[-4:] if len(cleaned) >= 4 else cleaned
    return f"******{last4}"

def _partial_mask_email(match: str) -> str:
    parts = match.split("@", 1)
    if len(parts) == 2:
        user, domain = parts
        masked_user = user[0] + "***" + (user[-1] if len(user) > 1 else "")
        return f"{masked_user}@{domain}"
    return "[TOKENIZED_EMAIL]"

def _partial_mask_pan(match: str) -> str:
    upper = match.upper()
    return f"{upper[:2]}*****{upper[-1]}"

def _partial_mask_aadhaar(match: str) -> str:
    digits = re.sub(r"\D", "", match)
    return f"XXXX-XXXX-{digits[-4:]}"

def _partial_mask_cif(match: str) -> str:
    return f"CIF******{match[-4:]}"

def _partial_mask_dob(match: str) -> str:
    return "**/**/****"

def _partial_mask_upi(match: str) -> str:
    parts = match.split("@", 1)
    return f"***@{parts[1]}" if len(parts) == 2 else "[TOKENIZED_UPI]"


# ---------------------------------------------------------------------------
# Pattern Definitions
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class PIIRule:
    name: str
    pattern: re.Pattern[str]
    token: str
    partial_formatter: Callable[[str], str]
    validator: Callable[[str], bool] | None = None


# Order: PAN -> Aadhaar -> Email -> UPI -> CIF -> DOB -> Mobile
PII_RULES: tuple[PIIRule, ...] = (
    PIIRule(
        name="pan",
        pattern=_PAN_RE,
        token=TOKEN_PAN,
        partial_formatter=_partial_mask_pan,
    ),
    PIIRule(
        name="aadhaar",
        pattern=_AADHAAR_RE,
        token=TOKEN_AADHAAR,
        partial_formatter=_partial_mask_aadhaar,
        validator=lambda s: validate_verhoeff_aadhaar(re.sub(r"\D", "", s)),
    ),
    PIIRule(
        name="email",
        pattern=_EMAIL_RE,
        token=TOKEN_EMAIL,
        partial_formatter=_partial_mask_email,
    ),
    PIIRule(
        name="upi",
        pattern=_UPI_RE,
        token=TOKEN_UPI,
        partial_formatter=_partial_mask_upi,
    ),
    PIIRule(
        name="cif",
        pattern=_CIF_RE,
        token=TOKEN_CIF,
        partial_formatter=_partial_mask_cif,
    ),
    PIIRule(
        name="dob",
        pattern=_DOB_RE,
        token=TOKEN_DOB,
        partial_formatter=_partial_mask_dob,
    ),
    PIIRule(
        name="mobile",
        pattern=_MOBILE_RE,
        token=TOKEN_MOBILE,
        partial_formatter=_partial_mask_mobile,
    ),
)


# ---------------------------------------------------------------------------
# Tokenization Logic
# ---------------------------------------------------------------------------
@dataclass
class TokenizationResult:
    sanitized_payload: Any
    fields_tokenized: list[str] = field(default_factory=list)
    total_substitutions: int = 0
    mode_applied: MaskingMode = MaskingMode.FULL_TOKEN

    @property
    def had_pii(self) -> bool:
        return self.total_substitutions > 0


def _tokenize_string(
    value: str, mode: MaskingMode = MaskingMode.FULL_TOKEN
) -> tuple[str, list[str], int]:
    if mode == MaskingMode.UNMASKED:
        return value, [], 0

    matched_fields: list[str] = []
    total_subs = 0

    for rule in PII_RULES:
        def replace_match(m: re.Match[str]) -> str:
            raw_match = m.group(0)
            if rule.validator and not rule.validator(raw_match):
                return raw_match
            
            nonlocal total_subs
            total_subs += 1
            if rule.name not in matched_fields:
                matched_fields.append(rule.name)

            if mode == MaskingMode.PARTIAL_MASK:
                return rule.partial_formatter(raw_match)
            return rule.token

        value = rule.pattern.sub(replace_match, value)

    return value, matched_fields, total_subs


def _tokenize_recursive(
    obj: Any, mode: MaskingMode = MaskingMode.FULL_TOKEN
) -> tuple[Any, list[str], int]:
    if isinstance(obj, str):
        return _tokenize_string(obj, mode)

    if isinstance(obj, dict):
        sanitized: dict[str, Any] = {}
        all_fields: list[str] = []
        total = 0
        for key, val in obj.items():
            new_val, fields, subs = _tokenize_recursive(val, mode)
            sanitized[key] = new_val
            all_fields.extend(fields)
            total += subs
        return sanitized, all_fields, total

    if isinstance(obj, (list, tuple)):
        sanitized_list: list[Any] = []
        all_fields = []
        total = 0
        for item in obj:
            new_item, fields, subs = _tokenize_recursive(item, mode)
            sanitized_list.append(new_item)
            all_fields.extend(fields)
            total += subs
        container = type(obj)(sanitized_list) if isinstance(obj, tuple) else sanitized_list
        return container, all_fields, total

    return obj, [], 0


def tokenize_payload(
    payload: Any, mode: MaskingMode = MaskingMode.FULL_TOKEN
) -> TokenizationResult:
    """Public API: Recursively scrub PII with optional dynamic masking mode."""
    sanitized, fields, subs = _tokenize_recursive(payload, mode)
    
    seen: set[str] = set()
    unique_fields: list[str] = []
    for f in fields:
        if f not in seen:
            seen.add(f)
            unique_fields.append(f)

    return TokenizationResult(
        sanitized_payload=sanitized,
        fields_tokenized=unique_fields,
        total_substitutions=subs,
        mode_applied=mode,
    )
