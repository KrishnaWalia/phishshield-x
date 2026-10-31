"""PhishShield X - Security & Sanitization Utilities

Ensures strict zero-trust data sanitization:
1. Scrubbing sensitive credentials (credit cards, CVVs, OTPs, PINs, passwords).
2. URL validation and scheme restriction (rejecting dangerous schemes like javascript:, data:, file:).
3. Safe descriptor generation so raw messages and credentials are NEVER persisted in DB.
"""

import re
from typing import Optional
from urllib.parse import urlparse

# Regular expressions for scrubbing sensitive financial & auth data
# Regular expressions for scrubbing sensitive financial & auth data
CARD_PATTERN = re.compile(r"\b(?:\d[ -]*?){13,19}\b")
CVV_PATTERN = re.compile(r"\b(?:cvv|cvc|security\s*code)(?:\s+(?:is|was|hai))?[\s:=#-]*\d{3,4}\b", re.IGNORECASE)
OTP_PATTERN = re.compile(
    r"\b(?:otp|one\s*time\s*password|pin|upi\s*pin|code|secret|verification\s*code|auth\s*code)"
    r"(?:\s+(?:is|was|to\s*be|hai|de|do))?[\s:=#-]*\d{4,8}\b",
    re.IGNORECASE,
)
# Standalone high-entropy 6-digit codes following keywords
STANDALONE_OTP_PATTERN = re.compile(r"(?<=\b(?:otp|pin|code)[\s:=]{1,10})\b\d{4,8}\b", re.IGNORECASE)
PASSWORD_PATTERN = re.compile(
    r"\b(?:password|passwd|pwd|passcode)(?:\s+(?:is|was|hai))?[\s:=#-]*\S+\b",
    re.IGNORECASE,
)
AADHAAR_PATTERN = re.compile(r"\b(?:\d{4}[\s-]?\d{4}[\s-]?\d{4}|\d{12})\b")
PAN_PATTERN = re.compile(r"\b[A-Za-z]{5}[0-9]{4}[A-Za-z]{1}\b")

# Zero-width & invisible format characters regex
INVISIBLE_CHARS_PATTERN = re.compile(r"[\u200b\u200c\u200d\u200e\u200f\ufeff\u202a-\u202e\u2060-\u206f]")

# Allowed safe protocols for URL scanning
ALLOWED_SCHEMES = {"http", "https"}


def clean_invisible_characters(text: str) -> str:
    """Strip zero-width spaces, ZWNJ, BOM, and deceptive formatting characters."""
    if not text:
        return ""
    return INVISIBLE_CHARS_PATTERN.sub("", text)


def scrub_sensitive_content(text: str) -> str:
    """Scrub sensitive credentials, card numbers, OTPs, PINs, and passwords from text.
    
    Used before any text is sent to an external AI provider, saved in finding evidence, or stored in logs.
    """
    if not text:
        return ""
    # Strip invisible characters first
    cleaned = clean_invisible_characters(text)
    scrubbed = CARD_PATTERN.sub("[REDACTED_CARD]", cleaned)
    scrubbed = CVV_PATTERN.sub("[REDACTED_CVV]", scrubbed)
    scrubbed = OTP_PATTERN.sub("[REDACTED_AUTH_CODE]", scrubbed)
    scrubbed = STANDALONE_OTP_PATTERN.sub("[REDACTED_CODE]", scrubbed)
    scrubbed = PASSWORD_PATTERN.sub("[REDACTED_PASSWORD]", scrubbed)
    scrubbed = AADHAAR_PATTERN.sub("[REDACTED_ID]", scrubbed)
    scrubbed = PAN_PATTERN.sub("[REDACTED_PAN]", scrubbed)
    return scrubbed


def validate_and_sanitize_url(raw_url: str) -> str:
    """Validate that a URL uses http or https and sanitize basic whitespace/control chars.
    
    Raises:
        ValueError: If URL has invalid scheme, missing hostname, or invalid structure.
    """
    if not raw_url or not isinstance(raw_url, str):
        raise ValueError("URL must be a non-empty string.")

    cleaned_url = clean_invisible_characters(raw_url).strip()
    try:
        parsed = urlparse(cleaned_url)
    except Exception as exc:
        raise ValueError(f"Malformed URL: {exc}")

    if not parsed.scheme or parsed.scheme.lower() not in ALLOWED_SCHEMES:
        raise ValueError(
            f"Invalid URL scheme '{parsed.scheme}'. Only http and https schemes are permitted."
        )

    if not parsed.netloc:
        raise ValueError("URL must include a valid network location (domain or host).")

    return cleaned_url


def create_safe_target_descriptor(target_type: str, raw_content: str) -> str:
    """Create a safe, non-sensitive descriptor for persistence in the database.
    
    CRITICAL: Strips embedded credentials (e.g. username:password@host) so passwords
    are NEVER persisted in target descriptors or exposed via API responses.
    """
    if target_type.lower() == "url":
        try:
            parsed = urlparse(raw_content.strip())
            # Strip embedded userinfo (admin:Secr3tPass@host -> host)
            hostname = parsed.hostname or parsed.netloc.split("@")[-1].split(":")[0]
            port_suffix = f":{parsed.port}" if parsed.port else ""
            safe_netloc = f"{hostname}{port_suffix}"
            safe_path = parsed.path if parsed.path else "/"
            return f"{parsed.scheme.lower()}://{safe_netloc}{safe_path}"
        except Exception:
            return scrub_sensitive_content(raw_content[:120].strip())

    # Message target: Safe truncated preview with all secrets scrubbed
    cleaned = scrub_sensitive_content(raw_content.strip())
    first_line = cleaned.splitlines()[0] if cleaned.splitlines() else "Empty message"
    if len(first_line) > 80:
        preview = first_line[:77] + "..."
    else:
        preview = first_line
    return f"Message: {preview} ({len(raw_content)} chars)"
