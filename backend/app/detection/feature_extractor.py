"""PhishShield X - Feature Extractor

Extracts structural, lexical, and brand-impersonation features from URLs,
anchor links, page titles, and visible text.
"""

import math
import re
import ipaddress
from typing import Dict, List, Optional, Set
from urllib.parse import urlparse
import tldextract

# High-profile brands frequently targeted by phishing campaigns
HIGH_PROFILE_BRANDS: Dict[str, Set[str]] = {
    "paypal": {"paypal.com"},
    "google": {"google.com", "accounts.google.com"},
    "microsoft": {"microsoft.com", "live.com", "login.microsoftonline.com"},
    "apple": {"apple.com", "icloud.com"},
    "amazon": {"amazon.com", "amazon.in", "amazon.co.uk"},
    "netflix": {"netflix.com"},
    "chase": {"chase.com"},
    "wellsfargo": {"wellsfargo.com"},
    "bankofamerica": {"bankofamerica.com"},
    "sbi": {"onlinesbi.sbi", "sbi.co.in", "statebankofindia.com"},
    "hdfc": {"hdfcbank.com"},
    "icici": {"icicibank.com"},
    "paytm": {"paytm.com"},
    "phonepe": {"phonepe.com"},
    "facebook": {"facebook.com", "meta.com"},
    "instagram": {"instagram.com"},
    "binance": {"binance.com"},
    "coinbase": {"coinbase.com"},
}

# Suspicious TLDs with high historical malicious abuse rates
SUSPICIOUS_TLDS = {
    "xyz", "top", "tk", "ml", "ga", "cf", "gq", "buzz", "work", "fit",
    "rest", "click", "icu", "cam", "kim", "country", "stream", "download",
    "racing", "party", "loan", "men", "bid", "trade", "webcam", "link",
}

# Suspicious security / auth keywords
SUSPICIOUS_KEYWORDS = {
    "login", "signin", "verify", "verification", "security", "account",
    "update", "banking", "kyc", "pan", "aadhaar", "wallet", "claim",
    "reward", "gift", "bonus", "unlock", "suspension", "unblock",
    "confirm", "support", "billing", "invoice", "refund", "auth",
}


# Homoglyph character mapping (Cyrillic & visual lookalikes to Latin ASCII)
HOMOGLYPH_MAP = {
    '\u0430': 'a', '\u0435': 'e', '\u043e': 'o', '\u0440': 'p',
    '\u0441': 'c', '\u0443': 'y', '\u0445': 'x', '\u0456': 'i',
    '\u0455': 's', '\u0458': 'j', '\u04bb': 'h', '\u0406': 'I',
    '\u0410': 'A', '\u0412': 'B', '\u0415': 'E', '\u041a': 'K',
    '\u041c': 'M', '\u041d': 'H', '\u041e': 'O', '\u0420': 'P',
    '\u0421': 'C', '\u0422': 'T', '\u0425': 'X',
}

# Leetspeak translation table
LEET_MAP = {
    '0': 'o',
    '1': 'l',
    '3': 'e',
    '4': 'a',
    '@': 'a',
    '$': 's',
    '5': 's',
    '8': 'b',
}


def normalize_homoglyphs_and_leetspeak(text: str) -> str:
    """Normalize Cyrillic homoglyphs, leetspeak characters, and visual digraphs (rn -> m)."""
    if not text:
        return ""
    # 1. Map Cyrillic homoglyphs to Latin
    chars = [HOMOGLYPH_MAP.get(c, c) for c in text]
    normalized = "".join(chars).lower()

    # 2. Map visual digraph lookalikes ('rn' -> 'm', 'vv' -> 'w')
    normalized = normalized.replace("rn", "m").replace("vv", "w").replace("cl", "d")

    # 3. Map leetspeak numbers/symbols to letters
    leet_chars = [LEET_MAP.get(c, c) for c in normalized]
    return "".join(leet_chars)


def has_unicode_homoglyphs(text: str) -> bool:
    """Check if string contains non-ASCII or mixed script homoglyphs."""
    if not text:
        return False
    return any(ord(c) > 127 for c in text)


def calculate_entropy(text: str) -> float:
    """Calculate Shannon entropy for a string (detects randomized domain/path names)."""
    if not text:
        return 0.0
    freq: Dict[str, int] = {}
    for char in text:
        freq[char] = freq.get(char, 0) + 1
    entropy = 0.0
    length = len(text)
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return round(entropy, 3)


def is_ip_address(host: str) -> bool:
    """Check if hostname is a raw IPv4, IPv6, decimal (integer), or hex IP address."""
    if not host:
        return False
    # Strip brackets if IPv6 and drop port
    clean_host = host.strip("[]").split(":")[0].strip()

    # 1. Standard dotted IPv4 or IPv6
    try:
        ipaddress.ip_address(clean_host)
        return True
    except ValueError:
        pass

    # 2. Obfuscated Decimal / Integer IP (e.g. 3232235777 -> 192.168.1.1)
    if clean_host.isdigit():
        try:
            val = int(clean_host)
            if 0 < val <= 4294967295:
                ipaddress.IPv4Address(val)
                return True
        except (ValueError, OverflowError):
            pass

    # 3. Hex IP (e.g. 0xc0a80101 or 0xc0.0xa8.0x01.0x01)
    if clean_host.lower().startswith("0x"):
        try:
            val = int(clean_host, 16)
            if 0 < val <= 4294967295:
                ipaddress.IPv4Address(val)
                return True
        except (ValueError, OverflowError):
            pass

    # 4. Octal or Dotted Hex parts
    parts = clean_host.split(".")
    if len(parts) == 4:
        try:
            octets = []
            for p in parts:
                if p.startswith(("0x", "0X")):
                    octets.append(int(p, 16))
                elif p.startswith("0") and len(p) > 1 and p.isdigit():
                    octets.append(int(p, 8))
                elif p.isdigit():
                    octets.append(int(p))
                else:
                    return False
            if all(0 <= o <= 255 for o in octets):
                return True
        except (ValueError, OverflowError):
            pass

    return False


def extract_domain_components(url: str) -> Dict[str, str]:
    """Extract domain, subdomain, suffix, and registered domain safely."""
    try:
        # Pre-process Cyrillic/IDN if needed
        parsed_raw = urlparse(url)
        raw_netloc = parsed_raw.netloc.split("@")[-1].split(":")[0]

        extracted = tldextract.extract(url)
        reg_domain = getattr(extracted, "top_domain_under_public_suffix", None) or getattr(extracted, "registered_domain", "")
        return {
            "subdomain": extracted.subdomain.lower(),
            "domain": extracted.domain.lower(),
            "suffix": extracted.suffix.lower(),
            "registered_domain": (reg_domain or "").lower(),
            "fqdn": extracted.fqdn.lower(),
            "raw_netloc": raw_netloc.lower(),
        }
    except Exception:
        # Fallback to basic urlparse if tldextract encounters issues
        parsed = urlparse(url)
        netloc = parsed.netloc.split("@")[-1].split(":")[0].lower()
        parts = netloc.split(".")
        return {
            "subdomain": ".".join(parts[:-2]) if len(parts) > 2 else "",
            "domain": parts[-2] if len(parts) >= 2 else netloc,
            "suffix": parts[-1] if len(parts) >= 2 else "",
            "registered_domain": ".".join(parts[-2:]) if len(parts) >= 2 else netloc,
            "fqdn": netloc,
            "raw_netloc": netloc,
        }


def check_brand_impersonation(url: str, domain_info: Dict[str, str]) -> Optional[Dict[str, str]]:
    """Detect if a well-known brand is impersonated in userinfo, subdomains, paths,
    registered domains, leetspeak variations, or visual homoglyphs (e.g. arnazon, paypa1, faceb00k).
    """
    registered_domain = domain_info.get("registered_domain", "")
    subdomain = domain_info.get("subdomain", "")
    full_url_lower = url.lower()
    parsed = urlparse(url)

    # 1. Check Userinfo Spoofing (e.g. paypal.com@evil.xyz or support@paypal.com.evil.xyz)
    if "@" in parsed.netloc:
        userinfo_part = parsed.netloc.split("@")[0].lower()
        for brand in HIGH_PROFILE_BRANDS.keys():
            if brand in userinfo_part:
                return {
                    "brand": brand,
                    "location": "userinfo",
                    "evidence": f"Brand '{brand}' embedded in deceptive userinfo prefix: '{userinfo_part}@' on actual host '{parsed.netloc.split('@')[-1]}'",
                }

    # Normalized versions for leetspeak and visual homoglyphs (arnazon -> amazon, paypa1 -> paypal)
    norm_reg_domain = normalize_homoglyphs_and_leetspeak(registered_domain)
    norm_subdomain = normalize_homoglyphs_and_leetspeak(subdomain)
    norm_url = normalize_homoglyphs_and_leetspeak(full_url_lower)

    for brand, legit_domains in HIGH_PROFILE_BRANDS.items():
        # Check if brand appears in raw or normalized strings
        is_in_url = (brand in full_url_lower) or (brand in norm_url)
        if not is_in_url:
            continue

        # If registered domain is legitimately official, not an impersonation
        if registered_domain in legit_domains or norm_reg_domain in legit_domains:
            continue

        # Brand in subdomain e.g., paypal.com.attacker.com or login.microsoftonline.com.evil.ru
        if brand in subdomain or brand in norm_subdomain:
            return {
                "brand": brand,
                "location": "subdomain",
                "evidence": f"Brand '{brand}' appears in subdomain '{subdomain}' on unauthorized domain '{registered_domain}'",
            }

        # Brand in registered domain (typosquatting, hyphenated, leetspeak, or homoglyph e.g. paypa1-secure, arnazon.in, sbi-kyc)
        if brand in registered_domain or brand in norm_reg_domain:
            return {
                "brand": brand,
                "location": "registered_domain",
                "evidence": f"Brand '{brand}' mimicked in registered domain '{registered_domain}' (normalized: '{norm_reg_domain}') which is not official ({', '.join(legit_domains)})",
            }

        # Brand in path combined with suspicious keywords e.g., attacker.com/login/paypal/verify
        path_lower = parsed.path.lower()
        norm_path = normalize_homoglyphs_and_leetspeak(path_lower)
        if (brand in path_lower or brand in norm_path) and any(kw in norm_path for kw in SUSPICIOUS_KEYWORDS):
            return {
                "brand": brand,
                "location": "path",
                "evidence": f"Brand '{brand}' combined with auth keywords in path '{parsed.path}' on domain '{registered_domain}'",
            }

    return None
